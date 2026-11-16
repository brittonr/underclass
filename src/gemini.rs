//! Google AI Ultra / Gemini Code Assist backend.
//!
//! Authentication and the upstream shape follow the open-source Gemini CLI
//! (`packages/core/src/code_assist/oauth2.ts`, `server.ts`, `setup.ts`, `converter.ts`):
//! a public installed-app OAuth client, the paste-back redirect
//! `https://codeassist.google.com/authcode`, and the Code Assist methods on
//! `https://cloudcode-pa.googleapis.com/v1internal`. The client secret is the one the CLI
//! publishes for that installed app; it is not a user credential.
//!
//! `prompt=consent` is added on top of the CLI's `access_type=offline` so a pooled account
//! always receives a refresh token. The OAuth client id and installed-app secret are read from
//! `UNDERCLASS_GEMINI_CLIENT_ID` and `UNDERCLASS_GEMINI_CLIENT_SECRET` (copy them from the CLI's
//! `oauth2.ts`; they are not stored in this repository). `fetchAvailableModels` is not called by
//! the CLI; the parser below accepts the shapes community clients observe and leaves the seeded
//! catalog in place when the call fails. Quota cooldowns follow HTTP 429 and `RESOURCE_EXHAUSTED`.
//! Neither the live model list nor a real Ultra quota window was exercised against Google.

use crate::flows::{FlowRegistry, FlowState, OAuthState};
use crate::models::{
    Account, AccountStatus, BackendId, FREE_PLAN_REASON, ModelInfo, Outcome, Surface, now_ms,
};
use crate::pool::PoolCore;
use crate::provider::{Backend, ResponseAdapter};
use crate::store::Store;
use crate::usage::UsageDialect;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderMap;
use reqwest::Client;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const REDIRECT_URI: &str = "https://codeassist.google.com/authcode";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
const CODE_ASSIST_ORIGIN: &str = "https://cloudcode-pa.googleapis.com";
const USER_AGENT: &str = "GeminiCLI/underclass (linux; amd64)";
const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
];
const DEFAULT_CONTEXT: i64 = 1_048_576;
const DEFAULT_OUTPUT: i64 = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("gemini authorization failed (HTTP {0})")]
    Rejected(u16),
    #[error("{0}")]
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientKind {
    Chat,
    Responses,
    Anthropic,
    Count,
}

#[derive(Clone, Debug)]
struct ToolCall {
    id: String,
    name: String,
    arguments: String,
}

#[derive(Clone, Debug)]
struct Usage {
    input: i64,
    output: i64,
    total: i64,
}

#[derive(Clone, Debug)]
pub struct QuotaBucket {
    pub model: String,
    pub remaining_fraction: Option<f64>,
    pub reset_time: Option<String>,
}

pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
}

pub struct CodeAssistAccount {
    pub label: String,
    pub email: Option<String>,
    pub project_id: String,
    pub plan: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

fn endpoint() -> String {
    std::env::var("UNDERCLASS_GEMINI_UPSTREAM").unwrap_or_else(|_| CODE_ASSIST_ORIGIN.to_string())
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    out.truncate(len);
    out
}

fn base64_url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn new_pkce() -> Pkce {
    let verifier = base64_url(&random_bytes(32));
    let challenge = base64_url(&Sha256::digest(verifier.as_bytes()));
    let state = base64_url(&random_bytes(16));
    Pkce {
        verifier,
        challenge,
        state,
    }
}

struct OAuthApp {
    id: String,
    secret: String,
}

/// The installed-app OAuth client. The values live in the operator's environment, copied from
/// the Gemini CLI's `oauth2.ts`, and are not embedded in this repository.
fn oauth_app() -> Result<OAuthApp, AuthError> {
    let id = std::env::var("UNDERCLASS_GEMINI_CLIENT_ID").unwrap_or_default();
    let secret = std::env::var("UNDERCLASS_GEMINI_CLIENT_SECRET").unwrap_or_default();
    if id.trim().is_empty() || secret.trim().is_empty() {
        return Err(AuthError::Failed(
            "set UNDERCLASS_GEMINI_CLIENT_ID and UNDERCLASS_GEMINI_CLIENT_SECRET from the Gemini CLI oauth2.ts constants before adding a Gemini account"
                .into(),
        ));
    }
    Ok(OAuthApp { id, secret })
}

/// @cc [owner:ghuntley,label:security] gemini-authorize-url-has-no-secret
/// `authorize_url` MUST be an accounts.google.com authorization URL that carries the supplied
/// client id, the Code Assist redirect, PKCE S256, offline access, and the Cloud Code scopes,
/// and MUST NOT contain the client secret, an access token, or a refresh token.
pub fn authorize_url(pkce: &Pkce, client_id: &str) -> String {
    let scope = SCOPES.join(" ");
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&code_challenge={}&code_challenge_method=S256&state={}",
        percent_encode(client_id),
        percent_encode(REDIRECT_URI),
        percent_encode(&scope),
        percent_encode(&pkce.challenge),
        percent_encode(&pkce.state),
    )
}

pub fn exchange_form<'a>(
    code: &'a str,
    verifier: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
) -> Vec<(&'static str, &'a str)> {
    vec![
        ("code", code),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("redirect_uri", REDIRECT_URI),
        ("grant_type", "authorization_code"),
        ("code_verifier", verifier),
    ]
}

pub fn refresh_form<'a>(
    refresh_token: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
) -> Vec<(&'static str, &'a str)> {
    vec![
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ]
}

fn pasted_code(raw: &str) -> &str {
    raw.trim()
        .split(['#', ' ', '\n', '\r'])
        .next()
        .unwrap_or("")
        .trim()
}

fn client_kind(path: &str) -> ClientKind {
    if path.contains("count_tokens") {
        ClientKind::Count
    } else if path.contains("/messages") {
        ClientKind::Anthropic
    } else if path.contains("chat/completions") {
        ClientKind::Chat
    } else {
        ClientKind::Responses
    }
}

/// Strips a `models/` resource prefix or a single `gemini/` catalog prefix.
pub fn upstream_model(id: &str) -> String {
    let id = id.trim();
    let id = id.strip_prefix("models/").unwrap_or(id);
    let id = id.strip_prefix("gemini/").unwrap_or(id);
    id.to_string()
}

/// @cc [owner:ghuntley,label:pool] gemini-free-tier-plan
/// `plan_for_tier` MUST return `free` when the tier id is `free` or `free-tier`
/// (case-insensitive). Otherwise it MUST return the tier's nonempty display name when that
/// name is not `free`, and the tier id when the name is missing or blank.
pub fn plan_for_tier(tier_id: &str, tier_name: Option<&str>) -> String {
    if tier_id.eq_ignore_ascii_case("free") || tier_id.eq_ignore_ascii_case("free-tier") {
        return "free".into();
    }
    tier_name
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.eq_ignore_ascii_case("free"))
        .unwrap_or(tier_id)
        .to_string()
}

fn duration_parts(raw: &str) -> Option<(&str, i64)> {
    if let Some(num) = raw.strip_suffix("ms") {
        Some((num, 1))
    } else if let Some(num) = raw.strip_suffix('s') {
        Some((num, 1_000))
    } else if let Some(num) = raw.strip_suffix('m') {
        Some((num, 60_000))
    } else {
        raw.strip_suffix('h').map(|num| (num, 3_600_000))
    }
}

/// @cc [owner:ghuntley,label:pool] gemini-duration-parse
/// `parse_duration_ms` MUST parse a protobuf duration (`30s`, `1.5s`, `500ms`, `2m`, `1h`)
/// into a non-negative millisecond count and MUST return `None` for a blank, negative, or
/// unlabelled value.
pub fn parse_duration_ms(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let (num, mult) = duration_parts(raw)?;
    let num = num.trim();
    if num.is_empty() {
        return None;
    }
    let value: f64 = num.parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let ms = value * mult as f64;
    if !ms.is_finite() || ms > i64::MAX as f64 {
        return None;
    }
    Some(ms as i64)
}

pub fn is_quota_exhausted(status: u16, body: &str) -> bool {
    if status == 429 {
        return true;
    }
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/status")
                .and_then(Value::as_str)
                .map(|status| status == "RESOURCE_EXHAUSTED")
        })
        .unwrap_or(false)
}

fn retry_delay_ms(body: &str) -> Option<i64> {
    let value: Value = serde_json::from_str(body).ok()?;
    let details = value.pointer("/error/details")?.as_array()?;
    for detail in details {
        if let Some(delay) = detail.get("retryDelay").and_then(Value::as_str)
            && let Some(ms) = parse_duration_ms(delay)
        {
            return Some(ms);
        }
    }
    None
}

/// @cc [owner:ghuntley,label:pool] gemini-quota-deadline
/// `quota_until_ms` MUST return an absolute epoch-millisecond deadline when the status is 429
/// or the JSON error status is `RESOURCE_EXHAUSTED`, preferring a `google.rpc.RetryInfo`
/// `retryDelay`, then a Retry-After header, then `cooldown_ms` added to `now_ms`. Any other
/// status MUST return `None`.
pub fn quota_until_ms(
    status: u16,
    body: &str,
    headers: &HeaderMap,
    cooldown_ms: i64,
    now_ms: i64,
) -> Option<i64> {
    if !is_quota_exhausted(status, body) {
        return None;
    }
    Some(
        retry_delay_ms(body)
            .map(|ms| now_ms.saturating_add(ms))
            .or_else(|| crate::health::parse_retry_after_headers(headers, now_ms))
            .unwrap_or_else(|| now_ms.saturating_add(cooldown_ms)),
    )
}

fn model_info(id: &str, name: &str, input: i64, output: i64) -> ModelInfo {
    ModelInfo {
        id: id.to_string(),
        name: name.to_string(),
        context: input,
        input,
        output,
    }
}

/// Visible models from the Gemini CLI's `defaultModelConfigs.ts` (November 2026). Limits are
/// the published Gemini 1M-context figures until `fetchAvailableModels` replaces them.
pub fn default_catalog() -> Vec<ModelInfo> {
    let entries: &[(&str, &str)] = &[
        ("gemini-2.5-flash", "Gemini 2.5 Flash"),
        ("gemini-2.5-flash-lite", "Gemini 2.5 Flash-Lite"),
        ("gemini-2.5-pro", "Gemini 2.5 Pro"),
        ("gemini-3-flash-preview", "Gemini 3 Flash"),
        ("gemini-3-pro-preview", "Gemini 3 Pro"),
        ("gemini-3.1-flash-lite", "Gemini 3.1 Flash-Lite"),
        (
            "gemini-3.1-flash-lite-preview",
            "Gemini 3.1 Flash-Lite Preview",
        ),
        ("gemini-3.1-pro-preview", "Gemini 3.1 Pro"),
        ("gemini-3.5-flash", "Gemini 3.5 Flash"),
        ("gemini-3.5-flash-lite", "Gemini 3.5 Flash-Lite"),
        ("gemini-3.8-flash", "Gemini 3.8 Flash"),
        ("gemma-4-26b-a4b-it", "Gemma 4 26B"),
        ("gemma-4-31b-it", "Gemma 4 31B"),
    ];
    entries
        .iter()
        .map(|(id, name)| model_info(id, name, DEFAULT_CONTEXT, DEFAULT_OUTPUT))
        .collect()
}

fn limits_from(info: &Value) -> (i64, i64) {
    let input = info
        .get("inputTokenLimit")
        .or_else(|| info.get("inputTokenCount"))
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_CONTEXT);
    let output = info
        .get("outputTokenLimit")
        .or_else(|| info.get("outputTokenCount"))
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_OUTPUT);
    (input, output)
}

pub fn parse_available_models(value: &Value) -> Vec<ModelInfo> {
    let mut models = Vec::new();
    match value.get("models") {
        Some(Value::Object(map)) => {
            for (id, info) in map {
                let name = info
                    .get("displayName")
                    .and_then(Value::as_str)
                    .unwrap_or(id);
                let (input, output) = limits_from(info);
                models.push(model_info(&upstream_model(id), name, input, output));
            }
        }
        Some(Value::Array(items)) => {
            for info in items {
                let raw = info
                    .get("name")
                    .or_else(|| info.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let id = raw.rsplit('/').next().unwrap_or(raw);
                if id.is_empty() {
                    continue;
                }
                let name = info
                    .get("displayName")
                    .and_then(Value::as_str)
                    .unwrap_or(id);
                let (input, output) = limits_from(info);
                models.push(model_info(&upstream_model(id), name, input, output));
            }
        }
        _ => {}
    }
    models.sort_by(|a, b| a.id.cmp(&b.id));
    models.dedup_by(|a, b| a.id == b.id);
    models
}

/// Keeps an operator's stored entry for every model the live list still serves, seeds new
/// models from the live limits, and drops models the live list no longer has. An empty live
/// list leaves the stored catalog (or the seed, when nothing is stored) untouched.
pub fn merge_catalog(
    live: &[ModelInfo],
    stored: &[ModelInfo],
    seed: &[ModelInfo],
) -> Vec<ModelInfo> {
    if live.is_empty() {
        return if stored.is_empty() {
            seed.to_vec()
        } else {
            stored.to_vec()
        };
    }
    let mut catalog: Vec<ModelInfo> = live
        .iter()
        .map(|model| {
            stored
                .iter()
                .find(|stored| stored.id == model.id)
                .cloned()
                .unwrap_or_else(|| model.clone())
        })
        .collect();
    catalog.sort_by(|a, b| a.id.cmp(&b.id));
    catalog.dedup_by(|a, b| a.id == b.id);
    catalog
}

pub fn parse_quota(value: &Value) -> Vec<QuotaBucket> {
    value
        .get("buckets")
        .and_then(Value::as_array)
        .map(|buckets| {
            buckets
                .iter()
                .map(|bucket| QuotaBucket {
                    model: bucket
                        .get("modelId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    remaining_fraction: bucket.get("remainingFraction").and_then(Value::as_f64),
                    reset_time: bucket
                        .get("resetTime")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn quota_view(buckets: &[QuotaBucket]) -> Value {
    let mut worst: Option<f64> = None;
    let items: Vec<Value> = buckets
        .iter()
        .map(|bucket| {
            if let Some(fraction) = bucket.remaining_fraction {
                worst = Some(worst.map_or(fraction, |current| current.min(fraction)));
            }
            json!({
                "model": bucket.model,
                "remaining_fraction": bucket.remaining_fraction,
                "reset_time": bucket.reset_time,
            })
        })
        .collect();
    let mut view = json!({ "buckets": items });
    if let Some(fraction) = worst {
        view["status"] = json!(format!("{}% left", (fraction * 100.0).round() as i64));
    }
    view
}

fn text_part(text: &str) -> Value {
    json!({ "text": text })
}

fn image_from_url(url: &str) -> Option<Value> {
    if let Some(rest) = url.strip_prefix("data:") {
        let (meta, data) = rest.split_once(',')?;
        let mime = meta.split(';').next().filter(|mime| !mime.is_empty())?;
        return Some(json!({ "inlineData": { "mimeType": mime, "data": data } }));
    }
    if url.starts_with("https://") || url.starts_with("http://") {
        return Some(json!({ "fileData": { "fileUri": url } }));
    }
    None
}

fn one_part(kind: ClientKind, item: &Value) -> Option<Value> {
    if let Some(text) = item.as_str() {
        return Some(text_part(text));
    }
    let ty = item.get("type").and_then(Value::as_str).unwrap_or("");
    match (kind, ty) {
        (_, "text")
        | (ClientKind::Responses, "input_text")
        | (ClientKind::Responses, "output_text") => {
            item.get("text").and_then(Value::as_str).map(text_part)
        }
        (ClientKind::Chat, "image_url") => {
            image_from_url(item.pointer("/image_url/url").and_then(Value::as_str)?)
        }
        (ClientKind::Responses, "input_image") => {
            let url = item
                .get("image_url")
                .and_then(Value::as_str)
                .or_else(|| item.pointer("/image_url/url").and_then(Value::as_str))?;
            image_from_url(url)
        }
        (ClientKind::Anthropic | ClientKind::Count, "image") => {
            let source = item.get("source")?;
            if source.get("type").and_then(Value::as_str) == Some("base64") {
                let mime = source
                    .get("media_type")
                    .and_then(Value::as_str)
                    .unwrap_or("image/png");
                let data = source.get("data").and_then(Value::as_str)?;
                Some(json!({ "inlineData": { "mimeType": mime, "data": data } }))
            } else {
                image_from_url(source.get("url").and_then(Value::as_str)?)
            }
        }
        _ => None,
    }
}

fn parts_of(kind: ClientKind, content: &Value) -> Vec<Value> {
    match content {
        Value::String(text) => vec![text_part(text)],
        Value::Array(items) => items
            .iter()
            .filter_map(|item| one_part(kind, item))
            .collect(),
        Value::Null => Vec::new(),
        other => one_part(kind, other).into_iter().collect(),
    }
}

fn flatten_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                item.as_str()
                    .or_else(|| item.get("text").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

fn push_system(system: &mut String, text: &str) {
    if text.is_empty() {
        return;
    }
    if !system.is_empty() {
        system.push('\n');
    }
    system.push_str(text);
}

fn push_part(turns: &mut Vec<(String, Vec<Value>)>, role: &str, part: Value) {
    if let Some((last, parts)) = turns.last_mut()
        && last == role
    {
        parts.push(part);
        return;
    }
    turns.push((role.to_string(), vec![part]));
}

fn function_call_part(name: &str, args: &Value, id: &str) -> Value {
    let arguments = match args {
        Value::String(text) => serde_json::from_str::<Value>(text).unwrap_or(json!({})),
        other => other.clone(),
    };
    let mut call = json!({ "name": name, "args": arguments });
    if !id.is_empty() {
        call["id"] = json!(id);
    }
    json!({ "functionCall": call })
}

fn function_response_part(name: &str, content: &Value, id: &str) -> Value {
    let response = match content {
        Value::Object(_) => content.clone(),
        Value::String(text) => {
            serde_json::from_str::<Value>(text).unwrap_or(json!({ "result": text }))
        }
        Value::Null => json!({ "result": "" }),
        other => json!({ "result": other }),
    };
    let mut part = json!({ "name": name, "response": response });
    if !id.is_empty() {
        part["id"] = json!(id);
    }
    json!({ "functionResponse": part })
}

fn conversation(kind: ClientKind, body: &Value) -> (String, Vec<Value>) {
    let mut system = String::new();
    let mut turns: Vec<(String, Vec<Value>)> = Vec::new();
    let mut names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    match kind {
        ClientKind::Chat => ingest_chat(body, &mut system, &mut turns, &mut names),
        ClientKind::Responses => ingest_responses(body, &mut system, &mut turns, &mut names),
        ClientKind::Anthropic | ClientKind::Count => {
            ingest_anthropic(body, &mut system, &mut turns, &mut names);
        }
    }
    let contents = turns
        .into_iter()
        .filter(|(_, parts)| !parts.is_empty())
        .map(|(role, parts)| json!({ "role": role, "parts": parts }))
        .collect();
    (system, contents)
}

fn ingest_chat(
    body: &Value,
    system: &mut String,
    turns: &mut Vec<(String, Vec<Value>)>,
    names: &mut std::collections::HashMap<String, String>,
) {
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return;
    };
    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user");
        match role {
            "system" | "developer" => push_system(system, &flatten_text(&message["content"])),
            "assistant" => {
                for part in parts_of(ClientKind::Chat, &message["content"]) {
                    push_part(turns, "model", part);
                }
                if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
                    for call in calls {
                        let id = call.get("id").and_then(Value::as_str).unwrap_or("");
                        let name = call
                            .pointer("/function/name")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let args = call
                            .pointer("/function/arguments")
                            .cloned()
                            .unwrap_or(json!("{}"));
                        if !id.is_empty() {
                            names.insert(id.to_string(), name.to_string());
                        }
                        push_part(turns, "model", function_call_part(name, &args, id));
                    }
                }
            }
            "tool" => {
                let id = message
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let name = names.get(id).cloned().unwrap_or_else(|| {
                    message
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(id)
                        .to_string()
                });
                push_part(
                    turns,
                    "user",
                    function_response_part(&name, &message["content"], id),
                );
            }
            _ => {
                for part in parts_of(ClientKind::Chat, &message["content"]) {
                    push_part(turns, "user", part);
                }
            }
        }
    }
}

fn ingest_responses(
    body: &Value,
    system: &mut String,
    turns: &mut Vec<(String, Vec<Value>)>,
    names: &mut std::collections::HashMap<String, String>,
) {
    if let Some(instructions) = body.get("instructions") {
        push_system(system, &flatten_text(instructions));
    }
    match body.get("input") {
        Some(Value::String(text)) => push_part(turns, "user", text_part(text)),
        Some(Value::Array(items)) => {
            for item in items {
                ingest_responses_item(item, system, turns, names);
            }
        }
        Some(other) => {
            for part in parts_of(ClientKind::Responses, other) {
                push_part(turns, "user", part);
            }
        }
        None => {}
    }
}

fn ingest_responses_item(
    item: &Value,
    system: &mut String,
    turns: &mut Vec<(String, Vec<Value>)>,
    names: &mut std::collections::HashMap<String, String>,
) {
    let ty = item.get("type").and_then(Value::as_str).unwrap_or("");
    match ty {
        "function_call" => {
            let id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let name = item.get("name").and_then(Value::as_str).unwrap_or("");
            let args = item.get("arguments").cloned().unwrap_or(json!("{}"));
            if !id.is_empty() {
                names.insert(id.to_string(), name.to_string());
            }
            push_part(turns, "model", function_call_part(name, &args, id));
        }
        "function_call_output" => {
            let id = item.get("call_id").and_then(Value::as_str).unwrap_or("");
            let name = names.get(id).cloned().unwrap_or_else(|| id.to_string());
            let output = item.get("output").cloned().unwrap_or(Value::Null);
            push_part(turns, "user", function_response_part(&name, &output, id));
        }
        "message" | "" => {
            let role = item.get("role").and_then(Value::as_str).unwrap_or("user");
            if role == "system" || role == "developer" {
                push_system(system, &flatten_text(item.get("content").unwrap_or(item)));
                return;
            }
            let gemini_role = if role == "assistant" { "model" } else { "user" };
            let content = item.get("content").unwrap_or(item);
            for part in parts_of(ClientKind::Responses, content) {
                push_part(turns, gemini_role, part);
            }
        }
        _ => {
            if let Some(part) = one_part(ClientKind::Responses, item) {
                push_part(turns, "user", part);
            }
        }
    }
}

fn ingest_anthropic(
    body: &Value,
    system: &mut String,
    turns: &mut Vec<(String, Vec<Value>)>,
    names: &mut std::collections::HashMap<String, String>,
) {
    match body.get("system") {
        Some(Value::String(text)) => push_system(system, text),
        Some(Value::Array(blocks)) => {
            for block in blocks {
                push_system(system, &flatten_text(block));
            }
        }
        _ => {}
    }
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return;
    };
    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user");
        let gemini_role = if role == "assistant" { "model" } else { "user" };
        let content = &message["content"];
        if content.is_string() {
            for part in parts_of(ClientKind::Anthropic, content) {
                push_part(turns, gemini_role, part);
            }
            continue;
        }
        let Some(blocks) = content.as_array() else {
            continue;
        };
        for block in blocks {
            let ty = block.get("type").and_then(Value::as_str).unwrap_or("text");
            match ty {
                "tool_use" => {
                    let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                    let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                    let args = block.get("input").cloned().unwrap_or(json!({}));
                    if !id.is_empty() {
                        names.insert(id.to_string(), name.to_string());
                    }
                    push_part(turns, "model", function_call_part(name, &args, id));
                }
                "tool_result" => {
                    let id = block
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let name = names.get(id).cloned().unwrap_or_else(|| id.to_string());
                    let payload = block.get("content").cloned().unwrap_or(Value::Null);
                    let payload = if payload.is_array() {
                        Value::String(flatten_text(&payload))
                    } else {
                        payload
                    };
                    push_part(turns, "user", function_response_part(&name, &payload, id));
                }
                _ => {
                    if let Some(part) = one_part(ClientKind::Anthropic, block) {
                        push_part(turns, gemini_role, part);
                    }
                }
            }
        }
    }
}

fn declaration(tool: &Value, schema_key: &str) -> Value {
    let mut decl = Map::new();
    decl.insert(
        "name".into(),
        json!(tool.get("name").and_then(Value::as_str).unwrap_or("")),
    );
    if let Some(description) = tool.get("description").and_then(Value::as_str) {
        decl.insert("description".into(), json!(description));
    }
    if let Some(schema) = tool.get(schema_key) {
        decl.insert("parameters".into(), schema.clone());
    }
    Value::Object(decl)
}

fn function_declarations(kind: ClientKind, body: &Value) -> Vec<Value> {
    let Some(tools) = body.get("tools").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut decls = Vec::new();
    for tool in tools {
        match kind {
            ClientKind::Chat => {
                let function = tool.get("function").unwrap_or(tool);
                if tool.get("type").and_then(Value::as_str) == Some("function")
                    || tool.get("function").is_some()
                {
                    decls.push(declaration(function, "parameters"));
                }
            }
            ClientKind::Responses => {
                if tool
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("function")
                    == "function"
                {
                    decls.push(declaration(tool, "parameters"));
                }
            }
            ClientKind::Anthropic | ClientKind::Count => {
                decls.push(declaration(tool, "input_schema"));
            }
        }
    }
    decls
}

fn tool_config(body: &Value) -> Option<Value> {
    let choice = body.get("tool_choice")?;
    let (mode, name) = match choice {
        Value::String(value) => match value.as_str() {
            "none" => ("NONE", None),
            "required" | "any" => ("ANY", None),
            _ => ("AUTO", None),
        },
        Value::Object(_) => {
            let ty = choice.get("type").and_then(Value::as_str).unwrap_or("");
            match ty {
                "none" => ("NONE", None),
                "any" | "required" => ("ANY", None),
                "function" | "tool" => {
                    let name = choice
                        .pointer("/function/name")
                        .or_else(|| choice.get("name"))
                        .and_then(Value::as_str);
                    ("ANY", name)
                }
                _ => ("AUTO", None),
            }
        }
        _ => return None,
    };
    let mut config = json!({ "mode": mode });
    if let Some(name) = name {
        config["allowedFunctionNames"] = json!([name]);
    }
    Some(json!({ "functionCallingConfig": config }))
}

fn normalize_stops(value: Option<Value>) -> Option<Value> {
    match value? {
        Value::String(text) if !text.is_empty() => Some(json!([text])),
        Value::Array(items) => {
            let stops: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
            (!stops.is_empty()).then(|| json!(stops))
        }
        _ => None,
    }
}

fn reasoning_effort(body: &Value) -> Option<&str> {
    body.get("reasoning_effort")
        .and_then(Value::as_str)
        .or_else(|| body.pointer("/reasoning/effort").and_then(Value::as_str))
        .or_else(|| {
            body.pointer("/output_config/effort")
                .and_then(Value::as_str)
        })
}

fn thinking_config(model: &str, effort: &str) -> Option<Value> {
    if model.contains("2.5") {
        let budget = match effort {
            "minimal" | "low" => 1_024,
            "medium" => 8_192,
            "high" | "xhigh" | "max" => 24_576,
            _ => return None,
        };
        return Some(json!({ "thinkingBudget": budget }));
    }
    let level = match effort {
        "minimal" | "low" => "LOW",
        "medium" => "MEDIUM",
        "high" | "xhigh" | "max" => "HIGH",
        _ => return None,
    };
    Some(json!({ "thinkingLevel": level }))
}

fn wants_json(kind: ClientKind, body: &Value) -> bool {
    let ty = match kind {
        ClientKind::Chat => body.pointer("/response_format/type"),
        ClientKind::Responses => body.pointer("/text/format/type"),
        _ => None,
    };
    matches!(
        ty.and_then(Value::as_str),
        Some("json_object" | "json_schema")
    )
}

fn json_schema(kind: ClientKind, body: &Value) -> Option<Value> {
    match kind {
        ClientKind::Chat => body.pointer("/response_format/json_schema/schema").cloned(),
        ClientKind::Responses => body.pointer("/text/format/schema").cloned(),
        _ => None,
    }
}

fn generation_config(kind: ClientKind, body: &Value, model: &str) -> Option<Value> {
    let mut cfg = Map::new();
    if let Some(temperature) = body.get("temperature").and_then(Value::as_f64) {
        cfg.insert("temperature".into(), json!(temperature));
    }
    if let Some(top_p) = body.get("top_p").and_then(Value::as_f64) {
        cfg.insert("topP".into(), json!(top_p));
    }
    if let Some(top_k) = body.get("top_k").and_then(Value::as_i64) {
        cfg.insert("topK".into(), json!(top_k));
    }
    let max = match kind {
        ClientKind::Chat => body
            .get("max_completion_tokens")
            .or_else(|| body.get("max_tokens")),
        ClientKind::Responses => body.get("max_output_tokens"),
        ClientKind::Anthropic | ClientKind::Count => body.get("max_tokens"),
    };
    if let Some(max) = max.and_then(Value::as_i64) {
        cfg.insert("maxOutputTokens".into(), json!(max));
    }
    let stops = match kind {
        ClientKind::Anthropic | ClientKind::Count => body.get("stop_sequences").cloned(),
        _ => body.get("stop").cloned(),
    };
    if let Some(stops) = normalize_stops(stops) {
        cfg.insert("stopSequences".into(), stops);
    }
    if wants_json(kind, body) {
        cfg.insert("responseMimeType".into(), json!("application/json"));
        if let Some(schema) = json_schema(kind, body) {
            cfg.insert("responseJsonSchema".into(), schema);
        }
    }
    if let Some(effort) = reasoning_effort(body)
        && let Some(thinking) = thinking_config(model, effort)
    {
        cfg.insert("thinkingConfig".into(), thinking);
    }
    (!cfg.is_empty()).then_some(Value::Object(cfg))
}

/// @cc [owner:ghuntley,label:proxy] gemini-request-carries-user-text
/// For an OpenAI chat completion, `to_code_assist` MUST copy each nonempty user message string
/// into a Gemini `contents` part with role `user`, MUST set `project` and `request.session_id`
/// when those values are provided, and MUST NOT put an access token, a refresh token, or an
/// `Authorization` value into the body.
pub fn to_code_assist(
    path: &str,
    body: &Value,
    project: Option<&str>,
    session: Option<&str>,
) -> Value {
    let kind = client_kind(path);
    let model = upstream_model(
        body.get("model")
            .and_then(Value::as_str)
            .unwrap_or("gemini-2.5-pro"),
    );
    let (system, mut contents) = conversation(kind, body);
    if contents.is_empty() {
        contents.push(json!({ "role": "user", "parts": [{ "text": "" }] }));
    }
    if kind == ClientKind::Count {
        return json!({
            "request": {
                "model": format!("models/{model}"),
                "contents": contents,
            }
        });
    }
    let mut request = Map::new();
    request.insert("contents".into(), json!(contents));
    if !system.is_empty() {
        request.insert(
            "systemInstruction".into(),
            json!({ "role": "user", "parts": [{ "text": system }] }),
        );
    }
    let declarations = function_declarations(kind, body);
    if !declarations.is_empty() {
        request.insert(
            "tools".into(),
            json!([{ "functionDeclarations": declarations }]),
        );
    }
    if let Some(config) = tool_config(body) {
        request.insert("toolConfig".into(), config);
    }
    if let Some(config) = generation_config(kind, body, &model) {
        request.insert("generationConfig".into(), config);
    }
    if let Some(session) = session.filter(|session| !session.is_empty()) {
        request.insert("session_id".into(), json!(session));
    }
    let mut out = Map::new();
    out.insert("model".into(), json!(model));
    if let Some(project) = project.filter(|project| !project.is_empty()) {
        out.insert("project".into(), json!(project));
    }
    out.insert(
        "user_prompt_id".into(),
        json!(uuid::Uuid::new_v4().to_string()),
    );
    out.insert("request".into(), Value::Object(request));
    Value::Object(out)
}

fn is_thought(part: &Value) -> bool {
    match part.get("thought") {
        Some(Value::Bool(true)) => true,
        Some(Value::String(text)) if !text.is_empty() => true,
        _ => false,
    }
}

fn candidate_of(upstream: &Value) -> (String, Vec<ToolCall>, Option<String>) {
    let response = upstream.get("response").unwrap_or(upstream);
    let candidate = response.pointer("/candidates/0");
    let finish = candidate
        .and_then(|candidate| candidate.get("finishReason"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut text = String::new();
    let mut tools = Vec::new();
    if let Some(parts) = candidate
        .and_then(|candidate| candidate.pointer("/content/parts"))
        .and_then(Value::as_array)
    {
        for part in parts {
            if is_thought(part) {
                continue;
            }
            if let Some(piece) = part.get("text").and_then(Value::as_str) {
                text.push_str(piece);
            }
            if let Some(call) = part.get("functionCall") {
                let name = call
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let id = call
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("call_{}", tools.len() + 1));
                let arguments = match call.get("args") {
                    Some(Value::String(text)) => text.clone(),
                    Some(other) => serde_json::to_string(other).unwrap_or_else(|_| "{}".into()),
                    None => "{}".into(),
                };
                tools.push(ToolCall {
                    id,
                    name,
                    arguments,
                });
            }
        }
    }
    (text, tools, finish)
}

fn usage_of(upstream: &Value) -> Option<Usage> {
    let response = upstream.get("response").unwrap_or(upstream);
    let meta = response.get("usageMetadata")?;
    let input = meta
        .get("promptTokenCount")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let candidates = meta
        .get("candidatesTokenCount")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let thoughts = meta
        .get("thoughtsTokenCount")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let output = candidates.saturating_add(thoughts);
    let total = meta
        .get("totalTokenCount")
        .and_then(Value::as_i64)
        .unwrap_or(input.saturating_add(output));
    Some(Usage {
        input,
        output,
        total,
    })
}

fn chat_finish(finish: Option<&str>, has_tools: bool) -> &'static str {
    match finish {
        Some("MAX_TOKENS") => "length",
        Some("SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII") => {
            "content_filter"
        }
        _ if has_tools => "tool_calls",
        _ => "stop",
    }
}

fn anthropic_stop(finish: Option<&str>, has_tools: bool) -> &'static str {
    match finish {
        Some("MAX_TOKENS") => "max_tokens",
        Some("SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII") => "refusal",
        _ if has_tools => "tool_use",
        _ => "end_turn",
    }
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn chat_message(
    model: &str,
    text: &str,
    tools: &[ToolCall],
    finish: Option<&str>,
    usage: Option<&Usage>,
) -> Value {
    let content = if text.is_empty() && !tools.is_empty() {
        Value::Null
    } else {
        json!(text)
    };
    let mut message = json!({ "role": "assistant", "content": content });
    if !tools.is_empty() {
        message["tool_calls"] = json!(
            tools
                .iter()
                .map(|tool| json!({
                    "id": tool.id,
                    "type": "function",
                    "function": { "name": tool.name, "arguments": tool.arguments }
                }))
                .collect::<Vec<_>>()
        );
    }
    let mut out = json!({
        "id": format!("chatcmpl-{}", short_id()),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": chat_finish(finish, !tools.is_empty())
        }]
    });
    if let Some(usage) = usage {
        out["usage"] = json!({
            "prompt_tokens": usage.input,
            "completion_tokens": usage.output,
            "total_tokens": usage.total
        });
    }
    out
}

fn responses_message(
    model: &str,
    text: &str,
    tools: &[ToolCall],
    finish: Option<&str>,
    usage: Option<&Usage>,
) -> Value {
    let mut output = Vec::new();
    if !text.is_empty() || tools.is_empty() {
        output.push(json!({
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "output_text", "text": text }]
        }));
    }
    for tool in tools {
        output.push(json!({
            "type": "function_call",
            "call_id": tool.id,
            "name": tool.name,
            "arguments": tool.arguments
        }));
    }
    let status = if matches!(finish, Some("MAX_TOKENS" | "SAFETY")) {
        "incomplete"
    } else {
        "completed"
    };
    let mut out = json!({
        "id": format!("resp_{}", short_id()),
        "object": "response",
        "status": status,
        "model": model,
        "output": output
    });
    if let Some(usage) = usage {
        out["usage"] = json!({
            "input_tokens": usage.input,
            "output_tokens": usage.output,
            "total_tokens": usage.total
        });
    }
    out
}

fn anthropic_message(
    model: &str,
    text: &str,
    tools: &[ToolCall],
    finish: Option<&str>,
    usage: Option<&Usage>,
) -> Value {
    let mut content = Vec::new();
    if !text.is_empty() || tools.is_empty() {
        content.push(json!({ "type": "text", "text": text }));
    }
    for tool in tools {
        let input = serde_json::from_str::<Value>(&tool.arguments).unwrap_or(json!({}));
        content.push(json!({
            "type": "tool_use",
            "id": tool.id,
            "name": tool.name,
            "input": input
        }));
    }
    let mut out = json!({
        "id": format!("msg_{}", short_id()),
        "type": "message",
        "role": "assistant",
        "model": model,
        "stop_reason": anthropic_stop(finish, !tools.is_empty()),
        "content": content
    });
    if let Some(usage) = usage {
        out["usage"] = json!({
            "input_tokens": usage.input,
            "output_tokens": usage.output
        });
    }
    out
}

/// @cc [owner:ghuntley,label:proxy] gemini-response-returns-candidate-text
/// `from_code_assist` MUST return candidate text that is not a thought as chat
/// `choices[0].message.content`, Responses output text, or an Anthropic text block, MUST map
/// `usageMetadata` prompt and candidate counts into that surface's usage object, and MUST NOT
/// include the Code Assist project id or any credential.
pub fn from_code_assist(path: &str, client: &Value, upstream: &Value) -> Value {
    let kind = client_kind(path);
    if kind == ClientKind::Count {
        let total = upstream
            .get("totalTokens")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        return json!({ "input_tokens": total });
    }
    let model = client
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("gemini");
    let (text, tools, finish) = candidate_of(upstream);
    let usage = usage_of(upstream);
    match kind {
        ClientKind::Chat => chat_message(model, &text, &tools, finish.as_deref(), usage.as_ref()),
        ClientKind::Responses => {
            responses_message(model, &text, &tools, finish.as_deref(), usage.as_ref())
        }
        ClientKind::Anthropic | ClientKind::Count => {
            anthropic_message(model, &text, &tools, finish.as_deref(), usage.as_ref())
        }
    }
}

pub fn translate_error(path: &str, status: u16, body: &str) -> String {
    let message = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .map(|message| {
                    let mut message = message.to_string();
                    if message.len() > 300 {
                        message.truncate(300);
                    }
                    message
                })
        })
        .unwrap_or_else(|| "upstream request failed".into());
    let code = if is_quota_exhausted(status, body) {
        "resource_exhausted"
    } else if matches!(status, 401 | 403) {
        "authentication_error"
    } else if status >= 500 {
        "api_error"
    } else {
        "invalid_request_error"
    };
    let value = match client_kind(path) {
        ClientKind::Anthropic | ClientKind::Count => json!({
            "type": "error",
            "error": { "type": code, "message": message }
        }),
        _ => json!({
            "error": { "message": message, "type": code, "code": code }
        }),
    };
    value.to_string()
}

pub struct GeminiTranslator {
    kind: ClientKind,
    stream: bool,
    model: String,
    id: String,
    created: i64,
    buf: Vec<u8>,
    data: Vec<u8>,
    started: bool,
    terminal_sent: bool,
    text: String,
    tools: Vec<ToolCall>,
    next_block: i64,
    text_open: bool,
    input_tokens: i64,
    output_tokens: i64,
    saw_usage: bool,
}

impl GeminiTranslator {
    pub fn new(path: &str, client: &Value) -> Self {
        let kind = client_kind(path);
        let stream = kind != ClientKind::Count
            && client.get("stream").and_then(Value::as_bool) == Some(true);
        let model = client
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("gemini")
            .to_string();
        let id = match kind {
            ClientKind::Chat => format!("chatcmpl-{}", short_id()),
            ClientKind::Responses => format!("resp_{}", short_id()),
            ClientKind::Anthropic | ClientKind::Count => format!("msg_{}", short_id()),
        };
        Self {
            kind,
            stream,
            model,
            id,
            created: chrono::Utc::now().timestamp(),
            buf: Vec::new(),
            data: Vec::new(),
            started: false,
            terminal_sent: false,
            text: String::new(),
            tools: Vec::new(),
            next_block: 0,
            text_open: false,
            input_tokens: 0,
            output_tokens: 0,
            saw_usage: false,
        }
    }

    fn push_bytes(&mut self, chunk: &[u8]) -> Vec<u8> {
        if !self.stream {
            self.buf.extend_from_slice(chunk);
            return Vec::new();
        }
        let mut out = Vec::new();
        for &byte in chunk {
            if byte == b'\n' {
                let line = std::mem::take(&mut self.buf);
                let line = line.strip_suffix(b"\r").unwrap_or(&line).to_vec();
                out.extend(self.push_line(&line));
            } else {
                self.buf.push(byte);
            }
        }
        out
    }

    fn push_line(&mut self, line: &[u8]) -> Vec<u8> {
        if line.is_empty() {
            return self.flush_data();
        }
        let Some(data) = line.strip_prefix(b"data:") else {
            return Vec::new();
        };
        let data = data.strip_prefix(b" ").unwrap_or(data);
        if data == b"[DONE]" {
            return self.terminal();
        }
        if !self.data.is_empty() {
            self.data.push(b'\n');
        }
        self.data.extend_from_slice(data);
        Vec::new()
    }

    fn flush_data(&mut self) -> Vec<u8> {
        if self.data.is_empty() {
            return Vec::new();
        }
        let raw = std::mem::take(&mut self.data);
        let Ok(value) = serde_json::from_slice::<Value>(&raw) else {
            return Vec::new();
        };
        if value.get("error").is_some() {
            return self.error_event(&value);
        }
        self.emit_candidate(&value)
    }

    fn error_event(&mut self, value: &Value) -> Vec<u8> {
        let message = value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("upstream request failed");
        let code = value
            .pointer("/error/status")
            .and_then(Value::as_str)
            .unwrap_or("api_error");
        self.terminal_sent = true;
        match self.kind {
            ClientKind::Chat => sse_data(&json!({
                "error": { "message": message, "type": code, "code": code }
            })),
            ClientKind::Responses => sse_event(
                "error",
                &json!({
                    "type": "error",
                    "code": code,
                    "message": message
                }),
            ),
            ClientKind::Anthropic | ClientKind::Count => sse_event(
                "error",
                &json!({
                    "type": "error",
                    "error": { "type": code, "message": message }
                }),
            ),
        }
    }

    fn emit_candidate(&mut self, upstream: &Value) -> Vec<u8> {
        let (piece, tools, finish) = candidate_of(upstream);
        if let Some(usage) = usage_of(upstream) {
            self.input_tokens = usage.input;
            self.output_tokens = usage.output;
            self.saw_usage = true;
        }
        if !piece.is_empty() {
            self.text.push_str(&piece);
        }
        let new_tools = tools.clone();
        self.tools.extend(tools);
        match self.kind {
            ClientKind::Chat => self.emit_chat(&piece, &new_tools, finish.as_deref()),
            ClientKind::Responses => self.emit_responses(&piece, &new_tools, finish.as_deref()),
            ClientKind::Anthropic | ClientKind::Count => {
                self.emit_anthropic(&piece, &new_tools, finish.as_deref())
            }
        }
    }

    fn emit_chat(&mut self, piece: &str, tools: &[ToolCall], finish: Option<&str>) -> Vec<u8> {
        let mut out = Vec::new();
        if !piece.is_empty() {
            let mut delta = json!({});
            if !self.started {
                delta["role"] = json!("assistant");
            }
            delta["content"] = json!(piece);
            out.extend(sse_data(&self.chat_chunk(delta, None)));
            self.started = true;
        }
        for (offset, tool) in tools.iter().enumerate() {
            let delta = json!({
                "tool_calls": [{
                    "index": self.tools.len() - tools.len() + offset,
                    "id": tool.id,
                    "type": "function",
                    "function": { "name": tool.name, "arguments": tool.arguments }
                }]
            });
            out.extend(sse_data(&self.chat_chunk(delta, None)));
            self.started = true;
        }
        if let Some(finish) = finish {
            let usage = self.saw_usage.then(|| {
                json!({
                    "prompt_tokens": self.input_tokens,
                    "completion_tokens": self.output_tokens,
                    "total_tokens": self.input_tokens.saturating_add(self.output_tokens)
                })
            });
            let mut chunk = self.chat_chunk(
                json!({}),
                Some(chat_finish(Some(finish), !self.tools.is_empty())),
            );
            if let Some(usage) = usage {
                chunk["usage"] = usage;
            }
            out.extend(sse_data(&chunk));
            self.started = true;
        }
        out
    }

    fn chat_chunk(&self, delta: Value, finish: Option<&str>) -> Value {
        json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": delta,
                "finish_reason": finish
            }]
        })
    }

    fn emit_responses(&mut self, piece: &str, tools: &[ToolCall], finish: Option<&str>) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.started {
            out.extend(sse_event(
                "response.created",
                &json!({
                    "type": "response.created",
                    "response": {
                        "id": self.id,
                        "object": "response",
                        "status": "in_progress",
                        "model": self.model
                    }
                }),
            ));
            self.started = true;
        }
        if !piece.is_empty() {
            if self.text == piece {
                out.extend(sse_event(
                    "response.output_item.added",
                    &json!({
                        "type": "response.output_item.added",
                        "output_index": 0,
                        "item": {
                            "type": "message",
                            "role": "assistant",
                            "id": format!("msg_{}", self.id),
                            "content": []
                        }
                    }),
                ));
            }
            out.extend(sse_event(
                "response.output_text.delta",
                &json!({
                    "type": "response.output_text.delta",
                    "output_index": 0,
                    "content_index": 0,
                    "delta": piece
                }),
            ));
        }
        for tool in tools {
            out.extend(sse_event(
                "response.output_item.added",
                &json!({
                    "type": "response.output_item.added",
                    "output_index": 1,
                    "item": {
                        "type": "function_call",
                        "call_id": tool.id,
                        "name": tool.name,
                        "arguments": tool.arguments
                    }
                }),
            ));
        }
        if finish.is_some() {
            out.extend(self.responses_completed());
        }
        out
    }

    fn responses_completed(&mut self) -> Vec<u8> {
        self.terminal_sent = true;
        let mut response = responses_message(
            &self.model.clone(),
            &self.text.clone(),
            &self.tools.clone(),
            None,
            self.saw_usage
                .then(|| Usage {
                    input: self.input_tokens,
                    output: self.output_tokens,
                    total: self.input_tokens.saturating_add(self.output_tokens),
                })
                .as_ref(),
        );
        response["id"] = json!(self.id);
        sse_event(
            "response.completed",
            &json!({ "type": "response.completed", "response": response }),
        )
    }

    fn emit_anthropic(&mut self, piece: &str, tools: &[ToolCall], finish: Option<&str>) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.started {
            out.extend(sse_event(
                "message_start",
                &json!({
                    "type": "message_start",
                    "message": {
                        "id": self.id,
                        "type": "message",
                        "role": "assistant",
                        "model": self.model,
                        "content": [],
                        "usage": { "input_tokens": self.input_tokens, "output_tokens": 0 }
                    }
                }),
            ));
            self.started = true;
        }
        if !piece.is_empty() {
            if !self.text_open {
                out.extend(sse_event(
                    "content_block_start",
                    &json!({
                        "type": "content_block_start",
                        "index": self.next_block,
                        "content_block": { "type": "text", "text": "" }
                    }),
                ));
                self.text_open = true;
            }
            out.extend(sse_event(
                "content_block_delta",
                &json!({
                    "type": "content_block_delta",
                    "index": self.next_block,
                    "delta": { "type": "text_delta", "text": piece }
                }),
            ));
        }
        for tool in tools {
            if self.text_open {
                out.extend(self.close_block());
            }
            let index = self.next_block;
            let input = serde_json::from_str::<Value>(&tool.arguments).unwrap_or(json!({}));
            out.extend(sse_event(
                "content_block_start",
                &json!({
                    "type": "content_block_start",
                    "index": index,
                    "content_block": {
                        "type": "tool_use",
                        "id": tool.id,
                        "name": tool.name,
                        "input": {}
                    }
                }),
            ));
            out.extend(sse_event(
                "content_block_delta",
                &json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": { "type": "input_json_delta", "partial_json": input.to_string() }
                }),
            ));
            out.extend(sse_event(
                "content_block_stop",
                &json!({ "type": "content_block_stop", "index": index }),
            ));
            self.next_block += 1;
        }
        if let Some(finish) = finish {
            if self.text_open {
                out.extend(self.close_block());
            }
            out.extend(sse_event(
                "message_delta",
                &json!({
                    "type": "message_delta",
                    "delta": { "stop_reason": anthropic_stop(Some(finish), !self.tools.is_empty()) },
                    "usage": { "output_tokens": self.output_tokens }
                }),
            ));
            out.extend(self.anthropic_stop_event());
        }
        out
    }

    fn close_block(&mut self) -> Vec<u8> {
        let index = self.next_block;
        self.next_block += 1;
        self.text_open = false;
        sse_event(
            "content_block_stop",
            &json!({ "type": "content_block_stop", "index": index }),
        )
    }

    fn anthropic_stop_event(&mut self) -> Vec<u8> {
        self.terminal_sent = true;
        sse_event("message_stop", &json!({ "type": "message_stop" }))
    }

    fn terminal(&mut self) -> Vec<u8> {
        if self.terminal_sent {
            return Vec::new();
        }
        self.terminal_sent = true;
        match self.kind {
            ClientKind::Chat => b"data: [DONE]\n\n".to_vec(),
            ClientKind::Responses => self.responses_completed(),
            ClientKind::Anthropic | ClientKind::Count => {
                let mut out = Vec::new();
                if !self.started {
                    out.extend(self.emit_anthropic("", &[], Some("STOP")));
                    return out;
                }
                if self.text_open {
                    out.extend(self.close_block());
                }
                out.extend(sse_event(
                    "message_delta",
                    &json!({
                        "type": "message_delta",
                        "delta": { "stop_reason": anthropic_stop(Some("STOP"), !self.tools.is_empty()) },
                        "usage": { "output_tokens": self.output_tokens }
                    }),
                ));
                self.terminal_sent = false;
                out.extend(self.anthropic_stop_event());
                out
            }
        }
    }

    fn finish_body(&mut self) -> Vec<u8> {
        if !self.stream {
            let value = serde_json::from_slice::<Value>(&self.buf).unwrap_or(Value::Null);
            let client = json!({ "model": self.model });
            let path = match self.kind {
                ClientKind::Chat => "/chat/completions",
                ClientKind::Responses => "/responses",
                ClientKind::Anthropic => "/messages",
                ClientKind::Count => "/messages/count_tokens",
            };
            return serde_json::to_vec(&from_code_assist(path, &client, &value))
                .unwrap_or_default();
        }
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            out.extend(self.push_line(&line));
        }
        out.extend(self.flush_data());
        out.extend(self.terminal());
        out
    }
}

fn sse_data(value: &Value) -> Vec<u8> {
    let mut out = b"data: ".to_vec();
    out.extend(serde_json::to_vec(value).unwrap_or_default());
    out.extend(b"\n\n");
    out
}

fn sse_event(name: &str, value: &Value) -> Vec<u8> {
    let mut out = format!("event: {name}\ndata: ").into_bytes();
    out.extend(serde_json::to_vec(value).unwrap_or_default());
    out.extend(b"\n\n");
    out
}

impl ResponseAdapter for GeminiTranslator {
    fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.push_bytes(chunk)
    }

    fn finish(&mut self) -> Vec<u8> {
        self.finish_body()
    }
}

async fn read_token(response: reqwest::Response) -> Result<TokenPair, AuthError> {
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let code = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("rejected");
        return Err(AuthError::Failed(format!(
            "token endpoint rejected the grant ({code})"
        )));
    }
    let access_token = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AuthError::Failed("token response had no access token".into()))?
        .to_string();
    let refresh_token = body
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_string);
    let expires_in = body
        .get("expires_in")
        .and_then(Value::as_i64)
        .unwrap_or(3_600);
    Ok(TokenPair {
        access_token,
        refresh_token,
        expires_in,
    })
}

pub async fn exchange(client: &Client, code: &str, verifier: &str) -> Result<TokenPair, AuthError> {
    let app = oauth_app()?;
    let response = client
        .post(TOKEN_URL)
        .form(&exchange_form(code, verifier, &app.id, &app.secret))
        .send()
        .await
        .map_err(|_| AuthError::Failed("token endpoint unreachable".into()))?;
    read_token(response).await
}

pub async fn refresh(client: &Client, refresh_token: &str) -> Result<TokenPair, AuthError> {
    let app = oauth_app()?;
    let response = client
        .post(TOKEN_URL)
        .form(&refresh_form(refresh_token, &app.id, &app.secret))
        .send()
        .await
        .map_err(|_| AuthError::Failed("token endpoint unreachable".into()))?;
    read_token(response).await
}

async fn code_assist(
    client: &Client,
    token: &str,
    method: &str,
    body: &Value,
) -> Result<Value, AuthError> {
    let response = client
        .post(format!("{}/v1internal:{method}", endpoint()))
        .bearer_auth(token)
        .header(http::header::USER_AGENT, USER_AGENT)
        .json(body)
        .send()
        .await
        .map_err(|_| AuthError::Failed("code assist request failed".into()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(AuthError::Rejected(status.as_u16()));
    }
    response
        .json()
        .await
        .map_err(|_| AuthError::Failed("code assist response was not json".into()))
}

async fn fetch_email(client: &Client, token: &str) -> Option<String> {
    let response = client
        .get(USERINFO_URL)
        .bearer_auth(token)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body: Value = response.json().await.ok()?;
    body.get("email")
        .and_then(Value::as_str)
        .filter(|email| !email.is_empty())
        .map(str::to_string)
}

fn metadata(project: Option<&str>) -> Value {
    let mut meta = json!({
        "ideType": "IDE_UNSPECIFIED",
        "platform": "PLATFORM_UNSPECIFIED",
        "pluginType": "GEMINI"
    });
    if let Some(project) = project {
        meta["duetProject"] = json!(project);
    }
    meta
}

fn tier_of(value: &Value) -> Option<(&str, Option<&str>)> {
    let tier = value
        .get("paidTier")
        .filter(|tier| tier.get("id").and_then(Value::as_str).is_some())
        .or_else(|| value.get("currentTier"));
    let id = tier?.get("id").and_then(Value::as_str)?;
    let name = tier
        .and_then(|tier| tier.get("name"))
        .and_then(Value::as_str);
    Some((id, name))
}

fn project_of(value: &Value) -> Option<String> {
    value
        .get("cloudaicompanionProject")
        .and_then(|project| {
            project
                .as_str()
                .or_else(|| project.get("id").and_then(Value::as_str))
        })
        .filter(|project| !project.is_empty())
        .map(str::to_string)
}

fn ineligible_message(value: &Value) -> String {
    let reasons: Vec<String> = value
        .get("ineligibleTiers")
        .and_then(Value::as_array)
        .map(|tiers| {
            tiers
                .iter()
                .filter_map(|tier| {
                    let message = tier.get("reasonMessage").and_then(Value::as_str)?;
                    let url = tier.get("validationUrl").and_then(Value::as_str);
                    Some(match url {
                        Some(url) => format!("{message} ({url})"),
                        None => message.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if reasons.is_empty() {
        "this Google account is not eligible for Code Assist".into()
    } else {
        reasons.join("; ")
    }
}

async fn setup_user(
    client: &Client,
    token: &str,
    supplied_project: Option<&str>,
) -> Result<(String, String), AuthError> {
    let mut request = json!({ "metadata": metadata(supplied_project) });
    if let Some(project) = supplied_project {
        request["cloudaicompanionProject"] = json!(project);
    }
    let loaded = code_assist(client, token, "loadCodeAssist", &request).await?;
    if loaded.get("currentTier").is_some() || loaded.get("paidTier").is_some() {
        let (id, name) = tier_of(&loaded).unwrap_or(("standard-tier", None));
        let plan = plan_for_tier(id, name);
        let project = project_of(&loaded).or_else(|| supplied_project.map(str::to_string));
        return project
            .map(|project| (project, plan))
            .ok_or_else(|| AuthError::Failed(ineligible_message(&loaded)));
    }
    let tier = loaded
        .get("allowedTiers")
        .and_then(Value::as_array)
        .and_then(|tiers| {
            tiers
                .iter()
                .find(|tier| tier.get("isDefault").and_then(Value::as_bool) == Some(true))
                .or_else(|| tiers.first())
        });
    let tier_id = tier
        .and_then(|tier| tier.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("legacy-tier");
    let tier_name = tier
        .and_then(|tier| tier.get("name"))
        .and_then(Value::as_str);
    let mut onboard = json!({
        "tierId": tier_id,
        "metadata": metadata(supplied_project)
    });
    if tier_id != "free-tier"
        && let Some(project) = supplied_project
    {
        onboard["cloudaicompanionProject"] = json!(project);
    }
    let mut operation = code_assist(client, token, "onboardUser", &onboard).await?;
    for _ in 0..15 {
        if operation.get("done").and_then(Value::as_bool) == Some(true) {
            break;
        }
        let Some(name) = operation.get("name").and_then(Value::as_str) else {
            break;
        };
        tokio::time::sleep(Duration::from_secs(2)).await;
        let response = client
            .get(format!("{}/v1internal/{name}", endpoint()))
            .bearer_auth(token)
            .header(http::header::USER_AGENT, USER_AGENT)
            .send()
            .await
            .map_err(|_| AuthError::Failed("code assist operation failed".into()))?;
        if !response.status().is_success() {
            return Err(AuthError::Rejected(response.status().as_u16()));
        }
        operation = response
            .json()
            .await
            .map_err(|_| AuthError::Failed("code assist operation was not json".into()))?;
    }
    let project = operation
        .pointer("/response/cloudaicompanionProject/id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| supplied_project.map(str::to_string))
        .ok_or_else(|| {
            AuthError::Failed(
                "Code Assist did not return a project id; pass one when adding the account".into(),
            )
        })?;
    Ok((project, plan_for_tier(tier_id, tier_name)))
}

pub async fn fetch_models(
    client: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<ModelInfo>, String> {
    let response = client
        .post(format!("{}/v1internal:fetchAvailableModels", endpoint()))
        .bearer_auth(token)
        .header(http::header::USER_AGENT, USER_AGENT)
        .json(&json!({ "project": project }))
        .send()
        .await
        .map_err(|_| "model list request failed".to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("model list returned {}", status.as_u16()));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|_| "model list was not json".to_string())?;
    Ok(parse_available_models(&body))
}

pub async fn refresh_catalog(
    client: &Client,
    store: &Store,
    pool: &Mutex<PoolCore>,
    token: &str,
    project: &str,
) -> Result<usize, String> {
    let live = fetch_models(client, token, project).await?;
    if live.is_empty() {
        return Ok(0);
    }
    let catalog = merge_catalog(&live, &store.catalog(BackendId::Gemini), &default_catalog());
    store.set_catalog(BackendId::Gemini, &catalog);
    pool.lock().unwrap().set_catalog(
        BackendId::Gemini,
        catalog.iter().map(|model| model.id.clone()).collect(),
    );
    Ok(catalog.len())
}

pub async fn fetch_quota(
    client: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<QuotaBucket>, String> {
    let response = client
        .post(format!("{}/v1internal:retrieveUserQuota", endpoint()))
        .bearer_auth(token)
        .header(http::header::USER_AGENT, USER_AGENT)
        .json(&json!({ "project": project }))
        .send()
        .await
        .map_err(|_| "quota request failed".to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("quota request returned {}", status.as_u16()));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|_| "quota response was not json".to_string())?;
    Ok(parse_quota(&body))
}

pub async fn start_flow(
    _client: Client,
    _store: Arc<Store>,
    flows: FlowRegistry,
    replace_account: Option<String>,
    project: Option<String>,
    label: Option<String>,
) -> Result<String, AuthError> {
    let app = oauth_app()?;
    let pkce = new_pkce();
    let url = authorize_url(&pkce, &app.id);
    let verifier = pkce.verifier;
    Ok(flows.create_with_oauth(
        BackendId::Gemini,
        FlowState::AwaitingCode { authorize_url: url },
        replace_account,
        Some(OAuthState {
            verifier,
            state: pkce.state,
            project: project.filter(|project| !project.trim().is_empty()),
            label: label.filter(|label| !label.trim().is_empty()),
        }),
    ))
}

pub async fn submit_code(
    client: &Client,
    store: &Store,
    flows: &FlowRegistry,
    flow_id: &str,
    pasted: &str,
) -> Result<Account, AuthError> {
    let Some(flow) = flows.get(flow_id) else {
        return Err(AuthError::Failed("unknown flow".into()));
    };
    if flow.backend != BackendId::Gemini {
        return Err(AuthError::Failed("flow is not a gemini login".into()));
    }
    let Some(oauth) = flow.oauth else {
        return Err(AuthError::Failed("flow is not awaiting a code".into()));
    };
    let code = pasted_code(pasted);
    if code.is_empty() {
        return Err(AuthError::Failed("no authorization code".into()));
    }
    let tokens = exchange(client, code, &oauth.verifier).await?;
    let refresh_token = tokens
        .refresh_token
        .clone()
        .or_else(|| {
            flow.replace_account
                .as_deref()
                .and_then(|id| store.get_account(id))
                .and_then(|account| account.refresh_token)
        })
        .ok_or_else(|| {
            AuthError::Failed(
                "Google did not return a refresh token; approve the consent screen and try again"
                    .into(),
            )
        })?;
    let (project, plan) =
        setup_user(client, &tokens.access_token, oauth.project.as_deref()).await?;
    let email = fetch_email(client, &tokens.access_token).await;
    let label = oauth
        .label
        .clone()
        .or(email)
        .unwrap_or_else(|| "gemini".into());
    let ts = now_ms();
    let mut account = match flow
        .replace_account
        .as_deref()
        .and_then(|id| store.get_account(id))
    {
        Some(existing) => existing,
        None => crate::flows::new_account(BackendId::Gemini, label.clone()),
    };
    account.label = label;
    account.backend = BackendId::Gemini;
    account.refresh_token = Some(refresh_token);
    account.access_token = Some(tokens.access_token);
    account.expires_at = ts.saturating_add(tokens.expires_in.saturating_mul(1_000));
    account.token_refreshed_at = ts;
    account.account_id = Some(project);
    account.plan = Some(plan.clone());
    account.updated_at = ts;
    if plan == "free" {
        account.status = AccountStatus::Disabled;
        account.disabled_reason = Some(FREE_PLAN_REASON.to_string());
    } else {
        account.status = AccountStatus::Healthy;
        account.disabled_reason = None;
        account.reset_at = 0;
    }
    store.upsert_account(&account);
    flows.set_state(
        flow_id,
        FlowState::Authorized {
            account_id: account.id.clone(),
        },
    );
    Ok(account)
}

pub struct GeminiBackend {
    pub cooldown_ms: i64,
}

impl Backend for GeminiBackend {
    fn id(&self) -> BackendId {
        BackendId::Gemini
    }

    fn surfaces(&self) -> &'static [Surface] {
        &[Surface::OpenAI, Surface::Anthropic]
    }

    fn default_cooldown_ms(&self) -> i64 {
        self.cooldown_ms
    }

    /// @cc [owner:ghuntley,label:proxy] gemini-admits-its-own-models
    /// `accepts_client` MUST admit a request only when its model id, after stripping a `models/`
    /// or `gemini/` prefix, starts with `gemini` or `gemma`. It MUST NOT admit a Claude model,
    /// so a non-Claude-Code client on the Anthropic surface is still rejected for Claude models.
    fn accepts_client(&self, _headers: &HeaderMap, body: &Value) -> bool {
        let model = upstream_model(body.get("model").and_then(Value::as_str).unwrap_or(""));
        model.starts_with("gemini") || model.starts_with("gemma")
    }

    fn usage_dialect(&self, path: &str) -> UsageDialect {
        match client_kind(path) {
            ClientKind::Chat => UsageDialect::Chat,
            ClientKind::Anthropic | ClientKind::Count => UsageDialect::Anthropic,
            ClientKind::Responses => UsageDialect::Responses,
        }
    }

    fn rewrite_url(&self, path: &str, account: &Account) -> String {
        self.upstream_url(path, account, &Value::Null)
    }

    fn upstream_url(&self, path: &str, _account: &Account, body: &Value) -> String {
        let method = if path.contains("count_tokens") {
            "countTokens"
        } else if body.get("stream").and_then(Value::as_bool) == Some(true) {
            "streamGenerateContent"
        } else {
            "generateContent"
        };
        let base = endpoint();
        if method == "streamGenerateContent" {
            format!("{base}/v1internal:{method}?alt=sse")
        } else {
            format!("{base}/v1internal:{method}")
        }
    }

    fn inject_headers(
        &self,
        _account: &Account,
        token: &str,
        _sticky: Option<&str>,
        body: &Value,
        _client: &HeaderMap,
        headers: &mut HeaderMap,
    ) {
        if let Ok(value) = http::HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(http::header::AUTHORIZATION, value);
        }
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static(USER_AGENT),
        );
        if body.get("stream").and_then(Value::as_bool) == Some(true) {
            headers.insert(
                http::header::ACCEPT,
                http::HeaderValue::from_static("text/event-stream"),
            );
        }
    }

    fn finalize_body(&self, account: &Account, path: &str, body: &mut Value, sticky: Option<&str>) {
        let session = sticky
            .filter(|sticky| !sticky.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| crate::opencode_go::derived_session(body));
        *body = to_code_assist(path, body, account.account_id.as_deref(), Some(&session));
    }

    fn response_adapter(
        &self,
        path: &str,
        client_body: &Value,
    ) -> Option<Box<dyn ResponseAdapter>> {
        Some(Box::new(GeminiTranslator::new(path, client_body)))
    }

    fn translate_error(&self, path: &str, status: u16, body: &str) -> Option<String> {
        Some(translate_error(path, status, body))
    }

    fn classify(&self, status: u16, body: &str, headers: &HeaderMap, now_ms: i64) -> Outcome {
        if let Some(until_ms) = quota_until_ms(status, body, headers, self.cooldown_ms, now_ms) {
            return Outcome::QuotaExhausted { until_ms };
        }
        crate::health::classify(status, headers, self.cooldown_ms, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_is_the_cli_paste_back_flow_without_the_secret() {
        let pkce = Pkce {
            verifier: "verifier".into(),
            challenge: "challenge".into(),
            state: "state".into(),
        };
        let url = authorize_url(&pkce, "test-client");
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("client_id=test-client"));
        assert!(url.contains("codeassist.google.com%2Fauthcode"));
        assert!(url.contains("code_challenge=challenge"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("cloud-platform"));
        assert!(!url.contains("client_secret"));
        assert!(!url.contains("test-secret"));
        assert!(!url.contains("access_token"));
        assert!(!url.contains("refresh_token"));
    }

    #[test]
    fn refresh_form_uses_the_refresh_grant() {
        let form = refresh_form("refresh-token-value", "test-client", "test-secret");
        assert!(form.contains(&("grant_type", "refresh_token")));
        assert!(form.contains(&("refresh_token", "refresh-token-value")));
        assert!(form.contains(&("client_id", "test-client")));
        assert!(form.contains(&("client_secret", "test-secret")));
    }

    #[test]
    fn chat_text_tools_and_usage_round_trip() {
        let body = json!({
            "model": "gemini/gemini-2.5-pro",
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": "what is the weather in Paris?"},
                {"role": "assistant", "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}
                }]},
                {"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
                {"role": "user", "content": [
                    {"type": "text", "text": "thanks"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
                ]}
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "weather",
                    "parameters": {"type": "object"}
                }
            }],
            "tool_choice": "auto",
            "max_tokens": 32,
            "temperature": 0.2
        });
        let upstream = to_code_assist(
            "/v1/chat/completions",
            &body,
            Some("ultra-project"),
            Some("sess-1"),
        );
        assert_eq!(upstream["model"], "gemini-2.5-pro");
        assert_eq!(upstream["project"], "ultra-project");
        assert_eq!(upstream["request"]["session_id"], "sess-1");
        assert_eq!(
            upstream["request"]["systemInstruction"]["parts"][0]["text"],
            "be brief"
        );
        assert_eq!(upstream["request"]["contents"][0]["role"], "user");
        assert_eq!(
            upstream["request"]["contents"][0]["parts"][0]["text"],
            "what is the weather in Paris?"
        );
        assert_eq!(
            upstream["request"]["contents"][1]["parts"][0]["functionCall"]["name"],
            "get_weather"
        );
        assert_eq!(
            upstream["request"]["contents"][2]["parts"][0]["functionResponse"]["response"]["result"],
            "sunny"
        );
        assert_eq!(
            upstream["request"]["contents"][2]["parts"][2]["inlineData"]["mimeType"],
            "image/png"
        );
        assert_eq!(
            upstream["request"]["tools"][0]["functionDeclarations"][0]["name"],
            "get_weather"
        );
        assert_eq!(
            upstream["request"]["toolConfig"]["functionCallingConfig"]["mode"],
            "AUTO"
        );
        assert_eq!(
            upstream["request"]["generationConfig"]["maxOutputTokens"],
            32
        );
        let rendered = upstream.to_string();
        assert!(!rendered.contains("Bearer "));
        assert!(!rendered.contains("client_secret"));

        let response = json!({
            "response": {
                "candidates": [{
                    "content": {
                        "role": "model",
                        "parts": [
                            {"text": "secret thought", "thought": true},
                            {"text": "It is sunny."},
                            {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}, "id": "call_9"}}
                        ]
                    },
                    "finishReason": "STOP"
                }],
                "usageMetadata": {
                    "promptTokenCount": 11,
                    "candidatesTokenCount": 4,
                    "thoughtsTokenCount": 2,
                    "totalTokenCount": 17
                }
            }
        });
        let back = from_code_assist("/chat/completions", &body, &response);
        assert_eq!(back["choices"][0]["message"]["content"], "It is sunny.");
        assert_eq!(
            back["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            "get_weather"
        );
        assert_eq!(back["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(back["usage"]["prompt_tokens"], 11);
        assert_eq!(back["usage"]["completion_tokens"], 6);
        assert!(back.get("project").is_none());
    }

    #[test]
    fn responses_and_anthropic_shapes_translate() {
        let responses = json!({
            "model": "gemini-2.5-flash",
            "instructions": "terse",
            "input": "hello",
            "max_output_tokens": 16
        });
        let upstream = to_code_assist("/responses", &responses, None, Some("sess"));
        assert_eq!(
            upstream["request"]["contents"][0]["parts"][0]["text"],
            "hello"
        );
        assert_eq!(
            upstream["request"]["systemInstruction"]["parts"][0]["text"],
            "terse"
        );
        let back = from_code_assist(
            "/responses",
            &responses,
            &json!({
                "response": {
                    "candidates": [{
                        "content": {"parts": [{"text": "hi"}]},
                        "finishReason": "STOP"
                    }],
                    "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1, "totalTokenCount": 3}
                }
            }),
        );
        assert_eq!(back["output"][0]["content"][0]["text"], "hi");
        assert_eq!(back["usage"]["input_tokens"], 2);
        assert_eq!(back["usage"]["output_tokens"], 1);

        let anthropic = json!({
            "model": "gemini-3-pro-preview",
            "max_tokens": 64,
            "system": "be kind",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "ping"}]},
                {"role": "assistant", "content": [{
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "lookup",
                    "input": {"q": "ping"}
                }]},
                {"role": "user", "content": [{
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": "pong"
                }]}
            ],
            "tools": [{
                "name": "lookup",
                "description": "look",
                "input_schema": {"type": "object"}
            }]
        });
        let upstream = to_code_assist("/v1/messages", &anthropic, Some("p"), None);
        assert_eq!(
            upstream["request"]["systemInstruction"]["parts"][0]["text"],
            "be kind"
        );
        assert_eq!(
            upstream["request"]["contents"][0]["parts"][0]["text"],
            "ping"
        );
        assert_eq!(
            upstream["request"]["contents"][1]["parts"][0]["functionCall"]["name"],
            "lookup"
        );
        assert_eq!(
            upstream["request"]["contents"][2]["parts"][0]["functionResponse"]["name"],
            "lookup"
        );
        assert_eq!(
            upstream["request"]["generationConfig"]["thinkingConfig"]["thinkingLevel"],
            Value::Null
        );
        let counted = to_code_assist("/messages/count_tokens", &anthropic, None, None);
        assert_eq!(counted["request"]["model"], "models/gemini-3-pro-preview");
        let count = from_code_assist(
            "/messages/count_tokens",
            &anthropic,
            &json!({ "totalTokens": 9 }),
        );
        assert_eq!(count["input_tokens"], 9);
    }

    #[test]
    fn reasoning_effort_picks_the_family_thinking_config() {
        let flash = json!({
            "model": "gemini-2.5-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "low"
        });
        let upstream = to_code_assist("/chat/completions", &flash, None, None);
        assert_eq!(
            upstream["request"]["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            1_024
        );
        let pro = json!({
            "model": "gemini-3-pro-preview",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "high"
        });
        let upstream = to_code_assist("/chat/completions", &pro, None, None);
        assert_eq!(
            upstream["request"]["generationConfig"]["thinkingConfig"]["thinkingLevel"],
            "HIGH"
        );
    }

    #[test]
    fn stream_chunks_reassemble_chat_text_tools_and_done() {
        let client = json!({
            "model": "gemini-2.5-pro",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let mut translator = GeminiTranslator::new("/v1/chat/completions", &client);
        let first = translator.push(
            b"data: {\"response\":{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hel\"}]}}]}}\n",
        );
        assert!(first.is_empty(), "a partial line stays buffered");
        let second = translator.push(b"\ndata: {\"response\":{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"lo\"},{\"functionCall\":{\"name\":\"ping\",\"args\":{}}}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":2,\"totalTokenCount\":5}}}\n\n");
        let text = String::from_utf8(second.clone()).unwrap();
        assert!(text.contains("\"content\":\"hel\""));
        assert!(text.contains("\"content\":\"lo\""));
        assert!(text.contains("\"name\":\"ping\""));
        assert!(text.contains("\"finish_reason\":\"tool_calls\""));
        assert!(text.contains("\"prompt_tokens\":3"));
        let tail = String::from_utf8(translator.finish()).unwrap();
        assert!(tail.contains("[DONE]"));
    }

    #[test]
    fn responses_stream_emits_output_before_completed() {
        let client = json!({"model": "gemini-2.5-pro", "stream": true, "input": "hi"});
        let mut translator = GeminiTranslator::new("/responses", &client);
        let bytes = translator.push(
            b"data: {\"response\":{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"yo\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2}}}\n\n",
        );
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("response.output_text.delta"));
        assert!(text.contains("response.completed"));
        assert!(text.contains("\"output_tokens\":1"));
        assert!(translator.finish().is_empty());
    }

    #[test]
    fn quota_deadline_prefers_retry_delay_then_header_then_cooldown() {
        let headers = HeaderMap::new();
        let body = r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"Resource has been exhausted","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"30s"}]}}"#;
        assert_eq!(
            quota_until_ms(429, body, &headers, 60_000, 1_000),
            Some(31_000)
        );
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", http::HeaderValue::from_static("15"));
        assert_eq!(
            quota_until_ms(
                429,
                r#"{"error":{"status":"RESOURCE_EXHAUSTED"}}"#,
                &headers,
                60_000,
                1_000
            ),
            Some(16_000)
        );
        assert_eq!(
            quota_until_ms(429, "{}", &HeaderMap::new(), 60_000, 1_000),
            Some(61_000)
        );
        assert_eq!(
            quota_until_ms(
                400,
                r#"{"error":{"status":"INVALID_ARGUMENT"}}"#,
                &HeaderMap::new(),
                60_000,
                1_000
            ),
            None
        );
        let backend = GeminiBackend { cooldown_ms: 5_000 };
        assert!(matches!(
            backend.classify(401, "nope", &HeaderMap::new(), 0),
            Outcome::AuthFailed
        ));
        assert!(matches!(
            backend.classify(503, "busy", &HeaderMap::new(), 0),
            Outcome::Transient
        ));
    }

    #[test]
    fn error_translation_hides_the_upstream_body() {
        let body = r#"{"error":{"status":"RESOURCE_EXHAUSTED","message":"slow down"}}"#;
        let chat = translate_error("/chat/completions", 429, body);
        assert!(chat.contains("resource_exhausted"));
        assert!(chat.contains("slow down"));
        assert!(!chat.contains("RESOURCE_EXHAUSTED"));
        let anthropic = translate_error(
            "/messages",
            401,
            r#"{"error":{"message":"bad token ya29.secret"}}"#,
        );
        let parsed: Value = serde_json::from_str(&anthropic).unwrap();
        assert_eq!(parsed["type"], "error");
        assert_eq!(parsed["error"]["type"], "authentication_error");
    }

    #[test]
    fn catalog_merge_keeps_operator_edits_and_free_tier_is_free() {
        let live = vec![model_info("gemini-2.5-pro", "Live", 10, 2)];
        let stored = vec![model_info("gemini-2.5-pro", "Mine", 99, 7)];
        let merged = merge_catalog(&live, &stored, &default_catalog());
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name, "Mine");
        assert_eq!(merged[0].context, 99);
        assert!(merge_catalog(&[], &[], &default_catalog()).len() > 5);
        let parsed = parse_available_models(&json!({
            "models": {
                "gemini-2.5-flash": {"displayName": "Flash", "inputTokenLimit": 1000, "outputTokenLimit": 50}
            }
        }));
        assert_eq!(parsed[0].id, "gemini-2.5-flash");
        assert_eq!(parsed[0].input, 1000);
        assert_eq!(plan_for_tier("free-tier", Some("Free")), "free");
        assert_eq!(
            plan_for_tier("g1-ultra", Some("Google AI Ultra")),
            "Google AI Ultra"
        );
    }

    #[test]
    fn claude_models_are_not_admitted() {
        let backend = GeminiBackend { cooldown_ms: 1 };
        let headers = HeaderMap::new();
        assert!(!backend.accepts_client(&headers, &json!({"model": "claude-haiku-5-5"})));
        assert!(backend.accepts_client(&headers, &json!({"model": "gemini-2.5-pro"})));
        assert!(backend.accepts_client(&headers, &json!({"model": "gemma-4-31b-it"})));
    }

    #[test]
    fn streaming_url_follows_the_client_flag() {
        let backend = GeminiBackend { cooldown_ms: 1 };
        let account = crate::flows::new_account(BackendId::Gemini, "g".into());
        let stream = backend.upstream_url("/chat/completions", &account, &json!({"stream": true}));
        assert!(stream.ends_with("/v1internal:streamGenerateContent?alt=sse"));
        let once = backend.upstream_url("/responses", &account, &json!({"stream": false}));
        assert!(once.ends_with("/v1internal:generateContent"));
        let count = backend.upstream_url("/messages/count_tokens", &account, &json!({}));
        assert!(count.ends_with("/v1internal:countTokens"));
    }
}
