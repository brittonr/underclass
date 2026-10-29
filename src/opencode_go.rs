//! OpenCode Go backend (ADR 0027).
//!
//! OpenCode Go is a flat subscription to a curated set of coding models from many vendors. Its
//! gateway serves every text model through the OpenAI Responses and Chat Completions APIs and
//! authenticates with a Console API key, so an account holds an API key rather than an OAuth
//! grant. Paid models draw on 5-hour, weekly and monthly allowances shared by the workspace; the
//! free models stay available once the allowance is spent.
//!
//! Catalog ids carry the `opencode-go/` namespace: OpenCode Go serves upstream ids such as
//! `gpt-6-luna` that other backends serve too, and the namespace keeps the two apart.

use crate::models::{Account, AccountStatus, BackendId, ModelInfo, Outcome, Surface, now_ms};
use crate::pool::PoolCore;
use crate::provider::Backend;
use crate::store::Store;
use http::HeaderMap;
use reqwest::Client;
use serde_json::Value;
use sha2::Digest;
use std::sync::Mutex;
use std::time::Duration;

/// The OpenCode Go gateway.
pub const DEFAULT_API_BASE: &str = "https://opencode.ai/inference/go";
/// Namespace in front of the upstream model id in every OpenCode Go catalog id.
pub const MODEL_NAMESPACE: &str = "opencode-go/";
/// The header OpenCode Go routes a conversation by and reuses its prompt cache for.
pub const SESSION_HEADER: &str = "x-opencode-session";
/// OpenCode Go asks clients to identify themselves rather than send a generic library agent.
pub const USER_AGENT: &str = concat!("underclass/", env!("CARGO_PKG_VERSION"));
/// Limits for a live model the seeded catalog does not describe.
const FALLBACK_CONTEXT: i64 = 128_000;
const FALLBACK_OUTPUT: i64 = 32_000;
/// Bound on account API calls, so a stalled gateway cannot hold the boot or a poll.
const ACCOUNT_API_TIMEOUT: Duration = Duration::from_secs(30);

/// The gateway base. Overridable so tests can point at a mock upstream.
pub fn api_base() -> String {
    std::env::var("UNDERCLASS_OPENCODE_GO_UPSTREAM")
        .unwrap_or_else(|_| DEFAULT_API_BASE.to_string())
        .trim_end_matches('/')
        .to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("OpenCode Go answered HTTP {status}{detail}")]
    Status { status: u16, detail: String },
    #[error("OpenCode Go sent an unexpected response")]
    Malformed,
    #[error("the API key is empty or contains characters a header cannot carry")]
    InvalidKey,
    #[error("the account being replaced is not an OpenCode Go account in this pool")]
    UnknownAccount,
}

/// An upstream error with OpenCode's own message. Its error bodies never carry the key.
fn status_error(status: u16, body: &str) -> AuthError {
    let detail = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .map(|message| format!(": {message}"))
        })
        .unwrap_or_default();
    AuthError::Status { status, detail }
}

/// The key as the operator pasted it, trimmed, or `InvalidKey` when it cannot travel as a bearer
/// credential.
pub fn normalize_key(api_key: &str) -> Result<String, AuthError> {
    let key = api_key.trim();
    if key.is_empty() || http::HeaderValue::from_str(&format!("Bearer {key}")).is_err() {
        return Err(AuthError::InvalidKey);
    }
    Ok(key.to_string())
}

/// @cc [owner:ghuntley,label:identity] opencode-go-default-label
/// Without an operator label, an OpenCode Go account MUST be labeled with the public key id of a
/// Console key (`oc_sk_<id>_<secret>` yields `opencode-go oc_sk_<id>`) and never with any part of
/// the secret; a key of any other shape MUST be labeled `opencode-go`.
pub fn default_label(api_key: &str) -> String {
    match api_key
        .strip_prefix("oc_sk_")
        .and_then(|rest| rest.split_once('_'))
    {
        Some((id, secret))
            if !id.is_empty()
                && !secret.is_empty()
                && id.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            format!("opencode-go oc_sk_{id}")
        }
        _ => "opencode-go".to_string(),
    }
}

/// The catalog id of an upstream OpenCode Go model.
pub fn catalog_id(upstream: &str) -> String {
    format!("{MODEL_NAMESPACE}{upstream}")
}

/// @cc [owner:ghuntley,label:proxy] opencode-go-upstream-model
/// `upstream_model` MUST strip one leading `opencode-go/` namespace, ASCII case-insensitively,
/// and MUST return any other model id unchanged.
pub fn upstream_model(model: &str) -> &str {
    match model.get(..MODEL_NAMESPACE.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(MODEL_NAMESPACE) => {
            &model[MODEL_NAMESPACE.len()..]
        }
        _ => model,
    }
}

/// The model ids a `/v1/models` listing advertises, sorted and deduplicated. Malformed entries
/// are skipped.
pub fn parse_model_ids(body: &Value) -> Vec<String> {
    let mut ids: Vec<String> = body
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|model| model.get("id").and_then(Value::as_str))
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// @cc [owner:ghuntley,label:pool] opencode-go-catalog-merge
/// `merge_catalog` MUST return exactly one entry per distinct live upstream id, under its
/// `opencode-go/` catalog id and sorted by it. An id already in the stored catalog MUST keep its
/// stored name and limits, so operator edits survive a refresh; otherwise the seeded entry MUST
/// be used, and an id neither describes MUST get its upstream id as name and the fallback limits.
/// Stored or seeded ids that are no longer live MUST be dropped.
pub fn merge_catalog(live: &[String], stored: &[ModelInfo], seed: &[ModelInfo]) -> Vec<ModelInfo> {
    let mut catalog: Vec<ModelInfo> = live
        .iter()
        .map(|upstream| {
            let id = catalog_id(upstream);
            stored
                .iter()
                .chain(seed)
                .find(|model| model.id == id)
                .cloned()
                .unwrap_or_else(|| ModelInfo {
                    name: upstream.clone(),
                    context: FALLBACK_CONTEXT,
                    input: FALLBACK_CONTEXT,
                    output: FALLBACK_OUTPUT,
                    id,
                })
        })
        .collect();
    catalog.sort_by(|a, b| a.id.cmp(&b.id));
    catalog.dedup_by(|a, b| a.id == b.id);
    catalog
}

/// The seeded catalog, used until the live model list is fetched. Names and limits follow
/// OpenCode's published model metadata (models.dev, October 2026).
pub fn default_catalog() -> Vec<ModelInfo> {
    let entries: &[(&str, &str, i64, i64, i64)] = &[
        ("beam-free", "Beam Free", 1_048_576, 1_048_576, 131_072),
        (
            "claude-haiku-5-5",
            "Claude Haiku 5.5",
            1_000_000,
            1_000_000,
            128_000,
        ),
        (
            "deepseek-v4-pro",
            "DeepSeek V4 Pro",
            1_000_000,
            1_000_000,
            384_000,
        ),
        (
            "deepseek-v4.1-flash",
            "DeepSeek V4.1 Flash",
            1_000_000,
            1_000_000,
            384_000,
        ),
        (
            "gemini-4-argon",
            "Gemini 4 Argon",
            1_048_576,
            1_048_576,
            65_536,
        ),
        ("glm-5.2", "GLM-5.2", 1_000_000, 1_000_000, 131_072),
        ("glm-5.3", "GLM-5.3", 1_000_000, 1_000_000, 131_072),
        (
            "glm-5.3-flash",
            "GLM-5.3-Flash",
            1_000_000,
            1_000_000,
            131_072,
        ),
        ("gpt-5.6-luna", "GPT-5.6 Luna", 1_050_000, 922_000, 128_000),
        ("gpt-6-luna", "GPT-6 Luna", 1_050_000, 922_000, 128_000),
        ("grok-4.7", "Grok 4.7", 500_000, 500_000, 500_000),
        ("hy3", "Hy3", 256_000, 192_000, 128_000),
        ("hy4-preview", "Hy4 preview", 1_024_000, 1_024_000, 64_000),
        (
            "iceman-contributor-free",
            "Iceman Contributor Free",
            262_144,
            262_144,
            131_072,
        ),
        (
            "kimi-k2.7-code",
            "Kimi K2.7 Code",
            262_144,
            262_144,
            262_144,
        ),
        ("kimi-k3", "Kimi K3", 1_048_576, 1_048_576, 131_072),
        (
            "kimi-k3.1-pro",
            "Kimi K3.1 Pro",
            1_048_576,
            1_048_576,
            131_072,
        ),
        ("longcat-2.0", "LongCat-2.0", 1_000_000, 1_000_000, 131_072),
        (
            "mimo-v2.6-flash",
            "MiMo-V2.6-Flash",
            1_048_576,
            1_048_576,
            131_072,
        ),
        (
            "mimo-v2.6-pro",
            "MiMo-V2.6-Pro",
            1_048_576,
            1_048_576,
            131_072,
        ),
        ("minimax-m3", "MiniMax-M3", 1_000_000, 1_000_000, 131_072),
        (
            "minimax-m3.1-flash",
            "MiniMax M3.1 Flash",
            1_000_000,
            1_000_000,
            512_000,
        ),
        (
            "muse-spark-1.2-contributor",
            "Muse Spark 1.2 Contributor",
            1_048_576,
            1_048_576,
            131_072,
        ),
        (
            "muse-spark-1.3-contributor",
            "Muse Spark 1.3 Contributor",
            1_048_576,
            1_048_576,
            131_072,
        ),
        ("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 1_000_000, 65_536),
        (
            "qwen3.8-flash",
            "Qwen3.8 Flash",
            1_000_000,
            1_000_000,
            131_072,
        ),
        ("qwen3.8-max", "Qwen3.8 Max", 1_000_000, 1_000_000, 131_072),
        (
            "step-5-preview",
            "Step 5 Preview",
            1_000_000,
            1_000_000,
            65_536,
        ),
    ];
    entries
        .iter()
        .map(|(id, name, context, input, output)| ModelInfo {
            id: catalog_id(id),
            name: name.to_string(),
            context: *context,
            input: *input,
            output: *output,
        })
        .collect()
}

/// One allowance window as the OpenCode Go usage API reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct UsageWindow {
    /// Fraction of the window consumed, 0.0 to 1.0.
    pub utilization: f64,
    /// Whether OpenCode Go reports the window as rate limited.
    pub limited: bool,
    /// When the window resets, in epoch milliseconds.
    pub resets_at_ms: Option<i64>,
}

/// The allowance windows of one OpenCode Go workspace.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UsageSnapshot {
    /// The rolling 5-hour window.
    pub rolling: Option<UsageWindow>,
    pub weekly: Option<UsageWindow>,
    pub monthly: Option<UsageWindow>,
    pub observed_at_ms: i64,
}

/// @cc [owner:ghuntley,label:pool] opencode-go-usage-parse
/// `parse_usage` MUST return `None` unless the payload carries a `usage` object. Each of its
/// `rolling`, `weekly` and `monthly` windows MUST be read only when it reports a `status` and a
/// finite `percent` from 0 to 100, which MUST become a 0.0-1.0 utilization; a `rate-limited`
/// status MUST mark the window limited, and an unparseable `resetsAt` MUST leave the reset
/// unknown. Malformed windows MUST be skipped, never panic.
pub fn parse_usage(body: &Value, now_ms: i64) -> Option<UsageSnapshot> {
    let usage = body.get("usage").filter(|usage| usage.is_object())?;
    let window = |name: &str| {
        let window = usage.get(name)?;
        let percent = window
            .get("percent")
            .and_then(Value::as_f64)
            .filter(|percent| percent.is_finite() && (0.0..=100.0).contains(percent))?;
        let status = window.get("status").and_then(Value::as_str)?;
        Some(UsageWindow {
            utilization: percent / 100.0,
            limited: status == "rate-limited",
            resets_at_ms: window
                .get("resetsAt")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.timestamp_millis()),
        })
    };
    Some(UsageSnapshot {
        rolling: window("rolling"),
        weekly: window("weekly"),
        monthly: window("monthly"),
        observed_at_ms: now_ms,
    })
}

/// The allowance windows as the admin UI and monitor show them: the Claude Code window names
/// for the 5-hour and weekly windows, plus `monthly`.
pub fn usage_view(snapshot: &UsageSnapshot) -> Value {
    let window = |window: &Option<UsageWindow>| {
        window.as_ref().map(|window| {
            serde_json::json!({
                "utilization": window.utilization,
                "limited": window.limited,
                "resets_at_ms": window.resets_at_ms,
            })
        })
    };
    serde_json::json!({
        "five_hour": window(&snapshot.rolling),
        "seven_day": window(&snapshot.weekly),
        "monthly": window(&snapshot.monthly),
        "observed_at_ms": snapshot.observed_at_ms,
    })
}

async fn get_json(client: &Client, path: &str, token: &str) -> Result<Value, AuthError> {
    let resp = client
        .get(format!("{}{path}", api_base()))
        .timeout(ACCOUNT_API_TIMEOUT)
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .header(http::header::USER_AGENT, USER_AGENT)
        .header(http::header::ACCEPT, "application/json")
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(status_error(status.as_u16(), &text));
    }
    serde_json::from_str(&text).map_err(|_| AuthError::Malformed)
}

/// The workspace's allowance windows. A key the gateway rejects fails with its status.
pub async fn fetch_usage(client: &Client, token: &str) -> Result<UsageSnapshot, AuthError> {
    let body = get_json(client, "/v1/usage", token).await?;
    parse_usage(&body, now_ms()).ok_or(AuthError::Malformed)
}

/// The upstream ids of the models the gateway serves.
pub async fn fetch_model_ids(client: &Client, token: &str) -> Result<Vec<String>, AuthError> {
    Ok(parse_model_ids(
        &get_json(client, "/v1/models", token).await?,
    ))
}

/// @cc [owner:ghuntley,label:pool] opencode-go-catalog-refresh
/// `refresh_catalog` MUST replace the stored and the routed OpenCode Go catalog with
/// `merge_catalog` of the live model list, and MUST leave both untouched when the list cannot be
/// fetched or is empty.
pub async fn refresh_catalog(
    client: &Client,
    store: &Store,
    pool: &Mutex<PoolCore>,
    token: &str,
) -> Result<usize, AuthError> {
    let live = fetch_model_ids(client, token).await?;
    if live.is_empty() {
        return Ok(0);
    }
    let catalog = merge_catalog(
        &live,
        &store.catalog(BackendId::OpencodeGo),
        &default_catalog(),
    );
    store.set_catalog(BackendId::OpencodeGo, &catalog);
    pool.lock().unwrap().set_catalog(
        BackendId::OpencodeGo,
        catalog.iter().map(|model| model.id.clone()).collect(),
    );
    Ok(catalog.len())
}

/// Refreshes the catalog with the first enabled account whose key the gateway accepts. Returns
/// the catalog size when an account succeeded, and each failed account's error.
pub async fn refresh_catalog_from_pool(
    client: &Client,
    store: &Store,
    pool: &Mutex<PoolCore>,
) -> (Option<usize>, Vec<String>) {
    let mut errors = Vec::new();
    let accounts = store
        .list_accounts()
        .into_iter()
        .filter(|a| a.backend == BackendId::OpencodeGo && a.status != AccountStatus::Disabled);
    for account in accounts {
        let Some(token) = account.access_token.as_deref() else {
            continue;
        };
        match refresh_catalog(client, store, pool, token).await {
            Ok(models) => return (Some(models), errors),
            Err(e) => errors.push(format!("{}: {e}", account.label)),
        }
    }
    (None, errors)
}

/// @cc [owner:ghuntley,label:identity] opencode-go-key-enrollment
/// `enroll` MUST validate the key against the OpenCode Go usage API before it stores anything,
/// and MUST keep the key only in the account's stored credential, never in a label, log or
/// error. The credential MUST be stored as an access token that expired at the epoch, with no
/// refresh token, so a build without this backend, which reads the account as Codex, has
/// nothing valid to send or refresh. With `replace_account` it MUST swap that OpenCode Go
/// account's credential (and label, when one is given) and return it to `Healthy`; otherwise it
/// MUST create an account labeled with the trimmed operator label or the key's default label.
pub async fn enroll(
    client: &Client,
    store: &Store,
    replace_account: Option<&str>,
    api_key: &str,
    label: Option<&str>,
) -> Result<(Account, UsageSnapshot), AuthError> {
    let key = normalize_key(api_key)?;
    let replaced = match replace_account {
        Some(id) => Some(
            store
                .get_account(id)
                .filter(|account| account.backend == BackendId::OpencodeGo)
                .ok_or(AuthError::UnknownAccount)?,
        ),
        None => None,
    };
    let usage = fetch_usage(client, &key).await?;
    let label = label
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(str::to_string);
    let mut account = match replaced {
        Some(mut account) => {
            account.status = AccountStatus::Healthy;
            account.reset_at = 0;
            account.updated_at = now_ms();
            if let Some(label) = label {
                account.label = label;
            }
            account
        }
        None => crate::flows::new_account(
            BackendId::OpencodeGo,
            label.unwrap_or_else(|| default_label(&key)),
        ),
    };
    account.access_token = Some(key);
    account.refresh_token = None;
    account.expires_at = 0;
    store.upsert_account(&account);
    Ok((account, usage))
}

/// @cc [owner:ghuntley,label:proxy] opencode-go-derived-session
/// `derived_session` MUST name a conversation by a SHA-256 digest of its opening: the Responses
/// `instructions`, and the chat `messages` or Responses `input` items up to and including the
/// first user turn. Every later turn of the conversation MUST get the same name, and the name
/// MUST be a valid header value.
pub fn derived_session(body: &Value) -> String {
    let opening: Vec<&Value> = match body.get("messages").or_else(|| body.get("input")) {
        Some(Value::Array(items)) => {
            let end = items
                .iter()
                .position(|item| item.get("role").and_then(Value::as_str) == Some("user"))
                .map_or(items.len(), |first_user| first_user + 1);
            items[..end].iter().collect()
        }
        Some(single) => vec![single],
        None => Vec::new(),
    };
    let digest = sha2::Sha256::digest(
        serde_json::json!([body.get("instructions"), opening])
            .to_string()
            .as_bytes(),
    );
    let name: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("underclass-{name}")
}

pub struct OpencodeGoBackend {
    pub cooldown_ms: i64,
}

impl Backend for OpencodeGoBackend {
    fn id(&self) -> BackendId {
        BackendId::OpencodeGo
    }

    fn surfaces(&self) -> &'static [Surface] {
        &[Surface::OpenAI]
    }

    fn default_cooldown_ms(&self) -> i64 {
        self.cooldown_ms
    }

    /// @cc [owner:ghuntley,label:proxy] opencode-go-url-rewrite
    /// OpenAI-surface requests MUST target the gateway's OpenAI API, `<base>/openai/v1<route>`,
    /// whether or not the route still carries the `/v1` prefix.
    fn rewrite_url(&self, path: &str, _account: &Account) -> String {
        let route = path
            .strip_prefix("/v1")
            .filter(|rest| rest.starts_with('/'))
            .unwrap_or(path);
        format!("{}/openai/v1{route}", api_base())
    }

    /// @cc [owner:ghuntley,label:proxy] opencode-go-headers
    /// Outbound OpenCode Go requests MUST carry the account's API key as a bearer credential,
    /// underclass's own user agent, and an `x-opencode-session`, which the gateway requires: the
    /// request's sticky key when it is a valid header value, otherwise `derived_session`.
    fn inject_headers(
        &self,
        _account: &Account,
        token: &str,
        sticky: Option<&str>,
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
        let session = sticky
            .and_then(|key| http::HeaderValue::from_str(key).ok())
            .or_else(|| http::HeaderValue::from_str(&derived_session(body)).ok());
        if let Some(value) = session {
            headers.insert(SESSION_HEADER, value);
        }
    }

    /// The namespace routes a request here; OpenCode Go knows the model by its own id.
    fn prepare_body(&self, body: &mut Value) {
        if let Some(model) = body.get("model").and_then(Value::as_str) {
            let upstream = upstream_model(model).to_string();
            body["model"] = Value::String(upstream);
        }
    }

    fn auto_stream_usage(&self, path: &str, body: &mut Value) -> bool {
        crate::usage::request_stream_usage(path, body)
    }

    /// @cc [owner:ghuntley,label:pool] opencode-go-classify-allowance
    /// `classify` MUST treat 429 (a spent allowance or a rate limit) and 402 (a spent allowance
    /// whose pay-as-you-go fallback has no funds) as `ModelQuotaExhausted` until the Retry-After
    /// deadline or, without one, the configured cooldown: the account's free models stay
    /// available. Every other status MUST follow the shared classification.
    fn classify(&self, status: u16, _body: &str, headers: &HeaderMap, now_ms: i64) -> Outcome {
        if matches!(status, 402 | 429) {
            let until_ms = crate::health::parse_retry_after_headers(headers, now_ms)
                .unwrap_or_else(|| now_ms.saturating_add(self.cooldown_ms))
                .max(now_ms);
            return Outcome::ModelQuotaExhausted { until_ms };
        }
        crate::health::classify(status, headers, self.cooldown_ms, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn backend() -> OpencodeGoBackend {
        OpencodeGoBackend { cooldown_ms: 1_000 }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (key, value) in pairs {
            map.insert(
                http::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn requests_target_the_gateway_openai_api() {
        let account = crate::flows::new_account(BackendId::OpencodeGo, "go".into());
        for (route, expected) in [
            ("/chat/completions", "/openai/v1/chat/completions"),
            ("/responses", "/openai/v1/responses"),
            ("/v1/responses", "/openai/v1/responses"),
        ] {
            assert_eq!(
                backend().rewrite_url(route, &account),
                format!("{}{expected}", api_base())
            );
        }
    }

    #[test]
    fn headers_carry_the_key_agent_and_session() {
        let account = crate::flows::new_account(BackendId::OpencodeGo, "go".into());
        let client = headers(&[("authorization", "Bearer client-proxy-key")]);
        let mut out = HeaderMap::new();
        backend().inject_headers(
            &account,
            "oc_sk_abc_secret",
            Some("ses_1"),
            &json!({}),
            &client,
            &mut out,
        );
        assert_eq!(out["authorization"], "Bearer oc_sk_abc_secret");
        assert_eq!(out["user-agent"], USER_AGENT);
        assert_eq!(out[SESSION_HEADER], "ses_1");

        // The gateway refuses requests without a session, so keyless requests get a derived
        // one, as do sticky keys a header cannot carry.
        let body = json!({"messages": [{"role": "user", "content": "hello"}]});
        for sticky in [None, Some("bad\nkey")] {
            let mut derived = HeaderMap::new();
            backend().inject_headers(
                &account,
                "oc_sk_abc_secret",
                sticky,
                &body,
                &client,
                &mut derived,
            );
            assert_eq!(derived[SESSION_HEADER], derived_session(&body).as_str());
        }
    }

    #[test]
    fn a_keyless_conversation_keeps_one_derived_session() {
        let first = json!({"model": "opencode-go/kimi-k3", "messages": [
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hello"}
        ]});
        let later = json!({"model": "opencode-go/glm-5.3", "messages": [
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
            {"role": "user", "content": "more"}
        ]});
        let other = json!({"messages": [{"role": "user", "content": "something else"}]});
        assert_eq!(derived_session(&first), derived_session(&later));
        assert_ne!(derived_session(&first), derived_session(&other));

        let responses = json!({"instructions": "be terse", "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "hello"}]}
        ]});
        let responses_later = json!({"instructions": "be terse", "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "hello"}]},
            {"type": "function_call_output", "call_id": "call_1", "output": "done"}
        ]});
        assert_eq!(
            derived_session(&responses),
            derived_session(&responses_later)
        );
        assert_ne!(
            derived_session(&responses),
            derived_session(&json!({"instructions": "be verbose", "input": "hello"}))
        );
        assert!(http::HeaderValue::from_str(&derived_session(&first)).is_ok());
    }

    #[test]
    fn the_body_names_the_upstream_model() {
        let mut body = json!({"model": "opencode-go/kimi-k3", "stream": true, "messages": []});
        backend().prepare_body(&mut body);
        assert_eq!(
            body,
            json!({"model": "kimi-k3", "stream": true, "messages": []})
        );
        let mut foreign = json!({"model": "gpt-6-luna"});
        backend().prepare_body(&mut foreign);
        assert_eq!(foreign["model"], "gpt-6-luna");
    }

    #[test]
    fn spent_allowances_cool_the_model_until_the_upstream_deadline() {
        // The 429 OpenCode Go sent for a spent weekly allowance.
        let limited = headers(&[("retry-after", "286163")]);
        assert_eq!(
            backend().classify(
                429,
                r#"{"type":"error","error":{"type":"GoUsageLimitError","message":"Go usage limit exceeded"}}"#,
                &limited,
                10_000
            ),
            Outcome::ModelQuotaExhausted {
                until_ms: 10_000 + 286_163_000
            }
        );
        // A spent allowance with Extra Usage on and no balance carries no deadline.
        assert_eq!(
            backend().classify(
                402,
                r#"{"error":{"type":"server_error","message":"Upstream request failed: Insufficient account funds"}}"#,
                &HeaderMap::new(),
                10_000
            ),
            Outcome::ModelQuotaExhausted { until_ms: 11_000 }
        );
    }

    #[test]
    fn other_statuses_follow_the_shared_classification() {
        let none = HeaderMap::new();
        assert_eq!(backend().classify(401, "", &none, 0), Outcome::AuthFailed);
        assert_eq!(backend().classify(503, "", &none, 0), Outcome::Transient);
        assert_eq!(backend().classify(400, "", &none, 0), Outcome::Ok);
    }

    #[test]
    fn usage_windows_parse_from_the_usage_api() {
        let body = json!({"usage": {
            "rolling": {"status": "ok", "percent": 0, "resetsAt": "2026-10-29T21:30:07.905Z"},
            "weekly": {"status": "ok", "percent": 94, "resetsAt": "2026-11-02T00:00:00.000Z"},
            "monthly": {"status": "rate-limited", "percent": 100, "resetsAt": "2026-11-15T00:09:27.000Z"}
        }});
        let snapshot = parse_usage(&body, 7).unwrap();
        assert_eq!(
            snapshot.monthly,
            Some(UsageWindow {
                utilization: 1.0,
                limited: true,
                resets_at_ms: Some(1_794_701_367_000),
            })
        );
        assert_eq!(snapshot.weekly.as_ref().unwrap().utilization, 0.94);
        assert!(!snapshot.rolling.as_ref().unwrap().limited);
        assert_eq!(snapshot.observed_at_ms, 7);
    }

    #[test]
    fn malformed_usage_windows_are_skipped() {
        let body = json!({"usage": {
            "rolling": {"status": "ok", "percent": 140, "resetsAt": "2026-10-29T21:30:07Z"},
            "weekly": {"percent": 12},
            "monthly": {"status": "ok", "percent": 3, "resetsAt": "soon"}
        }});
        let snapshot = parse_usage(&body, 0).unwrap();
        assert_eq!(snapshot.rolling, None);
        assert_eq!(snapshot.weekly, None);
        assert_eq!(snapshot.monthly.unwrap().resets_at_ms, None);
        assert_eq!(parse_usage(&json!({"error": "nope"}), 0), None);
        assert_eq!(parse_usage(&json!({"usage": 3}), 0), None);
    }

    #[test]
    fn default_labels_show_only_the_public_key_id() {
        assert_eq!(
            default_label("oc_sk_1a2b3c4d5e6f_s3cr3tvalue"),
            "opencode-go oc_sk_1a2b3c4d5e6f"
        );
        for other in ["sk-legacy-key", "oc_sk_", "oc_sk_nounderscore", "oc_sk_id_"] {
            assert_eq!(default_label(other), "opencode-go", "{other}");
        }
    }

    #[test]
    fn keys_must_travel_as_a_bearer_credential() {
        assert_eq!(normalize_key("  oc_sk_a_b \n").unwrap(), "oc_sk_a_b");
        assert!(matches!(normalize_key("   "), Err(AuthError::InvalidKey)));
        assert!(matches!(
            normalize_key("oc_sk_a\nb"),
            Err(AuthError::InvalidKey)
        ));
    }

    #[test]
    fn model_ids_parse_from_the_listing() {
        let body = json!({"object": "list", "data": [
            {"id": "kimi-k3", "object": "model", "owned_by": "opencode"},
            {"id": "deepseek-v4.1-flash", "object": "model"},
            {"id": "kimi-k3"},
            {"id": ""},
            {"object": "model"},
            7
        ]});
        assert_eq!(parse_model_ids(&body), ["deepseek-v4.1-flash", "kimi-k3"]);
        assert!(parse_model_ids(&json!({"data": "nope"})).is_empty());
    }

    #[test]
    fn refresh_keeps_stored_limits_and_seeds_new_models() {
        let stored = vec![ModelInfo {
            id: catalog_id("kimi-k3"),
            name: "Kimi K3 (edited)".into(),
            context: 1,
            input: 1,
            output: 1,
        }];
        let live = ["kimi-k3", "glm-5.3", "brand-new"].map(String::from);
        let catalog = merge_catalog(&live, &stored, &default_catalog());
        let ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "opencode-go/brand-new",
                "opencode-go/glm-5.3",
                "opencode-go/kimi-k3"
            ]
        );
        assert_eq!(catalog[0].name, "brand-new");
        assert_eq!(catalog[0].context, FALLBACK_CONTEXT);
        assert_eq!(catalog[1].name, "GLM-5.3");
        assert_eq!(catalog[2].name, "Kimi K3 (edited)");
    }
}
