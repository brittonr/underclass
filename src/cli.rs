use clap::Parser;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

pub const PROVIDER_ID: &str = "underclass";
pub const DEFAULT_MODEL: &str = "gpt-5.5";

#[derive(Parser, Debug)]
pub struct ConnectArgs {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    pub base_url: String,
    #[arg(long)]
    pub api_key: Option<String>,
    #[arg(long, default_value = DEFAULT_MODEL)]
    pub model: String,
    #[arg(long, help = "do not set the default model in opencode config")]
    pub no_default_model: bool,
    #[arg(
        long,
        help = "write to ./.opencode/opencode.json instead of the global config"
    )]
    pub project: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, help = "remove the underclass provider and credentials")]
    pub remove: bool,
}

#[derive(Parser, Debug)]
pub struct ResetArgs {
    #[arg(help = "account label (email/username), account id, or unique id prefix")]
    pub account: String,
    #[arg(
        long,
        help = "redeem even when upstream reports the account is not rate limited"
    )]
    pub force: bool,
    #[arg(long, help = "server URL (requires UNDERCLASS_UI_TOKEN)")]
    pub url: Option<String>,
}

#[derive(Parser, Debug)]
pub struct RefreshArgs {
    #[arg(
        help = "account label (email/username), account id, or unique id prefix",
        required_unless_present = "all",
        conflicts_with = "all"
    )]
    pub account: Option<String>,
    #[arg(long, help = "refresh every ChatGPT/Codex and Claude Code account")]
    pub all: bool,
    #[arg(long, help = "server URL (requires UNDERCLASS_UI_TOKEN)")]
    pub url: Option<String>,
}

/// One row of the admin state's account list, as much as the CLI needs to pick a target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRef {
    pub id: String,
    pub label: String,
    pub backend: String,
}

/// @cc [owner:ghuntley,label:cli] reset-account-selector
/// `match_account` MUST resolve an operator's selector to exactly one account: a case-insensitive
/// exact label match wins, then an exact id match, then a unique id prefix of at least 8
/// characters. It MUST fail with a message naming the absence or ambiguity rather than guessing,
/// and MUST never match on an empty selector.
pub fn match_account<'a>(
    accounts: &'a [AccountRef],
    selector: &str,
) -> Result<&'a AccountRef, String> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err("account selector must not be empty".into());
    }
    let by_label: Vec<&AccountRef> = accounts
        .iter()
        .filter(|a| a.label.eq_ignore_ascii_case(selector))
        .collect();
    match by_label.as_slice() {
        [one] => return Ok(one),
        [] => {}
        many => {
            return Err(format!(
                "label {selector:?} matches {} accounts; use an account id instead",
                many.len()
            ));
        }
    }
    if let Some(exact) = accounts.iter().find(|a| a.id == selector) {
        return Ok(exact);
    }
    if selector.len() >= 8 {
        let by_prefix: Vec<&AccountRef> = accounts
            .iter()
            .filter(|a| a.id.starts_with(selector))
            .collect();
        match by_prefix.as_slice() {
            [one] => return Ok(one),
            [] => {}
            many => {
                return Err(format!(
                    "id prefix {selector:?} matches {} accounts",
                    many.len()
                ));
            }
        }
    }
    Err(format!("no account matches {selector:?}"))
}

fn account_refs(state: &Value) -> Vec<AccountRef> {
    state["accounts"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    Some(AccountRef {
                        id: row["id"].as_str()?.to_string(),
                        label: row["label"].as_str()?.to_string(),
                        backend: row["backend"].as_str().unwrap_or_default().to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// An authenticated client for the running server's admin API.
struct AdminApi {
    client: reqwest::blocking::Client,
    url: String,
    token: String,
}

impl AdminApi {
    fn connect(url: Option<String>) -> Result<Self, String> {
        let config = crate::config::Config::load();
        let (url, token) = crate::top::admin_http_target(&config, url)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self { client, url, token })
    }

    fn accounts(&self) -> Result<Vec<AccountRef>, String> {
        let state: Value = self
            .client
            .get(format!("{}/admin/api/state", self.url))
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| format!("cannot reach {}: {e}", self.url))?
            .error_for_status()
            .map_err(|e| format!("admin state request failed: {e}"))?
            .json()
            .map_err(|e| format!("admin state response: {e}"))?;
        Ok(account_refs(&state))
    }
}

/// @cc [owner:ghuntley,label:cli] reset-cli-via-admin-api
/// `reset` MUST act only through the running server's authenticated admin API (resolve the
/// account from `/admin/api/state`, then POST `/admin/api/accounts/{id}/reset`), MUST NOT read
/// credentials from or write to the local database, and MUST surface the server's `message` on
/// a non-2xx response instead of a bare status code.
pub fn reset(args: &ResetArgs) -> Result<(), String> {
    let admin = AdminApi::connect(args.url.clone())?;
    let (client, url, token) = (&admin.client, &admin.url, &admin.token);
    let accounts = admin.accounts()?;
    let account = match_account(&accounts, &args.account)?;
    if !matches!(account.backend.as_str(), "codex" | "claude") {
        return Err(format!(
            "{} is a {} account; only ChatGPT/Codex and Claude Code accounts have banked resets",
            account.label, account.backend
        ));
    }
    let response = client
        .post(format!(
            "{url}/admin/api/accounts/{}/reset?force={}",
            account.id, args.force
        ))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("reset request failed: {e}"))?;
    let status = response.status();
    let body: Value = response.json().unwrap_or(Value::Null);
    if status.is_success() {
        println!(
            "{}: {} (credit {}); account is now {}, {} reset(s) remaining",
            account.label,
            body["outcome"].as_str().unwrap_or("unknown"),
            body["credit_id"].as_str().unwrap_or("?"),
            body["status"].as_str().unwrap_or("unknown"),
            body["available_resets"].as_i64().unwrap_or(0),
        );
        Ok(())
    } else {
        let message = body["message"]
            .as_str()
            .or_else(|| body["error"].as_str())
            .unwrap_or("request failed");
        Err(format!(
            "{}: {message} (HTTP {})",
            account.label,
            status.as_u16()
        ))
    }
}

/// @cc [owner:ghuntley,label:cli] refresh-cli-via-admin-api
/// `refresh` MUST act only through the running server's authenticated admin API (resolve accounts
/// from `/admin/api/state`, then POST `/admin/api/accounts/{id}/refresh`) and MUST NOT read
/// credentials from or write to the local database. A single account MUST be resolved with
/// `match_account`; `--all` MUST target every account whose backend refreshes with its issuer.
/// It MUST print one line per account, surfacing the server's `message` on a non-2xx response, and
/// MUST fail when any targeted refresh failed.
pub fn refresh(args: &RefreshArgs) -> Result<(), String> {
    let admin = AdminApi::connect(args.url.clone())?;
    let accounts = admin.accounts()?;
    let targets: Vec<&AccountRef> = match &args.account {
        Some(selector) => vec![match_account(&accounts, selector)?],
        None => accounts
            .iter()
            .filter(|a| {
                crate::models::BackendId::parse(&a.backend)
                    .is_some_and(crate::tokens::refreshes_with_issuer)
            })
            .collect(),
    };
    if targets.is_empty() {
        return Err("no refreshable accounts".into());
    }
    let mut failed = 0;
    for account in targets {
        let response = admin
            .client
            .post(format!(
                "{}/admin/api/accounts/{}/refresh",
                admin.url, account.id
            ))
            .bearer_auth(&admin.token)
            .send()
            .map_err(|e| format!("refresh request failed: {e}"))?;
        let status = response.status();
        let body: Value = response.json().unwrap_or(Value::Null);
        if status.is_success() {
            let expires = body["expires_at"]
                .as_i64()
                .and_then(chrono::DateTime::from_timestamp_millis)
                .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "?".into());
            let before = body["previous_status"].as_str().unwrap_or("unknown");
            let after = body["status"].as_str().unwrap_or("unknown");
            let transition = if before == after {
                after.to_string()
            } else {
                format!("{before} -> {after}")
            };
            println!(
                "{}: refreshed; account is {transition}, token expires {expires}",
                account.label
            );
        } else {
            failed += 1;
            let message = body["message"]
                .as_str()
                .or_else(|| body["error"].as_str())
                .unwrap_or("request failed");
            eprintln!("{}: {message} (HTTP {})", account.label, status.as_u16());
        }
    }
    match failed {
        0 => Ok(()),
        n => Err(format!("{n} refresh(es) failed")),
    }
}

pub fn opencode_global_config_dir() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) => PathBuf::from(dir).join("opencode"),
        None => home().join(".config/opencode"),
    }
}

pub fn opencode_data_dir() -> PathBuf {
    match std::env::var_os("XDG_DATA_HOME") {
        Some(dir) => PathBuf::from(dir).join("opencode"),
        None => home().join(".local/share/opencode"),
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn find_opencode_config(project: bool) -> PathBuf {
    if project {
        return std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".opencode/opencode.json");
    }
    let global = opencode_global_config_dir();
    let jsonc = global.join("opencode.jsonc");
    if jsonc.exists() {
        return jsonc;
    }
    let json = global.join("opencode.json");
    if json.exists() {
        return json;
    }
    global.join("opencode.json")
}

/// @cc [owner:ghuntley,label:cli] parse-jsonc-tolerant
/// `parse_jsonc` MUST accept opencode configs containing `//` and `/* */` comments and trailing
/// commas, MUST NOT alter values or commas inside string literals, and MUST fail with a message
/// on genuinely invalid documents.
pub fn parse_jsonc(text: &str) -> Result<Value, String> {
    let mut stripped = json_comments::StripComments::new(text.as_bytes());
    let mut cleaned = String::new();
    std::io::Read::read_to_string(&mut stripped, &mut cleaned).map_err(|e| e.to_string())?;
    let cleaned = remove_trailing_commas(&cleaned);
    serde_json::from_str(&cleaned).map_err(|e| e.to_string())
}

fn remove_trailing_commas(text: &str) -> String {
    #[derive(PartialEq)]
    enum Mode {
        Normal,
        Str,
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut mode = Mode::Normal;
    let mut escape = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if mode == Mode::Str {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                mode = Mode::Normal;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                out.push(c);
                mode = Mode::Str;
                i += 1;
            }
            ',' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                let next_meaningful = chars.get(j);
                if next_meaningful.is_some_and(|&n| n == '}' || n == ']') {
                    i += 1;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

pub fn provider_block(base_url: &str, api_key: &str, models: &[crate::models::ModelInfo]) -> Value {
    let models: serde_json::Map<String, Value> = models
        .iter()
        .map(|m| {
            let mut model = serde_json::Map::new();
            model.insert("name".into(), Value::String(m.name.clone()));
            (m.id.clone(), Value::Object(model))
        })
        .collect();
    serde_json::json!({
        "npm": "@ai-sdk/openai-compatible",
        "name": "Underclass (pooled Codex, Copilot + OpenCode Go)",
        "options": {
            "baseURL": base_url,
            "apiKey": api_key,
            "setCacheKey": true
        },
        "models": Value::Object(models)
    })
}

/// @cc [owner:ghuntley,label:cli] connect-merge-idempotent-preserves-unrelated
/// `merge_provider` MUST be idempotent (merging twice yields the same document), MUST preserve
/// every unrelated key including other providers, and MUST remove a stale `underclass/*` default
/// model when no default model is requested.
pub fn merge_provider(doc: &mut Value, block: &Value, default_model: Option<&str>) {
    if !doc.is_object() {
        *doc = serde_json::json!({});
    }
    let map = doc.as_object_mut().unwrap();
    let providers = map
        .entry("provider")
        .or_insert_with(|| Value::Object(Default::default()));
    if !providers.is_object() {
        *providers = Value::Object(Default::default());
    }
    providers
        .as_object_mut()
        .unwrap()
        .insert(PROVIDER_ID.to_string(), block.clone());
    match default_model {
        Some(model) => {
            map.insert(
                "model".into(),
                Value::String(format!("{PROVIDER_ID}/{model}")),
            );
        }
        None => {
            if let Some(model) = map.get("model").and_then(|v| v.as_str()) {
                if model.starts_with(&format!("{PROVIDER_ID}/")) {
                    map.remove("model");
                }
            }
        }
    }
}

pub fn remove_provider(doc: &mut Value) {
    if let Some(map) = doc.as_object_mut() {
        if let Some(providers) = map.get_mut("provider").and_then(|p| p.as_object_mut()) {
            providers.remove(PROVIDER_ID);
        }
        if let Some(model) = map.get("model").and_then(|v| v.as_str()).map(String::from) {
            if model.starts_with(&format!("{PROVIDER_ID}/")) {
                map.remove("model");
            }
        }
    }
}

pub fn merge_auth(doc: &mut Value, key: &str) {
    if !doc.is_object() {
        *doc = serde_json::json!({});
    }
    doc.as_object_mut().unwrap().insert(
        PROVIDER_ID.to_string(),
        serde_json::json!({ "type": "api", "key": key }),
    );
}

pub fn remove_auth(doc: &mut Value) {
    if let Some(map) = doc.as_object_mut() {
        map.remove(PROVIDER_ID);
    }
}

/// @cc [owner:ghuntley,label:cli] connect-backup-before-write
/// `write_with_backup` MUST copy an existing file to `<path>.bak` before overwriting it, and MUST
/// NOT leave the original truncated or missing on failure.
fn write_with_backup(path: &PathBuf, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if path.exists() {
        let mut backup_name = path.as_os_str().to_os_string();
        backup_name.push(".bak");
        let backup = PathBuf::from(backup_name);
        std::fs::copy(path, &backup).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, contents).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn connect(args: &ConnectArgs, underclass_store: &crate::store::Store) -> Result<(), String> {
    let base_url = format!("{}/v1", args.base_url.trim_end_matches('/'));

    if args.remove {
        return remove(&config_path_for(args), &auth_path(), args.dry_run);
    }

    let api_key = resolve_api_key(args, underclass_store)?;
    // The OpenAI-shaped backends; the Anthropic surface is not OpenAI-shaped (ADR 0024).
    let mut all_models = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for backend in [
        crate::models::BackendId::Codex,
        crate::models::BackendId::Copilot,
        crate::models::BackendId::OpencodeGo,
    ] {
        for m in underclass_store.catalog(backend) {
            if seen.insert(m.id.clone()) {
                all_models.push(m);
            }
        }
    }
    if all_models.is_empty() {
        eprintln!("warning: proxy catalog is empty; run the server and add accounts first");
        all_models = crate::codex::default_catalog();
    }

    let config_path = config_path_for(args);
    let existing = if config_path.exists() {
        let text = std::fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
        if text.trim().is_empty() {
            serde_json::json!({})
        } else {
            parse_jsonc(&text)?
        }
    } else {
        serde_json::json!({})
    };

    let block = provider_block(&base_url, &api_key, &all_models);
    let default_model = if args.no_default_model {
        None
    } else {
        Some(args.model.clone())
    };
    let mut updated = existing.clone();
    merge_provider(&mut updated, &block, default_model.as_deref());

    let auth_path = auth_path();
    let mut auth_doc = if auth_path.exists() {
        let text = std::fs::read_to_string(&auth_path).map_err(|e| e.to_string())?;
        parse_jsonc(&text)?
    } else {
        serde_json::json!({})
    };
    merge_auth(&mut auth_doc, &api_key);

    if args.dry_run {
        println!("--- {} ---", config_path.display());
        println!(
            "{}",
            serde_json::to_string_pretty(&updated).map_err(|e| e.to_string())?
        );
        println!("--- {} ---", auth_path.display());
        println!(
            "{}",
            serde_json::to_string_pretty(&auth_doc).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    write_with_backup(
        &config_path,
        &serde_json::to_string_pretty(&updated).map_err(|e| e.to_string())?,
    )?;
    if let Some(parent) = auth_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        &auth_path,
        serde_json::to_string_pretty(&auth_doc).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600));
    }

    verify(&base_url, &api_key);
    println!(
        "configured opencode provider '{PROVIDER_ID}' at {}",
        config_path.display()
    );
    println!(
        "run: opencode --provider {PROVIDER_ID} --model {PROVIDER_ID}/{}",
        args.model
    );
    println!();
    println!("point Claude Code at the same pool (it speaks the Anthropic surface):");
    println!(
        "  export ANTHROPIC_BASE_URL={}",
        base_url.trim_end_matches("/v1")
    );
    println!("  export CLAUDE_CODE_OAUTH_TOKEN=<the underclass proxy key>");
    Ok(())
}

fn config_path_for(args: &ConnectArgs) -> PathBuf {
    find_opencode_config(args.project)
}

fn auth_path() -> PathBuf {
    opencode_data_dir().join("auth.json")
}

fn resolve_api_key(args: &ConnectArgs, store: &crate::store::Store) -> Result<String, String> {
    if let Some(key) = &args.api_key {
        return Ok(key.clone());
    }
    if let Ok(key) = std::env::var("UNDERCLASS_PROXY_KEY") {
        if !key.is_empty() {
            return Ok(key);
        }
    }
    if let Some(key) = store.config_get("proxy_key") {
        return Ok(key);
    }
    Err(
        "no proxy api key found. pass --api-key, set UNDERCLASS_PROXY_KEY, or run 'underclass serve' once to mint one"
            .to_string(),
    )
}

fn remove(config_path: &PathBuf, auth_path: &PathBuf, dry_run: bool) -> Result<(), String> {
    if config_path.exists() {
        let text = std::fs::read_to_string(config_path).map_err(|e| e.to_string())?;
        let mut doc = parse_jsonc(&text)?;
        remove_provider(&mut doc);
        if !dry_run {
            write_with_backup(
                config_path,
                &serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
            )?;
        } else {
            println!("--- {} (dry run) ---", config_path.display());
            println!(
                "{}",
                serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
            );
        }
    }
    if auth_path.exists() {
        let text = std::fs::read_to_string(auth_path).map_err(|e| e.to_string())?;
        let mut doc = parse_jsonc(&text)?;
        remove_auth(&mut doc);
        if !dry_run {
            write_with_backup(
                auth_path,
                &serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
            )?;
        } else {
            println!("--- {} (dry run) ---", auth_path.display());
            println!(
                "{}",
                serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
            );
        }
    }
    println!("removed '{PROVIDER_ID}' from opencode config and auth");
    Ok(())
}

fn verify(base_url: &str, api_key: &str) {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let Ok(client) = client else { return };
    match client
        .get(format!("{base_url}/models"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>() {
                let count = body["data"].as_array().map(|a| a.len()).unwrap_or(0);
                println!("pool reachable: {count} models available");
            }
        }
        Ok(resp) => eprintln!(
            "warning: pool responded with {} — is 'underclass serve' running with the same key?",
            resp.status()
        ),
        Err(e) => eprintln!("warning: could not reach pool at {base_url}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_creates_provider_and_default_model() {
        let mut doc = json!({"theme": "dark"});
        let block = json!({"npm": "@ai-sdk/openai-compatible"});
        merge_provider(&mut doc, &block, Some("gpt-5.5"));
        assert_eq!(doc["theme"], "dark");
        assert_eq!(
            doc["provider"]["underclass"]["npm"],
            "@ai-sdk/openai-compatible"
        );
        assert_eq!(doc["model"], "underclass/gpt-5.5");
    }

    #[test]
    fn merge_is_idempotent() {
        let block = json!({"npm": "@ai-sdk/openai-compatible", "models": {}});
        let mut doc = json!({"other": {"nested": true}});
        merge_provider(&mut doc, &block, Some("gpt-5.5"));
        let once = doc.clone();
        merge_provider(&mut doc, &block, Some("gpt-5.5"));
        assert_eq!(once, doc);
    }

    #[test]
    fn merge_preserves_unrelated_providers() {
        let block = json!({"npm": "@ai-sdk/openai-compatible"});
        let mut doc = json!({"provider": {"openai": {"npm": "@ai-sdk/openai"}}});
        merge_provider(&mut doc, &block, None);
        assert_eq!(doc["provider"]["openai"]["npm"], "@ai-sdk/openai");
    }

    #[test]
    fn merge_without_default_removes_stale_default() {
        let block = json!({});
        let mut doc = json!({"model": "underclass/gpt-5.4"});
        merge_provider(&mut doc, &block, None);
        assert!(doc.get("model").is_none());
        let mut doc = json!({"model": "openai/gpt-5.4"});
        merge_provider(&mut doc, &block, None);
        assert_eq!(doc["model"], "openai/gpt-5.4");
    }

    #[test]
    fn remove_undoes_merge() {
        let block = json!({"npm": "@ai-sdk/openai-compatible"});
        let mut doc =
            json!({"model": "openai/gpt-5.4", "provider": {"openai": {"npm": "@ai-sdk/openai"}}});
        merge_provider(&mut doc, &block, Some("gpt-5.5"));
        remove_provider(&mut doc);
        assert_eq!(doc["provider"]["openai"]["npm"], "@ai-sdk/openai");
        assert!(doc["provider"].get("underclass").is_none());
        assert!(doc.get("model").is_none());
    }

    #[test]
    fn parses_jsonc_with_comments_and_trailing_commas() {
        let doc = parse_jsonc(
            "{\n  // comment\n  \"a\": 1, /* block */\n  \"list\": [1, 2,],\n  \"nested\": {\"x\": 2,},\n}",
        )
        .unwrap();
        assert_eq!(doc["a"], 1);
        assert_eq!(doc["list"].as_array().unwrap().len(), 2);
        assert_eq!(doc["nested"]["x"], 2);
    }

    #[test]
    fn trailing_comma_inside_strings_is_preserved() {
        let doc = parse_jsonc(r#"{"a": "has , comma"}"#).unwrap();
        assert_eq!(doc["a"], "has , comma");
    }

    #[test]
    fn auth_roundtrip() {
        let mut doc = json!({"openai": {"type": "api", "key": "sk"}});
        merge_auth(&mut doc, "key-1");
        assert_eq!(doc["underclass"]["key"], "key-1");
        assert_eq!(doc["underclass"]["type"], "api");
        remove_auth(&mut doc);
        assert!(doc.get("underclass").is_none());
        assert!(doc.get("openai").is_some());
    }

    #[test]
    fn provider_block_carries_set_cache_key() {
        let block = provider_block("http://127.0.0.1:8080/v1", "key", &[]);
        assert_eq!(block["options"]["setCacheKey"], true);
        assert_eq!(block["options"]["baseURL"], "http://127.0.0.1:8080/v1");
    }
}

#[cfg(test)]
mod reset_tests {
    use super::*;

    fn pool() -> Vec<AccountRef> {
        vec![
            AccountRef {
                id: "aaaaaaaa-1111".into(),
                label: "One@Example.test".into(),
                backend: "codex".into(),
            },
            AccountRef {
                id: "aaaaaaaa-2222".into(),
                label: "two@example.test".into(),
                backend: "codex".into(),
            },
            AccountRef {
                id: "bbbbbbbb-3333".into(),
                label: "gh-user".into(),
                backend: "copilot".into(),
            },
        ]
    }

    #[test]
    fn label_match_is_case_insensitive_and_wins_over_id() {
        let accounts = pool();
        assert_eq!(
            match_account(&accounts, "one@example.TEST").unwrap().id,
            "aaaaaaaa-1111"
        );
        assert_eq!(
            match_account(&accounts, " two@example.test ").unwrap().id,
            "aaaaaaaa-2222"
        );
    }

    #[test]
    fn exact_id_and_unique_prefix_resolve() {
        let accounts = pool();
        assert_eq!(
            match_account(&accounts, "bbbbbbbb-3333").unwrap().label,
            "gh-user"
        );
        assert_eq!(
            match_account(&accounts, "bbbbbbbb").unwrap().label,
            "gh-user"
        );
    }

    #[test]
    fn ambiguous_short_or_missing_selectors_fail() {
        let accounts = pool();
        assert!(
            match_account(&accounts, "aaaaaaaa")
                .unwrap_err()
                .contains("matches 2")
        );
        assert!(
            match_account(&accounts, "bbbb")
                .unwrap_err()
                .contains("no account")
        );
        assert!(match_account(&accounts, "nobody@example.test").is_err());
        assert!(match_account(&accounts, "   ").is_err());
        assert!(match_account(&[], "x").is_err());
    }

    #[test]
    fn duplicate_labels_are_rejected() {
        let mut accounts = pool();
        accounts.push(AccountRef {
            id: "cccccccc-4444".into(),
            label: "two@example.test".into(),
            backend: "codex".into(),
        });
        assert!(
            match_account(&accounts, "two@example.test")
                .unwrap_err()
                .contains("matches 2")
        );
        assert_eq!(
            match_account(&accounts, "cccccccc-4444").unwrap().label,
            "two@example.test"
        );
    }

    #[test]
    fn account_refs_skip_malformed_rows() {
        let state = serde_json::json!({"accounts": [
            {"id": "a", "label": "l", "backend": "codex"},
            {"id": 5, "label": "bad"},
            {"id": "b", "label": "m"}
        ]});
        let refs = account_refs(&state);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[1].backend, "");
        assert!(account_refs(&serde_json::json!({})).is_empty());
    }
}
