use crate::flows::{FlowRegistry, FlowState, OAuthState};
use crate::models::{Account, BackendId, ModelInfo, Outcome, Surface, now_ms};
use crate::provider::Backend;
use crate::store::Store;
use crate::usage::UsageDialect;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::HeaderMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::sync::Arc;

/// The public Claude Code OAuth client id.
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const AUTHORIZE_URL: &str = "https://claude.com/cai/oauth/authorize";
pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
pub const API_BASE: &str = "https://api.anthropic.com";
/// The beta that opts an OAuth bearer token into the Anthropic API.
pub const OAUTH_BETA: &str = "oauth-2025-04-20";
/// The beta that marks a request as Claude Code traffic.
pub const CLAUDE_CODE_BETA: &str = "claude-code-20250219";
/// The hosted callback that renders the authorization code for the user to copy.
pub const REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
/// The scope set the official Claude Code client requests.
pub const SCOPES: &str = "org:create_api_key user:profile user:inference \
                          user:sessions:claude_code user:mcp_servers user:file_upload user:plugins";

/// The Anthropic API base. Overridable so tests can point at a mock upstream.
pub fn api_base() -> String {
    std::env::var("UNDERCLASS_CLAUDE_UPSTREAM").unwrap_or_else(|_| API_BASE.to_string())
}

pub const UNIFIED_STATUS: &str = "anthropic-ratelimit-unified-status";
pub const UNIFIED_RESET: &str = "anthropic-ratelimit-unified-reset";
pub const UNIFIED_CLAIM: &str = "anthropic-ratelimit-unified-representative-claim";
pub const UNIFIED_5H_UTILIZATION: &str = "anthropic-ratelimit-unified-5h-utilization";
pub const UNIFIED_5H_RESET: &str = "anthropic-ratelimit-unified-5h-reset";
pub const UNIFIED_7D_UTILIZATION: &str = "anthropic-ratelimit-unified-7d-utilization";
pub const UNIFIED_7D_RESET: &str = "anthropic-ratelimit-unified-7d-reset";

/// The identity lines the official client puts in the request's system blocks.
const IDENTITY_PREFIXES: [&str; 3] = [
    "x-anthropic-billing-header:",
    "You are Claude Code, Anthropic's official CLI for Claude.",
    "You are a Claude agent, built on Anthropic's Claude Agent SDK.",
];

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("unexpected status {0}")]
    Status(u16),
    #[error("authorization failed: {0}")]
    Failed(String),
}

/// The scope a Claude 429 applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaScope {
    /// The credential's shared window is exhausted: every model on the account is blocked.
    Credential,
    /// Only one model is refused: the account keeps serving its other models.
    Model,
    /// The request itself was refused; nothing is exhausted.
    Request,
    /// The upstream refused the request without saying what was exhausted.
    Unknown,
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn status_rejected(headers: &HeaderMap, name: &str) -> bool {
    header_value(headers, name).is_some_and(|value| value.eq_ignore_ascii_case("rejected"))
}

/// @cc [owner:ghuntley,label:pool] claude-429-scope
/// `quota_scope` MUST report a credential-wide scope when the shared five-hour or seven-day
/// window is rejected, MUST report a model scope when only a model-scoped window (the weekly
/// other-models window, overage, or an overage-disabled reason) is rejected while the shared
/// windows are healthy, and MUST report a request scope for the upstream's fast-rejection and
/// credits-required messages.
pub fn quota_scope(headers: &HeaderMap, body: &str) -> QuotaScope {
    let weekly_other = header_value(headers, "anthropic-ratelimit-unified-7d_oi-status");
    let overage = header_value(headers, "anthropic-ratelimit-unified-overage-status");
    let unified = header_value(headers, UNIFIED_STATUS);
    let representative = header_value(headers, UNIFIED_CLAIM)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let overage_disabled = header_value(
        headers,
        "anthropic-ratelimit-unified-overage-disabled-reason",
    )
    .is_some();
    let has_header = weekly_other.is_some() || overage.is_some() || unified.is_some();
    let shared_healthy = !status_rejected(headers, "anthropic-ratelimit-unified-5h-status")
        && !status_rejected(headers, "anthropic-ratelimit-unified-7d-status");
    let model_rejected = status_rejected(headers, "anthropic-ratelimit-unified-7d_oi-status")
        || status_rejected(headers, "anthropic-ratelimit-unified-overage-status")
        || representative.contains("overage")
        || overage_disabled;

    if status_rejected(headers, "anthropic-ratelimit-unified-5h-status")
        || status_rejected(headers, "anthropic-ratelimit-unified-7d-status")
    {
        return QuotaScope::Credential;
    }
    if model_rejected && shared_healthy {
        return QuotaScope::Model;
    }
    if status_rejected(headers, UNIFIED_STATUS) {
        return if model_rejected && shared_healthy {
            QuotaScope::Model
        } else {
            QuotaScope::Credential
        };
    }
    if has_header {
        if model_rejected && shared_healthy {
            return QuotaScope::Model;
        }
        for name in [
            "anthropic-ratelimit-unified-7d_oi-status",
            "anthropic-ratelimit-unified-overage-status",
            UNIFIED_STATUS,
        ] {
            if header_value(headers, name).is_some_and(|value| {
                !value.eq_ignore_ascii_case("allowed")
                    && !value.eq_ignore_ascii_case("allowed_warning")
            }) {
                return QuotaScope::Credential;
            }
        }
        return QuotaScope::Model;
    }
    let text = body.to_ascii_lowercase();
    for phrase in [
        "fast request rejected",
        "usage credits are required",
        "credits are required",
    ] {
        if text.contains(phrase) {
            return QuotaScope::Request;
        }
    }
    for phrase in [
        "model overloaded",
        "model is overloaded",
        "model rate limit",
        "model quota",
    ] {
        if text.contains(phrase) {
            return QuotaScope::Model;
        }
    }
    // Nothing in the response says what was exhausted: do not cool anything.
    QuotaScope::Unknown
}

/// A quota window as the response headers report it.
fn header_window(headers: &HeaderMap, utilization: &str, reset: &str) -> Option<UsageWindow> {
    let utilization: f64 = header_value(headers, utilization)?.parse().ok()?;
    let resets_at_ms = header_value(headers, reset)?
        .parse::<i64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1000))?;
    Some(UsageWindow {
        reported: true,
        utilization: Some(utilization),
        resets_at_ms: Some(resets_at_ms),
    })
}

/// The model name without Claude Code's thinking suffix, lowercased.
pub fn canonical_model(model: &str) -> String {
    crate::models::normalize_model_name(model)
}

/// One quota window as the account's own usage API reports it.
#[derive(Clone, Debug, Default)]
pub struct UsageWindow {
    /// A non-null window was reported. Missing/invalid utilization is not headroom.
    pub reported: bool,
    /// Fraction of the window consumed; values at or above 1.0 are exhausted.
    pub utilization: Option<f64>,
    /// When the window resets, in epoch milliseconds.
    pub resets_at_ms: Option<i64>,
}

/// The subscription quota of one account, as the account's own usage API reports it.
#[derive(Clone, Debug, Default)]
pub struct UsageSnapshot {
    pub plan: Option<String>,
    pub five_hour: UsageWindow,
    pub seven_day: UsageWindow,
    pub seven_day_fable: UsageWindow,
    /// Banked rate-limit reset credits the account can redeem.
    pub reset_credits: Option<i64>,
    pub observed_at_ms: i64,
}

impl UsageSnapshot {
    /// @cc [owner:ghuntley,label:pool] claude-shared-exhaustion-deadline
    /// Account exhaustion MUST consider only shared five-hour/seven-day windows and MUST
    /// return the latest exhausted reset strictly after the observation time, never a family reset.
    pub fn exhausted_reset_ms(&self) -> Option<i64> {
        [&self.five_hour, &self.seven_day]
            .into_iter()
            .filter_map(|window| {
                let utilization = window.utilization?;
                if utilization.is_finite() && utilization >= 1.0 {
                    window.resets_at_ms
                } else {
                    None
                }
            })
            .filter(|reset| *reset > self.observed_at_ms)
            .max()
    }

    /// @cc [owner:ghuntley,label:pool] claude-shared-headroom-evidence
    /// Headroom MUST require at least one valid shared utilization below 100% and MUST
    /// reject every reported malformed, negative, nonfinite, or exhausted shared utilization.
    /// Absent/null shared windows are nonapplicable; family windows MUST NOT affect this result.
    pub fn shared_headroom(&self) -> bool {
        let mut observed = false;
        for window in [&self.five_hour, &self.seven_day] {
            match window.utilization {
                Some(used) if (0.0..1.0).contains(&used) => observed = true,
                None if !window.reported => {}
                _ => return false,
            }
        }
        observed
    }
}

/// Parses the account usage payload.
pub fn parse_usage(body: &Value, now_ms: i64) -> UsageSnapshot {
    let window = |payload: Option<&Value>| UsageWindow {
        reported: payload.is_some_and(|value| !value.is_null()),
        // The usage API reports percent (`26.0`); everything downstream, like the unified
        // rate-limit headers, works in fractions of the window.
        utilization: payload
            .and_then(|w| w.get("utilization"))
            .and_then(Value::as_f64)
            .filter(|percent| percent.is_finite() && *percent >= 0.0)
            .map(|percent| percent / 100.0),
        resets_at_ms: payload
            .and_then(|w| w.get("resets_at"))
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.timestamp_millis()),
    };
    UsageSnapshot {
        plan: body
            .get("plan_type")
            .and_then(Value::as_str)
            .map(str::to_string),
        five_hour: window(body.get("five_hour")),
        seven_day: window(body.get("seven_day")),
        seven_day_fable: window(body.get("seven_day_fable")),
        reset_credits: body
            .get("rate_limit_reset_credits")
            .and_then(|credits| credits.get("available_count"))
            .and_then(Value::as_i64),
        observed_at_ms: now_ms,
    }
}

/// Fetches the account's own usage: plan, quota windows, and banked reset credits.
///
/// This is a first-party account API, so underclass reads an account's quota without sending
/// anything that looks like a Claude Code request.
pub async fn fetch_usage(
    client: &Client,
    account: &Account,
    token: &str,
) -> Result<UsageSnapshot, AuthError> {
    let mut request = client.get(format!("{}/api/oauth/usage", api_base()));
    request = request.header("authorization", format!("Bearer {token}"));
    if let Some(account_id) = account.account_id.as_deref() {
        request = request.header("anthropic-account-id", account_id);
    }
    let resp = request.send().await?;
    if !resp.status().is_success() {
        return Err(AuthError::Status(resp.status().as_u16()));
    }
    let body: Value = resp.json().await?;
    Ok(parse_usage(&body, now_ms()))
}

/// The account usage as the admin UI shows it.
pub fn usage_view(snapshot: &UsageSnapshot) -> Value {
    let window = |window: &UsageWindow| {
        serde_json::json!({
            "utilization": window.utilization,
            "resets_at_ms": window.resets_at_ms,
        })
    };
    serde_json::json!({
        "plan": snapshot.plan,
        "five_hour": window(&snapshot.five_hour),
        "seven_day": window(&snapshot.seven_day),
        "seven_day_fable": window(&snapshot.seven_day_fable),
        "reset_credits": snapshot.reset_credits,
        "observed_at_ms": snapshot.observed_at_ms,
    })
}

/// @cc [owner:ghuntley,label:pool] claude-fable-observation-scope
/// A valid exhausted Fable observation MUST cool only the `claude-fable-` family until its
/// future reset. Valid headroom or an absent/null nonapplicable Fable window MUST clear only
/// that family observation, never exact-model HTTP cooldowns. Malformed reported windows and
/// Disabled/AuthError/deleted accounts MUST NOT change family cooldowns.
pub fn reconcile_family_quota(
    core: &mut crate::pool::PoolCore,
    account_id: &str,
    snapshot: &UsageSnapshot,
    now: i64,
) {
    if !core.account(account_id).is_some_and(|account| {
        matches!(
            account.status,
            crate::models::AccountStatus::Healthy | crate::models::AccountStatus::Cooling
        )
    }) {
        return;
    }
    let family = &snapshot.seven_day_fable;
    if !family.reported && family.utilization.is_none() {
        core.clear_model_family_quota(account_id, "claude-fable-");
        return;
    }
    if let Some(used) = family.utilization {
        if used.is_finite() && used >= 1.0 {
            if let Some(until) = family.resets_at_ms.filter(|until| *until > now) {
                core.report_model_family_quota(account_id, "claude-fable-", until);
            }
        } else if (0.0..1.0).contains(&used) {
            core.clear_model_family_quota(account_id, "claude-fable-");
        }
    }
}

/// A banked rate-limit reset credit.
#[derive(Clone, Debug, Deserialize)]
pub struct ResetCredit {
    pub id: String,
    #[serde(default)]
    pub reset_type: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl ResetCredit {
    /// Whether the credit can still be redeemed.
    pub fn available(&self) -> bool {
        self.reset_type.as_deref() == Some("claude_rate_limits")
            && self.status.as_deref() == Some("available")
    }

    /// When the credit expires, in epoch milliseconds.
    pub fn expires_at_ms(&self) -> Option<i64> {
        self.expires_at
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.timestamp_millis())
    }
}

#[derive(Debug, Deserialize)]
struct ResetCreditsPayload {
    #[serde(default)]
    credits: Vec<ResetCredit>,
}

/// Fetches the account's banked reset credits.
pub async fn fetch_reset_credits(
    client: &Client,
    account: &Account,
    token: &str,
) -> Result<Vec<ResetCredit>, AuthError> {
    let mut request = client.get(format!("{}/api/oauth/rate-limit-reset-credits", api_base()));
    request = request.header("authorization", format!("Bearer {token}"));
    if let Some(account_id) = account.account_id.as_deref() {
        request = request.header("anthropic-account-id", account_id);
    }
    let resp = request.send().await?;
    if !resp.status().is_success() {
        return Err(AuthError::Status(resp.status().as_u16()));
    }
    let payload: ResetCreditsPayload = resp.json().await?;
    Ok(payload.credits)
}

/// Redeems one banked reset credit.
pub async fn consume_reset_credit(
    client: &Client,
    account: &Account,
    token: &str,
    credit_id: &str,
    request_id: &str,
) -> Result<Value, AuthError> {
    let mut request = client.post(format!(
        "{}/api/oauth/rate-limit-reset-credits/consume",
        api_base()
    ));
    request = request
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    if let Some(account_id) = account.account_id.as_deref() {
        request = request.header("anthropic-account-id", account_id);
    }
    let resp = request
        .json(&serde_json::json!({
            "redeem_request_id": request_id,
            "credit_id": credit_id,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(AuthError::Status(resp.status().as_u16()));
    }
    Ok(resp.json().await?)
}

/// The outcome of an operator-initiated Claude reset redemption.
#[derive(Clone, Debug, Serialize)]
pub struct ClaudeResetOutcome {
    /// Upstream redemption code.
    pub outcome: String,
    pub credit_id: String,
    /// Pool status after the redemption.
    pub status: crate::models::AccountStatus,
    /// Banked credits upstream still reports as available.
    pub available_resets: i64,
}

/// Why an operator-initiated Claude redemption did not consume a credit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaudeResetError {
    /// Upstream reports ordinary usage allowed; redeeming would waste the credit.
    NotRateLimited,
    /// Upstream lists no available credit.
    NoCredit,
    /// The upstream call failed.
    Upstream(&'static str),
}

impl ClaudeResetError {
    pub fn code(&self) -> &'static str {
        match self {
            ClaudeResetError::NotRateLimited => "not_rate_limited",
            ClaudeResetError::NoCredit => "no_credit",
            ClaudeResetError::Upstream(_) => "upstream_error",
        }
    }

    pub fn message(&self) -> String {
        match self {
            ClaudeResetError::NotRateLimited => {
                "upstream reports this account is not rate limited".into()
            }
            ClaudeResetError::NoCredit => "upstream lists no available reset credit".into(),
            ClaudeResetError::Upstream(reason) => format!("upstream call failed: {reason}"),
        }
    }
}

/// @cc [owner:ghuntley,label:pool] claude-reset-consume-outcome
/// Only `reset` and `already_redeemed` MUST count as successful consume outcomes. `no_credit`
/// MUST return NoCredit, `nothing_to_reset` MUST return NotRateLimited even when forced, and missing, invalid,
/// or unknown codes MUST return Upstream without changing account status.
fn reset_consume_code(body: &Value) -> Result<&str, ClaudeResetError> {
    match body.get("code").and_then(Value::as_str) {
        Some(code @ ("reset" | "already_redeemed")) => Ok(code),
        Some("no_credit") => Err(ClaudeResetError::NoCredit),
        Some("nothing_to_reset") => Err(ClaudeResetError::NotRateLimited),
        _ => Err(ClaudeResetError::Upstream("consume outcome")),
    }
}

/// @cc [owner:ghuntley,label:pool] claude-reset-readmission-guard
/// Fresh valid shared headroom MAY readmit only a currently Cooling existing account.
/// Disabled/AuthError/Healthy account statuses and deleted accounts MUST remain unchanged.
/// Status persistence MUST hold the pool lock through the store write; the returned status
/// MUST be the current one.
fn reconcile_reset_status(
    pool: &Arc<std::sync::Mutex<crate::pool::PoolCore>>,
    store: &Store,
    account_id: &str,
    usage: &UsageSnapshot,
) -> Result<crate::models::AccountStatus, ClaudeResetError> {
    let mut core = pool.lock().unwrap();
    let status = core
        .account(account_id)
        .map(|account| account.status)
        .ok_or(ClaudeResetError::Upstream("account removed"))?;
    reconcile_family_quota(&mut core, account_id, usage, now_ms());
    if status == crate::models::AccountStatus::Cooling && usage.shared_headroom() {
        core.set_status(account_id, crate::models::AccountStatus::Healthy, 0);
        store.update_account_status(account_id, crate::models::AccountStatus::Healthy, 0);
        return Ok(crate::models::AccountStatus::Healthy);
    }
    Ok(status)
}

/// @cc [owner:ghuntley,label:pool] claude-manual-reset-redeems-one-credit
/// `manual_reset` MUST consume at most one available credit and MUST refuse when neither shared
/// nor family exhaustion is reported unless forced. After consumption, only explicit success
/// followed by fresh valid shared headroom MAY readmit a currently Cooling account. When no
/// window remains exhausted, fresh pre-consume headroom MUST reconcile an external reset
/// without spending a credit when not forced.
/// A confirmed consumption MUST still return its outcome and current status if follow-up usage
/// is unavailable, without changing status or family cooldowns in the absence of fresh evidence.
pub async fn manual_reset(
    client: &Client,
    account: &Account,
    token: &str,
    pool: &Arc<std::sync::Mutex<crate::pool::PoolCore>>,
    store: &Store,
    force: bool,
) -> Result<ClaudeResetOutcome, ClaudeResetError> {
    let usage = fetch_usage(client, account, token)
        .await
        .map_err(|_| ClaudeResetError::Upstream("usage"))?;
    let family = &usage.seven_day_fable;
    let exhausted = usage.exhausted_reset_ms().is_some()
        || (family
            .utilization
            .is_some_and(|used| used.is_finite() && used >= 1.0)
            && family
                .resets_at_ms
                .is_some_and(|reset| reset > usage.observed_at_ms));
    if !exhausted && !force {
        reconcile_reset_status(pool, store, &account.id, &usage)?;
        return Err(ClaudeResetError::NotRateLimited);
    }
    let credits = fetch_reset_credits(client, account, token)
        .await
        .map_err(|_| ClaudeResetError::Upstream("credits"))?;
    let Some(credit) = credits
        .into_iter()
        .filter(|credit| credit.available())
        .min_by_key(|credit| credit.expires_at_ms().unwrap_or(i64::MAX))
    else {
        return Err(ClaudeResetError::NoCredit);
    };
    let request_id = uuid::Uuid::new_v4().to_string();
    let body = consume_reset_credit(client, account, token, &credit.id, &request_id)
        .await
        .map_err(|_| ClaudeResetError::Upstream("consume"))?;
    let code = reset_consume_code(&body)?.to_string();
    let remaining = fetch_reset_credits(client, account, token)
        .await
        .map(|credits| credits.iter().filter(|credit| credit.available()).count() as i64)
        .unwrap_or(0);
    let status = match fetch_usage(client, account, token).await {
        Ok(usage) => reconcile_reset_status(pool, store, &account.id, &usage)?,
        Err(_) => pool
            .lock()
            .unwrap()
            .account(&account.id)
            .map(|account| account.status)
            .ok_or(ClaudeResetError::Upstream("account removed"))?,
    };
    Ok(ClaudeResetOutcome {
        outcome: code,
        credit_id: credit.id,
        status,
        available_resets: remaining,
    })
}

/// @cc [owner:ghuntley,label:pool] claude-quota-reset-from-headers
/// `unified_reset_ms` MUST return the absolute epoch-millisecond reset of the window Anthropic
/// reports as the representative claim, preferring the general unified reset, and MUST return
/// `None` when no usable reset is present.
pub fn unified_reset_ms(headers: &HeaderMap) -> Option<i64> {
    let general = headers
        .get(UNIFIED_RESET)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|seconds| seconds.saturating_mul(1000));
    if general.is_some() {
        return general;
    }
    let claim = headers
        .get(UNIFIED_CLAIM)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let window = match claim {
        "five_hour" => UNIFIED_5H_RESET,
        "seven_day" | "seven_day_opus" | "seven_day_sonnet" => UNIFIED_7D_RESET,
        _ => return None,
    };
    headers
        .get(window)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|seconds| seconds.saturating_mul(1000))
}

/// Whether the request carries the Claude Code client fingerprint Anthropic validates.
pub fn is_claude_code_client(headers: &HeaderMap, body: &Value) -> bool {
    let app_ok = headers
        .get("x-app")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "cli");
    let agent_ok = headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("claude-cli/"));
    let beta_ok = headers
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|beta| beta.trim() == CLAUDE_CODE_BETA));
    app_ok && agent_ok && beta_ok && has_claude_code_identity(body)
}

/// Whether the request body carries a Claude Code identity or billing block.
fn has_claude_code_identity(body: &Value) -> bool {
    let Some(system) = body.get("system") else {
        return false;
    };
    let texts: Vec<&str> = match system {
        Value::String(text) => vec![text.as_str()],
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.get("text"))
            .filter_map(Value::as_str)
            .collect(),
        _ => Vec::new(),
    };
    texts.iter().any(|text| {
        IDENTITY_PREFIXES
            .iter()
            .any(|prefix| text.starts_with(prefix))
    })
}

/// The sticky key for an Anthropic request: the client's session header, else the session id
/// inside `metadata.user_id`.
pub fn sticky_key(headers: &HeaderMap, body: &Value) -> Option<String> {
    if let Some(session) = headers
        .get("x-claude-code-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(session.to_string());
    }
    let user_id = body
        .get("metadata")
        .and_then(|m| m.get("user_id"))
        .and_then(Value::as_str)?;
    if let Ok(parsed) = serde_json::from_str::<Value>(user_id) {
        if let Some(session) = parsed
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(session.to_string());
        }
        return None;
    }
    user_id
        .split("_session_")
        .nth(1)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// PKCE material for one authorization attempt.
#[derive(Clone, Debug)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    out.truncate(len);
    out
}

/// @cc [owner:ghuntley,label:auth] claude-pkce-challenge
/// `new_pkce` MUST produce a verifier of at least 43 characters, a distinct random state, and a
/// challenge that is the base64url-encoded SHA-256 of the verifier.
pub fn new_pkce() -> Pkce {
    let verifier = URL_SAFE_NO_PAD.encode(random_bytes(48));
    let state = URL_SAFE_NO_PAD.encode(random_bytes(32));
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
        state,
    }
}

fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(ch),
            ' ' => out.push('+'),
            other => {
                let mut buf = [0u8; 4];
                for byte in other.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
        }
    }
    out
}

/// The authorization URL the user opens to sign in.
pub fn authorize_url(pkce: &Pkce) -> String {
    format!(
        "{AUTHORIZE_URL}?code=true&client_id={CLIENT_ID}&response_type=code\
&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
        encode_component(REDIRECT_URI),
        encode_component(SCOPES),
        encode_component(&pkce.challenge),
        encode_component(&pkce.state),
    )
}

/// Splits the pasted authorization code into its parts.
///
/// The callback page shows `code#state`, and a local OAuth callback shows a full address such
/// as `http://localhost:54545/callback?code=…&state=…`; both are accepted.
pub fn split_pasted_code(pasted: &str) -> (String, Option<String>) {
    let trimmed = pasted.trim();
    if let Some((code, state)) = trimmed.split_once('#') {
        return (
            code.trim().to_string(),
            Some(state.trim().to_string()).filter(|s| !s.is_empty()),
        );
    }
    if trimmed.contains("code=") {
        let query = trimmed
            .split_once('?')
            .map(|(_, query)| query)
            .unwrap_or(trimmed);
        let mut code = None;
        let mut state = None;
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let value = percent_decode(value);
            match key {
                "code" => code = Some(value),
                "state" => state = Some(value),
                _ => {}
            }
        }
        if let Some(code) = code {
            return (code, state.filter(|s| !s.is_empty()));
        }
    }
    (trimmed.to_string(), None)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

#[derive(Debug, Deserialize)]
pub struct TokenAccount {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub email_address: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenOrganization {
    #[serde(default)]
    pub uuid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub account: Option<TokenAccount>,
    #[serde(default)]
    pub organization: Option<TokenOrganization>,
}

/// Exchanges the pasted authorization code for tokens.
pub async fn exchange(
    client: &Client,
    code: &str,
    state: &str,
    verifier: &str,
) -> Result<TokenResponse, AuthError> {
    let resp = client
        .post(TOKEN_URL)
        .header("content-type", "application/json")
        .json(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
            "state": state,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(AuthError::Status(resp.status().as_u16()));
    }
    Ok(resp.json().await?)
}

/// @cc [owner:ghuntley,label:auth] claude-refresh-keeps-granted-scopes
/// `refresh_body` MUST NOT request a `scope`: the refresh grant keeps the scopes granted at
/// login, and the token endpoint rejects the login scope list (`org:create_api_key` is never
/// granted) with `invalid_scope`, which left accounts with an expired token.
fn refresh_body(refresh_token: &str) -> Value {
    json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    })
}

/// Refreshes an access token. The refresh token rotates, so the caller must persist the new one.
pub async fn refresh(client: &Client, refresh_token: &str) -> Result<TokenResponse, AuthError> {
    let resp = client
        .post(TOKEN_URL)
        .header("content-type", "application/json")
        .json(&refresh_body(refresh_token))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(AuthError::Status(resp.status().as_u16()));
    }
    Ok(resp.json().await?)
}

#[derive(Debug, Deserialize)]
pub struct ProfileAccount {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProfileOrganization {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub organization_type: Option<String>,
    #[serde(default)]
    pub rate_limit_tier: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProfileResponse {
    #[serde(default)]
    pub account: Option<ProfileAccount>,
    #[serde(default)]
    pub organization: Option<ProfileOrganization>,
}

/// The subscription plan an organization type maps to.
pub fn plan_for(organization_type: Option<&str>) -> Option<String> {
    let plan = match organization_type {
        Some("claude_max") => "max",
        Some("claude_pro") => "pro",
        Some("claude_team") => "team",
        Some("claude_enterprise") => "enterprise",
        _ => return None,
    };
    Some(plan.to_string())
}

/// Fetches the account's identity and plan.
pub async fn fetch_profile(client: &Client, token: &str) -> Result<ProfileResponse, AuthError> {
    let resp = client
        .get(format!("{}/api/oauth/profile", api_base()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(AuthError::Status(resp.status().as_u16()));
    }
    Ok(resp.json().await?)
}

/// The identity of a Claude account: its label and plan.
pub struct Identity {
    pub label: String,
    pub plan: Option<String>,
    pub account_id: Option<String>,
}

/// Resolves the account label and plan from a profile response.
pub fn identity_from_profile(profile: &ProfileResponse) -> Identity {
    let account = profile.account.as_ref();
    let label = account
        .and_then(|a| a.email.clone())
        .or_else(|| account.and_then(|a| a.display_name.clone()))
        .unwrap_or_else(|| "claude".to_string());
    Identity {
        label,
        plan: plan_for(
            profile
                .organization
                .as_ref()
                .and_then(|o| o.organization_type.as_deref()),
        ),
        account_id: account
            .and_then(|a| a.uuid.clone())
            .or_else(|| profile.organization.as_ref().and_then(|o| o.uuid.clone())),
    }
}

/// @cc [owner:ghuntley,label:pool] claude-catalog-from-models-api
/// `parse_models_response` MUST read the Anthropic Models API shape and MUST skip entries
/// without an id, a display name, or token limits.
pub fn parse_models_response(body: &Value) -> Vec<ModelInfo> {
    let Some(items) = body.get("data").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        let Some(id) = item
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let Some(input) = item.get("max_input_tokens").and_then(Value::as_i64) else {
            continue;
        };
        let Some(output) = item.get("max_tokens").and_then(Value::as_i64) else {
            continue;
        };
        let name = item
            .get("display_name")
            .and_then(Value::as_str)
            .unwrap_or(id)
            .to_string();
        out.push(ModelInfo {
            id: id.to_string(),
            name,
            context: input,
            input,
            output,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Fetches the live model catalog with the account's token.
pub async fn fetch_catalog(
    client: &Client,
    _account: &Account,
    token: &str,
) -> Result<Vec<ModelInfo>, AuthError> {
    let resp = client
        .get(format!("{}/v1/models", api_base()))
        .header("authorization", format!("Bearer {token}"))
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", OAUTH_BETA)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(AuthError::Status(resp.status().as_u16()));
    }
    let body: Value = resp.json().await?;
    Ok(parse_models_response(&body))
}

/// The static catalog seed, used until the live catalog is fetched.
pub fn default_catalog() -> Vec<ModelInfo> {
    let entries: &[(&str, &str, i64, i64)] = &[
        ("claude-haiku-5-5", "Claude Haiku 5.5", 1_000_000, 128_000),
        ("claude-sonnet-5-5", "Claude Sonnet 5.5", 1_000_000, 128_000),
        ("claude-opus-5-5", "Claude Opus 5.5", 1_000_000, 128_000),
        ("claude-fable-5-1", "Claude Fable 5.1", 1_000_000, 128_000),
        ("claude-opus-5", "Claude Opus 5", 1_000_000, 128_000),
        ("claude-sonnet-5", "Claude Sonnet 5", 1_000_000, 128_000),
        ("claude-fable-5", "Claude Fable 5", 1_000_000, 128_000),
        ("claude-opus-4-8", "Claude Opus 4.8", 1_000_000, 128_000),
        ("claude-opus-4-7", "Claude Opus 4.7", 1_000_000, 128_000),
        ("claude-sonnet-4-6", "Claude Sonnet 4.6", 1_000_000, 128_000),
        ("claude-opus-4-6", "Claude Opus 4.6", 1_000_000, 128_000),
        (
            "claude-opus-4-5-20251101",
            "Claude Opus 4.5",
            200_000,
            64_000,
        ),
        (
            "claude-haiku-4-5-20251001",
            "Claude Haiku 4.5",
            200_000,
            64_000,
        ),
        (
            "claude-sonnet-4-5-20250929",
            "Claude Sonnet 4.5",
            200_000,
            64_000,
        ),
    ];
    entries
        .iter()
        .map(|(id, name, input, output)| ModelInfo {
            id: id.to_string(),
            name: name.to_string(),
            context: *input,
            input: *input,
            output: *output,
        })
        .collect()
}

/// Starts the paste-back authorization flow: the user opens the returned URL, signs in, and
/// pastes the code the hosted callback shows.
pub async fn start_flow(
    _client: Client,
    store: Arc<Store>,
    flows: FlowRegistry,
    replace_account: Option<String>,
) -> Result<String, AuthError> {
    let pkce = new_pkce();
    let url = authorize_url(&pkce);
    let flow_id = flows.create_with_oauth(
        BackendId::Claude,
        FlowState::AwaitingCode { authorize_url: url },
        replace_account,
        Some(OAuthState {
            verifier: pkce.verifier,
            state: pkce.state,
        }),
    );
    let _ = store;
    Ok(flow_id)
}

/// Completes the flow with the code the user pasted back.
pub async fn submit_code(
    client: Client,
    store: Arc<Store>,
    flows: FlowRegistry,
    flow_id: &str,
    pasted: &str,
) -> Result<String, AuthError> {
    let Some(flow) = flows.get(flow_id) else {
        return Err(AuthError::Failed("unknown flow".into()));
    };
    let Some(oauth) = flow.oauth else {
        return Err(AuthError::Failed("flow is not awaiting a code".into()));
    };
    let (code, returned_state) = split_pasted_code(pasted);
    if code.is_empty() {
        return Err(AuthError::Failed("no authorization code".into()));
    }
    if let Some(returned) = returned_state
        && returned != oauth.state
    {
        return Err(AuthError::Failed(
            "state mismatch: paste the whole code#state".into(),
        ));
    }
    let tokens = exchange(&client, &code, &oauth.state, &oauth.verifier).await?;
    let ts = now_ms();
    let profile = fetch_profile(&client, &tokens.access_token).await.ok();
    let identity = profile
        .as_ref()
        .map(identity_from_profile)
        .unwrap_or(Identity {
            label: "claude".into(),
            plan: None,
            account_id: None,
        });
    let account_id = tokens
        .account
        .as_ref()
        .and_then(|a| a.uuid.clone())
        .or(identity.account_id.clone());

    let account = match flow
        .replace_account
        .as_deref()
        .and_then(|id| store.get_account(id))
    {
        Some(mut existing) => {
            existing.refresh_token = tokens.refresh_token.clone().or(existing.refresh_token);
            existing.access_token = Some(tokens.access_token.clone());
            existing.expires_at = ts + (tokens.expires_in.unwrap_or(3600) as i64) * 1000;
            existing.account_id = account_id.or(existing.account_id);
            existing.plan = identity.plan.clone().or(existing.plan);
            existing.status = crate::models::AccountStatus::Healthy;
            existing.reset_at = 0;
            existing.token_refreshed_at = ts;
            existing.updated_at = ts;
            existing
        }
        None => {
            let mut account = crate::flows::new_account(BackendId::Claude, identity.label.clone());
            account.refresh_token = tokens.refresh_token.clone();
            account.access_token = Some(tokens.access_token.clone());
            account.expires_at = ts + (tokens.expires_in.unwrap_or(3600) as i64) * 1000;
            account.account_id = account_id;
            account.plan = identity.plan.clone();
            account.token_refreshed_at = ts;
            account
        }
    };
    store.upsert_account(&account);
    if let Ok(catalog) = fetch_catalog(&client, &account, &tokens.access_token).await
        && !catalog.is_empty()
    {
        store.set_catalog(BackendId::Claude, &catalog);
    }
    flows.set_state(
        flow_id,
        FlowState::Authorized {
            account_id: account.id.clone(),
        },
    );
    Ok(account.id)
}

pub struct ClaudeBackend {
    pub cooldown_ms: i64,
}

impl Backend for ClaudeBackend {
    fn id(&self) -> BackendId {
        BackendId::Claude
    }

    fn surfaces(&self) -> &'static [Surface] {
        &[Surface::Anthropic]
    }

    fn default_cooldown_ms(&self) -> i64 {
        self.cooldown_ms
    }

    fn usage_is_chat(&self, _path: &str) -> bool {
        false
    }

    fn usage_dialect(&self, _path: &str) -> UsageDialect {
        UsageDialect::Anthropic
    }

    /// The Anthropic API validates the Claude Code client fingerprint, so the client's own
    /// headers travel upstream untouched.
    fn forward_client_headers(&self) -> bool {
        true
    }

    /// The request body carries the identity and billing blocks Anthropic checks, so it is
    /// forwarded byte for byte.
    fn forward_body_verbatim(&self) -> bool {
        true
    }

    /// @cc [owner:ghuntley,label:proxy] claude-only-claude-code-clients
    /// `accepts_client` MUST admit only requests carrying the Claude Code client fingerprint:
    /// `x-app: cli`, a `claude-cli/` user agent, the `claude-code-20250219` beta, and a Claude
    /// Code identity or billing block in the body.
    fn accepts_client(&self, headers: &HeaderMap, body: &Value) -> bool {
        is_claude_code_client(headers, body)
    }

    fn rewrite_url(&self, path: &str, _account: &Account) -> String {
        // The Anthropic API lives under `/v1`. The proxy's routes are nested under `/v1` as
        // well, so the path arrives without that prefix.
        let path = if path.starts_with("/v1/") {
            path.to_string()
        } else {
            format!("/v1{path}")
        };
        format!("{}{path}", api_base())
    }

    /// @cc [owner:ghuntley,label:proxy] claude-credential-swap
    /// Outbound Anthropic requests MUST carry the selected account's OAuth token as a bearer
    /// credential, MUST keep the client's `anthropic-beta` list and add `oauth-2025-04-20` to
    /// it, and MUST NOT forward the client's own credential headers.
    fn inject_headers(
        &self,
        _account: &Account,
        token: &str,
        _sticky: Option<&str>,
        _body: &Value,
        client: &HeaderMap,
        headers: &mut HeaderMap,
    ) {
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer"),
        );
        let mut betas: Vec<String> = client
            .get("anthropic-beta")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|beta| !beta.is_empty())
            .map(str::to_string)
            .collect();
        if !betas.iter().any(|beta| beta == OAUTH_BETA) {
            betas.push(OAUTH_BETA.to_string());
        }
        if let Ok(value) = http::HeaderValue::from_str(&betas.join(",")) {
            headers.insert("anthropic-beta", value);
        }
        if !headers.contains_key("anthropic-version") {
            headers.insert(
                "anthropic-version",
                http::HeaderValue::from_static("2023-06-01"),
            );
        }
    }

    /// @cc [owner:ghuntley,label:pool] claude-classify-window-quota
    /// `classify` MUST treat a 429 that carries Anthropic's unified rate-limit headers as
    /// `QuotaExhausted` until the reported window reset, MUST treat a 429 without them as a
    /// credential rejection that is transient rather than a quota exhaustion, and MUST leave
    /// 5xx (including the 529 overload) transient.
    fn classify(&self, status: u16, body: &str, headers: &HeaderMap, now_ms: i64) -> Outcome {
        if status == 429 {
            let until = || {
                unified_reset_ms(headers)
                    .or_else(|| crate::health::parse_retry_after_headers(headers, now_ms))
                    .unwrap_or_else(|| now_ms.saturating_add(self.cooldown_ms))
                    .max(now_ms)
            };
            return match quota_scope(headers, body) {
                // The shared window is exhausted: every model on this account is blocked.
                QuotaScope::Credential => Outcome::QuotaExhausted { until_ms: until() },
                // Only this model is refused: the account keeps serving its other models.
                QuotaScope::Model => Outcome::ModelQuotaExhausted { until_ms: until() },
                // The request was refused, or nothing says what was exhausted.
                QuotaScope::Request | QuotaScope::Unknown => Outcome::Transient,
            };
        }
        crate::health::classify(status, headers, self.cooldown_ms, now_ms)
    }

    /// @cc [owner:ghuntley,label:pool] claude-quota-observation
    /// `observe_response` MUST report the subscription's window utilization and resets as the
    /// upstream reported them, and MUST report nothing when the upstream sent no window
    /// headers.
    fn observe_response(
        &self,
        _account: &Account,
        _headers: &HeaderMap,
        _now_ms: i64,
    ) -> Option<Value> {
        // The account's own usage API is the authoritative quota source; underclass polls it
        // rather than reconstructing it from response headers.
        None
    }

    /// @cc [owner:ghuntley,label:pool] claude-exhausted-window-cooling
    /// `exhausted_until_ms` MUST return the latest reset of fully consumed shared windows, so
    /// the account leaves rotation until the window resets instead of failing a request.
    fn exhausted_until_ms(&self, headers: &HeaderMap) -> Option<i64> {
        [
            header_window(headers, UNIFIED_5H_UTILIZATION, UNIFIED_5H_RESET),
            header_window(headers, UNIFIED_7D_UTILIZATION, UNIFIED_7D_RESET),
        ]
        .into_iter()
        .flatten()
        .filter(|window| window.utilization.unwrap_or_default() >= 1.0)
        .filter_map(|window| window.resets_at_ms)
        .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn window_quota_uses_the_unified_reset() {
        let backend = ClaudeBackend {
            cooldown_ms: 30_000,
        };
        let map = headers(&[
            ("anthropic-ratelimit-unified-status", "rejected"),
            ("anthropic-ratelimit-unified-reset", "1792506000"),
        ]);
        assert!(matches!(
            backend.classify(429, "{}", &map, 1_000),
            Outcome::QuotaExhausted {
                until_ms: 1_792_506_000_000
            }
        ));
    }

    #[test]
    fn quota_without_window_headers_is_transient() {
        let backend = ClaudeBackend {
            cooldown_ms: 30_000,
        };
        assert!(matches!(
            backend.classify(429, "{}", &HeaderMap::new(), 1_000),
            Outcome::Transient
        ));
    }

    #[test]
    fn overload_is_transient_and_auth_is_auth_failed() {
        let backend = ClaudeBackend {
            cooldown_ms: 30_000,
        };
        let map = HeaderMap::new();
        assert!(matches!(
            backend.classify(529, "{}", &map, 1_000),
            Outcome::Transient
        ));
        assert!(matches!(
            backend.classify(401, "{}", &map, 1_000),
            Outcome::AuthFailed
        ));
    }

    #[test]
    fn exhausted_window_is_read_from_the_response_headers() {
        let map = headers(&[
            ("anthropic-ratelimit-unified-status", "allowed"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.06"),
            ("anthropic-ratelimit-unified-5h-reset", "1792506000"),
            ("anthropic-ratelimit-unified-7d-utilization", "1.0"),
            ("anthropic-ratelimit-unified-7d-reset", "1792728000"),
        ]);
        let backend = ClaudeBackend { cooldown_ms: 1_000 };
        assert_eq!(
            backend.exhausted_until_ms(&map),
            Some(1_792_728_000_000),
            "only the exhausted weekly window counts"
        );
    }

    #[test]
    fn exhausted_shared_headers_use_the_latest_deadline() {
        let map = headers(&[
            (UNIFIED_5H_UTILIZATION, "1.0"),
            (UNIFIED_5H_RESET, "1792506000"),
            (UNIFIED_7D_UTILIZATION, "1.0"),
            (UNIFIED_7D_RESET, "1792728000"),
        ]);
        let backend = ClaudeBackend { cooldown_ms: 1_000 };
        assert_eq!(backend.exhausted_until_ms(&map), Some(1_792_728_000_000));
    }

    #[test]
    fn quota_scope_separates_credential_model_and_request_limits() {
        // The shared five-hour window is rejected: every model on the account is blocked.
        let credential = headers(&[
            ("anthropic-ratelimit-unified-5h-status", "rejected"),
            ("anthropic-ratelimit-unified-7d-status", "allowed"),
            ("anthropic-ratelimit-unified-reset", "1792506000"),
        ]);
        assert_eq!(quota_scope(&credential, ""), QuotaScope::Credential);

        // Only the weekly other-models window is rejected: the account keeps serving the rest.
        let model = headers(&[
            ("anthropic-ratelimit-unified-5h-status", "allowed"),
            ("anthropic-ratelimit-unified-7d-status", "allowed"),
            ("anthropic-ratelimit-unified-7d_oi-status", "rejected"),
        ]);
        assert_eq!(quota_scope(&model, ""), QuotaScope::Model);

        // A request-scoped refusal cools nothing.
        assert_eq!(
            quota_scope(&HeaderMap::new(), "Fast request rejected by the upstream"),
            QuotaScope::Request
        );

        // Nothing says what was exhausted: nothing is cooled.
        assert_eq!(quota_scope(&HeaderMap::new(), "{}"), QuotaScope::Unknown);
    }

    #[test]
    fn model_scoped_limit_does_not_cool_the_account() {
        let backend = ClaudeBackend {
            cooldown_ms: 30_000,
        };
        let map = headers(&[
            ("anthropic-ratelimit-unified-5h-status", "allowed"),
            ("anthropic-ratelimit-unified-7d-status", "allowed"),
            ("anthropic-ratelimit-unified-7d_oi-status", "rejected"),
            ("anthropic-ratelimit-unified-reset", "1792506000"),
        ]);
        assert!(matches!(
            backend.classify(429, "{}", &map, 1_000),
            Outcome::ModelQuotaExhausted {
                until_ms: 1_792_506_000_000
            }
        ));
    }

    #[test]
    fn account_usage_payload_is_parsed() {
        let body = json!({
            "plan_type": "max",
            "five_hour": {"utilization": 7.0, "resets_at": "2026-10-20T13:00:00Z"},
            "seven_day": {"utilization": 5.0, "resets_at": "2026-10-27T00:00:00Z"},
            "seven_day_fable": {"utilization": 100.0, "resets_at": "2026-10-27T00:00:00Z"},
            "rate_limit_reset_credits": {"available_count": 2}
        });
        let snapshot = parse_usage(&body, 1_000);
        assert_eq!(snapshot.plan.as_deref(), Some("max"));
        assert_eq!(snapshot.five_hour.utilization, Some(0.07));
        assert_eq!(snapshot.reset_credits, Some(2));
        assert_eq!(snapshot.exhausted_reset_ms(), None);
        assert!(snapshot.shared_headroom());
    }

    #[test]
    fn shared_headroom_distinguishes_nonapplicable_from_invalid_windows() {
        for nonapplicable in [json!({}), json!({"five_hour": null})] {
            let mut body = nonapplicable;
            body["seven_day"] = json!({"utilization": 20});
            assert!(parse_usage(&body, 1_000).shared_headroom(), "{body}");
        }
        for invalid in [
            json!({}),
            json!({"utilization": null}),
            json!({"utilization": "unknown"}),
            json!({"utilization": "20"}),
            json!({"utilization": -1}),
            json!({"utilization": 100}),
            json!({"utilization": 101}),
            json!([]),
            json!(false),
            json!(20),
        ] {
            for shared in ["five_hour", "seven_day"] {
                let mut body = json!({
                    "five_hour": {"utilization": 20},
                    "seven_day": {"utilization": 20}
                });
                body[shared] = invalid.clone();
                assert!(!parse_usage(&body, 1_000).shared_headroom(), "{body}");
            }
        }
        for body in [
            json!({}),
            json!({"five_hour": null, "seven_day": null}),
            json!({"seven_day_fable": {"utilization": 20}}),
        ] {
            assert!(!parse_usage(&body, 1_000).shared_headroom());
        }
        let mut usage = parse_usage(&json!({"five_hour": {"utilization": 0}}), 1_000);
        assert!(usage.shared_headroom());
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.01, 1.0] {
            usage.five_hour.utilization = Some(invalid);
            assert!(!usage.shared_headroom());
        }
        usage.five_hour.utilization = Some(0.999);
        assert!(usage.shared_headroom());
    }

    #[test]
    fn shared_exhaustion_uses_latest_future_reset_not_family_or_elapsed_reset() {
        let mut body = json!({
            "five_hour": {"utilization": 100, "resets_at": "1970-01-01T00:00:10Z"},
            "seven_day": {"utilization": 120, "resets_at": "1970-01-01T00:00:20Z"},
            "seven_day_fable": {"utilization": 100, "resets_at": "1970-01-01T00:00:30Z"}
        });
        assert_eq!(parse_usage(&body, 1_000).exhausted_reset_ms(), Some(20_000));
        assert_eq!(
            parse_usage(&body, 10_000).exhausted_reset_ms(),
            Some(20_000)
        );
        assert_eq!(parse_usage(&body, 20_000).exhausted_reset_ms(), None);
        body["seven_day"]["resets_at"] = json!("invalid");
        assert_eq!(parse_usage(&body, 1_000).exhausted_reset_ms(), Some(10_000));
        body["five_hour"]["utilization"] = json!(20);
        assert_eq!(parse_usage(&body, 1_000).exhausted_reset_ms(), None);
    }

    #[test]
    fn reset_consume_codes_are_explicit_and_fail_closed() {
        for code in ["reset", "already_redeemed"] {
            assert_eq!(reset_consume_code(&json!({"code": code})), Ok(code));
        }
        assert_eq!(
            reset_consume_code(&json!({"code": "no_credit"})),
            Err(ClaudeResetError::NoCredit)
        );
        assert_eq!(
            reset_consume_code(&json!({"code": "nothing_to_reset"})),
            Err(ClaudeResetError::NotRateLimited)
        );
        for body in [
            json!({}),
            json!(null),
            json!([]),
            json!({"code": null}),
            json!({"code": 1}),
            json!({"code": true}),
            json!({"code": ""}),
            json!({"code": "RESET"}),
            json!({"code": "unknown"}),
        ] {
            assert_eq!(
                reset_consume_code(&body),
                Err(ClaudeResetError::Upstream("consume outcome"))
            );
        }
    }

    #[test]
    fn partly_used_windows_are_not_exhausted() {
        // Observed in production: 2% and 26% used must not cool the account until the weekly reset.
        let body = json!({
            "five_hour": {"utilization": 2.0, "resets_at": "2026-10-22T06:59:59Z"},
            "seven_day": {"utilization": 26.0, "resets_at": "2026-10-23T03:59:59Z"},
        });
        let snapshot = parse_usage(&body, 1_000);
        assert_eq!(snapshot.seven_day.utilization, Some(0.26));
        assert_eq!(snapshot.exhausted_reset_ms(), None);
    }

    #[test]
    fn refresh_requests_no_scope() {
        let body = refresh_body("refresh");
        assert_eq!(body["grant_type"], "refresh_token");
        assert!(body.get("scope").is_none());
    }

    #[test]
    fn reset_credits_are_read_and_availability_is_explicit() {
        let credit = ResetCredit {
            id: "credit-1".into(),
            reset_type: Some("claude_rate_limits".into()),
            status: Some("available".into()),
            expires_at: Some("2026-10-27T00:00:00Z".into()),
        };
        assert!(credit.available());
        assert_eq!(credit.expires_at_ms(), Some(1_793_059_200_000));
        let spent = ResetCredit {
            id: "credit-2".into(),
            reset_type: Some("claude_rate_limits".into()),
            status: Some("redeemed".into()),
            expires_at: None,
        };
        assert!(!spent.available());
        assert_eq!(spent.expires_at_ms(), None);
    }

    #[test]
    fn canonical_model_drops_the_thinking_suffix() {
        assert_eq!(
            canonical_model("claude-sonnet-4-5(high)"),
            "claude-sonnet-4-5"
        );
        assert_eq!(canonical_model("  Claude-Sonnet-5-5 "), "claude-sonnet-5-5");
        assert_eq!(canonical_model("gpt-5.5"), "gpt-5.5");
    }

    #[test]
    fn only_claude_code_clients_are_admitted() {
        let backend = ClaudeBackend { cooldown_ms: 1_000 };
        let body = json!({
            "system": [
                {"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.304.c61; cc_entrypoint=sdk-cli;"},
                {"type": "text", "text": "You are a Claude agent, built on Anthropic's Claude Agent SDK."}
            ]
        });
        let good = headers(&[
            ("x-app", "cli"),
            ("user-agent", "claude-cli/2.1.304 (external, sdk-cli)"),
            ("anthropic-beta", "oauth-2025-04-20,claude-code-20250219"),
        ]);
        assert!(backend.accepts_client(&good, &body));

        let no_beta = headers(&[
            ("x-app", "cli"),
            ("user-agent", "claude-cli/2.1.304 (external, sdk-cli)"),
        ]);
        assert!(!backend.accepts_client(&no_beta, &body));

        let foreign = headers(&[
            ("x-app", "cli"),
            ("user-agent", "opencode/1.0"),
            ("anthropic-beta", "oauth-2025-04-20,claude-code-20250219"),
        ]);
        assert!(!backend.accepts_client(&foreign, &body));

        let plain_body = json!({"messages": []});
        assert!(!backend.accepts_client(&good, &plain_body));
    }

    #[test]
    fn sticky_key_prefers_the_session_header() {
        let map = headers(&[("x-claude-code-session-id", "sess-1")]);
        let body = json!({"metadata": {"user_id": "{\"session_id\":\"sess-2\"}"}});
        assert_eq!(sticky_key(&map, &body).as_deref(), Some("sess-1"));
        let empty = HeaderMap::new();
        assert_eq!(sticky_key(&empty, &body).as_deref(), Some("sess-2"));
    }

    #[test]
    fn sticky_key_reads_the_legacy_user_id_format() {
        let map = HeaderMap::new();
        let body = json!({"metadata": {"user_id": "user_abc_account_def_session_sess-3"}});
        assert_eq!(sticky_key(&map, &body).as_deref(), Some("sess-3"));
    }

    #[test]
    fn pasted_code_splits_on_the_state_separator() {
        assert_eq!(
            split_pasted_code("abc#state-1"),
            ("abc".to_string(), Some("state-1".to_string()))
        );
        assert_eq!(split_pasted_code("  abc  "), ("abc".to_string(), None));
    }

    #[test]
    fn pasted_code_accepts_a_full_callback_address() {
        assert_eq!(
            split_pasted_code("http://localhost:54545/callback?code=abc&state=state-1"),
            ("abc".to_string(), Some("state-1".to_string()))
        );
        assert_eq!(
            split_pasted_code("http://localhost:54545/callback?code=a%2Bb&state="),
            ("a+b".to_string(), None)
        );
    }

    #[test]
    fn pkce_challenge_is_the_sha256_of_the_verifier() {
        let pkce = new_pkce();
        assert!(pkce.verifier.len() >= 43);
        assert_ne!(pkce.verifier, pkce.state);
        let expected = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(pkce.verifier.as_bytes()));
        assert_eq!(pkce.challenge, expected);
    }

    #[test]
    fn authorize_url_carries_the_full_scope_set() {
        let pkce = new_pkce();
        let url = authorize_url(&pkce);
        assert!(url.starts_with(AUTHORIZE_URL));
        assert!(url.contains("client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("user%3Ainference"));
        assert!(url.contains("user%3Aplugins"));
        assert!(
            url.contains(
                "redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"
            )
        );
    }

    #[test]
    fn models_api_shape_is_parsed() {
        let body = json!({
            "data": [
                {"id": "claude-haiku-5-5", "display_name": "Claude Haiku 5.5", "max_input_tokens": 1000000, "max_tokens": 128000},
                {"id": "no-limits", "display_name": "Nope"},
                {"id": "claude-opus-4-5-20251101", "display_name": "Claude Opus 4.5", "max_input_tokens": 200000, "max_tokens": 64000}
            ]
        });
        let models = parse_models_response(&body);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "claude-haiku-5-5");
        assert_eq!(models[0].context, 1_000_000);
        assert_eq!(models[0].output, 128_000);
        assert_eq!(models[1].id, "claude-opus-4-5-20251101");
        assert_eq!(models[1].input, 200_000);
    }

    #[test]
    fn plans_map_from_organization_type() {
        assert_eq!(plan_for(Some("claude_max")).as_deref(), Some("max"));
        assert_eq!(plan_for(Some("claude_pro")).as_deref(), Some("pro"));
        assert_eq!(plan_for(Some("claude_team")).as_deref(), Some("team"));
        assert_eq!(
            plan_for(Some("claude_enterprise")).as_deref(),
            Some("enterprise")
        );
        assert_eq!(plan_for(Some("something_else")), None);
    }
}
