use underclass::provider::BackendMap;
use underclass::{
    claude, cli, codex, config, copilot, flows, gemini, logging, models, monitor, opencode_go,
    pool, proxy, stats_api, store, tokens, top, ui,
};

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// How often the scheduled rotation loop re-evaluates which refresh tokens are due. The rotation
/// window itself is `tokens::ROTATION_INTERVAL_MS`; this only bounds how late a due token can be,
/// so a coarse tick keeps the 24h cadence cheap without pinning a timer to the exact deadline.
const ROTATION_TICK: std::time::Duration = std::time::Duration::from_secs(900);
/// How often stats retention pruning and finished-day rollups run.
const STATS_TICK: std::time::Duration = std::time::Duration::from_secs(900);
/// How often the Claude Code accounts' own usage is polled: plan, quota windows, and banked
/// reset credits.
const CLAUDE_USAGE_POLL: std::time::Duration = std::time::Duration::from_secs(120);
/// How often the OpenCode Go accounts' allowance windows are polled.
const OPENCODE_GO_USAGE_POLL: std::time::Duration = std::time::Duration::from_secs(120);
/// How often Gemini Code Assist quota buckets are polled for the admin UI.
const GEMINI_QUOTA_POLL: std::time::Duration = std::time::Duration::from_secs(120);

#[derive(Parser)]
#[command(
    name = "underclass",
    about = "pooled multi-subscription codex/copilot proxy for opencode"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long, value_enum, default_value = "auto", global = true)]
    log_format: logging::LogFormat,
}

#[derive(Subcommand)]
enum Command {
    /// run the proxy server
    Serve {
        #[arg(long)]
        bind: Option<String>,
    },
    /// configure opencode to use this pool
    Connect {
        #[clap(flatten)]
        args: cli::ConnectArgs,
    },
    /// watch live pool activity in a read-only terminal dashboard
    Top {
        #[arg(long, help = "server URL (requires UNDERCLASS_UI_TOKEN)")]
        url: Option<String>,
    },
    /// redeem one banked Codex reset credit for an account via the running server
    Reset {
        #[clap(flatten)]
        args: cli::ResetArgs,
    },
    /// force a token refresh for one account (or `--all`) via the running server
    Refresh {
        #[clap(flatten)]
        args: cli::RefreshArgs,
    },
    /// add a Google AI Ultra account through the running server's paste-back OAuth flow
    Login {
        #[clap(flatten)]
        args: cli::LoginArgs,
    },
    /// show token, session, concurrency, capacity, and refusal statistics from the running server
    Stats {
        #[clap(flatten)]
        args: underclass::stats_cli::StatsArgs,
    },
}

fn main() {
    let cli = Cli::parse();
    if !matches!(
        cli.command,
        Some(Command::Top { .. })
            | Some(Command::Reset { .. })
            | Some(Command::Refresh { .. })
            | Some(Command::Login { .. })
            | Some(Command::Stats { .. })
    ) {
        logging::init(cli.log_format);
    }
    match cli.command {
        Some(Command::Connect { args }) => {
            let cfg = config::Config::load();
            let store = store::Store::open(&cfg.db_path()).expect("open pool db");
            if let Err(e) = cli::connect(&args, &store) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Serve { bind }) => serve(bind).expect("server failed"),
        Some(Command::Top { url }) => {
            if let Err(e) = top::run(url) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Reset { args }) => {
            if let Err(e) = cli::reset(&args) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Refresh { args }) => {
            if let Err(e) = cli::refresh(&args) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Login { args }) => {
            if let Err(e) = cli::login(&args) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Stats { args }) => {
            if let Err(e) = underclass::stats_cli::run(&args) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        None => serve(None).expect("server failed"),
    }
}

fn serve(bind_override: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_serve(bind_override))
}

/// @cc [owner:ghuntley,label:security] keys-minted-once
/// The proxy API key and admin UI token MUST be minted on first run, persisted to the store, and
/// reused on every subsequent start; an explicitly configured key/token MUST take precedence over
/// minted ones. Key and token values MUST NOT be written to diagnostics.
async fn async_serve(bind_override: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::Config::load();
    let store = Arc::new(store::Store::open(&cfg.db_path())?);
    store.prune_bindings(
        models::now_ms(),
        pool::BINDING_TTL_MS,
        pool::DEFAULT_BINDING_CAP,
    );

    let proxy_key = match cfg.proxy_key.clone() {
        Some(key) if !key.is_empty() => Some(key),
        _ => match store.config_get("proxy_key") {
            Some(key) => Some(key),
            None => {
                let key = format!("sk-underclass-{}", crate::models::new_id().replace('-', ""));
                store.config_set("proxy_key", &key);
                Some(key)
            }
        },
    };

    let ui_token = match cfg.ui_token.clone() {
        Some(token) if !token.is_empty() => token,
        _ => match store.config_get("ui_token") {
            Some(token) => token,
            None => {
                let token = crate::models::new_id().replace('-', "");
                store.config_set("ui_token", &token);
                token
            }
        },
    };

    seed_catalog(&store, models::BackendId::Codex, codex::default_catalog());
    seed_catalog(
        &store,
        models::BackendId::Copilot,
        copilot::fallback_catalog(),
    );
    seed_catalog(&store, models::BackendId::Claude, claude::default_catalog());
    seed_catalog(
        &store,
        models::BackendId::OpencodeGo,
        opencode_go::default_catalog(),
    );
    seed_catalog(&store, models::BackendId::Gemini, gemini::default_catalog());

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()?;

    let tokens = Arc::new(tokens::TokenManager::new(store.clone(), client.clone()));

    let mut backends: BackendMap = HashMap::new();
    backends.insert(
        models::BackendId::Codex,
        Arc::new(codex::CodexBackend {
            cooldown_ms: cfg.codex_cooldown_ms,
        }),
    );
    backends.insert(
        models::BackendId::Copilot,
        Arc::new(copilot::CopilotBackend {
            cooldown_ms: cfg.copilot_cooldown_ms,
        }),
    );
    backends.insert(
        models::BackendId::Claude,
        Arc::new(claude::ClaudeBackend {
            cooldown_ms: cfg.claude_cooldown_ms,
        }),
    );
    backends.insert(
        models::BackendId::OpencodeGo,
        Arc::new(opencode_go::OpencodeGoBackend {
            cooldown_ms: cfg.opencode_go_cooldown_ms,
        }),
    );
    backends.insert(
        models::BackendId::Gemini,
        Arc::new(gemini::GeminiBackend {
            cooldown_ms: cfg.gemini_cooldown_ms,
        }),
    );
    // The pool learns which surfaces each backend serves from the backends themselves.
    let surfaces: HashMap<models::BackendId, Vec<models::Surface>> = backends
        .iter()
        .map(|(id, backend)| (*id, backend.surfaces().to_vec()))
        .collect();
    let backends = Arc::new(backends);

    let core = pool::PoolCore::new(&store, surfaces);
    let pool = Arc::new(Mutex::new(core));

    let state = Arc::new(proxy::AppState {
        store: store.clone(),
        pool: pool.clone(),
        tokens: tokens.clone(),
        backends: backends.clone(),
        client: client.clone(),
        logs: Arc::new(Mutex::new(std::collections::VecDeque::new())),
        flows: flows::FlowRegistry::default(),
        proxy_key,
        ui_token: ui_token.clone(),
        resets: Arc::new(underclass::resets::ResetManager::new(
            client.clone(),
            std::env::var("UNDERCLASS_CODEX_USAGE_BASE")
                .unwrap_or_else(|_| "https://chatgpt.com/backend-api".to_string()),
            cfg.auto_codex_resets,
        )),
        stream_usage_unsupported: Mutex::new(Default::default()),
        observations: Mutex::new(Default::default()),
        stats_retention_days: cfg.stats_retention_days,
    });

    {
        let store = store.clone();
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                store.prune_bindings(
                    models::now_ms(),
                    pool::BINDING_TTL_MS,
                    pool::DEFAULT_BINDING_CAP,
                );
                enforce_plan_gates(&state);
                state.pool.lock().unwrap().sync_from_store(&store);
            }
        });
    }

    {
        let store = store.clone();
        let retention_days = cfg.stats_retention_days;
        tokio::spawn(async move {
            loop {
                let store = store.clone();
                let result = tokio::task::spawn_blocking(move || {
                    stats_api::maintain(&store, models::now_ms(), retention_days)
                })
                .await;
                match result {
                    Ok(Ok((pruned, rolled))) => {
                        if pruned > 0 || rolled > 0 {
                            tracing::info!(pruned, rolled, retention_days, "stats.maintained");
                        }
                    }
                    Ok(Err(error)) => tracing::error!(error = %error, "stats.maintenance_failed"),
                    Err(error) => tracing::error!(error = %error, "stats.maintenance_failed"),
                }
                tokio::time::sleep(STATS_TICK).await;
            }
        });
    }

    refresh_copilot_catalogs_on_boot(&state).await;
    refresh_claude_catalogs_on_boot(&state).await;
    refresh_opencode_go_catalog_on_boot(&state).await;
    refresh_gemini_catalog_on_boot(&state).await;
    refresh_identities_on_boot(&state).await;
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                poll_claude_usage(&state).await;
                tokio::time::sleep(CLAUDE_USAGE_POLL).await;
            }
        });
    }
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                poll_opencode_go_usage(&state).await;
                tokio::time::sleep(OPENCODE_GO_USAGE_POLL).await;
            }
        });
    }
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                poll_gemini_quota(&state).await;
                tokio::time::sleep(GEMINI_QUOTA_POLL).await;
            }
        });
    }
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                rotate_due_tokens(&state).await;
                tokio::time::sleep(ROTATION_TICK).await;
            }
        });
    }
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                for account in state.store.list_accounts() {
                    state
                        .resets
                        .poll_account(&account, &state.tokens, &state.pool, &state.store)
                        .await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            }
        });
    }

    let bind_addr = bind_override.unwrap_or_else(|| cfg.bind.clone());
    let v1 = axum::Router::new()
        .route("/models", axum::routing::get(proxy::models))
        .route("/responses", axum::routing::post(proxy::infer))
        .route("/chat/completions", axum::routing::post(proxy::infer))
        .route("/messages", axum::routing::post(proxy::messages))
        .route(
            "/messages/count_tokens",
            axum::routing::post(proxy::messages),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            proxy::require_proxy_key,
        ))
        .with_state(state.clone());

    // The local socket serves only the read-only monitor snapshot. Network admin routes
    // retain their token middleware.
    let local_app = axum::Router::new()
        .route("/monitor", axum::routing::get(monitor::snapshot))
        .with_state(state.clone());

    // Some clients post to `<base>/messages` rather than `<base>/v1/messages`; the alias serves
    // the same Anthropic surface at the root.
    let anthropic_alias = axum::Router::new()
        .route("/messages", axum::routing::post(proxy::messages))
        .route(
            "/messages/count_tokens",
            axum::routing::post(proxy::messages),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            proxy::require_proxy_key,
        ))
        .with_state(state.clone());

    let app = axum::Router::new()
        .route("/admin/api/state", axum::routing::get(ui::state))
        .route("/admin/api/usage", axum::routing::get(ui::usage_summary))
        .route(
            "/admin/api/usage/requests",
            axum::routing::get(ui::usage_requests),
        )
        .route("/admin/api/monitor", axum::routing::get(monitor::snapshot))
        .route(
            "/admin/api/stats",
            axum::routing::get(stats_api::stats_handler),
        )
        .route(
            "/admin/api/events/import",
            axum::routing::post(stats_api::import_handler),
        )
        .route("/admin/api/flows", axum::routing::post(ui::start_flow))
        .route("/admin/api/flows/{id}", axum::routing::get(ui::flow_status))
        .route(
            "/admin/api/flows/{id}/code",
            axum::routing::post(ui::submit_flow_code),
        )
        .route(
            "/admin/api/accounts/{id}",
            axum::routing::delete(ui::delete_account),
        )
        .route(
            "/admin/api/accounts/{id}/disable",
            axum::routing::post(ui::disable_account),
        )
        .route(
            "/admin/api/accounts/{id}/enable",
            axum::routing::post(ui::enable_account),
        )
        .route(
            "/admin/api/accounts/{id}/relogin",
            axum::routing::post(ui::relogin_account),
        )
        .route(
            "/admin/api/accounts/{id}/refresh",
            axum::routing::post(ui::refresh_account),
        )
        .route(
            "/admin/api/accounts/{id}/reset",
            axum::routing::post(ui::reset_account),
        )
        .route(
            "/admin/api/catalog/{backend}",
            axum::routing::get(ui::get_catalog).put(ui::put_catalog),
        )
        .route(
            "/admin/api/catalog/refresh-copilot",
            axum::routing::post(ui::refresh_copilot_catalog),
        )
        .route(
            "/admin/api/catalog/refresh-opencode-go",
            axum::routing::post(ui::refresh_opencode_go_catalog),
        )
        .route(
            "/admin/api/catalog/refresh-gemini",
            axum::routing::post(ui::refresh_gemini_catalog),
        )
        .route("/admin/api/client-key", axum::routing::get(ui::client_key))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ui::require_ui_token,
        ))
        .route("/", axum::routing::get(ui::index))
        .merge(anthropic_alias)
        .nest("/v1", v1)
        .layer(axum::middleware::from_fn(
            underclass::correlation::middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    let monitor_socket = bind_monitor_socket(&cfg.monitor_socket_path())?;
    println!("underclass listening on http://{bind_addr}");
    println!("web ui: http://{bind_addr}/");
    tokio::try_join!(
        axum::serve(listener, app),
        axum::serve(monitor_socket, local_app)
    )?;
    Ok(())
}

/// @cc [owner:ghuntley,label:security] local-monitor-socket
/// The local monitor socket MUST be a Unix socket with mode 0666 so local users can read its
/// limited monitor endpoint. A stale socket MAY be replaced only when no server accepts it;
/// non-socket paths and live sockets MUST remain untouched.
fn bind_monitor_socket(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = match tokio::net::UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            let metadata = path.symlink_metadata()?;
            if !metadata.file_type().is_socket() {
                return Err(error);
            }
            match std::os::unix::net::UnixStream::connect(path) {
                Err(connect_error)
                    if connect_error.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    std::fs::remove_file(path)?;
                    tokio::net::UnixListener::bind(path)?
                }
                _ => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

#[cfg(test)]
mod monitor_socket_tests {
    use super::bind_monitor_socket;

    #[tokio::test]
    async fn keeps_live_socket_and_recovers_stale_socket() {
        // macOS expands std::env::temp_dir() to a long per-user path that can exceed SUN_LEN.
        let dir = std::path::PathBuf::from("/tmp")
            .join(format!("ucm-{}", &uuid::Uuid::new_v4().to_string()[..8]));
        let path = dir.join("monitor.sock");
        let first = bind_monitor_socket(&path).unwrap();
        assert!(bind_monitor_socket(&path).is_err());
        drop(first);
        let second = bind_monitor_socket(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o666
        );
        drop(second);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    use std::os::unix::fs::PermissionsExt;
}

fn seed_catalog(
    store: &store::Store,
    backend: models::BackendId,
    defaults: Vec<models::ModelInfo>,
) {
    if store.catalog(backend).is_empty() {
        store.set_catalog(backend, &defaults);
    }
}

async fn refresh_copilot_catalogs_on_boot(state: &Arc<proxy::AppState>) {
    let accounts: Vec<models::Account> = state
        .store
        .list_accounts()
        .into_iter()
        .filter(|a| a.backend == models::BackendId::Copilot)
        .collect();
    for account in accounts {
        let Some(token) = account.refresh_token.clone() else {
            continue;
        };
        if let Ok(catalog) = copilot::fetch_catalog(&state.client, &account, &token).await {
            if !catalog.is_empty() {
                state
                    .store
                    .set_catalog(models::BackendId::Copilot, &catalog);
                let ids: Vec<String> = catalog.iter().map(|m| m.id.clone()).collect();
                state
                    .pool
                    .lock()
                    .unwrap()
                    .set_catalog(models::BackendId::Copilot, ids);
            }
        }
    }
}

/// Refreshes the Claude model catalog from Anthropic's Models API.
async fn refresh_claude_catalogs_on_boot(state: &Arc<proxy::AppState>) {
    let accounts: Vec<models::Account> = state
        .store
        .list_accounts()
        .into_iter()
        .filter(|a| a.backend == models::BackendId::Claude)
        .collect();
    for account in accounts {
        let Ok(token) = state.tokens.access_token(&account).await else {
            continue;
        };
        if let Ok(catalog) = claude::fetch_catalog(&state.client, &account, &token).await
            && !catalog.is_empty()
        {
            state.store.set_catalog(models::BackendId::Claude, &catalog);
            let ids: Vec<String> = catalog.iter().map(|m| m.id.clone()).collect();
            state
                .pool
                .lock()
                .unwrap()
                .set_catalog(models::BackendId::Claude, ids);
        }
    }
}

/// Refreshes the OpenCode Go catalog from the gateway's live model list.
async fn refresh_opencode_go_catalog_on_boot(state: &Arc<proxy::AppState>) {
    let (_, errors) =
        opencode_go::refresh_catalog_from_pool(&state.client, &state.store, &state.pool).await;
    for error in errors {
        tracing::warn!(error = %error, "opencode_go.catalog_refresh_failed");
    }
}

/// @cc [owner:ghuntley,label:pool] claude-usage-readmission
/// A fresh Claude usage snapshot MUST readmit a Cooling account only with valid shared
/// headroom. Only Healthy/Cooling accounts MAY enter or extend Cooling, using the latest
/// future exhausted shared reset without shortening an existing cooldown. Disabled/AuthError
/// states MUST remain untouched; family windows MUST NOT affect account status.
fn claude_quota_transition(
    status: models::AccountStatus,
    reset_at: i64,
    snapshot: &claude::UsageSnapshot,
    now: i64,
) -> Option<(models::AccountStatus, i64)> {
    if !matches!(
        status,
        models::AccountStatus::Healthy | models::AccountStatus::Cooling
    ) {
        return None;
    }
    if let Some(until) = snapshot.exhausted_reset_ms()
        && until > now
        && (status == models::AccountStatus::Healthy || until > reset_at)
    {
        return Some((models::AccountStatus::Cooling, until));
    }
    if status != models::AccountStatus::Cooling {
        return None;
    }
    snapshot
        .shared_headroom()
        .then_some((models::AccountStatus::Healthy, 0))
}

/// @cc [owner:ghuntley,label:persistence] claude-poll-reconciliation-atomic
/// Late observations MUST NOT recreate removed accounts or replace credentials/operator state.
/// Plan updates MUST update existing metadata only. Status changes MUST hold pool -> store
/// locks through persistence, with observations published only after policy reconciliation and
/// while deletion is excluded by the pool lock.
fn reconcile_claude_usage(
    state: &proxy::AppState,
    account_id: &str,
    snapshot: &claude::UsageSnapshot,
    now: i64,
) -> Option<(models::AccountStatus, i64)> {
    let mut core = state.pool.lock().unwrap();
    let current = core.account(account_id)?;
    let next = claude_quota_transition(current.status, current.reset_at, snapshot, now);
    if let Some(plan) = snapshot.plan.as_deref()
        && current.plan.as_deref() != Some(plan)
    {
        if !state.store.update_account_plan(account_id, plan) {
            return None;
        }
        core.set_plan(account_id, plan.to_owned());
    }
    claude::reconcile_family_quota(&mut core, account_id, snapshot, now);
    if let Some((status, reset_at)) = next {
        core.set_status(account_id, status, reset_at);
        state
            .store
            .update_account_status(account_id, status, reset_at);
    }
    state
        .observations
        .lock()
        .unwrap()
        .insert(account_id.to_owned(), claude::usage_view(snapshot));
    next
}

/// @cc [owner:ghuntley,label:pool] claude-poll-persists-quota-recovery
/// `poll_claude_usage` MUST update the in-memory pool and SQLite status together when a
/// successfully fetched usage snapshot changes an account's quota state. A failed usage fetch
/// MUST leave the account status unchanged and MUST NOT redeem any reset credit. Fable quota
/// MUST cool only the `claude-fable-` family, independently of exact-model HTTP cooldowns.
/// Polls each Claude account's own usage API for its plan, quota windows, and banked reset
/// credits, and reconciles its cooldown with those windows.
///
/// The account usage API is a first-party endpoint, so this never sends anything that looks like
/// a Claude Code request.
async fn poll_claude_usage(state: &Arc<proxy::AppState>) {
    let accounts: Vec<models::Account> = state
        .store
        .list_accounts()
        .into_iter()
        .filter(|a| a.backend == models::BackendId::Claude)
        .filter(|a| a.status != models::AccountStatus::Disabled)
        .collect();
    for account in accounts {
        let token = match state.tokens.access_token(&account).await {
            Ok(token) => token,
            Err(e) => {
                logging::log_account_state(
                    &account.id,
                    Some(&account.label),
                    "usage_poll_failed",
                    &e.to_string(),
                );
                continue;
            }
        };
        let snapshot = match claude::fetch_usage(&state.client, &account, &token).await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                logging::log_account_state(
                    &account.id,
                    Some(&account.label),
                    "usage_poll_failed",
                    &e.to_string(),
                );
                continue;
            }
        };
        let transition = reconcile_claude_usage(state, &account.id, &snapshot, models::now_ms());
        let Some((status, reset_at)) = transition else {
            continue;
        };
        if status == models::AccountStatus::Healthy {
            logging::log_account_state(
                &account.id,
                Some(&account.label),
                "recovered",
                "subscription usage has headroom",
            );
        } else {
            logging::log_account_state(
                &account.id,
                Some(&account.label),
                "cooling",
                &format!("subscription window exhausted until {reset_at}"),
            );
        }
    }
}

/// Polls each OpenCode Go account's allowance windows for the admin UI and monitor.
///
/// The windows are observations only. A spent allowance still serves the free models, and
/// OpenCode's Extra Usage setting can serve paid ones from the pay-as-you-go balance, so only an
/// upstream refusal cools a model on an account.
async fn poll_opencode_go_usage(state: &Arc<proxy::AppState>) {
    let accounts: Vec<models::Account> = state
        .store
        .list_accounts()
        .into_iter()
        .filter(|a| a.backend == models::BackendId::OpencodeGo)
        .filter(|a| a.status != models::AccountStatus::Disabled)
        .collect();
    for account in accounts {
        let result = match state.tokens.access_token(&account).await {
            Ok(token) => opencode_go::fetch_usage(&state.client, &token)
                .await
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        match result {
            Ok(snapshot) => {
                state
                    .observations
                    .lock()
                    .unwrap()
                    .insert(account.id.clone(), opencode_go::usage_view(&snapshot));
            }
            Err(e) => {
                logging::log_account_state(
                    &account.id,
                    Some(&account.label),
                    "usage_poll_failed",
                    &e,
                );
            }
        }
    }
}

/// Polls each Gemini account's Code Assist quota buckets for the admin UI.
///
/// The buckets are observations only. A bucket at zero does not cool the account: only an
/// upstream 429 or `RESOURCE_EXHAUSTED` does, because the bucket schema was not verified live.
async fn poll_gemini_quota(state: &Arc<proxy::AppState>) {
    let accounts: Vec<models::Account> = state
        .store
        .list_accounts()
        .into_iter()
        .filter(|account| account.backend == models::BackendId::Gemini)
        .filter(|account| account.status != models::AccountStatus::Disabled)
        .collect();
    for account in accounts {
        let Some(project) = account.account_id.clone() else {
            continue;
        };
        let result = match state.tokens.access_token(&account).await {
            Ok(token) => gemini::fetch_quota(&state.client, &token, &project).await,
            Err(error) => Err(error.to_string()),
        };
        match result {
            Ok(buckets) => {
                state
                    .observations
                    .lock()
                    .unwrap()
                    .insert(account.id.clone(), gemini::quota_view(&buckets));
            }
            Err(error) => {
                logging::log_account_state(
                    &account.id,
                    Some(&account.label),
                    "usage_poll_failed",
                    &error,
                );
            }
        }
    }
}

async fn refresh_gemini_catalog_on_boot(state: &Arc<proxy::AppState>) {
    let Some(account) = state.store.list_accounts().into_iter().find(|account| {
        account.backend == models::BackendId::Gemini
            && account.status != models::AccountStatus::Disabled
            && account.account_id.is_some()
    }) else {
        return;
    };
    let Some(project) = account.account_id.clone() else {
        return;
    };
    let Ok(token) = state.tokens.access_token(&account).await else {
        return;
    };
    if let Err(error) =
        gemini::refresh_catalog(&state.client, &state.store, &state.pool, &token, &project).await
    {
        tracing::warn!(error = %error, "gemini.catalog_refresh_failed");
    }
}

/// @cc [owner:ghuntley,label:pool] plan-gate-operator-serialization
/// Plan-gate decisions MUST read current account metadata and persist status under the pool
/// lock, in pool -> store order. Only a disable attributed to the plan gate MAY be reversed;
/// concurrent operator disable/delete actions MUST NOT be overwritten by a stale decision.
///
/// Codex plans come from the stored access token's claims, which the daily scheduled rotation
/// keeps current even while the account is disabled.
fn enforce_plan_gates(state: &Arc<proxy::AppState>) {
    let mut pool = state.pool.lock().unwrap();
    for account in state.store.list_accounts() {
        let (status, reason, event) = match account.plan_gate() {
            Some(models::PlanGate::Disable) => (
                models::AccountStatus::Disabled,
                Some(models::FREE_PLAN_REASON),
                "disabled",
            ),
            Some(models::PlanGate::Enable) => (models::AccountStatus::Healthy, None, "enabled"),
            None => continue,
        };
        let plan = account.plan_label().unwrap_or_default();
        state.store.update_account_status(&account.id, status, 0);
        state.store.set_disabled_reason(&account.id, reason);
        pool.set_status(&account.id, status, 0);
        logging::log_account_state(
            &account.id,
            Some(&account.label),
            event,
            &format!("subscription plan is {plan}"),
        );
    }
}

fn is_generic_label(label: &str) -> bool {
    matches!(label, "chatgpt" | "github" | "claude" | "gemini") || label.trim().is_empty()
}

/// @cc [owner:ghuntley,label:auth] scheduled-rotation-never-bricks-account
/// `rotate_due_tokens` MUST call `force_refresh` for every account reported due by
/// `tokens::rotation_due`, and MUST NOT change any account's status, pool state, or cooldown for any
/// outcome, including failure. A failed rotation MUST be logged and left for a later tick to retry
/// rather than reported as `auth_error`, so a transient issuer outage cannot remove a working
/// subscription from the pool.
async fn rotate_due_tokens(state: &Arc<proxy::AppState>) {
    let now = models::now_ms();
    for account in state.store.list_accounts() {
        if !tokens::rotation_due(&account, now) {
            continue;
        }
        match state.tokens.force_refresh(&account.id).await {
            Ok(_) => {
                logging::log_token_rotation(&account.id, &account.label, "rotated", "scheduled")
            }
            Err(e) => logging::log_token_rotation(
                &account.id,
                &account.label,
                "rotation_failed",
                &e.to_string(),
            ),
        }
    }
}

async fn refresh_identities_on_boot(state: &Arc<proxy::AppState>) {
    let accounts: Vec<models::Account> = state
        .store
        .list_accounts()
        .into_iter()
        .filter(|a| is_generic_label(&a.label))
        .collect();
    for account in accounts {
        let mut plan = None;
        let identity = match account.backend {
            models::BackendId::Codex => {
                let token = match state.tokens.access_token(&account).await {
                    Ok(token) => token,
                    Err(_) => continue,
                };
                codex::identity_from_token(&token)
            }
            models::BackendId::Copilot => {
                let Some(token) = account.refresh_token.clone() else {
                    continue;
                };
                copilot::fetch_github_identity(&state.client, &token).await
            }
            models::BackendId::Claude => {
                let token = match state.tokens.access_token(&account).await {
                    Ok(token) => token,
                    Err(_) => continue,
                };
                match claude::fetch_profile(&state.client, &token).await {
                    Ok(profile) => {
                        let identity = claude::identity_from_profile(&profile);
                        plan = identity.plan.clone();
                        Some(identity.label)
                    }
                    Err(_) => None,
                }
            }
            // An OpenCode Go key carries no identity beyond the label it was enrolled with.
            models::BackendId::OpencodeGo => continue,
            // A Gemini account is labeled with the Google email at enrollment.
            models::BackendId::Gemini => continue,
        };
        let Some(identity) = identity else {
            continue;
        };
        let mut updated = account.clone();
        updated.label = identity;
        if let Some(plan) = plan {
            updated.plan = Some(plan);
        }
        updated.updated_at = models::now_ms();
        state.store.upsert_account(&updated);
        state.pool.lock().unwrap().sync_account(updated);
        tracing::info!(account = %account.id, "account.identity_refreshed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_headroom_readmits_stale_claude_cooldown() {
        let mut usage = claude::UsageSnapshot::default();
        usage.seven_day.utilization = Some(0.6);
        usage.seven_day_fable.utilization = Some(1.0);
        assert_eq!(
            claude_quota_transition(models::AccountStatus::Cooling, 10_000, &usage, 1_000),
            Some((models::AccountStatus::Healthy, 0))
        );
    }

    #[test]
    fn exhausted_or_unknown_usage_cannot_readmit_claude() {
        let mut usage = claude::UsageSnapshot::default();
        assert_eq!(
            claude_quota_transition(models::AccountStatus::Cooling, 10_000, &usage, 1_000),
            None
        );
        usage.seven_day.utilization = Some(0.6);
        usage.five_hour.utilization = Some(1.0);
        assert_eq!(
            claude_quota_transition(models::AccountStatus::Cooling, 10_000, &usage, 1_000),
            None
        );
    }

    #[test]
    fn exhausted_usage_only_extends_cooldown() {
        let mut usage = claude::UsageSnapshot::default();
        usage.seven_day.utilization = Some(1.0);
        usage.seven_day.resets_at_ms = Some(20_000);
        assert_eq!(
            claude_quota_transition(models::AccountStatus::Cooling, 10_000, &usage, 1_000),
            Some((models::AccountStatus::Cooling, 20_000))
        );
        assert_eq!(
            claude_quota_transition(models::AccountStatus::Cooling, 30_000, &usage, 1_000),
            None
        );
    }

    #[test]
    fn headroom_does_not_clear_non_cooling_account_states() {
        let mut usage = claude::UsageSnapshot::default();
        usage.seven_day.utilization = Some(0.6);
        for status in [
            models::AccountStatus::Healthy,
            models::AccountStatus::AuthError,
            models::AccountStatus::Disabled,
        ] {
            assert_eq!(claude_quota_transition(status, 0, &usage, 1_000), None);
        }
    }

    #[test]
    fn exhausted_usage_does_not_override_operator_or_auth_states() {
        let usage = claude::parse_usage(
            &serde_json::json!({
                "five_hour": {"utilization": 100, "resets_at": "1970-01-01T00:00:20Z"}
            }),
            1_000,
        );
        for status in [
            models::AccountStatus::Disabled,
            models::AccountStatus::AuthError,
        ] {
            assert_eq!(claude_quota_transition(status, 0, &usage, 1_000), None);
        }
        assert_eq!(
            claude_quota_transition(models::AccountStatus::Healthy, 0, &usage, 1_000),
            Some((models::AccountStatus::Cooling, 20_000))
        );
    }

    fn claude_usage_state() -> (proxy::AppState, String) {
        let store = Arc::new(store::Store::in_memory().unwrap());
        let account = flows::new_account(models::BackendId::Claude, "owner@example.test".into());
        store.upsert_account(&account);
        let pool = Arc::new(Mutex::new(pool::PoolCore::new(
            &store,
            HashMap::from([(models::BackendId::Claude, vec![models::Surface::Anthropic])]),
        )));
        let client = reqwest::Client::new();
        let state = proxy::AppState {
            tokens: Arc::new(tokens::TokenManager::new(store.clone(), client.clone())),
            store,
            pool,
            backends: Arc::new(BackendMap::new()),
            client,
            logs: Arc::new(Mutex::new(Default::default())),
            flows: flows::FlowRegistry::default(),
            proxy_key: None,
            ui_token: "unused".into(),
            resets: Arc::new(underclass::resets::ResetManager::new(
                reqwest::Client::new(),
                "http://127.0.0.1:1".into(),
                false,
            )),
            stream_usage_unsupported: Mutex::new(Default::default()),
            observations: Mutex::new(Default::default()),
            stats_retention_days: 730,
        };
        (state, account.id)
    }

    #[test]
    fn late_claude_plan_observation_preserves_credentials_and_newer_state() {
        for status in [
            models::AccountStatus::Disabled,
            models::AccountStatus::AuthError,
            models::AccountStatus::Cooling,
        ] {
            let (state, id) = claude_usage_state();
            let usage = claude::parse_usage(
                &serde_json::json!({
                    "plan_type": "max",
                    "five_hour": {"utilization": 100, "resets_at": "1970-01-01T00:00:20Z"}
                }),
                1_000,
            );
            // Credentials and status changed while the usage request was in flight.
            let mut current = state.store.get_account(&id).unwrap();
            current.status = status;
            current.reset_at = 30_000;
            current.access_token = Some("rotated-access".into());
            current.refresh_token = Some("rotated-refresh".into());
            current.expires_at = 90_000;
            current.token_refreshed_at = 900;
            {
                let mut core = state.pool.lock().unwrap();
                core.sync_account(current);
                state.store.upsert_account(core.account(&id).unwrap());
            }
            assert_eq!(reconcile_claude_usage(&state, &id, &usage, 1_000), None);
            let stored = state.store.get_account(&id).unwrap();
            let core = state.pool.lock().unwrap();
            let pooled = core.account(&id).unwrap();
            for account in [&stored, pooled] {
                assert_eq!(account.status, status);
                assert_eq!(account.reset_at, 30_000);
                assert_eq!(account.plan.as_deref(), Some("max"));
                assert_eq!(account.access_token.as_deref(), Some("rotated-access"));
                assert_eq!(account.refresh_token.as_deref(), Some("rotated-refresh"));
                assert_eq!(account.expires_at, 90_000);
                assert_eq!(account.token_refreshed_at, 900);
            }
        }
    }

    #[test]
    fn late_claude_usage_does_not_recreate_deleted_account_or_observation() {
        let (state, id) = claude_usage_state();
        let usage = claude::parse_usage(
            &serde_json::json!({
                "plan_type": "max", "five_hour": {"utilization": 20}
            }),
            1_000,
        );
        {
            let mut core = state.pool.lock().unwrap();
            state.store.delete_account(&id);
            core.remove_account(&id);
        }
        assert_eq!(reconcile_claude_usage(&state, &id, &usage, 1_000), None);
        assert!(state.store.get_account(&id).is_none());
        assert!(state.pool.lock().unwrap().account(&id).is_none());
        assert!(!state.observations.lock().unwrap().contains_key(&id));
    }

    #[test]
    fn claude_poll_requires_valid_reported_shared_headroom_to_persist_recovery() {
        for (five_hour, expected) in [
            (serde_json::json!(null), models::AccountStatus::Healthy),
            (
                serde_json::json!({"utilization": 0}),
                models::AccountStatus::Healthy,
            ),
            (serde_json::json!({}), models::AccountStatus::Cooling),
            (
                serde_json::json!({"utilization": "unknown"}),
                models::AccountStatus::Cooling,
            ),
            (
                serde_json::json!({"utilization": 100}),
                models::AccountStatus::Cooling,
            ),
        ] {
            let (state, id) = claude_usage_state();
            {
                let mut core = state.pool.lock().unwrap();
                core.set_status(&id, models::AccountStatus::Cooling, 30_000);
                state
                    .store
                    .update_account_status(&id, models::AccountStatus::Cooling, 30_000);
            }
            let usage = claude::parse_usage(
                &serde_json::json!({
                    "five_hour": five_hour, "seven_day": {"utilization": 20}
                }),
                1_000,
            );
            reconcile_claude_usage(&state, &id, &usage, 1_000);
            assert_eq!(state.store.get_account(&id).unwrap().status, expected);
            assert_eq!(
                state.pool.lock().unwrap().account(&id).unwrap().status,
                expected
            );
        }
    }

    #[test]
    fn claude_family_observations_preserve_protected_account_cooldowns() {
        for status in [
            models::AccountStatus::Disabled,
            models::AccountStatus::AuthError,
        ] {
            let (state, id) = claude_usage_state();
            {
                let mut core = state.pool.lock().unwrap();
                core.report_model_family_quota(&id, "claude-fable-", 20_000);
                core.set_status(&id, status, 0);
                state.store.update_account_status(&id, status, 0);
            }
            for used in [20, 100] {
                let usage = claude::parse_usage(
                    &serde_json::json!({
                        "five_hour": {"utilization": 20},
                        "seven_day_fable": {"utilization": used, "resets_at": "1970-01-01T00:00:30Z"}
                    }),
                    1_000,
                );
                reconcile_claude_usage(&state, &id, &usage, 1_000);
                let core = state.pool.lock().unwrap();
                assert_eq!(
                    core.model_cooling_until(&id, "claude-fable-5-1"),
                    Some(20_000)
                );
                assert_eq!(core.account(&id).unwrap().status, status);
            }
        }
    }

    #[test]
    fn claude_family_quota_is_independent_of_account_and_exact_model_cooldowns() {
        let (state, id) = claude_usage_state();
        let mut body = serde_json::json!({
            "five_hour": {"utilization": 10}, "seven_day": {"utilization": 20},
            "seven_day_fable": {"utilization": 100, "resets_at": "1970-01-01T00:00:20Z"}
        });
        {
            let mut core = state.pool.lock().unwrap();
            core.set_status(&id, models::AccountStatus::Cooling, 50_000);
            state
                .store
                .update_account_status(&id, models::AccountStatus::Cooling, 50_000);
            core.report_model_quota(&id, "claude-fable-5-1", 40_000);
        }
        let usage = claude::parse_usage(&body, 1_000);
        assert_eq!(
            reconcile_claude_usage(&state, &id, &usage, 1_000),
            Some((models::AccountStatus::Healthy, 0))
        );
        {
            let core = state.pool.lock().unwrap();
            assert_eq!(
                core.model_cooling_until(&id, "claude-fable-5-1"),
                Some(40_000)
            );
            assert_eq!(
                core.model_cooling_until(&id, "claude-fable-5-2"),
                Some(20_000)
            );
            assert_eq!(core.model_cooling_until(&id, "claude-haiku-5-5"), None);
            assert_eq!(core.model_cooling_until(&id, "claude-fable"), None);
        }
        let stored = state.store.get_account(&id).unwrap();
        assert_eq!(
            (stored.status, stored.reset_at),
            (models::AccountStatus::Healthy, 0)
        );
        assert!(state.observations.lock().unwrap().contains_key(&id));
        body["seven_day_fable"]["utilization"] = serde_json::json!("unknown");
        reconcile_claude_usage(&state, &id, &claude::parse_usage(&body, 1_000), 1_000);
        assert_eq!(
            state
                .pool
                .lock()
                .unwrap()
                .model_cooling_until(&id, "claude-fable-5-2"),
            Some(20_000)
        );
        for headroom in [
            serde_json::json!({"utilization": 20}),
            serde_json::json!(null),
        ] {
            state
                .pool
                .lock()
                .unwrap()
                .report_model_family_quota(&id, "claude-fable-", 20_000);
            body["seven_day_fable"] = headroom;
            reconcile_claude_usage(&state, &id, &claude::parse_usage(&body, 1_000), 1_000);
            let core = state.pool.lock().unwrap();
            assert_eq!(core.model_cooling_until(&id, "claude-fable-5-2"), None);
            assert_eq!(
                core.model_cooling_until(&id, "claude-fable-5-1"),
                Some(40_000)
            );
        }
    }
}
