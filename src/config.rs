use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FileConfig {
    pub bind: Option<String>,
    pub proxy_key: Option<String>,
    pub ui_token: Option<String>,
    pub codex_cooldown_secs: Option<u64>,
    pub copilot_cooldown_secs: Option<u64>,
    pub claude_cooldown_secs: Option<u64>,
    pub claude_cooldown_ms: Option<u64>,
    pub opencode_go_cooldown_secs: Option<u64>,
    pub opencode_go_cooldown_ms: Option<u64>,
    pub gemini_cooldown_secs: Option<u64>,
    pub gemini_cooldown_ms: Option<u64>,
    pub copilot_cooldown_ms: Option<u64>,
    pub codex_cooldown_ms: Option<u64>,
    pub auto_codex_resets: Option<bool>,
    pub stats_retention_days: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub proxy_key: Option<String>,
    pub ui_token: Option<String>,
    pub codex_cooldown_ms: i64,
    pub auto_codex_resets: bool,
    pub copilot_cooldown_ms: i64,
    pub claude_cooldown_ms: i64,
    pub opencode_go_cooldown_ms: i64,
    pub gemini_cooldown_ms: i64,
    pub stats_retention_days: i64,
    pub data_dir: PathBuf,
    #[allow(dead_code)]
    pub config_dir: PathBuf,
}

pub const DEFAULT_COOLDOWN_MS: i64 = 30 * 60 * 1000;

/// @cc [owner:ghuntley,label:config] cooldown-ms-overrides-secs
/// `resolve_cooldown` MUST return `ms` when it is set, otherwise `secs` converted to
/// milliseconds, and otherwise `DEFAULT_COOLDOWN_MS`.
pub fn resolve_cooldown(ms: Option<u64>, secs: Option<u64>) -> i64 {
    ms.or_else(|| secs.map(|secs| secs.saturating_mul(1000)))
        .unwrap_or(DEFAULT_COOLDOWN_MS as u64) as i64
}
pub const SYSTEM_MONITOR_SOCKET: &str = "/run/underclass/monitor.sock";

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn default_data_dir() -> PathBuf {
    home_dir().join(".local/share/underclass")
}

pub fn default_config_dir() -> PathBuf {
    home_dir().join(".config/underclass")
}

impl Config {
    pub fn load() -> Self {
        let config_dir = std::env::var_os("UNDERCLASS_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_config_dir);
        let data_dir = std::env::var_os("UNDERCLASS_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir);

        let mut file_cfg = FileConfig::default();
        let config_path = config_dir.join("config.toml");
        if let Ok(text) = std::fs::read_to_string(&config_path) {
            if let Ok(parsed) = toml::from_str::<FileConfig>(&text) {
                file_cfg = parsed;
            } else {
                eprintln!(
                    "warning: could not parse {}, using defaults",
                    config_path.display()
                );
            }
        }

        let bind = std::env::var("UNDERCLASS_BIND")
            .ok()
            .or(file_cfg.bind)
            .unwrap_or_else(|| "127.0.0.1:8080".to_string());
        let proxy_key = std::env::var("UNDERCLASS_PROXY_KEY")
            .ok()
            .or(file_cfg.proxy_key);
        let ui_token = std::env::var("UNDERCLASS_UI_TOKEN")
            .ok()
            .or(file_cfg.ui_token);
        let codex_cooldown_ms =
            resolve_cooldown(file_cfg.codex_cooldown_ms, file_cfg.codex_cooldown_secs);
        let copilot_cooldown_ms =
            resolve_cooldown(file_cfg.copilot_cooldown_ms, file_cfg.copilot_cooldown_secs);
        let claude_cooldown_ms =
            resolve_cooldown(file_cfg.claude_cooldown_ms, file_cfg.claude_cooldown_secs);
        let opencode_go_cooldown_ms = resolve_cooldown(
            file_cfg.opencode_go_cooldown_ms,
            file_cfg.opencode_go_cooldown_secs,
        );
        let gemini_cooldown_ms =
            resolve_cooldown(file_cfg.gemini_cooldown_ms, file_cfg.gemini_cooldown_secs);

        let auto_codex_resets = std::env::var("UNDERCLASS_AUTO_CODEX_RESETS")
            .ok()
            .and_then(|value| value.parse::<bool>().ok())
            .or(file_cfg.auto_codex_resets)
            .unwrap_or(true);

        let stats_retention_days = std::env::var("UNDERCLASS_STATS_RETENTION_DAYS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .or(file_cfg.stats_retention_days)
            .unwrap_or(crate::stats::DEFAULT_RETENTION_DAYS)
            .max(1);

        Self {
            bind,
            proxy_key,
            ui_token,
            codex_cooldown_ms,
            auto_codex_resets,
            copilot_cooldown_ms,
            claude_cooldown_ms,
            opencode_go_cooldown_ms,
            gemini_cooldown_ms,
            stats_retention_days,
            data_dir,
            config_dir,
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("pool.db")
    }

    /// @cc [owner:ghuntley,label:cli] monitor-socket-location
    /// The server MUST honor a nonempty `UNDERCLASS_MONITOR_SOCKET` and otherwise place its local
    /// monitor socket beside the SQLite database.
    pub fn monitor_socket_path(&self) -> PathBuf {
        std::env::var_os("UNDERCLASS_MONITOR_SOCKET")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.data_dir.join("monitor.sock"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemini_cooldown_prefers_milliseconds_then_seconds() {
        assert_eq!(resolve_cooldown(Some(1_500), Some(90)), 1_500);
        assert_eq!(resolve_cooldown(None, Some(90)), 90_000);
        assert_eq!(resolve_cooldown(None, None), DEFAULT_COOLDOWN_MS);
        let parsed: FileConfig = toml::from_str("gemini_cooldown_secs = 90\n").unwrap();
        assert_eq!(
            resolve_cooldown(parsed.gemini_cooldown_ms, parsed.gemini_cooldown_secs),
            90_000
        );
    }
}
