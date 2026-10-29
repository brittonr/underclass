use crate::models::{Account, AccountStatus, BackendId, Binding, Outcome, Surface};
use crate::store::Store;
use lru::LruCache;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;

pub const BINDING_TTL_MS: i64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_BINDING_CAP: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    StickyHit,
    StickyRebind,
    NewBinding,
    Unsticky,
}

#[derive(Clone, Debug)]
pub struct Selection {
    pub account_id: String,
    pub backend: BackendId,
    pub decision: Decision,
}

#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    #[error("all eligible accounts are cooling until {until_ms}")]
    Saturated { until_ms: i64 },
    #[error("no accounts configured for this model")]
    NoAccounts,
}

pub struct AccountState {
    pub account: Account,
    pub inflight: u32,
}

pub struct PoolCore {
    pub accounts: HashMap<String, AccountState>,
    bindings: LruCache<String, (String, i64)>,
    catalog: HashMap<BackendId, HashSet<String>>,
    /// Which request surfaces each backend can serve, as declared by the backend itself.
    surfaces: HashMap<BackendId, Vec<Surface>>,
    /// Per-account, per-model cooldowns: the upstream refused this model on this account while
    /// the account keeps serving its other models.
    model_cooldowns: HashMap<String, HashMap<String, i64>>,
}

impl PoolCore {
    /// @cc [owner:ghuntley,label:pool] pool-surfaces-from-backends
    /// `PoolCore::new` MUST take the surface declarations of the registered backends and MUST
    /// NOT infer them from backend names or model catalogs.
    pub fn new(store: &Store, surfaces: HashMap<BackendId, Vec<Surface>>) -> Self {
        let mut core = Self {
            accounts: HashMap::new(),
            bindings: LruCache::new(NonZeroUsize::new(DEFAULT_BINDING_CAP).unwrap()),
            catalog: HashMap::new(),
            surfaces,
            model_cooldowns: HashMap::new(),
        };
        for a in store.list_accounts() {
            core.accounts.insert(
                a.id.clone(),
                AccountState {
                    account: a,
                    inflight: 0,
                },
            );
        }
        for b in store.list_bindings() {
            core.bindings.put(b.cache_key, (b.account_id, b.bound_at));
        }
        for backend in BackendId::all() {
            let ids: HashSet<String> = store.catalog(backend).into_iter().map(|m| m.id).collect();
            core.catalog.insert(backend, ids);
        }
        core
    }

    pub fn set_catalog(&mut self, backend: BackendId, models: Vec<String>) {
        self.catalog.insert(backend, models.into_iter().collect());
    }

    pub fn serves(&self, backend: BackendId, model: &str) -> bool {
        self.catalog
            .get(&backend)
            .is_some_and(|set| set.contains(model))
    }

    fn eligible_backends(&self, model: &str, surface: Surface) -> Vec<BackendId> {
        let mut out: Vec<BackendId> = BackendId::all()
            .into_iter()
            .filter(|b| self.serves_surface(*b, surface))
            .filter(|b| self.serves(*b, model))
            .collect();
        if out.is_empty()
            && let Some(fallback) = self.fallback_backend(surface)
        {
            out.push(fallback);
        }
        out
    }

    /// Whether a backend can serve the given request surface at all.
    pub fn serves_surface(&self, backend: BackendId, surface: Surface) -> bool {
        self.surfaces
            .get(&backend)
            .is_some_and(|list| list.contains(&surface))
    }

    /// The backend an unknown model falls back to on a surface: the first registered backend
    /// that declares the surface, in a stable order.
    fn fallback_backend(&self, surface: Surface) -> Option<BackendId> {
        BackendId::all()
            .into_iter()
            .find(|b| self.serves_surface(*b, surface))
    }

    /// @cc [owner:ghuntley,label:pool] sweep-readmits-expired-cooling
    /// `sweep(now)` MUST return every account whose `Cooling` state has `reset_at <= now` back to
    /// `Healthy` (eligible for selection again), MUST evict expired per-model cooldowns, and MUST
    /// evict sticky bindings older than `BINDING_TTL_MS`. It MUST NOT touch Cooling accounts
    /// whose reset has not passed.
    pub fn sweep(&mut self, now: i64) -> Vec<String> {
        let mut readmitted = Vec::new();
        for state in self.accounts.values_mut() {
            if state.account.status == AccountStatus::Cooling && state.account.reset_at <= now {
                state.account.status = AccountStatus::Healthy;
                state.account.reset_at = 0;
                readmitted.push(state.account.id.clone());
            }
        }
        let expired: Vec<String> = self
            .model_cooldowns
            .iter_mut()
            .filter_map(|(account_id, models)| {
                models.retain(|_, until_ms| *until_ms > now);
                if models.is_empty() {
                    Some(account_id.clone())
                } else {
                    None
                }
            })
            .collect();
        for account_id in expired {
            self.model_cooldowns.remove(&account_id);
        }
        loop {
            let expired = match self.bindings.peek_lru() {
                Some((key, (_, bound_at))) if now - *bound_at > BINDING_TTL_MS => Some(key.clone()),
                _ => None,
            };
            match expired {
                Some(key) => {
                    self.bindings.pop(&key);
                }
                None => break,
            }
        }
        readmitted
    }

    /// @cc [owner:ghuntley,label:pool] model-cooldown-scopes-one-model
    /// `report_model_quota` MUST record a cooldown for one model on one account until
    /// `until_ms`, MUST NOT change the account's status, and MUST never shorten an existing
    /// cooldown for the same account and model.
    pub fn report_model_quota(&mut self, account_id: &str, model: &str, until_ms: i64) {
        let models = self
            .model_cooldowns
            .entry(account_id.to_string())
            .or_default();
        let entry = models.entry(model.to_string()).or_insert(until_ms);
        if until_ms > *entry {
            *entry = until_ms;
        }
    }

    /// Whether the account is cooling for the given model.
    pub fn model_cooling_until(&self, account_id: &str, model: &str) -> Option<i64> {
        self.model_cooldowns
            .get(account_id)
            .and_then(|models| models.get(model))
            .copied()
    }

    /// @cc [owner:ghuntley,label:pool] select-sticky-healthy-never-unhealthy
    /// Selection MUST return, in priority order: (1) the account bound to the sticky key when it
    /// is Healthy, serves the model and is not cooling for it (decision `StickyHit`); (2) on
    /// rebinding, a Healthy account of the bound account's backend when one exists, else any
    /// Healthy eligible account; (3) for sticky misses, the least-in-flight Healthy eligible
    /// account. It MUST NOT ever return an account that is Cooling, AuthError, or Disabled, or one
    /// cooling for the requested model. When no eligible Healthy account exists it
    /// MUST fail with `Saturated { until_ms = min reset_at over eligible cooling accounts }` or,
    /// if none are cooling, `NoAccounts`. Requests without a sticky key MUST NOT create bindings.
    /// Only backends that declare the requested `surface` are eligible.
    pub fn select(
        &mut self,
        now: i64,
        sticky: Option<&str>,
        model: &str,
        surface: Surface,
    ) -> Result<Selection, SelectError> {
        self.select_excluding(now, sticky, model, surface, &HashSet::new())
    }

    /// @cc [owner:ghuntley,label:pool] select-excluding-skips-excluded
    /// `select_excluding` MUST behave as `select` with every account in `exclude` treated as
    /// ineligible: it MUST NOT return an excluded account, a sticky key bound to an excluded
    /// account MUST rebind as if that account were unhealthy, and with an empty `exclude` it MUST
    /// be identical to `select`.
    pub fn select_excluding(
        &mut self,
        now: i64,
        sticky: Option<&str>,
        model: &str,
        surface: Surface,
        exclude: &HashSet<String>,
    ) -> Result<Selection, SelectError> {
        self.sweep(now);
        let backends: HashSet<BackendId> =
            self.eligible_backends(model, surface).into_iter().collect();

        let find_healthy = |core: &Self, backend_filter: Option<BackendId>| -> Option<String> {
            let mut candidates: Vec<(u32, &String)> = core
                .accounts
                .iter()
                .filter(|(id, s)| {
                    !exclude.contains(*id)
                        && s.account.healthy()
                        && backends.contains(&s.account.backend)
                        && backend_filter.is_none_or(|b| s.account.backend == b)
                        && !core
                            .model_cooldowns
                            .get(*id)
                            .and_then(|models| models.get(model))
                            .is_some_and(|until_ms| *until_ms > now)
                })
                .map(|(id, s)| (s.inflight, id))
                .collect();
            candidates.sort();
            candidates.into_iter().next().map(|(_, id)| id.clone())
        };

        if let Some(key) = sticky {
            let bound = self.bindings.get(key).map(|(id, at)| (id.clone(), *at));
            if let Some((bound_id, bound_at)) = bound {
                if now - bound_at <= BINDING_TTL_MS {
                    if let Some(state) = self.accounts.get(&bound_id) {
                        if state.account.healthy()
                            && backends.contains(&state.account.backend)
                            && !exclude.contains(&bound_id)
                            && self
                                .model_cooling_until(&bound_id, model)
                                .is_none_or(|until_ms| until_ms <= now)
                        {
                            return Ok(Selection {
                                account_id: bound_id.clone(),
                                backend: state.account.backend,
                                decision: Decision::StickyHit,
                            });
                        }
                    }
                    let preferred = self.accounts.get(&bound_id).map(|s| s.account.backend);
                    if let Some(next) = find_healthy(self, preferred) {
                        let backend = self.accounts[&next].account.backend;
                        self.bind(key, &next, now);
                        return Ok(Selection {
                            account_id: next,
                            backend,
                            decision: Decision::StickyRebind,
                        });
                    }
                } else {
                    self.bindings.pop(key);
                }
            }
        }

        if let Some(next) = find_healthy(self, None) {
            let backend = self.accounts[&next].account.backend;
            let decision = if sticky.is_some() {
                Decision::NewBinding
            } else {
                Decision::Unsticky
            };
            if let Some(key) = sticky {
                self.bind(key, &next, now);
            }
            return Ok(Selection {
                account_id: next,
                backend,
                decision,
            });
        }

        match self.min_reset(|a| backends.contains(&a.backend), model, now) {
            Some(until_ms) => Err(SelectError::Saturated { until_ms }),
            None => Err(SelectError::NoAccounts),
        }
    }

    /// The earliest moment an eligible account can serve the model again.
    fn min_reset(&self, eligible: impl Fn(&Account) -> bool, model: &str, now: i64) -> Option<i64> {
        let mut deadlines: Vec<i64> = self
            .accounts
            .values()
            .filter(|s| s.account.status == AccountStatus::Cooling && eligible(&s.account))
            .map(|s| s.account.reset_at)
            .collect();
        deadlines.extend(
            self.model_cooldowns
                .iter()
                .filter(|(id, _)| {
                    self.accounts
                        .get(*id)
                        .is_some_and(|state| eligible(&state.account))
                })
                .filter_map(|(_, models)| models.get(model).copied())
                .filter(|until_ms| *until_ms > now),
        );
        deadlines.into_iter().min()
    }

    fn bind(&mut self, key: &str, account_id: &str, now: i64) {
        self.bindings
            .put(key.to_string(), (account_id.to_string(), now));
    }

    pub fn bindings(&self) -> Vec<Binding> {
        self.bindings
            .iter()
            .filter_map(|(key, (account_id, bound_at))| {
                let backend = self.accounts.get(account_id)?.account.backend;
                Some(Binding {
                    cache_key: key.clone(),
                    account_id: account_id.clone(),
                    backend,
                    bound_at: *bound_at,
                })
            })
            .collect()
    }

    /// @cc [owner:ghuntley,label:pool] inflight-saturating
    /// `acquire` MUST increment and `release` decrement the account's in-flight counter with
    /// saturating semantics: `release` MUST NOT move the counter below zero.
    pub fn acquire(&mut self, account_id: &str) {
        if let Some(s) = self.accounts.get_mut(account_id) {
            s.inflight = s.inflight.saturating_add(1);
        }
    }

    pub fn release(&mut self, account_id: &str) {
        if let Some(s) = self.accounts.get_mut(account_id) {
            s.inflight = s.inflight.saturating_sub(1);
        }
    }

    /// @cc [owner:ghuntley,label:pool] report-quota-transitions
    /// `report` MUST transition the account to `Cooling { reset_at = until_ms }` on
    /// `Outcome::QuotaExhausted` and to `AuthError` on `Outcome::AuthFailed`, and MUST NOT change
    /// the account's status on `Outcome::Ok`, `Outcome::Transient`, or a model-scoped quota
    /// rejection.
    pub fn report(&mut self, account_id: &str, outcome: Outcome) -> Option<AccountStatus> {
        let state = self.accounts.get_mut(account_id)?;
        let new_status = match outcome {
            Outcome::QuotaExhausted { until_ms } => Some((AccountStatus::Cooling, until_ms)),
            Outcome::AuthFailed => Some((AccountStatus::AuthError, 0)),
            Outcome::Transient | Outcome::Ok | Outcome::ModelQuotaExhausted { .. } => None,
        };
        if let Some((status, reset_at)) = new_status {
            state.account.status = status;
            state.account.reset_at = reset_at;
            Some(status)
        } else {
            None
        }
    }

    pub fn set_status(&mut self, account_id: &str, status: AccountStatus, reset_at: i64) {
        if let Some(s) = self.accounts.get_mut(account_id) {
            s.account.status = status;
            s.account.reset_at = reset_at;
        }
    }

    pub fn insert_account(&mut self, account: Account) {
        self.accounts.insert(
            account.id.clone(),
            AccountState {
                account,
                inflight: 0,
            },
        );
    }

    pub fn sync_account(&mut self, account: Account) {
        match self.accounts.get_mut(&account.id) {
            Some(state) => {
                let inflight = state.inflight;
                state.account = account;
                state.inflight = inflight;
            }
            None => self.insert_account(account),
        }
    }

    pub fn sync_from_store(&mut self, store: &Store) {
        let now = crate::models::now_ms();
        for account in store.list_accounts() {
            let mut account = account;
            if account.status == AccountStatus::Cooling && account.reset_at <= now {
                account.status = AccountStatus::Healthy;
                account.reset_at = 0;
                store.update_account_status(&account.id, AccountStatus::Healthy, 0);
            }
            self.sync_account(account);
        }
        let live: std::collections::HashSet<String> = self.accounts.keys().cloned().collect();
        let stale: Vec<String> = store
            .list_accounts()
            .into_iter()
            .filter(|a| !live.contains(&a.id))
            .map(|a| a.id)
            .collect();
        for id in stale {
            self.remove_account(&id);
        }
    }

    pub fn remove_account(&mut self, account_id: &str) {
        self.accounts.remove(account_id);
        let keys: Vec<String> = self
            .bindings
            .iter()
            .filter(|(_, (id, _))| id == account_id)
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.bindings.pop(&k);
        }
    }

    pub fn account(&self, account_id: &str) -> Option<&Account> {
        self.accounts.get(account_id).map(|s| &s.account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: &str, backend: BackendId) -> Account {
        Account {
            id: id.into(),
            backend,
            label: id.into(),
            refresh_token: None,
            access_token: None,
            expires_at: 0,
            token_refreshed_at: 0,
            account_id: None,
            residency: None,
            enterprise_url: None,
            plan: None,
            disabled_reason: None,
            status: AccountStatus::Healthy,
            reset_at: 0,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn core_with(backends: &[(BackendId, &[&str], &[&str])]) -> PoolCore {
        let store = Store::in_memory().unwrap();
        let surfaces = backends
            .iter()
            .map(|(backend, _, _)| {
                let surface = match backend {
                    BackendId::Claude => Surface::Anthropic,
                    _ => Surface::OpenAI,
                };
                (*backend, vec![surface])
            })
            .collect();
        let mut core = PoolCore::new(&store, surfaces);
        for (backend, models, ids) in backends {
            core.set_catalog(*backend, models.iter().map(|s| s.to_string()).collect());
            for id in *ids {
                core.insert_account(account(id, *backend));
            }
        }
        core
    }

    #[test]
    fn sticky_key_pins_to_one_account() {
        let mut core = core_with(&[(BackendId::Codex, &["gpt-5.5"], &["a", "b"])]);
        let s1 = core
            .select(0, Some("k1"), "gpt-5.5", Surface::OpenAI)
            .unwrap();
        let s2 = core
            .select(1, Some("k1"), "gpt-5.5", Surface::OpenAI)
            .unwrap();
        assert_eq!(s1.account_id, s2.account_id);
        assert_eq!(s2.decision, Decision::StickyHit);
    }

    #[test]
    fn sticky_rebinds_within_same_backend_when_cooling() {
        let mut core = core_with(&[
            (BackendId::Codex, &["gpt-5.5"], &["a", "b"]),
            (BackendId::Copilot, &["gpt-5.5"], &["c"]),
        ]);
        let first = core
            .select(0, Some("k"), "gpt-5.5", Surface::OpenAI)
            .unwrap();
        core.report(
            &first.account_id,
            Outcome::QuotaExhausted { until_ms: 10_000 },
        );
        let second = core
            .select(1, Some("k"), "gpt-5.5", Surface::OpenAI)
            .unwrap();
        assert_ne!(second.account_id, first.account_id);
        assert_eq!(second.backend, BackendId::Codex);
        assert_eq!(second.decision, Decision::StickyRebind);
    }

    #[test]
    fn selection_never_returns_unhealthy_accounts() {
        let mut core = core_with(&[(BackendId::Codex, &["gpt-5.5"], &["a"])]);
        core.report("a", Outcome::QuotaExhausted { until_ms: 100 });
        assert!(matches!(
            core.select(50, Some("k"), "gpt-5.5", Surface::OpenAI),
            Err(SelectError::Saturated { until_ms: 100 })
        ));
        assert!(matches!(
            core.select(150, Some("k"), "gpt-5.5", Surface::OpenAI),
            Ok(Selection { .. })
        ));
    }

    #[test]
    fn unknown_model_routes_to_codex_pass_through() {
        let mut core = core_with(&[
            (BackendId::Codex, &["gpt-5.5"], &["a"]),
            (BackendId::Copilot, &["gpt-4.1"], &["c"]),
        ]);
        let s = core
            .select(0, Some("k"), "totally-unknown-model", Surface::OpenAI)
            .unwrap();
        assert_eq!(s.backend, BackendId::Codex);
        assert_eq!(s.account_id, "a");
    }

    #[test]
    fn model_eligibility_respects_catalog() {
        let mut core = core_with(&[
            (BackendId::Codex, &["gpt-5.5"], &["a"]),
            (BackendId::Copilot, &["gpt-4.1"], &["c"]),
        ]);
        let s = core.select(0, None, "gpt-4.1", Surface::OpenAI).unwrap();
        assert_eq!(s.backend, BackendId::Copilot);
    }

    #[test]
    fn least_in_flight_is_preferred() {
        let mut core = core_with(&[(BackendId::Codex, &["gpt-5.5"], &["a", "b"])]);
        core.acquire("a");
        core.acquire("a");
        let s = core.select(0, None, "gpt-5.5", Surface::OpenAI).unwrap();
        assert_eq!(s.account_id, "b");
        core.release("a");
        core.release("a");
    }

    #[test]
    fn in_flight_never_goes_negative() {
        let mut core = core_with(&[(BackendId::Codex, &["gpt-5.5"], &["a"])]);
        core.release("a");
        core.release("a");
        assert_eq!(core.accounts["a"].inflight, 0);
    }

    #[test]
    fn saturation_reports_earliest_reset() {
        let mut core = core_with(&[(BackendId::Codex, &["gpt-5.5"], &["a", "b"])]);
        core.report("a", Outcome::QuotaExhausted { until_ms: 500 });
        core.report("b", Outcome::QuotaExhausted { until_ms: 300 });
        match core.select(100, Some("k"), "gpt-5.5", Surface::OpenAI) {
            Err(SelectError::Saturated { until_ms }) => assert_eq!(until_ms, 300),
            other => panic!("expected saturated, got {other:?}"),
        }
    }

    #[test]
    fn no_accounts_error_when_nothing_configured() {
        let mut core = core_with(&[]);
        assert!(matches!(
            core.select(0, Some("k"), "gpt-5.5", Surface::OpenAI),
            Err(SelectError::NoAccounts)
        ));
    }

    #[test]
    fn unsticky_requests_do_not_bind() {
        let mut core = core_with(&[(BackendId::Codex, &["gpt-5.5"], &["a"])]);
        let s = core.select(0, None, "gpt-5.5", Surface::OpenAI).unwrap();
        assert_eq!(s.decision, Decision::Unsticky);
        assert!(core.bindings().is_empty());
    }

    #[test]
    fn new_binding_created_for_sticky_request_on_miss() {
        let mut core = core_with(&[(BackendId::Codex, &["gpt-5.5"], &["a"])]);
        let s = core
            .select(0, Some("k"), "gpt-5.5", Surface::OpenAI)
            .unwrap();
        assert_eq!(s.decision, Decision::NewBinding);
        let bindings = core.bindings();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].account_id, "a");
        assert_eq!(bindings[0].cache_key, "k");
    }

    /// @cc [owner:ghuntley,label:pool] surfaces-partition-selection
    /// Selection MUST only return accounts whose backend declares the requested surface, and an
    /// unknown model MUST fall back to a backend that declares that surface.
    #[test]
    fn surfaces_partition_selection() {
        let mut core = core_with(&[
            (BackendId::Codex, &["gpt-5.5"], &["codex-a"]),
            (BackendId::Copilot, &["gpt-5.5"], &["copilot-a"]),
            (BackendId::Claude, &["claude-opus-5-5"], &["claude-a"]),
        ]);
        let openai = core
            .select(0, Some("k"), "gpt-5.5", Surface::OpenAI)
            .unwrap();
        assert!(openai.backend != BackendId::Claude);
        let anthropic = core
            .select(0, Some("k2"), "claude-opus-5-5", Surface::Anthropic)
            .unwrap();
        assert_eq!(anthropic.backend, BackendId::Claude);
        assert_eq!(anthropic.account_id, "claude-a");
        // An unknown model falls back to a backend that serves the requested surface.
        let unknown = core
            .select(0, Some("k3"), "claude-unknown-model", Surface::Anthropic)
            .unwrap();
        assert_eq!(unknown.backend, BackendId::Claude);
    }

    #[test]
    fn anthropic_surface_never_selects_an_openai_account() {
        let mut core = core_with(&[
            (BackendId::Codex, &["gpt-5.5"], &["codex-a"]),
            (BackendId::Claude, &["claude-opus-5-5"], &["claude-a"]),
        ]);
        for _ in 0..5 {
            let selection = core
                .select(0, None, "claude-opus-5-5", Surface::Anthropic)
                .unwrap();
            assert_eq!(selection.backend, BackendId::Claude);
        }
    }

    #[test]
    fn saturation_is_measured_per_surface() {
        let mut core = core_with(&[
            (BackendId::Codex, &["gpt-5.5"], &["codex-a"]),
            (BackendId::Claude, &["claude-opus-5-5"], &["claude-a"]),
        ]);
        core.report("codex-a", Outcome::QuotaExhausted { until_ms: 10_000 });
        // The Anthropic surface has a healthy account and must not report saturation.
        assert!(
            core.select(0, None, "claude-opus-5-5", Surface::Anthropic)
                .is_ok()
        );
        // The OpenAI surface is saturated until its account's reset.
        assert!(matches!(
            core.select(0, None, "gpt-5.5", Surface::OpenAI),
            Err(SelectError::Saturated { until_ms: 10_000 })
        ));
    }
}
