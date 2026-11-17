# 0020 - Manual Redemption of Codex Banked Resets

## Status

Accepted

## Context

ADR 0013 redeems a banked Codex reset only when a live request finds the whole Codex pool exhausted, and it picks the account by latest natural recovery. Operators sometimes want to spend a credit on a specific account outside that trigger: before a session starts, on an account that is cooling while other Codex accounts are still healthy, or when automatic redemption is disabled. Until now the only way was to call the upstream `rate-limit-reset-credits/consume` endpoint by hand with a token copied out of `pool.db`, which bypasses the proxy's idempotency record, its health readmission, and the no-secret-handling rule.

## Decision

- `ResetManager::manual_reset` redeems at most one credit for exactly the named ChatGPT/Codex account. It does not depend on `auto_codex_resets` and shares the automatic path's serialization lock, credit choice (earliest-expiring available credit), persisted idempotency key, and confirm-then-readmit behaviour.
- Fresh included or credit-backed access prevents reset consumption and readmits a cooling account. A completed redemption whose outage continues also prevents another reset. The `force` flag overrides both refusals. A missing credit or a non-Codex account always prevents redemption.
- The operation is exposed as `POST /admin/api/accounts/{id}/reset?force=` behind the admin token, returning JSON with a stable `error` code and `message` on refusal (409 for `not_rate_limited`, `already_redeemed`, `no_credit`; 400 for `not_codex`; 502 for upstream failure). The admin page shows a **Use reset** button on Codex rows with banked credits and offers the force retry on an overridable refusal.
- `underclass reset <label-or-id> [--force] [--url]` drives that endpoint from the terminal. It resolves the account from `/admin/api/state` (exact label, exact id, or unique id prefix of at least 8 characters) and reuses `top`'s admin token resolution, so a database token is never sent to a remote host. The CLI never reads credentials or writes the database itself.

## Consequences

- Operators can spend a credit deliberately, and the proxy records the attempt, reuses the key on retry, and readmits the account only after upstream confirms, exactly as for automatic redemption.
- The default refusals make it hard to waste a credit on an account that is already usable; the override exists because upstream, not the proxy, is the source of truth on whether a reset does anything.
- Structured logs record manual attempts under the request id `manual` with the same outcome vocabulary as automatic redemption, still without tokens or upstream bodies.
