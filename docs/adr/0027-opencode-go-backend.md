# 0027 - OpenCode Go Backend

## Status

Accepted

## Context

OpenCode Go is a flat subscription to a curated set of coding models from many vendors (GLM,
Kimi, DeepSeek, MiMo, Qwen, MiniMax, Grok, GPT Luna, Claude Haiku and more). It differs from the
existing backends in three ways that matter to the pool.

**Credential.** An account is a Console API key (`oc_sk_<id>_<secret>`), not an OAuth grant. The
key never refreshes; a revoked or expired key answers 401 (`api_key_expired`).

**Wire.** The gateway at `https://opencode.ai/inference/go` serves every text model through
`/openai/v1/responses` and `/openai/v1/chat/completions`, translating to the model's native API
when needed. `/v1/models` lists the model ids without names or limits, and `/v1/usage` reports the
workspace's allowance windows (`rolling` 5 hours, `weekly`, `monthly`), each with a `percent`, a
`status` (`ok` or `rate-limited`) and a `resetsAt`. The gateway asks clients to send their own user
agent and a stable `x-opencode-session` per conversation, which it uses for routing and prompt
caching.

**Quota.** Paid models draw on the workspace's allowance. A spent allowance answers 429
`GoUsageLimitError` with a `Retry-After` until the window resets; with OpenCode's *Extra Usage*
switched on and no pay-as-you-go balance it answers 402 `Insufficient account funds` instead.
Either way the free models (`beam-free`) keep working, so a spent allowance does not take the
whole account out of service.

OpenCode Go also serves upstream ids that another backend serves: `gpt-6-luna` and `gpt-5.6-luna`
are both Codex and OpenCode Go models. Under ADR 0010's flat pool, sharing the id would make the two
compete for every request, and `/v1/models` merges duplicate ids by the larger context window, so
the OpenCode Go entry would take over the Codex model's `owned_by`. Clients that select Codex
models by `owned_by` would lose them.

## Decision

- A fourth backend, `opencode-go`, declares the OpenAI surface and rewrites `/responses` and
  `/chat/completions` to `<base>/openai/v1/...`. It injects the key as a bearer credential and
  `underclass/<version>` as the user agent. The gateway answers 400 `MissingSessionID` to a
  request without `x-opencode-session`, so every request carries one: the request's sticky key
  (ADR 0003), or, for a keyless request, a name derived from a SHA-256 digest of the
  conversation's opening (instructions and the turns through the first user message), which
  stays the same on every later turn. The derived name only feeds the header; a keyless request
  still creates no binding.
- **Catalog ids are namespaced**: an upstream model `kimi-k3` is cataloged as
  `opencode-go/kimi-k3`. Routing stays catalog-driven (ADR 0007, ADR 0010); the namespace only
  makes the OpenCode Go catalog disjoint from the others, so no existing model changes hands. The
  backend strips the namespace from the request body before forwarding. A model in no catalog
  still passes through to Codex, as before.
- The catalog is seeded with OpenCode's published names and limits and refreshed from the live
  `/v1/models` list on boot, on enrollment and through `POST /admin/api/catalog/refresh-opencode-go`.
  A refresh keeps the stored entry of every model still live, so operator edits survive, seeds new
  models, and drops models that are gone.
- 429 and 402 classify as `ModelQuotaExhausted`: the refused model cools on that account until the
  gateway's `Retry-After`, or `opencode_go_cooldown_secs` without one. The account stays `Healthy`
  and keeps serving its free models; each other paid model learns its own cooldown on first
  refusal. 401 and 403 follow the shared classification.
- A sticky hit now also requires the bound account not to be cooling for the requested model.
  Before, a session bound to an account kept landing on it after the upstream refused its model,
  so the failover attempt repeated the refusal; this applied to Claude's model-scoped windows as
  well.
- Enrollment is synchronous: `POST /admin/api/flows` with `{"backend": "opencode-go", "api_key":
  ..., "label": ...}` validates the key against `/v1/usage` before storing it and returns an already
  authorized flow. `POST /admin/api/accounts/{id}/relogin` with `{"api_key": ...}` swaps an
  account's key. The key is never echoed, logged or used in a label; without an operator label an
  account is named after the key's public id. It is stored as an access token that expired at the
  epoch, with no refresh token.
- The key has nothing to refresh, so `tokens::refreshes_with_issuer` is false for `opencode-go`:
  a manual refresh (ADR 0026) answers `409 not_refreshable`, the admin UI shows no **Refresh
  token** button, and `underclass refresh --all` skips these accounts. A revoked key comes back
  only through **Re-login** with a new key.
- The allowance windows are polled every two minutes and shown as observations in the admin UI
  and `utop`. They never cool an account by themselves: a spent allowance still serves the free
  models, and Extra Usage can serve paid ones from the balance, so only an upstream refusal says a
  model is unavailable.

## Consequences

- Clients address OpenCode Go models as `opencode-go/<id>`; `underclass connect` includes them in
  the opencode provider block.
- OpenCode Go accounts never absorb Codex or Copilot traffic, and the reverse. Sharing capacity for
  an overlapping upstream id would need a routing policy across catalogs, which this ADR does not
  introduce.
- A spent allowance costs one refused attempt per paid model per account before the cooldown is
  known. Model cooldowns live in memory, so a restart relearns them the same way.
- Because unknown models still fall back to Codex, a namespaced id missing from the catalog is
  answered by Codex's error until the catalog is refreshed.
- A build without this backend reads `opencode-go` accounts as Codex accounts. Because their key
  is an expired access token with no refresh token, such a build has nothing to refresh or send:
  it marks them `auth_error` when it selects them and fails over. Re-enable them after upgrading
  again, or remove them before downgrading.
