# 0023 - Claude Code Subscription Backend over an Anthropic-Native Surface

## Status

Proposed

## Context

underclass pools ChatGPT/Codex and GitHub Copilot subscriptions behind one OpenAI-shaped
endpoint (ADR 0010). The operator wants the same treatment for **Claude Code
subscriptions** (Pro/Max/Team/Enterprise).

Three facts shape the design, and all three were **verified empirically** against the live
Anthropic API rather than inferred (method and captures in "Evidence" below):

1. **The upstream protocol is the Anthropic Messages API, not OpenAI.** Claude Code speaks
   `POST /v1/messages?beta=true` with Anthropic's content-block schema. Both existing
   backends happen to accept OpenAI shapes upstream; Anthropic does not. A
   protocol-translation layer would therefore be new machinery, not a reuse of anything
   underclass already has.

2. **Anthropic enforces the Claude Code client shape server-side.** With a subscription OAuth
   token, a hand-rolled `POST /v1/messages` was rejected with `429 rate_limit_error` and
   `x-should-retry: true`; the *same* token and model, one second later, with Claude Code's
   identity system block and billing block, returned `200` and a normal event stream. The
   credential is usable only for Claude Code-shaped traffic.

3. **Anthropic's terms restrict this credential.** As of February 2026 the legal-and-compliance
   page states that subscription OAuth authentication "is intended exclusively for Claude Code
   and Claude.ai", that developers "may not collect, store, or intermediate Claude.ai
   credentials or session tokens", and that using subscription OAuth "in any other product,
   tool, or service" violates the Consumer Terms of Service. Anthropic has deployed
   server-side enforcement and reserves the right to invalidate credentials without notice.

Point 2 makes the "official Claude Code client only" rule a **functional** requirement, not
merely a policy preference: underclass cannot manufacture traffic that Anthropic will accept.
Point 3 makes it a **constraint on the operator**, which this ADR records rather than hides.

The design below therefore keeps every Claude Code artifact exactly as the client produced
it - identity prompt, billing block, beta list, SDK fingerprint - and only swaps the
credential.

## Decision

- Add a third backend, `claude`, implementing `provider::Backend`, upstream
  `https://api.anthropic.com`, credentialed by a Claude Code subscription OAuth token.

- Add a second **surface** to the proxy: `POST /v1/messages` and
  `POST /v1/messages/count_tokens`, speaking the Anthropic Messages API. The existing
  `/v1/responses` and `/v1/chat/completions` remain OpenAI-shaped and never select a
  `claude` account; the Anthropic surface never selects a `codex` or `copilot` account.
  Backend capability is declared by the backend (`Backend::surfaces`), so the pool core
  stays backend-agnostic (CONTRACTS `backend-agnostic-core`).

- **Passthrough, not rewriting.** For the Anthropic surface underclass forwards the client's
  request body verbatim and forwards every client request header except credentials and
  hop-by-hop/transport headers. No system-prompt munging, no body rewriting, no beta
  rewriting: the identity system block and the `x-anthropic-billing-header` block are part of
  the request Anthropic validates, so touching them breaks the request (point 2 above).
  Only the credential is replaced: the client's `Authorization`/`x-api-key` are stripped and
  the selected account's OAuth token is injected (CONTRACTS `outbound-credential-stripping`).

- **Claude Code clients only.** The Anthropic surface admits only requests carrying Claude
  Code's markers (`x-app: cli`, `User-Agent: claude-cli/…`, `claude-code-20250219` in
  `anthropic-beta`, and the billing block in the body). Anything else is rejected with 403
  **before** a pooled credential is touched, so a pooled subscription token is never spent on
  traffic Anthropic would refuse.

- **Onboarding is a paste-back PKCE flow**, not a device flow: Anthropic has no device
  grant. The web UI shows an authorize URL; the user signs in, lands on the hosted callback
  page, and pastes the `code#state` string back; underclass exchanges it. This keeps
  ADR 0009's "no browser on the proxy host" property.

- **The authorize request asks for the full Claude Code scope set, verbatim:**
  `org:create_api_key user:profile user:inference user:sessions:claude_code
  user:mcp_servers user:file_upload user:plugins`. Matching the official client exactly
  keeps the consent page consistent with what the registered application expects, and
  avoids a narrower grant that some subscription capability could later depend on. The
  server grants a **subset** of what is requested - observed grants were every scope above
  except `org:create_api_key` - so underclass must treat the granted set as authoritative
  and must not assume a scope it asked for is present.

- **Token lifecycle**: access tokens are short-lived; the refresh token **rotates** on every
  refresh and the new one is persisted immediately (ADR 0005). Refresh failures are retried
  with backoff, not treated as fatal: the token endpoint itself rate-limits (observed
  `429 rate_limit_error` immediately after an exchange).

- **Quota is window-based, not bucket-based.** A Claude Code subscription has a 5-hour
  session window, a 7-day weekly window, and a weekly window scoped to one model family. The
  account's own usage API (`GET /api/oauth/usage`) reports all three, plus the plan and the
  banked rate-limit reset credits, so underclass reads an account's quota **without sending
  anything that looks like a Claude Code request** - which keeps the credential usable only for
  the official client. Shared five-hour/seven-day exhaustion can cool an account until the
  latest exhausted shared reset. A spent family window blocks only that family's model variants,
  independently of exact-model HTTP refusals. Fresh valid shared headroom can readmit only a
  currently cooling account; malformed reported windows cannot establish headroom, and passive
  observations must preserve operator disables, authentication blocks and deleted accounts.

- **A 429's scope decides the cooldown.** Anthropic reports the scope in the response headers:
  a rejected shared five-hour or seven-day window blocks the credential across models, while a
  rejected model-scoped window (the weekly other-models window, overage, or an overage-disabled
  reason) blocks only that model on the account. A request-scoped refusal ("fast request
  rejected", "credits are required") cools nothing. A 429 that says nothing at all cools
  nothing either: underclass measured that Anthropic answers a request it refuses to serve with
  exactly that shape, and cooling an account on it would be wrong.

- **Catalog**: `GET /v1/models` accepts the OAuth token (with `anthropic-version`), so the
  model list is fetched live like Copilot's, with a static seed as fallback.

## Evidence

All values below were captured on 2026-10-20 from the live API. **No credential value
appears**: access tokens, refresh tokens, and authorization codes were redacted at capture
time (length and public prefix only), and account/organization identifiers are shown as
placeholders.

### Method

- Client: Claude Code **2.1.304** (native build), run against a throwaway
  `CLAUDE_CONFIG_DIR` so the operator's real `~/.claude` credentials were untouched.
- Interception: `mitmproxy 12.2.3` (`mitmdump`) on `127.0.0.1:8081` as an HTTPS proxy, with
  its CA installed into the system trust store and passed to the client via
  `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`. A capture addon wrote every request **and
  response** for `*.claude.com` / `*.anthropic.com` to disk with secret-shaped values
  redacted at write time.
- Two capture modes were used: (a) `ANTHROPIC_BASE_URL` pointed at a local cleartext
  recorder for the full Claude Code request shape, and (b) the MITM proxy for the OAuth
  exchange and the API responses.

### OAuth: authorize and exchange

Authorize URL printed by the client (parameters verbatim):

```
https://claude.com/cai/oauth/authorize
  ?code=true
  &client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e
  &response_type=code
  &redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback
  &scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference
         +user%3Asessions%3Aclaude_code+user%3Amcp_servers+user%3Afile_upload+user%3Aplugins
  &code_challenge=<per-flow S256 challenge>
  &code_challenge_method=S256
  &state=<per-flow state>
```

- `client_id` is the public Claude Code client id (`9d1c250a-e61b-44d9-88ed-5944d1962f5e`).
- `redirect_uri` is the **hosted** callback (`https://platform.claude.com/oauth/code/callback`),
  which renders the authorization code for the user to copy. The CLI prompts
  "Paste code here if prompted>" and accepts `code#state`.
- PKCE is S256 with a per-flow verifier and state; the flow echoes the verifier back as
  `state`.
- The scopes **granted** by the server differ from those requested: `org:create_api_key` was
  requested but **not** granted. Granted set observed:
  `user:file_upload user:inference user:mcp_servers user:plugins user:profile user:sessions:claude_code`.

Token endpoint (both grants), JSON body:

| grant | endpoint | body |
|---|---|---|
| exchange | `POST https://platform.claude.com/v1/oauth/token` | `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`, `state` |
| refresh | `POST https://platform.claude.com/v1/oauth/token` | `grant_type=refresh_token`, `refresh_token`, `client_id` |

Token response shape (values redacted):

```
access_token   sk-ant-oat01-…   (108 chars)
refresh_token  sk-ant-ort01-…   (108 chars)
expires_in     <seconds>
scope          <space-separated granted scopes>
account        { uuid, email_address }
organization   { uuid }
```

The refresh grant **rotates** the refresh token; the previous one is invalidated.

### Claude Code request shape (v2.1.304, captured in the clear)

Endpoint: `POST /v1/messages?beta=true`. Request headers:

```
authorization: Bearer <client's own oauth token>          # stripped by underclass
content-type: application/json
accept: application/json                                    # streaming is body-driven ("stream": true), not Accept-driven
user-agent: claude-cli/2.1.304 (external, sdk-cli)
x-app: cli
x-claude-code-session-id: <uuid>
anthropic-version: 2023-06-01
anthropic-dangerous-direct-browser-access: true
anthropic-beta: oauth-2025-04-20, interleaved-thinking-2025-05-14,
               thinking-token-count-2026-05-13, context-management-2025-06-27,
               prompt-caching-scope-2026-01-05, claude-code-20250219,
               per-turn-control-2026-07-01, mid-conversation-tool-changes-2026-07-01,
               inline-tools-2026-09-15, advisor-tool-2026-03-01,
               advanced-tool-use-2025-11-20, effort-2025-11-24,
               extended-cache-ttl-2025-04-11
x-stainless-arch: x64
x-stainless-lang: js
x-stainless-os: Linux
x-stainless-package-version: 0.128.0
x-stainless-retry-count: 0
x-stainless-runtime: node
x-stainless-runtime-version: v26.3.0
x-stainless-timeout: 600
```

**The attribution/billing header is not an HTTP header in this version - it is the first
system block of the request body:**

```
system[0] = "x-anthropic-billing-header: cc_version=2.1.304.c61; cc_entrypoint=sdk-cli;"
system[1] = "You are a Claude agent, built on Anthropic's Claude Agent SDK."   # cache_control: ephemeral, ttl 1h
system[2] = <main system prompt>                                               # cache_control: ephemeral, ttl 1h
```

(`claude -p` uses the Agent SDK identity line; the interactive CLI uses
`You are Claude Code, Anthropic's official CLI for Claude.`)

Body shape:

```
model              claude-haiku-5-5
max_tokens         128000
stream             true
thinking           { type: adaptive, display: omitted }
output_config      { effort: medium }
context_management { edits: [ { type: clear_thinking_20251015, keep: all } ] }
metadata.user_id   "{\"device_id\":\"<sha256>\",\"account_uuid\":\"<uuid>\",\"session_id\":\"<uuid>\"}"
system             [ billing block, identity block, main prompt ]   # see above
messages           [ { role: user, content: [ ... ] }, { role: system, content: [ ... ] } ]
tools              [ ... ]                                          # 12 tools in the captured run
```

`metadata.user_id` is a **JSON-encoded string**, not an object; `session_id` matches
`x-claude-code-session-id` and is the natural sticky key for the pool.

### Response shape (200, `text/event-stream`)

```
event: message_start        data: { type: message_start, message: { id, model, role, usage: {
                                   input_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                                   cache_creation: { ephemeral_5m_input_tokens, ephemeral_1h_input_tokens },
                                   output_tokens, service_tier, inference_geo, speed } } }
event: content_block_start  data: { type, index, content_block: { type: text, text: "" } }
event: ping                 data: { type: ping }
event: content_block_delta  data: { type, index, delta: { type: text_delta, text } }
event: content_block_stop   data: { type, index }
event: message_delta        data: { type, delta: { stop_reason, stop_sequence }, usage: {
                                   input_tokens, output_tokens, output_tokens_details: { thinking_tokens } } }
event: message_stop         data: { type: message_stop }
```

Anthropic reports usage in **two** places (`message_start` for input, `message_delta` for
output), unlike the OpenAI dialects underclass already parses.

### Rate-limit headers (present on every successful response)

```
anthropic-ratelimit-unified-status: allowed
anthropic-ratelimit-unified-5h-status: allowed
anthropic-ratelimit-unified-7d-status: allowed
anthropic-ratelimit-unified-representative-claim: five_hour
anthropic-ratelimit-unified-reset: <unix seconds>
anthropic-ratelimit-unified-5h-utilization: 0.06
anthropic-ratelimit-unified-5h-reset: <unix seconds>
anthropic-ratelimit-unified-7d-utilization: 0.04
anthropic-ratelimit-unified-7d-reset: <unix seconds>
anthropic-ratelimit-unified-overage-status: rejected
anthropic-ratelimit-unified-overage-disabled-reason: org_level_disabled
anthropic-ratelimit-unified-fallback-percentage: 0.5
anthropic-organization-id: <organization uuid>
anthropic-workspace-id: <workspace uuid>
request-id: req_…
```

There is **no** `retry-after` on a subscription-window 429; the window reset comes from
`anthropic-ratelimit-unified-reset` (and the per-window `-reset` headers).

### Enforcement evidence

| request | result |
|---|---|
| `POST /v1/messages`, plain body, `Authorization: Bearer <oauth>`, `anthropic-beta: oauth-2025-04-20` | `429` `{"type":"error","error":{"type":"rate_limit_error","message":"Error"}}`, response header `x-should-retry: true`, **no** unified rate-limit headers |
| `POST /v1/messages`, same token and model, with Claude Code identity block + billing block + `claude-code-20250219` + `x-app: cli` + `user-agent: claude-cli/…` | `200`, full SSE event stream |

A 429 that carries **no** `anthropic-ratelimit-unified-*` headers is therefore a credential
rejection, not a quota exhaustion, and must not be classified as "cooling until reset".

### Identity, plan and roles

`GET https://api.anthropic.com/api/oauth/profile` (Bearer token) -> `200`:

```
account       { uuid, full_name, display_name, email, has_claude_max, has_claude_pro, created_at }
organization  { uuid, name, organization_type: claude_max|claude_pro|claude_team|claude_enterprise,
                billing_type, rate_limit_tier, seat_tier, has_extra_usage_enabled,
                subscription_status, subscription_created_at }
application   { uuid: <client id>, name: "Claude Code", slug: "claude-code" }
```

`GET https://api.anthropic.com/api/claude_cli/bootstrap?entrypoint=sdk-cli&model=<model>` ->
`200`, and carries everything needed for an account label and plan in one call:

```
oauth_account { account_uuid, account_email, organization_uuid, organization_name,
                organization_type, organization_rate_limit_tier, user_rate_limit_tier, seat_tier }
client_data   { ...feature flags... }
model_access  null | {...}
```

`GET https://api.anthropic.com/api/oauth/claude_cli/roles` -> `200`
(`organization_role`, `workspace_uuid`, `workspace_role`).

`GET https://api.anthropic.com/api/organization/claude_code_first_token_date` -> `403`
`permission_error` (not usable with a subscription token).

### Catalog

`GET https://api.anthropic.com/v1/models` with the OAuth token **and**
`anthropic-version: 2023-06-01` -> `200` (without `anthropic-version` it is a `400`
`invalid_request_error`). Each entry carries `id`, `display_name`, `line`,
`max_input_tokens`, `max_tokens`, `created_at`, and a `capabilities` object. Observed list
(14 models):

| id | display name | max input | max output | line |
|---|---|---|---|---|
| `claude-haiku-5-5` | Claude Haiku 5.5 | 1,000,000 | 128,000 | haiku |
| `claude-sonnet-5-5` | Claude Sonnet 5.5 | 1,000,000 | 128,000 | sonnet |
| `claude-opus-5-5` | Claude Opus 5.5 | 1,000,000 | 128,000 | opus |
| `claude-fable-5-1` | Claude Fable 5.1 | 1,000,000 | 128,000 | fable |
| `claude-opus-5` | Claude Opus 5 | 1,000,000 | 128,000 | opus |
| `claude-sonnet-5` | Claude Sonnet 5 | 1,000,000 | 128,000 | sonnet |
| `claude-fable-5` | Claude Fable 5 | 1,000,000 | 128,000 | fable |
| `claude-opus-4-8` | Claude Opus 4.8 | 1,000,000 | 128,000 | opus |
| `claude-opus-4-7` | Claude Opus 4.7 | 1,000,000 | 128,000 | opus |
| `claude-sonnet-4-6` | Claude Sonnet 4.6 | 1,000,000 | 128,000 | sonnet |
| `claude-opus-4-6` | Claude Opus 4.6 | 1,000,000 | 128,000 | opus |
| `claude-opus-4-5-20251101` | Claude Opus 4.5 | 200,000 | 64,000 | opus |
| `claude-haiku-4-5-20251001` | Claude Haiku 4.5 | 200,000 | 64,000 | haiku |
| `claude-sonnet-4-5-20250929` | Claude Sonnet 4.5 | 200,000 | 64,000 | sonnet |

### Error taxonomy observed

| status | body `error.type` | notes |
|---|---|---|
| 400 | `invalid_request_error` | e.g. missing `anthropic-version` |
| 401 | `authentication_error` | expired/invalid token |
| 403 | `permission_error` | e.g. organization-scoped endpoints |
| 429 | `rate_limit_error` | ambiguous: **quota** when unified headers are present, **credential rejection** when absent |
| 529 | `overloaded_error` | capacity (from the client source, not re-verified here) |

The OAuth token endpoint also returns `429 rate_limit_error` ("Rate limited. Please try again
later.") independently of the message API.

## Consequences

- The pool gains a third backend and a second protocol surface; routing becomes
  surface-aware, so the pool core learns which backends can serve which surface rather than
  inferring it from model names. This is a new architectural decision and gets its own ADR
  (surface-partitioned routing) plus property tests.
- Claude models appear in the union catalog with their real limits, and Claude accounts
  appear in the admin UI and `utop` with plan and 5h/7d quota columns.
- Claude Code is pointed at underclass with `ANTHROPIC_BASE_URL` and `CLAUDE_CODE_OAUTH_TOKEN`:
  the client keeps sending its own Claude Code identity and underclass replaces only the
  credential, so the request Anthropic receives is the request Claude Code produced.
  `CLAUDE_CODE_OAUTH_TOKEN` is the environment variable the official client already uses when
  an auth-injecting proxy sits in front of it; `ANTHROPIC_AUTH_TOKEN` is not enough, because a
  client that still holds its own claude.ai login keeps using that token.
- underclass stores Anthropic OAuth credentials. Per Anthropic's February 2026 terms this is
  "collecting/storing/intermediating Claude.ai credentials", which those terms prohibit for
  third-party developers, and Anthropic enforces server-side and may invalidate
  credentials without notice. The operator runs this locally, for their own subscriptions,
  with the official client as the only admitted caller. That residual risk is accepted
  knowingly and is recorded here rather than left implicit.
- **Deliberately not automatic**: redeeming a banked rate-limit reset credit spends the
  operator's own subscription credit, so underclass never does it on its own. It reports how
  many credits an account holds, and redeems exactly one when the operator asks for it (the
  admin page's **Use reset** button, or `underclass reset <account>`).

## Risks

- **Credential invalidation.** Anthropic can revoke a pooled credential at any time
  (observed shape of the failure: a `429` with no unified headers, i.e. indistinguishable
  from a quota 429 unless the classifier checks for the unified headers).
- **Silent protocol drift.** Anthropic can change OAuth endpoints, beta names, the system
  block layout, or the billing block. underclass's Anthropic path must therefore forward
  rather than reconstruct, and the constants must live in one module.
- **Attestation.** Newer clients may add a native client-attestation token to the billing
  block that only the official binary can compute. Forwarding the body verbatim is what
  keeps such a token valid; any underclass-side body rewriting would break it.
- **Token-endpoint rate limiting.** The OAuth token endpoint returns 429 independently of
  the message API, so refresh needs backoff and must never mark an account broken.
- **Pre-output failover.** Anthropic signals capacity with 529 and quota with 429; the
  failover path must distinguish them, and the pre-output hold must recognise Anthropic's
  event names (`content_block_delta` is the first output event).

## Open questions

- Whether the Anthropic surface should expose `GET /v1/models` (Claude Code does not call
  it, but other Anthropic-shaped clients might). The live `GET /v1/models` fetch works with
  the OAuth token, so the data is already available if the answer is yes.
