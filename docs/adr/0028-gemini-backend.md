# 0028 - Gemini Code Assist Backend (Google AI Ultra)

## Status

Accepted

## Context

The operator bought a consumer Google AI Ultra subscription on a dedicated Google account and wants it in the same pool as Codex, Copilot, Claude Code, and OpenCode Go.

The official Gemini CLI (`google-gemini/gemini-cli`, `packages/core/src/code_assist/`) is the client that spends that subscription. Reading that source, rather than the public Gemini API, shows three facts that shape the backend:

1. **Auth is installed-app OAuth, not an API key.** The CLI publishes its OAuth client id and installed-app client secret in `packages/core/src/code_assist/oauth2.ts`. Google treats that secret as an application identifier, not a user credential, but this repository does not copy either value: the operator sets `UNDERCLASS_GEMINI_CLIENT_ID` and `UNDERCLASS_GEMINI_CLIENT_SECRET` from that file. Scopes are `cloud-platform`, `userinfo.email`, and `userinfo.profile`. Headless sign-in (`NO_BROWSER`) uses redirect `https://codeassist.google.com/authcode`, PKCE S256, and `access_type=offline`. The user pastes the code the page displays. Tokens are exchanged and refreshed at `https://oauth2.googleapis.com/token`. The refresh grant does not rotate the refresh token the way Anthropic's does.

2. **Quota lives on Code Assist, not generativelanguage.googleapis.com.** Calls go to `https://cloudcode-pa.googleapis.com/v1internal`: `loadCodeAssist` and `onboardUser` establish a project id and tier, `generateContent` / `streamGenerateContent?alt=sse` run the model, `countTokens` counts, and `retrieveUserQuota` reports buckets. The body is a wrapper `{model, project, user_prompt_id, request}` whose `request` is Vertex-shaped (`contents`, `systemInstruction`, `tools`, `generationConfig`, `session_id`).

3. **The wire format is not OpenAI or Anthropic.** underclass clients speak those two surfaces (ADR 0010, ADR 0024). Gemini therefore translates, unlike Claude, which forwards Claude Code's body verbatim because Anthropic checks it.

This was verified against the CLI source. It was **not** verified against a live Google AI Ultra account. The assumptions that follow from that are listed under Consequences.

## Decision

- A fifth backend, `gemini`, implements `provider::Backend` and declares both the OpenAI and Anthropic surfaces. It translates `/v1/chat/completions`, `/v1/responses`, and `/v1/messages` (including `count_tokens`) into Code Assist `generateContent` or `streamGenerateContent`, and translates the response, including streaming deltas and function calls, back. Thought parts are dropped. The client's model id is echoed; a `models/` or `gemini/` prefix is stripped before the upstream call.
- The backend admits a client only when the model id starts with `gemini` or `gemma`. A selected backend that does not admit the client is rejected with 403 before its credential is used, so registering Gemini does not open the Anthropic surface to non-Claude-Code clients asking for Claude models.
- Onboarding is the CLI's paste-back flow, with `prompt=consent` added so a pooled account always receives a refresh token. The OAuth client id and installed-app secret are read from `UNDERCLASS_GEMINI_CLIENT_ID` and `UNDERCLASS_GEMINI_CLIENT_SECRET` and are never logged. The web UI and `underclass login --backend gemini` both drive the flow through the admin API. An optional project id is sent as `cloudaicompanionProject` for tiers that require one. The resolved project id is stored on `account_id` and is not cleared by refresh. The tier id `free-tier` is stored as plan `free`, so the existing free-plan gate disables it; any other tier stores the display name.
- Access tokens refresh on use and on `underclass refresh`, the same way Claude's do. The refresh token is kept when Google omits a new one.
- Catalog ids are unprefixed (`gemini-2.5-pro`, `gemini-3-pro-preview`, `gemma-4-31b-it`, …) because they do not collide with Codex, Claude, or the namespaced OpenCode Go catalog. The seed lists the models the CLI marks visible. `POST /admin/api/catalog/refresh-gemini` and enrollment try `fetchAvailableModels`; a failure or an empty list leaves the stored catalog alone. Operator edits of a model that is still listed survive.
- HTTP 429, and any status whose JSON `error.status` is `RESOURCE_EXHAUSTED`, cools the whole account until a `retryDelay`, else `Retry-After`, else `gemini_cooldown_secs` (default 30 minutes). The account is readmitted by the existing sweep. `retrieveUserQuota` is polled for the admin UI and `utop` and does not cool an account by itself. Multiple Gemini accounts share the flat pool and sticky sessions. The sticky key, or a digest of the conversation opening, is sent as Code Assist `session_id`.
- The user agent is `GeminiCLI/underclass (linux; amd64)`. No access token, refresh token, authorization header, or prompt is logged.

## Consequences

- Clients address Gemini models by their catalog id on either surface. `underclass connect` includes them in the OpenAI provider block. A Claude model on `/v1/messages` is still served only by a Claude Code client.
- A build without this backend reads `gemini` accounts as Codex accounts. Their refresh token is not a Codex token, so that build marks them `auth_error` when it selects them. Remove them before downgrading, or re-enable them after upgrading.
- **Not verified live.** The operator must smoke-test after signing in:
  1. Copy `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` from the Gemini CLI file `packages/core/src/code_assist/oauth2.ts` into `UNDERCLASS_GEMINI_CLIENT_ID` and `UNDERCLASS_GEMINI_CLIENT_SECRET` for the server process. Do not commit them.
  2. Run the server (`underclass serve`) and `underclass login --backend gemini` (or Add account → Gemini in the web UI). Sign in with the Ultra account and paste the code from `https://codeassist.google.com/authcode`.
  3. If setup reports that a project id is required, re-run with `--project <gcp-project-id>` (the string id, not the numeric project number).
  4. Confirm the account row shows a non-`free` plan and a project. A `free` plan is disabled on purpose.
  5. `POST /v1/chat/completions` with `"model": "gemini-2.5-pro"` and the proxy key. Expect a normal chat completion. Repeat with `"stream": true` and with a tool call.
  6. Spend the account until Google returns 429. The row should move to cooling and return on its own. A second Gemini account, if added, should take the request meanwhile.
  7. `POST /admin/api/catalog/refresh-gemini`. If it errors, the seed catalog is still in force; add any missing Ultra model ids in the catalog editor.
- `fetchAvailableModels` is not part of the CLI. Its response parser accepts a map or a list of `{name, displayName, inputTokenLimit, outputTokenLimit}`. If Google uses another shape, the seed remains.
- Thinking config is best-effort: `reasoning_effort` becomes `thinkingBudget` on `gemini-2.5*` and `thinkingLevel` otherwise, matching the CLI's split. Remote image URLs are sent as `fileData` and may be rejected; data URLs are sent as `inlineData`.
- Input-token accounting on an Anthropic stream uses the usage block of the first translated event. Chat and Responses streams take usage from the event that carries `usageMetadata`.
