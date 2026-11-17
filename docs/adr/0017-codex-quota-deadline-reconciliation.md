# 0017 - Codex Quota Deadline Reconciliation

## Status

Accepted

## Context

ADR 0004 cools an account until Retry-After or a configured fallback. Codex also returns an
absolute `error.resets_at` in `usage_limit_reached` responses, and its account usage endpoint
reports exhausted windows. A fallback can expire before the upstream window resets. The existing
usage poll moved healthy accounts into cooling but did not extend an already cooling account.

## Decision

Keep the account health states and fail-fast behavior from ADR 0004. Codex classifies structured
usage-limit errors in its backend implementation. For a quota error, use the later valid future
deadline from `error.resets_at` (Unix seconds) and Retry-After; use the configured fallback when
neither gives a future deadline. Treat overload as transient. Other backends retain the generic
status and Retry-After classification.

An account-matched Codex usage poll can cool an account only when its included allowance is exhausted and credit-backed usage is unavailable.
Available included usage takes precedence over credit or spend limits.
Credit-backed usage needs `credits.has_credits: true` or `credits.unlimited: true`, without an explicit `credits.overage_limit_reached: true` or `spend_control.reached: true` block.

Missing credit metadata does not grant access.
Either form of usable access readmits a cooling account and clears its reset attempt.
Otherwise, an exhausted window can extend a cooling deadline, but cannot shorten one.

Failed or missing usage responses leave health unchanged.
Persist each health transition immediately.
Model-specific limits remain separate.

## Consequences

- A Codex account remains out of rotation through a known upstream reset time, even when the
  fallback would have expired sooner.
- The dashboard continues to show usage windows and the account's persisted cooldown deadline.
- Accounts without a usable upstream deadline retain the configured fallback behavior.
