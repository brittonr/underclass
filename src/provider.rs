use crate::models::{Account, BackendId, Outcome, Surface};
use crate::usage::UsageDialect;
use http::HeaderMap;
use serde_json::Value;

pub trait Backend: Send + Sync {
    fn id(&self) -> BackendId;

    /// The request surfaces this backend can serve. The pool only ever selects a backend for a
    /// surface the backend declares, so an Anthropic-shaped request can never land on an
    /// OpenAI-shaped upstream.
    fn surfaces(&self) -> &'static [Surface];

    fn default_cooldown_ms(&self) -> i64;

    fn rewrite_url(&self, path: &str, account: &Account) -> String;

    /// Injects the upstream request headers.
    ///
    /// `client` carries the headers the client sent, for backends that need the client's own
    /// fingerprint; `headers` is the outbound header map the proxy builds.
    fn inject_headers(
        &self,
        account: &Account,
        token: &str,
        sticky: Option<&str>,
        body: &Value,
        client: &HeaderMap,
        headers: &mut HeaderMap,
    );

    fn prepare_body(&self, _body: &mut Value) {}

    fn auto_stream_usage(&self, _path: &str, _body: &mut Value) -> bool {
        false
    }

    fn usage_is_chat(&self, path: &str) -> bool {
        path.ends_with("/chat/completions")
    }

    /// The wire dialect of the upstream response bodies, used for token accounting.
    fn usage_dialect(&self, path: &str) -> UsageDialect {
        if self.usage_is_chat(path) {
            UsageDialect::Chat
        } else {
            UsageDialect::Responses
        }
    }

    /// Whether the client's own request headers are forwarded upstream. Backends whose upstream
    /// validates the client fingerprint enable this; the proxy still strips credentials and
    /// hop-by-hop headers before forwarding.
    fn forward_client_headers(&self) -> bool {
        false
    }

    /// Whether the client's request body is forwarded byte for byte. Backends whose upstream
    /// validates the request body's contents enable this; the proxy then neither rewrites nor
    /// re-serializes it.
    fn forward_body_verbatim(&self) -> bool {
        false
    }

    /// Whether this backend admits the given client request. Backends that only serve one
    /// client shape reject anything else before a pooled credential is spent.
    fn accepts_client(&self, _headers: &HeaderMap, _body: &Value) -> bool {
        true
    }

    /// A backend-specific observation of an upstream response, stored per account for the admin
    /// UI. Backends decide what to report; the proxy only stores it.
    fn observe_response(
        &self,
        _account: &Account,
        _headers: &HeaderMap,
        _now_ms: i64,
    ) -> Option<Value> {
        None
    }

    /// The deadline until which the upstream reports the account cannot serve, so the pool can
    /// cool it without waiting for a failed request.
    fn exhausted_until_ms(&self, _headers: &HeaderMap) -> Option<i64> {
        None
    }

    fn classify(&self, status: u16, _body: &str, headers: &HeaderMap, now_ms: i64) -> Outcome {
        crate::health::classify(status, headers, self.default_cooldown_ms(), now_ms)
    }
}

pub type BackendMap = std::collections::HashMap<BackendId, std::sync::Arc<dyn Backend>>;
