//! OpenAI-compatible chat-completions wire types and shared HTTP helper.
//!
//! Both the vLLM and OpenAI judge backends talk to `/v1/chat/completions`
//! with identical request/response shapes; only auth differs. This
//! module owns the wire types and the retry-wrapped call, so the
//! backends collapse to thin wrappers that inject their own auth and
//! stamp the verdict.
//!
//! Extracted per issue #67 — it resolves two problems at once:
//! 1. vLLM previously bypassed [`super::retry::with_retry`], so the
//!    default backend had the weakest resilience. All callers now go
//!    through a single retry-aware path.
//! 2. ~180 lines of wire-type duplication between `vllm.rs` and
//!    `openai.rs` collapse to one source of truth.

use chrono::{DateTime, Utc};
use llmtrace_core::JudgeRetryConfig;
use reqwest::header::HeaderMap;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::{retry, truncate_helper, JudgeError};

/// Parse the HTTP `Retry-After` header (RFC 7231 §7.1.3) into
/// milliseconds. Supports both delta-seconds (`"120"`) and HTTP-date
/// forms. Returns `None` when the header is absent, malformed, or
/// points to a past date.
///
/// Referenced from `openai_compat::call_chat_completions` and
/// `anthropic::judge` so `JudgeError::BackendError` can carry a hint
/// that `retry::with_retry` uses to override the computed backoff
/// (issue #75).
#[must_use]
pub(crate) fn parse_retry_after(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?;
    let text = value.to_str().ok()?;
    // Delta-seconds form: non-negative integer.
    if let Ok(secs) = text.trim().parse::<u64>() {
        return Some(secs.saturating_mul(1000));
    }
    // HTTP-date form: RFC 7231 allows IMF-fixdate / obs-date. Chrono
    // parses RFC 2822 which covers IMF-fixdate.
    if let Ok(when) = DateTime::parse_from_rfc2822(text.trim()) {
        let when = when.with_timezone(&Utc);
        let now = Utc::now();
        if when > now {
            let delta = (when - now).num_milliseconds();
            if delta > 0 {
                return Some(delta as u64);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct ChatRequest<'a> {
    pub model: &'a str,
    pub messages: Vec<ChatMessage<'a>>,
    pub max_tokens: u32,
    pub temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Serialize)]
pub(crate) struct ChatMessage<'a> {
    pub role: &'a str,
    pub content: String,
}

#[derive(Serialize)]
pub(crate) struct ResponseFormat {
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Present only when `kind == "json_schema"` (issue #81). Carries
    /// the strict schema contract the provider is required to match.
    /// vLLM continues to use `json_object` mode and leaves this None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<JsonSchemaSpec>,
}

/// OpenAI `response_format.json_schema` spec. `strict: true` makes the
/// provider refuse the completion when the generated object fails the
/// schema, which removes the malformed-JSON failure mode entirely.
#[derive(Serialize)]
pub(crate) struct JsonSchemaSpec {
    pub name: &'static str,
    pub strict: bool,
    pub schema: serde_json::Value,
}

#[derive(Deserialize)]
pub(crate) struct ChatResponse {
    pub choices: Vec<ChatChoice>,
    #[serde(default)]
    pub usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
pub(crate) struct ChatChoice {
    pub message: ChatResponseMessage,
}

#[derive(Deserialize)]
pub(crate) struct ChatResponseMessage {
    pub content: String,
}

#[derive(Deserialize)]
pub(crate) struct ChatUsage {
    #[serde(default)]
    pub prompt_tokens: Option<u32>,
    #[serde(default)]
    pub completion_tokens: Option<u32>,
}

impl ChatResponse {
    /// Return the text content of the first choice, or a `ParseError`
    /// when the response has no choices.
    pub(crate) fn first_content(&self) -> Result<&str, JudgeError> {
        self.choices
            .first()
            .map(|c| c.message.content.as_str())
            .ok_or_else(|| JudgeError::ParseError("chat response has no choices".to_string()))
    }

    /// Return `(prompt_tokens, completion_tokens)` — either may be
    /// `None` when the backend omits usage.
    pub(crate) fn tokens(&self) -> (Option<u32>, Option<u32>) {
        self.usage
            .as_ref()
            .map(|u| (u.prompt_tokens, u.completion_tokens))
            .unwrap_or((None, None))
    }
}

// ---------------------------------------------------------------------------
// Retry-wrapped HTTP call
// ---------------------------------------------------------------------------

/// POST `body` to `url` as a `/v1/chat/completions`-shaped request,
/// retrying transient failures per `retry_cfg`, and return the parsed
/// [`ChatResponse`].
///
/// `auth_fn` is applied to the [`RequestBuilder`] immediately before
/// `.send()` so backends can inject per-provider auth headers (e.g.
/// OpenAI's `Authorization: Bearer` or a no-op for vLLM). It is called
/// once per retry attempt.
///
/// Retry semantics:
/// - [`JudgeError::Timeout`] / [`JudgeError::Transport`] → retried
/// - HTTP 5xx → retried
/// - HTTP 4xx → non-retriable (bad client config)
/// - Malformed response → surfaced as `ParseError`, non-retriable
pub(crate) async fn call_chat_completions<F>(
    client: &Client,
    url: &str,
    auth_fn: &F,
    body: &ChatRequest<'_>,
    timeout: Duration,
    retry_cfg: &JudgeRetryConfig,
    total_deadline: Option<Duration>,
) -> Result<ChatResponse, JudgeError>
where
    F: Fn(RequestBuilder) -> RequestBuilder,
{
    let body_bytes = retry::with_retry(
        retry_cfg.max_retries,
        retry_cfg.backoff_base_ms,
        total_deadline,
        || async {
            let req = client.post(url).json(body);
            let req = auth_fn(req);
            let response = tokio::time::timeout(timeout, req.send())
                .await
                .map_err(|_| JudgeError::Timeout {
                    elapsed_ms: timeout.as_millis() as u64,
                })?
                .map_err(|e| JudgeError::Transport(e.to_string()))?;

            let status = response.status();
            let retry_after_ms = parse_retry_after(response.headers());
            let bytes = response.bytes().await.unwrap_or_default();
            if !status.is_success() {
                return Err(JudgeError::BackendError {
                    status: status.as_u16(),
                    message: truncate_helper::truncate_for_error(
                        &String::from_utf8_lossy(&bytes),
                        512,
                    ),
                    retry_after_ms,
                });
            }
            Ok(bytes)
        },
    )
    .await?;

    serde_json::from_slice::<ChatResponse>(&body_bytes)
        .map_err(|e| JudgeError::ParseError(format!("chat response decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};

    #[test]
    fn parse_retry_after_missing_header_is_none() {
        let headers = HeaderMap::new();
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_delta_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
        assert_eq!(parse_retry_after(&headers), Some(5000));

        headers.clear();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(parse_retry_after(&headers), Some(120_000));

        headers.clear();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(parse_retry_after(&headers), Some(0));
    }

    #[test]
    fn parse_retry_after_malformed_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-number"));
        assert_eq!(parse_retry_after(&headers), None);

        headers.clear();
        headers.insert(RETRY_AFTER, HeaderValue::from_static(""));
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_http_date_future() {
        // A date 60 seconds in the future (formatted per RFC 2822 which
        // matches RFC 7231 IMF-fixdate).
        let future = Utc::now() + chrono::Duration::seconds(60);
        let date_str = future.to_rfc2822();
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_str(&date_str).unwrap());
        let parsed = parse_retry_after(&headers).expect("future date should parse");
        // Allow a few hundred ms of jitter from test execution time.
        assert!(parsed >= 55_000 && parsed <= 65_000, "got {parsed}ms");
    }

    #[test]
    fn parse_retry_after_past_http_date_is_none() {
        let past = Utc::now() - chrono::Duration::seconds(60);
        let date_str = past.to_rfc2822();
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_str(&date_str).unwrap());
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_handles_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("  30  "));
        assert_eq!(parse_retry_after(&headers), Some(30_000));
    }
}
