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

use llmtrace_core::JudgeRetryConfig;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::{retry, truncate_helper, JudgeError};

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
) -> Result<ChatResponse, JudgeError>
where
    F: Fn(RequestBuilder) -> RequestBuilder,
{
    let body_bytes =
        retry::with_retry(retry_cfg.max_retries, retry_cfg.backoff_base_ms, || async {
            let req = client.post(url).json(body);
            let req = auth_fn(req);
            let response = tokio::time::timeout(timeout, req.send())
                .await
                .map_err(|_| JudgeError::Timeout {
                    elapsed_ms: timeout.as_millis() as u64,
                })?
                .map_err(|e| JudgeError::Transport(e.to_string()))?;

            let status = response.status();
            let bytes = response.bytes().await.unwrap_or_default();
            if !status.is_success() {
                return Err(JudgeError::BackendError {
                    status: status.as_u16(),
                    message: truncate_helper::truncate_for_error(
                        &String::from_utf8_lossy(&bytes),
                        512,
                    ),
                });
            }
            Ok(bytes)
        })
        .await?;

    serde_json::from_slice::<ChatResponse>(&body_bytes)
        .map_err(|e| JudgeError::ParseError(format!("chat response decode: {e}")))
}
