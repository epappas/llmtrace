//! Anthropic Messages API judge backend.
//!
//! Uses the Anthropic Messages API (`/v1/messages`) with `system` as a
//! top-level field and a single user message carrying the candidate
//! JSON envelope. The API key is read from
//! `LLMTRACE_JUDGE_ANTHROPIC_API_KEY`.

use async_trait::async_trait;
use chrono::Utc;
use llmtrace_core::JudgeVerdict;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::{
    build_system_prompt, build_user_message_json, parse_verdict_json, JudgeBackend, JudgeCandidate,
    JudgeError,
};

/// Environment variable holding the Anthropic API key.
pub const API_KEY_ENV: &str = "LLMTRACE_JUDGE_ANTHROPIC_API_KEY";

/// Anthropic Messages API version header value.
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Construction-time options for the Anthropic judge backend.
///
/// `Debug` is implemented manually to redact `api_key`. Do not add a
/// `derive(Debug)` here: any future `tracing::debug!(?options, ...)`
/// or panic message that formats this struct would leak the key.
#[derive(Clone)]
pub struct AnthropicJudgeOptions {
    pub base_url: String,
    pub model: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub timeout: Duration,
    pub max_retries: u32,
    pub backoff_base_ms: u64,
    /// Issue #73: total end-to-end deadline covering all retries + backoff.
    pub total_deadline: Option<Duration>,
    pub system_prompt_override: Option<String>,
    pub api_key: String,
}

impl fmt::Debug for AnthropicJudgeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicJudgeOptions")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("max_tokens", &self.max_tokens)
            .field("temperature", &self.temperature)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("backoff_base_ms", &self.backoff_base_ms)
            .field(
                "system_prompt_override",
                &self.system_prompt_override.as_ref().map(|_| "<set>"),
            )
            .field("api_key", &"<redacted>")
            .finish()
    }
}

pub struct AnthropicJudgeBackend {
    client: Client,
    options: AnthropicJudgeOptions,
}

impl AnthropicJudgeBackend {
    #[must_use]
    pub fn new(client: Client, options: AnthropicJudgeOptions) -> Self {
        Self { client, options }
    }

    fn messages_url(&self) -> String {
        format!(
            "{}/v1/messages",
            self.options.base_url.trim_end_matches('/')
        )
    }
}

#[derive(Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    temperature: f32,
    system: &'a str,
    messages: Vec<UserMessage<'a>>,
}

#[derive(Serialize)]
struct UserMessage<'a> {
    role: &'a str,
    content: String,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
    #[serde(default)]
    usage: Option<MessagesUsage>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct MessagesUsage {
    #[serde(default)]
    input_tokens: Option<u32>,
    #[serde(default)]
    output_tokens: Option<u32>,
}

#[async_trait]
impl JudgeBackend for AnthropicJudgeBackend {
    async fn judge(&self, candidate: &JudgeCandidate) -> Result<JudgeVerdict, JudgeError> {
        let system = build_system_prompt(self.options.system_prompt_override.as_deref());
        let user = build_user_message_json(candidate);

        let body = MessagesRequest {
            model: &self.options.model,
            max_tokens: self.options.max_tokens,
            temperature: self.options.temperature,
            system,
            messages: vec![UserMessage {
                role: "user",
                content: user,
            }],
        };

        let url = self.messages_url();
        let started = Instant::now();
        let body_bytes = super::retry::with_retry(
            self.options.max_retries,
            self.options.backoff_base_ms,
            self.options.total_deadline,
            || async {
                let response = tokio::time::timeout(
                    self.options.timeout,
                    self.client
                        .post(&url)
                        .header("x-api-key", &self.options.api_key)
                        .header("anthropic-version", ANTHROPIC_API_VERSION)
                        .json(&body)
                        .send(),
                )
                .await
                .map_err(|_| JudgeError::Timeout {
                    elapsed_ms: self.options.timeout.as_millis() as u64,
                })?
                .map_err(|e| JudgeError::Transport(e.to_string()))?;

                let status = response.status();
                let retry_after_ms = super::openai_compat::parse_retry_after(response.headers());
                let bytes = response.bytes().await.unwrap_or_default();
                if !status.is_success() {
                    return Err(JudgeError::BackendError {
                        status: status.as_u16(),
                        message: super::truncate_helper::truncate_for_error(
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

        let parsed: MessagesResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| JudgeError::ParseError(format!("messages response decode: {e}")))?;

        // Extract the first text block. Anthropic returns an array of
        // content blocks; in non-streaming mode with JSON output the
        // first block is a `text` block whose content is our expected
        // JSON verdict.
        let text = parsed
            .content
            .iter()
            .find(|b| b.kind == "text")
            .and_then(|b| b.text.clone())
            .ok_or_else(|| {
                JudgeError::ParseError("anthropic response has no text block".to_string())
            })?;

        let raw = parse_verdict_json(&text)?;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let (prompt_tokens, completion_tokens) = parsed
            .usage
            .map(|u| (u.input_tokens, u.output_tokens))
            .unwrap_or((None, None));

        Ok(JudgeVerdict {
            id: Uuid::new_v4(),
            trace_id: candidate.trace_id,
            tenant_id: candidate.tenant_id,
            is_threat: raw.is_threat,
            category: raw.category,
            confidence: raw.confidence,
            security_score: raw.security_score,
            recommended_action: raw.recommended_action,
            reasoning: raw.reasoning,
            mode: candidate.mode,
            model_used: self.options.model.clone(),
            latency_ms: elapsed_ms,
            prompt_tokens,
            completion_tokens,
            created_at: Utc::now(),
        })
    }

    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn health_check(&self) -> Result<(), JudgeError> {
        // Anthropic does not publish a cheap /v1/models equivalent.
        // A ping-style request with minimal max_tokens is the
        // standard smoke test; we issue that against the configured
        // model.
        let body = serde_json::json!({
            "model": self.options.model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "ping"}]
        });
        let url = self.messages_url();
        let response = tokio::time::timeout(
            self.options.timeout,
            self.client
                .post(&url)
                .header("x-api-key", &self.options.api_key)
                .header("anthropic-version", ANTHROPIC_API_VERSION)
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| JudgeError::Timeout {
            elapsed_ms: self.options.timeout.as_millis() as u64,
        })?
        .map_err(|e| JudgeError::Transport(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(JudgeError::BackendError {
                status: response.status().as_u16(),
                message: "health check non-2xx".to_string(),
                retry_after_ms: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use llmtrace_core::{JudgeMode, TenantId};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn debug_impl_redacts_api_key() {
        const SECRET: &str = "ak-super-secret-anthropic-key-9876543210";
        let opts = AnthropicJudgeOptions {
            base_url: "https://api.anthropic.com".to_string(),
            model: "claude-3-5-haiku-20241022".to_string(),
            max_tokens: 256,
            temperature: 0.1,
            timeout: Duration::from_millis(500),
            max_retries: 0,
            backoff_base_ms: 10,
            total_deadline: None,
            system_prompt_override: None,
            api_key: SECRET.to_string(),
        };
        let rendered = format!("{opts:?}");
        assert!(
            !rendered.contains(SECRET),
            "api_key leaked in Debug output: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("claude-3-5-haiku-20241022"));
    }

    #[derive(Clone)]
    struct MockState {
        received_api_key: Arc<Mutex<Option<String>>>,
        received_version: Arc<Mutex<Option<String>>>,
        response_body: Arc<Mutex<serde_json::Value>>,
        status_seq: Arc<Mutex<Vec<u16>>>,
        call_count: Arc<AtomicU32>,
    }

    async fn mock_handler(
        State(state): State<MockState>,
        headers: HeaderMap,
        Json(_body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let n = state.call_count.fetch_add(1, Ordering::SeqCst);
        *state.received_api_key.lock().await = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        *state.received_version.lock().await = headers
            .get("anthropic-version")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let seq = state.status_seq.lock().await;
        let code = if seq.is_empty() {
            200
        } else {
            seq[(n as usize).min(seq.len() - 1)]
        };
        drop(seq);
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
        let body = state.response_body.lock().await.clone();
        (status, Json(body))
    }

    async fn spawn_mock(state: MockState) -> String {
        let app = Router::new()
            .route("/v1/messages", post(mock_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn candidate() -> JudgeCandidate {
        JudgeCandidate {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            model_name: "claude-3-5".to_string(),
            analysis_text: "harmless".to_string(),
            prior_findings: vec![],
            mode: JudgeMode::Async,
        }
    }

    fn mock_messages_body(verdict_json: &str) -> serde_json::Value {
        serde_json::json!({
            "content": [{ "type": "text", "text": verdict_json }],
            "usage": { "input_tokens": 80, "output_tokens": 30 }
        })
    }

    fn options(base_url: String, api_key: &str) -> AnthropicJudgeOptions {
        AnthropicJudgeOptions {
            base_url,
            model: "claude-3-5-haiku-20241022".to_string(),
            max_tokens: 256,
            temperature: 0.1,
            timeout: Duration::from_millis(500),
            max_retries: 0,
            backoff_base_ms: 10,
            total_deadline: None,
            system_prompt_override: None,
            api_key: api_key.to_string(),
        }
    }

    #[tokio::test]
    async fn anthropic_happy_path_includes_api_key_and_version_headers() {
        let state = MockState {
            received_api_key: Arc::new(Mutex::new(None)),
            received_version: Arc::new(Mutex::new(None)),
            response_body: Arc::new(Mutex::new(mock_messages_body(
                r#"{"is_threat":false,"category":"benign","confidence":0.1,"security_score":5,"recommended_action":"allow","reasoning":"ok"}"#,
            ))),
            status_seq: Arc::new(Mutex::new(vec![])),
            call_count: Arc::new(AtomicU32::new(0)),
        };
        let base_url = spawn_mock(state.clone()).await;
        let backend = AnthropicJudgeBackend::new(Client::new(), options(base_url, "ak-test"));
        let v = backend.judge(&candidate()).await.unwrap();
        assert_eq!(v.category, "benign");
        assert_eq!(v.prompt_tokens, Some(80));
        assert_eq!(v.completion_tokens, Some(30));
        assert_eq!(
            state.received_api_key.lock().await.as_deref(),
            Some("ak-test")
        );
        assert_eq!(
            state.received_version.lock().await.as_deref(),
            Some("2023-06-01")
        );
    }

    #[tokio::test]
    async fn anthropic_retries_on_5xx_then_succeeds() {
        let state = MockState {
            received_api_key: Arc::new(Mutex::new(None)),
            received_version: Arc::new(Mutex::new(None)),
            response_body: Arc::new(Mutex::new(mock_messages_body(
                r#"{"is_threat":true,"category":"jailbreak","confidence":0.88,"security_score":75,"recommended_action":"block","reasoning":"ok"}"#,
            ))),
            status_seq: Arc::new(Mutex::new(vec![529, 200])),
            call_count: Arc::new(AtomicU32::new(0)),
        };
        let base_url = spawn_mock(state.clone()).await;
        let mut opts = options(base_url, "ak-retry");
        opts.max_retries = 1;
        let backend = AnthropicJudgeBackend::new(Client::new(), opts);
        let v = backend.judge(&candidate()).await.unwrap();
        assert!(v.is_threat);
        assert_eq!(v.category, "jailbreak");
        assert_eq!(state.call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn anthropic_4xx_not_retried() {
        let state = MockState {
            received_api_key: Arc::new(Mutex::new(None)),
            received_version: Arc::new(Mutex::new(None)),
            response_body: Arc::new(Mutex::new(serde_json::json!({"error":"bad key"}))),
            status_seq: Arc::new(Mutex::new(vec![401, 401, 401])),
            call_count: Arc::new(AtomicU32::new(0)),
        };
        let base_url = spawn_mock(state.clone()).await;
        let mut opts = options(base_url, "ak-bad");
        opts.max_retries = 3;
        let backend = AnthropicJudgeBackend::new(Client::new(), opts);
        let err = backend.judge(&candidate()).await.unwrap_err();
        match err {
            JudgeError::BackendError { status, .. } => assert_eq!(status, 401),
            other => panic!("expected BackendError, got {other:?}"),
        }
        // 4xx is not retriable -> exactly 1 call
        assert_eq!(state.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn anthropic_missing_text_block_is_parse_error() {
        let state = MockState {
            received_api_key: Arc::new(Mutex::new(None)),
            received_version: Arc::new(Mutex::new(None)),
            response_body: Arc::new(Mutex::new(serde_json::json!({
                "content": [{"type": "image", "source": "..."}]
            }))),
            status_seq: Arc::new(Mutex::new(vec![])),
            call_count: Arc::new(AtomicU32::new(0)),
        };
        let base_url = spawn_mock(state).await;
        let backend = AnthropicJudgeBackend::new(Client::new(), options(base_url, "ak"));
        let err = backend.judge(&candidate()).await.unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }
}
