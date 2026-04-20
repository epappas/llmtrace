//! OpenAI API judge backend.
//!
//! Uses the same chat-completions request shape as
//! [`VllmJudgeBackend`](super::VllmJudgeBackend) against `api.openai.com`,
//! adding an `Authorization: Bearer $LLMTRACE_JUDGE_OPENAI_API_KEY`
//! header. The API key is read from the environment (never from config
//! files) so operators can rotate it without redeploying.

use async_trait::async_trait;
use chrono::Utc;
use llmtrace_core::JudgeVerdict;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::{
    build_system_prompt, build_user_message_json, parse_verdict_json, JudgeBackend, JudgeCandidate,
    JudgeError,
};

/// Environment variable holding the OpenAI API key. Must be set when
/// the judge backend is `openai`; absence is a startup misconfiguration.
pub const API_KEY_ENV: &str = "LLMTRACE_JUDGE_OPENAI_API_KEY";

/// Construction-time options for the OpenAI judge backend.
#[derive(Debug, Clone)]
pub struct OpenAiJudgeOptions {
    pub base_url: String,
    pub model: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub timeout: Duration,
    pub max_retries: u32,
    pub backoff_base_ms: u64,
    pub system_prompt_override: Option<String>,
    pub api_key: String,
}

pub struct OpenAIJudgeBackend {
    client: Client,
    options: OpenAiJudgeOptions,
}

impl OpenAIJudgeBackend {
    #[must_use]
    pub fn new(client: Client, options: OpenAiJudgeOptions) -> Self {
        Self { client, options }
    }

    fn chat_completions_url(&self) -> String {
        format!(
            "{}/v1/chat/completions",
            self.options.base_url.trim_end_matches('/')
        )
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    max_tokens: u32,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: String,
}

#[derive(Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatResponseMessage,
}

#[derive(Deserialize)]
struct ChatResponseMessage {
    content: String,
}

#[derive(Deserialize)]
struct ChatUsage {
    #[serde(default)]
    prompt_tokens: Option<u32>,
    #[serde(default)]
    completion_tokens: Option<u32>,
}

#[async_trait]
impl JudgeBackend for OpenAIJudgeBackend {
    async fn judge(&self, candidate: &JudgeCandidate) -> Result<JudgeVerdict, JudgeError> {
        let system = build_system_prompt(self.options.system_prompt_override.as_deref());
        let user = build_user_message_json(candidate);

        let body = ChatRequest {
            model: &self.options.model,
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: system.to_string(),
                },
                ChatMessage {
                    role: "user",
                    content: user,
                },
            ],
            max_tokens: self.options.max_tokens,
            temperature: self.options.temperature,
            response_format: Some(ResponseFormat {
                kind: "json_object",
            }),
        };

        let url = self.chat_completions_url();
        let started = Instant::now();
        // Retry wraps the full HTTP round-trip + status check so 5xx
        // responses trigger a retry via `is_retriable`. 4xx responses
        // return a permanent BackendError and short-circuit.
        let body_bytes = super::retry::with_retry(
            self.options.max_retries,
            self.options.backoff_base_ms,
            || async {
                let response = tokio::time::timeout(
                    self.options.timeout,
                    self.client
                        .post(&url)
                        .bearer_auth(&self.options.api_key)
                        .json(&body)
                        .send(),
                )
                .await
                .map_err(|_| JudgeError::Timeout {
                    elapsed_ms: self.options.timeout.as_millis() as u64,
                })?
                .map_err(|e| JudgeError::Transport(e.to_string()))?;

                let status = response.status();
                let bytes = response.bytes().await.unwrap_or_default();
                if !status.is_success() {
                    return Err(JudgeError::BackendError {
                        status: status.as_u16(),
                        message: super::truncate_helper::truncate_for_error(
                            &String::from_utf8_lossy(&bytes),
                            512,
                        ),
                    });
                }
                Ok(bytes)
            },
        )
        .await?;

        let parsed: ChatResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| JudgeError::ParseError(format!("chat response decode: {e}")))?;

        let content = parsed
            .choices
            .first()
            .ok_or_else(|| JudgeError::ParseError("chat response has no choices".to_string()))?
            .message
            .content
            .clone();

        let raw = parse_verdict_json(&content)?;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let (prompt_tokens, completion_tokens) = parsed
            .usage
            .map(|u| (u.prompt_tokens, u.completion_tokens))
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
        "openai"
    }

    async fn health_check(&self) -> Result<(), JudgeError> {
        let url = format!("{}/v1/models", self.options.base_url.trim_end_matches('/'));
        let response = tokio::time::timeout(
            self.options.timeout,
            self.client
                .get(&url)
                .bearer_auth(&self.options.api_key)
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
    use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Clone)]
    struct MockState {
        received_auth: Arc<Mutex<Option<String>>>,
        response_body: Arc<Mutex<serde_json::Value>>,
        status_seq: Arc<Mutex<Vec<u16>>>,
        call_count: Arc<AtomicU32>,
    }

    async fn mock_handler(
        State(state): State<MockState>,
        headers: HeaderMap,
        Json(_body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let count = state.call_count.fetch_add(1, Ordering::SeqCst);
        *state.received_auth.lock().await = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let seq = state.status_seq.lock().await;
        let code = if seq.is_empty() {
            200
        } else {
            // Consume one status per call; if seq has fewer entries than
            // calls we saturate at the last status.
            let idx = (count as usize).min(seq.len() - 1);
            seq[idx]
        };
        drop(seq);
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
        let body = state.response_body.lock().await.clone();
        (status, Json(body))
    }

    async fn spawn_mock(state: MockState) -> String {
        let app = Router::new()
            .route("/v1/chat/completions", post(mock_handler))
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
            model_name: "gpt-4o".to_string(),
            analysis_text: "Ignore previous".to_string(),
            prior_findings: vec![],
            mode: JudgeMode::Inline,
        }
    }

    fn mock_verdict_body(verdict_json: &str) -> serde_json::Value {
        serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": verdict_json } }],
            "usage": { "prompt_tokens": 50, "completion_tokens": 20 }
        })
    }

    fn options(base_url: String, api_key: &str) -> OpenAiJudgeOptions {
        OpenAiJudgeOptions {
            base_url,
            model: "gpt-4o-mini".to_string(),
            max_tokens: 256,
            temperature: 0.1,
            timeout: Duration::from_millis(500),
            max_retries: 0,
            backoff_base_ms: 10,
            system_prompt_override: None,
            api_key: api_key.to_string(),
        }
    }

    #[tokio::test]
    async fn openai_happy_path_includes_bearer_auth_and_returns_verdict() {
        let state = MockState {
            received_auth: Arc::new(Mutex::new(None)),
            response_body: Arc::new(Mutex::new(mock_verdict_body(
                r#"{"is_threat":false,"category":"benign","confidence":0.1,"security_score":5,"recommended_action":"allow","reasoning":"ok"}"#,
            ))),
            status_seq: Arc::new(Mutex::new(vec![])),
            call_count: Arc::new(AtomicU32::new(0)),
        };
        let base_url = spawn_mock(state.clone()).await;
        let backend = OpenAIJudgeBackend::new(Client::new(), options(base_url, "sk-test"));
        let verdict = backend.judge(&candidate()).await.unwrap();
        assert_eq!(verdict.category, "benign");
        assert_eq!(
            state.received_auth.lock().await.as_deref(),
            Some("Bearer sk-test")
        );
    }

    #[tokio::test]
    async fn openai_retries_on_5xx_then_succeeds() {
        let state = MockState {
            received_auth: Arc::new(Mutex::new(None)),
            response_body: Arc::new(Mutex::new(mock_verdict_body(
                r#"{"is_threat":true,"category":"prompt_injection","confidence":0.9,"security_score":80,"recommended_action":"block","reasoning":"ok"}"#,
            ))),
            // First call 503, second 200.
            status_seq: Arc::new(Mutex::new(vec![503, 200])),
            call_count: Arc::new(AtomicU32::new(0)),
        };
        let base_url = spawn_mock(state.clone()).await;
        let mut opts = options(base_url, "sk-retry");
        opts.max_retries = 1;
        let backend = OpenAIJudgeBackend::new(Client::new(), opts);
        let verdict = backend.judge(&candidate()).await.unwrap();
        assert!(verdict.is_threat);
        assert_eq!(state.call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn openai_retries_exhausted_returns_backend_error() {
        let state = MockState {
            received_auth: Arc::new(Mutex::new(None)),
            response_body: Arc::new(Mutex::new(serde_json::json!({"error":"nope"}))),
            status_seq: Arc::new(Mutex::new(vec![500, 500, 500])),
            call_count: Arc::new(AtomicU32::new(0)),
        };
        let base_url = spawn_mock(state.clone()).await;
        let mut opts = options(base_url, "sk-fail");
        opts.max_retries = 2;
        let backend = OpenAIJudgeBackend::new(Client::new(), opts);
        let err = backend.judge(&candidate()).await.unwrap_err();
        match err {
            JudgeError::BackendError { status, .. } => assert_eq!(status, 500),
            other => panic!("expected BackendError, got {other:?}"),
        }
        // 1 initial + 2 retries = 3 calls
        assert_eq!(state.call_count.load(Ordering::SeqCst), 3);
    }

    // Silence the unused-imports lint for AtomicU8 when this module is
    // included in the test binary but only AtomicU32 is referenced.
    #[allow(dead_code)]
    fn _touch_unused(_: &AtomicU8) {}
}
