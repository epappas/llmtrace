//! Core proxy request handler.
//!
//! Receives incoming HTTP requests, extracts LLM metadata, forwards them to
//! the upstream, captures the response, and spawns async background tasks for
//! trace storage and security analysis.

use crate::circuit_breaker::CircuitBreaker;
use crate::streaming::StreamingAccumulator;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, Response, StatusCode};
use bytes::Bytes;
use chrono::Utc;
use futures_util::StreamExt;
use llmtrace_core::{
    AnalysisContext, LLMProvider, ProxyConfig, SecurityAnalyzer, StorageBackend, TenantId,
    TraceEvent, TraceSpan,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Shared state threaded through axum handlers via [`State`].
pub struct AppState {
    /// Proxy configuration.
    pub config: ProxyConfig,
    /// HTTP client for forwarding requests upstream.
    pub client: Client,
    /// Storage backend for persisting traces.
    pub storage: Arc<dyn StorageBackend>,
    /// Security analyzer for scanning requests and responses.
    pub security: Arc<dyn SecurityAnalyzer>,
    /// Circuit breaker for the storage subsystem.
    pub storage_breaker: Arc<CircuitBreaker>,
    /// Circuit breaker for the security subsystem.
    pub security_breaker: Arc<CircuitBreaker>,
}

// ---------------------------------------------------------------------------
// Request body types (OpenAI-compatible subset)
// ---------------------------------------------------------------------------

/// Minimal representation of an OpenAI-compatible request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LLMRequestBody {
    #[serde(default)]
    model: String,
    #[serde(default)]
    messages: Vec<ChatMessage>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    stream: Option<bool>,
}

/// A single chat message in OpenAI format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the API key from the `Authorization` header (Bearer token).
fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Extract tenant ID from a custom `X-LLMTrace-Tenant-ID` header, or
/// derive one deterministically from the API key.
fn resolve_tenant(headers: &HeaderMap) -> TenantId {
    if let Some(raw) = headers.get("x-llmtrace-tenant-id") {
        if let Ok(s) = raw.to_str() {
            if let Ok(uuid) = Uuid::parse_str(s) {
                return TenantId(uuid);
            }
        }
    }
    // Fallback: derive from API key hash or generate a default
    if let Some(key) = extract_api_key(headers) {
        // Deterministic UUID v5 from the API key
        let ns = Uuid::NAMESPACE_URL;
        return TenantId(Uuid::new_v5(&ns, key.as_bytes()));
    }
    TenantId::default()
}

/// Concatenate all chat message contents into a single string for analysis.
fn messages_to_prompt_text(messages: &[ChatMessage]) -> String {
    messages
        .iter()
        .map(|m| format!("{}: {}", m.role, m.content))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the upstream URL for a given request path.
fn build_upstream_url(config: &ProxyConfig, path: &str, query: Option<&str>) -> String {
    let base = config.upstream_url.trim_end_matches('/');
    match query {
        Some(q) => format!("{base}{path}?{q}"),
        None => format!("{base}{path}"),
    }
}

// ---------------------------------------------------------------------------
// Main proxy handler
// ---------------------------------------------------------------------------

/// Axum handler that proxies LLM API requests to the upstream.
///
/// This is the core of the transparent proxy: it reads the request body,
/// extracts metadata, forwards the request, returns the response verbatim,
/// and spawns background tasks for trace capture and security analysis.
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response<Body> {
    let start_time = Utc::now();
    let trace_id = Uuid::new_v4();

    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().map(|q| q.to_string());
    let headers = req.headers().clone();
    let tenant_id = resolve_tenant(&headers);
    let _api_key = extract_api_key(&headers);

    debug!(
        %trace_id,
        %tenant_id,
        %method,
        %path,
        "Proxying request"
    );

    // Read the request body
    let body_bytes = match axum::body::to_bytes(
        req.into_body(),
        state.config.max_request_size_bytes as usize,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(%trace_id, "Failed to read request body: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "Failed to read request body");
        }
    };

    // Parse LLM metadata from the body (best-effort — don't fail if parse fails)
    let llm_body: Option<LLMRequestBody> = serde_json::from_slice(&body_bytes).ok();
    let model_name = llm_body
        .as_ref()
        .map(|b| b.model.clone())
        .unwrap_or_default();
    let prompt_text = llm_body
        .as_ref()
        .map(|b| {
            if !b.messages.is_empty() {
                messages_to_prompt_text(&b.messages)
            } else {
                b.prompt.clone().unwrap_or_default()
            }
        })
        .unwrap_or_default();

    // Build the upstream request
    let upstream_url = build_upstream_url(&state.config, &path, query.as_deref());

    let mut upstream_req = state.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST),
        &upstream_url,
    );

    // Forward all headers except `Host` (reqwest sets it from the URL)
    let mut forwarded_headers = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        if name == "host" {
            continue;
        }
        if let Ok(rname) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(rval) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                forwarded_headers.insert(rname, rval);
            }
        }
    }
    upstream_req = upstream_req.headers(forwarded_headers);
    upstream_req = upstream_req.body(body_bytes.to_vec());

    // Send the request upstream
    let upstream_response = match upstream_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!(%trace_id, "Upstream request failed: {}", e);
            return error_response(StatusCode::BAD_GATEWAY, "Upstream request failed");
        }
    };

    let response_status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();

    debug!(
        %trace_id,
        status = %response_status,
        "Upstream responded"
    );

    // Build the axum response, streaming the body through
    let response_stream = upstream_response.bytes_stream();

    // We'll collect the response body in the background for trace capture
    let (body_sender, body_receiver) = tokio::sync::mpsc::channel::<Result<Bytes, String>>(64);

    let response_body_stream = async_stream::stream! {
        let mut rx = tokio_stream::wrappers::ReceiverStream::new(body_receiver);
        while let Some(item) = rx.next().await {
            match item {
                Ok(bytes) => yield Ok::<_, std::io::Error>(bytes),
                Err(e) => yield Err(std::io::Error::other(e)),
            }
        }
    };

    // Detect whether this is a streaming request
    let is_streaming = llm_body.as_ref().and_then(|b| b.stream).unwrap_or(false);

    // Spawn a task that reads from the upstream stream and fans out to both
    // the client response and a background buffer for trace capture.
    let state_bg = Arc::clone(&state);
    let prompt_text_bg = prompt_text.clone();
    let model_name_bg = model_name.clone();
    tokio::spawn(async move {
        let mut stream = response_stream;
        let mut sse_accumulator = if is_streaming {
            Some(StreamingAccumulator::new())
        } else {
            None
        };
        let mut raw_collected = Vec::new();
        let mut ttft_ms: Option<u64> = None;

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    // For streaming responses, parse SSE chunks incrementally
                    if let Some(ref mut acc) = sse_accumulator {
                        let is_first_token = acc.process_chunk(&bytes);
                        if is_first_token {
                            let elapsed = Utc::now().signed_duration_since(start_time);
                            ttft_ms = Some(elapsed.num_milliseconds().max(0) as u64);
                        }
                    }
                    raw_collected.extend_from_slice(&bytes);
                    if body_sender.send(Ok(bytes)).await.is_err() {
                        // Client disconnected
                        break;
                    }
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    let _ = body_sender.send(Err(err_msg)).await;
                    break;
                }
            }
        }
        // body_sender is dropped here, closing the stream to the client.
        drop(body_sender);

        // Build the captured interaction with streaming metrics if applicable
        let (response_text, prompt_tokens, completion_tokens, total_tokens) =
            if let Some(acc) = sse_accumulator {
                (
                    acc.content.clone(),
                    acc.prompt_tokens(),
                    Some(acc.final_completion_tokens()),
                    acc.total_tokens(),
                )
            } else {
                (
                    String::from_utf8_lossy(&raw_collected).to_string(),
                    None,
                    None,
                    None,
                )
            };

        let captured = CapturedInteraction {
            trace_id,
            tenant_id,
            model_name: model_name_bg,
            prompt_text: prompt_text_bg,
            response_text,
            status_code: response_status.as_u16(),
            start_time,
            is_streaming,
            time_to_first_token_ms: ttft_ms,
            prompt_tokens,
            completion_tokens,
            total_tokens,
        };

        // --- Async trace capture ---
        spawn_trace_capture(&state_bg, &captured).await;

        // --- Async security analysis ---
        spawn_security_analysis(&state_bg, &captured).await;
    });

    // Build and return the response to the client
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(response_status.as_u16()).unwrap_or(StatusCode::OK));

    // Copy response headers
    for (name, value) in response_headers.iter() {
        if let Ok(hname) = axum::http::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(hval) = axum::http::HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(hname, hval);
            }
        }
    }

    builder
        .body(Body::from_stream(response_body_stream))
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build response",
            )
        })
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

/// Context for a captured request/response pair, used by background tasks.
struct CapturedInteraction {
    trace_id: Uuid,
    tenant_id: TenantId,
    model_name: String,
    prompt_text: String,
    response_text: String,
    status_code: u16,
    start_time: chrono::DateTime<Utc>,
    /// Whether this was a streaming (SSE) response.
    is_streaming: bool,
    /// Time to first token in milliseconds (streaming only).
    time_to_first_token_ms: Option<u64>,
    /// Prompt tokens (from provider usage data, if reported).
    prompt_tokens: Option<u32>,
    /// Completion tokens (observed or provider-reported).
    completion_tokens: Option<u32>,
    /// Total tokens (from provider usage data, if reported).
    total_tokens: Option<u32>,
}

/// Spawn a background task that stores a trace event (never blocks the response).
async fn spawn_trace_capture(state: &Arc<AppState>, captured: &CapturedInteraction) {
    if !state.config.enable_trace_storage {
        return;
    }
    if !state.storage_breaker.allow().await {
        debug!(trace_id = %captured.trace_id, "Storage circuit breaker open — skipping trace capture");
        return;
    }

    let storage = Arc::clone(&state.storage);
    let breaker = Arc::clone(&state.storage_breaker);
    let trace_id = captured.trace_id;
    let tenant_id = captured.tenant_id;
    let model_name = captured.model_name.clone();
    let prompt_text = captured.prompt_text.clone();
    let response_text = captured.response_text.clone();
    let status_code = captured.status_code;
    let start_time = captured.start_time;

    let is_streaming = captured.is_streaming;
    let ttft_ms = captured.time_to_first_token_ms;
    let prompt_tokens = captured.prompt_tokens;
    let completion_tokens = captured.completion_tokens;
    let total_tokens = captured.total_tokens;

    tokio::spawn(async move {
        let operation = if is_streaming {
            "chat_completion_stream"
        } else {
            "chat_completion"
        };

        let span = TraceSpan::new(
            trace_id,
            tenant_id,
            operation.to_string(),
            LLMProvider::OpenAI, // default; future loops will detect provider
            model_name,
            prompt_text,
        )
        .finish_with_response(response_text);

        let mut completed_span = span;
        completed_span.status_code = Some(status_code);
        completed_span.prompt_tokens = prompt_tokens;
        completed_span.completion_tokens = completion_tokens;
        completed_span.total_tokens = total_tokens;
        completed_span.time_to_first_token_ms = ttft_ms;

        let end_time = Utc::now();
        let duration = end_time.signed_duration_since(start_time);
        completed_span.duration_ms = Some(duration.num_milliseconds().max(0) as u64);

        let trace = TraceEvent {
            trace_id,
            tenant_id,
            spans: vec![completed_span],
            created_at: start_time,
        };

        match storage.store_trace(&trace).await {
            Ok(()) => {
                breaker.record_success().await;
                info!(%trace_id, "Trace stored successfully");
            }
            Err(e) => {
                breaker.record_failure().await;
                error!(%trace_id, "Failed to store trace: {}", e);
            }
        }
    });
}

/// Spawn a background task that performs security analysis (never blocks the response).
async fn spawn_security_analysis(state: &Arc<AppState>, captured: &CapturedInteraction) {
    if !state.config.enable_security_analysis {
        return;
    }
    if !state.security_breaker.allow().await {
        debug!(trace_id = %captured.trace_id, "Security circuit breaker open — skipping analysis");
        return;
    }

    let security = Arc::clone(&state.security);
    let breaker = Arc::clone(&state.security_breaker);
    let trace_id = captured.trace_id;
    let tenant_id = captured.tenant_id;
    let model_name = captured.model_name.clone();
    let prompt_text = captured.prompt_text.clone();
    let response_text = captured.response_text.clone();

    tokio::spawn(async move {
        let context = AnalysisContext {
            tenant_id,
            trace_id,
            span_id: Uuid::new_v4(),
            provider: LLMProvider::OpenAI,
            model_name,
            parameters: std::collections::HashMap::new(),
        };

        let result = security
            .analyze_interaction(&prompt_text, &response_text, &context)
            .await;

        match result {
            Ok(findings) => {
                breaker.record_success().await;
                if findings.is_empty() {
                    debug!(%trace_id, "Security analysis: no findings");
                } else {
                    info!(
                        %trace_id,
                        finding_count = findings.len(),
                        "Security findings detected"
                    );
                }
            }
            Err(e) => {
                breaker.record_failure().await;
                error!(%trace_id, "Security analysis failed: {}", e);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

/// Health check handler returning a JSON status object.
pub async fn health_handler(State(state): State<Arc<AppState>>) -> Response<Body> {
    let storage_ok = state.storage.health_check().await.is_ok();
    let security_ok = state.security.health_check().await.is_ok();
    let storage_circuit = state.storage_breaker.state().await;
    let security_circuit = state.security_breaker.state().await;

    let body = serde_json::json!({
        "status": if storage_ok && security_ok { "healthy" } else { "degraded" },
        "storage": {
            "healthy": storage_ok,
            "circuit_breaker": format!("{:?}", storage_circuit),
        },
        "security": {
            "healthy": security_ok,
            "circuit_breaker": format!("{:?}", security_circuit),
        },
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Build a JSON error response.
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "proxy_error",
        }
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_api_key_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-test-key-123".parse().unwrap());
        assert_eq!(
            extract_api_key(&headers),
            Some("sk-test-key-123".to_string())
        );
    }

    #[test]
    fn test_extract_api_key_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_api_key(&headers), None);
    }

    #[test]
    fn test_extract_api_key_no_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_eq!(extract_api_key(&headers), None);
    }

    #[test]
    fn test_resolve_tenant_from_header() {
        let mut headers = HeaderMap::new();
        let tenant_uuid = Uuid::new_v4();
        headers.insert(
            "x-llmtrace-tenant-id",
            tenant_uuid.to_string().parse().unwrap(),
        );
        let tenant = resolve_tenant(&headers);
        assert_eq!(tenant.0, tenant_uuid);
    }

    #[test]
    fn test_resolve_tenant_from_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-my-key".parse().unwrap());
        let tenant = resolve_tenant(&headers);
        // Should produce a deterministic UUID v5
        let expected = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"sk-my-key");
        assert_eq!(tenant.0, expected);
    }

    #[test]
    fn test_resolve_tenant_fallback() {
        let headers = HeaderMap::new();
        let tenant = resolve_tenant(&headers);
        // Should produce a valid (non-nil) UUID
        assert_ne!(tenant.0, Uuid::nil());
    }

    #[test]
    fn test_build_upstream_url_no_query() {
        let config = ProxyConfig {
            upstream_url: "http://localhost:11434".to_string(),
            ..ProxyConfig::default()
        };
        assert_eq!(
            build_upstream_url(&config, "/v1/chat/completions", None),
            "http://localhost:11434/v1/chat/completions"
        );
    }

    #[test]
    fn test_build_upstream_url_with_query() {
        let config = ProxyConfig {
            upstream_url: "http://localhost:11434/".to_string(),
            ..ProxyConfig::default()
        };
        assert_eq!(
            build_upstream_url(&config, "/v1/models", Some("format=json")),
            "http://localhost:11434/v1/models?format=json"
        );
    }

    #[test]
    fn test_messages_to_prompt_text() {
        let msgs = vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You are helpful.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "Hello!".to_string(),
            },
        ];
        let text = messages_to_prompt_text(&msgs);
        assert!(text.contains("system: You are helpful."));
        assert!(text.contains("user: Hello!"));
    }

    #[test]
    fn test_messages_to_prompt_text_empty() {
        let text = messages_to_prompt_text(&[]);
        assert!(text.is_empty());
    }

    #[test]
    fn test_error_response_format() {
        let resp = error_response(StatusCode::BAD_GATEWAY, "upstream down");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
