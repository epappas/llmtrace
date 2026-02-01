//! Core proxy request handler.
//!
//! Receives incoming HTTP requests, extracts LLM metadata, forwards them to
//! the upstream, captures the response, and spawns async background tasks for
//! trace storage and security analysis.

use crate::circuit_breaker::CircuitBreaker;
use crate::cost::CostEstimator;
use crate::provider::{self, ParsedResponse};
use crate::streaming::{StreamingAccumulator, StreamingSecurityMonitor};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, Response, StatusCode};
use bytes::Bytes;
use chrono::Utc;
use futures_util::StreamExt;
use llmtrace_core::{
    AgentAction, AnalysisContext, LLMProvider, ProxyConfig, SecurityAnalyzer, SecurityFinding,
    Storage, TenantId, TraceEvent, TraceSpan,
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
    /// Composite storage (traces, metadata, cache).
    pub storage: Storage,
    /// Security analyzer for scanning requests and responses.
    pub security: Arc<dyn SecurityAnalyzer>,
    /// Circuit breaker for the storage subsystem.
    pub storage_breaker: Arc<CircuitBreaker>,
    /// Circuit breaker for the security subsystem.
    pub security_breaker: Arc<CircuitBreaker>,
    /// Cost estimator for computing per-request cost in USD.
    pub cost_estimator: CostEstimator,
    /// Alert engine for webhook notifications (`None` if alerts are disabled).
    pub alert_engine: Option<crate::alerts::AlertEngine>,
    /// Cost cap tracker (`None` if cost caps are disabled).
    pub cost_tracker: Option<crate::cost_caps::CostTracker>,
    /// Anomaly detector (`None` if anomaly detection is disabled).
    pub anomaly_detector: Option<crate::anomaly::AnomalyDetector>,
    /// In-memory store for compliance reports.
    pub report_store: crate::compliance::ReportStore,
}

impl AppState {
    /// Convenience accessor for the metadata repository.
    pub fn metadata(&self) -> &dyn llmtrace_core::MetadataRepository {
        self.storage.metadata.as_ref()
    }
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

/// Extract the agent ID from the `X-LLMTrace-Agent-ID` header.
pub(crate) fn extract_agent_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-llmtrace-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

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
pub(crate) fn resolve_tenant(headers: &HeaderMap) -> TenantId {
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
    let agent_id = extract_agent_id(&headers);
    let detected_provider = provider::detect_provider(&headers, &state.config.upstream_url, &path);

    // Auto-create tenant on first request (best-effort, non-blocking).
    {
        let state_ac = Arc::clone(&state);
        let api_key_prefix = _api_key
            .as_deref()
            .map(|k| {
                let prefix_len = k.len().min(8);
                format!("key-{}", &k[..prefix_len])
            })
            .unwrap_or_else(|| format!("auto-{}", tenant_id.0));
        tokio::spawn(async move {
            crate::tenant_api::ensure_tenant_exists(&state_ac, tenant_id, &api_key_prefix).await;
        });
    }

    debug!(
        %trace_id,
        %tenant_id,
        %method,
        %path,
        provider = ?detected_provider,
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

    // --- Pre-request cost cap enforcement ---
    if let Some(ref tracker) = state.cost_tracker {
        // Token cap (best-effort from request body — max_tokens field)
        let req_max_tokens: Option<u32> = llm_body
            .as_ref()
            .and_then(|b| serde_json::to_value(b).ok())
            .and_then(|v| v.get("max_tokens").and_then(|t| t.as_u64()))
            .map(|t| t as u32);

        let token_result = tracker.check_token_caps(
            agent_id.as_deref(),
            None,           // prompt tokens unknown pre-request
            req_max_tokens, // requested max completion tokens
            None,
        );
        if let crate::cost_caps::CapCheckResult::TokenCapExceeded { reason } = token_result {
            warn!(%trace_id, %reason, "Token cap exceeded — rejecting request");
            return cap_rejected_response(&reason, 0);
        }

        // Budget cap
        let budget_result = tracker
            .check_budget_caps(tenant_id, agent_id.as_deref())
            .await;
        match budget_result {
            crate::cost_caps::CapCheckResult::Rejected {
                window,
                current_spend_usd,
                hard_limit_usd,
                retry_after_secs,
            } => {
                let msg = format!(
                    "{window} budget exceeded: ${current_spend_usd:.4} / ${hard_limit_usd:.2}"
                );
                warn!(%trace_id, %msg, "Budget cap exceeded — rejecting request");
                return cap_rejected_response(&msg, retry_after_secs);
            }
            crate::cost_caps::CapCheckResult::AllowedWithWarning { warnings } => {
                for w in &warnings {
                    info!(%trace_id, warning = %w, "Cost cap warning");
                }
                // Fire alerts for soft caps / 80% threshold
                if let Some(ref engine) = state.alert_engine {
                    let alert_findings: Vec<llmtrace_core::SecurityFinding> = warnings
                        .iter()
                        .map(|w| {
                            llmtrace_core::SecurityFinding::new(
                                llmtrace_core::SecuritySeverity::Medium,
                                "cost_cap_warning".to_string(),
                                w.clone(),
                                0.9,
                            )
                            .with_alert_required(true)
                        })
                        .collect();
                    engine.check_and_alert(trace_id, tenant_id, &alert_findings);
                }
            }
            _ => {}
        }
    }

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
    let provider_bg = detected_provider;
    let agent_id_bg = agent_id;
    tokio::spawn(async move {
        let mut stream = response_stream;
        let mut sse_accumulator = if is_streaming {
            Some(StreamingAccumulator::new())
        } else {
            None
        };
        // Initialise the streaming security monitor (only for SSE streams
        // when streaming analysis is enabled).
        let mut streaming_monitor = if is_streaming {
            StreamingSecurityMonitor::new(&state_bg.config.streaming_analysis)
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

                        // --- Real-time streaming security analysis ---
                        if let Some(ref mut monitor) = streaming_monitor {
                            if monitor.should_analyze(acc.completion_token_count) {
                                let new_findings = monitor
                                    .analyze_incremental(&acc.content, acc.completion_token_count);
                                // Fire mid-stream alerts for critical findings
                                if !new_findings.is_empty() {
                                    info!(
                                        %trace_id,
                                        count = new_findings.len(),
                                        tokens = acc.completion_token_count,
                                        "Streaming security findings detected mid-stream"
                                    );
                                    if let Some(ref engine) = state_bg.alert_engine {
                                        engine.check_and_alert(trace_id, tenant_id, &new_findings);
                                    }
                                }
                            }
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

        // Run one final streaming analysis on any remaining content that
        // didn't cross a token-interval boundary.
        if let (Some(ref acc), Some(ref mut monitor)) = (&sse_accumulator, &mut streaming_monitor) {
            let final_findings =
                monitor.analyze_incremental(&acc.content, acc.completion_token_count);
            if !final_findings.is_empty() {
                info!(
                    %trace_id,
                    count = final_findings.len(),
                    "Streaming security findings in final flush"
                );
                if let Some(ref engine) = state_bg.alert_engine {
                    engine.check_and_alert(trace_id, tenant_id, &final_findings);
                }
            }
        }

        // Collect streaming security findings for attachment to the trace span.
        let streaming_findings: Vec<SecurityFinding> = streaming_monitor
            .as_mut()
            .map(|m| m.take_findings())
            .unwrap_or_default();

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
                let ParsedResponse { text, usage } =
                    provider::parse_response(&provider_bg, &raw_collected);
                let response_str =
                    text.unwrap_or_else(|| String::from_utf8_lossy(&raw_collected).to_string());
                (
                    response_str,
                    usage.prompt_tokens,
                    usage.completion_tokens,
                    usage.total_tokens,
                )
            };

        // Auto-extract tool calls from the response
        let auto_actions = if is_streaming {
            Vec::new() // TODO: SSE tool call parsing deferred to future loop
        } else {
            provider::extract_tool_calls(&provider_bg, &raw_collected)
        };

        let captured = CapturedInteraction {
            trace_id,
            tenant_id,
            provider: provider_bg,
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
            agent_actions: auto_actions,
        };

        // --- Async spend recording for cost caps ---
        if let Some(ref tracker) = state_bg.cost_tracker {
            let estimated = state_bg.cost_estimator.estimate_cost(
                &captured.provider,
                &captured.model_name,
                captured.prompt_tokens,
                captured.completion_tokens,
            );
            if let Some(cost) = estimated {
                tracker
                    .record_spend(captured.tenant_id, agent_id_bg.as_deref(), cost)
                    .await;
            }
        }

        // --- Security analysis first, so findings can be persisted with the trace ---
        let mut security_findings = run_security_analysis(&state_bg, &captured).await;

        // Merge in any findings detected during streaming (early warning layer).
        // These have already been alerted on mid-stream; now we persist them
        // alongside the full post-stream analysis findings.
        security_findings.extend(streaming_findings);

        // --- Anomaly detection (async, non-blocking) ---
        if let Some(ref detector) = state_bg.anomaly_detector {
            let anomaly_findings = detector
                .record_and_check(
                    captured.tenant_id,
                    state_bg.cost_estimator.estimate_cost(
                        &captured.provider,
                        &captured.model_name,
                        captured.prompt_tokens,
                        captured.completion_tokens,
                    ),
                    captured.total_tokens,
                    captured
                        .start_time
                        .signed_duration_since(captured.start_time)
                        .num_milliseconds()
                        .max(0)
                        .try_into()
                        .ok()
                        .or_else(|| {
                            Utc::now()
                                .signed_duration_since(captured.start_time)
                                .num_milliseconds()
                                .try_into()
                                .ok()
                        }),
                )
                .await;
            if !anomaly_findings.is_empty() {
                info!(
                    trace_id = %captured.trace_id,
                    count = anomaly_findings.len(),
                    "Anomaly findings detected"
                );
                security_findings.extend(anomaly_findings);
            }
        }

        // --- Alert engine: fire-and-forget webhook notification ---
        if let Some(ref engine) = state_bg.alert_engine {
            engine.check_and_alert(captured.trace_id, captured.tenant_id, &security_findings);
        }

        // --- Trace capture with enriched security findings ---
        run_trace_capture(&state_bg, &captured, &security_findings).await;
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
    /// Detected LLM provider for this request.
    provider: LLMProvider,
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
    /// Agent actions auto-parsed from the LLM response (tool calls).
    agent_actions: Vec<AgentAction>,
}

/// Run security analysis and return findings.
///
/// Called inline within the background task so findings can be attached to
/// the trace span before storage. Returns an empty vec when analysis is
/// disabled, the circuit breaker is open, or analysis fails.
async fn run_security_analysis(
    state: &Arc<AppState>,
    captured: &CapturedInteraction,
) -> Vec<SecurityFinding> {
    if !state.config.enable_security_analysis {
        return Vec::new();
    }
    if !state.security_breaker.allow().await {
        debug!(trace_id = %captured.trace_id, "Security circuit breaker open — skipping analysis");
        return Vec::new();
    }

    let context = AnalysisContext {
        tenant_id: captured.tenant_id,
        trace_id: captured.trace_id,
        span_id: Uuid::new_v4(),
        provider: captured.provider.clone(),
        model_name: captured.model_name.clone(),
        parameters: std::collections::HashMap::new(),
    };

    match state
        .security
        .analyze_interaction(&captured.prompt_text, &captured.response_text, &context)
        .await
    {
        Ok(findings) => {
            state.security_breaker.record_success().await;
            if findings.is_empty() {
                debug!(trace_id = %captured.trace_id, "Security analysis: no findings");
            } else {
                info!(
                    trace_id = %captured.trace_id,
                    finding_count = findings.len(),
                    "Security findings detected"
                );
            }
            findings
        }
        Err(e) => {
            state.security_breaker.record_failure().await;
            error!(trace_id = %captured.trace_id, "Security analysis failed: {}", e);
            Vec::new()
        }
    }
}

/// Store a trace event enriched with security findings.
///
/// Called inline within the background task after security analysis completes,
/// ensuring findings are persisted alongside the trace span.
async fn run_trace_capture(
    state: &Arc<AppState>,
    captured: &CapturedInteraction,
    security_findings: &[SecurityFinding],
) {
    if !state.config.enable_trace_storage {
        return;
    }
    if !state.storage_breaker.allow().await {
        debug!(trace_id = %captured.trace_id, "Storage circuit breaker open — skipping trace capture");
        return;
    }

    let operation = if captured.is_streaming {
        "chat_completion_stream"
    } else {
        "chat_completion"
    };

    let mut span = TraceSpan::new(
        captured.trace_id,
        captured.tenant_id,
        operation.to_string(),
        captured.provider.clone(),
        captured.model_name.clone(),
        captured.prompt_text.clone(),
    )
    .finish_with_response(captured.response_text.clone());

    span.status_code = Some(captured.status_code);
    span.prompt_tokens = captured.prompt_tokens;
    span.completion_tokens = captured.completion_tokens;
    span.total_tokens = captured.total_tokens;
    span.time_to_first_token_ms = captured.time_to_first_token_ms;

    // Estimate cost once token counts are known
    span.estimated_cost_usd = state.cost_estimator.estimate_cost(
        &captured.provider,
        &captured.model_name,
        captured.prompt_tokens,
        captured.completion_tokens,
    );

    let end_time = Utc::now();
    let duration = end_time.signed_duration_since(captured.start_time);
    span.duration_ms = Some(duration.num_milliseconds().max(0) as u64);

    // Attach auto-parsed agent actions to the span
    for action in &captured.agent_actions {
        span.add_agent_action(action.clone());
    }

    // Analyze agent actions for security issues
    if !captured.agent_actions.is_empty() {
        if let Ok(analyzer) = llmtrace_security::RegexSecurityAnalyzer::new() {
            let action_findings = analyzer.analyze_agent_actions(&captured.agent_actions);
            for finding in action_findings {
                span.add_security_finding(finding);
            }
        }
    }

    // Attach security findings to the span
    for finding in security_findings {
        span.add_security_finding(finding.clone());
    }

    let trace = TraceEvent {
        trace_id: captured.trace_id,
        tenant_id: captured.tenant_id,
        spans: vec![span],
        created_at: captured.start_time,
    };

    match state.storage.traces.store_trace(&trace).await {
        Ok(()) => {
            state.storage_breaker.record_success().await;
            info!(trace_id = %captured.trace_id, "Trace stored successfully");
        }
        Err(e) => {
            state.storage_breaker.record_failure().await;
            error!(trace_id = %captured.trace_id, "Failed to store trace: {}", e);
        }
    }
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

/// Health check handler returning a JSON status object.
pub async fn health_handler(State(state): State<Arc<AppState>>) -> Response<Body> {
    let traces_ok = state.storage.traces.health_check().await.is_ok();
    let metadata_ok = state.storage.metadata.health_check().await.is_ok();
    let cache_ok = state.storage.cache.health_check().await.is_ok();
    let security_ok = state.security.health_check().await.is_ok();
    let storage_circuit = state.storage_breaker.state().await;
    let security_circuit = state.security_breaker.state().await;

    let all_healthy = traces_ok && metadata_ok && cache_ok && security_ok;

    let body = serde_json::json!({
        "status": if all_healthy { "healthy" } else { "degraded" },
        "storage": {
            "traces": { "healthy": traces_ok },
            "metadata": { "healthy": metadata_ok },
            "cache": { "healthy": cache_ok },
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

/// Build a 429 Too Many Requests response for cost cap rejections.
fn cap_rejected_response(message: &str, retry_after_secs: u64) -> Response<Body> {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "cost_cap_exceeded",
            "retry_after_secs": retry_after_secs,
        }
    });
    let mut builder = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json");
    if retry_after_secs > 0 {
        builder = builder.header("retry-after", retry_after_secs.to_string());
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

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
    fn test_extract_agent_id_present() {
        let mut headers = HeaderMap::new();
        headers.insert("x-llmtrace-agent-id", "my-agent".parse().unwrap());
        assert_eq!(extract_agent_id(&headers), Some("my-agent".to_string()));
    }

    #[test]
    fn test_extract_agent_id_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_agent_id(&headers), None);
    }

    #[test]
    fn test_cap_rejected_response_format() {
        let resp = cap_rejected_response("budget exceeded", 3600);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get("retry-after").unwrap().to_str().unwrap(),
            "3600"
        );
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
