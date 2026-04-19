//! Core proxy request handler.
//!
//! Receives incoming HTTP requests, extracts LLM metadata, forwards them to
//! the upstream, captures the response, and spawns async background tasks for
//! trace storage and security analysis.

use crate::action_router::ActionRouter;
use crate::circuit_breaker::CircuitBreaker;
use crate::config_handle::ConfigHandle;
use crate::cost::CostEstimator;
use crate::provider::{self, ParsedResponse};
use crate::streaming::{StreamingAccumulator, StreamingOutputMonitor, StreamingSecurityMonitor};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, Response, StatusCode};
use bytes::Bytes;
use chrono::Utc;
use futures_util::StreamExt;
use llmtrace_core::{
    truncate_to_byte_limit, AgentAction, AnalysisContext, LLMProvider, ProxyConfig,
    SecurityAnalyzer, SecurityFinding, Storage, TenantId, TraceEvent, TraceSpan,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Stable, operator-facing reason code for a non-writable runtime
/// overlay path. The raw `std::io::Error` message is intentionally NOT
/// exposed to unauthenticated `/health` callers (would leak the
/// filesystem layout); it is only logged server-side at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeOverlayReasonCode {
    /// Filesystem reports read-only (mount option or ConfigMap mount).
    ReadOnlyFilesystem,
    /// Filesystem accepts writes but the proxy process lacks permission.
    PermissionDenied,
    /// The resolved parent directory does not exist and cannot be
    /// created (for example, points at a non-existent path under a
    /// read-only parent).
    ParentMissing,
    /// Any other I/O error — intentionally coarse so the wire shape
    /// does not leak kernel-specific strings to unauthenticated
    /// callers.
    Unknown,
}

impl RuntimeOverlayReasonCode {
    /// Wire representation used in the `/health` JSON body.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnlyFilesystem => "read_only_filesystem",
            Self::PermissionDenied => "permission_denied",
            Self::ParentMissing => "parent_missing",
            Self::Unknown => "unknown",
        }
    }

    /// Infer the stable reason code from a raw `std::io::Error`.
    /// Returns `Unknown` when the OS-level classification is not
    /// actionable. `EROFS` (errno 30 on Linux / 30 on macOS) is
    /// detected via `raw_os_error()` so we do not need an explicit
    /// libc dependency; this keeps the check portable and coarse on
    /// non-POSIX targets (which will just report `Unknown`).
    pub fn from_io_error(err: &std::io::Error) -> Self {
        const EROFS: i32 = 30;
        match err.kind() {
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::NotFound => Self::ParentMissing,
            _ if err.raw_os_error() == Some(EROFS) => Self::ReadOnlyFilesystem,
            _ => Self::Unknown,
        }
    }
}

/// Writability state of the sidecar runtime overlay path at startup.
///
/// Computed by `main::probe_runtime_overlay_writable` and surfaced on
/// the `/health` endpoint so Kubernetes readiness probes and
/// operators can detect the silent-revert trap where the base
/// `--config` lives in a read-only ConfigMap mount and the derived
/// `config.runtime.yaml` inherits the mount (issue #42 B2).
#[derive(Debug, Clone)]
pub enum RuntimeOverlayStatus {
    /// No runtime overlay path was resolved — the proxy was started
    /// without `--config` / `--runtime-config` and persistence is
    /// intentionally disabled.
    Disabled,
    /// The runtime overlay path resolved and the filesystem accepts
    /// writes. Admin PUTs to `/api/v1/config/features` will persist
    /// across restarts.
    Writable,
    /// The runtime overlay path resolved but the filesystem rejected
    /// the startup probe. Admin PUTs will apply in memory but will
    /// NOT persist — pod restart silently reverts. Only the stable
    /// reason code is exposed via `/health`; the raw filesystem
    /// error is logged server-side.
    NotWritable {
        /// Stable operator-facing reason code, safe to expose on the
        /// unauthenticated `/health` endpoint.
        reason_code: RuntimeOverlayReasonCode,
    },
}

/// Status of ML model loading at startup.
#[derive(Debug, Clone)]
pub enum MlModelStatus {
    /// ML not enabled in configuration.
    Disabled,
    /// ML models loaded successfully.
    Loaded {
        /// Whether the prompt injection model is available.
        prompt_injection: bool,
        /// Whether the NER model is available.
        ner: bool,
        /// Whether the InjecGuard model is available.
        injecguard: bool,
        /// Whether the PIGuard model is available.
        piguard: bool,
        /// Time taken to load models in milliseconds.
        load_time_ms: u64,
    },
    /// ML model loading failed; proxy continues with regex fallback.
    Failed {
        /// Error description.
        error: String,
    },
}

/// Shared state threaded through axum handlers via [`State`].
pub struct AppState {
    /// Runtime-mutable proxy configuration.
    ///
    /// Reads are lock-free via [`arc_swap::ArcSwap`]. Callers that need
    /// the config across an `.await` must use `config_handle.snapshot()`
    /// (an `Arc<ProxyConfig>`) instead of `load()` because the `Guard`
    /// returned by `load()` is `!Send`.
    pub config_handle: ConfigHandle,
    /// HTTP client for forwarding requests upstream.
    pub client: Client,
    /// Composite storage (traces, metadata, cache).
    pub storage: Storage,
    /// Security analyzer for scanning requests and responses.
    pub security: Arc<dyn SecurityAnalyzer>,
    /// Runtime handle for toggling ensemble feature flags from the admin
    /// API (issue #42). When the ensemble is not constructed (regex-only
    /// fallback path), this is an inert handle whose writes round-trip
    /// but are not observed.
    pub ensemble_runtime: Arc<llmtrace_security::EnsembleRuntimeHandle>,
    /// Regex-only security analyzer for fast-path enforcement.
    pub fast_analyzer: Arc<dyn SecurityAnalyzer>,
    /// Circuit breaker for the storage subsystem.
    pub storage_breaker: Arc<CircuitBreaker>,
    /// Circuit breaker for the security subsystem.
    pub security_breaker: Arc<CircuitBreaker>,
    /// Cost estimator for computing per-request cost in USD.
    pub cost_estimator: CostEstimator,
    /// Alert engine for webhook notifications (`None` if alerts are disabled).
    pub alert_engine: Option<crate::alerts::AlertEngine>,
    /// Cost cap tracker.
    ///
    /// Always constructed so that toggling `cost_caps_enabled` at runtime
    /// via the feature-flag admin API takes effect without restart (#42).
    /// Hot-path call sites gate usage on `cfg.cost_caps.enabled`.
    pub cost_tracker: crate::cost_caps::CostTracker,
    /// Anomaly detector (`None` if anomaly detection is disabled).
    pub anomaly_detector: Option<crate::anomaly::AnomalyDetector>,
    /// Action orchestrator for routing enforcement actions.
    pub action_router: ActionRouter,
    /// In-memory store for compliance reports (legacy — reports are now also
    /// persisted to MetadataRepository).
    pub report_store: crate::compliance::ReportStore,
    /// Per-tenant rate limiter.
    ///
    /// Always constructed so that toggling `rate_limiting_enabled` at
    /// runtime via the feature-flag admin API takes effect without
    /// restart (#42). Hot-path call sites gate usage on
    /// `cfg.rate_limiting.enabled`.
    pub rate_limiter: crate::rate_limit::RateLimiter,
    /// Status of ML model loading at startup.
    pub ml_status: MlModelStatus,
    /// Whether the LLM-as-a-Judge worker was spawned at startup (#43).
    ///
    /// Computed once by `build_app_state`: `true` iff `judge.enabled`
    /// was true at startup AND the configured backend was constructed
    /// successfully (e.g., required API-key env vars present). When
    /// `false`, flipping `llm_judge_enabled` via the admin API is
    /// persisted but inert until the proxy restarts with a successful
    /// backend construction. Surfaced via `/api/v1/config/features`
    /// `effective["llm_judge_enabled"]`.
    pub judge_worker_spawned: bool,
    /// Writability of the sidecar runtime overlay path at startup.
    ///
    /// Computed once by `build_app_state` via a probe write; the
    /// `/health` endpoint exposes the result so operators and
    /// Kubernetes readiness probes can catch the silent-revert trap
    /// where the base `--config` lives in a read-only ConfigMap mount
    /// and the derived `config.runtime.yaml` inherits the mount.
    pub runtime_overlay_status: RuntimeOverlayStatus,
    /// Shutdown coordinator for graceful shutdown and task tracking.
    pub shutdown: crate::shutdown::ShutdownCoordinator,
    /// Prometheus metrics collectors.
    pub metrics: crate::metrics::Metrics,
    /// Whether storage initialisation is complete.
    ///
    /// Set to `true` once all storage backends have been confirmed healthy
    /// at least once. The `/health` endpoint reports `"starting": true` until
    /// this flag flips, which lets Kubernetes `startupProbe` differentiate a
    /// cold start from a genuine failure.
    pub ready: Arc<AtomicBool>,
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
///
/// The `extra` map captures all fields not explicitly modeled (e.g.
/// `temperature`, `max_tokens`, `tools`, `top_p`) so they survive
/// round-trip serialization when the proxy modifies the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LLMRequestBody {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub stream: Option<bool>,
    /// Anthropic top-level system parameter (not in messages array).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<serde_json::Value>,
    /// Preserve all other fields through round-trip serialization.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A single chat message (provider-agnostic).
///
/// `content` is `serde_json::Value` to handle plain strings (OpenAI),
/// arrays of content blocks (multimodal / Anthropic), and null.
/// The `extra` map preserves `tool_call_id`, `name`, `tool_calls`,
/// and any other provider-specific fields through round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChatMessage {
    pub role: String,
    #[serde(default)]
    pub content: serde_json::Value,
    /// Preserve all other fields (tool_call_id, name, etc.)
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
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
pub(crate) fn resolve_tenant(headers: &HeaderMap) -> Option<TenantId> {
    if let Some(raw) = headers.get("x-llmtrace-tenant-id") {
        if let Ok(s) = raw.to_str() {
            if let Ok(uuid) = Uuid::parse_str(s) {
                return Some(TenantId(uuid));
            }
        }
    }
    // Fallback: derive from API key hash
    if let Some(key) = extract_api_key(headers) {
        // Deterministic UUID v5 from the API key
        let ns = Uuid::NAMESPACE_URL;
        return Some(TenantId(Uuid::new_v5(&ns, key.as_bytes())));
    }
    None
}

/// Extract the text content from a `serde_json::Value` message content field.
///
/// Handles string content (OpenAI), array content blocks (multimodal /
/// Anthropic), null, and other shapes gracefully.
fn extract_content_text(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|block| block.get("text").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Concatenate all chat message contents into a single string for display/storage.
///
/// Includes role prefixes (e.g. "user: Hello") so the stored trace shows
/// which role sent each message.
fn messages_to_prompt_text(messages: &[ChatMessage]) -> String {
    messages
        .iter()
        .map(|m| format!("{}: {}", m.role, extract_content_text(&m.content)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Extract raw message content for security analysis (no role prefixes).
///
/// The security analyzer should see only the actual content so that structural
/// role markers added by the proxy (e.g. "user: ") do not trigger false
/// positives on role-injection or ML prompt-injection detectors.
fn messages_to_analysis_text(messages: &[ChatMessage]) -> String {
    messages
        .iter()
        .map(|m| extract_content_text(&m.content))
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
    state.metrics.active_connections.inc();
    let start_time = Utc::now();
    let trace_id = Uuid::new_v4();
    // Snapshot the live config for this request. `Arc<ProxyConfig>` is
    // `Send + 'static`, so it can cross `await` points freely.
    let cfg = state.config_handle.snapshot();

    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().map(|q| q.to_string());
    let headers = req.headers().clone();

    // Use authenticated tenant if available, otherwise fall back to header resolution
    let (tenant_id_opt, _) = crate::auth::resolve_authenticated_tenant(&headers, req.extensions());

    // Resolve tenant ID. If auth is enabled, we MUST have a tenant ID from resolve_authenticated_tenant.
    let tenant_id = match tenant_id_opt {
        Some(id) if !id.0.is_nil() => id,
        _ => {
            if cfg.auth.enabled {
                // This shouldn't be reached if auth_middleware is working correctly
                warn!(%trace_id, "Missing authenticated tenant when auth is enabled");
                return error_response(StatusCode::UNAUTHORIZED, "Authentication required");
            }
            // Fallback for when auth is disabled: use deterministic "Unknown" tenant
            TenantId(Uuid::new_v5(&Uuid::NAMESPACE_OID, b"Unknown"))
        }
    };

    let _api_key = extract_api_key(&headers);
    let agent_id = extract_agent_id(&headers);
    let detected_provider = provider::detect_provider(&headers, &cfg.upstream_url, &path);

    let source_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        });

    // Fetch tenant configuration (best-effort)
    let tenant_config = state
        .metadata()
        .get_tenant_config(tenant_id)
        .await
        .ok()
        .flatten();
    let monitoring_scope = tenant_config
        .as_ref()
        .map(|c| c.monitoring_scope)
        .unwrap_or(llmtrace_core::MonitoringScope::Hybrid);

    // Auto-create tenant on first request (best-effort, non-blocking).
    // If auth is enabled, only create if we have an authenticated tenant.
    // If auth is disabled, we still auto-create the "Unknown" tenant.
    if !cfg.auth.enabled || tenant_id_opt.is_some() {
        let state_ac = Arc::clone(&state);
        let name = if tenant_id_opt.is_some() {
            _api_key
                .as_deref()
                .map(|k| {
                    let prefix_len = k.len().min(8);
                    format!("key-{}", &k[..prefix_len])
                })
                .unwrap_or_else(|| format!("tenant-{}", tenant_id.0))
        } else {
            "Unknown".to_string()
        };
        tokio::spawn(async move {
            crate::tenant_api::ensure_tenant_exists(&state_ac, tenant_id, &name).await;
        });
    }

    // --- Pre-request IP blocking (Action Router) ---
    if state
        .action_router
        .is_ip_blocked(source_ip, &Some(Arc::clone(&state.storage.cache)))
        .await
    {
        warn!(%trace_id, ?source_ip, "Request blocked by IP reputation (Action Router)");
        state.metrics.active_connections.dec();
        return crate::enforcement::blocked_response("IP blocked by enforcement action", &[]);
    }

    // --- Per-tenant rate limiting ---
    // The limiter is always constructed; the runtime feature-flag API
    // can toggle `rate_limiting.enabled` per-request via `ConfigHandle`.
    if cfg.rate_limiting.enabled {
        match state.rate_limiter.check(tenant_id).await {
            crate::rate_limit::RateLimitResult::Exceeded {
                retry_after_secs,
                limit,
                tenant_id: tid,
            } => {
                warn!(
                    %trace_id,
                    %tid,
                    limit,
                    retry_after_secs,
                    "Rate limit exceeded"
                );
                state.metrics.active_connections.dec();
                return rate_limit_response(tid, limit, retry_after_secs);
            }
            crate::rate_limit::RateLimitResult::Allowed => {}
        }
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
    let body_bytes =
        match axum::body::to_bytes(req.into_body(), cfg.max_request_size_bytes as usize).await {
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
    let analysis_text = llm_body
        .as_ref()
        .map(|b| {
            if !b.messages.is_empty() {
                messages_to_analysis_text(&b.messages)
            } else {
                b.prompt.clone().unwrap_or_default()
            }
        })
        .unwrap_or_default();

    // --- Pre-request cost cap enforcement ---
    // The tracker is always constructed; the runtime feature-flag API
    // can toggle `cost_caps.enabled` per-request via `ConfigHandle`.
    if cfg.cost_caps.enabled {
        let tracker = &state.cost_tracker;
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

    // --- Pre-request security enforcement ---
    let mut flagged_findings: Vec<SecurityFinding> = Vec::new();
    if cfg.enable_security_analysis {
        let enf_context = AnalysisContext {
            tenant_id,
            trace_id,
            span_id: Uuid::new_v4(),
            provider: detected_provider.clone(),
            model_name: model_name.clone(),
            parameters: std::collections::HashMap::new(),
        };
        let (mut decision, pre_findings) = crate::enforcement::run_enforcement(
            &analysis_text,
            &enf_context,
            &cfg.enforcement,
            &state.security,
            &state.fast_analyzer,
        )
        .await;

        let action_ctx = crate::action_router::ActionContext {
            trace_id,
            tenant_id,
            findings: &pre_findings,
            analysis_text: &analysis_text,
            source_ip,
            model_name: model_name.clone(),
            provider: detected_provider.clone(),
            execution_mode: crate::action_router::ExecutionMode::Inline,
            cache: Some(Arc::clone(&state.storage.cache)),
            metrics: Some(state.metrics.clone()),
        };

        decision = state
            .action_router
            .execute_inline(decision, &action_ctx)
            .await;

        match decision {
            crate::enforcement::EnforcementDecision::Block { reason, findings } => {
                warn!(%trace_id, %reason, "Security enforcement blocked request");
                state.metrics.active_connections.dec();
                return crate::enforcement::blocked_response(&reason, &findings);
            }
            crate::enforcement::EnforcementDecision::Flag { findings } => {
                info!(%trace_id, count = findings.len(), "Security enforcement flagged request");
                flagged_findings = findings;
            }
            crate::enforcement::EnforcementDecision::Allow => {}
        }
    }

    // --- Boundary token injection defense ---
    let boundary_result = crate::boundary::apply_boundary_defense(
        &body_bytes,
        &cfg.boundary_defense,
        &detected_provider,
    );
    let boundary_active = cfg.boundary_defense.enabled
        && !cfg.boundary_defense.shadow_mode
        && boundary_result.messages_wrapped > 0;

    if boundary_result.messages_wrapped > 0 {
        let mode = if cfg.boundary_defense.shadow_mode {
            "shadow"
        } else {
            "active"
        };
        debug!(
            %trace_id,
            provider = ?detected_provider,
            messages_wrapped = boundary_result.messages_wrapped,
            reminder_injected = boundary_result.reminder_injected,
            overhead_bytes = boundary_result.overhead_bytes,
            mode,
            "Boundary defense applied"
        );
        let provider_lbl = crate::metrics::provider_label(&detected_provider);
        state.metrics.record_boundary_defense(
            provider_lbl,
            boundary_result.messages_wrapped,
            boundary_result.reminder_injected,
            boundary_result.overhead_bytes,
            cfg.boundary_defense.shadow_mode,
        );
    }

    // Build the upstream request
    let upstream_url = build_upstream_url(&cfg, &path, query.as_deref());

    let mut upstream_req = state.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST),
        &upstream_url,
    );

    // Forward all headers except `Host` (reqwest sets it) and `Accept-Encoding`
    // (the proxy needs to read uncompressed responses for security analysis and
    // trace capture; reqwest does not enable auto-decompression).
    // When boundary defense is active, also strip `Content-Length` because the
    // body size has changed; reqwest will set it from the new body.
    let mut forwarded_headers = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        if name == "host" || name == "accept-encoding" {
            continue;
        }
        if boundary_active && name == "content-length" {
            continue;
        }
        if let Ok(rname) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(rval) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                forwarded_headers.insert(rname, rval);
            }
        }
    }
    upstream_req = upstream_req.headers(forwarded_headers);

    // Forward the modified body when boundary defense is active, original otherwise
    let forward_body = if boundary_active {
        boundary_result.body
    } else {
        body_bytes.to_vec()
    };
    upstream_req = upstream_req.body(forward_body);

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
    // Share the SAME config snapshot with the background task so the
    // request path and its streaming tail observe a single, coherent
    // version of the config. An admin PUT landing mid-request will be
    // picked up on the next request, not in the middle of this one.
    let cfg_bg = Arc::clone(&cfg);
    let prompt_text_bg = prompt_text.clone();
    let analysis_text_bg = analysis_text;
    let model_name_bg = model_name.clone();
    let provider_bg = detected_provider;
    let agent_id_bg = agent_id;
    let scope_bg = monitoring_scope;
    let task_guard = state.shutdown.track_task();
    tokio::spawn(async move {
        // Hold the task guard for the lifetime of this background task so the
        // shutdown coordinator knows when all in-flight work has drained.
        let _guard = task_guard;
        // We'll decrement active_connections at the end of this task.
        let mut stream = response_stream;
        let mut sse_accumulator = if is_streaming {
            Some(StreamingAccumulator::with_max_content_bytes(
                cfg_bg.max_response_size_bytes as usize,
            ))
        } else {
            None
        };
        // Initialise the streaming security monitor (only for SSE streams
        // when streaming analysis is enabled).
        // Respect monitoring_scope: disable if OutputOnly.
        let mut streaming_monitor =
            if is_streaming && scope_bg != llmtrace_core::MonitoringScope::OutputOnly {
                StreamingSecurityMonitor::new(&cfg_bg.streaming_analysis)
            } else {
                None
            };
        // Initialise the streaming output monitor for response-side analysis (R7).
        // Respect monitoring_scope: disable if InputOnly.
        let mut output_monitor =
            if is_streaming && scope_bg != llmtrace_core::MonitoringScope::InputOnly {
                StreamingOutputMonitor::new(&cfg_bg.streaming_analysis, &cfg_bg.output_safety)
            } else {
                None
            };
        let mut raw_collected = Vec::new();
        let mut response_truncated = false;
        let max_response_bytes = cfg_bg.max_response_size_bytes as usize;
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

                        // --- Real-time streaming OUTPUT analysis (R7) ---
                        if let Some(ref mut out_mon) = output_monitor {
                            if out_mon.should_analyze(acc.completion_token_count) {
                                let new_findings = out_mon
                                    .analyze_incremental(&acc.content, acc.completion_token_count);
                                if !new_findings.is_empty() {
                                    info!(
                                        %trace_id,
                                        count = new_findings.len(),
                                        tokens = acc.completion_token_count,
                                        "Streaming output safety findings detected mid-stream"
                                    );
                                    if let Some(ref engine) = state_bg.alert_engine {
                                        engine.check_and_alert(trace_id, tenant_id, &new_findings);
                                    }
                                }
                            }

                            // Early stop: inject warning and terminate stream
                            if out_mon.should_early_stop() {
                                warn!(
                                    %trace_id,
                                    "Critical output safety issue detected — early stopping stream"
                                );
                                let warning = StreamingOutputMonitor::early_stop_sse_event();
                                let _ = body_sender.send(Ok(Bytes::from(warning))).await;
                                break;
                            }
                        }
                    }
                    if !response_truncated {
                        if raw_collected.len() + bytes.len() > max_response_bytes {
                            warn!(
                                %trace_id,
                                collected = raw_collected.len(),
                                limit = max_response_bytes,
                                "Response exceeds max_response_size_bytes, truncating trace collection"
                            );
                            response_truncated = true;
                            state_bg.metrics.response_truncated_total.inc();
                        } else {
                            raw_collected.extend_from_slice(&bytes);
                        }
                    }
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

        // Run one final streaming OUTPUT analysis flush.
        if let (Some(ref acc), Some(ref mut out_mon)) = (&sse_accumulator, &mut output_monitor) {
            let final_findings =
                out_mon.analyze_incremental(&acc.content, acc.completion_token_count);
            if !final_findings.is_empty() {
                info!(
                    %trace_id,
                    count = final_findings.len(),
                    "Streaming output safety findings in final flush"
                );
                if let Some(ref engine) = state_bg.alert_engine {
                    engine.check_and_alert(trace_id, tenant_id, &final_findings);
                }
            }
        }

        // Collect streaming security findings for attachment to the trace span.
        let mut streaming_findings: Vec<SecurityFinding> = streaming_monitor
            .as_mut()
            .map(|m| m.take_findings())
            .unwrap_or_default();

        // Merge in streaming output findings.
        if let Some(ref mut out_mon) = output_monitor {
            streaming_findings.extend(out_mon.take_findings());
        }

        // Extract tool calls from streaming accumulator before it is moved.
        let streaming_tool_calls = sse_accumulator
            .as_mut()
            .map(|acc| acc.take_tool_calls())
            .unwrap_or_default();

        // Build the captured interaction with streaming metrics if applicable
        let (response_text, prompt_tokens, completion_tokens, total_tokens) =
            if let Some(acc) = sse_accumulator {
                let prompt_tok = acc.prompt_tokens();
                let completion_tok = acc.final_completion_tokens();
                let total_tok = acc.total_tokens();
                (acc.content, prompt_tok, Some(completion_tok), total_tok)
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
            streaming_tool_calls
        } else {
            provider::extract_tool_calls(&provider_bg, &raw_collected)
        };

        // Truncate analysis text to configured limit before security analysis
        let max_analysis = cfg_bg.security_analysis.max_analysis_text_bytes;
        let analysis_text_final = if analysis_text_bg.len() > max_analysis {
            warn!(
                original_len = analysis_text_bg.len(),
                limit = max_analysis,
                "Truncating analysis text to max_analysis_text_bytes"
            );
            state_bg.metrics.analysis_text_truncated_total.inc();
            truncate_to_byte_limit(&analysis_text_bg, max_analysis).to_string()
        } else {
            analysis_text_bg
        };

        let captured = CapturedInteraction {
            trace_id,
            tenant_id,
            provider: provider_bg,
            model_name: model_name_bg,
            prompt_text: prompt_text_bg,
            analysis_text: analysis_text_final,
            response_text,
            status_code: response_status.as_u16(),
            start_time,
            is_streaming,
            time_to_first_token_ms: ttft_ms,
            prompt_tokens,
            completion_tokens,
            total_tokens,
            agent_actions: auto_actions,
            monitoring_scope: scope_bg,
        };

        // --- Async spend recording for cost caps ---
        if cfg_bg.cost_caps.enabled {
            let estimated = state_bg.cost_estimator.estimate_cost(
                &captured.provider,
                &captured.model_name,
                captured.prompt_tokens,
                captured.completion_tokens,
            );
            if let Some(cost) = estimated {
                state_bg
                    .cost_tracker
                    .record_spend(captured.tenant_id, agent_id_bg.as_deref(), cost)
                    .await;
            }
        }

        // --- Security analysis first, so findings can be persisted with the trace ---
        let security_start = std::time::Instant::now();
        let mut security_findings = run_security_analysis(&state_bg, &captured).await;
        let security_ms = security_start.elapsed().as_millis() as u64;
        state_bg
            .metrics
            .record_detector_latency("ensemble", security_ms);

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

        // --- Execute async Enforcement Actions ---
        let async_action_ctx = crate::action_router::ActionContext {
            trace_id: captured.trace_id,
            tenant_id: captured.tenant_id,
            findings: &security_findings,
            analysis_text: &captured.analysis_text,
            source_ip,
            model_name: captured.model_name.clone(),
            provider: captured.provider.clone(),
            execution_mode: crate::action_router::ExecutionMode::Async,
            cache: Some(Arc::clone(&state_bg.storage.cache)),
            metrics: Some(state_bg.metrics.clone()),
        };
        state_bg
            .action_router
            .execute_async(&async_action_ctx)
            .await;

        // --- Alert engine: fire-and-forget webhook notification ---
        if let Some(ref engine) = state_bg.alert_engine {
            engine.check_and_alert(captured.trace_id, captured.tenant_id, &security_findings);
        }

        // --- Trace capture with enriched security findings ---
        run_trace_capture(&state_bg, &captured, &security_findings).await;

        // --- Prometheus metrics instrumentation ---
        {
            let provider_lbl = crate::metrics::provider_label(&captured.provider);
            let model_lbl = &captured.model_name;
            let duration_secs = Utc::now()
                .signed_duration_since(captured.start_time)
                .num_milliseconds()
                .max(0) as f64
                / 1000.0;

            state_bg.metrics.record_request(
                provider_lbl,
                model_lbl,
                captured.status_code,
                duration_secs,
            );

            state_bg.metrics.record_tokens(
                provider_lbl,
                model_lbl,
                captured.prompt_tokens,
                captured.completion_tokens,
            );

            state_bg
                .metrics
                .record_security_findings(&security_findings);
            state_bg.metrics.record_anomalies(&security_findings);

            if let Some(cost) = state_bg.cost_estimator.estimate_cost(
                &captured.provider,
                &captured.model_name,
                captured.prompt_tokens,
                captured.completion_tokens,
            ) {
                state_bg
                    .metrics
                    .record_cost(&captured.tenant_id.0.to_string(), model_lbl, cost);
            }

            state_bg.metrics.active_connections.dec();
        }
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

    // Inject enforcement flag headers if the request was flagged
    if !flagged_findings.is_empty() {
        builder = builder.header("x-llmtrace-flagged", "true");
        let summary = crate::enforcement::findings_header_value(&flagged_findings);
        if let Ok(hval) = axum::http::HeaderValue::from_str(&summary) {
            builder = builder.header("x-llmtrace-findings", hval);
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
    /// Role-prefixed prompt text for display/storage (e.g. "user: Hello").
    prompt_text: String,
    /// Raw content without role prefixes, for security analysis only.
    analysis_text: String,
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
    /// Monitoring scope for this tenant.
    monitoring_scope: llmtrace_core::MonitoringScope,
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
    let cfg = state.config_handle.snapshot();
    if !cfg.enable_security_analysis {
        return Vec::new();
    }
    if !state.security_breaker.allow().await {
        debug!(trace_id = %captured.trace_id, "Security circuit breaker open — skipping analysis");
        state.metrics.set_circuit_breaker_state("security", "open");
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

    let timeout = std::time::Duration::from_millis(cfg.security_analysis_timeout_ms);

    // Respect monitoring_scope: pass empty string for parts we shouldn't monitor
    let prompt = if captured.monitoring_scope == llmtrace_core::MonitoringScope::OutputOnly {
        ""
    } else {
        &captured.analysis_text
    };
    let response = if captured.monitoring_scope == llmtrace_core::MonitoringScope::InputOnly {
        ""
    } else {
        &captured.response_text
    };

    let analysis_result = tokio::time::timeout(
        timeout,
        state
            .security
            .analyze_interaction(prompt, response, &context),
    )
    .await;

    let mut all_findings = match analysis_result {
        Ok(Ok(findings)) => {
            state.security_breaker.record_success().await;
            let cb_state = state.security_breaker.state().await;
            state
                .metrics
                .set_circuit_breaker_state("security", circuit_breaker_state_label(cb_state));
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
        Ok(Err(e)) => {
            state.security_breaker.record_failure().await;
            let cb_state = state.security_breaker.state().await;
            state
                .metrics
                .set_circuit_breaker_state("security", circuit_breaker_state_label(cb_state));
            error!(trace_id = %captured.trace_id, "Security analysis failed: {}", e);
            Vec::new()
        }
        Err(_elapsed) => {
            state.security_breaker.record_failure().await;
            let cb_state = state.security_breaker.state().await;
            state
                .metrics
                .set_circuit_breaker_state("security", circuit_breaker_state_label(cb_state));
            warn!(
                trace_id = %captured.trace_id,
                timeout_ms = cfg.security_analysis_timeout_ms,
                "Security analysis timed out"
            );
            Vec::new()
        }
    };

    // --- Output safety analysis (R6) ---
    // Respect monitoring_scope: skip if InputOnly.
    if cfg.output_safety.enabled
        && !captured.response_text.is_empty()
        && captured.monitoring_scope != llmtrace_core::MonitoringScope::InputOnly
    {
        let output_analyzer =
            llmtrace_security::OutputAnalyzer::new_with_fallback(&cfg.output_safety);
        let result = output_analyzer.analyze_output(&captured.response_text);
        if !result.findings.is_empty() {
            info!(
                trace_id = %captured.trace_id,
                finding_count = result.findings.len(),
                has_critical = result.has_critical_toxicity,
                "Output safety findings detected"
            );
            all_findings.extend(result.findings);
        }
    }

    all_findings
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
    if !state.config_handle.load().enable_trace_storage {
        return;
    }
    if !state.storage_breaker.allow().await {
        debug!(trace_id = %captured.trace_id, "Storage circuit breaker open — skipping trace capture");
        state.metrics.set_circuit_breaker_state("storage", "open");
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
            state.metrics.record_storage_operation("store_trace", true);
            let cb_state = state.storage_breaker.state().await;
            state
                .metrics
                .set_circuit_breaker_state("storage", circuit_breaker_state_label(cb_state));
            info!(trace_id = %captured.trace_id, "Trace stored successfully");
        }
        Err(e) => {
            state.storage_breaker.record_failure().await;
            state.metrics.record_storage_operation("store_trace", false);
            let cb_state = state.storage_breaker.state().await;
            state
                .metrics
                .set_circuit_breaker_state("storage", circuit_breaker_state_label(cb_state));
            error!(trace_id = %captured.trace_id, "Failed to store trace: {}", e);
        }
    }
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

/// Health check handler returning a JSON status object.
///
/// During startup (before all storage backends have been confirmed healthy at
/// least once) the response includes `"starting": true` and returns HTTP 503.
/// Kubernetes `startupProbe` will keep retrying until the endpoint returns 200,
/// at which point the liveness and readiness probes take over.
pub async fn health_handler(State(state): State<Arc<AppState>>) -> Response<Body> {
    let traces_ok = state.storage.traces.health_check().await.is_ok();
    let metadata_ok = state.storage.metadata.health_check().await.is_ok();
    let cache_ok = state.storage.cache.health_check().await.is_ok();
    let security_ok = state.security.health_check().await.is_ok();
    let storage_circuit = state.storage_breaker.state().await;
    let security_circuit = state.security_breaker.state().await;

    let ml_status = match &state.ml_status {
        MlModelStatus::Disabled => serde_json::json!({
            "status": "disabled",
        }),
        MlModelStatus::Loaded {
            prompt_injection,
            ner,
            injecguard,
            piguard,
            load_time_ms,
        } => {
            // Count injection detectors active for majority voting:
            // regex (always) + prompt_injection + injecguard + piguard
            let injection_detectors =
                1 + (*prompt_injection as u8) + (*injecguard as u8) + (*piguard as u8);
            let voting_mode = if injection_detectors >= 3 {
                "majority"
            } else {
                "union"
            };
            serde_json::json!({
                "status": "loaded",
                "prompt_injection_model": prompt_injection,
                "ner_model": ner,
                "injecguard_model": injecguard,
                "piguard_model": piguard,
                "load_time_ms": load_time_ms,
                "injection_detector_count": injection_detectors,
                "voting_mode": voting_mode,
            })
        }
        MlModelStatus::Failed { error } => serde_json::json!({
            "status": "failed",
            "error": error,
        }),
    };

    let all_healthy = traces_ok && metadata_ok && cache_ok && security_ok;

    // Once every backend is healthy for the first time, mark the proxy as
    // ready. This is a one-way latch: once set it stays set so transient
    // blips don't re-trigger startup mode.
    let was_ready = state.ready.load(Ordering::Acquire);
    if !was_ready && all_healthy {
        state.ready.store(true, Ordering::Release);
    }
    let is_ready = was_ready || all_healthy;

    let (status_label, http_status) = if !is_ready {
        ("starting", StatusCode::SERVICE_UNAVAILABLE)
    } else if all_healthy {
        ("healthy", StatusCode::OK)
    } else {
        ("degraded", StatusCode::OK)
    };

    let runtime_overlay = match &state.runtime_overlay_status {
        RuntimeOverlayStatus::Disabled => serde_json::json!({
            "status": "disabled",
            "persistence": false,
            "writable": false,
        }),
        RuntimeOverlayStatus::Writable => serde_json::json!({
            "status": "writable",
            "persistence": true,
            "writable": true,
        }),
        // Only expose the stable reason code; the raw filesystem
        // error was logged server-side at startup. /health is on the
        // unauthenticated skip-list so we must not leak paths or
        // errno strings (issue #42 C1).
        RuntimeOverlayStatus::NotWritable { reason_code } => serde_json::json!({
            "status": "not_writable",
            "persistence": false,
            "writable": false,
            "reason_code": reason_code.as_str(),
        }),
    };

    let body = serde_json::json!({
        "status": status_label,
        "starting": !is_ready,
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
        "ml": ml_status,
        "runtime_overlay": runtime_overlay,
    });

    Response::builder()
        .status(http_status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Build a 429 Too Many Requests response for rate limit violations.
fn rate_limit_response(tenant_id: TenantId, limit: u32, retry_after_secs: u64) -> Response<Body> {
    let body = serde_json::json!({
        "error": {
            "message": format!("Rate limit exceeded for tenant {tenant_id}"),
            "type": "rate_limit_exceeded",
            "tenant_id": tenant_id.0.to_string(),
            "limit_requests_per_second": limit,
            "retry_after_secs": retry_after_secs,
        }
    });
    let mut builder = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("retry-after", retry_after_secs.to_string());
    // Add standard rate limit headers
    builder = builder.header("x-ratelimit-limit", limit.to_string());
    builder = builder.header("x-ratelimit-remaining", "0");
    builder.body(Body::from(body.to_string())).unwrap()
}

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

/// Map a [`CircuitState`] to the label string used in Prometheus metrics.
fn circuit_breaker_state_label(state: crate::circuit_breaker::CircuitState) -> &'static str {
    match state {
        crate::circuit_breaker::CircuitState::Closed => "closed",
        crate::circuit_breaker::CircuitState::Open => "open",
        crate::circuit_breaker::CircuitState::HalfOpen => "half_open",
    }
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
        let tenant = resolve_tenant(&headers).unwrap();
        assert_eq!(tenant.0, tenant_uuid);
    }

    #[test]
    fn test_resolve_tenant_from_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-my-key".parse().unwrap());
        let tenant = resolve_tenant(&headers).unwrap();
        // Should produce a deterministic UUID v5
        let expected = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"sk-my-key");
        assert_eq!(tenant.0, expected);
    }

    #[test]
    fn test_resolve_tenant_fallback() {
        let headers = HeaderMap::new();
        let tenant = resolve_tenant(&headers);
        // Should be None when no header or key is present
        assert!(tenant.is_none());
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

    /// Helper to build a ChatMessage with string content and no extra fields.
    fn chat_msg(role: &str, content: &str) -> ChatMessage {
        ChatMessage {
            role: role.to_string(),
            content: serde_json::Value::String(content.to_string()),
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn test_messages_to_prompt_text() {
        let msgs = vec![
            chat_msg("system", "You are helpful."),
            chat_msg("user", "Hello!"),
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
    fn test_messages_to_analysis_text() {
        let msgs = vec![
            chat_msg("system", "You are helpful."),
            chat_msg("user", "Hello!"),
        ];
        let text = messages_to_analysis_text(&msgs);
        assert!(text.contains("You are helpful."));
        assert!(text.contains("Hello!"));
        assert!(
            !text.contains("user:"),
            "analysis text must not include role prefixes"
        );
        assert!(
            !text.contains("system:"),
            "analysis text must not include role prefixes"
        );
    }

    #[test]
    fn test_messages_to_analysis_text_empty() {
        let text = messages_to_analysis_text(&[]);
        assert!(text.is_empty());
    }

    #[test]
    fn test_extract_content_text_string() {
        let val = serde_json::Value::String("hello world".to_string());
        assert_eq!(extract_content_text(&val), "hello world");
    }

    #[test]
    fn test_extract_content_text_array() {
        let val = serde_json::json!([
            {"type": "text", "text": "line one"},
            {"type": "image_url", "image_url": {"url": "http://img"}},
            {"type": "text", "text": "line two"}
        ]);
        assert_eq!(extract_content_text(&val), "line one\nline two");
    }

    #[test]
    fn test_extract_content_text_null() {
        assert_eq!(extract_content_text(&serde_json::Value::Null), "");
    }

    #[test]
    fn test_messages_to_analysis_text_value_content() {
        let msgs = vec![
            ChatMessage {
                role: "user".to_string(),
                content: serde_json::json!([
                    {"type": "text", "text": "What is this?"},
                    {"type": "image_url", "image_url": {"url": "http://img"}}
                ]),
                extra: serde_json::Map::new(),
            },
            chat_msg("assistant", "It is a cat."),
        ];
        let text = messages_to_analysis_text(&msgs);
        assert!(text.contains("What is this?"));
        assert!(text.contains("It is a cat."));
        assert!(!text.contains("user:"));
    }

    #[test]
    fn test_error_response_format() {
        let resp = error_response(StatusCode::BAD_GATEWAY, "upstream down");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
