//! REST Query API handlers for traces, spans, and security findings.
//!
//! These endpoints allow users to query stored LLM traces and security
//! findings via HTTP without direct database access. All endpoints
//! identify the tenant via the auth middleware (when auth is enabled) or
//! from request headers (legacy fallback).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use chrono::{DateTime, Utc};
use llmtrace_core::{
    AgentAction, AgentActionType, ApiKeyRole, AuthContext, LLMProvider, TraceQuery,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Paginated API response wrapper.
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    /// The data items for this page.
    pub data: Vec<T>,
    /// Total number of matching items (before pagination).
    pub total: u64,
    /// Maximum items per page.
    pub limit: u32,
    /// Number of items skipped.
    pub offset: u32,
}

/// API error response body.
#[derive(Debug, Serialize)]
struct ApiError {
    error: ApiErrorDetail,
}

/// Inner error detail.
#[derive(Debug, Serialize)]
struct ApiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
}

// ---------------------------------------------------------------------------
// Query parameter types
// ---------------------------------------------------------------------------

/// Query parameters for `GET /api/v1/traces`.
#[derive(Debug, Deserialize)]
pub struct ListTracesParams {
    /// Filter traces starting after this time (RFC 3339).
    pub start_time: Option<DateTime<Utc>>,
    /// Filter traces ending before this time (RFC 3339).
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by LLM provider name.
    pub provider: Option<String>,
    /// Filter by model name.
    pub model: Option<String>,
    /// Maximum number of results (default 50, max 1000).
    pub limit: Option<u32>,
    /// Number of results to skip (default 0).
    pub offset: Option<u32>,
}

/// Query parameters for `GET /api/v1/spans`.
#[derive(Debug, Deserialize)]
pub struct ListSpansParams {
    /// Minimum security score filter.
    pub security_score_min: Option<u8>,
    /// Maximum security score filter.
    pub security_score_max: Option<u8>,
    /// Filter by operation name.
    pub operation_name: Option<String>,
    /// Filter by model name.
    pub model: Option<String>,
    /// Maximum number of results (default 50, max 1000).
    pub limit: Option<u32>,
    /// Number of results to skip (default 0).
    pub offset: Option<u32>,
}

/// Query parameters for `GET /api/v1/security/findings`.
#[derive(Debug, Deserialize)]
pub struct ListFindingsParams {
    /// Maximum number of results (default 50, max 1000).
    pub limit: Option<u32>,
    /// Number of results to skip (default 0).
    pub offset: Option<u32>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Default page size.
const DEFAULT_LIMIT: u32 = 50;

/// Maximum page size.
const MAX_LIMIT: u32 = 1000;

/// Clamp the requested limit to a valid range.
fn clamp_limit(limit: Option<u32>) -> u32 {
    limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

/// Parse a provider string into an [`LLMProvider`] variant.
///
/// Matching is case-insensitive. Unknown strings map to [`LLMProvider::Custom`].
fn parse_provider(s: &str) -> LLMProvider {
    match s.to_lowercase().as_str() {
        "openai" => LLMProvider::OpenAI,
        "anthropic" => LLMProvider::Anthropic,
        "vllm" => LLMProvider::VLLm,
        "sglang" => LLMProvider::SGLang,
        "tgi" => LLMProvider::TGI,
        "ollama" => LLMProvider::Ollama,
        "azureopenai" | "azure_openai" | "azure-openai" => LLMProvider::AzureOpenAI,
        "bedrock" => LLMProvider::Bedrock,
        other => LLMProvider::Custom(other.to_string()),
    }
}

/// Check that the caller has at least viewer role.
fn require_role_viewer(auth: &AuthContext) -> Option<Response> {
    if !auth.role.has_permission(ApiKeyRole::Viewer) {
        Some(api_error(StatusCode::FORBIDDEN, "Insufficient permissions"))
    } else {
        None
    }
}

/// Check that the caller has at least operator role.
fn require_role_operator(auth: &AuthContext) -> Option<Response> {
    if !auth.role.has_permission(ApiKeyRole::Operator) {
        Some(api_error(
            StatusCode::FORBIDDEN,
            "Insufficient permissions: requires operator role",
        ))
    } else {
        None
    }
}

/// Build a JSON error response.
fn api_error(status: StatusCode, message: &str) -> Response {
    let body = ApiError {
        error: ApiErrorDetail {
            message: message.to_string(),
            error_type: "api_error".to_string(),
        },
    };
    (status, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/traces` — list traces with filters.
///
/// Supports filtering by time range, provider, and model. Results are
/// paginated via `limit` and `offset` query parameters.
pub async fn list_traces(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListTracesParams>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;
    let limit = clamp_limit(params.limit);
    let offset = params.offset.unwrap_or(0);

    let mut query = TraceQuery::new(tenant_id);
    query.start_time = params.start_time;
    query.end_time = params.end_time;
    if let Some(ref provider_str) = params.provider {
        query.provider = Some(parse_provider(provider_str));
    }
    query.model_name = params.model;

    // Query without pagination to get total count, then paginate here.
    match state.storage.traces.query_traces(&query).await {
        Ok(all) => {
            let total = all.len() as u64;
            let data: Vec<_> = all
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            Json(PaginatedResponse {
                data,
                total,
                limit,
                offset,
            })
            .into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/traces/:trace_id` — get a single trace with all spans.
pub async fn get_trace(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(trace_id): Path<Uuid>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;

    match state.storage.traces.get_trace(tenant_id, trace_id).await {
        Ok(Some(trace)) => Json(trace).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "Trace not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/spans` — list spans with filters.
///
/// Supports filtering by security score range, operation name, and model.
/// Results are paginated via `limit` and `offset` query parameters.
pub async fn list_spans(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListSpansParams>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;
    let limit = clamp_limit(params.limit);
    let offset = params.offset.unwrap_or(0);

    let mut query = TraceQuery::new(tenant_id);
    query.min_security_score = params.security_score_min;
    query.max_security_score = params.security_score_max;
    query.operation_name = params.operation_name;
    query.model_name = params.model;

    match state.storage.traces.query_spans(&query).await {
        Ok(all) => {
            let total = all.len() as u64;
            let data: Vec<_> = all
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            Json(PaginatedResponse {
                data,
                total,
                limit,
                offset,
            })
            .into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/spans/:span_id` — get a single span.
pub async fn get_span(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(span_id): Path<Uuid>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;

    match state.storage.traces.get_span(tenant_id, span_id).await {
        Ok(Some(span)) => Json(span).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "Span not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/stats` — storage statistics for the tenant.
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;

    match state.storage.traces.get_stats(tenant_id).await {
        Ok(stats) => Json(stats).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/costs/current` — real-time spend per budget window.
///
/// Returns the current spend for the tenant (and optionally a specific agent)
/// across all configured budget windows, including remaining budget and
/// utilization percentage.
pub async fn get_current_costs(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<CostQueryParams>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;

    let tracker = match &state.cost_tracker {
        Some(t) => t,
        None => return api_error(StatusCode::NOT_FOUND, "Cost caps are not enabled"),
    };

    let snapshot = tracker
        .current_spend(tenant_id, params.agent_id.as_deref())
        .await;

    Json(snapshot).into_response()
}

/// Query parameters for `GET /api/v1/costs/current`.
#[derive(Debug, Deserialize)]
pub struct CostQueryParams {
    /// Optional agent ID to filter spend for.
    pub agent_id: Option<String>,
}

/// `GET /api/v1/security/findings` — spans with security findings.
///
/// Returns all spans where `security_score > 0`, paginated.
pub async fn list_security_findings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListFindingsParams>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;
    let limit = clamp_limit(params.limit);
    let offset = params.offset.unwrap_or(0);

    let mut query = TraceQuery::new(tenant_id);
    query.min_security_score = Some(1);

    match state.storage.traces.query_spans(&query).await {
        Ok(all) => {
            let total = all.len() as u64;
            let data: Vec<_> = all
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            Json(PaginatedResponse {
                data,
                total,
                limit,
                offset,
            })
            .into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Agent action types
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/traces/:trace_id/actions`.
#[derive(Debug, Deserialize)]
pub struct ReportActionRequest {
    /// Type of action: "tool_call", "skill_invocation", "command_execution",
    /// "web_access", "file_access".
    pub action_type: String,
    /// Name of the tool, skill, command, URL, or file path.
    pub name: String,
    /// Arguments or parameters.
    #[serde(default)]
    pub arguments: Option<String>,
    /// Result or output of the action (truncated at 4KB).
    #[serde(default)]
    pub result: Option<String>,
    /// Duration of the action in milliseconds.
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// Whether the action succeeded (default true).
    #[serde(default = "default_true")]
    pub success: bool,
    /// Exit code (for command executions).
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// HTTP method (for web access).
    #[serde(default)]
    pub http_method: Option<String>,
    /// HTTP status code (for web access).
    #[serde(default)]
    pub http_status: Option<u16>,
    /// File operation type (for file access).
    #[serde(default)]
    pub file_operation: Option<String>,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// Parse a string into an [`AgentActionType`].
fn parse_action_type(s: &str) -> Option<AgentActionType> {
    match s {
        "tool_call" => Some(AgentActionType::ToolCall),
        "skill_invocation" => Some(AgentActionType::SkillInvocation),
        "command_execution" => Some(AgentActionType::CommandExecution),
        "web_access" => Some(AgentActionType::WebAccess),
        "file_access" => Some(AgentActionType::FileAccess),
        _ => None,
    }
}

/// `POST /api/v1/traces/:trace_id/actions` — report a client-side agent action.
///
/// Appends an action to the first span of the given trace. If the trace has
/// no spans, returns 404.
pub async fn report_action(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(trace_id): Path<Uuid>,
    Json(body): Json<ReportActionRequest>,
) -> Response {
    if let Some(err) = require_role_operator(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;

    let action_type = match parse_action_type(&body.action_type) {
        Some(t) => t,
        None => {
            return api_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid action_type: '{}'. Expected one of: tool_call, skill_invocation, command_execution, web_access, file_access", body.action_type),
            )
        }
    };

    // Load the trace
    let trace = match state.storage.traces.get_trace(tenant_id, trace_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Trace not found"),
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    if trace.spans.is_empty() {
        return api_error(StatusCode::NOT_FOUND, "Trace has no spans");
    }

    // Build the action
    let mut action = AgentAction::new(action_type, body.name);
    if let Some(args) = body.arguments {
        action = action.with_arguments(args);
    }
    if let Some(result) = body.result {
        action = action.with_result(result);
    }
    if let Some(ms) = body.duration_ms {
        action = action.with_duration_ms(ms);
    }
    if !body.success {
        action = action.with_failure();
    }
    if let Some(code) = body.exit_code {
        action = action.with_exit_code(code);
    }
    if let Some(ref method) = body.http_method {
        let status = body.http_status.unwrap_or(0);
        action = action.with_http(method.clone(), status);
    }
    if let Some(ref op) = body.file_operation {
        action = action.with_file_operation(op.clone());
    }
    for (k, v) in body.metadata {
        action = action.with_metadata(k, v);
    }

    // Append the action to the first span and re-store it
    let mut span = trace.spans[0].clone();
    span.add_agent_action(action.clone());

    match state.storage.traces.store_span(&span).await {
        Ok(()) => Json(serde_json::json!({
            "status": "ok",
            "action_id": action.id.to_string(),
            "trace_id": trace_id.to_string(),
        }))
        .into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Response type for the actions summary endpoint.
#[derive(Debug, Serialize)]
pub struct ActionsSummary {
    /// Total number of spans scanned.
    pub total_spans: u64,
    /// Number of spans with tool calls.
    pub spans_with_tool_calls: u64,
    /// Number of spans with web access.
    pub spans_with_web_access: u64,
    /// Number of spans with command executions.
    pub spans_with_commands: u64,
    /// Total action count by type.
    pub action_counts: HashMap<String, u64>,
    /// Top action names by frequency.
    pub top_actions: Vec<ActionFrequency>,
}

/// Action name with its frequency count.
#[derive(Debug, Serialize)]
pub struct ActionFrequency {
    /// Action name.
    pub name: String,
    /// Action type.
    pub action_type: String,
    /// Number of times this action was observed.
    pub count: u64,
}

/// `GET /api/v1/actions/summary` — aggregate view of agent actions.
pub async fn actions_summary(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListSpansParams>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }
    let tenant_id = auth.tenant_id;
    let mut query = TraceQuery::new(tenant_id);
    query.model_name = params.model;
    query.operation_name = params.operation_name;

    let spans = match state.storage.traces.query_spans(&query).await {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let total_spans = spans.len() as u64;
    let mut spans_with_tool_calls = 0u64;
    let mut spans_with_web_access = 0u64;
    let mut spans_with_commands = 0u64;
    let mut action_counts: HashMap<String, u64> = HashMap::new();
    let mut name_freq: HashMap<(String, String), u64> = HashMap::new();

    for span in &spans {
        if span.has_tool_calls() {
            spans_with_tool_calls += 1;
        }
        if span.has_web_access() {
            spans_with_web_access += 1;
        }
        if span.has_commands() {
            spans_with_commands += 1;
        }
        for action in &span.agent_actions {
            let type_key = action.action_type.to_string();
            *action_counts.entry(type_key.clone()).or_default() += 1;
            *name_freq
                .entry((action.name.clone(), type_key))
                .or_default() += 1;
        }
    }

    // Build top actions (sorted by frequency, top 20)
    let mut top_actions: Vec<ActionFrequency> = name_freq
        .into_iter()
        .map(|((name, action_type), count)| ActionFrequency {
            name,
            action_type,
            count,
        })
        .collect();
    top_actions.sort_by(|a, b| b.count.cmp(&a.count));
    top_actions.truncate(20);

    Json(ActionsSummary {
        total_spans,
        spans_with_tool_calls,
        spans_with_web_access,
        spans_with_commands,
        action_counts,
        top_actions,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use llmtrace_core::{
        LLMProvider, ProxyConfig, SecurityAnalyzer, SecurityFinding, SecuritySeverity,
        StorageConfig, TenantId, TraceEvent, TraceSpan,
    };
    use llmtrace_security::RegexSecurityAnalyzer;
    use llmtrace_storage::StorageProfile;
    use tower::ServiceExt;

    /// Build shared application state backed by in-memory storage.
    async fn test_state() -> Arc<AppState> {
        let storage = StorageProfile::Memory.build().await.unwrap();
        let security = Arc::new(RegexSecurityAnalyzer::new().unwrap()) as Arc<dyn SecurityAnalyzer>;
        let client = reqwest::Client::new();
        let config = ProxyConfig {
            storage: StorageConfig {
                profile: "memory".to_string(),
                database_path: String::new(),
                ..StorageConfig::default()
            },
            ..ProxyConfig::default()
        };
        let storage_breaker = Arc::new(crate::circuit_breaker::CircuitBreaker::from_config(
            &config.circuit_breaker,
        ));
        let security_breaker = Arc::new(crate::circuit_breaker::CircuitBreaker::from_config(
            &config.circuit_breaker,
        ));

        let cost_estimator = crate::cost::CostEstimator::new(&config.cost_estimation);

        Arc::new(AppState {
            config,
            client,
            storage,
            security,
            storage_breaker,
            security_breaker,
            cost_estimator,
            alert_engine: None,
            cost_tracker: None,
            anomaly_detector: None,
            report_store: crate::compliance::new_report_store(),
            rate_limiter: None,
            ml_status: crate::proxy::MlModelStatus::Disabled,
            shutdown: crate::shutdown::ShutdownCoordinator::new(30),
            metrics: crate::metrics::Metrics::new(),
            ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Build shared application state with cost caps enabled.
    async fn test_state_with_cost_caps() -> Arc<AppState> {
        let storage = StorageProfile::Memory.build().await.unwrap();
        let security = Arc::new(RegexSecurityAnalyzer::new().unwrap()) as Arc<dyn SecurityAnalyzer>;
        let client = reqwest::Client::new();
        let cost_cap_config = llmtrace_core::CostCapConfig {
            enabled: true,
            default_budget_caps: vec![llmtrace_core::BudgetCap {
                window: llmtrace_core::BudgetWindow::Daily,
                hard_limit_usd: 100.0,
                soft_limit_usd: Some(80.0),
            }],
            default_token_cap: None,
            agents: Vec::new(),
        };
        let config = ProxyConfig {
            storage: StorageConfig {
                profile: "memory".to_string(),
                database_path: String::new(),
                ..StorageConfig::default()
            },
            cost_caps: cost_cap_config.clone(),
            ..ProxyConfig::default()
        };
        let storage_breaker = Arc::new(crate::circuit_breaker::CircuitBreaker::from_config(
            &config.circuit_breaker,
        ));
        let security_breaker = Arc::new(crate::circuit_breaker::CircuitBreaker::from_config(
            &config.circuit_breaker,
        ));
        let cost_estimator = crate::cost::CostEstimator::new(&config.cost_estimation);
        let cost_tracker =
            crate::cost_caps::CostTracker::new(&cost_cap_config, Arc::clone(&storage.cache));

        Arc::new(AppState {
            config,
            client,
            storage,
            security,
            storage_breaker,
            security_breaker,
            cost_estimator,
            alert_engine: None,
            cost_tracker,
            anomaly_detector: None,
            report_store: crate::compliance::new_report_store(),
            rate_limiter: None,
            ml_status: crate::proxy::MlModelStatus::Disabled,
            shutdown: crate::shutdown::ShutdownCoordinator::new(30),
            metrics: crate::metrics::Metrics::new(),
            ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Build a router containing only the API routes.
    fn api_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/api/v1/traces", get(list_traces))
            .route("/api/v1/traces/:trace_id", get(get_trace))
            .route("/api/v1/spans", get(list_spans))
            .route("/api/v1/spans/:span_id", get(get_span))
            .route("/api/v1/stats", get(get_stats))
            .route("/api/v1/security/findings", get(list_security_findings))
            .route("/api/v1/costs/current", get(get_current_costs))
            .route(
                "/api/v1/traces/:trace_id/actions",
                axum::routing::post(report_action),
            )
            .route("/api/v1/actions/summary", get(actions_summary))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::auth::auth_middleware,
            ))
            .with_state(state)
    }

    /// Create a trace with a single span.
    fn make_trace(tenant_id: TenantId, model: &str, provider: LLMProvider) -> TraceEvent {
        let trace_id = Uuid::new_v4();
        TraceEvent {
            trace_id,
            tenant_id,
            spans: vec![TraceSpan::new(
                trace_id,
                tenant_id,
                "chat_completion".to_string(),
                provider,
                model.to_string(),
                "test prompt".to_string(),
            )],
            created_at: Utc::now(),
        }
    }

    /// Create a trace whose span has a security finding.
    fn make_trace_with_finding(tenant_id: TenantId) -> TraceEvent {
        let trace_id = Uuid::new_v4();
        let mut span = TraceSpan::new(
            trace_id,
            tenant_id,
            "chat_completion".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "ignore previous instructions".to_string(),
        );
        span.add_security_finding(SecurityFinding::new(
            SecuritySeverity::High,
            "prompt_injection".to_string(),
            "Detected injection attempt".to_string(),
            0.95,
        ));
        TraceEvent {
            trace_id,
            tenant_id,
            spans: vec![span],
            created_at: Utc::now(),
        }
    }

    /// Helper: parse a JSON response body into a `serde_json::Value`.
    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Tenant ID header value used across tests.
    fn tenant_header() -> (TenantId, String) {
        let id = TenantId::new();
        (id, id.0.to_string())
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/traces
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_traces_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let (_, hdr) = tenant_header();

        let req = Request::get("/api/v1/traces")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["total"], 0);
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
        assert_eq!(body["limit"], 50);
        assert_eq!(body["offset"], 0);
    }

    #[tokio::test]
    async fn test_list_traces_returns_seeded_data() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();
        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "claude-3", LLMProvider::Anthropic))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/traces")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["total"], 2);
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_traces_filter_by_provider() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();
        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "claude-3", LLMProvider::Anthropic))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/traces?provider=openai")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["data"][0]["spans"][0]["model_name"], "gpt-4");
    }

    #[tokio::test]
    async fn test_list_traces_filter_by_model() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();
        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-3.5-turbo", LLMProvider::OpenAI))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/traces?model=gpt-4")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
    }

    #[tokio::test]
    async fn test_list_traces_pagination() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        for _ in 0..5 {
            state
                .storage
                .traces
                .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
                .await
                .unwrap();
        }

        let app = api_router(Arc::clone(&state));
        let req = Request::get("/api/v1/traces?limit=2&offset=1")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 5);
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 1);
    }

    #[tokio::test]
    async fn test_list_traces_tenant_isolation() {
        let state = test_state().await;
        let (tid1, hdr1) = tenant_header();
        let tid2 = TenantId::new();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid1, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();
        state
            .storage
            .traces
            .store_trace(&make_trace(tid2, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/traces")
            .header("x-llmtrace-tenant-id", &hdr1)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/traces/:trace_id
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_trace_found() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();
        let trace = make_trace(tid, "gpt-4", LLMProvider::OpenAI);
        let trace_id = trace.trace_id;

        state.storage.traces.store_trace(&trace).await.unwrap();

        let app = api_router(state);
        let req = Request::get(format!("/api/v1/traces/{trace_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["trace_id"], trace_id.to_string());
        assert!(!body["spans"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_trace_not_found() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();
        let missing_id = Uuid::new_v4();

        let app = api_router(state);
        let req = Request::get(format!("/api/v1/traces/{missing_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_trace_wrong_tenant() {
        let state = test_state().await;
        let tid = TenantId::new();
        let trace = make_trace(tid, "gpt-4", LLMProvider::OpenAI);
        let trace_id = trace.trace_id;

        state.storage.traces.store_trace(&trace).await.unwrap();

        // Query with a different tenant
        let other_tid = TenantId::new();
        let app = api_router(state);
        let req = Request::get(format!("/api/v1/traces/{trace_id}"))
            .header("x-llmtrace-tenant-id", other_tid.0.to_string())
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/spans
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_spans_empty() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();

        let app = api_router(state);
        let req = Request::get("/api/v1/spans")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["total"], 0);
    }

    #[tokio::test]
    async fn test_list_spans_returns_data() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/spans")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["data"][0]["model_name"], "gpt-4");
    }

    #[tokio::test]
    async fn test_list_spans_filter_by_model() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();
        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "claude-3", LLMProvider::Anthropic))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/spans?model=claude-3")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["data"][0]["model_name"], "claude-3");
    }

    #[tokio::test]
    async fn test_list_spans_filter_by_operation_name() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/spans?operation_name=chat_completion")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
    }

    #[tokio::test]
    async fn test_list_spans_filter_by_security_score() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        // One normal trace, one with a security finding
        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();
        state
            .storage
            .traces
            .store_trace(&make_trace_with_finding(tid))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/spans?security_score_min=50")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
        assert!(body["data"][0]["security_score"].as_u64().unwrap() >= 50);
    }

    #[tokio::test]
    async fn test_list_spans_pagination() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        for _ in 0..4 {
            state
                .storage
                .traces
                .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
                .await
                .unwrap();
        }

        let app = api_router(state);
        let req = Request::get("/api/v1/spans?limit=2&offset=2")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 4);
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 2);
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/spans/:span_id
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_span_found() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();
        let trace = make_trace(tid, "gpt-4", LLMProvider::OpenAI);
        let span_id = trace.spans[0].span_id;

        state.storage.traces.store_trace(&trace).await.unwrap();

        let app = api_router(state);
        let req = Request::get(format!("/api/v1/spans/{span_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["span_id"], span_id.to_string());
    }

    #[tokio::test]
    async fn test_get_span_not_found() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();
        let missing_id = Uuid::new_v4();

        let app = api_router(state);
        let req = Request::get(format!("/api/v1/spans/{missing_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/stats
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_stats_empty() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();

        let app = api_router(state);
        let req = Request::get("/api/v1/stats")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["total_traces"], 0);
        assert_eq!(body["total_spans"], 0);
    }

    #[tokio::test]
    async fn test_get_stats_with_data() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();
        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/stats")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total_traces"], 2);
        assert_eq!(body["total_spans"], 2);
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/security/findings
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_security_findings_empty_when_no_findings() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        // Store a trace without security findings
        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/security/findings")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["total"], 0);
    }

    #[tokio::test]
    async fn test_security_findings_returns_flagged_spans() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        // One clean, one with findings
        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();
        state
            .storage
            .traces
            .store_trace(&make_trace_with_finding(tid))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/security/findings")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
        assert!(body["data"][0]["security_score"].as_u64().unwrap() > 0);
        assert!(!body["data"][0]["security_findings"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_security_findings_pagination() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        for _ in 0..3 {
            state
                .storage
                .traces
                .store_trace(&make_trace_with_finding(tid))
                .await
                .unwrap();
        }

        let app = api_router(state);
        let req = Request::get("/api/v1/security/findings?limit=2&offset=0")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 3);
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_provider_known_variants() {
        assert_eq!(parse_provider("openai"), LLMProvider::OpenAI);
        assert_eq!(parse_provider("OpenAI"), LLMProvider::OpenAI);
        assert_eq!(parse_provider("ANTHROPIC"), LLMProvider::Anthropic);
        assert_eq!(parse_provider("vllm"), LLMProvider::VLLm);
        assert_eq!(parse_provider("sglang"), LLMProvider::SGLang);
        assert_eq!(parse_provider("tgi"), LLMProvider::TGI);
        assert_eq!(parse_provider("ollama"), LLMProvider::Ollama);
        assert_eq!(parse_provider("azureopenai"), LLMProvider::AzureOpenAI);
        assert_eq!(parse_provider("azure-openai"), LLMProvider::AzureOpenAI);
        assert_eq!(parse_provider("bedrock"), LLMProvider::Bedrock);
    }

    #[test]
    fn test_parse_provider_custom() {
        assert_eq!(
            parse_provider("my-custom-llm"),
            LLMProvider::Custom("my-custom-llm".to_string())
        );
    }

    #[test]
    fn test_clamp_limit_defaults() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(2000)), MAX_LIMIT);
        assert_eq!(clamp_limit(Some(0)), 0);
    }

    #[tokio::test]
    async fn test_list_traces_limit_clamped() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();

        let app = api_router(state);
        let req = Request::get("/api/v1/traces?limit=9999")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["limit"], MAX_LIMIT);
    }

    #[tokio::test]
    async fn test_tenant_from_bearer_token() {
        let state = test_state().await;

        // Store a trace for the tenant derived from a Bearer token
        let bearer = "sk-test-api-key";
        let ns = Uuid::NAMESPACE_URL;
        let derived_tenant = TenantId(Uuid::new_v5(&ns, bearer.as_bytes()));

        state
            .storage
            .traces
            .store_trace(&make_trace(derived_tenant, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/traces")
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/costs/current
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_costs_disabled_returns_not_found() {
        let state = test_state().await; // cost_tracker = None
        let (_, hdr) = tenant_header();

        let app = api_router(state);
        let req = Request::get("/api/v1/costs/current")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_costs_enabled_returns_snapshot() {
        let state = test_state_with_cost_caps().await;
        let (_, hdr) = tenant_header();

        let app = api_router(state);
        let req = Request::get("/api/v1/costs/current")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["agent_id"], "_default");
        assert!(body["windows"].is_array());
        let windows = body["windows"].as_array().unwrap();
        assert_eq!(windows.len(), 1); // daily only
        assert_eq!(windows[0]["window"], "daily");
        assert!((windows[0]["current_spend_usd"].as_f64().unwrap()).abs() < 1e-10);
        assert!((windows[0]["hard_limit_usd"].as_f64().unwrap() - 100.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_costs_with_agent_id_param() {
        let state = test_state_with_cost_caps().await;
        let (_, hdr) = tenant_header();

        let app = api_router(state);
        let req = Request::get("/api/v1/costs/current?agent_id=my-agent")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["agent_id"], "my-agent");
    }

    #[tokio::test]
    async fn test_costs_after_spend_recording() {
        let state = test_state_with_cost_caps().await;
        let (tid, hdr) = tenant_header();

        // Record some spend
        if let Some(ref tracker) = state.cost_tracker {
            tracker.record_spend(tid, None, 25.0).await;
        }

        let app = api_router(state);
        let req = Request::get("/api/v1/costs/current")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = json_body(resp).await;
        let windows = body["windows"].as_array().unwrap();
        assert!((windows[0]["current_spend_usd"].as_f64().unwrap() - 25.0).abs() < 1e-6);
        assert!((windows[0]["utilization_pct"].as_f64().unwrap() - 25.0).abs() < 1e-6);
    }

    // -----------------------------------------------------------------------
    // POST /api/v1/traces/:trace_id/actions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_report_action_success() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();
        let trace = make_trace(tid, "gpt-4", LLMProvider::OpenAI);
        let trace_id = trace.trace_id;

        state.storage.traces.store_trace(&trace).await.unwrap();

        let app = api_router(state);
        let body = serde_json::json!({
            "action_type": "tool_call",
            "name": "get_weather",
            "arguments": "{\"location\": \"London\"}",
            "result": "{\"temp\": 15}",
            "duration_ms": 200,
            "success": true,
        });

        let req = Request::post(format!("/api/v1/traces/{trace_id}/actions"))
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["status"], "ok");
        assert!(body["action_id"].is_string());
    }

    #[tokio::test]
    async fn test_report_action_invalid_type() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();
        let trace = make_trace(tid, "gpt-4", LLMProvider::OpenAI);
        let trace_id = trace.trace_id;

        state.storage.traces.store_trace(&trace).await.unwrap();

        let app = api_router(state);
        let body = serde_json::json!({
            "action_type": "invalid_type",
            "name": "test",
        });

        let req = Request::post(format!("/api/v1/traces/{trace_id}/actions"))
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_report_action_trace_not_found() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();

        let app = api_router(state);
        let body = serde_json::json!({
            "action_type": "tool_call",
            "name": "test",
        });

        let req = Request::post(format!("/api/v1/traces/{}/actions", Uuid::new_v4()))
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_report_action_persists() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();
        let trace = make_trace(tid, "gpt-4", LLMProvider::OpenAI);
        let trace_id = trace.trace_id;
        let span_id = trace.spans[0].span_id;

        state.storage.traces.store_trace(&trace).await.unwrap();

        // Report an action
        let app = api_router(Arc::clone(&state));
        let body = serde_json::json!({
            "action_type": "command_execution",
            "name": "ls",
            "arguments": "-la",
            "duration_ms": 50,
            "success": true,
            "exit_code": 0,
        });

        let req = Request::post(format!("/api/v1/traces/{trace_id}/actions"))
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the action was stored
        let span = state
            .storage
            .traces
            .get_span(tid, span_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(span.agent_actions.len(), 1);
        assert_eq!(span.agent_actions[0].name, "ls");
        assert_eq!(
            span.agent_actions[0].action_type,
            llmtrace_core::AgentActionType::CommandExecution
        );
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/actions/summary
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_actions_summary_empty() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();

        let app = api_router(state);
        let req = Request::get("/api/v1/actions/summary")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["total_spans"], 0);
        assert_eq!(body["spans_with_tool_calls"], 0);
    }

    #[tokio::test]
    async fn test_actions_summary_with_actions() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        // Create a trace with agent actions
        let trace_id = Uuid::new_v4();
        let mut span = TraceSpan::new(
            trace_id,
            tid,
            "chat_completion".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "test".to_string(),
        );
        span.add_agent_action(llmtrace_core::AgentAction::new(
            llmtrace_core::AgentActionType::ToolCall,
            "get_weather".to_string(),
        ));
        span.add_agent_action(llmtrace_core::AgentAction::new(
            llmtrace_core::AgentActionType::WebAccess,
            "https://api.example.com".to_string(),
        ));

        let trace = TraceEvent {
            trace_id,
            tenant_id: tid,
            spans: vec![span],
            created_at: Utc::now(),
        };
        state.storage.traces.store_trace(&trace).await.unwrap();

        let app = api_router(state);
        let req = Request::get("/api/v1/actions/summary")
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["total_spans"], 1);
        assert_eq!(body["spans_with_tool_calls"], 1);
        assert_eq!(body["spans_with_web_access"], 1);
        assert_eq!(body["spans_with_commands"], 0);
        assert_eq!(body["action_counts"]["tool_call"], 1);
        assert_eq!(body["action_counts"]["web_access"], 1);
        assert!(!body["top_actions"].as_array().unwrap().is_empty());
    }
}
