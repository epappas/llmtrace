//! Compliance report generation for SOC2, GDPR, and HIPAA.
//!
//! Queries audit events, security findings, and access logs for a
//! configurable time period and produces structured JSON reports.
//! Reports are stored in-memory and retrievable by ID.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use chrono::{DateTime, Utc};
use llmtrace_core::{ApiKeyRole, AuditQuery, AuthContext, TraceQuery};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// Supported compliance report types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    /// SOC2 audit trail report — covers audit events, access patterns,
    /// and security findings for a time period.
    Soc2,
    /// GDPR data processing records — tracks data processing activities
    /// including what data was processed and by whom.
    Gdpr,
    /// HIPAA access logs — records all access to protected information,
    /// including who accessed what and when.
    Hipaa,
}

impl std::fmt::Display for ReportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Soc2 => write!(f, "soc2"),
            Self::Gdpr => write!(f, "gdpr"),
            Self::Hipaa => write!(f, "hipaa"),
        }
    }
}

/// Status of a generated report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Report generation is in progress.
    Pending,
    /// Report generation completed successfully.
    Completed,
    /// Report generation failed.
    Failed,
}

// ---------------------------------------------------------------------------
// SOC2 report sections
// ---------------------------------------------------------------------------

/// SOC2 audit trail report content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soc2Report {
    /// Total number of audit events in the period.
    pub total_audit_events: u64,
    /// Audit events grouped by event type.
    pub events_by_type: HashMap<String, u64>,
    /// Total number of security findings in the period.
    pub total_security_findings: u64,
    /// Security findings grouped by severity.
    pub findings_by_severity: HashMap<String, u64>,
    /// Total traces processed in the period.
    pub total_traces_processed: u64,
    /// Unique actors (users/keys) that performed actions.
    pub unique_actors: Vec<String>,
    /// Access control summary: key management events.
    pub access_control_events: u64,
}

// ---------------------------------------------------------------------------
// GDPR report sections
// ---------------------------------------------------------------------------

/// GDPR data processing records report content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdprReport {
    /// Total data processing activities (traces) in the period.
    pub total_processing_activities: u64,
    /// Data processing grouped by LLM provider.
    pub processing_by_provider: HashMap<String, u64>,
    /// Data processing grouped by model.
    pub processing_by_model: HashMap<String, u64>,
    /// Total PII-related security findings detected.
    pub pii_findings: u64,
    /// Total audit events recording data lifecycle actions.
    pub data_lifecycle_events: u64,
    /// Unique tenants whose data was processed.
    pub tenants_processed: u64,
}

// ---------------------------------------------------------------------------
// HIPAA report sections
// ---------------------------------------------------------------------------

/// HIPAA access log report content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaReport {
    /// Total access events (traces) in the period.
    pub total_access_events: u64,
    /// Access events grouped by operation type.
    pub access_by_operation: HashMap<String, u64>,
    /// Unique actors who accessed data.
    pub unique_accessors: Vec<String>,
    /// Total security findings related to unauthorized access.
    pub unauthorized_access_findings: u64,
    /// Failed access attempts (traces with errors).
    pub failed_access_attempts: u64,
    /// Audit events related to access control changes.
    pub access_control_changes: u64,
}

// ---------------------------------------------------------------------------
// Unified report content
// ---------------------------------------------------------------------------

/// Report content — variant depends on the report type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "report_type", content = "data")]
pub enum ReportContent {
    /// SOC2 audit trail.
    #[serde(rename = "soc2")]
    Soc2(Soc2Report),
    /// GDPR data processing records.
    #[serde(rename = "gdpr")]
    Gdpr(GdprReport),
    /// HIPAA access logs.
    #[serde(rename = "hipaa")]
    Hipaa(HipaaReport),
}

// ---------------------------------------------------------------------------
// Stored report
// ---------------------------------------------------------------------------

/// A generated compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Unique report identifier.
    pub id: Uuid,
    /// Tenant that requested the report.
    pub tenant_id: llmtrace_core::TenantId,
    /// Type of compliance report.
    pub report_type: ReportType,
    /// Current status of the report.
    pub status: ReportStatus,
    /// Start of the reporting period.
    pub period_start: DateTime<Utc>,
    /// End of the reporting period.
    pub period_end: DateTime<Utc>,
    /// When the report was requested.
    pub created_at: DateTime<Utc>,
    /// When the report generation completed (if finished).
    pub completed_at: Option<DateTime<Utc>>,
    /// Report content (populated when status is `Completed`).
    pub content: Option<ReportContent>,
    /// Error message (populated when status is `Failed`).
    pub error: Option<String>,
}

/// In-memory store for generated reports, keyed by report ID.
pub type ReportStore = Arc<RwLock<HashMap<Uuid, ComplianceReport>>>;

/// Create a new empty report store.
#[must_use]
pub fn new_report_store() -> ReportStore {
    Arc::new(RwLock::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/reports/generate`.
#[derive(Debug, Deserialize)]
pub struct GenerateReportRequest {
    /// Type of report to generate.
    pub report_type: ReportType,
    /// Start of the reporting period (RFC 3339).
    pub period_start: DateTime<Utc>,
    /// End of the reporting period (RFC 3339).
    pub period_end: DateTime<Utc>,
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/reports/generate` — request a new compliance report.
///
/// Creates a report record in `Pending` status, spawns an async task to
/// gather data and populate the report, then returns the report ID
/// immediately so the caller can poll `GET /api/v1/reports/:id`.
pub async fn generate_report(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<GenerateReportRequest>,
) -> Response {
    if let Some(err) = require_role_operator(&auth) {
        return err;
    }

    if body.period_end <= body.period_start {
        return api_error(
            StatusCode::BAD_REQUEST,
            "period_end must be after period_start",
        );
    }

    let report_id = Uuid::new_v4();
    let tenant_id = auth.tenant_id;

    let report = ComplianceReport {
        id: report_id,
        tenant_id,
        report_type: body.report_type,
        status: ReportStatus::Pending,
        period_start: body.period_start,
        period_end: body.period_end,
        created_at: Utc::now(),
        completed_at: None,
        content: None,
        error: None,
    };

    // Insert the pending report
    {
        let mut store = state.report_store.write().await;
        store.insert(report_id, report);
    }

    // Spawn async generation
    let store = Arc::clone(&state.report_store);
    let metadata = Arc::clone(&state.storage.metadata);
    let traces = Arc::clone(&state.storage.traces);
    let report_type = body.report_type;
    let period_start = body.period_start;
    let period_end = body.period_end;

    tokio::spawn(async move {
        let result = build_report(
            tenant_id,
            report_type,
            period_start,
            period_end,
            metadata.as_ref(),
            traces.as_ref(),
        )
        .await;

        let mut store = store.write().await;
        if let Some(r) = store.get_mut(&report_id) {
            match result {
                Ok(content) => {
                    r.status = ReportStatus::Completed;
                    r.completed_at = Some(Utc::now());
                    r.content = Some(content);
                }
                Err(msg) => {
                    r.status = ReportStatus::Failed;
                    r.completed_at = Some(Utc::now());
                    r.error = Some(msg);
                }
            }
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "id": report_id.to_string(),
            "status": "pending",
        })),
    )
        .into_response()
}

/// `GET /api/v1/reports/:id` — retrieve a compliance report by ID.
///
/// Returns the full report object including content when completed.
pub async fn get_report(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(report_id): Path<Uuid>,
) -> Response {
    if let Some(err) = require_role_viewer(&auth) {
        return err;
    }

    let store = state.report_store.read().await;
    match store.get(&report_id) {
        Some(report) => {
            // Enforce tenant isolation
            if report.tenant_id != auth.tenant_id {
                return api_error(StatusCode::NOT_FOUND, "Report not found");
            }
            Json(report.clone()).into_response()
        }
        None => api_error(StatusCode::NOT_FOUND, "Report not found"),
    }
}

// ---------------------------------------------------------------------------
// Report builders
// ---------------------------------------------------------------------------

/// Build the report content by querying storage.
async fn build_report(
    tenant_id: llmtrace_core::TenantId,
    report_type: ReportType,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    metadata: &dyn llmtrace_core::MetadataRepository,
    traces: &dyn llmtrace_core::TraceRepository,
) -> Result<ReportContent, String> {
    match report_type {
        ReportType::Soc2 => build_soc2(tenant_id, period_start, period_end, metadata, traces)
            .await
            .map(ReportContent::Soc2),
        ReportType::Gdpr => build_gdpr(tenant_id, period_start, period_end, metadata, traces)
            .await
            .map(ReportContent::Gdpr),
        ReportType::Hipaa => build_hipaa(tenant_id, period_start, period_end, metadata, traces)
            .await
            .map(ReportContent::Hipaa),
    }
}

/// Build SOC2 audit trail report.
async fn build_soc2(
    tenant_id: llmtrace_core::TenantId,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    metadata: &dyn llmtrace_core::MetadataRepository,
    traces: &dyn llmtrace_core::TraceRepository,
) -> Result<Soc2Report, String> {
    // Query audit events
    let audit_query = AuditQuery::new(tenant_id).with_time_range(period_start, period_end);
    let audit_events = metadata
        .query_audit_events(&audit_query)
        .await
        .map_err(|e| format!("Failed to query audit events: {e}"))?;

    let total_audit_events = audit_events.len() as u64;

    let mut events_by_type: HashMap<String, u64> = HashMap::new();
    let mut unique_actors_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut access_control_events = 0u64;

    for event in &audit_events {
        *events_by_type.entry(event.event_type.clone()).or_default() += 1;
        unique_actors_set.insert(event.actor.clone());
        if event.event_type.contains("key") || event.event_type.contains("auth") {
            access_control_events += 1;
        }
    }

    // Query traces with security findings
    let trace_query = TraceQuery::new(tenant_id).with_time_range(period_start, period_end);
    let spans = traces
        .query_spans(&trace_query)
        .await
        .map_err(|e| format!("Failed to query spans: {e}"))?;

    let total_traces_processed = traces
        .query_traces(&trace_query)
        .await
        .map_err(|e| format!("Failed to query traces: {e}"))?
        .len() as u64;

    let mut total_security_findings = 0u64;
    let mut findings_by_severity: HashMap<String, u64> = HashMap::new();

    for span in &spans {
        for finding in &span.security_findings {
            total_security_findings += 1;
            *findings_by_severity
                .entry(finding.severity.to_string())
                .or_default() += 1;
        }
    }

    Ok(Soc2Report {
        total_audit_events,
        events_by_type,
        total_security_findings,
        findings_by_severity,
        total_traces_processed,
        unique_actors: unique_actors_set.into_iter().collect(),
        access_control_events,
    })
}

/// Build GDPR data processing records report.
async fn build_gdpr(
    tenant_id: llmtrace_core::TenantId,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    metadata: &dyn llmtrace_core::MetadataRepository,
    traces: &dyn llmtrace_core::TraceRepository,
) -> Result<GdprReport, String> {
    let trace_query = TraceQuery::new(tenant_id).with_time_range(period_start, period_end);
    let trace_events = traces
        .query_traces(&trace_query)
        .await
        .map_err(|e| format!("Failed to query traces: {e}"))?;
    let spans = traces
        .query_spans(&trace_query)
        .await
        .map_err(|e| format!("Failed to query spans: {e}"))?;

    let total_processing_activities = trace_events.len() as u64;

    let mut processing_by_provider: HashMap<String, u64> = HashMap::new();
    let mut processing_by_model: HashMap<String, u64> = HashMap::new();
    let mut pii_findings = 0u64;

    for span in &spans {
        let provider_str = format!("{:?}", span.provider);
        *processing_by_provider.entry(provider_str).or_default() += 1;
        *processing_by_model
            .entry(span.model_name.clone())
            .or_default() += 1;

        for finding in &span.security_findings {
            if finding.finding_type.contains("pii") {
                pii_findings += 1;
            }
        }
    }

    // Audit events related to data lifecycle
    let audit_query = AuditQuery::new(tenant_id).with_time_range(period_start, period_end);
    let audit_events = metadata
        .query_audit_events(&audit_query)
        .await
        .map_err(|e| format!("Failed to query audit events: {e}"))?;
    let data_lifecycle_events = audit_events
        .iter()
        .filter(|e| {
            e.event_type.contains("delete")
                || e.event_type.contains("create")
                || e.event_type.contains("update")
        })
        .count() as u64;

    // Unique tenants (in a multi-tenant context, the caller is one tenant)
    let tenants_processed = 1u64;

    Ok(GdprReport {
        total_processing_activities,
        processing_by_provider,
        processing_by_model,
        pii_findings,
        data_lifecycle_events,
        tenants_processed,
    })
}

/// Build HIPAA access log report.
async fn build_hipaa(
    tenant_id: llmtrace_core::TenantId,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    metadata: &dyn llmtrace_core::MetadataRepository,
    traces: &dyn llmtrace_core::TraceRepository,
) -> Result<HipaaReport, String> {
    let trace_query = TraceQuery::new(tenant_id).with_time_range(period_start, period_end);
    let spans = traces
        .query_spans(&trace_query)
        .await
        .map_err(|e| format!("Failed to query spans: {e}"))?;

    let total_access_events = spans.len() as u64;

    let mut access_by_operation: HashMap<String, u64> = HashMap::new();
    let mut unauthorized_access_findings = 0u64;
    let mut failed_access_attempts = 0u64;

    for span in &spans {
        *access_by_operation
            .entry(span.operation_name.clone())
            .or_default() += 1;

        if span.is_failed() {
            failed_access_attempts += 1;
        }

        for finding in &span.security_findings {
            if finding.finding_type.contains("injection")
                || finding.finding_type.contains("unauthorized")
            {
                unauthorized_access_findings += 1;
            }
        }
    }

    // Audit events for access control changes
    let audit_query = AuditQuery::new(tenant_id).with_time_range(period_start, period_end);
    let audit_events = metadata
        .query_audit_events(&audit_query)
        .await
        .map_err(|e| format!("Failed to query audit events: {e}"))?;

    let mut unique_accessors_set: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut access_control_changes = 0u64;

    for event in &audit_events {
        unique_accessors_set.insert(event.actor.clone());
        if event.event_type.contains("key")
            || event.event_type.contains("auth")
            || event.event_type.contains("tenant")
        {
            access_control_changes += 1;
        }
    }

    Ok(HipaaReport {
        total_access_events,
        access_by_operation,
        unique_accessors: unique_accessors_set.into_iter().collect(),
        unauthorized_access_findings,
        failed_access_attempts,
        access_control_changes,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use llmtrace_core::{
        AuditEvent, LLMProvider, ProxyConfig, SecurityAnalyzer, SecurityFinding, SecuritySeverity,
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
            report_store: new_report_store(),
        })
    }

    /// Build a router containing compliance report routes.
    fn compliance_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/api/v1/reports/generate", post(generate_report))
            .route("/api/v1/reports/:id", get(get_report))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::auth::auth_middleware,
            ))
            .with_state(state)
    }

    /// Helper: parse a JSON response body.
    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn tenant_header() -> (TenantId, String) {
        let id = TenantId::new();
        (id, id.0.to_string())
    }

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

    // -----------------------------------------------------------------------
    // POST /api/v1/reports/generate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_generate_soc2_report() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        // Seed some data
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

        let app = compliance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "report_type": "soc2",
            "period_start": "2020-01-01T00:00:00Z",
            "period_end": "2030-01-01T00:00:00Z",
        });

        let req = Request::post("/api/v1/reports/generate")
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp_body = json_body(resp).await;
        assert_eq!(resp_body["status"], "pending");
        let report_id = resp_body["id"].as_str().unwrap().to_string();

        // Wait for background task to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Retrieve the completed report
        let app = compliance_router(Arc::clone(&state));
        let req = Request::get(&format!("/api/v1/reports/{report_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let report = json_body(resp).await;
        assert_eq!(report["status"], "completed");
        assert_eq!(report["content"]["report_type"], "soc2");
        assert!(
            report["content"]["data"]["total_traces_processed"]
                .as_u64()
                .unwrap()
                >= 2
        );
        assert!(
            report["content"]["data"]["total_security_findings"]
                .as_u64()
                .unwrap()
                >= 1
        );
    }

    #[tokio::test]
    async fn test_generate_gdpr_report() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        state
            .storage
            .traces
            .store_trace(&make_trace(tid, "gpt-4", LLMProvider::OpenAI))
            .await
            .unwrap();

        let app = compliance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "report_type": "gdpr",
            "period_start": "2020-01-01T00:00:00Z",
            "period_end": "2030-01-01T00:00:00Z",
        });

        let req = Request::post("/api/v1/reports/generate")
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp_body = json_body(resp).await;
        let report_id = resp_body["id"].as_str().unwrap().to_string();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let app = compliance_router(Arc::clone(&state));
        let req = Request::get(&format!("/api/v1/reports/{report_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let report = json_body(resp).await;
        assert_eq!(report["status"], "completed");
        assert_eq!(report["content"]["report_type"], "gdpr");
        assert_eq!(report["content"]["data"]["total_processing_activities"], 1);
    }

    #[tokio::test]
    async fn test_generate_hipaa_report() {
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
            .store_trace(&make_trace_with_finding(tid))
            .await
            .unwrap();

        let app = compliance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "report_type": "hipaa",
            "period_start": "2020-01-01T00:00:00Z",
            "period_end": "2030-01-01T00:00:00Z",
        });

        let req = Request::post("/api/v1/reports/generate")
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp_body = json_body(resp).await;
        let report_id = resp_body["id"].as_str().unwrap().to_string();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let app = compliance_router(Arc::clone(&state));
        let req = Request::get(&format!("/api/v1/reports/{report_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let report = json_body(resp).await;
        assert_eq!(report["status"], "completed");
        assert_eq!(report["content"]["report_type"], "hipaa");
        assert!(
            report["content"]["data"]["total_access_events"]
                .as_u64()
                .unwrap()
                >= 2
        );
        assert!(
            report["content"]["data"]["unauthorized_access_findings"]
                .as_u64()
                .unwrap()
                >= 1
        );
    }

    #[tokio::test]
    async fn test_generate_report_invalid_period() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();

        let app = compliance_router(state);
        let body = serde_json::json!({
            "report_type": "soc2",
            "period_start": "2025-06-01T00:00:00Z",
            "period_end": "2025-01-01T00:00:00Z",
        });

        let req = Request::post("/api/v1/reports/generate")
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_report_not_found() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();

        let app = compliance_router(state);
        let req = Request::get(&format!("/api/v1/reports/{}", Uuid::new_v4()))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_report_tenant_isolation() {
        let state = test_state().await;
        let (_tid1, hdr1) = tenant_header();
        let (_tid2, hdr2) = tenant_header();

        // Generate a report as tenant 1
        let app = compliance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "report_type": "soc2",
            "period_start": "2020-01-01T00:00:00Z",
            "period_end": "2030-01-01T00:00:00Z",
        });

        let req = Request::post("/api/v1/reports/generate")
            .header("x-llmtrace-tenant-id", &hdr1)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let resp_body = json_body(resp).await;
        let report_id = resp_body["id"].as_str().unwrap().to_string();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Tenant 2 should not be able to see tenant 1's report
        let app = compliance_router(Arc::clone(&state));
        let req = Request::get(&format!("/api/v1/reports/{report_id}"))
            .header("x-llmtrace-tenant-id", &hdr2)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Tenant 1 can see their own report
        let app = compliance_router(Arc::clone(&state));
        let req = Request::get(&format!("/api/v1/reports/{report_id}"))
            .header("x-llmtrace-tenant-id", &hdr1)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_generate_report_empty_data() {
        let state = test_state().await;
        let (_, hdr) = tenant_header();

        let app = compliance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "report_type": "soc2",
            "period_start": "2020-01-01T00:00:00Z",
            "period_end": "2030-01-01T00:00:00Z",
        });

        let req = Request::post("/api/v1/reports/generate")
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp_body = json_body(resp).await;
        let report_id = resp_body["id"].as_str().unwrap().to_string();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let app = compliance_router(Arc::clone(&state));
        let req = Request::get(&format!("/api/v1/reports/{report_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let report = json_body(resp).await;
        assert_eq!(report["status"], "completed");
        assert_eq!(report["content"]["data"]["total_audit_events"], 0);
        assert_eq!(report["content"]["data"]["total_traces_processed"], 0);
    }

    #[tokio::test]
    async fn test_soc2_report_with_audit_events() {
        let state = test_state().await;
        let (tid, hdr) = tenant_header();

        // Record an audit event
        let event = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id: tid,
            event_type: "key_created".to_string(),
            actor: "admin@example.com".to_string(),
            resource: "api_key".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
        };
        state
            .storage
            .metadata
            .record_audit_event(&event)
            .await
            .unwrap();

        let app = compliance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "report_type": "soc2",
            "period_start": "2020-01-01T00:00:00Z",
            "period_end": "2030-01-01T00:00:00Z",
        });

        let req = Request::post("/api/v1/reports/generate")
            .header("x-llmtrace-tenant-id", &hdr)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let resp_body = json_body(resp).await;
        let report_id = resp_body["id"].as_str().unwrap().to_string();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let app = compliance_router(Arc::clone(&state));
        let req = Request::get(&format!("/api/v1/reports/{report_id}"))
            .header("x-llmtrace-tenant-id", &hdr)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let report = json_body(resp).await;
        assert_eq!(report["status"], "completed");
        assert_eq!(report["content"]["data"]["total_audit_events"], 1);
        assert_eq!(report["content"]["data"]["access_control_events"], 1);
        let actors = report["content"]["data"]["unique_actors"]
            .as_array()
            .unwrap();
        assert!(actors.iter().any(|a| a == "admin@example.com"));
    }

    // -----------------------------------------------------------------------
    // Unit tests for ReportType Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_report_type_display() {
        assert_eq!(ReportType::Soc2.to_string(), "soc2");
        assert_eq!(ReportType::Gdpr.to_string(), "gdpr");
        assert_eq!(ReportType::Hipaa.to_string(), "hipaa");
    }

    #[test]
    fn test_report_type_serde_roundtrip() {
        let json = serde_json::to_string(&ReportType::Soc2).unwrap();
        assert_eq!(json, "\"soc2\"");
        let parsed: ReportType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ReportType::Soc2);
    }
}
