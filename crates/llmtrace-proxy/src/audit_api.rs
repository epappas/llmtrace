//! Audit log query API.
//!
//! Exposes `GET /api/v1/audit` which returns audit events recorded for the
//! authenticated tenant. Admin-only; the tenant is resolved from the
//! `AuthContext` injected by the auth middleware — operators can never see
//! events from another tenant via this endpoint.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use chrono::{DateTime, Utc};
use llmtrace_core::{ApiKeyRole, AuditQuery, AuthContext};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default page size when no `limit` is supplied.
const DEFAULT_LIMIT: u32 = 100;

/// Hard upper bound for the page size — protects the database from huge scans.
const MAX_LIMIT: u32 = 1000;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Query parameters accepted by `GET /api/v1/audit`.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListAuditParams {
    /// Filter by event type (e.g. `tenant_created`, `api_key_created`).
    pub event_type: Option<String>,
    /// Inclusive start of the time window (RFC 3339).
    #[param(value_type = String, format = "date-time")]
    pub start_time: Option<DateTime<Utc>>,
    /// Inclusive end of the time window (RFC 3339).
    #[param(value_type = String, format = "date-time")]
    pub end_time: Option<DateTime<Utc>>,
    /// Maximum number of results (default 100, max 1000).
    pub limit: Option<u32>,
    /// Number of results to skip (default 0).
    pub offset: Option<u32>,
}

/// API error response body.
#[derive(Debug, Serialize, ToSchema)]
struct ApiError {
    error: ApiErrorDetail,
}

/// Inner error detail.
#[derive(Debug, Serialize, ToSchema)]
struct ApiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Clamp `limit` to `[1, MAX_LIMIT]`. Logs a warning when the request value is
/// reduced so operators can spot abusive clients.
fn clamp_limit(requested: Option<u32>) -> u32 {
    let raw = requested.unwrap_or(DEFAULT_LIMIT);
    if raw > MAX_LIMIT {
        tracing::warn!(
            requested = raw,
            max = MAX_LIMIT,
            "audit query limit clamped"
        );
        MAX_LIMIT
    } else if raw == 0 {
        DEFAULT_LIMIT
    } else {
        raw
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /api/v1/audit` — list audit events for the authenticated tenant.
///
/// Admin-only. The tenant is derived from the authenticated principal — no
/// `tenant_id` parameter is accepted. Results are filtered server-side and
/// returned newest-first (delegated to the storage layer).
#[utoipa::path(
    get,
    path = "/api/v1/audit",
    params(
        ListAuditParams
    ),
    responses(
        (status = 200, description = "Audit events for the authenticated tenant", body = [llmtrace_core::AuditEvent]),
        (status = 400, description = "Missing tenant context", body = ApiError),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden — requires admin role", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
pub async fn list_audit_events(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListAuditParams>,
) -> Response {
    if !auth.role.has_permission(ApiKeyRole::Admin) {
        return api_error(
            StatusCode::FORBIDDEN,
            "Insufficient permissions: requires admin role",
        );
    }

    let limit = clamp_limit(params.limit);
    let offset = params.offset.unwrap_or(0);

    let query = AuditQuery {
        tenant_id: auth.tenant_id,
        event_type: params.event_type,
        start_time: params.start_time,
        end_time: params.end_time,
        limit: Some(limit),
        offset: Some(offset),
    };

    match state.metadata().query_audit_events(&query).await {
        Ok(events) => Json(events).into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to query audit events: {e}"),
        ),
    }
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
    use chrono::Utc;
    use llmtrace_core::{
        ApiKeyRecord, ApiKeyRole, AuditEvent, AuthConfig, ProxyConfig, SecurityAnalyzer,
        StorageConfig, Tenant, TenantId,
    };
    use llmtrace_security::RegexSecurityAnalyzer;
    use llmtrace_storage::StorageProfile;
    use tower::ServiceExt;
    use uuid::Uuid;

    /// Build shared state with auth enabled and a known admin key.
    async fn auth_state(admin_key: &str) -> Arc<AppState> {
        let storage = StorageProfile::Memory.build().await.unwrap();
        let security = Arc::new(RegexSecurityAnalyzer::new().unwrap()) as Arc<dyn SecurityAnalyzer>;
        let client = reqwest::Client::new();
        let config = ProxyConfig {
            storage: StorageConfig {
                profile: "memory".to_string(),
                database_path: String::new(),
                ..StorageConfig::default()
            },
            auth: AuthConfig {
                enabled: true,
                admin_key: Some(admin_key.to_string()),
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
        let cost_tracker =
            crate::cost_caps::CostTracker::new(&config.cost_caps, Arc::clone(&storage.cache));
        let rate_limiter =
            crate::rate_limit::RateLimiter::new(&config.rate_limiting, Arc::clone(&storage.cache));

        Arc::new(AppState {
            config_handle: crate::config_handle::ConfigHandle::new(config, None, None),
            client,
            storage,
            fast_analyzer: security.clone(),
            security,
            #[cfg(feature = "ml")]
            security_ensemble: None,
            ensemble_runtime: std::sync::Arc::new(llmtrace_security::EnsembleRuntimeHandle::inert()),
            storage_breaker,
            security_breaker,
            cost_estimator,
            alert_engine: None,
            cost_tracker,
            anomaly_detector: None,
            action_router: crate::action_router::ActionRouter::new(
                &llmtrace_core::ActionRouterConfig::default(),
                llmtrace_core::JudgePromotionConfig::default(),
                llmtrace_core::JudgeWorkerConfig::default().max_analysis_text_bytes,
                None,
                reqwest::Client::new(),
            ),
            report_store: crate::compliance::new_report_store(),
            rate_limiter,
            ml_status: crate::proxy::MlModelStatus::Disabled,
            judge_worker_spawned: false,
            runtime_overlay_status: crate::proxy::RuntimeOverlayStatus::Disabled,
            shutdown: crate::shutdown::ShutdownCoordinator::new(30),
            metrics: crate::metrics::Metrics::new(),
            ml_pipeline_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(8)),
            ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Build a router with the audit handler behind the real auth middleware.
    fn audit_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/api/v1/audit", get(super::list_audit_events))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::auth::auth_middleware,
            ))
            .with_state(state)
    }

    /// Parse a JSON response body.
    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Insert a tenant and a key with the requested role into storage.
    async fn provision_key(state: &Arc<AppState>, role: ApiKeyRole) -> (Tenant, String) {
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Test Tenant".to_string(),
            api_token: format!("token-{}", Uuid::new_v4()),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let (plaintext, hash) = crate::auth::generate_api_key();
        let record = ApiKeyRecord {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            name: format!("{role}-key"),
            key_hash: hash,
            key_prefix: crate::auth::key_prefix(&plaintext),
            role,
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.metadata().create_api_key(&record).await.unwrap();
        (tenant, plaintext)
    }

    /// Record a single audit event for a tenant.
    async fn record_event(
        state: &Arc<AppState>,
        tenant_id: TenantId,
        event_type: &str,
    ) -> AuditEvent {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id,
            event_type: event_type.to_string(),
            actor: "test".to_string(),
            resource: format!("resource:{}", Uuid::new_v4()),
            data: serde_json::json!({"key": "value"}),
            timestamp: Utc::now(),
        };
        state.metadata().record_audit_event(&event).await.unwrap();
        event
    }

    #[test]
    fn test_clamp_limit_default() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
    }

    #[test]
    fn test_clamp_limit_explicit_within_range() {
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(MAX_LIMIT)), MAX_LIMIT);
    }

    #[test]
    fn test_clamp_limit_exceeds_max() {
        assert_eq!(clamp_limit(Some(999_999)), MAX_LIMIT);
    }

    #[test]
    fn test_clamp_limit_zero_falls_back_to_default() {
        assert_eq!(clamp_limit(Some(0)), DEFAULT_LIMIT);
    }

    #[tokio::test]
    async fn test_audit_endpoint_rejects_unauthenticated() {
        let state = auth_state("admin-secret").await;
        let app = audit_router(state);

        let req = Request::get("/api/v1/audit").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_audit_endpoint_rejects_operator_role() {
        let state = auth_state("admin-secret").await;
        let (_tenant, plaintext) = provision_key(&state, ApiKeyRole::Operator).await;

        let app = audit_router(Arc::clone(&state));
        let req = Request::get("/api/v1/audit")
            .header("authorization", format!("Bearer {plaintext}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_audit_endpoint_returns_events_for_admin() {
        let state = auth_state("admin-secret").await;
        let (tenant, plaintext) = provision_key(&state, ApiKeyRole::Admin).await;
        let event = record_event(&state, tenant.id, "tenant_created").await;

        let app = audit_router(Arc::clone(&state));
        let req = Request::get("/api/v1/audit")
            .header("authorization", format!("Bearer {plaintext}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        let arr = body.as_array().expect("response must be a JSON array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], event.id.to_string());
        assert_eq!(arr[0]["event_type"], "tenant_created");
        assert_eq!(arr[0]["tenant_id"], tenant.id.0.to_string());
        // Ensure the locked response shape matches AuditEvent.
        for field in [
            "id",
            "tenant_id",
            "event_type",
            "actor",
            "resource",
            "data",
            "timestamp",
        ] {
            assert!(arr[0].get(field).is_some(), "missing field {field}");
        }
    }

    #[tokio::test]
    async fn test_audit_endpoint_filters_by_event_type() {
        let state = auth_state("admin-secret").await;
        let (tenant, plaintext) = provision_key(&state, ApiKeyRole::Admin).await;
        record_event(&state, tenant.id, "tenant_created").await;
        record_event(&state, tenant.id, "api_key_created").await;

        let app = audit_router(Arc::clone(&state));
        let req = Request::get("/api/v1/audit?event_type=tenant_created")
            .header("authorization", format!("Bearer {plaintext}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["event_type"], "tenant_created");
    }

    #[tokio::test]
    async fn test_audit_endpoint_honours_explicit_limit() {
        let state = auth_state("admin-secret").await;
        let (tenant, plaintext) = provision_key(&state, ApiKeyRole::Admin).await;
        for _ in 0..3 {
            record_event(&state, tenant.id, "config_changed").await;
        }

        let app = audit_router(Arc::clone(&state));
        let req = Request::get("/api/v1/audit?limit=2")
            .header("authorization", format!("Bearer {plaintext}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_audit_endpoint_tenant_isolation() {
        let state = auth_state("admin-secret").await;
        let (tenant_a, key_a) = provision_key(&state, ApiKeyRole::Admin).await;
        let (tenant_b, _key_b) = provision_key(&state, ApiKeyRole::Admin).await;

        // Tenant A and B each get one event.
        record_event(&state, tenant_a.id, "tenant_created").await;
        record_event(&state, tenant_b.id, "tenant_created").await;

        // Tenant A's key should ONLY see tenant A's event.
        let app = audit_router(Arc::clone(&state));
        let req = Request::get("/api/v1/audit")
            .header("authorization", format!("Bearer {key_a}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["tenant_id"], tenant_a.id.0.to_string());
        assert_ne!(arr[0]["tenant_id"], tenant_b.id.0.to_string());
    }
}
