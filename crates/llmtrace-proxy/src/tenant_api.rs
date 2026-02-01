//! Tenant Management API — CRUD operations for tenants and their configurations.
//!
//! Provides endpoints for creating, listing, retrieving, updating, and deleting
//! tenants. Each mutation records an audit event for traceability.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use chrono::Utc;
use llmtrace_core::{ApiKeyRole, AuditEvent, AuthContext, Tenant, TenantId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/tenants`.
#[derive(Debug, Deserialize)]
pub struct CreateTenantRequest {
    /// Human-readable tenant name.
    pub name: String,
    /// Subscription plan (e.g., "free", "pro", "enterprise").
    #[serde(default = "default_plan")]
    pub plan: String,
    /// Optional arbitrary tenant-level configuration.
    #[serde(default = "default_config")]
    pub config: serde_json::Value,
}

/// Request body for `PUT /api/v1/tenants/:id`.
#[derive(Debug, Deserialize)]
pub struct UpdateTenantRequest {
    /// Updated tenant name (optional).
    pub name: Option<String>,
    /// Updated subscription plan (optional).
    pub plan: Option<String>,
    /// Updated configuration (optional).
    pub config: Option<serde_json::Value>,
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

fn default_plan() -> String {
    "default".to_string()
}

fn default_config() -> serde_json::Value {
    serde_json::json!({})
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

/// Record an audit event (best-effort — log but don't fail the request).
///
/// Public variant for use by other modules (e.g. auth).
pub async fn record_audit_for(
    state: &Arc<AppState>,
    tenant_id: TenantId,
    event_type: &str,
    resource: &str,
    data: serde_json::Value,
) {
    record_audit(state, tenant_id, event_type, resource, data).await;
}

/// Record an audit event (best-effort — log but don't fail the request).
async fn record_audit(
    state: &Arc<AppState>,
    tenant_id: TenantId,
    event_type: &str,
    resource: &str,
    data: serde_json::Value,
) {
    let event = AuditEvent {
        id: Uuid::new_v4(),
        tenant_id,
        event_type: event_type.to_string(),
        actor: "api".to_string(),
        resource: resource.to_string(),
        data,
        timestamp: Utc::now(),
    };
    if let Err(e) = state.metadata().record_audit_event(&event).await {
        tracing::warn!(
            tenant_id = %tenant_id,
            event_type = %event_type,
            "Failed to record audit event: {e}"
        );
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Check that the caller has admin role.
fn require_admin(auth: &AuthContext) -> Option<Response> {
    if !auth.role.has_permission(ApiKeyRole::Admin) {
        Some(api_error(
            StatusCode::FORBIDDEN,
            "Insufficient permissions: requires admin role",
        ))
    } else {
        None
    }
}

/// `POST /api/v1/tenants` — create a new tenant.
pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateTenantRequest>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    if body.name.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Tenant name must not be empty");
    }

    let tenant = Tenant {
        id: TenantId::new(),
        name: body.name.clone(),
        plan: body.plan.clone(),
        created_at: Utc::now(),
        config: body.config.clone(),
    };

    match state.metadata().create_tenant(&tenant).await {
        Ok(()) => {
            record_audit(
                &state,
                tenant.id,
                "tenant_created",
                &format!("tenant:{}", tenant.id),
                serde_json::json!({ "name": tenant.name, "plan": tenant.plan }),
            )
            .await;
            (StatusCode::CREATED, Json(tenant)).into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/tenants` — list all tenants.
pub async fn list_tenants(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    match state.metadata().list_tenants().await {
        Ok(tenants) => Json(tenants).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/tenants/:id` — get tenant details.
pub async fn get_tenant(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    let tenant_id = TenantId(id);
    match state.metadata().get_tenant(tenant_id).await {
        Ok(Some(tenant)) => Json(tenant).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "Tenant not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `PUT /api/v1/tenants/:id` — update tenant name, plan, or config.
pub async fn update_tenant(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateTenantRequest>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    let tenant_id = TenantId(id);

    // Fetch existing tenant
    let existing = match state.metadata().get_tenant(tenant_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Tenant not found"),
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let updated = Tenant {
        id: existing.id,
        name: body.name.unwrap_or(existing.name),
        plan: body.plan.unwrap_or(existing.plan),
        created_at: existing.created_at,
        config: body.config.unwrap_or(existing.config),
    };

    match state.metadata().update_tenant(&updated).await {
        Ok(()) => {
            record_audit(
                &state,
                tenant_id,
                "tenant_updated",
                &format!("tenant:{tenant_id}"),
                serde_json::json!({ "name": updated.name, "plan": updated.plan }),
            )
            .await;
            Json(updated).into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `DELETE /api/v1/tenants/:id` — delete a tenant.
pub async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    let tenant_id = TenantId(id);

    // Check existence first so we can return 404 for unknown tenants
    match state.metadata().get_tenant(tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Tenant not found"),
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }

    match state.metadata().delete_tenant(tenant_id).await {
        Ok(()) => {
            record_audit(
                &state,
                tenant_id,
                "tenant_deleted",
                &format!("tenant:{tenant_id}"),
                serde_json::json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Auto-create tenant helper (used by proxy.rs)
// ---------------------------------------------------------------------------

/// Ensure a tenant exists in the metadata repository.
///
/// If the tenant already exists, this is a no-op. If not, a new tenant is
/// created with the given `name` and `"default"` plan. Errors are logged
/// but not propagated — this is best-effort to avoid blocking the proxy.
pub async fn ensure_tenant_exists(state: &Arc<AppState>, tenant_id: TenantId, name: &str) {
    // Fast path: check if the tenant already exists
    match state.metadata().get_tenant(tenant_id).await {
        Ok(Some(_)) => return, // already exists
        Ok(None) => {}         // need to create
        Err(e) => {
            tracing::debug!(
                %tenant_id,
                "Failed to check tenant existence: {e}"
            );
            return;
        }
    }

    let tenant = Tenant {
        id: tenant_id,
        name: name.to_string(),
        plan: "default".to_string(),
        created_at: Utc::now(),
        config: serde_json::json!({}),
    };

    match state.metadata().create_tenant(&tenant).await {
        Ok(()) => {
            tracing::info!(%tenant_id, name = %tenant.name, "Auto-created tenant");
            record_audit(
                state,
                tenant_id,
                "tenant_auto_created",
                &format!("tenant:{tenant_id}"),
                serde_json::json!({ "name": tenant.name, "plan": "default" }),
            )
            .await;
        }
        Err(e) => {
            // Another request may have created it concurrently — that's fine
            tracing::debug!(
                %tenant_id,
                "Auto-create tenant failed (may already exist): {e}"
            );
        }
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
    use axum::routing::{get, post};
    use axum::Router;
    use llmtrace_core::{AuditQuery, ProxyConfig, SecurityAnalyzer, StorageConfig};
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
            ml_status: crate::proxy::MlModelStatus::Disabled,
            shutdown: crate::shutdown::ShutdownCoordinator::new(30),
        })
    }

    /// Build a router containing the tenant API routes.
    fn tenant_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/api/v1/tenants", post(create_tenant).get(list_tenants))
            .route(
                "/api/v1/tenants/:id",
                get(get_tenant).put(update_tenant).delete(delete_tenant),
            )
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

    // -- POST /api/v1/tenants -----------------------------------------------

    #[tokio::test]
    async fn test_create_tenant() {
        let state = test_state().await;
        let app = tenant_router(state);

        let body = serde_json::json!({ "name": "Acme Corp", "plan": "pro" });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = json_body(resp).await;
        assert_eq!(json["name"], "Acme Corp");
        assert_eq!(json["plan"], "pro");
        assert!(json["id"].is_string());
    }

    #[tokio::test]
    async fn test_create_tenant_default_plan() {
        let state = test_state().await;
        let app = tenant_router(state);

        let body = serde_json::json!({ "name": "Test Org" });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = json_body(resp).await;
        assert_eq!(json["plan"], "default");
    }

    #[tokio::test]
    async fn test_create_tenant_with_config() {
        let state = test_state().await;
        let app = tenant_router(state);

        let body = serde_json::json!({
            "name": "Configured Org",
            "plan": "enterprise",
            "config": { "max_traces_per_day": 50000 }
        });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = json_body(resp).await;
        assert_eq!(json["config"]["max_traces_per_day"], 50000);
    }

    #[tokio::test]
    async fn test_create_tenant_empty_name_rejected() {
        let state = test_state().await;
        let app = tenant_router(state);

        let body = serde_json::json!({ "name": "  " });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -- GET /api/v1/tenants ------------------------------------------------

    #[tokio::test]
    async fn test_list_tenants_empty() {
        let state = test_state().await;
        let app = tenant_router(state);

        let req = Request::get("/api/v1/tenants").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = json_body(resp).await;
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_tenants_returns_created() {
        let state = test_state().await;

        // Create two tenants directly via storage
        let t1 = Tenant {
            id: TenantId::new(),
            name: "Alpha".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        let t2 = Tenant {
            id: TenantId::new(),
            name: "Beta".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&t1).await.unwrap();
        state.metadata().create_tenant(&t2).await.unwrap();

        let app = tenant_router(state);
        let req = Request::get("/api/v1/tenants").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = json_body(resp).await;
        assert_eq!(json.as_array().unwrap().len(), 2);
    }

    // -- GET /api/v1/tenants/:id --------------------------------------------

    #[tokio::test]
    async fn test_get_tenant_found() {
        let state = test_state().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Get Me".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(state);
        let req = Request::get(&format!("/api/v1/tenants/{}", tenant.id.0))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = json_body(resp).await;
        assert_eq!(json["name"], "Get Me");
    }

    #[tokio::test]
    async fn test_get_tenant_not_found() {
        let state = test_state().await;
        let app = tenant_router(state);

        let req = Request::get(&format!("/api/v1/tenants/{}", Uuid::new_v4()))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -- PUT /api/v1/tenants/:id --------------------------------------------

    #[tokio::test]
    async fn test_update_tenant_name() {
        let state = test_state().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Old Name".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(state);
        let body = serde_json::json!({ "name": "New Name" });
        let req = Request::put(&format!("/api/v1/tenants/{}", tenant.id.0))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = json_body(resp).await;
        assert_eq!(json["name"], "New Name");
        assert_eq!(json["plan"], "free"); // unchanged
    }

    #[tokio::test]
    async fn test_update_tenant_plan_and_config() {
        let state = test_state().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Org".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(state);
        let body = serde_json::json!({
            "plan": "enterprise",
            "config": { "rate_limit": 1000 }
        });
        let req = Request::put(&format!("/api/v1/tenants/{}", tenant.id.0))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = json_body(resp).await;
        assert_eq!(json["plan"], "enterprise");
        assert_eq!(json["config"]["rate_limit"], 1000);
        assert_eq!(json["name"], "Org"); // unchanged
    }

    #[tokio::test]
    async fn test_update_tenant_not_found() {
        let state = test_state().await;
        let app = tenant_router(state);

        let body = serde_json::json!({ "name": "Ghost" });
        let req = Request::put(&format!("/api/v1/tenants/{}", Uuid::new_v4()))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -- DELETE /api/v1/tenants/:id -----------------------------------------

    #[tokio::test]
    async fn test_delete_tenant() {
        let state = test_state().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "To Delete".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(Arc::clone(&state));
        let req = Request::delete(&format!("/api/v1/tenants/{}", tenant.id.0))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify it's gone
        let result = state.metadata().get_tenant(tenant.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_tenant_not_found() {
        let state = test_state().await;
        let app = tenant_router(state);

        let req = Request::delete(&format!("/api/v1/tenants/{}", Uuid::new_v4()))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -- Audit events -------------------------------------------------------

    #[tokio::test]
    async fn test_create_tenant_records_audit_event() {
        let state = test_state().await;
        let app = tenant_router(Arc::clone(&state));

        let body = serde_json::json!({ "name": "Audited Org", "plan": "pro" });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = json_body(resp).await;
        let tenant_id = TenantId(Uuid::parse_str(json["id"].as_str().unwrap()).unwrap());

        let audit_query = AuditQuery::new(tenant_id);
        let events = state
            .metadata()
            .query_audit_events(&audit_query)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "tenant_created");
    }

    #[tokio::test]
    async fn test_update_tenant_records_audit_event() {
        let state = test_state().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Before Update".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(Arc::clone(&state));
        let body = serde_json::json!({ "name": "After Update" });
        let req = Request::put(&format!("/api/v1/tenants/{}", tenant.id.0))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let audit_query = AuditQuery::new(tenant.id);
        let events = state
            .metadata()
            .query_audit_events(&audit_query)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "tenant_updated");
    }

    #[tokio::test]
    async fn test_delete_tenant_records_audit_event() {
        let state = test_state().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Will Be Deleted".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(Arc::clone(&state));
        let req = Request::delete(&format!("/api/v1/tenants/{}", tenant.id.0))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let audit_query = AuditQuery::new(tenant.id);
        let events = state
            .metadata()
            .query_audit_events(&audit_query)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "tenant_deleted");
    }

    // -- Auto-creation -----------------------------------------------------

    #[tokio::test]
    async fn test_ensure_tenant_exists_creates_new() {
        let state = test_state().await;
        let tenant_id = TenantId::new();

        // Should not exist yet
        assert!(state
            .metadata()
            .get_tenant(tenant_id)
            .await
            .unwrap()
            .is_none());

        ensure_tenant_exists(&state, tenant_id, "auto-test").await;

        let tenant = state
            .metadata()
            .get_tenant(tenant_id)
            .await
            .unwrap()
            .expect("tenant should have been auto-created");
        assert_eq!(tenant.name, "auto-test");
        assert_eq!(tenant.plan, "default");

        // Check audit event was recorded
        let events = state
            .metadata()
            .query_audit_events(&AuditQuery::new(tenant_id))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "tenant_auto_created");
    }

    #[tokio::test]
    async fn test_ensure_tenant_exists_noop_for_existing() {
        let state = test_state().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Already Here".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        // Should be a no-op
        ensure_tenant_exists(&state, tenant.id, "should-not-overwrite").await;

        let after = state
            .metadata()
            .get_tenant(tenant.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.name, "Already Here"); // not overwritten
        assert_eq!(after.plan, "pro"); // not changed to "default"
    }
}
