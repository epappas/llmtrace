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
use utoipa::ToSchema;
use uuid::Uuid;

use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/tenants`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    /// Optional caller-supplied tenant id. Absent => a fresh id is generated.
    /// The Basilica deployment bootstrap supplies a stable id so the SAME
    /// tenant persists across `--strategy recreate` (issue 9). When a tenant
    /// with this id already exists, create is idempotent and returns it
    /// unchanged.
    #[serde(default)]
    pub id: Option<TenantId>,
    /// Human-readable tenant name.
    pub name: String,
    /// Subscription plan (e.g., "free", "pro", "enterprise").
    #[serde(default = "default_plan")]
    pub plan: String,
    /// Optional arbitrary tenant-level configuration.
    #[serde(default = "default_config")]
    pub config: serde_json::Value,
    /// Optional per-tenant upstream base URL override. `null`/absent => inherit
    /// the global `upstream_url`.
    #[serde(default)]
    pub upstream_url: Option<String>,
    /// Optional per-tenant upstream provider API key (write-only). When present
    /// and non-empty it is AEAD-encrypted before storage; `null`/empty clears
    /// it (inherit the global env-based credential). NEVER returned.
    #[serde(default)]
    pub upstream_api_key: Option<String>,
}

/// Public, secret-safe view of a tenant returned by GET/LIST/CREATE/UPDATE.
///
/// Mirrors [`Tenant`] but NEVER exposes the encrypted upstream key. Instead it
/// surfaces `upstream_api_key_set: bool` (CONTRACT 1).
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantView {
    /// Unique tenant identifier.
    pub id: TenantId,
    /// Human-readable tenant name.
    pub name: String,
    /// Unique API token for proxy traffic.
    pub api_token: String,
    /// Subscription plan.
    pub plan: String,
    /// When the tenant was created.
    #[schema(value_type = String, format = "date-time")]
    pub created_at: chrono::DateTime<Utc>,
    /// Arbitrary tenant-level configuration.
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    /// Per-tenant upstream base URL override, or `null` to inherit global.
    pub upstream_url: Option<String>,
    /// Whether a per-tenant upstream API key is set. The secret is never
    /// returned.
    pub upstream_api_key_set: bool,
}

impl From<Tenant> for TenantView {
    fn from(t: Tenant) -> Self {
        Self {
            id: t.id,
            name: t.name,
            api_token: t.api_token,
            plan: t.plan,
            created_at: t.created_at,
            config: t.config,
            upstream_url: t.upstream_url,
            upstream_api_key_set: t.upstream_api_key_ciphertext.is_some(),
        }
    }
}

/// Response body for `POST /api/v1/tenants`.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateTenantResponse {
    /// The created tenant metadata (secret-safe view).
    #[serde(flatten)]
    pub tenant: TenantView,
    /// The plaintext API key (only returned once on creation).
    pub api_key: Option<String>,
}

/// Request body for `PUT /api/v1/tenants/:id`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTenantRequest {
    /// Updated tenant name (optional).
    pub name: Option<String>,
    /// Updated subscription plan (optional).
    pub plan: Option<String>,
    /// Updated configuration (optional).
    pub config: Option<serde_json::Value>,
    /// Updated per-tenant upstream base URL. Present-with-value sets it;
    /// present-and-null/empty clears it (inherit global); absent leaves it
    /// unchanged.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub upstream_url: Option<Option<String>>,
    /// Updated per-tenant upstream API key (write-only). Present-with-value
    /// encrypts + stores it; present-and-null/empty clears it; absent leaves it
    /// unchanged. NEVER returned.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub upstream_api_key: Option<Option<String>>,
}

/// Deserialize a JSON field that may be absent, null, or a value, into a
/// double-`Option`: outer `None` = absent (leave unchanged), inner `None` =
/// explicit null (clear), `Some(v)` = set.
fn deserialize_optional_field<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
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

/// Response body for tenant token endpoints.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantTokenResponse {
    /// Tenant token used for proxy traffic (`X-LLMTrace-Token`).
    pub api_token: String,
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

/// Encrypt a plaintext per-tenant upstream key, failing closed.
///
/// Returns `Ok(Some(ciphertext))` on success, `Ok(None)` when `plaintext` is
/// empty (caller should clear the stored key), or `Err(SecretBoxError)` when the
/// master key is unavailable/invalid (CONTRACT 1 fail-closed). Callers map the
/// error to a `400 Bad Request` via [`upstream_key_error`].
fn encrypt_upstream_key(
    plaintext: &str,
) -> std::result::Result<Option<String>, crate::secretbox::SecretBoxError> {
    if plaintext.is_empty() {
        return Ok(None);
    }
    let secret_box = crate::secretbox::SecretBox::from_env()?;
    let ciphertext = secret_box.encrypt(plaintext.as_bytes())?;
    Ok(Some(ciphertext))
}

/// Build the `400` response for an upstream-key encryption failure
/// (CONTRACT 1 fail-closed).
fn upstream_key_error(e: &crate::secretbox::SecretBoxError) -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        &format!("Cannot store upstream_api_key: {e}"),
    )
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
#[utoipa::path(
    post,
    path = "/api/v1/tenants",
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created", body = CreateTenantResponse),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
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

    // Resolve the tenant id. A caller-supplied id makes create idempotent so the
    // SAME tenant persists across `--strategy recreate` (issue 9): if a tenant
    // with this id already exists, return it unchanged (mirroring the
    // get-or-create semantics of `ensure_tenant_exists`). Absent => fresh id.
    let tenant_id = match body.id {
        Some(id) => match state.metadata().get_tenant(id).await {
            Ok(Some(existing)) => {
                return Json(TenantView::from(existing)).into_response();
            }
            Ok(None) => id,
            Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        },
        None => TenantId::new(),
    };

    let (api_token, _) = crate::auth::generate_api_key(); // Reusing the same generator for tokens

    // Encrypt the optional per-tenant upstream key (fail-closed via 400).
    let upstream_api_key_ciphertext = match body.upstream_api_key.as_deref() {
        Some(key) => match encrypt_upstream_key(key) {
            Ok(ct) => ct,
            Err(e) => return upstream_key_error(&e),
        },
        None => None,
    };
    // Normalise upstream_url: empty/whitespace => inherit (None).
    let upstream_url = body
        .upstream_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let tenant = Tenant {
        id: tenant_id,
        name: body.name.clone(),
        api_token: api_token.clone(),
        plan: body.plan.clone(),
        created_at: Utc::now(),
        config: body.config.clone(),
        upstream_url,
        upstream_api_key_ciphertext,
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

            // Automatically create a default API key for the new tenant
            let (plaintext, hash) = crate::auth::generate_api_key();
            let prefix = crate::auth::key_prefix(&plaintext);
            let key_record = llmtrace_core::ApiKeyRecord {
                id: Uuid::new_v4(),
                tenant_id: tenant.id,
                name: "Default Key".to_string(),
                key_hash: hash,
                key_prefix: prefix.clone(),
                // SECURITY: a tenant's default key is scoped to its OWN
                // tenant only. It must be Operator (full access WITHIN the
                // tenant), never Admin — an Admin key satisfies the
                // `X-LLMTrace-Tenant-Scope: all` guard in auth.rs and could
                // read every tenant's traces (cross-tenant leak).
                role: llmtrace_core::ApiKeyRole::Operator,
                created_at: Utc::now(),
                revoked_at: None,
            };

            if let Err(e) = state.metadata().create_api_key(&key_record).await {
                tracing::error!(tenant_id = %tenant.id, "Failed to auto-generate API key: {e}");
                // Return tenant without key if key generation fails
                let resp = CreateTenantResponse {
                    tenant: TenantView::from(tenant),
                    api_key: None,
                };
                (StatusCode::CREATED, Json(resp)).into_response()
            } else {
                record_audit(
                    &state,
                    tenant.id,
                    "api_key_created",
                    &format!("api_key:{}", key_record.id),
                    serde_json::json!({
                        "key_id": key_record.id.to_string(),
                        "key_prefix": prefix,
                        "role": "operator",
                        "note": "auto-generated on tenant creation"
                    }),
                )
                .await;

                let resp = CreateTenantResponse {
                    tenant: TenantView::from(tenant),
                    api_key: Some(plaintext),
                };
                (StatusCode::CREATED, Json(resp)).into_response()
            }
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/tenants` — list all tenants.
#[utoipa::path(
    get,
    path = "/api/v1/tenants",
    responses(
        (status = 200, description = "Tenants", body = [TenantView]),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
pub async fn list_tenants(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    match state.metadata().list_tenants().await {
        Ok(tenants) => {
            let views: Vec<TenantView> = tenants.into_iter().map(TenantView::from).collect();
            Json(views).into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/tenants/:id` — get tenant details.
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{id}",
    params(
        ("id" = String, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Tenant", body = TenantView),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 404, description = "Tenant not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
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
        Ok(Some(tenant)) => Json(TenantView::from(tenant)).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "Tenant not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `PUT /api/v1/tenants/:id` — update tenant name, plan, or config.
#[utoipa::path(
    put,
    path = "/api/v1/tenants/{id}",
    params(
        ("id" = String, Path, description = "Tenant ID"),
    ),
    request_body = UpdateTenantRequest,
    responses(
        (status = 200, description = "Updated tenant", body = TenantView),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 404, description = "Tenant not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
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

    // Resolve upstream_url: absent => keep; present null/empty => clear; set.
    let upstream_url = match body.upstream_url {
        None => existing.upstream_url,
        Some(opt) => opt
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    };

    // Resolve upstream_api_key: absent => keep ciphertext; present null/empty =>
    // clear; set => encrypt (fail-closed via 400).
    let upstream_api_key_ciphertext = match body.upstream_api_key {
        None => existing.upstream_api_key_ciphertext,
        Some(opt) => match opt.as_deref().unwrap_or("") {
            "" => None,
            key => match encrypt_upstream_key(key) {
                Ok(ct) => ct,
                Err(e) => return upstream_key_error(&e),
            },
        },
    };

    let updated = Tenant {
        id: existing.id,
        name: body.name.unwrap_or(existing.name),
        api_token: existing.api_token,
        plan: body.plan.unwrap_or(existing.plan),
        created_at: existing.created_at,
        config: body.config.unwrap_or(existing.config),
        upstream_url,
        upstream_api_key_ciphertext,
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
            Json(TenantView::from(updated)).into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `DELETE /api/v1/tenants/:id` — delete a tenant.
#[utoipa::path(
    delete,
    path = "/api/v1/tenants/{id}",
    params(
        ("id" = String, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 204, description = "Tenant deleted"),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 404, description = "Tenant not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
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

/// `GET /api/v1/tenants/current/token` — get the API token for the currently authenticated tenant.
#[utoipa::path(
    get,
    path = "/api/v1/tenants/current/token",
    responses(
        (status = 200, description = "Current tenant token", body = TenantTokenResponse),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 404, description = "Tenant not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
pub async fn get_current_tenant_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match state.metadata().get_tenant(auth.tenant_id).await {
        Ok(Some(tenant)) => Json(TenantTokenResponse {
            api_token: tenant.api_token,
        })
        .into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "Tenant not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/v1/tenants/:id/token` — retrieve the API token for a specific tenant (Admin only).
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{id}/token",
    params(
        ("id" = String, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Tenant token", body = TenantTokenResponse),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 404, description = "Tenant not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
pub async fn get_tenant_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    match state.metadata().get_tenant(TenantId(id)).await {
        Ok(Some(tenant)) => Json(TenantTokenResponse {
            api_token: tenant.api_token,
        })
        .into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "Tenant not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `POST /api/v1/tenants/:id/token/reset` — regenerate the API token for a tenant.
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{id}/token/reset",
    params(
        ("id" = String, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "New tenant token", body = TenantTokenResponse),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 404, description = "Tenant not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
pub async fn reset_tenant_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    let tenant_id = TenantId(id);

    // Fetch existing tenant
    let mut tenant = match state.metadata().get_tenant(tenant_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Tenant not found"),
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let (new_token, _) = crate::auth::generate_api_key();
    tenant.api_token = new_token.clone();

    match state.metadata().update_tenant(&tenant).await {
        Ok(()) => {
            record_audit(
                &state,
                tenant_id,
                "tenant_token_reset",
                &format!("tenant:{tenant_id}"),
                serde_json::json!({ "note": "API token regenerated" }),
            )
            .await;
            Json(TenantTokenResponse {
                api_token: new_token,
            })
            .into_response()
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
    // Don't auto-create the Nil/Default tenant in the database
    if tenant_id.0.is_nil() {
        return;
    }

    // Fast path: check if the tenant already exists
    match state.metadata().get_tenant(tenant_id).await {
        Ok(Some(mut tenant)) => {
            // Repair path: if tenant exists but has no api_token, generate one.
            // This handles migrations from older versions.
            if tenant.api_token.is_empty() {
                let (new_token, _) = crate::auth::generate_api_key();
                tenant.api_token = new_token;
                if let Err(e) = state.metadata().update_tenant(&tenant).await {
                    tracing::warn!(%tenant_id, "Failed to repair tenant api_token: {e}");
                } else {
                    tracing::info!(%tenant_id, "Repaired missing api_token for existing tenant");
                }
            }
            return;
        }
        Ok(None) => {} // need to create
        Err(e) => {
            tracing::debug!(
                %tenant_id,
                "Failed to check tenant existence: {e}"
            );
            return;
        }
    }

    let (api_token, _) = crate::auth::generate_api_key();

    let tenant = Tenant {
        id: tenant_id,
        name: name.to_string(),
        api_token,
        plan: "default".to_string(),
        created_at: Utc::now(),
        config: serde_json::json!({}),
        upstream_url: None,
        upstream_api_key_ciphertext: None,
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
        assert!(json["api_key"].is_string());
        assert!(json["api_key"].as_str().unwrap().starts_with("llmt_"));
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

    #[tokio::test]
    async fn test_create_tenant_honors_explicit_id() {
        let state = test_state().await;
        let app = tenant_router(Arc::clone(&state));

        // A fixed, caller-supplied tenant id (Basilica bootstrap supplies a
        // stable id so the SAME tenant persists across redeploy — issue 9).
        let explicit_id = "550e8400-e29b-41d4-a716-446655440000";
        let body = serde_json::json!({ "id": explicit_id, "name": "Stable Org", "plan": "pro" });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = json_body(resp).await;
        // The response id must equal the caller-supplied id, not a random one.
        assert_eq!(json["id"], explicit_id);
        // Fresh creation still surfaces the one-time plaintext api_key.
        assert!(json["api_key"].as_str().unwrap().starts_with("llmt_"));

        // A row with exactly that id must exist in the metadata store.
        let expected = TenantId(Uuid::parse_str(explicit_id).unwrap());
        let stored = state
            .metadata()
            .get_tenant(expected)
            .await
            .unwrap()
            .expect("tenant with explicit id must exist");
        assert_eq!(stored.id, expected);
        assert_eq!(stored.name, "Stable Org");
    }

    #[tokio::test]
    async fn test_create_tenant_idempotent_on_explicit_id() {
        let state = test_state().await;
        let explicit_id = "550e8400-e29b-41d4-a716-446655440000";
        let expected = TenantId(Uuid::parse_str(explicit_id).unwrap());

        // First create with the explicit id.
        let app1 = tenant_router(Arc::clone(&state));
        let body = serde_json::json!({ "id": explicit_id, "name": "First", "plan": "pro" });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp1 = app1.oneshot(req).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);
        let json1 = json_body(resp1).await;
        assert_eq!(json1["id"], explicit_id);

        // Second create with the SAME explicit id (e.g. after `recreate`).
        let app2 = tenant_router(Arc::clone(&state));
        let body2 =
            serde_json::json!({ "id": explicit_id, "name": "Second", "plan": "enterprise" });
        let req2 = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body2).unwrap()))
            .unwrap();
        let resp2 = app2.oneshot(req2).await.unwrap();
        // Idempotent: returns 200 with the existing tenant unchanged.
        assert_eq!(resp2.status(), StatusCode::OK);
        let json2 = json_body(resp2).await;
        assert_eq!(json2["id"], explicit_id);
        // The existing record is returned unchanged (original name kept).
        assert_eq!(json2["name"], "First");

        // Exactly ONE tenant row exists for that id — no duplicate minted.
        let all = state.metadata().list_tenants().await.unwrap();
        let matching: Vec<_> = all.iter().filter(|t| t.id == expected).collect();
        assert_eq!(matching.len(), 1, "must not create a duplicate tenant");
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
            api_token: "token-1".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
        };
        let t2 = Tenant {
            id: TenantId::new(),
            name: "Beta".to_string(),
            api_token: "token-2".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
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
            api_token: "token-get".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(state);
        let req = Request::get(format!("/api/v1/tenants/{}", tenant.id.0))
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

        let req = Request::get(format!("/api/v1/tenants/{}", Uuid::new_v4()))
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
            api_token: "token-old".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(state);
        let body = serde_json::json!({ "name": "New Name" });
        let req = Request::put(format!("/api/v1/tenants/{}", tenant.id.0))
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
            api_token: "token-org".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(state);
        let body = serde_json::json!({
            "plan": "enterprise",
            "config": { "rate_limit": 1000 }
        });
        let req = Request::put(format!("/api/v1/tenants/{}", tenant.id.0))
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
        let req = Request::put(format!("/api/v1/tenants/{}", Uuid::new_v4()))
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
            api_token: "token-delete".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(Arc::clone(&state));
        let req = Request::delete(format!("/api/v1/tenants/{}", tenant.id.0))
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

        let req = Request::delete(format!("/api/v1/tenants/{}", Uuid::new_v4()))
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
        // Tenant creation records both the tenant creation and the auto-generated default API key.
        let mut types: Vec<String> = events.into_iter().map(|e| e.event_type).collect();
        types.sort();
        assert_eq!(
            types,
            vec!["api_key_created".to_string(), "tenant_created".to_string()]
        );
    }

    #[tokio::test]
    async fn test_update_tenant_records_audit_event() {
        let state = test_state().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Before Update".to_string(),
            api_token: "token-audit-update".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(Arc::clone(&state));
        let body = serde_json::json!({ "name": "After Update" });
        let req = Request::put(format!("/api/v1/tenants/{}", tenant.id.0))
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
            api_token: "token-audit-delete".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(Arc::clone(&state));
        let req = Request::delete(format!("/api/v1/tenants/{}", tenant.id.0))
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
        assert!(!tenant.api_token.is_empty());

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
            api_token: "token-already".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: None,
            upstream_api_key_ciphertext: None,
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

    // -- Idempotent bootstrap (issue 9) ------------------------------------

    #[tokio::test]
    async fn test_ensure_tenant_exists_is_idempotent_on_stable_id() {
        let state = test_state().await;
        // A stable, externally-provided tenant id (e.g. user-uuid-...).
        let stable_id = TenantId(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap());

        ensure_tenant_exists(&state, stable_id, "first-call").await;
        let first = state
            .metadata()
            .get_tenant(stable_id)
            .await
            .unwrap()
            .expect("tenant created");

        // Re-provision after a notional redeploy with the SAME id.
        ensure_tenant_exists(&state, stable_id, "second-call").await;

        let all = state.metadata().list_tenants().await.unwrap();
        let matching: Vec<_> = all.iter().filter(|t| t.id == stable_id).collect();
        assert_eq!(matching.len(), 1, "must not mint a duplicate tenant row");

        let second = state
            .metadata()
            .get_tenant(stable_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            second.id, stable_id,
            "tenant id must be stable across calls"
        );
        assert_eq!(second.id, first.id);
        // Existing record is returned unchanged (name not overwritten).
        assert_eq!(second.name, "first-call");
        assert_eq!(second.api_token, first.api_token);
    }

    // -- Per-tenant upstream creds (CONTRACT 1) ----------------------------

    /// A valid 32-byte master key in hex used to exercise encryption paths.
    const TEST_MASTER_KEY: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// Serialises tests that mutate the master-key env var. A tokio mutex is
    /// used so the guard can be safely held across `.await` points.
    static MASTER_KEY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn test_create_tenant_with_upstream_creds_contract() {
        let _guard = MASTER_KEY_LOCK.lock().await;
        std::env::set_var(crate::secretbox::SECRET_ENCRYPTION_KEY_ENV, TEST_MASTER_KEY);
        let state = test_state().await;
        let app = tenant_router(Arc::clone(&state));

        let body = serde_json::json!({
            "name": "Routed Org",
            "upstream_url": "https://tenant.example.com",
            "upstream_api_key": "sk-tenant-secret"
        });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        std::env::remove_var(crate::secretbox::SECRET_ENCRYPTION_KEY_ENV);
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = json_body(resp).await;
        // CONTRACT 1: response surfaces upstream_url + upstream_api_key_set,
        // and NEVER the secret/ciphertext.
        assert_eq!(json["upstream_url"], "https://tenant.example.com");
        assert_eq!(json["upstream_api_key_set"], true);
        assert!(json.get("upstream_api_key").is_none());
        assert!(json.get("upstream_api_key_ciphertext").is_none());

        // The stored ciphertext must NOT contain the plaintext secret.
        let tid = TenantId(Uuid::parse_str(json["id"].as_str().unwrap()).unwrap());
        let stored = state.metadata().get_tenant(tid).await.unwrap().unwrap();
        let ct = stored
            .upstream_api_key_ciphertext
            .expect("ciphertext stored");
        assert!(
            !ct.contains("sk-tenant-secret"),
            "secret must be encrypted at rest"
        );
    }

    #[tokio::test]
    async fn test_create_tenant_upstream_key_fails_closed_without_master_key() {
        let _guard = MASTER_KEY_LOCK.lock().await;
        std::env::remove_var(crate::secretbox::SECRET_ENCRYPTION_KEY_ENV);
        let state = test_state().await;
        let app = tenant_router(state);

        let body = serde_json::json!({
            "name": "No Key Org",
            "upstream_api_key": "sk-should-fail"
        });
        let req = Request::post("/api/v1/tenants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "setting a per-tenant key without a master key must fail closed (400)"
        );
    }

    #[tokio::test]
    async fn test_update_tenant_clears_upstream_key_on_null() {
        let _guard = MASTER_KEY_LOCK.lock().await;
        std::env::set_var(crate::secretbox::SECRET_ENCRYPTION_KEY_ENV, TEST_MASTER_KEY);
        let secret_box = crate::secretbox::SecretBox::from_env().unwrap();
        let ct = secret_box.encrypt(b"sk-existing").unwrap();
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Has Key".to_string(),
            api_token: "token-haskey".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: Some("https://old.example.com".to_string()),
            upstream_api_key_ciphertext: Some(ct),
        };
        let state = test_state().await;
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(Arc::clone(&state));
        // Explicit null clears the key and the url (inherit global).
        let body = serde_json::json!({ "upstream_api_key": null, "upstream_url": null });
        let req = Request::put(format!("/api/v1/tenants/{}", tenant.id.0))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        std::env::remove_var(crate::secretbox::SECRET_ENCRYPTION_KEY_ENV);
        assert_eq!(resp.status(), StatusCode::OK);

        let json = json_body(resp).await;
        assert_eq!(json["upstream_api_key_set"], false);
        assert!(json["upstream_url"].is_null());

        let after = state
            .metadata()
            .get_tenant(tenant.id)
            .await
            .unwrap()
            .unwrap();
        assert!(after.upstream_api_key_ciphertext.is_none());
        assert!(after.upstream_url.is_none());
    }

    #[tokio::test]
    async fn test_update_tenant_absent_upstream_fields_unchanged() {
        let _guard = MASTER_KEY_LOCK.lock().await;
        std::env::set_var(crate::secretbox::SECRET_ENCRYPTION_KEY_ENV, TEST_MASTER_KEY);
        let secret_box = crate::secretbox::SecretBox::from_env().unwrap();
        let ct = secret_box.encrypt(b"sk-keep").unwrap();
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Keep Key".to_string(),
            api_token: "token-keep".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
            upstream_url: Some("https://keep.example.com".to_string()),
            upstream_api_key_ciphertext: Some(ct.clone()),
        };
        let state = test_state().await;
        state.metadata().create_tenant(&tenant).await.unwrap();

        let app = tenant_router(Arc::clone(&state));
        // Only updating the name; upstream fields are absent => unchanged.
        let body = serde_json::json!({ "name": "Renamed" });
        let req = Request::put(format!("/api/v1/tenants/{}", tenant.id.0))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        std::env::remove_var(crate::secretbox::SECRET_ENCRYPTION_KEY_ENV);
        assert_eq!(resp.status(), StatusCode::OK);

        let after = state
            .metadata()
            .get_tenant(tenant.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.upstream_api_key_ciphertext.as_deref(),
            Some(ct.as_str())
        );
        assert_eq!(
            after.upstream_url.as_deref(),
            Some("https://keep.example.com")
        );
        assert_eq!(after.name, "Renamed");
    }

    // -- SECURITY regression: tenant default key is Operator, not Admin ------

    /// Build shared application state with auth ENABLED and a bootstrap admin
    /// key, mirroring the auth-enabled harness used in `auth.rs` tests.
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
            auth: llmtrace_core::AuthConfig {
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

    /// Build a router with auth middleware wired, exposing tenant creation and
    /// the trace-listing route so the cross-tenant scope guard can be exercised.
    fn auth_tenant_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/api/v1/tenants", post(create_tenant).get(list_tenants))
            .route("/api/v1/traces", get(crate::api::list_traces))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::auth::auth_middleware,
            ))
            .with_state(state)
    }

    /// Create a tenant as the bootstrap admin and return its one-time api_key.
    async fn create_tenant_as_admin(state: &Arc<AppState>, admin_key: &str, name: &str) -> String {
        let app = auth_tenant_router(Arc::clone(state));
        let body = serde_json::json!({ "name": name, "plan": "pro" });
        let req = Request::post("/api/v1/tenants")
            .header("authorization", format!("Bearer {admin_key}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "tenant creation must succeed"
        );
        let json = json_body(resp).await;
        json["api_key"].as_str().unwrap().to_string()
    }

    /// The auto-generated tenant "Default Key" must be Operator, not Admin, so
    /// it cannot satisfy the admin-only `X-LLMTrace-Tenant-Scope: all` guard and
    /// read other tenants' traces (the confirmed cross-tenant leak).
    #[tokio::test]
    async fn test_tenant_default_key_is_operator_not_admin_and_cannot_scope_all() {
        let admin_key = "admin-secret";
        let state = auth_state(admin_key).await;

        // As the bootstrap admin, create tenant A and tenant B.
        let a_key = create_tenant_as_admin(&state, admin_key, "Tenant A").await;
        let _b_key = create_tenant_as_admin(&state, admin_key, "Tenant B").await;

        // The persisted Default Key for tenant A must be Operator, never Admin.
        let a_hash = crate::auth::hash_api_key(&a_key);
        let record = state
            .metadata()
            .get_api_key_by_hash(&a_hash)
            .await
            .unwrap()
            .expect("tenant A default key must be persisted");
        assert_eq!(
            record.role,
            ApiKeyRole::Operator,
            "tenant default key must be Operator (full access within its own tenant)"
        );
        assert_ne!(
            record.role,
            ApiKeyRole::Admin,
            "tenant default key must NEVER be Admin (would unlock cross-tenant scope=all)"
        );

        // Behavioral: tenant A's key requesting cross-tenant scope=all must be
        // rejected 403 by the non-admin scope guard in auth.rs.
        let app = auth_tenant_router(Arc::clone(&state));
        let req = Request::get("/api/v1/traces")
            .header("authorization", format!("Bearer {a_key}"))
            .header("x-llmtrace-tenant-scope", "all")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "tenant Operator key requesting scope=all must be 403 (no cross-tenant reads)"
        );
    }
}
