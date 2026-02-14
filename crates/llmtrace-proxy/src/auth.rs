//! Authentication and role-based access control (RBAC) module.
//!
//! Provides API key generation, validation middleware, and management endpoints.
//! When `auth.enabled` is `true` in the configuration, every request (except
//! `/health`) must carry a valid API key in the `Authorization: Bearer <key>`
//! header. The key determines the tenant and role.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use llmtrace_core::{ApiKeyRecord, ApiKeyRole, AuthContext, TenantId};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prefix for generated API keys.
const KEY_PREFIX: &str = "llmt_";

/// Number of random bytes in a generated API key (256 bits).
const KEY_RANDOM_BYTES: usize = 32;

/// Number of characters from the key stored as the visible prefix.
const VISIBLE_PREFIX_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Key generation & hashing
// ---------------------------------------------------------------------------

/// Generate a new random API key and return `(plaintext_key, sha256_hex_hash)`.
#[must_use]
pub fn generate_api_key() -> (String, String) {
    let mut random_bytes = [0u8; KEY_RANDOM_BYTES];
    rand::thread_rng().fill_bytes(&mut random_bytes);

    let plaintext = format!("{KEY_PREFIX}{}", hex::encode(random_bytes));
    let hash = hash_api_key(&plaintext);

    (plaintext, hash)
}

/// Compute the SHA-256 hex digest of a plaintext API key.
#[must_use]
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Extract the visible prefix from a plaintext key for identification.
#[must_use]
pub fn key_prefix(key: &str) -> String {
    let end = key.len().min(VISIBLE_PREFIX_LEN);
    format!("{}…", &key[..end])
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Axum middleware that validates API keys and injects [`AuthContext`].
///
/// **When `auth.enabled = false`**: injects an `AuthContext` with `Admin` role
/// derived from existing header-based tenant resolution. This ensures downstream
/// handlers can always access `AuthContext` from extensions.
///
/// **When `auth.enabled = true`**:
/// 1. Skips auth for `/health`
/// 2. Checks the `Authorization: Bearer <key>` header
/// 3. Matches against the `auth.admin_key` (bootstrap admin key)
/// 4. Falls back to database lookup by key hash
/// 5. Returns 401 if no valid key is found
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // When auth is disabled, inject a permissive AuthContext using the legacy
    // tenant resolution so downstream handlers can always rely on extensions.
    if !state.config.auth.enabled {
        let tenant_id = crate::proxy::resolve_tenant(req.headers()).unwrap_or_default();
        let ctx = AuthContext {
            tenant_id,
            role: ApiKeyRole::Admin,
            key_id: None,
        };
        req.extensions_mut().insert(ctx);
        return next.run(req).await;
    }

    // Allow health endpoint and tenant/key listing/revocation (for dashboard discovery) without auth
    let path = req.uri().path();
    let method = req.method();
    if path == "/health"
        || (path == "/api/v1/tenants" && method == axum::http::Method::GET)
        || (path == "/api/v1/auth/keys" && method == axum::http::Method::GET)
        || (path.starts_with("/api/v1/auth/keys") && method == axum::http::Method::DELETE)
    {
        // Still try to resolve tenant from header if provided, for downstream context
        let tenant_id = resolve_tenant_from_header(req.headers()).unwrap_or_default();
        let ctx = AuthContext {
            tenant_id,
            role: ApiKeyRole::Viewer, // Default to viewer for unauthenticated discovery
            key_id: None,
        };
        req.extensions_mut().insert(ctx);
        return next.run(req).await;
    }

    let headers = req.headers();

    // 1. Try X-LLMTrace-Token header (preferred for proxy traffic)
    if let Some(token) = headers.get("x-llmtrace-token").and_then(|v| v.to_str().ok()) {
        match state.metadata().get_tenant_by_token(token).await {
            Ok(Some(tenant)) => {
                let ctx = AuthContext {
                    tenant_id: tenant.id,
                    role: ApiKeyRole::Operator, // Token grants operator access for traffic
                    key_id: None,
                };
                req.extensions_mut().insert(ctx);
                return next.run(req).await;
            }
            Ok(None) => {
                // If token is invalid, we continue to check other auth methods
                // but we might want to return 401 later if nothing else matches.
            }
            Err(e) => {
                tracing::error!("Tenant token lookup failed: {e}");
                return auth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Authentication service unavailable",
                );
            }
        }
    }

    // 2. Extract the bearer token (existing logic)
    let token = match extract_bearer_token(headers) {
        Some(t) => Some(t),
        None => None,
    };

    if let Some(token) = token {
        // Check bootstrap admin key first
        if let Some(ref admin_key) = state.config.auth.admin_key {
            if token == admin_key.as_str() {
                // Admin key uses tenant from X-LLMTrace-Tenant-ID header, or a default
                let tenant_id = resolve_tenant_from_header(headers).unwrap_or_default();
                let ctx = AuthContext {
                    tenant_id,
                    role: ApiKeyRole::Admin,
                    key_id: None,
                };
                req.extensions_mut().insert(ctx);
                return next.run(req).await;
            }
        }

        // Look up key in the database
        let key_hash = hash_api_key(token);
        match state.metadata().get_api_key_by_hash(&key_hash).await {
            Ok(Some(record)) => {
                let ctx = AuthContext {
                    tenant_id: record.tenant_id,
                    role: record.role,
                    key_id: Some(record.id),
                };
                req.extensions_mut().insert(ctx);
                return next.run(req).await;
            }
            Ok(None) => return auth_error(StatusCode::UNAUTHORIZED, "Invalid API key"),
            Err(e) => {
                tracing::error!("API key lookup failed: {e}");
                return auth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Authentication service unavailable",
                );
            }
        }
    }

    // 3. Reject unauthenticated traffic when auth is enabled
    auth_error(
        StatusCode::UNAUTHORIZED,
        "Authentication required: Missing or invalid Authorization header or X-LLMTrace-Token",
    )
}

/// Extract the tenant from [`AuthContext`] (if present) or fall back to header-based resolution.
///
/// This is the unified way to get the authenticated tenant in handlers.
/// When auth is enabled, the middleware will have set `AuthContext`; when
/// disabled, we fall back to the legacy `resolve_tenant` logic.
pub fn resolve_authenticated_tenant(
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
) -> (Option<TenantId>, Option<ApiKeyRole>) {
    if let Some(ctx) = extensions.get::<AuthContext>() {
        (Some(ctx.tenant_id), Some(ctx.role))
    } else {
        (crate::proxy::resolve_tenant(headers), None)
    }
}

/// Check that the caller has at least the required role.
///
/// When auth is disabled (no `AuthContext` in extensions), this always succeeds.
/// Returns `Some(error_response)` if the role check fails.
pub fn require_role(extensions: &axum::http::Extensions, required: ApiKeyRole) -> Option<Response> {
    if let Some(ctx) = extensions.get::<AuthContext>() {
        if !ctx.role.has_permission(required) {
            return Some(auth_error(
                StatusCode::FORBIDDEN,
                &format!(
                    "Insufficient permissions: requires {} role, have {}",
                    required, ctx.role
                ),
            ));
        }
    }
    // No AuthContext means auth is disabled — allow everything.
    None
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/auth/keys`.
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    /// Tenant ID to create the key for.
    pub tenant_id: Uuid,
    /// Human-readable name for the key.
    pub name: String,
    /// Role: "admin", "operator", or "viewer".
    pub role: String,
}

/// Successful response from `POST /api/v1/auth/keys` — includes plaintext key once.
#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    /// The key ID.
    pub id: Uuid,
    /// The plaintext API key — shown only once, store it securely.
    pub key: String,
    /// Key prefix for future identification.
    pub key_prefix: String,
    /// Tenant this key belongs to.
    pub tenant_id: TenantId,
    /// Role granted by this key.
    pub role: ApiKeyRole,
    /// When the key was created.
    pub created_at: chrono::DateTime<Utc>,
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
// API handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/keys` — create a new API key (admin only).
pub async fn create_api_key(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    // Require admin role
    if let Some(err) = require_role(req.extensions(), ApiKeyRole::Admin) {
        return err;
    }

    // Parse the body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return auth_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid request body: {e}"),
            )
        }
    };
    let body: CreateApiKeyRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(e) => return auth_error(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {e}")),
    };

    if body.name.trim().is_empty() {
        return auth_error(StatusCode::BAD_REQUEST, "Key name must not be empty");
    }

    let role: ApiKeyRole = match body.role.parse() {
        Ok(r) => r,
        Err(e) => return auth_error(StatusCode::BAD_REQUEST, &e),
    };

    let tenant_id = TenantId(body.tenant_id);

    // Verify the tenant exists
    match state.metadata().get_tenant(tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return auth_error(StatusCode::NOT_FOUND, "Tenant not found"),
        Err(e) => {
            return auth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to verify tenant: {e}"),
            )
        }
    }

    let (plaintext, hash) = generate_api_key();
    let prefix = key_prefix(&plaintext);

    let record = ApiKeyRecord {
        id: Uuid::new_v4(),
        tenant_id,
        name: body.name,
        key_hash: hash,
        key_prefix: prefix.clone(),
        role,
        created_at: Utc::now(),
        revoked_at: None,
    };

    match state.metadata().create_api_key(&record).await {
        Ok(()) => {
            // Record audit event
            crate::tenant_api::record_audit_for(
                &state,
                tenant_id,
                "api_key_created",
                &format!("api_key:{}", record.id),
                serde_json::json!({
                    "key_id": record.id.to_string(),
                    "key_prefix": prefix,
                    "role": role.to_string(),
                }),
            )
            .await;

            let resp = CreateApiKeyResponse {
                id: record.id,
                key: plaintext,
                key_prefix: prefix,
                tenant_id,
                role,
                created_at: record.created_at,
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to create API key: {e}"),
        ),
    }
}

/// `GET /api/v1/auth/keys` — list API keys for the authenticated tenant (admin only).
pub async fn list_api_keys(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    if let Some(err) = require_role(req.extensions(), ApiKeyRole::Admin) {
        return err;
    }

    let (tenant_id_opt, _) = resolve_authenticated_tenant(req.headers(), req.extensions());
    let tenant_id = match tenant_id_opt {
        Some(id) => id,
        None => return auth_error(StatusCode::BAD_REQUEST, "Missing tenant identifier"),
    };

    match state.metadata().list_api_keys(tenant_id).await {
        Ok(keys) => Json(keys).into_response(),
        Err(e) => auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to list API keys: {e}"),
        ),
    }
}

/// `DELETE /api/v1/auth/keys/:id` — revoke an API key (admin only).
pub async fn revoke_api_key(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
    req: Request<Body>,
) -> Response {
    if let Some(err) = require_role(req.extensions(), ApiKeyRole::Admin) {
        return err;
    }

    let (tenant_id_opt, _) = resolve_authenticated_tenant(req.headers(), req.extensions());
    let tenant_id = match tenant_id_opt {
        Some(id) => id,
        None => return auth_error(StatusCode::BAD_REQUEST, "Missing tenant identifier"),
    };

    match state.metadata().revoke_api_key(key_id).await {
        Ok(true) => {
            crate::tenant_api::record_audit_for(
                &state,
                tenant_id,
                "api_key_revoked",
                &format!("api_key:{key_id}"),
                serde_json::json!({ "key_id": key_id.to_string() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => auth_error(
            StatusCode::NOT_FOUND,
            "API key not found or already revoked",
        ),
        Err(e) => auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to revoke API key: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Extract tenant ID from the `X-LLMTrace-Tenant-ID` header.
fn resolve_tenant_from_header(headers: &HeaderMap) -> Option<TenantId> {
    if let Some(raw) = headers.get("x-llmtrace-tenant-id") {
        if let Ok(s) = raw.to_str() {
            if let Ok(uuid) = Uuid::parse_str(s) {
                return Some(TenantId(uuid));
            }
        }
    }
    None
}

/// Build a JSON authentication error response.
fn auth_error(status: StatusCode, message: &str) -> Response {
    let body = ApiError {
        error: ApiErrorDetail {
            message: message.to_string(),
            error_type: "auth_error".to_string(),
        },
    };
    (status, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::TenantId;

    #[test]
    fn test_generate_api_key_format() {
        let (plaintext, hash) = generate_api_key();
        assert!(plaintext.starts_with("llmt_"));
        // 5-char prefix + 64 hex chars = 69 total
        assert_eq!(plaintext.len(), 5 + KEY_RANDOM_BYTES * 2);
        // SHA-256 hex = 64 chars
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_api_key_deterministic() {
        let key = "llmt_deadbeef";
        let h1 = hash_api_key(key);
        let h2 = hash_api_key(key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_api_key_different_keys() {
        let h1 = hash_api_key("llmt_aaaa");
        let h2 = hash_api_key("llmt_bbbb");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_key_prefix_extraction() {
        let prefix = key_prefix("llmt_abcdef0123456789");
        assert_eq!(prefix, "llmt_abcdef0…");
    }

    #[test]
    fn test_api_key_role_permissions() {
        // Admin has all permissions
        assert!(ApiKeyRole::Admin.has_permission(ApiKeyRole::Admin));
        assert!(ApiKeyRole::Admin.has_permission(ApiKeyRole::Operator));
        assert!(ApiKeyRole::Admin.has_permission(ApiKeyRole::Viewer));

        // Operator has operator + viewer
        assert!(!ApiKeyRole::Operator.has_permission(ApiKeyRole::Admin));
        assert!(ApiKeyRole::Operator.has_permission(ApiKeyRole::Operator));
        assert!(ApiKeyRole::Operator.has_permission(ApiKeyRole::Viewer));

        // Viewer has only viewer
        assert!(!ApiKeyRole::Viewer.has_permission(ApiKeyRole::Admin));
        assert!(!ApiKeyRole::Viewer.has_permission(ApiKeyRole::Operator));
        assert!(ApiKeyRole::Viewer.has_permission(ApiKeyRole::Viewer));
    }

    #[test]
    fn test_api_key_role_display() {
        assert_eq!(ApiKeyRole::Admin.to_string(), "admin");
        assert_eq!(ApiKeyRole::Operator.to_string(), "operator");
        assert_eq!(ApiKeyRole::Viewer.to_string(), "viewer");
    }

    #[test]
    fn test_api_key_role_parse() {
        assert_eq!("admin".parse::<ApiKeyRole>().unwrap(), ApiKeyRole::Admin);
        assert_eq!(
            "operator".parse::<ApiKeyRole>().unwrap(),
            ApiKeyRole::Operator
        );
        assert_eq!("viewer".parse::<ApiKeyRole>().unwrap(), ApiKeyRole::Viewer);
        assert_eq!("ADMIN".parse::<ApiKeyRole>().unwrap(), ApiKeyRole::Admin);
        assert!("unknown".parse::<ApiKeyRole>().is_err());
    }

    #[test]
    fn test_extract_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-test".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("sk-test"));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_no_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_resolve_tenant_from_header_valid() {
        let mut headers = HeaderMap::new();
        let uuid = Uuid::new_v4();
        headers.insert("x-llmtrace-tenant-id", uuid.to_string().parse().unwrap());
        assert_eq!(resolve_tenant_from_header(&headers).unwrap().0, uuid);
    }

    #[test]
    fn test_resolve_tenant_from_header_missing() {
        let headers = HeaderMap::new();
        let tenant = resolve_tenant_from_header(&headers);
        assert!(tenant.is_none());
    }

    #[test]
    fn test_require_role_no_context() {
        // When no AuthContext is set (auth disabled), all roles pass
        let extensions = axum::http::Extensions::new();
        assert!(require_role(&extensions, ApiKeyRole::Admin).is_none());
    }

    #[test]
    fn test_require_role_sufficient() {
        let mut extensions = axum::http::Extensions::new();
        extensions.insert(AuthContext {
            tenant_id: TenantId::new(),
            role: ApiKeyRole::Admin,
            key_id: None,
        });
        assert!(require_role(&extensions, ApiKeyRole::Viewer).is_none());
        assert!(require_role(&extensions, ApiKeyRole::Operator).is_none());
        assert!(require_role(&extensions, ApiKeyRole::Admin).is_none());
    }

    #[test]
    fn test_require_role_insufficient() {
        let mut extensions = axum::http::Extensions::new();
        extensions.insert(AuthContext {
            tenant_id: TenantId::new(),
            role: ApiKeyRole::Viewer,
            key_id: None,
        });
        assert!(require_role(&extensions, ApiKeyRole::Admin).is_some());
        assert!(require_role(&extensions, ApiKeyRole::Operator).is_some());
    }

    // -----------------------------------------------------------------------
    // Integration tests: middleware + endpoints
    // -----------------------------------------------------------------------

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{delete, get, post};
    use axum::Router;
    use llmtrace_core::{AuthConfig, ProxyConfig, SecurityAnalyzer, StorageConfig, Tenant};
    use llmtrace_security::RegexSecurityAnalyzer;
    use llmtrace_storage::StorageProfile;
    use tower::ServiceExt;

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

    /// Build a router with auth middleware and key management routes.
    fn auth_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route(
                "/api/v1/auth/keys",
                post(super::create_api_key).get(super::list_api_keys),
            )
            .route("/api/v1/auth/keys/:id", delete(super::revoke_api_key))
            .route("/api/v1/traces", get(crate::api::list_traces))
            .route(
                "/api/v1/tenants",
                post(crate::tenant_api::create_tenant).get(crate::tenant_api::list_tenants),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                super::auth_middleware,
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

    #[tokio::test]
    async fn test_auth_rejects_missing_key() {
        let state = auth_state("admin-secret").await;
        let app = auth_router(state);

        let req = Request::get("/api/v1/traces").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_rejects_invalid_key() {
        let state = auth_state("admin-secret").await;
        let app = auth_router(state);

        let req = Request::get("/api/v1/traces")
            .header("authorization", "Bearer wrong-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_key_grants_access() {
        let state = auth_state("admin-secret").await;
        let app = auth_router(state);

        let req = Request::get("/api/v1/traces")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_and_use_api_key() {
        let state = auth_state("admin-secret").await;

        // Create a tenant first
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Test Org".to_string(),
            api_token: "token-test".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        // Create an API key via admin
        let app = auth_router(Arc::clone(&state));
        let body = serde_json::json!({
            "tenant_id": tenant.id.0.to_string(),
            "name": "test-key",
            "role": "viewer",
        });

        let req = Request::post("/api/v1/auth/keys")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let create_resp = json_body(resp).await;
        let key = create_resp["key"].as_str().unwrap().to_string();
        assert!(key.starts_with("llmt_"));

        // Use the created key to access traces
        let app = auth_router(Arc::clone(&state));
        let req = Request::get("/api/v1/traces")
            .header("authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_viewer_cannot_manage_tenants() {
        let state = auth_state("admin-secret").await;

        // Create a tenant and a viewer key
        let tenant = Tenant {
            id: TenantId::new(),
            name: "RBAC Test".to_string(),
            api_token: "token-viewer".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let (plaintext, hash) = generate_api_key();
        let key_record = ApiKeyRecord {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            name: "viewer-key".to_string(),
            key_hash: hash,
            key_prefix: key_prefix(&plaintext),
            role: ApiKeyRole::Viewer,
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.metadata().create_api_key(&key_record).await.unwrap();

        // Viewer should NOT be able to create tenants
        let app = auth_router(Arc::clone(&state));
        let body = serde_json::json!({ "name": "New Tenant" });
        let req = Request::post("/api/v1/tenants")
            .header("authorization", format!("Bearer {plaintext}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_revoke_api_key_prevents_access() {
        let state = auth_state("admin-secret").await;

        let tenant = Tenant {
            id: TenantId::new(),
            name: "Revoke Test".to_string(),
            api_token: "token-revoke".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        let (plaintext, hash) = generate_api_key();
        let key_record = ApiKeyRecord {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            name: "will-be-revoked".to_string(),
            key_hash: hash,
            key_prefix: key_prefix(&plaintext),
            role: ApiKeyRole::Operator,
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.metadata().create_api_key(&key_record).await.unwrap();

        // Key works before revocation
        let app = auth_router(Arc::clone(&state));
        let req = Request::get("/api/v1/traces")
            .header("authorization", format!("Bearer {plaintext}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Revoke via admin
        let app = auth_router(Arc::clone(&state));
        let req = Request::delete(format!("/api/v1/auth/keys/{}", key_record.id))
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Key should no longer work
        let app = auth_router(Arc::clone(&state));
        let req = Request::get("/api/v1/traces")
            .header("authorization", format!("Bearer {plaintext}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tenant_isolation_via_auth() {
        let state = auth_state("admin-secret").await;

        // Create two tenants
        let t1 = Tenant {
            id: TenantId::new(),
            name: "Tenant A".to_string(),
            api_token: "token-a".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        let t2 = Tenant {
            id: TenantId::new(),
            name: "Tenant B".to_string(),
            api_token: "token-b".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&t1).await.unwrap();
        state.metadata().create_tenant(&t2).await.unwrap();

        // Create a key for tenant A
        let (key_a, hash_a) = generate_api_key();
        let rec_a = ApiKeyRecord {
            id: Uuid::new_v4(),
            tenant_id: t1.id,
            name: "key-a".to_string(),
            key_hash: hash_a,
            key_prefix: key_prefix(&key_a),
            role: ApiKeyRole::Operator,
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.metadata().create_api_key(&rec_a).await.unwrap();

        // Store a trace for tenant A
        let trace_id_a = Uuid::new_v4();
        let trace = llmtrace_core::TraceEvent {
            trace_id: trace_id_a,
            tenant_id: t1.id,
            spans: vec![llmtrace_core::TraceSpan::new(
                trace_id_a,
                t1.id,
                "chat_completion".to_string(),
                llmtrace_core::LLMProvider::OpenAI,
                "gpt-4".to_string(),
                "test".to_string(),
            )],
            created_at: Utc::now(),
        };
        state.storage.traces.store_trace(&trace).await.unwrap();

        // Store a trace for tenant B
        let trace_id_b = Uuid::new_v4();
        let trace_b = llmtrace_core::TraceEvent {
            trace_id: trace_id_b,
            tenant_id: t2.id,
            spans: vec![llmtrace_core::TraceSpan::new(
                trace_id_b,
                t2.id,
                "chat_completion".to_string(),
                llmtrace_core::LLMProvider::OpenAI,
                "gpt-4".to_string(),
                "secret".to_string(),
            )],
            created_at: Utc::now(),
        };
        state.storage.traces.store_trace(&trace_b).await.unwrap();

        // Key A should only see tenant A's traces
        let app = auth_router(Arc::clone(&state));
        let req = Request::get("/api/v1/traces")
            .header("authorization", format!("Bearer {key_a}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert_eq!(body["total"], 1);
        // Verify we only see tenant A's trace
        assert_eq!(body["data"][0]["trace_id"], trace_id_a.to_string());
    }

    #[tokio::test]
    async fn test_list_api_keys_returns_keys() {
        let state = auth_state("admin-secret").await;

        let tenant = Tenant {
            id: TenantId::new(),
            name: "Key List Test".to_string(),
            api_token: "token-key-list".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        state.metadata().create_tenant(&tenant).await.unwrap();

        // Create two keys
        for i in 0..2 {
            let (_, hash) = generate_api_key();
            let rec = ApiKeyRecord {
                id: Uuid::new_v4(),
                tenant_id: tenant.id,
                name: format!("key-{i}"),
                key_hash: hash,
                key_prefix: format!("llmt_{i}…"),
                role: ApiKeyRole::Viewer,
                created_at: Utc::now(),
                revoked_at: None,
            };
            state.metadata().create_api_key(&rec).await.unwrap();
        }

        let app = auth_router(Arc::clone(&state));
        let req = Request::get("/api/v1/auth/keys")
            .header("authorization", "Bearer admin-secret")
            .header("x-llmtrace-tenant-id", tenant.id.0.to_string())
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        let keys = body.as_array().unwrap();
        assert_eq!(keys.len(), 2);
        // Key hashes should NOT be exposed in the response
        for key_json in keys {
            assert!(key_json.get("key_hash").is_none());
        }
    }
}
