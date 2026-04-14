//! HTTP handlers for the runtime feature-flag admin API (issue #42).
//!
//! Three routes, all gated by `ApiKeyRole::Admin`:
//!
//! - `GET    /api/v1/config/features`             — list the current
//!   [`FeatureFlags`] snapshot.
//! - `PUT    /api/v1/config/features/:feature`    — toggle one flag.
//! - `PUT    /api/v1/config/features`             — atomic bulk update.
//!
//! Validation runs inside the [`crate::config_handle::ConfigHandle::update`]
//! closure, so a single rule violation rolls back automatically and the
//! live config is never observed in a half-updated state. After a
//! successful swap, [`apply_runtime_effects`] diffs the previous and
//! next [`FeatureFlags`] and replays the changes onto
//! [`llmtrace_security::EnsembleRuntimeHandle`] so the ensemble's atomic
//! gates and operating-point thresholds reflect the new state on the
//! very next request.
//!
//! ## Error encoding through `ConfigHandle::update`
//!
//! The mutator closure passed to `ConfigHandle::update` returns
//! `Result<(), String>`, but Phase 2 needs to distinguish 400 vs 422
//! responses. We prefix-encode the HTTP status into the error string
//! (`"400:unknown feature: foo"`, `"422:..."`) and parse the prefix
//! back at the handler boundary. This keeps the `ConfigHandle` API
//! agnostic of HTTP semantics while still preserving the typed
//! `ValidationError::http_status` mapping.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use llmtrace_core::{ApiKeyRole, AuthContext, ProxyConfig};
use llmtrace_security::OperatingPoint;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::config_handle::ConfigUpdateError;
use crate::feature_flags::{apply_single, FeatureFlags, FeatureValue, ValidationError};
use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Body for `PUT /api/v1/config/features/:feature`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct UpdateFeatureRequest {
    pub value: FeatureValue,
}

/// Successful response from a single-feature PUT.
#[derive(Debug, Serialize, ToSchema)]
pub struct UpdateFeatureResponse {
    pub updated: String,
    pub previous: FeatureValue,
    pub features: FeatureFlags,
    pub warnings: Vec<String>,
}

/// Body for `PUT /api/v1/config/features` (atomic bulk update).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct BulkUpdateRequest {
    pub features: FeatureFlags,
}

/// Successful response from a bulk PUT.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkUpdateResponse {
    pub features: FeatureFlags,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiErrorDetail {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn api_error(status: StatusCode, error_type: &str, message: &str) -> Response {
    let body = ApiError {
        error: ApiErrorDetail {
            message: message.to_string(),
            error_type: error_type.to_string(),
        },
    };
    (status, Json(body)).into_response()
}

fn require_admin(auth: &AuthContext) -> Option<Response> {
    if !auth.role.has_permission(ApiKeyRole::Admin) {
        Some(api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Insufficient permissions: requires admin role",
        ))
    } else {
        None
    }
}

/// Encode a [`ValidationError`] for transport through
/// `ConfigHandle::update`'s `Result<(), String>` channel. The HTTP
/// status, error type, and message are joined with `|` so the handler
/// can decode them at the boundary without losing typing.
fn encode_validation_error(e: &ValidationError) -> String {
    format!("{}|{}|{}", e.http_status().as_u16(), e.error_type(), e)
}

/// Decode an error string produced by [`encode_validation_error`].
/// Returns `(status, error_type, message)`.
fn decode_validation_error(raw: &str) -> (StatusCode, String, String) {
    let mut parts = raw.splitn(3, '|');
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let error_type = parts.next().unwrap_or("validation_error").to_string();
    let message = parts.next().unwrap_or(raw).to_string();
    (status, error_type, message)
}

fn map_update_error(err: ConfigUpdateError) -> Response {
    match err {
        ConfigUpdateError::Validation(s) => {
            let (status, etype, msg) = decode_validation_error(&s);
            api_error(status, &etype, &msg)
        }
        ConfigUpdateError::Poisoned => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_lock_poisoned",
            "Config writer lock is poisoned; restart the proxy",
        ),
    }
}

/// Diff `prev` against `next` and replay the changes on the ensemble's
/// runtime handle so the security analyzer's atomic gates pick up the
/// new state on the very next request.
fn apply_runtime_effects(state: &AppState, prev: &FeatureFlags, next: &FeatureFlags) {
    let rh = &state.ensemble_runtime;
    if prev.analyzer_ml_enabled != next.analyzer_ml_enabled {
        rh.set_ml(next.analyzer_ml_enabled);
    }
    if prev.analyzer_injecguard_enabled != next.analyzer_injecguard_enabled {
        rh.set_injecguard(next.analyzer_injecguard_enabled);
    }
    if prev.analyzer_piguard_enabled != next.analyzer_piguard_enabled {
        rh.set_piguard(next.analyzer_piguard_enabled);
    }
    if prev.analyzer_jailbreak_enabled != next.analyzer_jailbreak_enabled {
        rh.set_jailbreak(next.analyzer_jailbreak_enabled);
    }
    if prev.over_defence != next.over_defence {
        rh.set_over_defence(next.over_defence);
    }
    if prev.operating_point != next.operating_point {
        // Already validated by apply_to_config / apply_single, so this
        // map is infallible at this point.
        let point = match next.operating_point.as_str() {
            "balanced" => OperatingPoint::Balanced,
            "high_recall" => OperatingPoint::HighRecall,
            "high_precision" => OperatingPoint::HighPrecision,
            _ => return,
        };
        rh.set_operating_point(point);
    }
}

/// Pick the typed [`FeatureValue`] for `feature` out of a [`FeatureFlags`]
/// snapshot. Used to populate the `previous` field of the single-feature
/// response. Returns `None` for unknown names.
fn extract_feature_value(flags: &FeatureFlags, feature: &str) -> Option<FeatureValue> {
    match feature {
        "analyzer_ml_enabled" => Some(FeatureValue::Bool(flags.analyzer_ml_enabled)),
        "analyzer_injecguard_enabled" => {
            Some(FeatureValue::Bool(flags.analyzer_injecguard_enabled))
        }
        "analyzer_piguard_enabled" => Some(FeatureValue::Bool(flags.analyzer_piguard_enabled)),
        "analyzer_jailbreak_enabled" => Some(FeatureValue::Bool(flags.analyzer_jailbreak_enabled)),
        "enforcement_mode" => Some(FeatureValue::String(flags.enforcement_mode.clone())),
        "boundary_defense_enabled" => Some(FeatureValue::Bool(flags.boundary_defense_enabled)),
        "boundary_defense_shadow_mode" => {
            Some(FeatureValue::Bool(flags.boundary_defense_shadow_mode))
        }
        "rate_limiting_enabled" => Some(FeatureValue::Bool(flags.rate_limiting_enabled)),
        "cost_caps_enabled" => Some(FeatureValue::Bool(flags.cost_caps_enabled)),
        "operating_point" => Some(FeatureValue::String(flags.operating_point.clone())),
        "over_defence" => Some(FeatureValue::Bool(flags.over_defence)),
        "llm_judge_enabled" => Some(FeatureValue::Bool(flags.llm_judge_enabled)),
        _ => None,
    }
}

fn collect_warnings(prev: &FeatureFlags, next: &FeatureFlags) -> Vec<String> {
    let mut out = Vec::new();
    if next.llm_judge_enabled && !prev.llm_judge_enabled {
        out.push(
            "llm_judge backend not implemented yet; flag stored but no analyzer reads it (see #43)"
                .to_string(),
        );
    }
    out
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/config/features` — return the current feature-flag snapshot.
#[utoipa::path(
    get,
    path = "/api/v1/config/features",
    responses(
        (status = 200, description = "Current feature flag values", body = FeatureFlags),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
pub async fn get_features(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }
    let cfg = state.config_handle.snapshot();
    Json(FeatureFlags::from_config(&cfg)).into_response()
}

/// `PUT /api/v1/config/features/:feature` — toggle one feature.
#[utoipa::path(
    put,
    path = "/api/v1/config/features/{feature}",
    params(
        ("feature" = String, Path, description = "Feature flag name")
    ),
    request_body = UpdateFeatureRequest,
    responses(
        (status = 200, description = "Feature updated", body = UpdateFeatureResponse),
        (status = 400, description = "Unknown feature, immutable, or wrong type", body = ApiError),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 422, description = "Validation rule violation", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
pub async fn update_feature(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(feature): Path<String>,
    Json(body): Json<UpdateFeatureRequest>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }

    let prev_cfg = state.config_handle.snapshot();
    let prev_flags = FeatureFlags::from_config(&prev_cfg);
    let previous = match extract_feature_value(&prev_flags, &feature) {
        Some(v) => v,
        None => {
            // analyzer_regex_enabled is the only "known but immutable"
            // name; everything else hits unknown_feature.
            if feature == "analyzer_regex_enabled" {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "immutable",
                    "feature 'analyzer_regex_enabled' is immutable",
                );
            }
            return api_error(
                StatusCode::BAD_REQUEST,
                "unknown_feature",
                &format!("unknown feature: {feature}"),
            );
        }
    };
    let new_value = body.value.clone();

    let result = state.config_handle.update(|cfg: &mut ProxyConfig| {
        match apply_single(cfg, &feature, body.value) {
            Ok(()) => Ok(()),
            Err(e) => Err(encode_validation_error(&e)),
        }
    });

    let new_arc = match result {
        Ok(arc) => arc,
        Err(e) => return map_update_error(e),
    };

    let next_flags = FeatureFlags::from_config(&new_arc);
    apply_runtime_effects(&state, &prev_flags, &next_flags);
    let warnings = collect_warnings(&prev_flags, &next_flags);

    let resp = UpdateFeatureResponse {
        updated: feature.clone(),
        previous,
        features: next_flags,
        warnings,
    };
    let _ = new_value; // silence unused warning when the body is logged elsewhere
    (StatusCode::OK, Json(resp)).into_response()
}

/// `PUT /api/v1/config/features` — atomic bulk update.
#[utoipa::path(
    put,
    path = "/api/v1/config/features",
    request_body = BulkUpdateRequest,
    responses(
        (status = 200, description = "Bulk update applied", body = BulkUpdateResponse),
        (status = 400, description = "Wrong type or malformed value", body = ApiError),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 403, description = "Forbidden", body = ApiError),
        (status = 422, description = "Validation rule violation", body = ApiError),
    ),
    security(("api_key" = [])),
    tag = "LLMTrace Proxy"
)]
pub async fn bulk_update_features(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<BulkUpdateRequest>,
) -> Response {
    if let Some(err) = require_admin(&auth) {
        return err;
    }

    let prev_cfg = state.config_handle.snapshot();
    let prev_flags = FeatureFlags::from_config(&prev_cfg);

    let result = state.config_handle.update(|cfg: &mut ProxyConfig| {
        match body.features.apply_to_config(cfg) {
            Ok(()) => Ok(()),
            Err(e) => Err(encode_validation_error(&e)),
        }
    });

    let new_arc = match result {
        Ok(arc) => arc,
        Err(e) => return map_update_error(e),
    };

    let next_flags = FeatureFlags::from_config(&new_arc);
    apply_runtime_effects(&state, &prev_flags, &next_flags);
    let warnings = collect_warnings(&prev_flags, &next_flags);

    let resp = BulkUpdateResponse {
        features: next_flags,
        warnings,
    };
    (StatusCode::OK, Json(resp)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_handle::ConfigHandle;
    use crate::feature_flags::FeatureFlags;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        routing::{get, put},
        Router,
    };
    use llmtrace_core::{
        ApiKeyRole, AuthContext, EnforcementMode, OperatingPoint, ProxyConfig, SecurityAnalyzer,
        StorageConfig, TenantId,
    };
    use llmtrace_security::{EnsembleRuntimeHandle, RegexSecurityAnalyzer};
    use llmtrace_storage::StorageProfile;
    use std::sync::Arc;
    use tower::ServiceExt;

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
            config_handle: ConfigHandle::new(config, None, None),
            client,
            storage,
            fast_analyzer: security.clone(),
            security,
            ensemble_runtime: Arc::new(EnsembleRuntimeHandle::inert()),
            storage_breaker,
            security_breaker,
            cost_estimator,
            alert_engine: None,
            cost_tracker,
            anomaly_detector: None,
            action_router: crate::action_router::ActionRouter::new(
                &llmtrace_core::ActionRouterConfig::default(),
                None,
                reqwest::Client::new(),
            ),
            report_store: crate::compliance::new_report_store(),
            rate_limiter,
            ml_status: crate::proxy::MlModelStatus::Disabled,
            shutdown: crate::shutdown::ShutdownCoordinator::new(30),
            metrics: crate::metrics::Metrics::new(),
            ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    fn admin_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route(
                "/api/v1/config/features",
                get(get_features).put(bulk_update_features),
            )
            .route("/api/v1/config/features/:feature", put(update_feature))
            .with_state(state)
    }

    fn admin_extension() -> AuthContext {
        AuthContext {
            tenant_id: TenantId::new(),
            role: ApiKeyRole::Admin,
            key_id: None,
        }
    }

    fn viewer_extension() -> AuthContext {
        AuthContext {
            tenant_id: TenantId::new(),
            role: ApiKeyRole::Viewer,
            key_id: None,
        }
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::Value::Null)
    }

    fn admin_get(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(path)
            .extension(admin_extension())
            .body(Body::empty())
            .unwrap()
    }

    fn admin_put(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(path)
            .header("content-type", "application/json")
            .extension(admin_extension())
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn get_features_returns_defaults() {
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_get("/api/v1/config/features"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        // Defaults from ProxyConfig::default()
        assert_eq!(body["enforcement_mode"], "log");
        assert_eq!(body["operating_point"], "balanced");
        assert_eq!(body["llm_judge_enabled"], false);
    }

    #[tokio::test]
    async fn get_features_requires_admin() {
        let state = test_state().await;
        let app = admin_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/config/features")
            .extension(viewer_extension())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn put_single_enforcement_mode_block_succeeds() {
        let state = test_state().await;
        let app = admin_router(state.clone());
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/enforcement_mode",
                serde_json::json!({"value": "block"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["updated"], "enforcement_mode");
        assert_eq!(body["previous"], "log");
        assert_eq!(body["features"]["enforcement_mode"], "block");

        // The live config must reflect the change.
        assert_eq!(
            state.config_handle.snapshot().enforcement.mode,
            EnforcementMode::Block
        );
    }

    #[tokio::test]
    async fn put_single_operating_point_high_precision_propagates_to_runtime_handle() {
        let state = test_state().await;
        let app = admin_router(state.clone());
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/operating_point",
                serde_json::json!({"value": "high_precision"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            state
                .config_handle
                .snapshot()
                .security_analysis
                .operating_point,
            OperatingPoint::HighPrecision
        );
    }

    #[tokio::test]
    async fn put_single_unknown_feature_returns_400() {
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/no_such_flag",
                serde_json::json!({"value": true}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["type"], "unknown_feature");
    }

    #[tokio::test]
    async fn put_single_analyzer_regex_enabled_immutable_400() {
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/analyzer_regex_enabled",
                serde_json::json!({"value": false}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["type"], "immutable");
    }

    #[tokio::test]
    async fn put_single_wrong_type_returns_400() {
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/enforcement_mode",
                serde_json::json!({"value": true}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["type"], "wrong_type");
    }

    #[tokio::test]
    async fn put_single_invalid_enum_returns_400() {
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/operating_point",
                serde_json::json!({"value": "paranoid"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["type"], "invalid_value");
    }

    #[tokio::test]
    async fn put_single_shadow_without_enabled_returns_422() {
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/boundary_defense_shadow_mode",
                serde_json::json!({"value": true}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["type"], "validation_error");
    }

    #[tokio::test]
    async fn put_single_llm_judge_returns_warning() {
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/llm_judge_enabled",
                serde_json::json!({"value": true}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let warnings = body["warnings"].as_array().unwrap();
        assert!(!warnings.is_empty());
        assert!(warnings[0].as_str().unwrap().contains("llm_judge"));
    }

    #[tokio::test]
    async fn put_bulk_atomic_rollback_on_validation_error() {
        let state = test_state().await;
        // Build a known-bad bulk body: shadow_mode true with enabled false.
        let mut flags = FeatureFlags::from_config(&state.config_handle.snapshot());
        flags.enforcement_mode = "block".to_string(); // valid change
        flags.boundary_defense_enabled = false;
        flags.boundary_defense_shadow_mode = true; // invalid combo

        let app = admin_router(state.clone());
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features",
                serde_json::json!({"features": flags}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // The valid change must NOT have been applied — atomic rollback.
        let snap = state.config_handle.snapshot();
        assert_eq!(snap.enforcement.mode, EnforcementMode::Log);
    }

    #[tokio::test]
    async fn put_bulk_runtime_handle_reflects_changes() {
        let state = test_state().await;
        let mut flags = FeatureFlags::from_config(&state.config_handle.snapshot());
        flags.analyzer_ml_enabled = false;
        flags.over_defence = true;

        let app = admin_router(state.clone());
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features",
                serde_json::json!({"features": flags}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Inert handle still records the writes.
        assert!(!state.ensemble_runtime.ml());
        assert!(state.ensemble_runtime.over_defence());
    }

    #[tokio::test]
    async fn put_bulk_requires_admin() {
        let state = test_state().await;
        let flags = FeatureFlags::from_config(&state.config_handle.snapshot());
        let app = admin_router(state);
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/config/features")
            .header("content-type", "application/json")
            .extension(viewer_extension())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({"features": flags})).unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
