//! HTTP handlers for the runtime feature-flag admin API (issue #42).
//!
//! Three routes, all gated by `ApiKeyRole::Admin`:
//!
//! - `GET    /api/v1/config/features`             — list the current
//!   [`FeatureFlagsView`] (values + `effective` + `overridden_by`).
//! - `PUT    /api/v1/config/features/:feature`    — toggle one flag.
//! - `PUT    /api/v1/config/features`             — atomic bulk update.
//!
//! Validation runs inside the [`crate::config_handle::ConfigHandle::update`]
//! closure (generic over the typed `ValidationError` — no string
//! prefix-encoding), so a single rule violation rolls back automatically
//! and the live config is never observed in a half-updated state. After a
//! successful swap, [`apply_runtime_effects`] diffs the previous and
//! next [`FeatureFlags`] and replays the changes onto
//! [`llmtrace_security::EnsembleRuntimeHandle`] so the ensemble's atomic
//! gates and operating-point thresholds reflect the new state on the
//! very next request.
//!
//! Each successful swap also:
//!
//! - Bumps `llmtrace_feature_flag_updates_total{feature}` once per
//!   differing field.
//! - Updates the `llmtrace_feature_flag_bool_state{feature}` /
//!   `llmtrace_feature_flag_string_state{feature,value}` info gauges so
//!   dashboards can show the live state without scraping the API.
//! - Writes a structured `tracing::info!` audit line (rate-limited 1/s
//!   per `(actor, feature)` to protect against pathological toggle
//!   loops — the counter and forensic AuditEvent persistence are NOT
//!   rate-limited).
//! - Persists an [`llmtrace_core::AuditEvent`] via
//!   `state.metadata().record_audit_event(...)` so the change is
//!   queryable long after log rotation.
//! - Writes the `config.runtime.yaml` sidecar overlay on disk.
//!   Disk-write failures are non-fatal (in-memory change still applies)
//!   and surface as a warning in the response body, matching FR-04.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use llmtrace_core::{ApiKeyRole, AuditEvent, AuthContext, ProxyConfig};
use llmtrace_security::OperatingPoint;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::config_handle::ConfigUpdateError;
use crate::feature_flags::{
    apply_single, write_runtime_overlay, FeatureFlags, FeatureId, FeatureKind, FeatureValue,
    ValidationError,
};
use crate::proxy::{AppState, MlModelStatus};

/// Debounce window for structured audit log emission. Counter and
/// forensic AuditEvent persistence are NOT gated by this.
const AUDIT_LOG_DEBOUNCE: Duration = Duration::from_secs(1);

/// Hard cap on the number of distinct `(actor, feature)` debounce
/// entries kept in memory. When the cap is reached the next write
/// triggers a sweep that evicts every entry whose last emission is
/// older than `AUDIT_LOG_DEBOUNCE * 10`, and — if the map is still
/// over-capacity afterwards — drains it wholesale. Rotating API keys
/// against a long-lived proxy would otherwise grow the map without
/// bound.
const AUDIT_DEBOUNCE_MAX_ENTRIES: usize = 4096;

/// Shared last-emission timestamps keyed by `"actor|feature"`. Lazily
/// initialised; lives for the process lifetime but is periodically
/// swept by [`should_log_audit`] so it cannot grow unbounded.
fn audit_debounce_state() -> &'static Mutex<HashMap<String, Instant>> {
    static STATE: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Body for `PUT /api/v1/config/features/:feature`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct UpdateFeatureRequest {
    pub value: FeatureValue,
}

/// Rich view of every feature flag exposed by the admin API.
///
/// The `values` map is the raw flag state (same field shape as the
/// legacy `FeatureFlags` struct). `effective` answers the operational
/// question "would flipping this flag actually change behavior on the
/// next request?". `overridden_by` names the higher-precedence config
/// layer (env/cli) that is currently shadowing the runtime value, if
/// any — it is `null` for the common case.
#[derive(Debug, Serialize, ToSchema)]
pub struct FeatureFlagsView {
    pub values: FeatureFlags,
    pub effective: BTreeMap<String, bool>,
    pub overridden_by: BTreeMap<String, Option<String>>,
}

/// Successful response from a single-feature PUT.
#[derive(Debug, Serialize, ToSchema)]
pub struct UpdateFeatureResponse {
    pub updated: String,
    pub previous: FeatureValue,
    pub view: FeatureFlagsView,
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
    pub view: FeatureFlagsView,
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

fn map_update_error(err: ConfigUpdateError<ValidationError>) -> Response {
    match err {
        ConfigUpdateError::Validation(e) => {
            let status = e.http_status();
            let etype = e.error_type();
            api_error(status, etype, &e.to_string())
        }
        ConfigUpdateError::Poisoned => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_lock_poisoned",
            "Config writer lock is poisoned; restart the proxy",
        ),
    }
}

fn feature_value_display(v: &FeatureValue) -> String {
    match v {
        FeatureValue::Bool(b) => b.to_string(),
        FeatureValue::String(s) => s.clone(),
    }
}

/// Whether a flag's runtime toggle would be observable on the next
/// request, based on startup state.
///
/// Analyzer flags require the corresponding ML model to be loaded at
/// startup; flipping them from an off-at-startup state is a silent
/// no-op (documented in issue #42), and this is how operators detect
/// that. The ensemble tuning knobs (`operating_point`, `over_defence`)
/// are effective only when **at least one** ML analyzer is loaded —
/// on a pure-regex deployment the ensemble short-circuits and these
/// knobs have no effect even though `ml_status == Loaded`. HOT flags
/// are always effective.
///
/// `llm_judge_enabled` is always `false` — the store-only contract is
/// explicit, not an operational surprise.
fn feature_is_effective(ml_status: &MlModelStatus, id: FeatureId) -> bool {
    use FeatureId::*;
    match id {
        AnalyzerMlEnabled => matches!(
            ml_status,
            MlModelStatus::Loaded {
                prompt_injection: true,
                ..
            }
        ),
        AnalyzerInjecguardEnabled => matches!(
            ml_status,
            MlModelStatus::Loaded {
                injecguard: true,
                ..
            }
        ),
        AnalyzerPiguardEnabled => matches!(ml_status, MlModelStatus::Loaded { piguard: true, .. }),
        // The ensemble short-circuits when none of the three ML
        // sub-models is loaded, so the ensemble-tuning knobs only
        // affect scoring when at least one is active. Flagging them
        // effective on a pure-regex deployment would lie to operators.
        OperatingPoint | OverDefence => matches!(
            ml_status,
            MlModelStatus::Loaded {
                prompt_injection: true,
                ..
            } | MlModelStatus::Loaded {
                injecguard: true,
                ..
            } | MlModelStatus::Loaded { piguard: true, .. }
        ),
        LlmJudgeEnabled => false,
        AnalyzerJailbreakEnabled
        | EnforcementMode
        | BoundaryDefenseEnabled
        | BoundaryDefenseShadowMode
        | RateLimitingEnabled
        | CostCapsEnabled => true,
    }
}

/// Placeholder for ENV/CLI shadow detection. Today no env var or CLI
/// flag overrides a feature-flag field, so this always returns `None`.
/// When future env vars are wired into `config::apply_env_overrides`,
/// add the detection here so operators get immediate visibility that
/// a PUT they made has no effect at restart.
fn feature_overridden_by(_id: FeatureId) -> Option<String> {
    None
}

/// Project the rich [`FeatureFlagsView`] from a live config snapshot +
/// startup ML status.
fn build_view(flags: FeatureFlags, ml_status: &MlModelStatus) -> FeatureFlagsView {
    let mut effective = BTreeMap::new();
    let mut overridden_by = BTreeMap::new();
    for id in FeatureId::ALL {
        effective.insert(id.name().to_string(), feature_is_effective(ml_status, *id));
        overridden_by.insert(id.name().to_string(), feature_overridden_by(*id));
    }
    FeatureFlagsView {
        values: flags,
        effective,
        overridden_by,
    }
}

/// Iterate over the locked [`FeatureId::ALL`] slice, yielding
/// `(id, prev, next)` triples only for fields whose values differ.
fn diff_flags<'a>(
    prev: &'a FeatureFlags,
    next: &'a FeatureFlags,
) -> impl Iterator<Item = (FeatureId, FeatureValue, FeatureValue)> + 'a {
    FeatureId::ALL.iter().filter_map(move |&id| {
        let p = id.read(prev);
        let n = id.read(next);
        if p == n {
            None
        } else {
            Some((id, p, n))
        }
    })
}

/// Refresh the Prometheus state gauges for every feature in the
/// `diff` iteration. Called after a successful swap.
fn update_state_metrics(state: &AppState, prev: &FeatureFlags, next: &FeatureFlags) {
    for (id, old_val, new_val) in diff_flags(prev, next) {
        match id.kind() {
            FeatureKind::Bool => {
                let v = matches!(new_val, FeatureValue::Bool(true));
                state
                    .metrics
                    .feature_flag_bool_state
                    .with_label_values(&[id.name()])
                    .set(i64::from(v));
            }
            FeatureKind::String => {
                if let FeatureValue::String(old) = &old_val {
                    let _ = state
                        .metrics
                        .feature_flag_string_state
                        .remove_label_values(&[id.name(), old.as_str()]);
                }
                if let FeatureValue::String(new) = &new_val {
                    state
                        .metrics
                        .feature_flag_string_state
                        .with_label_values(&[id.name(), new.as_str()])
                        .set(1);
                }
            }
        }
    }
}

/// Initial snapshot of the state metrics, called from `build_app_state`
/// so dashboards show the correct values from process start.
pub fn init_state_metrics(state: &AppState, flags: &FeatureFlags) {
    for id in FeatureId::ALL {
        let val = id.read(flags);
        match id.kind() {
            FeatureKind::Bool => {
                let v = matches!(val, FeatureValue::Bool(true));
                state
                    .metrics
                    .feature_flag_bool_state
                    .with_label_values(&[id.name()])
                    .set(i64::from(v));
            }
            FeatureKind::String => {
                if let FeatureValue::String(s) = &val {
                    state
                        .metrics
                        .feature_flag_string_state
                        .with_label_values(&[id.name(), s.as_str()])
                        .set(1);
                }
            }
        }
    }
}

/// Return `true` when enough time has elapsed since the last audit log
/// emission for this `(actor, feature)` pair to warrant a new tracing
/// line. Prevents log spam from pathological toggle loops without
/// suppressing the counter or persisted AuditEvent.
///
/// The underlying map is bounded to [`AUDIT_DEBOUNCE_MAX_ENTRIES`]
/// entries. When capacity is reached, old entries (older than
/// `AUDIT_LOG_DEBOUNCE * 10`) are swept first; if the map is still
/// full after the sweep (pathological case — e.g. many active
/// rotating API keys) it is drained wholesale so the process cannot
/// grow without bound.
fn should_log_audit(actor: &str, feature: &str) -> bool {
    let key = format!("{actor}|{feature}");
    let now = Instant::now();
    let map = audit_debounce_state();
    let mut guard = match map.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if guard.len() >= AUDIT_DEBOUNCE_MAX_ENTRIES {
        let stale_cutoff = AUDIT_LOG_DEBOUNCE * 10;
        guard.retain(|_, last| now.duration_since(*last) < stale_cutoff);
        if guard.len() >= AUDIT_DEBOUNCE_MAX_ENTRIES {
            guard.clear();
        }
    }

    match guard.get(&key) {
        Some(last) if now.duration_since(*last) < AUDIT_LOG_DEBOUNCE => false,
        _ => {
            guard.insert(key, now);
            true
        }
    }
}

#[cfg(test)]
fn reset_audit_debounce() {
    let map = audit_debounce_state();
    if let Ok(mut guard) = map.lock() {
        guard.clear();
    }
}

/// Emit structured audit log lines, bump the Prometheus counter, update
/// the state gauges, and persist a forensic [`AuditEvent`] per changed
/// field.
async fn record_audit_and_metrics(
    state: &AppState,
    auth: &AuthContext,
    prev: &FeatureFlags,
    next: &FeatureFlags,
) {
    let actor = auth
        .key_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "bootstrap-admin".to_string());
    let timestamp = chrono::Utc::now();
    let timestamp_str = timestamp.to_rfc3339();

    let diffs: Vec<(FeatureId, FeatureValue, FeatureValue)> = diff_flags(prev, next).collect();

    // Metrics — state gauges and per-feature update counter — fire on
    // every diff without rate limiting.
    update_state_metrics(state, prev, next);

    for (id, prev_val, next_val) in &diffs {
        let name = id.name();
        state
            .metrics
            .feature_flag_updates_total
            .with_label_values(&[name])
            .inc();

        let old_display = feature_value_display(prev_val);
        let new_display = feature_value_display(next_val);

        if should_log_audit(&actor, name) {
            tracing::info!(
                event = "feature_flag_changed",
                actor = %actor,
                actor_role = %auth.role,
                feature = %name,
                old_value = %old_display,
                new_value = %new_display,
                timestamp = %timestamp_str,
                "runtime feature flag updated"
            );
        }

        // Forensic AuditEvent — always persisted, never rate-limited.
        let event = AuditEvent {
            id: uuid::Uuid::new_v4(),
            tenant_id: auth.tenant_id,
            event_type: "feature_flag_changed".to_string(),
            actor: actor.clone(),
            resource: format!("feature/{name}"),
            data: serde_json::json!({
                "feature": name,
                "old_value": old_display,
                "new_value": new_display,
                "actor_role": auth.role.to_string(),
            }),
            timestamp,
        };
        if let Err(e) = state.metadata().record_audit_event(&event).await {
            tracing::warn!(
                feature = %name,
                "Failed to persist feature_flag_changed audit event: {e}"
            );
        }
    }
}

/// Diff `prev` against `next` and replay the changes on the ensemble's
/// runtime handle so the security analyzer's atomic gates pick up the
/// new state on the very next request.
fn apply_runtime_effects(state: &AppState, prev: &FeatureFlags, next: &FeatureFlags) {
    let rh = &state.ensemble_runtime;
    for (id, _old, new_val) in diff_flags(prev, next) {
        match id {
            FeatureId::AnalyzerMlEnabled => {
                if let FeatureValue::Bool(b) = new_val {
                    rh.set_ml(b);
                }
            }
            FeatureId::AnalyzerInjecguardEnabled => {
                if let FeatureValue::Bool(b) = new_val {
                    rh.set_injecguard(b);
                }
            }
            FeatureId::AnalyzerPiguardEnabled => {
                if let FeatureValue::Bool(b) = new_val {
                    rh.set_piguard(b);
                }
            }
            FeatureId::AnalyzerJailbreakEnabled => {
                if let FeatureValue::Bool(b) = new_val {
                    rh.set_jailbreak(b);
                }
            }
            FeatureId::OverDefence => {
                if let FeatureValue::Bool(b) = new_val {
                    rh.set_over_defence(b);
                }
            }
            FeatureId::OperatingPoint => {
                if let FeatureValue::String(s) = new_val {
                    let point = match s.as_str() {
                        "balanced" => OperatingPoint::Balanced,
                        "high_recall" => OperatingPoint::HighRecall,
                        "high_precision" => OperatingPoint::HighPrecision,
                        _ => continue,
                    };
                    rh.set_operating_point(point);
                }
            }
            // HOT flags and the store-only llm_judge_enabled need no
            // runtime side effect: they are read per-request from the
            // live config snapshot (or, in llm_judge's case, by the
            // future #43 implementation).
            FeatureId::EnforcementMode
            | FeatureId::BoundaryDefenseEnabled
            | FeatureId::BoundaryDefenseShadowMode
            | FeatureId::RateLimitingEnabled
            | FeatureId::CostCapsEnabled
            | FeatureId::LlmJudgeEnabled => {}
        }
    }
}

fn collect_warnings(
    prev: &FeatureFlags,
    next: &FeatureFlags,
    view: &FeatureFlagsView,
) -> Vec<String> {
    let mut out = Vec::new();
    if next.llm_judge_enabled && !prev.llm_judge_enabled {
        out.push(
            "llm_judge backend not implemented yet; flag stored but no analyzer reads it (see #43)"
                .to_string(),
        );
    }
    for (id, _old, new_val) in diff_flags(prev, next) {
        let name = id.name();
        // Only warn about inert bool flags when the operator is
        // trying to ENABLE a subsystem that isn't loaded. Flipping an
        // already-off ML analyzer to `false` is a no-op that matches
        // the on-disk state — no need to scare the operator.
        // String flags (operating_point) always warn on diff when
        // inert because changing their value is always a positive
        // intent to reconfigure.
        let direction_warrants_inert_warning = match &new_val {
            FeatureValue::Bool(true) => true,
            FeatureValue::Bool(false) => false,
            FeatureValue::String(_) => true,
        };
        if direction_warrants_inert_warning && view.effective.get(name) == Some(&false) {
            out.push(format!(
                "flag '{name}' is inert: the backing subsystem was not loaded at startup; \
                 the value is persisted but no request will observe it until the proxy restarts \
                 with the corresponding startup configuration"
            ));
        }
        if let Some(Some(source)) = view.overridden_by.get(name) {
            out.push(format!(
                "flag '{name}' is currently shadowed by '{source}'; the runtime value is persisted \
                 but a process restart will be overridden by the {source} layer"
            ));
        }
    }
    out
}

/// Persist the current feature-flag snapshot to the sidecar overlay
/// file, if configured. Returns a warning string on failure so the API
/// response can surface the problem without returning an HTTP error —
/// FR-04 of issue #42 explicitly requires the in-memory change to
/// still apply even when disk persistence fails.
fn persist_overlay(state: &AppState, flags: &FeatureFlags) -> Option<String> {
    let path = state.config_handle.persist_path()?;
    match write_runtime_overlay(path, flags) {
        Ok(()) => None,
        Err(e) => {
            state.metrics.config_persist_errors_total.inc();
            tracing::error!(
                event = "config_persist_failed",
                path = %path.display(),
                error = %e,
                "Failed to persist runtime feature flag overlay"
            );
            Some(format!(
                "runtime overlay persistence failed: {e}; change applied in memory only"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/config/features` — return the current feature-flag snapshot.
#[utoipa::path(
    get,
    path = "/api/v1/config/features",
    responses(
        (status = 200, description = "Current feature flag view", body = FeatureFlagsView),
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
    let flags = FeatureFlags::from_config(&cfg);
    let view = build_view(flags, &state.ml_status);
    Json(view).into_response()
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

    // Surface immutable / unknown names with their specific error
    // categories before touching the config handle.
    if feature == "analyzer_regex_enabled" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "immutable",
            "feature 'analyzer_regex_enabled' is immutable",
        );
    }
    let previous = match FeatureId::from_name(&feature).map(|id| id.read(&prev_flags)) {
        Some(v) => v,
        None => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "unknown_feature",
                &format!("unknown feature: {feature}"),
            )
        }
    };

    let result = state
        .config_handle
        .update::<_, ValidationError>(|cfg: &mut ProxyConfig| {
            apply_single(cfg, &feature, body.value)
        });

    let new_arc = match result {
        Ok(arc) => arc,
        Err(e) => return map_update_error(e),
    };

    let next_flags = FeatureFlags::from_config(&new_arc);
    apply_runtime_effects(&state, &prev_flags, &next_flags);
    record_audit_and_metrics(&state, &auth, &prev_flags, &next_flags).await;
    let view = build_view(next_flags.clone(), &state.ml_status);
    let mut warnings = collect_warnings(&prev_flags, &next_flags, &view);
    if let Some(msg) = persist_overlay(&state, &next_flags) {
        warnings.push(msg);
    }

    let resp = UpdateFeatureResponse {
        updated: feature,
        previous,
        view,
        warnings,
    };
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

    let result = state
        .config_handle
        .update::<_, ValidationError>(|cfg: &mut ProxyConfig| body.features.apply_to_config(cfg));

    let new_arc = match result {
        Ok(arc) => arc,
        Err(e) => return map_update_error(e),
    };

    let next_flags = FeatureFlags::from_config(&new_arc);
    apply_runtime_effects(&state, &prev_flags, &next_flags);
    record_audit_and_metrics(&state, &auth, &prev_flags, &next_flags).await;
    let view = build_view(next_flags.clone(), &state.ml_status);
    let mut warnings = collect_warnings(&prev_flags, &next_flags, &view);
    if let Some(msg) = persist_overlay(&state, &next_flags) {
        warnings.push(msg);
    }

    let resp = BulkUpdateResponse { view, warnings };
    (StatusCode::OK, Json(resp)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_handle::ConfigHandle;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        routing::{get, put},
        Router,
    };
    use llmtrace_core::{
        ApiKeyRole, AuthContext, EnforcementMode, OperatingPoint as CoreOperatingPoint,
        ProxyConfig, SecurityAnalyzer, StorageConfig, TenantId,
    };
    use llmtrace_security::{EnsembleRuntimeHandle, RegexSecurityAnalyzer};
    use llmtrace_storage::StorageProfile;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn test_state() -> Arc<AppState> {
        test_state_with_persistence(None).await
    }

    async fn test_state_with_persistence(
        persist_path: Option<std::path::PathBuf>,
    ) -> Arc<AppState> {
        reset_audit_debounce();
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
            config_handle: ConfigHandle::new(config, None, persist_path),
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
            runtime_overlay_status: crate::proxy::RuntimeOverlayStatus::Disabled,
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
    async fn get_features_returns_defaults_and_view_shape() {
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_get("/api/v1/config/features"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["values"]["enforcement_mode"], "log");
        assert_eq!(body["values"]["operating_point"], "balanced");
        assert_eq!(body["values"]["llm_judge_enabled"], false);
        // effective + overridden_by maps exist for every flag
        let effective = body["effective"].as_object().unwrap();
        assert!(effective.contains_key("enforcement_mode"));
        // llm_judge_enabled is always inert (store-only)
        assert_eq!(effective["llm_judge_enabled"], false);
        // analyzer_ml_enabled is inert when ml_status is Disabled
        assert_eq!(effective["analyzer_ml_enabled"], false);
        // HOT flags are always effective
        assert_eq!(effective["enforcement_mode"], true);
        assert_eq!(effective["rate_limiting_enabled"], true);
        // overridden_by is null for every flag today
        let overridden_by = body["overridden_by"].as_object().unwrap();
        assert!(overridden_by.values().all(|v| v.is_null()));
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
        assert_eq!(body["view"]["values"]["enforcement_mode"], "block");
        assert_eq!(
            state.config_handle.snapshot().enforcement.mode,
            EnforcementMode::Block
        );
    }

    #[tokio::test]
    async fn put_single_operating_point_propagates_to_runtime_handle() {
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
            CoreOperatingPoint::HighPrecision
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
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("llm_judge")));
    }

    #[tokio::test]
    async fn put_single_analyzer_ml_enabled_enable_surfaces_inert_warning() {
        // test_state() builds ml_status = Disabled. Default config has
        // analyzer_ml_enabled = true, so flip it off first and then
        // attempt to re-enable; the true-direction flip should emit
        // the inert warning because no ML model was loaded at startup.
        let state = test_state().await;
        state
            .config_handle
            .update::<_, ValidationError>(|c| {
                c.security_analysis.ml_enabled = false;
                Ok(())
            })
            .unwrap();
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/analyzer_ml_enabled",
                serde_json::json!({"value": true}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let warnings = body["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap().contains("inert")),
            "expected inert warning on true-direction flip against Disabled ML, got {:?}",
            warnings
        );
        assert_eq!(body["view"]["effective"]["analyzer_ml_enabled"], false);
    }

    #[tokio::test]
    async fn put_single_analyzer_ml_enabled_disable_does_not_warn() {
        // Disabling an already-off ML analyzer on a Disabled ml_status
        // box should NOT surface an inert warning — the operator's
        // intent (off) matches the runtime state (off). Flipping the
        // default true -> false is a no-op with respect to inert
        // semantics.
        let state = test_state().await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/analyzer_ml_enabled",
                serde_json::json!({"value": false}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let warnings = body["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .all(|w| !w.as_str().unwrap().contains("inert")),
            "disable direction should not emit inert warning, got {:?}",
            warnings
        );
    }

    #[tokio::test]
    async fn put_bulk_atomic_rollback_on_validation_error() {
        let state = test_state().await;
        let mut flags = FeatureFlags::from_config(&state.config_handle.snapshot());
        flags.enforcement_mode = "block".to_string();
        flags.boundary_defense_enabled = false;
        flags.boundary_defense_shadow_mode = true;

        let app = admin_router(state.clone());
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features",
                serde_json::json!({"features": flags}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
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
        assert!(!state.ensemble_runtime.ml());
        assert!(state.ensemble_runtime.over_defence());
    }

    #[tokio::test]
    async fn put_single_persists_overlay_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let overlay_path = tmp.path().join("config.runtime.yaml");
        let state = test_state_with_persistence(Some(overlay_path.clone())).await;
        let app = admin_router(state.clone());
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/enforcement_mode",
                serde_json::json!({"value": "block"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(overlay_path.exists());
        let loaded = crate::feature_flags::load_runtime_overlay(&overlay_path)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.enforcement_mode, "block");
    }

    #[tokio::test]
    async fn put_single_persistence_failure_returns_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, "").unwrap();
        let overlay_path = blocker.join("config.runtime.yaml");
        let state = test_state_with_persistence(Some(overlay_path)).await;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features/enforcement_mode",
                serde_json::json!({"value": "block"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let warnings = body["warnings"].as_array().unwrap();
        assert!(warnings.iter().any(|w| w
            .as_str()
            .unwrap()
            .contains("runtime overlay persistence failed")));
    }

    #[tokio::test]
    async fn put_bulk_persists_overlay_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let overlay_path = tmp.path().join("config.runtime.yaml");
        let state = test_state_with_persistence(Some(overlay_path.clone())).await;
        let mut flags = FeatureFlags::from_config(&state.config_handle.snapshot());
        flags.cost_caps_enabled = true;
        flags.over_defence = true;
        let app = admin_router(state);
        let resp = app
            .oneshot(admin_put(
                "/api/v1/config/features",
                serde_json::json!({"features": flags}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let loaded = crate::feature_flags::load_runtime_overlay(&overlay_path)
            .unwrap()
            .unwrap();
        assert!(loaded.cost_caps_enabled);
        assert!(loaded.over_defence);
    }

    #[tokio::test]
    async fn put_single_bumps_feature_flag_metric() {
        let state = test_state().await;
        let app = admin_router(state.clone());
        let _ = app
            .oneshot(admin_put(
                "/api/v1/config/features/enforcement_mode",
                serde_json::json!({"value": "block"}),
            ))
            .await
            .unwrap();
        let val = state
            .metrics
            .feature_flag_updates_total
            .with_label_values(&["enforcement_mode"])
            .get();
        assert_eq!(val, 1);
    }

    #[tokio::test]
    async fn put_bulk_bumps_counter_once_per_changed_field() {
        let state = test_state().await;
        let mut flags = FeatureFlags::from_config(&state.config_handle.snapshot());
        flags.cost_caps_enabled = true;
        flags.over_defence = true;
        flags.enforcement_mode = "flag".to_string();
        let app = admin_router(state.clone());
        let _ = app
            .oneshot(admin_put(
                "/api/v1/config/features",
                serde_json::json!({"features": flags}),
            ))
            .await
            .unwrap();
        assert_eq!(
            state
                .metrics
                .feature_flag_updates_total
                .with_label_values(&["cost_caps_enabled"])
                .get(),
            1
        );
        assert_eq!(
            state
                .metrics
                .feature_flag_updates_total
                .with_label_values(&["over_defence"])
                .get(),
            1
        );
        assert_eq!(
            state
                .metrics
                .feature_flag_updates_total
                .with_label_values(&["enforcement_mode"])
                .get(),
            1
        );
        assert_eq!(
            state
                .metrics
                .feature_flag_updates_total
                .with_label_values(&["operating_point"])
                .get(),
            0
        );
    }

    #[tokio::test]
    async fn persistence_failure_bumps_error_counter() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, "").unwrap();
        let overlay_path = blocker.join("config.runtime.yaml");
        let state = test_state_with_persistence(Some(overlay_path)).await;
        let app = admin_router(state.clone());
        let _ = app
            .oneshot(admin_put(
                "/api/v1/config/features/enforcement_mode",
                serde_json::json!({"value": "block"}),
            ))
            .await
            .unwrap();
        assert_eq!(state.metrics.config_persist_errors_total.get(), 1);
    }

    #[tokio::test]
    async fn bool_state_gauge_tracks_live_flag() {
        let state = test_state().await;
        // Initialize to defaults so the gauge reflects them even without
        // going through an API call.
        init_state_metrics(
            &state,
            &FeatureFlags::from_config(&state.config_handle.snapshot()),
        );
        assert_eq!(
            state
                .metrics
                .feature_flag_bool_state
                .with_label_values(&["cost_caps_enabled"])
                .get(),
            0
        );
        let app = admin_router(state.clone());
        let _ = app
            .oneshot(admin_put(
                "/api/v1/config/features/cost_caps_enabled",
                serde_json::json!({"value": true}),
            ))
            .await
            .unwrap();
        assert_eq!(
            state
                .metrics
                .feature_flag_bool_state
                .with_label_values(&["cost_caps_enabled"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn string_state_gauge_moves_label_combination_on_change() {
        let state = test_state().await;
        init_state_metrics(
            &state,
            &FeatureFlags::from_config(&state.config_handle.snapshot()),
        );
        // Default is "log" initially -> gauge value 1.
        assert_eq!(
            state
                .metrics
                .feature_flag_string_state
                .with_label_values(&["enforcement_mode", "log"])
                .get(),
            1
        );
        let app = admin_router(state.clone());
        let _ = app
            .oneshot(admin_put(
                "/api/v1/config/features/enforcement_mode",
                serde_json::json!({"value": "block"}),
            ))
            .await
            .unwrap();
        // Old combo was removed (get returns 0 because a newly-vivified
        // child on a removed label resets), new combo is 1.
        assert_eq!(
            state
                .metrics
                .feature_flag_string_state
                .with_label_values(&["enforcement_mode", "block"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn put_persists_forensic_audit_event() {
        let state = test_state().await;
        let tenant_id = admin_extension().tenant_id;
        // The test_state admin_extension() TenantId isn't the one in
        // the request — the handler reads auth.tenant_id from the
        // Extension we set. Re-read by constructing a fresh extension
        // and sharing its tenant across the request and the query.
        let auth = AuthContext {
            tenant_id,
            role: ApiKeyRole::Admin,
            key_id: None,
        };
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/config/features/enforcement_mode")
            .header("content-type", "application/json")
            .extension(auth)
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({"value": "flag"})).unwrap(),
            ))
            .unwrap();
        let app = admin_router(state.clone());
        let _ = app.oneshot(req).await.unwrap();

        let query = llmtrace_core::AuditQuery::new(tenant_id);
        let events = state
            .metadata()
            .query_audit_events(&query)
            .await
            .unwrap_or_default();
        let matched = events.iter().any(|e| {
            e.event_type == "feature_flag_changed" && e.resource == "feature/enforcement_mode"
        });
        assert!(matched, "expected forensic audit event, got {:?}", events);
    }

    #[test]
    fn audit_debounce_map_is_bounded() {
        // Fill the debounce map past AUDIT_DEBOUNCE_MAX_ENTRIES with
        // unique (actor, feature) pairs and assert the state map size
        // never exceeds the cap after the next write.
        reset_audit_debounce();
        for i in 0..(AUDIT_DEBOUNCE_MAX_ENTRIES + 500) {
            let actor = format!("actor-{i}");
            let _ = should_log_audit(&actor, "enforcement_mode");
        }
        let map = audit_debounce_state();
        let guard = map.lock().unwrap();
        assert!(
            guard.len() <= AUDIT_DEBOUNCE_MAX_ENTRIES,
            "debounce map grew beyond cap: {}",
            guard.len()
        );
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
