//! Debug-only HTTP endpoints used by the e2e adversarial test framework
//! (umbrella issue #91, child #95).
//!
//! Every route in this module is gated by `server.debug_endpoints: true`.
//! The default is `false`, and `build_router` does not register the
//! routes at all when the flag is off — there is no per-request opt-in
//! and no auth bypass: if the flag is off the endpoint returns 404 from
//! axum's not-found handler because it was never mounted.
//!
//! These endpoints return raw verdict payloads keyed by `trace_id` and
//! must therefore never be reachable from production proxies.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{Response, StatusCode};
use llmtrace_core::JudgeVerdictQuery;
use llmtrace_security::golden_set::{load_golden_set, replay_golden_set};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use crate::proxy::AppState;

/// Env var read by [`golden_set_replay_handler`] to resolve the
/// fixture root at request time. Operators set this when enabling
/// `server.debug_endpoints: true` and want the replay endpoint to do
/// real work; if unset the endpoint returns 503 with a clear message.
pub const GOLDEN_SET_PATH_ENV: &str = "LLMTRACE_GOLDEN_SET_PATH";

/// Query parameters for `GET /debug/judge/verdicts`.
#[derive(Debug, Deserialize)]
pub struct VerdictByTraceIdParams {
    /// Required. The `trace_id` correlated with a request the e2e
    /// harness fired earlier in the same session.
    pub trace_id: String,
}

/// `GET /debug/judge/verdicts?trace_id=<uuid>`.
///
/// Returns the most recent persisted [`JudgeVerdict`] for the trace as
/// JSON, or 404 if no verdict has been recorded yet (the judge worker
/// runs asynchronously after the upstream response, so the harness
/// polls this endpoint).
///
/// Implemented as a thin wrapper over the existing
/// `JudgeVerdictStore::query_verdicts` trait method using the already
/// supported `JudgeVerdictQuery { trace_id, .. }` filter — no new
/// trait surface is required (see Loop E2E-L1 audit finding E2E-003).
pub async fn verdict_by_trace_id_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<VerdictByTraceIdParams>,
) -> Response<Body> {
    let trace_id = match Uuid::parse_str(params.trace_id.trim()) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "trace_id must be a UUID"),
    };

    let query = JudgeVerdictQuery {
        trace_id: Some(trace_id),
        limit: Some(1),
        ..JudgeVerdictQuery::default()
    };

    let verdicts = match state.storage.judge_verdicts.query_verdicts(&query).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(%trace_id, error = %err, "verdict_by_trace_id query failed");
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, "verdict query failed");
        }
    };

    let Some(verdict) = verdicts.into_iter().next() else {
        return error_json(StatusCode::NOT_FOUND, "no verdict for trace_id");
    };

    let body = match serde_json::to_vec(&verdict) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(%trace_id, error = %err, "verdict serialization failed");
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "verdict serialization failed",
            );
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("infallible response build")
}

fn error_json(status: StatusCode, message: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": { "message": message, "type": "debug_error" } });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("infallible response build")
}

/// `GET /debug/judge/golden_set/replay`.
///
/// Loads every fixture from `$LLMTRACE_GOLDEN_SET_PATH`, replays each
/// prompt through `state.security`, updates the
/// [`llmtrace_judge_golden_set_alignment`] /
/// [`llmtrace_judge_golden_set_false_positive_rate`] gauges, and
/// returns the aggregate [`GoldenSetReplay`] as JSON.
///
/// # Status codes
///
/// | Status | Meaning |
/// |---|---|
/// | `200` | Replay succeeded; body is the JSON summary. |
/// | `503` | `LLMTRACE_GOLDEN_SET_PATH` is unset — replay disabled. |
/// | `400` | Fixture root invalid (does not exist, schema violation). |
/// | `500` | Analyzer call failed mid-replay. |
///
/// Same gating as the verdict endpoint: only registered when
/// `server.debug_endpoints: true`.
pub async fn golden_set_replay_handler(State(state): State<Arc<AppState>>) -> Response<Body> {
    let path = match std::env::var(GOLDEN_SET_PATH_ENV) {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => {
            return error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                concat!(
                    "golden-set replay disabled: set ",
                    "LLMTRACE_GOLDEN_SET_PATH to the fixture root ",
                    "(e.g. crates/llmtrace-security/fixtures/judge_golden_set)"
                ),
            );
        }
    };

    let entries = match load_golden_set(&path) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, root = %path.display(), "golden-set load failed");
            return error_json(StatusCode::BAD_REQUEST, &format!("load failed: {err}"));
        }
    };

    let result = match replay_golden_set(&path, &entries, state.security.as_ref()).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "golden-set replay failed");
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("replay failed: {err}"),
            );
        }
    };

    for cat in &result.categories {
        state.metrics.record_golden_set_alignment(
            &cat.category,
            cat.alignment_rate,
            cat.false_positive_rate,
        );
    }

    let body = match serde_json::to_vec(&result) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, "golden-set serialization failed");
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed");
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("infallible response build")
}
