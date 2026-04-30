//! Prometheus metrics for the LLMTrace proxy.
//!
//! Provides a [`Metrics`] struct that holds all Prometheus metric collectors
//! (counters, histograms, gauges) and a handler that renders them in
//! Prometheus exposition text format at `/metrics`.
//!
//! The endpoint is intentionally unauthenticated — this is the standard
//! convention for Prometheus scraping endpoints.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::sync::Arc;

use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// Metrics struct
// ---------------------------------------------------------------------------

/// Holds all Prometheus metric collectors for the proxy.
///
/// Constructed once at startup and shared via [`AppState`]. Individual
/// handlers and background tasks call the `record_*` helpers to update
/// the relevant counters/histograms after each operation.
#[derive(Clone)]
pub struct Metrics {
    /// Private Prometheus registry — keeps our metrics isolated from the
    /// global default registry so tests are deterministic.
    registry: Registry,

    /// Total requests proxied, labelled by provider, model, and HTTP status.
    pub requests_total: IntCounterVec,

    /// Request duration in seconds, labelled by provider and model.
    pub request_duration_seconds: HistogramVec,

    /// Total tokens observed, labelled by direction (prompt|completion),
    /// provider, and model.
    pub tokens_total: IntCounterVec,

    /// Security findings detected, labelled by severity and finding type.
    pub security_findings_total: IntCounterVec,

    /// Circuit-breaker state gauge (1.0 = active state), labelled by
    /// subsystem (storage|security) and state (closed|open|half_open).
    pub circuit_breaker_state: GaugeVec,

    /// Storage operations, labelled by operation and status (success|error).
    pub storage_operations_total: IntCounterVec,

    /// Estimated cost in USD, labelled by tenant and model.
    pub cost_usd_total: IntCounterVec,

    /// Anomalies detected, labelled by anomaly type.
    pub anomalies_total: IntCounterVec,

    /// Per-detector security analysis latency, labelled by detector name.
    pub security_detector_latency_seconds: HistogramVec,

    /// Currently active connections / in-flight proxy requests.
    pub active_connections: IntGauge,

    /// Requests where boundary defense was applied, labelled by provider and mode.
    pub boundary_defense_applied_total: IntCounterVec,

    /// Number of messages wrapped per request, labelled by provider.
    pub boundary_defense_messages_wrapped: HistogramVec,

    /// Requests where system prompt reminder was injected, labelled by provider.
    pub boundary_defense_reminder_injected_total: IntCounterVec,

    /// Byte delta per request from boundary defense, labelled by provider.
    pub boundary_defense_overhead_bytes: HistogramVec,

    /// Errors in boundary defense pipeline, labelled by error type.
    pub boundary_defense_errors_total: IntCounterVec,

    /// Requests skipped by boundary defense, labelled by reason.
    pub boundary_defense_skipped_total: IntCounterVec,

    /// Whether shadow mode is active (1) or not (0).
    pub boundary_defense_shadow_mode: IntGauge,

    /// Zones emitted by the IS-060 zone detector, labelled by
    /// kind (`instruction`/`data`), origin
    /// (`role`/`heuristic`/`operator_inline`/`operator_header`), and
    /// `framing` (heuristic label, or `_` when `origin != heuristic`).
    pub zone_detection_zones_total: IntCounterVec,

    /// Findings produced by zone-aware analysis, labelled by
    /// `finding_type` and `zone_kind`. Combined with
    /// `security_findings_total{finding_type}` this lets dashboards
    /// attribute each finding to the zone path.
    pub zone_detection_findings_total: IntCounterVec,

    /// Zone-detection failures (header parse errors, byte-range
    /// out-of-bounds against the message content, etc.), labelled by
    /// reason.
    pub zone_detection_failures_total: IntCounterVec,

    /// ML sliding window chunks processed per classify call.
    pub ml_chunks_total: HistogramVec,

    /// ML inputs that hit the MAX_CHUNKS cap.
    pub ml_input_truncated_total: IntCounterVec,

    /// Response collections truncated due to max_response_size_bytes.
    pub response_truncated_total: IntCounter,

    /// Analysis text truncations due to max_analysis_text_bytes.
    pub analysis_text_truncated_total: IntCounter,

    /// Total enforcement actions executed by the router.
    pub action_executions_total: IntCounterVec,
    /// Action execution latency in seconds.
    pub action_latency_seconds: HistogramVec,
    /// Currently active IP blocks recorded by this proxy instance.
    pub ip_blocks_active: IntGauge,
    /// Total action-rule matches by finding type and action type.
    pub action_rule_matches_total: IntCounterVec,

    /// Feature flag updates by feature name (issue #42).
    ///
    /// Incremented once per changed field in a PUT request to
    /// `/api/v1/config/features`. Bulk updates increment once per
    /// differing field, not once per request, so dashboards can
    /// distinguish which flags are getting toggled hot.
    pub feature_flag_updates_total: IntCounterVec,

    /// Current runtime value of every bool-typed feature flag (0 or 1).
    ///
    /// Dashboards query this gauge to display the live state of
    /// `analyzer_*_enabled`, `boundary_defense_*`, `rate_limiting_enabled`,
    /// `cost_caps_enabled`, `over_defence`, and `llm_judge_enabled` without
    /// hitting `/api/v1/config/features`.
    pub feature_flag_bool_state: IntGaugeVec,

    /// Current runtime value of every string-typed feature flag as an
    /// info metric. One (feature, value) combination per flag is set to
    /// 1 at a time; on change the old combination is zeroed so stale
    /// label pairs do not accumulate.
    pub feature_flag_string_state: IntGaugeVec,

    /// Failed writes of the sidecar `config.runtime.yaml` overlay.
    ///
    /// A non-zero value means the in-memory change took effect but the
    /// next proxy restart will revert it.
    pub config_persist_errors_total: IntCounter,

    /// Forensic audit events that could not be persisted to the
    /// metadata store, labelled by event type. A non-zero value on
    /// `{event_type="feature_flag_changed"}` means a feature flag
    /// mutation was applied to live traffic without a durable audit
    /// record — alert on this in production dashboards. Issue #42 C2.
    pub audit_event_dropped_total: IntCounterVec,

    // ----------- LLM-as-a-Judge metrics (issue #43) -----------
    /// Total judge invocations labelled by backend, mode, and status.
    pub judge_requests_total: IntCounterVec,
    /// Judge call latency in seconds, labelled by backend and mode.
    pub judge_latency_seconds: HistogramVec,
    /// Judge token consumption by direction (prompt|completion) and backend.
    pub judge_tokens_total: IntCounterVec,
    /// Verdict distribution by category, recommended action, and threat flag.
    pub judge_verdicts_total: IntCounterVec,
    /// Current judge worker queue depth.
    pub judge_queue_depth: IntGauge,
    /// Agreement between judge and prior ensemble outcome.
    pub judge_verdict_agreement: IntCounterVec,
    /// Judge requests dropped without issuing a backend call.
    pub judge_dropped_total: IntCounterVec,
    /// Judge verdicts that failed the inline promotion gate (#70), by
    /// reason. Distinguishes from `judge_dropped_total`, which is
    /// pre-backend: a rejected promotion DID produce a verdict, the
    /// verdict just wasn't allowed to flip the decision to Block.
    pub judge_promotion_rejected_total: IntCounterVec,
    /// Judge verdicts that would have been promoted to Block but the
    /// promotion config had `shadow=true` (#84). Lets operators measure
    /// the enforcement rate in shadow mode before flipping enforcement
    /// on.
    pub judge_shadow_would_block_total: IntCounterVec,
    /// Per-category alignment between the security analyzer and the
    /// golden-set ground truth (#66 T3c). Updated by the
    /// `/debug/judge/golden_set/replay` endpoint. Range `[0.0, 1.0]`.
    /// A drop below the per-category floor (see
    /// `tests/judge_golden_set.rs::alignment_floor`) is the
    /// canonical drift signal alerted on in T4.
    pub judge_golden_set_alignment: GaugeVec,
    /// Per-category false-positive rate against benign golden-set
    /// entries (#66 T3c). Range `[0.0, 1.0]`.
    pub judge_golden_set_false_positive_rate: GaugeVec,
}

impl Metrics {
    /// Create a new `Metrics` instance with all collectors registered.
    ///
    /// # Panics
    ///
    /// Panics if any metric fails to register — this is called once at
    /// startup so a panic is appropriate (misconfiguration).
    pub fn new() -> Self {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("llmtrace_requests_total", "Total proxied LLM requests"),
            &["provider", "model", "status_code"],
        )
        .expect("metric: requests_total");
        registry
            .register(Box::new(requests_total.clone()))
            .expect("register requests_total");

        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "llmtrace_request_duration_seconds",
                "Request duration in seconds",
            )
            .buckets(vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]),
            &["provider", "model"],
        )
        .expect("metric: request_duration_seconds");
        registry
            .register(Box::new(request_duration_seconds.clone()))
            .expect("register request_duration_seconds");

        let tokens_total = IntCounterVec::new(
            Opts::new("llmtrace_tokens_total", "Total tokens observed"),
            &["direction", "provider", "model"],
        )
        .expect("metric: tokens_total");
        registry
            .register(Box::new(tokens_total.clone()))
            .expect("register tokens_total");

        let security_findings_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_security_findings_total",
                "Total security findings detected",
            ),
            &["severity", "finding_type"],
        )
        .expect("metric: security_findings_total");
        registry
            .register(Box::new(security_findings_total.clone()))
            .expect("register security_findings_total");

        let circuit_breaker_state = GaugeVec::new(
            Opts::new(
                "llmtrace_circuit_breaker_state",
                "Circuit breaker state (1 = active)",
            ),
            &["subsystem", "state"],
        )
        .expect("metric: circuit_breaker_state");
        registry
            .register(Box::new(circuit_breaker_state.clone()))
            .expect("register circuit_breaker_state");

        let storage_operations_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_storage_operations_total",
                "Total storage operations",
            ),
            &["operation", "status"],
        )
        .expect("metric: storage_operations_total");
        registry
            .register(Box::new(storage_operations_total.clone()))
            .expect("register storage_operations_total");

        let cost_usd_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_cost_usd_total",
                "Estimated cost in micro-USD (divide by 1_000_000 for USD)",
            ),
            &["tenant", "model"],
        )
        .expect("metric: cost_usd_total");
        registry
            .register(Box::new(cost_usd_total.clone()))
            .expect("register cost_usd_total");

        let anomalies_total = IntCounterVec::new(
            Opts::new("llmtrace_anomalies_total", "Total anomalies detected"),
            &["anomaly_type"],
        )
        .expect("metric: anomalies_total");
        registry
            .register(Box::new(anomalies_total.clone()))
            .expect("register anomalies_total");

        let security_detector_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "llmtrace_security_detector_latency_seconds",
                "Per-detector security analysis latency in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["detector"],
        )
        .expect("metric: security_detector_latency_seconds");
        registry
            .register(Box::new(security_detector_latency_seconds.clone()))
            .expect("register security_detector_latency_seconds");

        let active_connections = IntGauge::new(
            "llmtrace_active_connections",
            "Currently active proxy connections",
        )
        .expect("metric: active_connections");
        registry
            .register(Box::new(active_connections.clone()))
            .expect("register active_connections");

        // Boundary defense metrics
        let boundary_defense_applied_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_boundary_defense_applied_total",
                "Requests where boundary defense was applied",
            ),
            &["provider", "mode"],
        )
        .expect("metric: boundary_defense_applied_total");
        registry
            .register(Box::new(boundary_defense_applied_total.clone()))
            .expect("register boundary_defense_applied_total");

        let boundary_defense_messages_wrapped = HistogramVec::new(
            HistogramOpts::new(
                "llmtrace_boundary_defense_messages_wrapped",
                "Number of messages wrapped per request",
            )
            .buckets(vec![0.0, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0]),
            &["provider"],
        )
        .expect("metric: boundary_defense_messages_wrapped");
        registry
            .register(Box::new(boundary_defense_messages_wrapped.clone()))
            .expect("register boundary_defense_messages_wrapped");

        let boundary_defense_reminder_injected_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_boundary_defense_reminder_injected_total",
                "Requests where system prompt reminder was injected",
            ),
            &["provider"],
        )
        .expect("metric: boundary_defense_reminder_injected_total");
        registry
            .register(Box::new(boundary_defense_reminder_injected_total.clone()))
            .expect("register boundary_defense_reminder_injected_total");

        let boundary_defense_overhead_bytes = HistogramVec::new(
            HistogramOpts::new(
                "llmtrace_boundary_defense_overhead_bytes",
                "Byte delta per request from boundary defense",
            )
            .buckets(vec![0.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 5000.0]),
            &["provider"],
        )
        .expect("metric: boundary_defense_overhead_bytes");
        registry
            .register(Box::new(boundary_defense_overhead_bytes.clone()))
            .expect("register boundary_defense_overhead_bytes");

        let boundary_defense_errors_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_boundary_defense_errors_total",
                "Errors in boundary defense pipeline",
            ),
            &["error_type"],
        )
        .expect("metric: boundary_defense_errors_total");
        registry
            .register(Box::new(boundary_defense_errors_total.clone()))
            .expect("register boundary_defense_errors_total");

        let boundary_defense_skipped_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_boundary_defense_skipped_total",
                "Requests skipped by boundary defense",
            ),
            &["reason"],
        )
        .expect("metric: boundary_defense_skipped_total");
        registry
            .register(Box::new(boundary_defense_skipped_total.clone()))
            .expect("register boundary_defense_skipped_total");

        let boundary_defense_shadow_mode = IntGauge::new(
            "llmtrace_boundary_defense_shadow_mode",
            "Whether boundary defense shadow mode is active (1) or not (0)",
        )
        .expect("metric: boundary_defense_shadow_mode");
        registry
            .register(Box::new(boundary_defense_shadow_mode.clone()))
            .expect("register boundary_defense_shadow_mode");

        // Zone-detection metrics (IS-060 PR-1)
        let zone_detection_zones_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_zone_detection_zones_total",
                "Zones emitted by the IS-060 zone detector",
            ),
            &["kind", "origin", "framing"],
        )
        .expect("metric: zone_detection_zones_total");
        registry
            .register(Box::new(zone_detection_zones_total.clone()))
            .expect("register zone_detection_zones_total");

        let zone_detection_findings_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_zone_detection_findings_total",
                "Findings produced by zone-aware analysis, by finding_type and zone_kind",
            ),
            &["finding_type", "zone_kind"],
        )
        .expect("metric: zone_detection_findings_total");
        registry
            .register(Box::new(zone_detection_findings_total.clone()))
            .expect("register zone_detection_findings_total");

        let zone_detection_failures_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_zone_detection_failures_total",
                "Zone-detection failures (header parse errors, byte-range mismatches)",
            ),
            &["reason"],
        )
        .expect("metric: zone_detection_failures_total");
        registry
            .register(Box::new(zone_detection_failures_total.clone()))
            .expect("register zone_detection_failures_total");

        // ML long-input defense metrics
        let ml_chunks_total = HistogramVec::new(
            HistogramOpts::new(
                "llmtrace_ml_chunks_total",
                "ML sliding window chunks processed per classify call",
            )
            .buckets(vec![1.0, 2.0, 3.0, 5.0, 10.0]),
            &["model"],
        )
        .expect("metric: ml_chunks_total");
        registry
            .register(Box::new(ml_chunks_total.clone()))
            .expect("register ml_chunks_total");

        let ml_input_truncated_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_ml_input_truncated_total",
                "ML inputs that hit the sliding window chunk cap",
            ),
            &["model"],
        )
        .expect("metric: ml_input_truncated_total");
        registry
            .register(Box::new(ml_input_truncated_total.clone()))
            .expect("register ml_input_truncated_total");

        let response_truncated_total = IntCounter::new(
            "llmtrace_response_truncated_total",
            "Response collections truncated due to max_response_size_bytes",
        )
        .expect("metric: response_truncated_total");
        registry
            .register(Box::new(response_truncated_total.clone()))
            .expect("register response_truncated_total");

        let analysis_text_truncated_total = IntCounter::new(
            "llmtrace_analysis_text_truncated_total",
            "Analysis text truncations due to max_analysis_text_bytes",
        )
        .expect("metric: analysis_text_truncated_total");
        registry
            .register(Box::new(analysis_text_truncated_total.clone()))
            .expect("register analysis_text_truncated_total");

        // ActionRouter metrics
        let action_executions_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_action_executions_total",
                "Total enforcement actions executed by the router",
            ),
            &["action_type", "status", "mode"],
        )
        .expect("metric: action_executions_total");
        registry
            .register(Box::new(action_executions_total.clone()))
            .expect("register action_executions_total");

        let action_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "llmtrace_action_latency_seconds",
                "Per-action execution latency in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["action_type"],
        )
        .expect("metric: action_latency_seconds");
        registry
            .register(Box::new(action_latency_seconds.clone()))
            .expect("register action_latency_seconds");

        let ip_blocks_active = IntGauge::new(
            "llmtrace_ip_blocks_active",
            "Currently blocked IPs recorded by this proxy instance",
        )
        .expect("metric: ip_blocks_active");
        registry
            .register(Box::new(ip_blocks_active.clone()))
            .expect("register ip_blocks_active");

        let action_rule_matches_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_action_rule_matches_total",
                "Rule match frequency by finding type and action type",
            ),
            &["finding_type", "action_type"],
        )
        .expect("metric: action_rule_matches_total");
        registry
            .register(Box::new(action_rule_matches_total.clone()))
            .expect("register action_rule_matches_total");

        let feature_flag_updates_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_feature_flag_updates_total",
                "Total runtime feature-flag updates, labelled by feature name",
            ),
            &["feature"],
        )
        .expect("metric: feature_flag_updates_total");
        registry
            .register(Box::new(feature_flag_updates_total.clone()))
            .expect("register feature_flag_updates_total");

        let feature_flag_bool_state = IntGaugeVec::new(
            Opts::new(
                "llmtrace_feature_flag_bool_state",
                "Current runtime value of each bool-typed feature flag (0 or 1)",
            ),
            &["feature"],
        )
        .expect("metric: feature_flag_bool_state");
        registry
            .register(Box::new(feature_flag_bool_state.clone()))
            .expect("register feature_flag_bool_state");

        let feature_flag_string_state = IntGaugeVec::new(
            Opts::new(
                "llmtrace_feature_flag_string_state",
                "Info metric for string-typed feature flags; the active (feature,value) pair is 1",
            ),
            &["feature", "value"],
        )
        .expect("metric: feature_flag_string_state");
        registry
            .register(Box::new(feature_flag_string_state.clone()))
            .expect("register feature_flag_string_state");

        let config_persist_errors_total = IntCounter::new(
            "llmtrace_config_persist_errors_total",
            "Total failures writing the runtime feature-flag sidecar overlay",
        )
        .expect("metric: config_persist_errors_total");
        registry
            .register(Box::new(config_persist_errors_total.clone()))
            .expect("register config_persist_errors_total");

        let audit_event_dropped_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_audit_event_dropped_total",
                "Total forensic AuditEvent writes that failed to persist, by event type",
            ),
            &["event_type"],
        )
        .expect("metric: audit_event_dropped_total");
        registry
            .register(Box::new(audit_event_dropped_total.clone()))
            .expect("register audit_event_dropped_total");

        // LLM-as-a-Judge metrics (issue #43)
        let judge_requests_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_judge_requests_total",
                "Total judge invocations by backend, model, mode, and status",
            ),
            &["backend", "model", "mode", "status"],
        )
        .expect("metric: judge_requests_total");
        registry
            .register(Box::new(judge_requests_total.clone()))
            .expect("register judge_requests_total");

        let judge_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "llmtrace_judge_latency_seconds",
                "Judge call latency in seconds",
            )
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0]),
            &["backend", "model", "mode"],
        )
        .expect("metric: judge_latency_seconds");
        registry
            .register(Box::new(judge_latency_seconds.clone()))
            .expect("register judge_latency_seconds");

        let judge_tokens_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_judge_tokens_total",
                "Judge token consumption by direction, backend, and model",
            ),
            &["direction", "backend", "model"],
        )
        .expect("metric: judge_tokens_total");
        registry
            .register(Box::new(judge_tokens_total.clone()))
            .expect("register judge_tokens_total");

        let judge_verdicts_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_judge_verdicts_total",
                "Verdicts emitted by the judge by category, recommended action, threat flag, and model",
            ),
            &["category", "recommended_action", "is_threat", "model"],
        )
        .expect("metric: judge_verdicts_total");
        registry
            .register(Box::new(judge_verdicts_total.clone()))
            .expect("register judge_verdicts_total");

        let judge_queue_depth = IntGauge::new(
            "llmtrace_judge_queue_depth",
            "Current judge worker queue depth",
        )
        .expect("metric: judge_queue_depth");
        registry
            .register(Box::new(judge_queue_depth.clone()))
            .expect("register judge_queue_depth");

        let judge_verdict_agreement = IntCounterVec::new(
            Opts::new(
                "llmtrace_judge_verdict_agreement",
                "Agreement between the judge verdict and the prior ensemble outcome",
            ),
            &["agreement"],
        )
        .expect("metric: judge_verdict_agreement");
        registry
            .register(Box::new(judge_verdict_agreement.clone()))
            .expect("register judge_verdict_agreement");

        let judge_dropped_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_judge_dropped_total",
                "Judge requests dropped without a backend call, by reason",
            ),
            &["reason"],
        )
        .expect("metric: judge_dropped_total");
        registry
            .register(Box::new(judge_dropped_total.clone()))
            .expect("register judge_dropped_total");

        // Pre-initialise zero samples for `judge_dropped_total` reason
        // labels so dashboards do not stay blank until the first drop
        // (matches the pattern established by audit_event_dropped_total
        // in commit 6364faa).
        for reason in &[
            "disabled",
            "below_threshold",
            "channel_full",
            "channel_closed",
            "persist_failure",
            "semaphore_closed",
            "shutdown",
            "analysis_text_truncated",
        ] {
            judge_dropped_total.with_label_values(&[reason]).inc_by(0);
        }

        let judge_promotion_rejected_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_judge_promotion_rejected_total",
                "Judge verdicts that did not pass the inline promotion gate, by reason",
            ),
            &["reason"],
        )
        .expect("metric: judge_promotion_rejected_total");
        registry
            .register(Box::new(judge_promotion_rejected_total.clone()))
            .expect("register judge_promotion_rejected_total");

        // Pre-initialise reason labels — same rationale as above.
        for reason in &[
            "not_threat_or_block",
            "below_confidence",
            "below_score",
            "no_ensemble_support",
        ] {
            judge_promotion_rejected_total
                .with_label_values(&[reason])
                .inc_by(0);
        }

        let judge_shadow_would_block_total = IntCounterVec::new(
            Opts::new(
                "llmtrace_judge_shadow_would_block_total",
                "Judge verdicts suppressed by shadow mode that would otherwise have been promoted to Block",
            ),
            &["category", "recommended_action"],
        )
        .expect("metric: judge_shadow_would_block_total");
        registry
            .register(Box::new(judge_shadow_would_block_total.clone()))
            .expect("register judge_shadow_would_block_total");

        let judge_golden_set_alignment = GaugeVec::new(
            Opts::new(
                "llmtrace_judge_golden_set_alignment",
                "Per-category alignment between the security analyzer and the golden-set ground truth (0.0–1.0)",
            ),
            &["category"],
        )
        .expect("metric: judge_golden_set_alignment");
        registry
            .register(Box::new(judge_golden_set_alignment.clone()))
            .expect("register judge_golden_set_alignment");

        let judge_golden_set_false_positive_rate = GaugeVec::new(
            Opts::new(
                "llmtrace_judge_golden_set_false_positive_rate",
                "Per-category false-positive rate against benign golden-set entries (0.0–1.0)",
            ),
            &["category"],
        )
        .expect("metric: judge_golden_set_false_positive_rate");
        registry
            .register(Box::new(judge_golden_set_false_positive_rate.clone()))
            .expect("register judge_golden_set_false_positive_rate");

        // Initialise circuit breaker gauges to their startup state (closed).
        for subsystem in &["storage", "security"] {
            for state in &["closed", "open", "half_open"] {
                let val = if *state == "closed" { 1.0 } else { 0.0 };
                circuit_breaker_state
                    .with_label_values(&[subsystem, state])
                    .set(val);
            }
        }

        Self {
            registry,
            requests_total,
            request_duration_seconds,
            tokens_total,
            security_findings_total,
            circuit_breaker_state,
            storage_operations_total,
            cost_usd_total,
            anomalies_total,
            security_detector_latency_seconds,
            active_connections,
            boundary_defense_applied_total,
            boundary_defense_messages_wrapped,
            boundary_defense_reminder_injected_total,
            boundary_defense_overhead_bytes,
            boundary_defense_errors_total,
            boundary_defense_skipped_total,
            boundary_defense_shadow_mode,
            zone_detection_zones_total,
            zone_detection_findings_total,
            zone_detection_failures_total,
            ml_chunks_total,
            ml_input_truncated_total,
            response_truncated_total,
            analysis_text_truncated_total,
            action_executions_total,
            action_latency_seconds,
            ip_blocks_active,
            action_rule_matches_total,
            feature_flag_updates_total,
            feature_flag_bool_state,
            feature_flag_string_state,
            config_persist_errors_total,
            audit_event_dropped_total,
            judge_requests_total,
            judge_latency_seconds,
            judge_tokens_total,
            judge_verdicts_total,
            judge_queue_depth,
            judge_verdict_agreement,
            judge_dropped_total,
            judge_promotion_rejected_total,
            judge_shadow_would_block_total,
            judge_golden_set_alignment,
            judge_golden_set_false_positive_rate,
        }
    }

    /// Record a per-category alignment fraction from the golden-set
    /// replay endpoint (#66 T3c).
    pub fn record_golden_set_alignment(
        &self,
        category: &str,
        alignment_rate: f64,
        false_positive_rate: f64,
    ) {
        self.judge_golden_set_alignment
            .with_label_values(&[category])
            .set(alignment_rate);
        self.judge_golden_set_false_positive_rate
            .with_label_values(&[category])
            .set(false_positive_rate);
    }

    /// Render all registered metrics in Prometheus text exposition format.
    pub fn gather_text(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    // -- convenience helpers ------------------------------------------------

    /// Record the completion of a proxied request.
    pub fn record_request(
        &self,
        provider: &str,
        model: &str,
        status_code: u16,
        duration_secs: f64,
    ) {
        let status = status_code.to_string();
        self.requests_total
            .with_label_values(&[provider, model, &status])
            .inc();
        self.request_duration_seconds
            .with_label_values(&[provider, model])
            .observe(duration_secs);
    }

    /// Record observed token counts.
    pub fn record_tokens(
        &self,
        provider: &str,
        model: &str,
        prompt_tokens: Option<u32>,
        completion_tokens: Option<u32>,
    ) {
        if let Some(pt) = prompt_tokens {
            self.tokens_total
                .with_label_values(&["prompt", provider, model])
                .inc_by(u64::from(pt));
        }
        if let Some(ct) = completion_tokens {
            self.tokens_total
                .with_label_values(&["completion", provider, model])
                .inc_by(u64::from(ct));
        }
    }

    /// Record security findings.
    pub fn record_security_findings(&self, findings: &[llmtrace_core::SecurityFinding]) {
        for f in findings {
            let severity = format!("{}", f.severity);
            self.security_findings_total
                .with_label_values(&[&severity, &f.finding_type])
                .inc();
        }
    }

    /// Update the circuit breaker state gauge for a subsystem.
    pub fn set_circuit_breaker_state(&self, subsystem: &str, state: &str) {
        for s in &["closed", "open", "half_open"] {
            let val = if *s == state { 1.0 } else { 0.0 };
            self.circuit_breaker_state
                .with_label_values(&[subsystem, s])
                .set(val);
        }
    }

    /// Record a storage operation outcome.
    pub fn record_storage_operation(&self, operation: &str, success: bool) {
        let status = if success { "success" } else { "error" };
        self.storage_operations_total
            .with_label_values(&[operation, status])
            .inc();
    }

    /// Record estimated cost in USD for a request.
    ///
    /// Internally stores micro-USD (×1 000 000) as an integer counter to
    /// avoid floating-point imprecision in Prometheus counters.
    pub fn record_cost(&self, tenant: &str, model: &str, cost_usd: f64) {
        let micro_usd = (cost_usd * 1_000_000.0) as u64;
        if micro_usd > 0 {
            self.cost_usd_total
                .with_label_values(&[tenant, model])
                .inc_by(micro_usd);
        }
    }

    /// Record per-detector security analysis latency.
    pub fn record_detector_latency(&self, detector: &str, duration_ms: u64) {
        let secs = duration_ms as f64 / 1000.0;
        self.security_detector_latency_seconds
            .with_label_values(&[detector])
            .observe(secs);
    }

    /// Record boundary defense outcome.
    pub fn record_boundary_defense(
        &self,
        provider: &str,
        messages_wrapped: u32,
        reminder_injected: bool,
        overhead_bytes: i64,
        shadow_mode: bool,
    ) {
        let mode = if shadow_mode { "shadow" } else { "active" };
        self.boundary_defense_applied_total
            .with_label_values(&[provider, mode])
            .inc();
        self.boundary_defense_messages_wrapped
            .with_label_values(&[provider])
            .observe(f64::from(messages_wrapped));
        if reminder_injected {
            self.boundary_defense_reminder_injected_total
                .with_label_values(&[provider])
                .inc();
        }
        self.boundary_defense_overhead_bytes
            .with_label_values(&[provider])
            .observe(overhead_bytes as f64);
    }

    /// Record zone-detection outcome (IS-060 PR-1).
    ///
    /// `zones` is a slice of `(kind, origin, framing)` triples — one
    /// per emitted zone. `failure_reasons` is a slice of stable
    /// reason labels (`header_parse_failed`, `header_range_out_of_bounds`,
    /// etc.); one entry per failure occurrence. The findings counter
    /// is bumped separately by [`Metrics::record_zone_findings`] after
    /// the ensemble returns.
    pub fn record_zone_detection(&self, zones: &[(&str, &str, &str)], failure_reasons: &[&str]) {
        for (kind, origin, framing) in zones {
            self.zone_detection_zones_total
                .with_label_values(&[kind, origin, framing])
                .inc();
        }
        for reason in failure_reasons {
            self.zone_detection_failures_total
                .with_label_values(&[reason])
                .inc();
        }
    }

    /// Record findings produced by zone-aware analysis. Reads
    /// `zone_kind` from each finding's metadata; findings without
    /// the metadata are skipped (they were not zone-aware).
    pub fn record_zone_findings(&self, findings: &[llmtrace_core::SecurityFinding]) {
        for f in findings {
            if let Some(zone_kind) = f.metadata.get("zone_kind") {
                self.zone_detection_findings_total
                    .with_label_values(&[&f.finding_type, zone_kind])
                    .inc();
            }
        }
    }

    /// Record anomalies detected.
    pub fn record_anomalies(&self, findings: &[llmtrace_core::SecurityFinding]) {
        for f in findings {
            if let Some(anomaly_type) = f.metadata.get("anomaly_type") {
                self.anomalies_total
                    .with_label_values(&[anomaly_type])
                    .inc();
            }
        }
    }

    /// Record enforcement action execution
    pub fn record_action_execution(&self, action_type: &str, status: &str, mode: &str) {
        self.action_executions_total
            .with_label_values(&[action_type, status, mode])
            .inc();
    }

    /// Record enforcement action latency.
    pub fn record_action_latency(&self, action_type: &str, duration: std::time::Duration) {
        self.action_latency_seconds
            .with_label_values(&[action_type])
            .observe(duration.as_secs_f64());
    }

    /// Record a matched router rule.
    pub fn record_action_rule_match(&self, finding_type: &str, action_type: &str) {
        self.action_rule_matches_total
            .with_label_values(&[finding_type, action_type])
            .inc();
    }

    // -- Judge metrics (issue #43) -----------------------------------------

    /// Record a judge invocation outcome.
    pub fn record_judge_request(&self, backend: &str, model: &str, mode: &str, status: &str) {
        self.judge_requests_total
            .with_label_values(&[backend, model, mode, status])
            .inc();
    }

    /// Record judge call latency.
    pub fn record_judge_latency(
        &self,
        backend: &str,
        model: &str,
        mode: &str,
        duration: std::time::Duration,
    ) {
        self.judge_latency_seconds
            .with_label_values(&[backend, model, mode])
            .observe(duration.as_secs_f64());
    }

    /// Record judge token consumption reported by the backend.
    pub fn record_judge_tokens(
        &self,
        backend: &str,
        model: &str,
        prompt_tokens: Option<u32>,
        completion_tokens: Option<u32>,
    ) {
        if let Some(n) = prompt_tokens {
            self.judge_tokens_total
                .with_label_values(&["prompt", backend, model])
                .inc_by(u64::from(n));
        }
        if let Some(n) = completion_tokens {
            self.judge_tokens_total
                .with_label_values(&["completion", backend, model])
                .inc_by(u64::from(n));
        }
    }

    /// Record a persisted verdict for dashboard distribution tracking.
    pub fn record_judge_verdict(&self, verdict: &llmtrace_core::JudgeVerdict) {
        let is_threat = if verdict.is_threat { "true" } else { "false" };
        self.judge_verdicts_total
            .with_label_values(&[
                verdict.category.as_str(),
                verdict.recommended_action.as_str(),
                is_threat,
                verdict.model_used.as_str(),
            ])
            .inc();
    }

    /// Increment the drop counter with one of a fixed set of reasons.
    pub fn record_judge_dropped(&self, reason: &str) {
        self.judge_dropped_total.with_label_values(&[reason]).inc();
    }

    /// Record an agreement/disagreement between judge and ensemble.
    pub fn record_judge_agreement(&self, agreement: &str) {
        self.judge_verdict_agreement
            .with_label_values(&[agreement])
            .inc();
    }

    /// Record a verdict that failed the inline promotion gate.
    pub fn record_judge_promotion_rejected(&self, reason: &str) {
        self.judge_promotion_rejected_total
            .with_label_values(&[reason])
            .inc();
    }

    /// Record a verdict that was suppressed by shadow mode (#84).
    pub fn record_judge_shadow_would_block(&self, category: &str, recommended_action: &str) {
        self.judge_shadow_would_block_total
            .with_label_values(&[category, recommended_action])
            .inc();
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// /metrics endpoint handler
// ---------------------------------------------------------------------------

/// Axum handler that returns Prometheus-format metrics.
///
/// This endpoint does **not** require authentication, following the standard
/// convention for Prometheus scraping endpoints.
pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response<Body> {
    match state.metrics.gather_text() {
        Ok(text) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(Body::from(text))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("content-type", "text/plain")
            .body(Body::from(format!("Failed to gather metrics: {e}")))
            .unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Helper: provider label from LLMProvider
// ---------------------------------------------------------------------------

/// Convert an [`LLMProvider`] to a short lowercase label suitable for metric
/// label values.
pub fn provider_label(provider: &llmtrace_core::LLMProvider) -> &'static str {
    use llmtrace_core::LLMProvider;
    match provider {
        LLMProvider::OpenAI => "openai",
        LLMProvider::Anthropic => "anthropic",
        LLMProvider::VLLm => "vllm",
        LLMProvider::SGLang => "sglang",
        LLMProvider::TGI => "tgi",
        LLMProvider::Ollama => "ollama",
        LLMProvider::AzureOpenAI => "azure_openai",
        LLMProvider::Bedrock => "bedrock",
        LLMProvider::Custom(_) => "custom",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::{SecurityFinding, SecuritySeverity};

    #[test]
    fn test_metrics_new_succeeds() {
        let m = Metrics::new();
        // Gather should produce valid text
        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_active_connections"));
    }

    #[test]
    fn test_record_request_increments_counter() {
        let m = Metrics::new();
        m.record_request("openai", "gpt-4", 200, 1.5);
        m.record_request("openai", "gpt-4", 200, 0.8);
        m.record_request("openai", "gpt-4", 500, 0.1);

        let text = m.gather_text().unwrap();
        // Should have requests_total with status_code labels
        assert!(text.contains("llmtrace_requests_total"));
        assert!(text.contains("status_code=\"200\""));
        assert!(text.contains("status_code=\"500\""));
    }

    #[test]
    fn test_record_request_observes_histogram() {
        let m = Metrics::new();
        m.record_request("anthropic", "claude-3", 200, 2.0);

        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_request_duration_seconds"));
        assert!(text.contains("provider=\"anthropic\""));
    }

    #[test]
    fn test_record_tokens() {
        let m = Metrics::new();
        m.record_tokens("openai", "gpt-4", Some(100), Some(50));

        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_tokens_total"));
        assert!(text.contains("direction=\"prompt\""));
        assert!(text.contains("direction=\"completion\""));
    }

    #[test]
    fn test_record_tokens_none_values() {
        let m = Metrics::new();
        // Should not panic with None values
        m.record_tokens("openai", "gpt-4", None, None);
        // With no actual increments, the metric family won't appear in output.
        // The key assertion is that it doesn't panic.
        let text = m.gather_text().unwrap();
        assert!(!text.is_empty());
    }

    #[test]
    fn test_record_security_findings() {
        let m = Metrics::new();
        let findings = vec![
            SecurityFinding::new(
                SecuritySeverity::High,
                "prompt_injection".to_string(),
                "test".to_string(),
                0.9,
            ),
            SecurityFinding::new(
                SecuritySeverity::Low,
                "pii_leak".to_string(),
                "test".to_string(),
                0.5,
            ),
        ];
        m.record_security_findings(&findings);

        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_security_findings_total"));
        assert!(text.contains("severity=\"High\""));
        assert!(text.contains("finding_type=\"prompt_injection\""));
        assert!(text.contains("severity=\"Low\""));
        assert!(text.contains("finding_type=\"pii_leak\""));
    }

    #[test]
    fn test_circuit_breaker_state_gauge() {
        let m = Metrics::new();

        // Initial state should have storage/closed=1, storage/open=0
        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_circuit_breaker_state"));

        // Transition storage to open
        m.set_circuit_breaker_state("storage", "open");
        let text = m.gather_text().unwrap();
        // The open gauge should be 1 and closed should be 0
        assert!(text.contains("llmtrace_circuit_breaker_state"));
    }

    #[test]
    fn test_storage_operations() {
        let m = Metrics::new();
        m.record_storage_operation("store_trace", true);
        m.record_storage_operation("store_trace", false);

        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_storage_operations_total"));
        assert!(text.contains("operation=\"store_trace\""));
        assert!(text.contains("status=\"success\""));
        assert!(text.contains("status=\"error\""));
    }

    #[test]
    fn test_cost_recording() {
        let m = Metrics::new();
        m.record_cost("tenant-abc", "gpt-4", 0.05); // 5 cents

        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_cost_usd_total"));
        assert!(text.contains("tenant=\"tenant-abc\""));
        assert!(text.contains("model=\"gpt-4\""));
    }

    #[test]
    fn test_cost_zero_not_recorded() {
        let m = Metrics::new();
        m.record_cost("t", "m", 0.0);
        // Zero micro-USD should not bump the counter, so the metric family
        // won't appear in the output (no label combinations have been touched).
        let text = m.gather_text().unwrap();
        // Just ensure no panic and that the text doesn't contain a sample for "t"/"m"
        assert!(!text.contains("tenant=\"t\""));
    }

    #[test]
    fn test_anomaly_recording() {
        let m = Metrics::new();
        let mut f = SecurityFinding::new(
            SecuritySeverity::High,
            "anomaly_cost_spike".to_string(),
            "test".to_string(),
            0.9,
        );
        f.metadata
            .insert("anomaly_type".to_string(), "cost_spike".to_string());
        m.record_anomalies(&[f]);

        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_anomalies_total"));
        assert!(text.contains("anomaly_type=\"cost_spike\""));
    }

    #[test]
    fn test_active_connections_gauge() {
        let m = Metrics::new();
        m.active_connections.inc();
        m.active_connections.inc();
        assert_eq!(m.active_connections.get(), 2);
        m.active_connections.dec();
        assert_eq!(m.active_connections.get(), 1);
    }

    #[test]
    fn test_provider_label() {
        use llmtrace_core::LLMProvider;
        assert_eq!(provider_label(&LLMProvider::OpenAI), "openai");
        assert_eq!(provider_label(&LLMProvider::Anthropic), "anthropic");
        assert_eq!(provider_label(&LLMProvider::VLLm), "vllm");
        assert_eq!(provider_label(&LLMProvider::Ollama), "ollama");
        assert_eq!(provider_label(&LLMProvider::Custom("foo".into())), "custom");
    }

    #[test]
    fn test_gather_text_valid_prometheus_format() {
        let m = Metrics::new();
        m.record_request("openai", "gpt-4", 200, 1.0);
        m.record_tokens("openai", "gpt-4", Some(100), Some(50));
        m.record_storage_operation("store_trace", true);

        let text = m.gather_text().unwrap();

        // Prometheus text format: each metric has a HELP and TYPE line
        assert!(text.contains("# HELP llmtrace_requests_total"));
        assert!(text.contains("# TYPE llmtrace_requests_total counter"));
        assert!(text.contains("# HELP llmtrace_request_duration_seconds"));
        assert!(text.contains("# TYPE llmtrace_request_duration_seconds histogram"));
        assert!(text.contains("# HELP llmtrace_tokens_total"));
        assert!(text.contains("# TYPE llmtrace_tokens_total counter"));
        assert!(text.contains("# HELP llmtrace_active_connections"));
        assert!(text.contains("# TYPE llmtrace_active_connections gauge"));
    }

    #[test]
    fn test_default_circuit_breaker_state() {
        let m = Metrics::new();
        // After construction, storage and security should both be in closed state
        let closed_storage = m
            .circuit_breaker_state
            .with_label_values(&["storage", "closed"])
            .get();
        let open_storage = m
            .circuit_breaker_state
            .with_label_values(&["storage", "open"])
            .get();
        assert_eq!(closed_storage, 1.0);
        assert_eq!(open_storage, 0.0);

        let closed_security = m
            .circuit_breaker_state
            .with_label_values(&["security", "closed"])
            .get();
        assert_eq!(closed_security, 1.0);
    }

    #[test]
    fn test_action_metrics_are_recorded() {
        let m = Metrics::new();
        m.record_action_execution("webhook", "success", "async");
        m.record_action_latency("webhook", std::time::Duration::from_millis(25));
        m.record_action_rule_match("prompt_injection", "webhook");
        m.ip_blocks_active.inc();

        let text = m.gather_text().unwrap();
        assert!(text.contains("llmtrace_action_executions_total"));
        assert!(text.contains("action_type=\"webhook\""));
        assert!(text.contains("status=\"success\""));
        assert!(text.contains("mode=\"async\""));
        assert!(text.contains("llmtrace_action_latency_seconds"));
        assert!(text.contains("llmtrace_ip_blocks_active"));
        assert!(text.contains("llmtrace_action_rule_matches_total"));
        assert!(text.contains("finding_type=\"prompt_injection\""));
    }
}
