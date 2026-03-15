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
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
    Registry, TextEncoder,
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

    /// ML sliding window chunks processed per classify call.
    pub ml_chunks_total: HistogramVec,

    /// ML inputs that hit the MAX_CHUNKS cap.
    pub ml_input_truncated_total: IntCounterVec,

    /// Response collections truncated due to max_response_size_bytes.
    pub response_truncated_total: IntCounter,

    /// Analysis text truncations due to max_analysis_text_bytes.
    pub analysis_text_truncated_total: IntCounter,
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
            ml_chunks_total,
            ml_input_truncated_total,
            response_truncated_total,
            analysis_text_truncated_total,
        }
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

    /// Record detected anomalies.
    pub fn record_anomalies(&self, findings: &[llmtrace_core::SecurityFinding]) {
        for f in findings {
            if let Some(anomaly_type) = f.metadata.get("anomaly_type") {
                self.anomalies_total
                    .with_label_values(&[anomaly_type])
                    .inc();
            }
        }
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
}
