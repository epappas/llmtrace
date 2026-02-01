//! Statistical anomaly detection engine.
//!
//! Tracks per-tenant sliding windows of request metrics (cost, tokens,
//! velocity, latency) and flags values that exceed a configurable sigma
//! threshold above the running mean. Detected anomalies are emitted as
//! [`SecurityFinding`]s that flow through the existing alert pipeline.
//!
//! State is persisted via the [`CacheLayer`] so it survives proxy restarts.

use chrono::Utc;
use llmtrace_core::{
    AnomalyDetectionConfig, AnomalyType, CacheLayer, SecurityFinding, SecuritySeverity, TenantId,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Sliding window data structure (serialized to cache)
// ---------------------------------------------------------------------------

/// A fixed-capacity circular buffer of `f64` observations.
///
/// Stored in the cache layer as JSON per tenant per metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlidingWindow {
    /// Ordered samples (oldest first when full).
    values: Vec<f64>,
    /// Maximum capacity.
    capacity: usize,
}

impl SlidingWindow {
    /// Create a new empty window with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Push a new value, evicting the oldest if at capacity.
    pub fn push(&mut self, value: f64) {
        if self.values.len() >= self.capacity {
            self.values.remove(0);
        }
        self.values.push(value);
    }

    /// Number of samples currently stored.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Compute the arithmetic mean.
    pub fn mean(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.values.iter().sum();
        sum / self.values.len() as f64
    }

    /// Compute the population standard deviation.
    pub fn std_dev(&self) -> f64 {
        if self.values.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance: f64 = self
            .values
            .iter()
            .map(|v| {
                let diff = v - mean;
                diff * diff
            })
            .sum::<f64>()
            / self.values.len() as f64;
        variance.sqrt()
    }

    /// Compute how many standard deviations `value` is above the mean.
    ///
    /// Returns `None` if there are fewer than 2 samples or the std dev is zero.
    pub fn sigma_distance(&self, value: f64) -> Option<f64> {
        if self.values.len() < 2 {
            return None;
        }
        let sd = self.std_dev();
        if sd < f64::EPSILON {
            return None;
        }
        Some((value - self.mean()) / sd)
    }
}

// ---------------------------------------------------------------------------
// AnomalyDetector
// ---------------------------------------------------------------------------

/// Cache key TTL for anomaly window data (24 hours).
const WINDOW_CACHE_TTL_SECS: u64 = 86_400;

/// Minimum number of samples before anomaly detection activates.
const MIN_SAMPLES: usize = 10;

/// Statistical anomaly detector backed by the cache layer.
///
/// After each proxied request, the caller feeds data points (cost, tokens,
/// latency) into the detector. If a value exceeds `mean + σ_threshold * σ`,
/// the detector returns [`SecurityFinding`]s that can be routed through the
/// alert engine.
pub struct AnomalyDetector {
    config: AnomalyDetectionConfig,
    cache: Arc<dyn CacheLayer>,
}

impl AnomalyDetector {
    /// Create a new detector.
    ///
    /// Returns `None` if anomaly detection is disabled.
    pub fn new(config: &AnomalyDetectionConfig, cache: Arc<dyn CacheLayer>) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            config: config.clone(),
            cache,
        })
    }

    /// Record a request and check for anomalies.
    ///
    /// Returns any [`SecurityFinding`]s generated.  This method is designed
    /// to run asynchronously after the response has been sent to the client.
    pub async fn record_and_check(
        &self,
        tenant_id: TenantId,
        cost_usd: Option<f64>,
        total_tokens: Option<u32>,
        latency_ms: Option<u64>,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // --- Cost anomaly ---
        if self.config.check_cost {
            if let Some(cost) = cost_usd {
                if let Some(f) = self
                    .check_metric(tenant_id, AnomalyType::CostSpike, cost)
                    .await
                {
                    findings.push(f);
                }
            }
        }

        // --- Token anomaly ---
        if self.config.check_tokens {
            if let Some(tokens) = total_tokens {
                if let Some(f) = self
                    .check_metric(tenant_id, AnomalyType::TokenSpike, tokens as f64)
                    .await
                {
                    findings.push(f);
                }
            }
        }

        // --- Latency anomaly ---
        if self.config.check_latency {
            if let Some(ms) = latency_ms {
                if let Some(f) = self
                    .check_metric(tenant_id, AnomalyType::LatencySpike, ms as f64)
                    .await
                {
                    findings.push(f);
                }
            }
        }

        // --- Velocity anomaly ---
        if self.config.check_velocity {
            if let Some(f) = self.check_velocity(tenant_id).await {
                findings.push(f);
            }
        }

        findings
    }

    // -- internal helpers --------------------------------------------------

    /// Check a single metric value against its sliding window.
    async fn check_metric(
        &self,
        tenant_id: TenantId,
        anomaly_type: AnomalyType,
        value: f64,
    ) -> Option<SecurityFinding> {
        let key = cache_key(tenant_id, &anomaly_type);
        let mut window = self.load_window(&key).await;

        // Check *before* pushing the new value so the new value is tested
        // against the historical distribution.
        let finding = if window.len() >= MIN_SAMPLES {
            if let Some(sigma) = window.sigma_distance(value) {
                if sigma >= self.config.sigma_threshold {
                    let severity = severity_from_sigma(sigma, self.config.sigma_threshold);
                    let mean = window.mean();
                    let sd = window.std_dev();
                    Some(build_finding(
                        &anomaly_type,
                        severity,
                        value,
                        mean,
                        sd,
                        sigma,
                        tenant_id,
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Always push the new value into the window
        window.push(value);
        self.save_window(&key, &window).await;

        finding
    }

    /// Track request velocity using a timestamp-based sliding window.
    ///
    /// Instead of storing raw RPM values, we store timestamps of recent
    /// requests. The current minute's request count becomes the velocity
    /// observation fed into the standard sigma check.
    async fn check_velocity(&self, tenant_id: TenantId) -> Option<SecurityFinding> {
        let ts_key = format!("anomaly:{tenant_id}:velocity_ts");
        let window_key = cache_key(tenant_id, &AnomalyType::VelocitySpike);

        // Load recent request timestamps
        let mut timestamps: Vec<i64> = self.load_timestamps(&ts_key).await;
        let now = Utc::now().timestamp();

        // Purge timestamps older than 60 seconds
        timestamps.retain(|t| now - t < 60);
        timestamps.push(now);

        // Save updated timestamps
        self.save_timestamps(&ts_key, &timestamps).await;

        // Current velocity = number of requests in the last 60s
        let current_rpm = timestamps.len() as f64;

        // Feed into the standard sliding window check
        let mut window = self.load_window(&window_key).await;

        let finding = if window.len() >= MIN_SAMPLES {
            if let Some(sigma) = window.sigma_distance(current_rpm) {
                if sigma >= self.config.sigma_threshold {
                    let severity = severity_from_sigma(sigma, self.config.sigma_threshold);
                    let mean = window.mean();
                    let sd = window.std_dev();
                    Some(build_finding(
                        &AnomalyType::VelocitySpike,
                        severity,
                        current_rpm,
                        mean,
                        sd,
                        sigma,
                        tenant_id,
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        window.push(current_rpm);
        self.save_window(&window_key, &window).await;

        finding
    }

    /// Load a sliding window from the cache.
    async fn load_window(&self, key: &str) -> SlidingWindow {
        match self.cache.get(key).await {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| SlidingWindow::new(self.config.window_size)),
            Ok(None) => SlidingWindow::new(self.config.window_size),
            Err(e) => {
                warn!(%key, "Failed to load anomaly window: {e}");
                SlidingWindow::new(self.config.window_size)
            }
        }
    }

    /// Save a sliding window to the cache.
    async fn save_window(&self, key: &str, window: &SlidingWindow) {
        match serde_json::to_vec(window) {
            Ok(bytes) => {
                let ttl = Duration::from_secs(WINDOW_CACHE_TTL_SECS);
                if let Err(e) = self.cache.set(key, &bytes, ttl).await {
                    warn!(%key, "Failed to save anomaly window: {e}");
                }
            }
            Err(e) => {
                warn!(%key, "Failed to serialize anomaly window: {e}");
            }
        }
    }

    /// Load velocity timestamps from the cache.
    async fn load_timestamps(&self, key: &str) -> Vec<i64> {
        match self.cache.get(key).await {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Ok(None) => Vec::new(),
            Err(e) => {
                warn!(%key, "Failed to load velocity timestamps: {e}");
                Vec::new()
            }
        }
    }

    /// Save velocity timestamps to the cache.
    async fn save_timestamps(&self, key: &str, timestamps: &[i64]) {
        match serde_json::to_vec(timestamps) {
            Ok(bytes) => {
                // TTL slightly longer than the 60s window we use
                let ttl = Duration::from_secs(120);
                if let Err(e) = self.cache.set(key, &bytes, ttl).await {
                    warn!(%key, "Failed to save velocity timestamps: {e}");
                }
            }
            Err(e) => {
                warn!(%key, "Failed to serialize velocity timestamps: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the cache key for a given tenant + anomaly metric.
fn cache_key(tenant_id: TenantId, anomaly_type: &AnomalyType) -> String {
    format!("anomaly:{tenant_id}:{anomaly_type}")
}

/// Map a sigma distance to a severity level.
///
/// - `base_sigma` .. `base_sigma * 5/3` → Medium
/// - `base_sigma * 5/3` .. `base_sigma * 10/3` → High
/// - `>= base_sigma * 10/3` → Critical
fn severity_from_sigma(sigma: f64, base_sigma: f64) -> SecuritySeverity {
    // Normalise: how many "base units" is sigma?
    // 3σ = Medium, 5σ = High, 10σ = Critical (when base = 3.0)
    let high_threshold = base_sigma * 5.0 / 3.0;
    let critical_threshold = base_sigma * 10.0 / 3.0;

    if sigma >= critical_threshold {
        SecuritySeverity::Critical
    } else if sigma >= high_threshold {
        SecuritySeverity::High
    } else {
        SecuritySeverity::Medium
    }
}

/// Build a [`SecurityFinding`] for a detected anomaly.
fn build_finding(
    anomaly_type: &AnomalyType,
    severity: SecuritySeverity,
    value: f64,
    mean: f64,
    std_dev: f64,
    sigma: f64,
    tenant_id: TenantId,
) -> SecurityFinding {
    let description = format!(
        "Anomaly detected: {anomaly_type} — value {value:.4} is {sigma:.1}σ above mean {mean:.4} (σ={std_dev:.4})"
    );

    // Higher sigma → higher confidence
    let confidence = (sigma / 20.0).clamp(0.5, 1.0);

    let requires_alert = matches!(
        severity,
        SecuritySeverity::High | SecuritySeverity::Critical
    );

    debug!(
        %tenant_id,
        %anomaly_type,
        value,
        mean,
        std_dev,
        sigma,
        %severity,
        "Anomaly detected"
    );

    SecurityFinding {
        id: uuid::Uuid::new_v4(),
        severity,
        finding_type: format!("anomaly_{anomaly_type}"),
        description,
        detected_at: Utc::now(),
        confidence_score: confidence,
        location: Some(format!("tenant:{tenant_id}")),
        metadata: [
            ("anomaly_type".to_string(), anomaly_type.to_string()),
            ("value".to_string(), format!("{value:.6}")),
            ("mean".to_string(), format!("{mean:.6}")),
            ("std_dev".to_string(), format!("{std_dev:.6}")),
            ("sigma".to_string(), format!("{sigma:.2}")),
        ]
        .into_iter()
        .collect(),
        requires_alert,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::AnomalyDetectionConfig;
    use llmtrace_storage::InMemoryCacheLayer;

    fn make_cache() -> Arc<dyn CacheLayer> {
        Arc::new(InMemoryCacheLayer::new())
    }

    fn enabled_config() -> AnomalyDetectionConfig {
        AnomalyDetectionConfig {
            enabled: true,
            window_size: 100,
            sigma_threshold: 3.0,
            check_cost: true,
            check_tokens: true,
            check_velocity: true,
            check_latency: true,
        }
    }

    // -- SlidingWindow unit tests ------------------------------------------

    #[test]
    fn test_sliding_window_empty() {
        let w = SlidingWindow::new(5);
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
        assert_eq!(w.mean(), 0.0);
        assert_eq!(w.std_dev(), 0.0);
        assert!(w.sigma_distance(42.0).is_none());
    }

    #[test]
    fn test_sliding_window_single_value() {
        let mut w = SlidingWindow::new(5);
        w.push(10.0);
        assert_eq!(w.len(), 1);
        assert_eq!(w.mean(), 10.0);
        assert_eq!(w.std_dev(), 0.0);
        assert!(w.sigma_distance(20.0).is_none()); // needs ≥2 samples
    }

    #[test]
    fn test_sliding_window_mean_and_stddev() {
        let mut w = SlidingWindow::new(10);
        // Push known values: 2, 4, 4, 4, 5, 5, 7, 9
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.push(v);
        }
        assert_eq!(w.len(), 8);
        let mean = w.mean();
        assert!((mean - 5.0).abs() < 1e-10);

        let sd = w.std_dev();
        // Population std dev of [2,4,4,4,5,5,7,9] = 2.0
        assert!((sd - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_sliding_window_sigma_distance() {
        let mut w = SlidingWindow::new(10);
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.push(v);
        }
        // mean=5.0, sd=2.0
        // value=11.0 → (11-5)/2 = 3.0σ
        let sigma = w.sigma_distance(11.0).unwrap();
        assert!((sigma - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_sliding_window_capacity_eviction() {
        let mut w = SlidingWindow::new(3);
        w.push(1.0);
        w.push(2.0);
        w.push(3.0);
        assert_eq!(w.len(), 3);

        // Pushing a 4th value evicts the oldest (1.0)
        w.push(4.0);
        assert_eq!(w.len(), 3);
        let mean = w.mean();
        assert!((mean - 3.0).abs() < 1e-10); // (2+3+4)/3 = 3.0
    }

    #[test]
    fn test_sliding_window_zero_stddev() {
        let mut w = SlidingWindow::new(5);
        w.push(5.0);
        w.push(5.0);
        w.push(5.0);
        assert_eq!(w.std_dev(), 0.0);
        // sigma_distance should return None when sd is zero
        assert!(w.sigma_distance(10.0).is_none());
    }

    // -- severity mapping --------------------------------------------------

    #[test]
    fn test_severity_from_sigma_medium() {
        // base=3.0: Medium at 3.0σ
        assert_eq!(severity_from_sigma(3.0, 3.0), SecuritySeverity::Medium);
        assert_eq!(severity_from_sigma(4.0, 3.0), SecuritySeverity::Medium);
    }

    #[test]
    fn test_severity_from_sigma_high() {
        // base=3.0: High at 5.0σ (threshold = 3.0 * 5/3 = 5.0)
        assert_eq!(severity_from_sigma(5.0, 3.0), SecuritySeverity::High);
        assert_eq!(severity_from_sigma(7.0, 3.0), SecuritySeverity::High);
    }

    #[test]
    fn test_severity_from_sigma_critical() {
        // base=3.0: Critical at 10.0σ (threshold = 3.0 * 10/3 = 10.0)
        assert_eq!(severity_from_sigma(10.0, 3.0), SecuritySeverity::Critical);
        assert_eq!(severity_from_sigma(15.0, 3.0), SecuritySeverity::Critical);
    }

    // -- constructor -------------------------------------------------------

    #[test]
    fn test_disabled_config_returns_none() {
        let config = AnomalyDetectionConfig::default(); // enabled=false
        assert!(AnomalyDetector::new(&config, make_cache()).is_none());
    }

    #[test]
    fn test_enabled_config_returns_detector() {
        assert!(AnomalyDetector::new(&enabled_config(), make_cache()).is_some());
    }

    // -- anomaly detection integration tests --------------------------------

    #[tokio::test]
    async fn test_no_anomaly_with_few_samples() {
        let cache = make_cache();
        let detector = AnomalyDetector::new(&enabled_config(), cache).unwrap();
        let tid = TenantId::new();

        // Feed fewer than MIN_SAMPLES (10) data points
        for i in 0..9 {
            let findings = detector
                .record_and_check(tid, Some(i as f64), Some(100), Some(50))
                .await;
            assert!(findings.is_empty(), "Expected no findings with <10 samples");
        }
    }

    #[tokio::test]
    async fn test_no_anomaly_with_stable_data() {
        let cache = make_cache();
        let detector = AnomalyDetector::new(&enabled_config(), cache).unwrap();
        let tid = TenantId::new();

        // Feed 20 stable data points (all roughly the same)
        for _ in 0..20 {
            let findings = detector
                .record_and_check(tid, Some(0.05), Some(500), Some(100))
                .await;
            // Stable data should produce no anomalies
            assert!(
                findings.is_empty(),
                "Stable data should not trigger anomaly"
            );
        }
    }

    #[tokio::test]
    async fn test_cost_spike_detected() {
        let cache = make_cache();
        let config = AnomalyDetectionConfig {
            check_tokens: false,
            check_velocity: false,
            check_latency: false,
            ..enabled_config()
        };
        let detector = AnomalyDetector::new(&config, cache).unwrap();
        let tid = TenantId::new();

        // Establish baseline with slight variation for non-zero std dev
        let baseline = [
            0.04, 0.05, 0.06, 0.05, 0.04, 0.05, 0.06, 0.05, 0.04, 0.05, 0.06, 0.05, 0.04, 0.05,
            0.06, 0.05, 0.04, 0.05, 0.06, 0.05,
        ];
        for &v in &baseline {
            let _ = detector.record_and_check(tid, Some(v), None, None).await;
        }

        // Inject a massive cost spike: $50
        let findings = detector.record_and_check(tid, Some(50.0), None, None).await;

        assert!(!findings.is_empty(), "Should detect cost spike");
        assert_eq!(findings[0].finding_type, "anomaly_cost_spike");
        assert!(
            findings[0].severity >= SecuritySeverity::Medium,
            "Severity should be at least Medium"
        );
    }

    #[tokio::test]
    async fn test_token_spike_detected() {
        let cache = make_cache();
        let config = AnomalyDetectionConfig {
            check_cost: false,
            check_velocity: false,
            check_latency: false,
            ..enabled_config()
        };
        let detector = AnomalyDetector::new(&config, cache).unwrap();
        let tid = TenantId::new();

        // Baseline with variation for non-zero std dev
        let baseline: Vec<u32> = (0..20).map(|i| 480 + (i % 5) * 10).collect();
        for v in &baseline {
            let _ = detector.record_and_check(tid, None, Some(*v), None).await;
        }

        // Spike: 50000 tokens
        let findings = detector
            .record_and_check(tid, None, Some(50000), None)
            .await;

        assert!(!findings.is_empty(), "Should detect token spike");
        assert_eq!(findings[0].finding_type, "anomaly_token_spike");
    }

    #[tokio::test]
    async fn test_latency_spike_detected() {
        let cache = make_cache();
        let config = AnomalyDetectionConfig {
            check_cost: false,
            check_tokens: false,
            check_velocity: false,
            ..enabled_config()
        };
        let detector = AnomalyDetector::new(&config, cache).unwrap();
        let tid = TenantId::new();

        // Baseline with variation for non-zero std dev
        let baseline: Vec<u64> = (0..20).map(|i| 90 + (i % 5) * 5).collect();
        for v in &baseline {
            let _ = detector.record_and_check(tid, None, None, Some(*v)).await;
        }

        // Spike: 10000ms
        let findings = detector
            .record_and_check(tid, None, None, Some(10000))
            .await;

        assert!(!findings.is_empty(), "Should detect latency spike");
        assert_eq!(findings[0].finding_type, "anomaly_latency_spike");
    }

    #[tokio::test]
    async fn test_disabled_metrics_not_checked() {
        let cache = make_cache();
        let config = AnomalyDetectionConfig {
            check_cost: false,
            check_tokens: false,
            check_velocity: false,
            check_latency: false,
            ..enabled_config()
        };
        let detector = AnomalyDetector::new(&config, cache).unwrap();
        let tid = TenantId::new();

        // Establish baseline
        for _ in 0..20 {
            let _ = detector
                .record_and_check(tid, Some(0.05), Some(500), Some(100))
                .await;
        }

        // Massive spikes — but all checks disabled
        let findings = detector
            .record_and_check(tid, Some(500.0), Some(999999), Some(999999))
            .await;

        assert!(
            findings.is_empty(),
            "All checks disabled should produce no findings"
        );
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let cache = make_cache();
        let config = AnomalyDetectionConfig {
            check_tokens: false,
            check_velocity: false,
            check_latency: false,
            ..enabled_config()
        };
        let detector = AnomalyDetector::new(&config, cache).unwrap();
        let tid1 = TenantId::new();
        let tid2 = TenantId::new();

        // Build baseline for tenant 1 only (with variation)
        let baseline = [
            0.04, 0.05, 0.06, 0.05, 0.04, 0.05, 0.06, 0.05, 0.04, 0.05, 0.06, 0.05, 0.04, 0.05,
            0.06, 0.05, 0.04, 0.05, 0.06, 0.05,
        ];
        for &v in &baseline {
            let _ = detector.record_and_check(tid1, Some(v), None, None).await;
        }

        // $50 spike for tenant 1 — should trigger anomaly
        let findings1 = detector
            .record_and_check(tid1, Some(50.0), None, None)
            .await;
        assert!(!findings1.is_empty(), "Tenant 1 should see anomaly");

        // $50 for tenant 2 — no baseline, should NOT trigger
        let findings2 = detector
            .record_and_check(tid2, Some(50.0), None, None)
            .await;
        assert!(
            findings2.is_empty(),
            "Tenant 2 has no baseline, no anomaly expected"
        );
    }

    #[tokio::test]
    async fn test_finding_metadata() {
        let cache = make_cache();
        let config = AnomalyDetectionConfig {
            check_tokens: false,
            check_velocity: false,
            check_latency: false,
            ..enabled_config()
        };
        let detector = AnomalyDetector::new(&config, cache).unwrap();
        let tid = TenantId::new();

        // Baseline with variation for non-zero std dev
        let baseline = [
            0.9, 1.0, 1.1, 1.0, 0.9, 1.0, 1.1, 1.0, 0.9, 1.0, 1.1, 1.0, 0.9, 1.0, 1.1, 1.0, 0.9,
            1.0, 1.1, 1.0,
        ];
        for &v in &baseline {
            let _ = detector.record_and_check(tid, Some(v), None, None).await;
        }

        let findings = detector
            .record_and_check(tid, Some(100.0), None, None)
            .await;

        assert!(!findings.is_empty());
        let f = &findings[0];
        assert!(f.metadata.contains_key("sigma"));
        assert!(f.metadata.contains_key("mean"));
        assert!(f.metadata.contains_key("std_dev"));
        assert!(f.metadata.contains_key("value"));
        assert!(f.metadata.contains_key("anomaly_type"));
        assert!(f.location.is_some());
        assert!(f.description.contains("cost_spike"));
    }

    #[tokio::test]
    async fn test_severity_escalation() {
        let cache = make_cache();
        let config = AnomalyDetectionConfig {
            check_tokens: false,
            check_velocity: false,
            check_latency: false,
            ..enabled_config()
        };
        let detector = AnomalyDetector::new(&config, cache).unwrap();
        let tid = TenantId::new();

        // Build a tight baseline with tiny variation (sd ≈ 0.005)
        for i in 0..20 {
            let v = 1.0 + (i as f64 % 3.0) * 0.005;
            let _ = detector.record_and_check(tid, Some(v), None, None).await;
        }

        // Value of 100.0 with mean≈1.0, sd≈0.005 → thousands of sigma → Critical
        let findings = detector
            .record_and_check(tid, Some(100.0), None, None)
            .await;

        assert!(!findings.is_empty(), "Should detect extreme spike");
        // With very tight baseline, this should be Critical
        assert!(
            findings[0].severity >= SecuritySeverity::High,
            "Large spike should be High or Critical"
        );
    }

    #[test]
    fn test_cache_key_format() {
        let tid = TenantId::new();
        let key = cache_key(tid, &AnomalyType::CostSpike);
        assert!(key.starts_with("anomaly:"));
        assert!(key.contains("cost_spike"));
    }

    #[test]
    fn test_build_finding_fields() {
        let tid = TenantId::new();
        let f = build_finding(
            &AnomalyType::CostSpike,
            SecuritySeverity::High,
            50.0,
            5.0,
            2.0,
            22.5,
            tid,
        );
        assert_eq!(f.finding_type, "anomaly_cost_spike");
        assert_eq!(f.severity, SecuritySeverity::High);
        assert!(f.requires_alert);
        assert!(f.confidence_score >= 0.5);
        assert!(f.confidence_score <= 1.0);
    }
}
