//! Production FPR monitoring with drift detection (R-IS-01).
//!
//! This module provides rolling-window false-positive rate monitoring per
//! detection category, with drift detection and alert generation.  When the
//! observed FPR deviates from an established baseline beyond a configurable
//! threshold, the monitor produces [`FprDriftAlert`] values that can be
//! converted into [`SecurityFinding`]s for the standard alerting pipeline.
//!
//! # Usage
//!
//! ```
//! use llmtrace_security::fpr_monitor::{FprMonitor, FprMonitorConfig};
//! use std::time::Duration;
//!
//! let config = FprMonitorConfig {
//!     window_duration: Duration::from_secs(600),
//!     drift_threshold: 0.02,
//!     min_window_samples: 100,
//!     categories: vec!["injection".into(), "jailbreak".into()],
//! };
//! let mut monitor = FprMonitor::new(config);
//! monitor.record_event("injection", true, 0.92);
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use llmtrace_core::{SecurityFinding, SecuritySeverity};

// ────────────────────────────────────────────────────────────────────────────
// Configuration
// ────────────────────────────────────────────────────────────────────────────

/// Configuration for the FPR monitor.
#[derive(Debug, Clone)]
pub struct FprMonitorConfig {
    /// Maximum age of events retained in the sliding window.
    pub window_duration: Duration,
    /// Minimum absolute FPR deviation from baseline that triggers an alert.
    pub drift_threshold: f64,
    /// Minimum number of samples in the window before drift detection fires.
    pub min_window_samples: usize,
    /// Detection categories to monitor.
    pub categories: Vec<String>,
}

impl Default for FprMonitorConfig {
    fn default() -> Self {
        Self {
            window_duration: Duration::from_secs(600),
            drift_threshold: 0.02,
            min_window_samples: 100,
            categories: Vec::new(),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Event record
// ────────────────────────────────────────────────────────────────────────────

/// A single recorded detection event.
#[derive(Debug, Clone)]
struct FprEvent {
    timestamp: Instant,
    was_flagged: bool,
    confidence: f64,
}

// ────────────────────────────────────────────────────────────────────────────
// Drift alert
// ────────────────────────────────────────────────────────────────────────────

/// Alert produced when FPR drift is detected for a category.
#[derive(Debug, Clone)]
pub struct FprDriftAlert {
    /// Detection category that drifted.
    pub category: String,
    /// Expected baseline FPR for this category.
    pub baseline_fpr: f64,
    /// Observed FPR in the current window.
    pub current_fpr: f64,
    /// Absolute deviation: `|current_fpr - baseline_fpr|`.
    pub deviation: f64,
    /// Number of samples in the current window.
    pub window_size: usize,
    /// When the drift was detected.
    pub detected_at: Instant,
}

// ────────────────────────────────────────────────────────────────────────────
// Per-category summary
// ────────────────────────────────────────────────────────────────────────────

/// Summary statistics for a single monitored category.
#[derive(Debug, Clone)]
pub struct FprCategorySummary {
    /// Detection category name.
    pub category: String,
    /// Current FPR in the sliding window.
    pub current_fpr: f64,
    /// Total number of samples in the window.
    pub sample_count: usize,
    /// Number of flagged samples in the window.
    pub flagged_count: usize,
    /// Mean confidence score across all samples in the window.
    pub avg_confidence: f64,
}

/// Aggregated summary across all monitored categories.
#[derive(Debug, Clone)]
pub struct FprMonitorSummary {
    /// Per-category summaries.
    pub categories: Vec<FprCategorySummary>,
}

// ────────────────────────────────────────────────────────────────────────────
// FPR Monitor
// ────────────────────────────────────────────────────────────────────────────

/// Rolling-window FPR monitor with per-category drift detection.
#[derive(Debug)]
pub struct FprMonitor {
    config: FprMonitorConfig,
    windows: HashMap<String, VecDeque<FprEvent>>,
}

impl FprMonitor {
    /// Create a new monitor with the given configuration.
    ///
    /// Pre-initialises empty windows for each configured category.
    #[must_use]
    pub fn new(config: FprMonitorConfig) -> Self {
        let mut windows = HashMap::new();
        for cat in &config.categories {
            windows.insert(cat.clone(), VecDeque::new());
        }
        Self { config, windows }
    }

    /// Record a detection event for the given category.
    ///
    /// If the category was not in the initial config, it is created on the fly.
    pub fn record_event(&mut self, category: &str, was_flagged: bool, confidence: f64) {
        self.record_event_at(category, Instant::now(), was_flagged, confidence);
    }

    /// Record a detection event with an explicit timestamp (useful for testing).
    pub fn record_event_at(
        &mut self,
        category: &str,
        at: Instant,
        was_flagged: bool,
        confidence: f64,
    ) {
        let window = self.windows.entry(category.to_string()).or_default();
        prune_window(window, self.config.window_duration);
        window.push_back(FprEvent {
            timestamp: at,
            was_flagged,
            confidence: confidence.clamp(0.0, 1.0),
        });
    }

    /// Compute the current FPR for a category within the sliding window.
    ///
    /// Returns `None` if the category has no recorded events.
    #[must_use]
    pub fn current_fpr(&mut self, category: &str) -> Option<f64> {
        let window = self.windows.get_mut(category)?;
        prune_window(window, self.config.window_duration);
        if window.is_empty() {
            return None;
        }
        let flagged = window.iter().filter(|e| e.was_flagged).count();
        Some(flagged as f64 / window.len() as f64)
    }

    /// Check whether the current FPR for `category` has drifted from `baseline_fpr`.
    ///
    /// Returns `Some(alert)` when the absolute deviation exceeds the configured
    /// threshold and the window contains at least `min_window_samples` events.
    /// Returns `None` otherwise.
    pub fn check_drift(&mut self, category: &str, baseline_fpr: f64) -> Option<FprDriftAlert> {
        let window = self.windows.get_mut(category)?;
        prune_window(window, self.config.window_duration);

        let count = window.len();
        if count < self.config.min_window_samples {
            return None;
        }

        let flagged = window.iter().filter(|e| e.was_flagged).count();
        let current = flagged as f64 / count as f64;
        let deviation = (current - baseline_fpr).abs();

        if deviation < self.config.drift_threshold {
            return None;
        }

        Some(FprDriftAlert {
            category: category.to_string(),
            baseline_fpr,
            current_fpr: current,
            deviation,
            window_size: count,
            detected_at: Instant::now(),
        })
    }

    /// Check drift across all categories against the provided baselines.
    pub fn check_all_drift(&mut self, baselines: &HashMap<String, f64>) -> Vec<FprDriftAlert> {
        let categories: Vec<String> = baselines.keys().cloned().collect();
        let mut alerts = Vec::new();
        for cat in categories {
            if let Some(baseline) = baselines.get(&cat) {
                if let Some(alert) = self.check_drift(&cat, *baseline) {
                    alerts.push(alert);
                }
            }
        }
        alerts
    }

    /// Convert a slice of drift alerts into [`SecurityFinding`]s.
    #[must_use]
    pub fn to_security_findings(alerts: &[FprDriftAlert]) -> Vec<SecurityFinding> {
        alerts.iter().map(alert_to_finding).collect()
    }

    /// Produce a summary of all tracked categories.
    pub fn summary(&mut self) -> FprMonitorSummary {
        let categories: Vec<String> = self.windows.keys().cloned().collect();
        let mut summaries = Vec::with_capacity(categories.len());
        for cat in categories {
            if let Some(cs) = self.category_summary(&cat) {
                summaries.push(cs);
            }
        }
        summaries.sort_by(|a, b| a.category.cmp(&b.category));
        FprMonitorSummary {
            categories: summaries,
        }
    }

    /// Produce a summary for a single category.
    fn category_summary(&mut self, category: &str) -> Option<FprCategorySummary> {
        let window = self.windows.get_mut(category)?;
        prune_window(window, self.config.window_duration);

        let sample_count = window.len();
        let flagged_count = window.iter().filter(|e| e.was_flagged).count();
        let current_fpr = if sample_count == 0 {
            0.0
        } else {
            flagged_count as f64 / sample_count as f64
        };
        let avg_confidence = if sample_count == 0 {
            0.0
        } else {
            window.iter().map(|e| e.confidence).sum::<f64>() / sample_count as f64
        };

        Some(FprCategorySummary {
            category: category.to_string(),
            current_fpr,
            sample_count,
            flagged_count,
            avg_confidence,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Remove events older than `window_duration` from the front of the deque.
fn prune_window(window: &mut VecDeque<FprEvent>, window_duration: Duration) {
    let cutoff = Instant::now() - window_duration;
    while window.front().is_some_and(|e| e.timestamp < cutoff) {
        window.pop_front();
    }
}

/// Convert a single drift alert into a [`SecurityFinding`].
#[must_use]
fn alert_to_finding(alert: &FprDriftAlert) -> SecurityFinding {
    let severity = if alert.deviation >= 0.10 {
        SecuritySeverity::High
    } else if alert.deviation >= 0.05 {
        SecuritySeverity::Medium
    } else {
        SecuritySeverity::Low
    };

    let description = format!(
        "FPR drift detected for category '{}': baseline={:.4}, current={:.4}, deviation={:.4} ({} samples)",
        alert.category,
        alert.baseline_fpr,
        alert.current_fpr,
        alert.deviation,
        alert.window_size,
    );

    let requires_alert = severity >= SecuritySeverity::High;
    let mut finding = SecurityFinding::new(
        severity,
        "fpr_drift".to_string(),
        description,
        1.0 - alert.deviation.min(1.0),
    );
    finding
        .metadata
        .insert("category".to_string(), alert.category.clone());
    finding.metadata.insert(
        "baseline_fpr".to_string(),
        format!("{:.6}", alert.baseline_fpr),
    );
    finding.metadata.insert(
        "current_fpr".to_string(),
        format!("{:.6}", alert.current_fpr),
    );
    finding
        .metadata
        .insert("deviation".to_string(), format!("{:.6}", alert.deviation));
    finding
        .metadata
        .insert("window_size".to_string(), alert.window_size.to_string());
    finding.requires_alert = requires_alert;
    finding
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> FprMonitorConfig {
        FprMonitorConfig {
            window_duration: Duration::from_secs(600),
            drift_threshold: 0.02,
            min_window_samples: 10,
            categories: vec!["injection".into(), "jailbreak".into()],
        }
    }

    // -- Empty monitor returns no drift ------------------------------------

    #[test]
    fn empty_monitor_returns_no_drift() {
        let mut monitor = FprMonitor::new(default_config());
        let result = monitor.check_drift("injection", 0.05);
        assert!(result.is_none());
    }

    #[test]
    fn empty_monitor_current_fpr_is_none_for_unknown() {
        let mut monitor = FprMonitor::new(default_config());
        assert!(monitor.current_fpr("nonexistent").is_none());
    }

    #[test]
    fn empty_monitor_current_fpr_is_none_for_known_category() {
        let mut monitor = FprMonitor::new(default_config());
        assert!(monitor.current_fpr("injection").is_none());
    }

    // -- Recording events updates counts -----------------------------------

    #[test]
    fn recording_events_updates_counts() {
        let mut monitor = FprMonitor::new(default_config());
        monitor.record_event("injection", true, 0.9);
        monitor.record_event("injection", false, 0.2);
        monitor.record_event("injection", true, 0.85);

        let summary = monitor.summary();
        let inj = summary
            .categories
            .iter()
            .find(|c| c.category == "injection")
            .unwrap();
        assert_eq!(inj.sample_count, 3);
        assert_eq!(inj.flagged_count, 2);
    }

    #[test]
    fn current_fpr_reflects_recorded_events() {
        let mut monitor = FprMonitor::new(default_config());
        for _ in 0..3 {
            monitor.record_event("injection", true, 0.9);
        }
        for _ in 0..7 {
            monitor.record_event("injection", false, 0.1);
        }
        let fpr = monitor.current_fpr("injection").unwrap();
        assert!((fpr - 0.3).abs() < f64::EPSILON);
    }

    // -- Per-category tracking ---------------------------------------------

    #[test]
    fn per_category_tracking() {
        let mut monitor = FprMonitor::new(default_config());
        monitor.record_event("injection", true, 0.9);
        monitor.record_event("injection", false, 0.1);
        monitor.record_event("jailbreak", true, 0.8);

        let inj_fpr = monitor.current_fpr("injection").unwrap();
        let jb_fpr = monitor.current_fpr("jailbreak").unwrap();

        assert!((inj_fpr - 0.5).abs() < f64::EPSILON);
        assert!((jb_fpr - 1.0).abs() < f64::EPSILON);
    }

    // -- Drift detection fires when exceeding threshold --------------------

    #[test]
    fn drift_fires_when_exceeding_threshold() {
        let config = FprMonitorConfig {
            min_window_samples: 10,
            drift_threshold: 0.02,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        // Baseline: 5% FPR. Observed: 30% (3 flagged out of 10).
        for _ in 0..3 {
            monitor.record_event("injection", true, 0.9);
        }
        for _ in 0..7 {
            monitor.record_event("injection", false, 0.1);
        }

        let alert = monitor.check_drift("injection", 0.05);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.category, "injection");
        assert!((alert.baseline_fpr - 0.05).abs() < f64::EPSILON);
        assert!((alert.current_fpr - 0.3).abs() < f64::EPSILON);
        assert!((alert.deviation - 0.25).abs() < f64::EPSILON);
        assert_eq!(alert.window_size, 10);
    }

    // -- Drift detection does NOT fire below threshold ---------------------

    #[test]
    fn no_drift_below_threshold() {
        let config = FprMonitorConfig {
            min_window_samples: 10,
            drift_threshold: 0.05,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        // Baseline: 10% FPR. Observed: 10% (1 flagged out of 10). Deviation = 0.
        monitor.record_event("injection", true, 0.9);
        for _ in 0..9 {
            monitor.record_event("injection", false, 0.1);
        }

        let alert = monitor.check_drift("injection", 0.10);
        assert!(alert.is_none());
    }

    #[test]
    fn drift_fires_when_exactly_at_threshold() {
        let config = FprMonitorConfig {
            min_window_samples: 10,
            drift_threshold: 0.10,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        // Observed: 20% FPR (2/10). Baseline: 10%. Deviation: 10% = threshold exactly.
        for _ in 0..2 {
            monitor.record_event("injection", true, 0.9);
        }
        for _ in 0..8 {
            monitor.record_event("injection", false, 0.1);
        }

        // deviation = 0.10, threshold = 0.10: fires because deviation >= threshold
        let alert = monitor.check_drift("injection", 0.10);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!((alert.deviation - 0.10).abs() < f64::EPSILON);
    }

    // -- Min samples enforcement -------------------------------------------

    #[test]
    fn min_samples_enforcement() {
        let config = FprMonitorConfig {
            min_window_samples: 100,
            drift_threshold: 0.02,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        // Only 10 events, well above baseline, but under min_window_samples.
        for _ in 0..10 {
            monitor.record_event("injection", true, 0.9);
        }

        let alert = monitor.check_drift("injection", 0.05);
        assert!(alert.is_none());
    }

    #[test]
    fn drift_fires_once_min_samples_reached() {
        let config = FprMonitorConfig {
            min_window_samples: 20,
            drift_threshold: 0.02,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        // 19 events: not enough
        for _ in 0..19 {
            monitor.record_event("injection", true, 0.9);
        }
        assert!(monitor.check_drift("injection", 0.05).is_none());

        // 20th event: now enough
        monitor.record_event("injection", true, 0.9);
        assert!(monitor.check_drift("injection", 0.05).is_some());
    }

    // -- Window pruning of old events --------------------------------------

    #[test]
    fn window_prunes_old_events() {
        let config = FprMonitorConfig {
            window_duration: Duration::from_secs(2),
            min_window_samples: 1,
            drift_threshold: 0.02,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        let old = Instant::now() - Duration::from_secs(10);
        monitor.record_event_at("injection", old, true, 0.9);
        monitor.record_event_at("injection", old, true, 0.9);

        // Recent event
        monitor.record_event("injection", false, 0.1);

        // Old events should be pruned
        let fpr = monitor.current_fpr("injection").unwrap();
        assert!(fpr.abs() < f64::EPSILON);

        let summary = monitor.summary();
        let inj = summary
            .categories
            .iter()
            .find(|c| c.category == "injection")
            .unwrap();
        assert_eq!(inj.sample_count, 1);
        assert_eq!(inj.flagged_count, 0);
    }

    #[test]
    fn pruned_events_do_not_affect_drift() {
        let config = FprMonitorConfig {
            window_duration: Duration::from_secs(1),
            min_window_samples: 5,
            drift_threshold: 0.02,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        let old = Instant::now() - Duration::from_secs(10);
        // 10 old flagged events
        for _ in 0..10 {
            monitor.record_event_at("injection", old, true, 0.9);
        }
        // 5 recent clean events
        for _ in 0..5 {
            monitor.record_event("injection", false, 0.1);
        }

        // Baseline 50%: after pruning, current FPR = 0%, so deviation = 0.50.
        // But the old events are gone, current FPR = 0.
        let fpr = monitor.current_fpr("injection").unwrap();
        assert!(fpr.abs() < f64::EPSILON);
    }

    // -- Multiple categories tracked independently -------------------------

    #[test]
    fn multiple_categories_independent() {
        let mut monitor = FprMonitor::new(default_config());

        // Injection: 100% flagged
        for _ in 0..10 {
            monitor.record_event("injection", true, 0.9);
        }
        // Jailbreak: 0% flagged
        for _ in 0..10 {
            monitor.record_event("jailbreak", false, 0.1);
        }

        let baselines: HashMap<String, f64> =
            [("injection".into(), 0.05), ("jailbreak".into(), 0.05)]
                .into_iter()
                .collect();

        let alerts = monitor.check_all_drift(&baselines);
        // Only injection should drift (1.0 vs 0.05 = 0.95 deviation)
        // Jailbreak: 0.0 vs 0.05 = 0.05 deviation > 0.02 threshold, so also drifts
        assert_eq!(alerts.len(), 2);

        let inj_alert = alerts.iter().find(|a| a.category == "injection").unwrap();
        assert!((inj_alert.current_fpr - 1.0).abs() < f64::EPSILON);

        let jb_alert = alerts.iter().find(|a| a.category == "jailbreak").unwrap();
        assert!(jb_alert.current_fpr.abs() < f64::EPSILON);
    }

    #[test]
    fn check_all_drift_only_drifted_categories() {
        let config = FprMonitorConfig {
            min_window_samples: 10,
            drift_threshold: 0.05,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        // Injection: 50% flagged (baseline 5% -> deviation 45%)
        for _ in 0..5 {
            monitor.record_event("injection", true, 0.9);
        }
        for _ in 0..5 {
            monitor.record_event("injection", false, 0.1);
        }

        // Jailbreak: ~5% flagged, close to baseline
        monitor.record_event("jailbreak", true, 0.8);
        for _ in 0..19 {
            monitor.record_event("jailbreak", false, 0.1);
        }

        let baselines: HashMap<String, f64> =
            [("injection".into(), 0.05), ("jailbreak".into(), 0.05)]
                .into_iter()
                .collect();

        let alerts = monitor.check_all_drift(&baselines);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, "injection");
    }

    // -- Summary computation -----------------------------------------------

    #[test]
    fn summary_computes_stats() {
        let mut monitor = FprMonitor::new(default_config());

        monitor.record_event("injection", true, 0.90);
        monitor.record_event("injection", false, 0.10);
        monitor.record_event("injection", true, 0.80);
        monitor.record_event("injection", false, 0.20);

        let summary = monitor.summary();
        let inj = summary
            .categories
            .iter()
            .find(|c| c.category == "injection")
            .unwrap();

        assert_eq!(inj.sample_count, 4);
        assert_eq!(inj.flagged_count, 2);
        assert!((inj.current_fpr - 0.5).abs() < f64::EPSILON);
        assert!((inj.avg_confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn summary_empty_category_has_zero_stats() {
        let mut monitor = FprMonitor::new(default_config());
        let summary = monitor.summary();
        for cat in &summary.categories {
            assert_eq!(cat.sample_count, 0);
            assert_eq!(cat.flagged_count, 0);
            assert!(cat.current_fpr.abs() < f64::EPSILON);
            assert!(cat.avg_confidence.abs() < f64::EPSILON);
        }
    }

    #[test]
    fn summary_sorted_by_category() {
        let config = FprMonitorConfig {
            categories: vec!["zzz".into(), "aaa".into(), "mmm".into()],
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);
        let summary = monitor.summary();
        let names: Vec<&str> = summary
            .categories
            .iter()
            .map(|c| c.category.as_str())
            .collect();
        assert_eq!(names, vec!["aaa", "mmm", "zzz"]);
    }

    // -- SecurityFinding generation from alerts ----------------------------

    #[test]
    fn security_finding_from_small_drift() {
        let alert = FprDriftAlert {
            category: "injection".into(),
            baseline_fpr: 0.05,
            current_fpr: 0.08,
            deviation: 0.03,
            window_size: 200,
            detected_at: Instant::now(),
        };
        let findings = FprMonitor::to_security_findings(&[alert]);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.finding_type, "fpr_drift");
        assert_eq!(f.severity, SecuritySeverity::Low);
        assert!(!f.requires_alert);
        assert!(f.description.contains("injection"));
        assert_eq!(f.metadata["category"], "injection");
        assert_eq!(f.metadata["window_size"], "200");
    }

    #[test]
    fn security_finding_from_medium_drift() {
        let alert = FprDriftAlert {
            category: "pii".into(),
            baseline_fpr: 0.01,
            current_fpr: 0.08,
            deviation: 0.07,
            window_size: 500,
            detected_at: Instant::now(),
        };
        let findings = FprMonitor::to_security_findings(&[alert]);
        assert_eq!(findings[0].severity, SecuritySeverity::Medium);
    }

    #[test]
    fn security_finding_from_large_drift() {
        let alert = FprDriftAlert {
            category: "toxicity".into(),
            baseline_fpr: 0.02,
            current_fpr: 0.15,
            deviation: 0.13,
            window_size: 1000,
            detected_at: Instant::now(),
        };
        let findings = FprMonitor::to_security_findings(&[alert]);
        assert_eq!(findings[0].severity, SecuritySeverity::High);
        assert!(findings[0].requires_alert);
    }

    #[test]
    fn security_finding_metadata_populated() {
        let alert = FprDriftAlert {
            category: "injection".into(),
            baseline_fpr: 0.05,
            current_fpr: 0.30,
            deviation: 0.25,
            window_size: 100,
            detected_at: Instant::now(),
        };
        let findings = FprMonitor::to_security_findings(&[alert]);
        let f = &findings[0];
        assert_eq!(f.metadata["category"], "injection");
        assert!(f.metadata.contains_key("baseline_fpr"));
        assert!(f.metadata.contains_key("current_fpr"));
        assert!(f.metadata.contains_key("deviation"));
        assert!(f.metadata.contains_key("window_size"));
    }

    #[test]
    fn empty_alerts_produce_empty_findings() {
        let findings = FprMonitor::to_security_findings(&[]);
        assert!(findings.is_empty());
    }

    // -- Edge cases --------------------------------------------------------

    #[test]
    fn single_sample_below_min_window() {
        let mut monitor = FprMonitor::new(default_config());
        monitor.record_event("injection", true, 0.95);

        let fpr = monitor.current_fpr("injection").unwrap();
        assert!((fpr - 1.0).abs() < f64::EPSILON);

        // min_window_samples = 10, only 1 sample -> no drift
        assert!(monitor.check_drift("injection", 0.05).is_none());
    }

    #[test]
    fn all_flagged() {
        let config = FprMonitorConfig {
            min_window_samples: 5,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);
        for _ in 0..10 {
            monitor.record_event("injection", true, 0.99);
        }

        let fpr = monitor.current_fpr("injection").unwrap();
        assert!((fpr - 1.0).abs() < f64::EPSILON);

        let alert = monitor.check_drift("injection", 0.05);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!((alert.deviation - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn none_flagged() {
        let config = FprMonitorConfig {
            min_window_samples: 5,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);
        for _ in 0..10 {
            monitor.record_event("injection", false, 0.01);
        }

        let fpr = monitor.current_fpr("injection").unwrap();
        assert!(fpr.abs() < f64::EPSILON);

        // Baseline 0% -> deviation 0 -> no drift
        assert!(monitor.check_drift("injection", 0.0).is_none());
    }

    #[test]
    fn dynamic_category_creation() {
        let mut monitor = FprMonitor::new(default_config());
        // "pii" was not in initial config
        monitor.record_event("pii", true, 0.7);
        let fpr = monitor.current_fpr("pii").unwrap();
        assert!((fpr - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_clamped_to_unit_range() {
        let mut monitor = FprMonitor::new(default_config());
        monitor.record_event("injection", true, 1.5);
        monitor.record_event("injection", false, -0.5);

        let summary = monitor.summary();
        let inj = summary
            .categories
            .iter()
            .find(|c| c.category == "injection")
            .unwrap();
        assert!((inj.avg_confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn drift_below_baseline_also_detected() {
        let config = FprMonitorConfig {
            min_window_samples: 10,
            drift_threshold: 0.02,
            ..default_config()
        };
        let mut monitor = FprMonitor::new(config);

        // Baseline: 50% FPR. Observed: 0% FPR. Deviation: 0.50.
        for _ in 0..10 {
            monitor.record_event("injection", false, 0.1);
        }

        let alert = monitor.check_drift("injection", 0.50);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!((alert.deviation - 0.50).abs() < f64::EPSILON);
    }

    #[test]
    fn multiple_findings_from_multiple_alerts() {
        let alerts = vec![
            FprDriftAlert {
                category: "injection".into(),
                baseline_fpr: 0.05,
                current_fpr: 0.30,
                deviation: 0.25,
                window_size: 100,
                detected_at: Instant::now(),
            },
            FprDriftAlert {
                category: "jailbreak".into(),
                baseline_fpr: 0.03,
                current_fpr: 0.10,
                deviation: 0.07,
                window_size: 200,
                detected_at: Instant::now(),
            },
        ];
        let findings = FprMonitor::to_security_findings(&alerts);
        assert_eq!(findings.len(), 2);

        let types: Vec<&str> = findings.iter().map(|f| f.finding_type.as_str()).collect();
        assert!(types.iter().all(|t| *t == "fpr_drift"));
    }
}
