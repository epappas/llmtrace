//! Configurable threshold system for the ensemble security analyzer.
//!
//! Provides [`OperatingPoint`] presets and [`ResolvedThresholds`] for per-category
//! confidence thresholds, plus a lightweight [`FalsePositiveTracker`] to monitor
//! detection rates over a sliding window.
//!
//! # Motivation
//!
//! A single global threshold creates an inherent trade-off between catching
//! every attack (high recall) and avoiding false positives (high precision).
//! Different detection categories (injection, jailbreak, PII, toxicity, data
//! leakage) have different base rates and cost profiles, so they benefit from
//! independent thresholds.  The [`OperatingPoint`] enum provides curated
//! presets inspired by the InjecGuard over-defence mitigation research.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// ────────────────────────────────────────────────────────────────────────────
// Operating point
// ────────────────────────────────────────────────────────────────────────────

/// Pre-defined operating points that balance precision against recall.
///
/// Each variant maps to a set of per-category thresholds.  Use
/// [`ResolvedThresholds::from_operating_point`] to materialise the concrete
/// values, optionally with per-category overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum OperatingPoint {
    /// High recall, more false positives — catch everything.
    HighRecall,
    /// Balanced precision and recall — recommended default.
    #[default]
    Balanced,
    /// High precision, fewer false positives — production-safe.
    HighPrecision,
    /// Fully custom thresholds (all values supplied via overrides).
    Custom,
}

// ────────────────────────────────────────────────────────────────────────────
// Resolved thresholds
// ────────────────────────────────────────────────────────────────────────────

/// Per-category confidence thresholds for the ensemble analyzer.
///
/// Each field represents the minimum confidence score required for a finding
/// of that category to be reported.  Values below the threshold are
/// suppressed.
#[derive(Debug, Clone)]
pub struct ResolvedThresholds {
    /// Threshold for prompt injection detection.
    pub injection: f64,
    /// Threshold for jailbreak detection.
    pub jailbreak: f64,
    /// Threshold for PII detection confidence.
    pub pii: f64,
    /// Threshold for toxicity detection.
    pub toxicity: f64,
    /// Threshold for data leakage detection.
    pub data_leakage: f64,
}

impl ResolvedThresholds {
    /// Resolve thresholds from an [`OperatingPoint`] with optional per-category overrides.
    ///
    /// Override keys are lower-case category names: `"injection"`, `"jailbreak"`,
    /// `"pii"`, `"toxicity"`, `"data_leakage"`.  Unknown keys are silently ignored.
    ///
    /// # Examples
    ///
    /// ```
    /// use llmtrace_security::thresholds::{OperatingPoint, ResolvedThresholds};
    ///
    /// let t = ResolvedThresholds::from_operating_point(&OperatingPoint::Balanced, None);
    /// assert!((t.injection - 0.75).abs() < f64::EPSILON);
    /// ```
    #[must_use]
    pub fn from_operating_point(
        point: &OperatingPoint,
        overrides: Option<&HashMap<String, f64>>,
    ) -> Self {
        let mut thresholds = match point {
            OperatingPoint::HighRecall => Self {
                injection: 0.50,
                jailbreak: 0.50,
                pii: 0.40,
                toxicity: 0.45,
                data_leakage: 0.45,
            },
            OperatingPoint::Balanced => Self {
                injection: 0.75,
                jailbreak: 0.75,
                pii: 0.60,
                toxicity: 0.65,
                data_leakage: 0.65,
            },
            OperatingPoint::HighPrecision => Self {
                injection: 0.90,
                jailbreak: 0.90,
                pii: 0.80,
                toxicity: 0.85,
                data_leakage: 0.85,
            },
            OperatingPoint::Custom => Self {
                injection: 0.75,
                jailbreak: 0.75,
                pii: 0.60,
                toxicity: 0.65,
                data_leakage: 0.65,
            },
        };

        if let Some(overrides) = overrides {
            thresholds.apply_overrides(overrides);
        }

        thresholds
    }

    /// Apply per-category overrides to this threshold set.
    ///
    /// Recognised keys: `"injection"`, `"jailbreak"`, `"pii"`, `"toxicity"`,
    /// `"data_leakage"`.  Values are clamped to `[0.0, 1.0]`.
    pub fn apply_overrides(&mut self, overrides: &HashMap<String, f64>) {
        if let Some(&v) = overrides.get("injection") {
            self.injection = v.clamp(0.0, 1.0);
        }
        if let Some(&v) = overrides.get("jailbreak") {
            self.jailbreak = v.clamp(0.0, 1.0);
        }
        if let Some(&v) = overrides.get("pii") {
            self.pii = v.clamp(0.0, 1.0);
        }
        if let Some(&v) = overrides.get("toxicity") {
            self.toxicity = v.clamp(0.0, 1.0);
        }
        if let Some(&v) = overrides.get("data_leakage") {
            self.data_leakage = v.clamp(0.0, 1.0);
        }
    }

    /// Apply a single per-category override by name.
    ///
    /// Returns `true` if the category was recognised and updated.
    pub fn apply_single_override(&mut self, category: &str, value: f64) -> bool {
        let clamped = value.clamp(0.0, 1.0);
        match category {
            "injection" => {
                self.injection = clamped;
                true
            }
            "jailbreak" => {
                self.jailbreak = clamped;
                true
            }
            "pii" => {
                self.pii = clamped;
                true
            }
            "toxicity" => {
                self.toxicity = clamped;
                true
            }
            "data_leakage" => {
                self.data_leakage = clamped;
                true
            }
            _ => false,
        }
    }

    /// Get the threshold for a specific finding type string.
    ///
    /// Maps finding type strings (e.g. `"prompt_injection"`, `"jailbreak"`,
    /// `"pii_detected"`, `"data_leakage"`) to the appropriate threshold.
    /// Returns `None` for unrecognised finding types.
    #[must_use]
    pub fn threshold_for_finding_type(&self, finding_type: &str) -> Option<f64> {
        match finding_type {
            "prompt_injection" | "role_injection" | "encoding_attack" | "ml_prompt_injection"
            | "fusion_prompt_injection" => Some(self.injection),
            "jailbreak" => Some(self.jailbreak),
            "pii_detected" => Some(self.pii),
            "toxicity" => Some(self.toxicity),
            "data_leakage" | "secret_leakage" => Some(self.data_leakage),
            _ => None,
        }
    }
}

impl Default for ResolvedThresholds {
    fn default() -> Self {
        Self::from_operating_point(&OperatingPoint::Balanced, None)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// False-positive tracker
// ────────────────────────────────────────────────────────────────────────────

/// Lightweight sliding-window tracker for recent detection events.
///
/// Records whether each analysed input was flagged, allowing operators to
/// monitor the flagging rate and detect threshold drift (e.g. a sudden spike
/// in flags may indicate the threshold is too low).
///
/// The tracker is deliberately simple — it does not persist across restarts
/// and uses wall-clock time.
pub struct FalsePositiveTracker {
    /// Ring buffer of `(timestamp, was_flagged)` entries.
    window: VecDeque<(Instant, bool)>,
    /// Maximum age of entries retained in the window.
    window_duration: Duration,
}

impl FalsePositiveTracker {
    /// Create a new tracker with the given window duration.
    ///
    /// # Examples
    ///
    /// ```
    /// use llmtrace_security::thresholds::FalsePositiveTracker;
    /// use std::time::Duration;
    ///
    /// let tracker = FalsePositiveTracker::new(Duration::from_secs(300));
    /// assert_eq!(tracker.total_in_window(), 0);
    /// ```
    #[must_use]
    pub fn new(window_duration: Duration) -> Self {
        Self {
            window: VecDeque::new(),
            window_duration,
        }
    }

    /// Record a detection event.
    ///
    /// `was_flagged` should be `true` if the input was flagged by the
    /// analyzer, `false` if it passed clean.
    pub fn record(&mut self, was_flagged: bool) {
        self.prune();
        self.window.push_back((Instant::now(), was_flagged));
    }

    /// Record a detection event with a specific timestamp (for testing).
    pub fn record_at(&mut self, at: Instant, was_flagged: bool) {
        self.prune();
        self.window.push_back((at, was_flagged));
    }

    /// Return the proportion of events that were flagged in the current window.
    ///
    /// Returns `0.0` if no events have been recorded.
    #[must_use]
    pub fn flagged_rate(&mut self) -> f64 {
        self.prune();
        let total = self.window.len();
        if total == 0 {
            return 0.0;
        }
        let flagged = self.window.iter().filter(|(_, f)| *f).count();
        flagged as f64 / total as f64
    }

    /// Return the total number of events currently in the window.
    #[must_use]
    pub fn total_in_window(&self) -> usize {
        self.window.len()
    }

    /// Return the number of flagged events currently in the window.
    #[must_use]
    pub fn flagged_in_window(&self) -> usize {
        self.window.iter().filter(|(_, f)| *f).count()
    }

    /// Remove entries older than `window_duration`.
    fn prune(&mut self) {
        let cutoff = Instant::now() - self.window_duration;
        while self
            .window
            .front()
            .is_some_and(|(ts, _)| *ts < cutoff)
        {
            self.window.pop_front();
        }
    }
}

impl Default for FalsePositiveTracker {
    fn default() -> Self {
        Self::new(Duration::from_secs(300)) // 5-minute window
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- OperatingPoint defaults ------------------------------------------

    #[test]
    fn test_operating_point_default_is_balanced() {
        assert_eq!(OperatingPoint::default(), OperatingPoint::Balanced);
    }

    // -- ResolvedThresholds from operating point --------------------------

    #[test]
    fn test_balanced_thresholds() {
        let t = ResolvedThresholds::from_operating_point(&OperatingPoint::Balanced, None);
        assert!((t.injection - 0.75).abs() < f64::EPSILON);
        assert!((t.jailbreak - 0.75).abs() < f64::EPSILON);
        assert!((t.pii - 0.60).abs() < f64::EPSILON);
        assert!((t.toxicity - 0.65).abs() < f64::EPSILON);
        assert!((t.data_leakage - 0.65).abs() < f64::EPSILON);
    }

    #[test]
    fn test_high_recall_thresholds_are_lower() {
        let t = ResolvedThresholds::from_operating_point(&OperatingPoint::HighRecall, None);
        assert!(t.injection < 0.75);
        assert!(t.jailbreak < 0.75);
        assert!(t.pii < 0.60);
    }

    #[test]
    fn test_high_precision_thresholds_are_higher() {
        let t = ResolvedThresholds::from_operating_point(&OperatingPoint::HighPrecision, None);
        assert!(t.injection > 0.75);
        assert!(t.jailbreak > 0.75);
        assert!(t.pii > 0.60);
    }

    #[test]
    fn test_custom_falls_back_to_balanced() {
        let balanced = ResolvedThresholds::from_operating_point(&OperatingPoint::Balanced, None);
        let custom = ResolvedThresholds::from_operating_point(&OperatingPoint::Custom, None);
        assert!((balanced.injection - custom.injection).abs() < f64::EPSILON);
        assert!((balanced.jailbreak - custom.jailbreak).abs() < f64::EPSILON);
    }

    #[test]
    fn test_overrides_applied() {
        let mut overrides = HashMap::new();
        overrides.insert("injection".to_string(), 0.42);
        overrides.insert("pii".to_string(), 0.99);
        let t = ResolvedThresholds::from_operating_point(
            &OperatingPoint::Balanced,
            Some(&overrides),
        );
        assert!((t.injection - 0.42).abs() < f64::EPSILON);
        assert!((t.pii - 0.99).abs() < f64::EPSILON);
        // Non-overridden values stay at Balanced defaults
        assert!((t.jailbreak - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_overrides_clamped() {
        let mut overrides = HashMap::new();
        overrides.insert("injection".to_string(), 1.5);
        overrides.insert("pii".to_string(), -0.3);
        let t = ResolvedThresholds::from_operating_point(
            &OperatingPoint::Balanced,
            Some(&overrides),
        );
        assert!((t.injection - 1.0).abs() < f64::EPSILON);
        assert!(t.pii.abs() < f64::EPSILON);
    }

    #[test]
    fn test_unknown_override_ignored() {
        let mut overrides = HashMap::new();
        overrides.insert("nonexistent".to_string(), 0.5);
        let t = ResolvedThresholds::from_operating_point(
            &OperatingPoint::Balanced,
            Some(&overrides),
        );
        assert!((t.injection - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_apply_single_override() {
        let mut t = ResolvedThresholds::default();
        assert!(t.apply_single_override("injection", 0.42));
        assert!((t.injection - 0.42).abs() < f64::EPSILON);
        assert!(!t.apply_single_override("nonexistent", 0.5));
    }

    #[test]
    fn test_threshold_for_finding_type() {
        let t = ResolvedThresholds::default();
        assert_eq!(t.threshold_for_finding_type("prompt_injection"), Some(0.75));
        assert_eq!(t.threshold_for_finding_type("jailbreak"), Some(0.75));
        assert_eq!(t.threshold_for_finding_type("pii_detected"), Some(0.60));
        assert_eq!(t.threshold_for_finding_type("data_leakage"), Some(0.65));
        assert_eq!(t.threshold_for_finding_type("secret_leakage"), Some(0.65));
        assert_eq!(t.threshold_for_finding_type("unknown_type"), None);
    }

    #[test]
    fn test_default_thresholds_equal_balanced() {
        let default = ResolvedThresholds::default();
        let balanced = ResolvedThresholds::from_operating_point(&OperatingPoint::Balanced, None);
        assert!((default.injection - balanced.injection).abs() < f64::EPSILON);
        assert!((default.jailbreak - balanced.jailbreak).abs() < f64::EPSILON);
        assert!((default.pii - balanced.pii).abs() < f64::EPSILON);
        assert!((default.toxicity - balanced.toxicity).abs() < f64::EPSILON);
        assert!((default.data_leakage - balanced.data_leakage).abs() < f64::EPSILON);
    }

    // -- FalsePositiveTracker ---------------------------------------------

    #[test]
    fn test_tracker_empty() {
        let tracker = FalsePositiveTracker::new(Duration::from_secs(60));
        assert_eq!(tracker.total_in_window(), 0);
        assert_eq!(tracker.flagged_in_window(), 0);
    }

    #[test]
    fn test_tracker_empty_rate_is_zero() {
        let mut tracker = FalsePositiveTracker::new(Duration::from_secs(60));
        assert!(tracker.flagged_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn test_tracker_records_events() {
        let mut tracker = FalsePositiveTracker::new(Duration::from_secs(60));
        tracker.record(true);
        tracker.record(false);
        tracker.record(true);
        assert_eq!(tracker.total_in_window(), 3);
        assert_eq!(tracker.flagged_in_window(), 2);
    }

    #[test]
    fn test_tracker_flagged_rate() {
        let mut tracker = FalsePositiveTracker::new(Duration::from_secs(300));
        tracker.record(true);
        tracker.record(false);
        tracker.record(false);
        tracker.record(true);
        let rate = tracker.flagged_rate();
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tracker_prunes_expired() {
        let mut tracker = FalsePositiveTracker::new(Duration::from_secs(1));
        // Insert an event "in the past" by using record_at
        let old = Instant::now() - Duration::from_secs(5);
        tracker.record_at(old, true);
        tracker.record(false); // recent

        // After pruning (triggered by flagged_rate), the old event should be gone
        let rate = tracker.flagged_rate();
        assert!(rate.abs() < f64::EPSILON); // only the false event remains
        assert_eq!(tracker.total_in_window(), 1);
    }

    #[test]
    fn test_tracker_default_window_is_5_minutes() {
        let tracker = FalsePositiveTracker::default();
        assert_eq!(tracker.window_duration, Duration::from_secs(300));
    }
}
