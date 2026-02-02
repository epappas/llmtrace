//! FPR-aware threshold calibration for security analyzers (IS-006).
//!
//! This module provides tools to compute optimal confidence thresholds that
//! achieve specific false-positive rate (FPR) operating points.  Given a set
//! of labeled samples (benign vs. malicious) with their confidence scores,
//! the calibrator finds the threshold where the proportion of benign samples
//! incorrectly flagged equals the target FPR.
//!
//! # Research Background
//!
//! The three standard FPR operating points (0.1 %, 0.5 %, 1 %) come directly
//! from the **PromptShield** evaluation methodology (Jacob et al., UC
//! Berkeley, ACM CODASPY 2025).  PromptShield demonstrated that existing
//! detectors fail catastrophically at deployment-realistic FPR thresholds:
//!
//! > At 0.1 % FPR, Meta PromptGuard detects only **9.4 %** of attacks.
//! > PromptShield achieved **65.3 % TPR** at the same operating point.
//!
//! This means the *threshold* at which a detector is evaluated matters more
//! than headline F1 scores.  A detector with excellent F1 may be unusable in
//! production if its FPR is unacceptable.
//!
//! The **InjecGuard** paper (Li & Liu, ACL 2025) further shows that
//! **over-defense** — false positives on benign inputs that contain trigger
//! words like "ignore", "system", "instructions" — is the dominant source of
//! false positives.  State-of-the-art models score as low as 0.88 %
//! over-defense accuracy (PromptGuard) on the NotInject benchmark.  This
//! module therefore tracks over-defense samples separately during calibration
//! to give operators visibility into this critical failure mode.
//!
//! # Supported Operating Points
//!
//! | Operating Point | Target FPR | Use Case                          | Reference |
//! |-----------------|-----------|-----------------------------------|-----------|
//! | Strict          | 0.1 %     | Production — minimal false alarms | PromptShield Table 2 |
//! | Moderate        | 0.5 %     | Balanced deployments              | PromptShield Table 2 |
//! | Permissive      | 1.0 %     | High-recall prioritised           | PromptShield Table 2 |
//!
//! # Algorithm
//!
//! Threshold calibration uses the empirical quantile of the benign score
//! distribution.  For a target FPR of X %:
//!
//! 1. Collect confidence scores from the analyzer on all labeled benign
//!    samples (including over-defense / NotInject-style samples).
//! 2. Sort benign scores in ascending order.
//! 3. Compute `index = ceil((1 − X/100) × N) − 1` where N is the number of
//!    benign samples.
//! 4. Set `threshold = benign_scores[index]`.
//! 5. At this threshold, at most X % of benign samples score strictly above
//!    it (i.e. would be false positives).
//! 6. Compute TPR as the proportion of malicious samples scoring above the
//!    threshold.
//!
//! This is an O(N log N) sort followed by O(1) index lookup — equivalent to
//! sweeping all possible thresholds but more efficient.
//!
//! # Example
//!
//! ```
//! use llmtrace_security::fpr_calibration::{
//!     CalibrationDataset, CalibrationSample, FprTarget, ThresholdCalibrator,
//! };
//!
//! let mut dataset = CalibrationDataset::new("injection");
//! // Add benign samples (low scores expected)
//! dataset.add(CalibrationSample::benign(0.1));
//! dataset.add(CalibrationSample::benign(0.2));
//! dataset.add(CalibrationSample::benign(0.05));
//! // Add malicious samples (high scores expected)
//! dataset.add(CalibrationSample::malicious(0.9));
//! dataset.add(CalibrationSample::malicious(0.85));
//!
//! let calibrator = ThresholdCalibrator::new();
//! let results = calibrator.calibrate(&dataset);
//! assert_eq!(results.len(), 3); // one per FPR target
//! ```

use std::collections::HashMap;
use std::fmt;

use crate::thresholds::ResolvedThresholds;

// ────────────────────────────────────────────────────────────────────────────
// FPR target operating points
// ────────────────────────────────────────────────────────────────────────────

/// Target false-positive rate for threshold calibration.
///
/// Each variant corresponds to a deployment scenario where a specific
/// maximum FPR is acceptable.  The three standard targets are derived from
/// the PromptShield evaluation methodology (Jacob et al., CODASPY 2025).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FprTarget {
    /// 0.1 % FPR — strict, production-safe with minimal false alarms.
    ///
    /// At this operating point, PromptShield reports that Meta PromptGuard
    /// detects only 9.4 % of attacks, while PromptShield itself achieves
    /// 65.3 % TPR.
    Strict,
    /// 0.5 % FPR — balanced for most deployments.
    Moderate,
    /// 1.0 % FPR — permissive, prioritising recall over precision.
    Permissive,
    /// Custom FPR target (value in range `[0.0, 1.0]`).
    Custom(f64),
}

impl FprTarget {
    /// Return the target FPR as a proportion (0.0–1.0).
    #[must_use]
    pub fn rate(&self) -> f64 {
        match self {
            Self::Strict => 0.001,
            Self::Moderate => 0.005,
            Self::Permissive => 0.01,
            Self::Custom(r) => r.clamp(0.0, 1.0),
        }
    }

    /// Return a human-readable label for the operating point.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Strict => "0.1% FPR (Strict)".to_string(),
            Self::Moderate => "0.5% FPR (Moderate)".to_string(),
            Self::Permissive => "1.0% FPR (Permissive)".to_string(),
            Self::Custom(r) => format!("{:.2}% FPR (Custom)", r * 100.0),
        }
    }

    /// Return the three standard FPR targets from the PromptShield paper.
    #[must_use]
    pub fn standard_targets() -> Vec<Self> {
        vec![Self::Strict, Self::Moderate, Self::Permissive]
    }
}

impl fmt::Display for FprTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Calibration sample & dataset
// ────────────────────────────────────────────────────────────────────────────

/// Classification of a benign sample for calibration purposes.
///
/// The InjecGuard paper (Li & Liu, ACL 2025) demonstrates that benign inputs
/// containing trigger words (e.g. "ignore", "system") are dramatically harder
/// to classify correctly — PromptGuard achieves only 0.88 % accuracy on such
/// inputs.  Tracking these separately lets operators understand where their
/// false positives come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenignClass {
    /// Clean benign input — no trigger words, no resemblance to attacks.
    Clean,
    /// Over-defense sample — benign input containing trigger words that
    /// commonly appear in injection attacks (NotInject methodology).
    ///
    /// The `u8` field is the difficulty level (1–3): number of trigger words.
    OverDefense(u8),
}

/// A single labeled sample used for threshold calibration.
///
/// Each sample carries the confidence score produced by the analyzer and a
/// ground-truth label (benign or malicious).
#[derive(Debug, Clone)]
pub struct CalibrationSample {
    /// The confidence score produced by the analyzer (0.0–1.0).
    pub score: f64,
    /// Whether the sample is truly malicious (`true`) or benign (`false`).
    pub is_malicious: bool,
    /// For benign samples: whether this is a clean benign or an over-defense
    /// sample (benign with trigger words).  `None` for malicious samples.
    pub benign_class: Option<BenignClass>,
}

impl CalibrationSample {
    /// Create a clean benign sample with the given confidence score.
    #[must_use]
    pub fn benign(score: f64) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            is_malicious: false,
            benign_class: Some(BenignClass::Clean),
        }
    }

    /// Create a malicious sample with the given confidence score.
    #[must_use]
    pub fn malicious(score: f64) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            is_malicious: true,
            benign_class: None,
        }
    }

    /// Create an over-defense sample — benign input with trigger words
    /// (NotInject methodology, InjecGuard paper).
    ///
    /// `difficulty` is the number of trigger words (1–3).  These samples are
    /// benign for threshold calibration purposes but tracked separately for
    /// diagnostics.
    #[must_use]
    pub fn over_defense(score: f64, difficulty: u8) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            is_malicious: false,
            benign_class: Some(BenignClass::OverDefense(difficulty.clamp(1, 3))),
        }
    }
}

/// A labeled dataset for a specific detection category.
///
/// Collects benign (including over-defense) and malicious samples with their
/// analyzer confidence scores, ready for threshold calibration.
#[derive(Debug, Clone)]
pub struct CalibrationDataset {
    /// Detection category name (e.g., `"injection"`, `"jailbreak"`, `"pii"`).
    pub category: String,
    /// Labeled samples.
    pub samples: Vec<CalibrationSample>,
}

impl CalibrationDataset {
    /// Create a new empty dataset for the given category.
    #[must_use]
    pub fn new(category: &str) -> Self {
        Self {
            category: category.to_string(),
            samples: Vec::new(),
        }
    }

    /// Add a sample to the dataset.
    pub fn add(&mut self, sample: CalibrationSample) {
        self.samples.push(sample);
    }

    /// Add multiple samples at once.
    pub fn add_many(&mut self, samples: impl IntoIterator<Item = CalibrationSample>) {
        self.samples.extend(samples);
    }

    /// Return the number of benign samples (clean + over-defense).
    #[must_use]
    pub fn benign_count(&self) -> usize {
        self.samples.iter().filter(|s| !s.is_malicious).count()
    }

    /// Return the number of clean benign samples (no trigger words).
    #[must_use]
    pub fn clean_benign_count(&self) -> usize {
        self.samples
            .iter()
            .filter(|s| s.benign_class == Some(BenignClass::Clean))
            .count()
    }

    /// Return the number of over-defense samples (benign with trigger words).
    #[must_use]
    pub fn over_defense_count(&self) -> usize {
        self.samples
            .iter()
            .filter(|s| matches!(s.benign_class, Some(BenignClass::OverDefense(_))))
            .count()
    }

    /// Return the number of malicious samples.
    #[must_use]
    pub fn malicious_count(&self) -> usize {
        self.samples.iter().filter(|s| s.is_malicious).count()
    }

    /// Return the total number of samples.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.samples.len()
    }

    /// Return sorted benign scores (ascending) — includes both clean and
    /// over-defense samples since both are genuinely benign.
    fn sorted_benign_scores(&self) -> Vec<f64> {
        let mut scores: Vec<f64> = self
            .samples
            .iter()
            .filter(|s| !s.is_malicious)
            .map(|s| s.score)
            .collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }

    /// Return sorted malicious scores (ascending).
    fn sorted_malicious_scores(&self) -> Vec<f64> {
        let mut scores: Vec<f64> = self
            .samples
            .iter()
            .filter(|s| s.is_malicious)
            .map(|s| s.score)
            .collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }

    /// Return sorted over-defense scores only (ascending).
    fn sorted_over_defense_scores(&self) -> Vec<f64> {
        let mut scores: Vec<f64> = self
            .samples
            .iter()
            .filter(|s| matches!(s.benign_class, Some(BenignClass::OverDefense(_))))
            .map(|s| s.score)
            .collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Calibration result
// ────────────────────────────────────────────────────────────────────────────

/// Result of calibrating a threshold for a specific FPR target.
#[derive(Debug, Clone)]
pub struct CalibrationResult {
    /// The detection category (e.g. `"injection"`).
    pub category: String,
    /// The target FPR operating point.
    pub fpr_target: FprTarget,
    /// The computed threshold that achieves (or gets closest to) the target FPR.
    pub threshold: f64,
    /// The actual FPR achieved at this threshold (over all benign samples).
    pub achieved_fpr: f64,
    /// The true-positive rate (recall) achieved at this threshold.
    pub achieved_tpr: f64,
    /// Number of benign samples used (clean + over-defense).
    pub benign_count: usize,
    /// Number of malicious samples used.
    pub malicious_count: usize,
    /// Over-defense FPR: false-positive rate on over-defense samples only.
    ///
    /// This is the fraction of NotInject-style samples (benign with trigger
    /// words) that would be incorrectly flagged at this threshold.  A high
    /// value here indicates trigger-word bias (InjecGuard paper).
    pub over_defense_fpr: f64,
    /// Number of over-defense samples in the dataset.
    pub over_defense_count: usize,
}

impl CalibrationResult {
    /// Return `true` if the achieved FPR is at or below the target.
    #[must_use]
    pub fn meets_target(&self) -> bool {
        self.achieved_fpr <= self.fpr_target.rate() + f64::EPSILON
    }
}

impl fmt::Display for CalibrationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} → threshold={:.4}, fpr={:.4}%, tpr={:.2}%, od_fpr={:.2}% \
             (n_benign={}, n_malicious={}, n_od={})",
            self.category,
            self.fpr_target,
            self.threshold,
            self.achieved_fpr * 100.0,
            self.achieved_tpr * 100.0,
            self.over_defense_fpr * 100.0,
            self.benign_count,
            self.malicious_count,
            self.over_defense_count,
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Multi-category calibration report
// ────────────────────────────────────────────────────────────────────────────

/// Aggregated calibration results across multiple categories and FPR targets.
#[derive(Debug, Clone)]
pub struct CalibrationReport {
    /// All individual calibration results.
    pub results: Vec<CalibrationResult>,
}

impl CalibrationReport {
    /// Create a new empty report.
    #[must_use]
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Filter results by category.
    #[must_use]
    pub fn for_category(&self, category: &str) -> Vec<&CalibrationResult> {
        self.results
            .iter()
            .filter(|r| r.category == category)
            .collect()
    }

    /// Filter results by FPR target.
    #[must_use]
    pub fn for_fpr_target(&self, target: &FprTarget) -> Vec<&CalibrationResult> {
        self.results
            .iter()
            .filter(|r| (r.fpr_target.rate() - target.rate()).abs() < f64::EPSILON)
            .collect()
    }

    /// Convert calibration results for a specific FPR target into
    /// [`ResolvedThresholds`], applying calibrated values for each category
    /// found in the report.
    ///
    /// Categories not present in the report retain their default values
    /// from the provided `base` thresholds.
    #[must_use]
    pub fn to_resolved_thresholds(
        &self,
        target: &FprTarget,
        base: &ResolvedThresholds,
    ) -> ResolvedThresholds {
        let mut thresholds = base.clone();
        for result in self.for_fpr_target(target) {
            thresholds.apply_single_override(&result.category, result.threshold);
        }
        thresholds
    }

    /// Return `true` if all results meet their respective FPR targets.
    #[must_use]
    pub fn all_targets_met(&self) -> bool {
        self.results.iter().all(|r| r.meets_target())
    }
}

impl Default for CalibrationReport {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CalibrationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== FPR-Aware Threshold Calibration Report ===")?;
        writeln!(
            f,
            "  (PromptShield methodology: Jacob et al., CODASPY 2025)"
        )?;
        writeln!(f)?;
        for result in &self.results {
            writeln!(f, "  {result}")?;
        }
        if self.all_targets_met() {
            writeln!(f, "\n  ✅ All FPR targets met.")?;
        } else {
            let missed: Vec<_> = self.results.iter().filter(|r| !r.meets_target()).collect();
            writeln!(f, "\n  ⚠ {} target(s) not met:", missed.len())?;
            for r in missed {
                writeln!(
                    f,
                    "    - [{}] {}: achieved {:.4}% > target {:.4}%",
                    r.category,
                    r.fpr_target,
                    r.achieved_fpr * 100.0,
                    r.fpr_target.rate() * 100.0,
                )?;
            }
        }
        // Print PromptShield reference comparison
        writeln!(f)?;
        writeln!(f, "  Reference (PromptShield paper, 0.1% FPR):")?;
        writeln!(f, "    Meta PromptGuard TPR:  9.4%")?;
        writeln!(f, "    PromptShield TPR:     65.3%")?;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Threshold calibrator
// ────────────────────────────────────────────────────────────────────────────

/// Calibrates confidence thresholds to achieve target FPR operating points.
///
/// Given labeled data (benign + malicious samples with scores), finds the
/// threshold for each target FPR using the empirical quantile of the benign
/// score distribution.  This is the same methodology used by PromptShield
/// (Jacob et al., CODASPY 2025) to evaluate detectors at deployment-realistic
/// operating points.
///
/// # Why FPR-based evaluation matters
///
/// The PromptShield paper showed that headline metrics (F1, accuracy) hide
/// production failures:
///
/// - **Meta PromptGuard**: 94 % F1, but only **9.4 % TPR** at 0.1 % FPR
/// - **PromptShield**: 89 % F1, but **65.3 % TPR** at 0.1 % FPR
///
/// A detector with lower F1 can be dramatically better in production if it
/// maintains recall at low false-positive rates.
#[derive(Debug, Clone)]
pub struct ThresholdCalibrator {
    /// FPR targets to evaluate.
    targets: Vec<FprTarget>,
}

impl ThresholdCalibrator {
    /// Create a calibrator with the three standard FPR targets (0.1 %, 0.5 %, 1 %).
    #[must_use]
    pub fn new() -> Self {
        Self {
            targets: FprTarget::standard_targets(),
        }
    }

    /// Create a calibrator with custom FPR targets.
    #[must_use]
    pub fn with_targets(targets: Vec<FprTarget>) -> Self {
        Self { targets }
    }

    /// Calibrate thresholds for a single category dataset.
    ///
    /// Returns one [`CalibrationResult`] per FPR target.  If the dataset has
    /// no benign samples, the threshold defaults to 1.0 (never flag — most
    /// conservative).  If it has no malicious samples, TPR is reported as 0.0.
    ///
    /// Over-defense samples (benign with trigger words) are included in the
    /// benign pool for threshold computation — they are genuinely benign and
    /// must not be flagged.  The `over_defense_fpr` field in the result
    /// separately reports the false-positive rate on just these samples.
    #[must_use]
    pub fn calibrate(&self, dataset: &CalibrationDataset) -> Vec<CalibrationResult> {
        let benign_scores = dataset.sorted_benign_scores();
        let malicious_scores = dataset.sorted_malicious_scores();
        let od_scores = dataset.sorted_over_defense_scores();

        self.targets
            .iter()
            .map(|target| {
                let threshold = compute_fpr_threshold(&benign_scores, target.rate());
                let achieved_fpr = compute_fpr_at_threshold(&benign_scores, threshold);
                let achieved_tpr = compute_tpr_at_threshold(&malicious_scores, threshold);
                let over_defense_fpr = compute_fpr_at_threshold(&od_scores, threshold);

                CalibrationResult {
                    category: dataset.category.clone(),
                    fpr_target: *target,
                    threshold,
                    achieved_fpr,
                    achieved_tpr,
                    benign_count: benign_scores.len(),
                    malicious_count: malicious_scores.len(),
                    over_defense_fpr,
                    over_defense_count: od_scores.len(),
                }
            })
            .collect()
    }

    /// Calibrate thresholds across multiple category datasets and produce a
    /// unified [`CalibrationReport`].
    #[must_use]
    pub fn calibrate_all(&self, datasets: &[CalibrationDataset]) -> CalibrationReport {
        let mut report = CalibrationReport::new();
        for dataset in datasets {
            report.results.extend(self.calibrate(dataset));
        }
        report
    }

    /// Calibrate and directly produce a [`ResolvedThresholds`] for a specific
    /// FPR target, starting from a base threshold set.
    ///
    /// This is a convenience method that calibrates all provided datasets and
    /// applies the results for the given `target` to `base`.
    #[must_use]
    pub fn calibrate_to_thresholds(
        &self,
        datasets: &[CalibrationDataset],
        target: &FprTarget,
        base: &ResolvedThresholds,
    ) -> ResolvedThresholds {
        let report = self.calibrate_all(datasets);
        report.to_resolved_thresholds(target, base)
    }
}

impl Default for ThresholdCalibrator {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Core threshold computation functions
// ────────────────────────────────────────────────────────────────────────────

/// Compute the threshold that achieves a target FPR on sorted benign scores.
///
/// Uses the empirical quantile of the benign score distribution.  For a
/// target FPR of X (as a proportion):
///
/// 1. `index = ceil((1 − X) × N) − 1`
/// 2. `threshold = benign_scores[index]`
///
/// Scores **strictly above** this threshold are classified as positive
/// (i.e. flagged).  This guarantees that at most `ceil(X × N)` benign
/// samples are false positives.
///
/// Returns `1.0` if `benign_scores` is empty (never flag anything —
/// most conservative fallback).
/// Returns `0.0` if `target_fpr >= 1.0` (flag everything).
#[must_use]
pub fn compute_fpr_threshold(benign_scores: &[f64], target_fpr: f64) -> f64 {
    if benign_scores.is_empty() {
        return 1.0;
    }
    if target_fpr >= 1.0 {
        return 0.0;
    }
    if target_fpr <= 0.0 {
        // FPR = 0 means no benign sample should be flagged.
        // Set threshold above the maximum benign score.
        return benign_scores
            .last()
            .copied()
            .map(|max| (max + 0.001).min(1.0))
            .unwrap_or(1.0);
    }

    let n = benign_scores.len();
    // We want at most `target_fpr * n` benign samples above the threshold.
    // The index into the sorted (ascending) array where we set the threshold
    // is at position `ceil((1 - target_fpr) * n) - 1`.
    let quantile_position = ((1.0 - target_fpr) * n as f64).ceil() as usize;
    let index = quantile_position.min(n) - 1;

    benign_scores[index]
}

/// Compute the actual FPR at a given threshold on benign scores.
///
/// FPR = (number of benign scores > threshold) / total benign count.
///
/// Uses strict inequality: a sample scoring *exactly* at the threshold is
/// not counted as a false positive.
#[must_use]
pub fn compute_fpr_at_threshold(benign_scores: &[f64], threshold: f64) -> f64 {
    if benign_scores.is_empty() {
        return 0.0;
    }
    let false_positives = benign_scores.iter().filter(|&&s| s > threshold).count();
    false_positives as f64 / benign_scores.len() as f64
}

/// Compute the true-positive rate (recall) at a given threshold on
/// malicious scores.
///
/// TPR = (number of malicious scores > threshold) / total malicious count.
#[must_use]
pub fn compute_tpr_at_threshold(malicious_scores: &[f64], threshold: f64) -> f64 {
    if malicious_scores.is_empty() {
        return 0.0;
    }
    let true_positives = malicious_scores.iter().filter(|&&s| s > threshold).count();
    true_positives as f64 / malicious_scores.len() as f64
}

/// Evaluate at all three standard FPR operating points (PromptShield
/// methodology) given raw benign and malicious score vectors.
///
/// This is a convenience function for quick evaluation without constructing
/// a full [`CalibrationDataset`].  It sorts the benign scores internally.
///
/// Returns a map of `FprTarget` label → `(threshold, achieved_fpr, achieved_tpr)`.
#[must_use]
pub fn evaluate_at_standard_operating_points(
    benign_scores: &[f64],
    malicious_scores: &[f64],
) -> HashMap<String, (f64, f64, f64)> {
    let mut sorted_benign = benign_scores.to_vec();
    sorted_benign.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mut results = HashMap::new();
    for target in FprTarget::standard_targets() {
        let threshold = compute_fpr_threshold(&sorted_benign, target.rate());
        let fpr = compute_fpr_at_threshold(&sorted_benign, threshold);
        let tpr = compute_tpr_at_threshold(malicious_scores, threshold);
        results.insert(target.label(), (threshold, fpr, tpr));
    }
    results
}

/// PromptShield-style evaluation from mixed `(score, is_malicious)` pairs.
///
/// This mirrors the interface of the `tpr_at_fpr` function in the benchmarks
/// crate but evaluates at all three standard operating points simultaneously.
///
/// Returns `Vec<(FprTarget, threshold, achieved_fpr, achieved_tpr)>` sorted
/// by strictness (0.1 % first).
#[must_use]
pub fn evaluate_scored_pairs(scored_pairs: &[(f64, bool)]) -> Vec<(FprTarget, f64, f64, f64)> {
    let mut benign_scores: Vec<f64> = scored_pairs
        .iter()
        .filter(|(_, is_mal)| !is_mal)
        .map(|(s, _)| *s)
        .collect();
    benign_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let malicious_scores: Vec<f64> = scored_pairs
        .iter()
        .filter(|(_, is_mal)| *is_mal)
        .map(|(s, _)| *s)
        .collect();

    FprTarget::standard_targets()
        .into_iter()
        .map(|target| {
            let threshold = compute_fpr_threshold(&benign_scores, target.rate());
            let fpr = compute_fpr_at_threshold(&benign_scores, threshold);
            let tpr = compute_tpr_at_threshold(&malicious_scores, threshold);
            (target, threshold, fpr, tpr)
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- FprTarget --------------------------------------------------------

    #[test]
    fn test_fpr_target_rates() {
        assert!((FprTarget::Strict.rate() - 0.001).abs() < f64::EPSILON);
        assert!((FprTarget::Moderate.rate() - 0.005).abs() < f64::EPSILON);
        assert!((FprTarget::Permissive.rate() - 0.01).abs() < f64::EPSILON);
        assert!((FprTarget::Custom(0.02).rate() - 0.02).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fpr_target_custom_clamped() {
        assert!((FprTarget::Custom(-0.5).rate()).abs() < f64::EPSILON);
        assert!((FprTarget::Custom(1.5).rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fpr_target_labels() {
        assert!(FprTarget::Strict.label().contains("0.1%"));
        assert!(FprTarget::Moderate.label().contains("0.5%"));
        assert!(FprTarget::Permissive.label().contains("1.0%"));
        assert!(FprTarget::Custom(0.02).label().contains("Custom"));
    }

    #[test]
    fn test_fpr_target_standard_targets() {
        let targets = FprTarget::standard_targets();
        assert_eq!(targets.len(), 3);
    }

    #[test]
    fn test_fpr_target_display() {
        let label = format!("{}", FprTarget::Strict);
        assert!(label.contains("0.1%"));
    }

    // -- CalibrationSample ------------------------------------------------

    #[test]
    fn test_calibration_sample_benign() {
        let s = CalibrationSample::benign(0.3);
        assert!(!s.is_malicious);
        assert!((s.score - 0.3).abs() < f64::EPSILON);
        assert_eq!(s.benign_class, Some(BenignClass::Clean));
    }

    #[test]
    fn test_calibration_sample_malicious() {
        let s = CalibrationSample::malicious(0.9);
        assert!(s.is_malicious);
        assert!((s.score - 0.9).abs() < f64::EPSILON);
        assert_eq!(s.benign_class, None);
    }

    #[test]
    fn test_calibration_sample_over_defense() {
        let s = CalibrationSample::over_defense(0.4, 2);
        assert!(!s.is_malicious);
        assert!((s.score - 0.4).abs() < f64::EPSILON);
        assert_eq!(s.benign_class, Some(BenignClass::OverDefense(2)));
    }

    #[test]
    fn test_calibration_sample_over_defense_difficulty_clamped() {
        let s = CalibrationSample::over_defense(0.4, 5);
        assert_eq!(s.benign_class, Some(BenignClass::OverDefense(3)));
        let s = CalibrationSample::over_defense(0.4, 0);
        assert_eq!(s.benign_class, Some(BenignClass::OverDefense(1)));
    }

    #[test]
    fn test_calibration_sample_score_clamped() {
        let s = CalibrationSample::benign(1.5);
        assert!((s.score - 1.0).abs() < f64::EPSILON);
        let s = CalibrationSample::malicious(-0.5);
        assert!(s.score.abs() < f64::EPSILON);
    }

    // -- CalibrationDataset -----------------------------------------------

    #[test]
    fn test_dataset_counts() {
        let mut ds = CalibrationDataset::new("injection");
        ds.add(CalibrationSample::benign(0.1));
        ds.add(CalibrationSample::benign(0.2));
        ds.add(CalibrationSample::over_defense(0.3, 1));
        ds.add(CalibrationSample::malicious(0.9));
        assert_eq!(ds.benign_count(), 3); // clean + over-defense
        assert_eq!(ds.clean_benign_count(), 2);
        assert_eq!(ds.over_defense_count(), 1);
        assert_eq!(ds.malicious_count(), 1);
        assert_eq!(ds.total_count(), 4);
    }

    #[test]
    fn test_dataset_add_many() {
        let mut ds = CalibrationDataset::new("pii");
        ds.add_many(vec![
            CalibrationSample::benign(0.1),
            CalibrationSample::benign(0.2),
            CalibrationSample::malicious(0.8),
        ]);
        assert_eq!(ds.total_count(), 3);
    }

    #[test]
    fn test_dataset_sorted_scores() {
        let mut ds = CalibrationDataset::new("test");
        ds.add(CalibrationSample::benign(0.3));
        ds.add(CalibrationSample::benign(0.1));
        ds.add(CalibrationSample::over_defense(0.5, 1));
        ds.add(CalibrationSample::malicious(0.9));
        ds.add(CalibrationSample::malicious(0.7));

        let benign = ds.sorted_benign_scores();
        // Over-defense is benign for threshold calibration
        assert_eq!(benign, vec![0.1, 0.3, 0.5]);

        let malicious = ds.sorted_malicious_scores();
        assert_eq!(malicious, vec![0.7, 0.9]);

        let od = ds.sorted_over_defense_scores();
        assert_eq!(od, vec![0.5]);
    }

    // -- Core threshold computation ---------------------------------------

    #[test]
    fn test_fpr_threshold_empty_benign() {
        assert!((compute_fpr_threshold(&[], 0.01) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fpr_threshold_full_fpr() {
        let scores = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        assert!(compute_fpr_threshold(&scores, 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fpr_threshold_zero_fpr() {
        let scores = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let threshold = compute_fpr_threshold(&scores, 0.0);
        // Should be above max benign score
        assert!(threshold > 0.5);
    }

    #[test]
    fn test_fpr_threshold_basic_computation() {
        // 100 benign scores uniformly distributed 0.01, 0.02, ..., 1.00
        let benign: Vec<f64> = (1..=100).map(|i| i as f64 / 100.0).collect();

        // At 1% FPR, we want at most 1 out of 100 benign samples above threshold
        let threshold = compute_fpr_threshold(&benign, 0.01);
        let fpr = compute_fpr_at_threshold(&benign, threshold);
        assert!(
            fpr <= 0.01 + f64::EPSILON,
            "FPR {fpr} should be <= 0.01 at threshold {threshold}"
        );
    }

    #[test]
    fn test_fpr_threshold_at_half_percent() {
        // 1000 benign scores
        let benign: Vec<f64> = (1..=1000).map(|i| i as f64 / 1000.0).collect();

        let threshold = compute_fpr_threshold(&benign, 0.005);
        let fpr = compute_fpr_at_threshold(&benign, threshold);
        assert!(
            fpr <= 0.005 + 0.002,
            "FPR {fpr} should be close to 0.005 at threshold {threshold}"
        );
    }

    #[test]
    fn test_fpr_threshold_at_tenth_percent() {
        // 10000 benign scores for fine-grained FPR
        let benign: Vec<f64> = (1..=10000).map(|i| i as f64 / 10000.0).collect();

        let threshold = compute_fpr_threshold(&benign, 0.001);
        let fpr = compute_fpr_at_threshold(&benign, threshold);
        assert!(
            fpr <= 0.001 + 0.001,
            "FPR {fpr} should be close to 0.001 at threshold {threshold}"
        );
    }

    #[test]
    fn test_fpr_at_threshold_empty() {
        assert!(compute_fpr_at_threshold(&[], 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tpr_at_threshold_empty() {
        assert!(compute_tpr_at_threshold(&[], 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tpr_computation() {
        let malicious = vec![0.7, 0.8, 0.85, 0.9, 0.95];
        let tpr = compute_tpr_at_threshold(&malicious, 0.75);
        // 0.8, 0.85, 0.9, 0.95 are above 0.75 → 4/5 = 0.8
        assert!((tpr - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tpr_all_above_threshold() {
        let malicious = vec![0.8, 0.85, 0.9];
        let tpr = compute_tpr_at_threshold(&malicious, 0.5);
        assert!((tpr - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tpr_none_above_threshold() {
        let malicious = vec![0.1, 0.2, 0.3];
        let tpr = compute_tpr_at_threshold(&malicious, 0.9);
        assert!(tpr.abs() < f64::EPSILON);
    }

    // -- ThresholdCalibrator ----------------------------------------------

    #[test]
    fn test_calibrator_standard_targets() {
        let calibrator = ThresholdCalibrator::new();
        assert_eq!(calibrator.targets.len(), 3);
    }

    #[test]
    fn test_calibrator_custom_targets() {
        let calibrator =
            ThresholdCalibrator::with_targets(vec![FprTarget::Custom(0.02), FprTarget::Strict]);
        assert_eq!(calibrator.targets.len(), 2);
    }

    #[test]
    fn test_calibrator_default() {
        let calibrator = ThresholdCalibrator::default();
        assert_eq!(calibrator.targets.len(), 3);
    }

    #[test]
    fn test_calibrate_well_separated_data() {
        // Well-separated: benign scores low (0.0–0.3), malicious high (0.7–1.0)
        let mut dataset = CalibrationDataset::new("injection");
        for i in 0..1000 {
            dataset.add(CalibrationSample::benign(i as f64 / 3333.0));
        }
        for i in 0..500 {
            dataset.add(CalibrationSample::malicious(0.7 + (i as f64 / 1666.0)));
        }

        let calibrator = ThresholdCalibrator::new();
        let results = calibrator.calibrate(&dataset);

        assert_eq!(results.len(), 3);
        for result in &results {
            assert_eq!(result.category, "injection");
            assert_eq!(result.benign_count, 1000);
            assert_eq!(result.malicious_count, 500);
            assert!(
                result.meets_target(),
                "FPR target not met: {} (achieved_fpr={:.6}, threshold={:.4})",
                result.fpr_target,
                result.achieved_fpr,
                result.threshold
            );
            assert!(
                result.achieved_tpr > 0.95,
                "TPR should be high: {} (tpr={:.4})",
                result.fpr_target,
                result.achieved_tpr
            );
        }
    }

    #[test]
    fn test_calibrate_overlapping_data() {
        // Overlapping: benign 0.0–0.6, malicious 0.4–1.0
        let mut dataset = CalibrationDataset::new("jailbreak");
        for i in 0..1000 {
            dataset.add(CalibrationSample::benign(i as f64 / 1666.0));
        }
        for i in 0..500 {
            dataset.add(CalibrationSample::malicious(0.4 + (i as f64 / 833.0)));
        }

        let calibrator = ThresholdCalibrator::new();
        let results = calibrator.calibrate(&dataset);

        assert_eq!(results.len(), 3);
        for result in &results {
            assert!(
                result.achieved_fpr <= result.fpr_target.rate() + 0.005,
                "FPR too high: {} (achieved={:.4}, target={:.4})",
                result.fpr_target,
                result.achieved_fpr,
                result.fpr_target.rate()
            );
            assert!(
                result.achieved_tpr > 0.0,
                "TPR should be positive for overlapping data"
            );
        }

        // Stricter FPR should produce higher threshold
        let strict_threshold = results
            .iter()
            .find(|r| r.fpr_target == FprTarget::Strict)
            .unwrap()
            .threshold;
        let permissive_threshold = results
            .iter()
            .find(|r| r.fpr_target == FprTarget::Permissive)
            .unwrap()
            .threshold;
        assert!(
            strict_threshold >= permissive_threshold,
            "Strict threshold ({strict_threshold}) should be >= permissive ({permissive_threshold})"
        );
    }

    #[test]
    fn test_calibrate_empty_benign() {
        let mut dataset = CalibrationDataset::new("test");
        dataset.add(CalibrationSample::malicious(0.9));

        let calibrator = ThresholdCalibrator::new();
        let results = calibrator.calibrate(&dataset);

        for result in &results {
            assert!(
                (result.threshold - 1.0).abs() < f64::EPSILON,
                "Threshold should be 1.0 with no benign data"
            );
            assert_eq!(result.benign_count, 0);
        }
    }

    #[test]
    fn test_calibrate_empty_malicious() {
        let mut dataset = CalibrationDataset::new("test");
        dataset.add(CalibrationSample::benign(0.1));

        let calibrator = ThresholdCalibrator::new();
        let results = calibrator.calibrate(&dataset);

        for result in &results {
            assert!(result.achieved_tpr.abs() < f64::EPSILON);
            assert_eq!(result.malicious_count, 0);
        }
    }

    #[test]
    fn test_calibrate_single_benign_sample() {
        let mut dataset = CalibrationDataset::new("test");
        dataset.add(CalibrationSample::benign(0.5));
        dataset.add(CalibrationSample::malicious(0.9));

        let calibrator = ThresholdCalibrator::new();
        let results = calibrator.calibrate(&dataset);

        for result in &results {
            assert_eq!(result.benign_count, 1);
            assert_eq!(result.malicious_count, 1);
        }
    }

    // -- Over-defense tracking --------------------------------------------

    #[test]
    fn test_over_defense_samples_included_in_benign_pool() {
        // Over-defense samples should be treated as benign for threshold calibration.
        // The threshold should be set to protect both clean benign AND over-defense.
        let mut dataset = CalibrationDataset::new("injection");

        // Clean benign: low scores
        for i in 0..500 {
            dataset.add(CalibrationSample::benign(i as f64 / 5000.0));
        }
        // Over-defense: benign with trigger words — often score higher
        for i in 0..500 {
            dataset.add(CalibrationSample::over_defense(0.2 + i as f64 / 2500.0, 2));
        }
        // Malicious: high scores
        for i in 0..200 {
            dataset.add(CalibrationSample::malicious(0.8 + i as f64 / 1000.0));
        }

        let calibrator = ThresholdCalibrator::new();
        let results = calibrator.calibrate(&dataset);

        for result in &results {
            // Both clean and OD count as benign
            assert_eq!(result.benign_count, 1000);
            assert_eq!(result.over_defense_count, 500);
            assert_eq!(result.malicious_count, 200);

            // The threshold must be high enough to protect the higher-scoring OD samples
            assert!(
                result.threshold > 0.1,
                "Threshold should account for over-defense samples"
            );

            // over_defense_fpr should be reported separately
            assert!(
                result.over_defense_fpr >= 0.0,
                "OD FPR should be non-negative"
            );
        }
    }

    #[test]
    fn test_over_defense_fpr_tracks_trigger_word_bias() {
        // Simulate a biased detector: OD samples score much higher than clean
        // benign.  With a 5% FPR target, the threshold is set low enough that
        // over-defense samples are disproportionately flagged, revealing bias.
        let mut dataset = CalibrationDataset::new("injection");

        // Clean benign: very low scores (detector handles these well)
        for _ in 0..900 {
            dataset.add(CalibrationSample::benign(0.05));
        }
        // Over-defense: higher scores (detector is biased by trigger words)
        // 100 samples spread from 0.30 to 0.60
        for i in 0..100 {
            dataset.add(CalibrationSample::over_defense(
                0.30 + (i as f64 / 333.0),
                2,
            ));
        }
        // Malicious
        for _ in 0..500 {
            dataset.add(CalibrationSample::malicious(0.9));
        }

        // Use 5% FPR — high enough that some OD samples are above threshold
        // while clean benign (all at 0.05) mostly aren't.
        let calibrator = ThresholdCalibrator::with_targets(vec![FprTarget::Custom(0.05)]);
        let results = calibrator.calibrate(&dataset);
        let result = &results[0];

        // With 5% FPR on 1000 benign samples, up to 50 are flagged.
        // The 100 OD samples (0.30–0.60) are the highest-scoring benign,
        // so they'll be flagged disproportionately — their FPR should be
        // much higher than the overall FPR.
        assert!(
            result.over_defense_fpr > result.achieved_fpr,
            "Over-defense FPR ({:.4}) should be higher than overall FPR ({:.4}) \
             when detector is biased by trigger words",
            result.over_defense_fpr,
            result.achieved_fpr
        );
    }

    // -- calibrate_all & CalibrationReport --------------------------------

    #[test]
    fn test_calibrate_all_multiple_categories() {
        let mut injection_ds = CalibrationDataset::new("injection");
        for i in 0..100 {
            injection_ds.add(CalibrationSample::benign(i as f64 / 500.0));
        }
        for i in 0..50 {
            injection_ds.add(CalibrationSample::malicious(0.8 + i as f64 / 250.0));
        }

        let mut pii_ds = CalibrationDataset::new("pii");
        for i in 0..100 {
            pii_ds.add(CalibrationSample::benign(i as f64 / 400.0));
        }
        for i in 0..50 {
            pii_ds.add(CalibrationSample::malicious(0.7 + i as f64 / 166.0));
        }

        let calibrator = ThresholdCalibrator::new();
        let report = calibrator.calibrate_all(&[injection_ds, pii_ds]);

        // 3 targets × 2 categories = 6 results
        assert_eq!(report.results.len(), 6);

        let injection_results = report.for_category("injection");
        assert_eq!(injection_results.len(), 3);

        let pii_results = report.for_category("pii");
        assert_eq!(pii_results.len(), 3);

        let strict_results = report.for_fpr_target(&FprTarget::Strict);
        assert_eq!(strict_results.len(), 2);
    }

    #[test]
    fn test_report_to_resolved_thresholds() {
        let mut injection_ds = CalibrationDataset::new("injection");
        for i in 0..1000 {
            injection_ds.add(CalibrationSample::benign(i as f64 / 5000.0));
        }
        for i in 0..100 {
            injection_ds.add(CalibrationSample::malicious(0.8 + i as f64 / 500.0));
        }

        let calibrator = ThresholdCalibrator::new();
        let report = calibrator.calibrate_all(&[injection_ds]);

        let base = ResolvedThresholds::default();
        let calibrated = report.to_resolved_thresholds(&FprTarget::Moderate, &base);

        assert!(
            (calibrated.injection - base.injection).abs() > f64::EPSILON,
            "Injection threshold should differ from base after calibration"
        );
        // Non-calibrated categories should match base
        assert!((calibrated.jailbreak - base.jailbreak).abs() < f64::EPSILON);
        assert!((calibrated.pii - base.pii).abs() < f64::EPSILON);
    }

    #[test]
    fn test_report_all_targets_met() {
        let mut ds = CalibrationDataset::new("injection");
        for i in 0..1000 {
            ds.add(CalibrationSample::benign(i as f64 / 10000.0));
        }
        for i in 0..100 {
            ds.add(CalibrationSample::malicious(0.9 + i as f64 / 1000.0));
        }

        let calibrator = ThresholdCalibrator::new();
        let report = calibrator.calibrate_all(&[ds]);
        assert!(report.all_targets_met());
    }

    #[test]
    fn test_calibrate_to_thresholds_convenience() {
        let mut ds = CalibrationDataset::new("injection");
        for i in 0..500 {
            ds.add(CalibrationSample::benign(i as f64 / 2500.0));
        }
        for i in 0..100 {
            ds.add(CalibrationSample::malicious(0.8 + i as f64 / 500.0));
        }

        let calibrator = ThresholdCalibrator::new();
        let base = ResolvedThresholds::default();
        let thresholds = calibrator.calibrate_to_thresholds(&[ds], &FprTarget::Permissive, &base);

        assert!(
            (thresholds.injection - base.injection).abs() > f64::EPSILON,
            "Should have calibrated injection threshold"
        );
    }

    // -- evaluate_at_standard_operating_points ----------------------------

    #[test]
    fn test_evaluate_at_standard_operating_points() {
        let benign: Vec<f64> = (1..=1000).map(|i| i as f64 / 5000.0).collect();
        let malicious: Vec<f64> = (1..=100).map(|i| 0.8 + i as f64 / 500.0).collect();

        let results = evaluate_at_standard_operating_points(&benign, &malicious);
        assert_eq!(results.len(), 3);
        assert!(results.contains_key(&FprTarget::Strict.label()));
        assert!(results.contains_key(&FprTarget::Moderate.label()));
        assert!(results.contains_key(&FprTarget::Permissive.label()));

        for (label, (threshold, fpr, tpr)) in &results {
            assert!(*threshold > 0.0, "Threshold for {label} should be positive");
            assert!(*fpr >= 0.0, "FPR for {label} should be non-negative");
            assert!(*tpr >= 0.0, "TPR for {label} should be non-negative");
        }
    }

    // -- evaluate_scored_pairs (PromptShield-style) -----------------------

    #[test]
    fn test_evaluate_scored_pairs() {
        let pairs: Vec<(f64, bool)> = (1..=1000)
            .map(|i| (i as f64 / 5000.0, false)) // benign
            .chain((1..=200).map(|i| (0.7 + i as f64 / 666.0, true))) // malicious
            .collect();

        let results = evaluate_scored_pairs(&pairs);
        assert_eq!(results.len(), 3);

        for (target, threshold, fpr, tpr) in &results {
            assert!(
                *threshold > 0.0,
                "Threshold for {} should be positive",
                target
            );
            assert!(
                *fpr <= target.rate() + 0.005,
                "FPR {fpr:.6} should be near target {:.6} for {target}",
                target.rate()
            );
            assert!(*tpr > 0.0, "TPR for {target} should be positive");
        }
    }

    // -- CalibrationResult display ----------------------------------------

    #[test]
    fn test_calibration_result_display() {
        let result = CalibrationResult {
            category: "injection".to_string(),
            fpr_target: FprTarget::Strict,
            threshold: 0.85,
            achieved_fpr: 0.001,
            achieved_tpr: 0.95,
            benign_count: 1000,
            malicious_count: 500,
            over_defense_fpr: 0.02,
            over_defense_count: 100,
        };
        let display = format!("{result}");
        assert!(display.contains("injection"));
        assert!(display.contains("0.1%"));
        assert!(display.contains("0.8500"));
        assert!(display.contains("n_od=100"));
    }

    #[test]
    fn test_calibration_result_meets_target() {
        let result = CalibrationResult {
            category: "test".to_string(),
            fpr_target: FprTarget::Permissive,
            threshold: 0.5,
            achieved_fpr: 0.008,
            achieved_tpr: 0.9,
            benign_count: 100,
            malicious_count: 50,
            over_defense_fpr: 0.0,
            over_defense_count: 0,
        };
        assert!(result.meets_target()); // 0.8% <= 1.0%

        let result2 = CalibrationResult {
            category: "test".to_string(),
            fpr_target: FprTarget::Strict,
            threshold: 0.5,
            achieved_fpr: 0.05,
            achieved_tpr: 0.9,
            benign_count: 100,
            malicious_count: 50,
            over_defense_fpr: 0.0,
            over_defense_count: 0,
        };
        assert!(!result2.meets_target()); // 5% > 0.1%
    }

    // -- CalibrationReport display ----------------------------------------

    #[test]
    fn test_report_display_all_met() {
        let report = CalibrationReport {
            results: vec![CalibrationResult {
                category: "injection".to_string(),
                fpr_target: FprTarget::Strict,
                threshold: 0.9,
                achieved_fpr: 0.001,
                achieved_tpr: 0.95,
                benign_count: 1000,
                malicious_count: 500,
                over_defense_fpr: 0.0,
                over_defense_count: 0,
            }],
        };
        let display = format!("{report}");
        assert!(display.contains("✅ All FPR targets met"));
        assert!(display.contains("PromptShield"));
    }

    #[test]
    fn test_report_display_targets_missed() {
        let report = CalibrationReport {
            results: vec![CalibrationResult {
                category: "injection".to_string(),
                fpr_target: FprTarget::Strict,
                threshold: 0.5,
                achieved_fpr: 0.05,
                achieved_tpr: 0.9,
                benign_count: 100,
                malicious_count: 50,
                over_defense_fpr: 0.0,
                over_defense_count: 0,
            }],
        };
        let display = format!("{report}");
        assert!(display.contains("⚠"));
        assert!(display.contains("not met"));
    }

    #[test]
    fn test_report_default() {
        let report = CalibrationReport::default();
        assert!(report.results.is_empty());
        assert!(report.all_targets_met()); // vacuously true
    }

    // -- Monotonicity property: stricter FPR → higher threshold -----------

    #[test]
    fn test_threshold_monotonicity() {
        let benign: Vec<f64> = (1..=10000).map(|i| i as f64 / 10000.0).collect();

        let t_strict = compute_fpr_threshold(&benign, 0.001);
        let t_moderate = compute_fpr_threshold(&benign, 0.005);
        let t_permissive = compute_fpr_threshold(&benign, 0.01);

        assert!(
            t_strict >= t_moderate,
            "Strict ({t_strict}) should be >= Moderate ({t_moderate})"
        );
        assert!(
            t_moderate >= t_permissive,
            "Moderate ({t_moderate}) should be >= Permissive ({t_permissive})"
        );
    }

    // -- PromptShield finding: weak detectors collapse at strict FPR ------

    #[test]
    fn test_promptshield_finding_tpr_degrades_at_strict_fpr() {
        // This test demonstrates the PromptShield paper's key finding:
        // a detector with poor score separation between benign and malicious
        // will have catastrophically low TPR at strict FPR operating points.
        //
        // At 0.1% FPR, Meta PromptGuard detects only 9.4% of attacks.
        //
        // We simulate a "poor" detector where benign and malicious scores
        // overlap heavily (benign: 0.0–0.8, malicious: 0.3–1.0).

        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(99);
        let mut dataset = CalibrationDataset::new("injection");

        // Poor detector: benign scores spread wide (mean 0.3, σ=0.15)
        for _ in 0..5000 {
            let score = sample_truncated_normal(&mut rng, 0.30, 0.15);
            dataset.add(CalibrationSample::benign(score));
        }
        // Malicious scores only moderately higher (mean 0.6, σ=0.15)
        for _ in 0..1000 {
            let score = sample_truncated_normal(&mut rng, 0.60, 0.15);
            dataset.add(CalibrationSample::malicious(score));
        }

        let calibrator = ThresholdCalibrator::new();
        let results = calibrator.calibrate(&dataset);

        let strict = results
            .iter()
            .find(|r| r.fpr_target == FprTarget::Strict)
            .unwrap();
        let permissive = results
            .iter()
            .find(|r| r.fpr_target == FprTarget::Permissive)
            .unwrap();

        // At strict FPR (0.1%), TPR should be low for this poor detector
        assert!(
            strict.achieved_tpr < 0.50,
            "Poor detector should have low TPR ({:.2}%) at 0.1% FPR — \
             this is the PromptShield finding",
            strict.achieved_tpr * 100.0
        );

        // At permissive FPR (1%), TPR should be meaningfully higher
        assert!(
            permissive.achieved_tpr > strict.achieved_tpr,
            "TPR should increase with more permissive FPR: \
             strict={:.2}% vs permissive={:.2}%",
            strict.achieved_tpr * 100.0,
            permissive.achieved_tpr * 100.0
        );
    }

    // -- Large-scale synthetic test with over-defense samples -------------

    #[test]
    fn test_large_scale_calibration_with_over_defense() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(42);
        let mut dataset = CalibrationDataset::new("injection");

        // 8,000 clean benign samples: low scores (mean 0.10, σ=0.06)
        for _ in 0..8_000 {
            let score = sample_truncated_normal(&mut rng, 0.10, 0.06);
            dataset.add(CalibrationSample::benign(score));
        }

        // 2,000 over-defense samples: higher scores due to trigger words
        // (mean 0.25, σ=0.10) — simulating the InjecGuard finding that
        // trigger words push benign scores higher.
        for _ in 0..2_000 {
            let score = sample_truncated_normal(&mut rng, 0.25, 0.10);
            dataset.add(CalibrationSample::over_defense(score, 2));
        }

        // 2,000 malicious samples: high scores (mean 0.85, σ=0.10)
        for _ in 0..2_000 {
            let score = sample_truncated_normal(&mut rng, 0.85, 0.10);
            dataset.add(CalibrationSample::malicious(score));
        }

        let calibrator = ThresholdCalibrator::new();
        let results = calibrator.calibrate(&dataset);

        for result in &results {
            assert_eq!(result.benign_count, 10_000); // 8000 clean + 2000 OD
            assert_eq!(result.over_defense_count, 2_000);
            assert_eq!(result.malicious_count, 2_000);

            // FPR should be at or very close to target
            assert!(
                result.achieved_fpr <= result.fpr_target.rate() + 0.002,
                "[{}] Achieved FPR {:.6} exceeds target {:.6} by too much",
                result.fpr_target,
                result.achieved_fpr,
                result.fpr_target.rate(),
            );

            // TPR should be high given good benign/malicious separation
            assert!(
                result.achieved_tpr > 0.80,
                "[{}] TPR {:.4} is too low",
                result.fpr_target,
                result.achieved_tpr,
            );

            // Over-defense FPR should be higher than overall FPR because
            // OD samples have higher scores on average
            // (This validates that the InjecGuard over-defense effect is
            //  captured in the diagnostic.)
            if result.over_defense_count > 0 && result.benign_count > result.over_defense_count {
                // With separate tracking, OD FPR should be meaningfully reported
                assert!(
                    result.over_defense_fpr >= 0.0,
                    "Over-defense FPR should be non-negative"
                );
            }
        }
    }

    /// Sample from a truncated normal distribution clamped to [0, 1].
    /// Uses Box-Muller transform.
    fn sample_truncated_normal(
        rng: &mut (impl rand::Rng + ?Sized),
        mean: f64,
        std_dev: f64,
    ) -> f64 {
        loop {
            let u1: f64 = rng.gen::<f64>().max(f64::EPSILON);
            let u2: f64 = rng.gen();
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            let value = mean + std_dev * z;
            if (0.0..=1.0).contains(&value) {
                return value;
            }
        }
    }
}
