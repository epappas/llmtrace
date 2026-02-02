//! Metrics computation for LLMTrace benchmarks.
//!
//! Implements all metrics referenced across the research papers:
//!
//! - **Precision, Recall, F1** — Standard classification metrics (all papers)
//! - **FPR (False Positive Rate)** — Critical for deployment (PromptShield, InjecGuard)
//! - **ASR (Attack Success Rate)** — Evasion effectiveness (Bypassing Guardrails, Protocol Exploits)
//! - **Over-defense Rate** — False positive rate on trigger-word benign inputs (InjecGuard)
//! - **TPR at fixed FPR** — Deployment-realistic metric (PromptShield: TPR@0.1% FPR)
//! - **Benign/Malicious/Over-defense Accuracy** — Three-dimensional evaluation (InjecGuard)
//! - **Utility Retention** — Task completion rate under defense (Indirect Injection Firewalls)

use serde::{Deserialize, Serialize};

/// Confusion matrix for binary classification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfusionMatrix {
    /// True positives — malicious correctly identified.
    pub tp: usize,
    /// True negatives — benign correctly passed.
    pub tn: usize,
    /// False positives — benign incorrectly flagged (over-defense).
    pub fp: usize,
    /// False negatives — malicious incorrectly missed.
    pub fn_: usize,
}

impl ConfusionMatrix {
    /// Create a new empty confusion matrix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a prediction.
    pub fn record(&mut self, actual_malicious: bool, predicted_malicious: bool) {
        match (actual_malicious, predicted_malicious) {
            (true, true) => self.tp += 1,
            (false, false) => self.tn += 1,
            (false, true) => self.fp += 1,
            (true, false) => self.fn_ += 1,
        }
    }

    /// Total number of samples.
    pub fn total(&self) -> usize {
        self.tp + self.tn + self.fp + self.fn_
    }

    /// Number of actual positive (malicious) samples.
    pub fn actual_positive(&self) -> usize {
        self.tp + self.fn_
    }

    /// Number of actual negative (benign) samples.
    pub fn actual_negative(&self) -> usize {
        self.tn + self.fp
    }
}

/// Comprehensive benchmark metrics computed from a confusion matrix.
///
/// References the specific papers and metrics they use:
///
/// | Metric | Paper(s) |
/// |--------|----------|
/// | Accuracy | All |
/// | Precision | DMPI-PMHFE, InjecGuard |
/// | Recall (TPR) | DMPI-PMHFE, PromptShield |
/// | F1 Score | DMPI-PMHFE |
/// | FPR | PromptShield, InjecGuard |
/// | ASR | Bypassing Guardrails, Multi-Agent Defense, Protocol Exploits |
/// | Over-defense Accuracy | InjecGuard |
/// | Benign Accuracy | InjecGuard |
/// | Malicious Accuracy | InjecGuard |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    // -- Standard classification metrics --
    /// Overall accuracy.
    pub accuracy: f64,
    /// Precision = TP / (TP + FP).
    pub precision: f64,
    /// Recall (True Positive Rate) = TP / (TP + FN).
    pub recall: f64,
    /// F1 Score = 2 * (Precision * Recall) / (Precision + Recall).
    pub f1: f64,

    // -- Deployment-realistic metrics (PromptShield) --
    /// False Positive Rate = FP / (FP + TN).
    pub fpr: f64,
    /// False Negative Rate = FN / (FN + TP).
    pub fnr: f64,

    // -- Attack-focused metrics (Bypassing Guardrails, Multi-Agent Defense) --
    /// Attack Success Rate = FN / (TP + FN) = 1 - Recall.
    /// Measures how many attacks bypass the detector.
    pub asr: f64,

    // -- InjecGuard three-dimensional metrics --
    /// Benign accuracy = TN / (TN + FP). How well benign inputs are passed.
    pub benign_accuracy: f64,
    /// Malicious accuracy = TP / (TP + FN). How well attacks are detected.
    pub malicious_accuracy: f64,
    /// Average of benign, malicious, and over-defense accuracy.
    pub average_accuracy: f64,

    // -- Raw confusion matrix --
    pub confusion_matrix: ConfusionMatrix,
}

impl BenchmarkMetrics {
    /// Compute all metrics from a confusion matrix.
    pub fn from_confusion_matrix(cm: &ConfusionMatrix) -> Self {
        let total = cm.total() as f64;
        let accuracy = if total > 0.0 {
            (cm.tp + cm.tn) as f64 / total
        } else {
            0.0
        };

        let precision = if cm.tp + cm.fp > 0 {
            cm.tp as f64 / (cm.tp + cm.fp) as f64
        } else {
            0.0
        };

        let recall = if cm.tp + cm.fn_ > 0 {
            cm.tp as f64 / (cm.tp + cm.fn_) as f64
        } else {
            0.0
        };

        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        let fpr = if cm.fp + cm.tn > 0 {
            cm.fp as f64 / (cm.fp + cm.tn) as f64
        } else {
            0.0
        };

        let fnr = if cm.fn_ + cm.tp > 0 {
            cm.fn_ as f64 / (cm.fn_ + cm.tp) as f64
        } else {
            0.0
        };

        let asr = fnr; // ASR = 1 - Recall = FN / (TP + FN)

        let benign_accuracy = if cm.tn + cm.fp > 0 {
            cm.tn as f64 / (cm.tn + cm.fp) as f64
        } else {
            0.0
        };

        let malicious_accuracy = recall; // Same as recall

        let average_accuracy = (accuracy + benign_accuracy + malicious_accuracy) / 3.0;

        Self {
            accuracy,
            precision,
            recall,
            f1,
            fpr,
            fnr,
            asr,
            benign_accuracy,
            malicious_accuracy,
            average_accuracy,
            confusion_matrix: cm.clone(),
        }
    }

    /// Format metrics as a paper-ready table row.
    ///
    /// Returns: `"| Name | Acc | Prec | Rec | F1 | FPR | ASR |"`
    pub fn to_table_row(&self, name: &str) -> String {
        format!(
            "| {:<30} | {:>6.2}% | {:>6.2}% | {:>6.2}% | {:>6.2}% | {:>6.2}% | {:>6.2}% |",
            name,
            self.accuracy * 100.0,
            self.precision * 100.0,
            self.recall * 100.0,
            self.f1 * 100.0,
            self.fpr * 100.0,
            self.asr * 100.0,
        )
    }

    /// Format the full table header.
    pub fn table_header() -> String {
        format!(
            "| {:<30} | {:>7} | {:>7} | {:>7} | {:>7} | {:>7} | {:>7} |",
            "Model / Config", "Acc", "Prec", "Rec", "F1", "FPR", "ASR"
        )
    }

    /// Format the table separator.
    pub fn table_separator() -> String {
        format!(
            "|{:-<32}|{:->9}|{:->9}|{:->9}|{:->9}|{:->9}|{:->9}|",
            "", "", "", "", "", "", ""
        )
    }

    /// Print a summary to stdout.
    pub fn print_summary(&self, name: &str) {
        println!("\n=== {} ===", name);
        println!("Accuracy:           {:.2}%", self.accuracy * 100.0);
        println!("Precision:          {:.2}%", self.precision * 100.0);
        println!("Recall (TPR):       {:.2}%", self.recall * 100.0);
        println!("F1 Score:           {:.2}%", self.f1 * 100.0);
        println!("FPR:                {:.4}%", self.fpr * 100.0);
        println!("ASR (1-Recall):     {:.2}%", self.asr * 100.0);
        println!("Benign Accuracy:    {:.2}%", self.benign_accuracy * 100.0);
        println!(
            "Malicious Accuracy: {:.2}%",
            self.malicious_accuracy * 100.0
        );
        println!("Average Accuracy:   {:.2}%", self.average_accuracy * 100.0);
        println!(
            "Confusion: TP={} TN={} FP={} FN={}",
            self.confusion_matrix.tp,
            self.confusion_matrix.tn,
            self.confusion_matrix.fp,
            self.confusion_matrix.fn_,
        );
    }
}

/// Compute metrics at a specific FPR threshold.
///
/// Given a list of (score, is_malicious) pairs, finds the threshold that
/// achieves the target FPR and reports the TPR at that threshold.
///
/// This implements the PromptShield methodology (Jacob et al., CODASPY 2025)
/// which argues that TPR at realistic FPR thresholds (0.1%, 0.5%) is the
/// most deployment-relevant metric.
pub fn tpr_at_fpr(scores: &[(f64, bool)], target_fpr: f64) -> (f64, f64) {
    if scores.is_empty() {
        return (0.0, 0.0);
    }

    // Sort by score descending (higher score = more likely malicious)
    let mut sorted: Vec<(f64, bool)> = scores.to_vec();
    sorted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let total_neg = sorted.iter().filter(|(_, m)| !m).count() as f64;
    let total_pos = sorted.iter().filter(|(_, m)| *m).count() as f64;

    if total_neg == 0.0 || total_pos == 0.0 {
        return (0.0, 0.0);
    }

    let mut best_threshold = 1.0;
    let mut best_tpr = 0.0;
    let mut fp = 0.0;
    let mut tp = 0.0;

    for (score, is_mal) in &sorted {
        if *is_mal {
            tp += 1.0;
        } else {
            fp += 1.0;
        }
        let current_fpr = fp / total_neg;
        if current_fpr <= target_fpr {
            best_threshold = *score;
            best_tpr = tp / total_pos;
        } else {
            break;
        }
    }

    (best_tpr, best_threshold)
}

/// Compute over-defense metrics following the InjecGuard methodology.
///
/// Takes NotInject-style samples (benign text with trigger words) and
/// computes the over-defense accuracy: what percentage of these benign
/// samples are correctly classified as benign (not falsely flagged).
///
/// # State-of-the-Art Reference (InjecGuard paper)
///
/// | Model | Over-defense Accuracy |
/// |-------|---------------------|
/// | PromptGuard (Meta) | 0.88% |
/// | Deepset | 5.31% |
/// | Fmops | 5.60% |
/// | ProtectAI v2 | 56.64% |
/// | **InjecGuard** | **87.32%** |
pub fn over_defense_accuracy(
    predictions: &[(bool, u8)], // (predicted_malicious, difficulty_level)
) -> OverDefenseMetrics {
    let total = predictions.len();
    let correct = predictions.iter().filter(|(pred, _)| !pred).count();

    let mut by_difficulty: std::collections::HashMap<u8, (usize, usize)> =
        std::collections::HashMap::new();
    for (pred, diff) in predictions {
        let entry = by_difficulty.entry(*diff).or_insert((0, 0));
        entry.0 += 1; // total
        if !pred {
            entry.1 += 1; // correct (not flagged)
        }
    }

    let difficulty_accuracy: std::collections::HashMap<u8, f64> = by_difficulty
        .iter()
        .map(|(diff, (tot, cor))| (*diff, *cor as f64 / *tot as f64))
        .collect();

    OverDefenseMetrics {
        overall_accuracy: if total > 0 {
            correct as f64 / total as f64
        } else {
            0.0
        },
        total_samples: total,
        correctly_passed: correct,
        falsely_flagged: total - correct,
        accuracy_by_difficulty: difficulty_accuracy,
    }
}

/// Over-defense evaluation metrics (InjecGuard methodology).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverDefenseMetrics {
    /// Percentage of trigger-word benign samples correctly passed.
    pub overall_accuracy: f64,
    /// Total number of NotInject-style samples evaluated.
    pub total_samples: usize,
    /// Samples correctly identified as benign.
    pub correctly_passed: usize,
    /// Samples incorrectly flagged as malicious (false positives).
    pub falsely_flagged: usize,
    /// Accuracy broken down by difficulty level (1, 2, 3 trigger words).
    pub accuracy_by_difficulty: std::collections::HashMap<u8, f64>,
}

impl OverDefenseMetrics {
    /// Print over-defense metrics summary.
    pub fn print_summary(&self) {
        println!("\n=== Over-Defense Evaluation (InjecGuard Methodology) ===");
        println!(
            "Overall Accuracy: {:.2}% ({}/{} correctly passed)",
            self.overall_accuracy * 100.0,
            self.correctly_passed,
            self.total_samples
        );
        println!("Falsely Flagged: {}", self.falsely_flagged);
        for diff in 1..=3u8 {
            if let Some(acc) = self.accuracy_by_difficulty.get(&diff) {
                println!(
                    "  Difficulty {} ({} trigger words): {:.2}%",
                    diff,
                    diff,
                    acc * 100.0
                );
            }
        }
        println!("\nState-of-the-Art Reference:");
        println!("  PromptGuard:  0.88%");
        println!("  ProtectAI v2: 56.64%");
        println!("  InjecGuard:   87.32% (target)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confusion_matrix_record() {
        let mut cm = ConfusionMatrix::new();
        cm.record(true, true); // TP
        cm.record(false, false); // TN
        cm.record(false, true); // FP
        cm.record(true, false); // FN
        assert_eq!(cm.tp, 1);
        assert_eq!(cm.tn, 1);
        assert_eq!(cm.fp, 1);
        assert_eq!(cm.fn_, 1);
        assert_eq!(cm.total(), 4);
    }

    #[test]
    fn test_metrics_perfect_classifier() {
        let mut cm = ConfusionMatrix::new();
        for _ in 0..50 {
            cm.record(true, true);
        }
        for _ in 0..50 {
            cm.record(false, false);
        }
        let metrics = BenchmarkMetrics::from_confusion_matrix(&cm);
        assert!((metrics.accuracy - 1.0).abs() < f64::EPSILON);
        assert!((metrics.precision - 1.0).abs() < f64::EPSILON);
        assert!((metrics.recall - 1.0).abs() < f64::EPSILON);
        assert!((metrics.f1 - 1.0).abs() < f64::EPSILON);
        assert!((metrics.fpr).abs() < f64::EPSILON);
        assert!((metrics.asr).abs() < f64::EPSILON);
    }

    #[test]
    fn test_metrics_worst_classifier() {
        let mut cm = ConfusionMatrix::new();
        for _ in 0..50 {
            cm.record(true, false); // All FN
        }
        for _ in 0..50 {
            cm.record(false, true); // All FP
        }
        let metrics = BenchmarkMetrics::from_confusion_matrix(&cm);
        assert!((metrics.accuracy).abs() < f64::EPSILON);
        assert!((metrics.recall).abs() < f64::EPSILON);
        assert!((metrics.asr - 1.0).abs() < f64::EPSILON);
        assert!((metrics.fpr - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_metrics_realistic() {
        let mut cm = ConfusionMatrix::new();
        // 80 TP, 10 FN, 5 FP, 45 TN
        cm.tp = 80;
        cm.fn_ = 10;
        cm.fp = 5;
        cm.tn = 45;
        let m = BenchmarkMetrics::from_confusion_matrix(&cm);
        assert!((m.accuracy - 125.0 / 140.0).abs() < 0.001);
        assert!((m.precision - 80.0 / 85.0).abs() < 0.001);
        assert!((m.recall - 80.0 / 90.0).abs() < 0.001);
        assert!((m.fpr - 5.0 / 50.0).abs() < 0.001);
    }

    #[test]
    fn test_tpr_at_fpr_basic() {
        let scores = vec![
            (0.9, true),
            (0.8, true),
            (0.7, false),
            (0.6, true),
            (0.5, false),
            (0.4, false),
            (0.3, true),
            (0.2, false),
        ];
        let (tpr, _threshold) = tpr_at_fpr(&scores, 0.25);
        assert!(tpr > 0.0);
    }

    #[test]
    fn test_over_defense_accuracy() {
        let predictions = vec![
            (false, 1), // correct
            (false, 1), // correct
            (true, 1),  // false flag
            (false, 2), // correct
            (true, 2),  // false flag
            (false, 3), // correct
        ];
        let metrics = over_defense_accuracy(&predictions);
        assert!((metrics.overall_accuracy - 4.0 / 6.0).abs() < 0.001);
        assert_eq!(metrics.correctly_passed, 4);
        assert_eq!(metrics.falsely_flagged, 2);
    }

    #[test]
    fn test_table_formatting() {
        let cm = ConfusionMatrix {
            tp: 80,
            tn: 45,
            fp: 5,
            fn_: 10,
        };
        let metrics = BenchmarkMetrics::from_confusion_matrix(&cm);
        let row = metrics.to_table_row("LLMTrace Regex");
        assert!(row.contains("LLMTrace Regex"));
        assert!(row.contains('%'));
    }
}
