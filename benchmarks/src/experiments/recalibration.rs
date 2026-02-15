//! Streaming-aware fusion weight re-calibration.
//!
//! Loads per-sample raw scores from Experiment A (truncation), pivots them
//! into multi-detector score vectors, and trains a logistic regression at
//! each truncation level. Compares the per-level "streaming-aware" model
//! against a "naive" model trained only on full-text (100%) data.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::time::Instant;

use crate::metrics::{BenchmarkMetrics, ConfusionMatrix};

use super::types::{
    LearnedWeights, RecalibrationExperimentResult, RecalibrationLevelResult, RecalibrationMetrics,
    TruncationExperimentResult, TruncationSampleResult,
};

// ---------------------------------------------------------------------------
// Logistic regression
// ---------------------------------------------------------------------------

/// Minimal logistic regression for combining detector scores.
pub struct LogisticRegression {
    pub weights: Vec<f64>,
    pub bias: f64,
}

/// Training hyperparameters for logistic regression.
struct LrConfig {
    lr: f64,
    max_epochs: usize,
    l2_lambda: f64,
    convergence_eps: f64,
}

impl Default for LrConfig {
    fn default() -> Self {
        Self {
            lr: 0.1,
            max_epochs: 1000,
            l2_lambda: 1e-4,
            convergence_eps: 1e-6,
        }
    }
}

/// Numerically stable sigmoid.
fn sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let ez = z.exp();
        ez / (1.0 + ez)
    }
}

impl LogisticRegression {
    fn new(num_features: usize) -> Self {
        Self {
            weights: vec![0.0; num_features],
            bias: 0.0,
        }
    }

    fn predict(&self, features: &[f64]) -> f64 {
        let z: f64 = self
            .weights
            .iter()
            .zip(features)
            .map(|(w, x)| w * x)
            .sum::<f64>()
            + self.bias;
        sigmoid(z)
    }

    /// Full-batch gradient descent with L2 regularization.
    fn train(&mut self, data: &[(Vec<f64>, f64)], cfg: &LrConfig) {
        let n = data.len() as f64;
        if n == 0.0 {
            return;
        }
        let k = self.weights.len();
        let mut prev_loss = f64::MAX;

        for _ in 0..cfg.max_epochs {
            let mut grad_w = vec![0.0; k];
            let mut grad_b = 0.0;
            let mut loss = 0.0;

            for (features, label) in data {
                let pred = self.predict(features);
                let err = pred - label;
                let eps = 1e-15;
                loss -= label * (pred + eps).ln() + (1.0 - label) * (1.0 - pred + eps).ln();
                for (gw, x) in grad_w.iter_mut().zip(features.iter()) {
                    *gw += err * x;
                }
                grad_b += err;
            }

            loss /= n;
            for (w, gw) in self.weights.iter_mut().zip(grad_w.iter()) {
                *w -= cfg.lr * (*gw / n + cfg.l2_lambda * *w);
            }
            self.bias -= cfg.lr * grad_b / n;

            if (prev_loss - loss).abs() < cfg.convergence_eps {
                break;
            }
            prev_loss = loss;
        }
    }
}

// ---------------------------------------------------------------------------
// Data joining and splitting
// ---------------------------------------------------------------------------

/// A sample with scores from all detectors at one truncation level.
struct JoinedSample {
    sample_id: String,
    actual_malicious: bool,
    truncation_fraction: f64,
    scores: Vec<f64>,
}

/// Encode a fraction as an integer key to avoid floating-point map issues.
fn fraction_key(f: f64) -> u64 {
    (f * 10000.0).round() as u64
}

fn fraction_from_key(k: u64) -> f64 {
    k as f64 / 10000.0
}

/// Pivot per-detector results into per-sample multi-detector score vectors.
///
/// Returns `(detector_names, joined_samples)`. Samples missing any detector
/// are dropped.
fn join_detector_scores(
    sample_results: &[TruncationSampleResult],
) -> (Vec<String>, Vec<JoinedSample>) {
    let detector_names: Vec<String> = {
        let mut s: BTreeSet<String> = BTreeSet::new();
        for r in sample_results {
            s.insert(r.detector.clone());
        }
        s.into_iter().collect()
    };
    let num_det = detector_names.len();

    // Group by (sample_id, fraction_key) -> (malicious, scores[detector_index])
    type Key = (String, u64);
    let mut groups: HashMap<Key, (bool, Vec<Option<f64>>)> = HashMap::new();

    for r in sample_results {
        let key = (r.sample_id.clone(), fraction_key(r.truncation_fraction));
        let det_idx = detector_names
            .iter()
            .position(|d| d == &r.detector)
            .unwrap();
        let entry = groups
            .entry(key)
            .or_insert_with(|| (r.actual_malicious, vec![None; num_det]));
        entry.1[det_idx] = Some(r.scores.injection_score);
    }

    // Keep only complete samples (all detectors present)
    let mut joined: Vec<JoinedSample> = groups
        .into_iter()
        .filter(|(_, (_, scores))| scores.iter().all(|s| s.is_some()))
        .map(|((id, fk), (mal, scores))| JoinedSample {
            sample_id: id,
            actual_malicious: mal,
            truncation_fraction: fraction_from_key(fk),
            scores: scores.into_iter().map(|s| s.unwrap()).collect(),
        })
        .collect();

    joined.sort_by(|a, b| {
        a.truncation_fraction
            .partial_cmp(&b.truncation_fraction)
            .unwrap()
            .then_with(|| a.sample_id.cmp(&b.sample_id))
    });

    (detector_names, joined)
}

/// Deterministic stratified split of sample IDs into train/val sets.
///
/// Uses a hash-based shuffle seeded by `seed` so the split is reproducible.
fn stratified_split_ids(
    joined: &[JoinedSample],
    val_ratio: f64,
    seed: u64,
) -> (HashSet<String>, HashSet<String>) {
    let mut malicious_ids: Vec<String> = Vec::new();
    let mut benign_ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for s in joined {
        if seen.insert(s.sample_id.clone()) {
            if s.actual_malicious {
                malicious_ids.push(s.sample_id.clone());
            } else {
                benign_ids.push(s.sample_id.clone());
            }
        }
    }

    let hash_id = |id: &str| -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        id.hash(&mut h);
        seed.hash(&mut h);
        h.finish()
    };
    malicious_ids.sort_by_key(|id| hash_id(id));
    benign_ids.sort_by_key(|id| hash_id(id));

    let n_mal_val = (malicious_ids.len() as f64 * val_ratio).ceil() as usize;
    let n_ben_val = (benign_ids.len() as f64 * val_ratio).ceil() as usize;

    let val_ids: HashSet<String> = malicious_ids[..n_mal_val]
        .iter()
        .chain(benign_ids[..n_ben_val].iter())
        .cloned()
        .collect();
    let train_ids: HashSet<String> = malicious_ids[n_mal_val..]
        .iter()
        .chain(benign_ids[n_ben_val..].iter())
        .cloned()
        .collect();

    (train_ids, val_ids)
}

// ---------------------------------------------------------------------------
// Experiment logic
// ---------------------------------------------------------------------------

/// Extract unique truncation levels from joined data, sorted ascending.
fn unique_levels(joined: &[JoinedSample]) -> Vec<f64> {
    let mut levels: Vec<f64> = joined.iter().map(|s| s.truncation_fraction).collect();
    levels.sort_by(|a, b| a.partial_cmp(b).unwrap());
    levels.dedup_by(|a, b| (*a - *b).abs() < 1e-6);
    levels
}

/// Build training pairs `(scores, label)` from joined data at a specific level.
fn build_training_data(
    joined: &[JoinedSample],
    ids: &HashSet<String>,
    level: f64,
) -> Vec<(Vec<f64>, f64)> {
    joined
        .iter()
        .filter(|s| (s.truncation_fraction - level).abs() < 1e-6 && ids.contains(&s.sample_id))
        .map(|s| (s.scores.clone(), if s.actual_malicious { 1.0 } else { 0.0 }))
        .collect()
}

/// Evaluate a logistic regression model on labeled data.
fn evaluate_model(model: &LogisticRegression, data: &[(Vec<f64>, f64)]) -> RecalibrationMetrics {
    let mut cm = ConfusionMatrix::new();
    for (features, label) in data {
        cm.record(*label >= 0.5, model.predict(features) >= 0.5);
    }
    let bm = BenchmarkMetrics::from_confusion_matrix(&cm);
    RecalibrationMetrics {
        accuracy: bm.accuracy,
        tpr: bm.recall,
        fpr: bm.fpr,
        f1: bm.f1,
    }
}

fn weights_from(model: &LogisticRegression) -> LearnedWeights {
    LearnedWeights {
        detector_weights: model.weights.clone(),
        bias: model.bias,
    }
}

/// Run the recalibration experiment from pre-computed Experiment A results.
///
/// Trains a logistic regression over detector scores at each truncation level
/// ("streaming-aware") and compares with a model trained only on full text
/// ("naive"). Uses a consistent 80/20 stratified sample split across all levels.
pub fn run_recalibration_experiment(
    truncation_result: &TruncationExperimentResult,
) -> RecalibrationExperimentResult {
    let start = Instant::now();
    let (detector_names, joined) = join_detector_scores(&truncation_result.sample_results);
    let (train_ids, val_ids) = stratified_split_ids(&joined, 0.2, 42);
    let levels = unique_levels(&joined);
    let cfg = LrConfig::default();

    println!(
        "  Detectors: {}  |  Joined samples: {}  |  Levels: {}",
        detector_names.join(", "),
        joined.len(),
        levels.len(),
    );
    println!(
        "  Train IDs: {}  |  Val IDs: {}",
        train_ids.len(),
        val_ids.len()
    );

    // Train global model on full-text (1.0) data
    let global_train = build_training_data(&joined, &train_ids, 1.0);
    let mut global_model = LogisticRegression::new(detector_names.len());
    global_model.train(&global_train, &cfg);
    let global_weights = weights_from(&global_model);

    // Per-level: train streaming-aware, evaluate both
    let per_level: Vec<RecalibrationLevelResult> = levels
        .iter()
        .map(|&level| {
            let train_data = build_training_data(&joined, &train_ids, level);
            let val_data = build_training_data(&joined, &val_ids, level);

            let mut streaming_model = LogisticRegression::new(detector_names.len());
            streaming_model.train(&train_data, &cfg);

            let streaming_metrics = evaluate_model(&streaming_model, &val_data);
            let naive_metrics = evaluate_model(&global_model, &val_data);

            println!(
                "  level={:.0}%: streaming acc={:.1}% tpr={:.1}%  |  naive acc={:.1}% tpr={:.1}%",
                level * 100.0,
                streaming_metrics.accuracy * 100.0,
                streaming_metrics.tpr * 100.0,
                naive_metrics.accuracy * 100.0,
                naive_metrics.tpr * 100.0,
            );

            RecalibrationLevelResult {
                truncation_fraction: level,
                num_train: train_data.len(),
                num_val: val_data.len(),
                streaming_weights: weights_from(&streaming_model),
                streaming_metrics,
                naive_metrics,
            }
        })
        .collect();

    RecalibrationExperimentResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_duration_ms: start.elapsed().as_millis() as u64,
        detector_names,
        global_weights,
        per_level,
    }
}

// ---------------------------------------------------------------------------
// Summary output
// ---------------------------------------------------------------------------

/// Print the recalibration comparison table.
pub fn print_recalibration_summary(result: &RecalibrationExperimentResult) {
    println!("\n{}", "=".repeat(100));
    println!("  Streaming-Aware Fusion Re-calibration");
    println!("{}", "=".repeat(100));
    println!(
        "  Detectors: {}  |  Duration: {:.1}s",
        result.detector_names.join(", "),
        result.total_duration_ms as f64 / 1000.0,
    );

    // Global weights
    println!("\n  Global Weights (trained on 100% text):");
    for (name, w) in result
        .detector_names
        .iter()
        .zip(&result.global_weights.detector_weights)
    {
        println!("    {}: {:.4}", name, w);
    }
    println!("    bias: {:.4}", result.global_weights.bias);

    print_comparison_table(result);
    print_weight_table(result);
}

fn print_comparison_table(result: &RecalibrationExperimentResult) {
    println!("\n--- Per-Level Comparison ---");
    println!(
        "  {:>6} | {:>6} {:>6} {:>6} {:>6} | {:>6} {:>6} {:>6} {:>6} | {:>6} {:>6}",
        "Level", "sAcc", "sTPR", "sFPR", "sF1", "nAcc", "nTPR", "nFPR", "nF1", "dAcc", "dTPR"
    );
    println!("  {}", "-".repeat(94));

    for r in &result.per_level {
        let s = &r.streaming_metrics;
        let n = &r.naive_metrics;
        println!(
            "  {:>5.0}% | {:>5.1}% {:>5.1}% {:>5.1}% {:>5.1}% | {:>5.1}% {:>5.1}% {:>5.1}% {:>5.1}% | {:>+5.1} {:>+5.1}",
            r.truncation_fraction * 100.0,
            s.accuracy * 100.0, s.tpr * 100.0, s.fpr * 100.0, s.f1 * 100.0,
            n.accuracy * 100.0, n.tpr * 100.0, n.fpr * 100.0, n.f1 * 100.0,
            (s.accuracy - n.accuracy) * 100.0,
            (s.tpr - n.tpr) * 100.0,
        );
    }
}

fn print_weight_table(result: &RecalibrationExperimentResult) {
    println!("\n--- Per-Level Weights ---");
    let mut header = format!("  {:>6} |", "Level");
    for name in &result.detector_names {
        header.push_str(&format!(" {:>10}", name));
    }
    header.push_str(&format!(" {:>10}", "bias"));
    println!("{header}");
    println!(
        "  {}",
        "-".repeat(10 + result.detector_names.len() * 11 + 11)
    );

    for r in &result.per_level {
        let mut line = format!("  {:>5.0}% |", r.truncation_fraction * 100.0);
        for w in &r.streaming_weights.detector_weights {
            line.push_str(&format!(" {:>10.4}", w));
        }
        line.push_str(&format!(" {:>10.4}", r.streaming_weights.bias));
        println!("{line}");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigmoid() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-10);
        assert!(sigmoid(10.0) > 0.999);
        assert!(sigmoid(-10.0) < 0.001);
        // Numerically stable for extreme values
        assert!(sigmoid(-1000.0).is_finite());
        assert!(sigmoid(1000.0).is_finite());
    }

    #[test]
    fn test_logistic_regression_predict() {
        let model = LogisticRegression {
            weights: vec![1.0, -1.0],
            bias: 0.0,
        };
        // w*x = 1*1 + (-1)*0 = 1 -> sigmoid(1) ~ 0.731
        let p = model.predict(&[1.0, 0.0]);
        assert!((p - 0.7310585).abs() < 1e-4);
    }

    #[test]
    fn test_logistic_regression_train_separable() {
        // Linearly separable data: positive class has high feature, negative has low
        let data: Vec<(Vec<f64>, f64)> = vec![
            (vec![0.9], 1.0),
            (vec![0.8], 1.0),
            (vec![0.85], 1.0),
            (vec![0.95], 1.0),
            (vec![0.1], 0.0),
            (vec![0.2], 0.0),
            (vec![0.15], 0.0),
            (vec![0.05], 0.0),
        ];

        let mut model = LogisticRegression::new(1);
        model.train(&data, &LrConfig::default());

        // After training, should classify correctly
        assert!(model.predict(&[0.9]) > 0.5, "high feature -> positive");
        assert!(model.predict(&[0.1]) < 0.5, "low feature -> negative");
        assert!(model.weights[0] > 0.0, "weight should be positive");
    }

    #[test]
    fn test_evaluate_model() {
        let model = LogisticRegression {
            weights: vec![10.0],
            bias: -5.0,
        };
        // sigmoid(10*0.9 - 5) = sigmoid(4) ~ 0.982 -> predicted positive
        // sigmoid(10*0.1 - 5) = sigmoid(-4) ~ 0.018 -> predicted negative
        let data = vec![
            (vec![0.9], 1.0), // TP
            (vec![0.1], 0.0), // TN
        ];
        let m = evaluate_model(&model, &data);
        assert!((m.accuracy - 1.0).abs() < 1e-6);
        assert!((m.tpr - 1.0).abs() < 1e-6);
        assert!((m.fpr - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_fraction_key_roundtrip() {
        for &f in &[0.2, 0.4, 0.6, 0.8, 1.0, 0.33, 0.67] {
            let k = fraction_key(f);
            let back = fraction_from_key(k);
            assert!((f - back).abs() < 0.001, "roundtrip failed for {f}");
        }
    }

    #[test]
    fn test_join_detector_scores() {
        use crate::experiments::types::{RawScores, TruncationSampleResult};
        let make = |id: &str, det: &str, frac: f64, score: f64, mal: bool| TruncationSampleResult {
            sample_id: id.to_string(),
            suite: String::new(),
            actual_malicious: mal,
            original_char_len: 100,
            truncation_fraction: frac,
            truncated_char_len: (100.0 * frac) as usize,
            detector: det.to_string(),
            scores: RawScores {
                injection_score: score,
                predicted_label: "INJECTION".to_string(),
                jailbreak_score: None,
                benign_score: None,
            },
            inference_us: 100,
        };

        let results = vec![
            make("s1", "DetA", 1.0, 0.9, true),
            make("s1", "DetB", 1.0, 0.8, true),
            make("s2", "DetA", 1.0, 0.1, false),
            make("s2", "DetB", 1.0, 0.2, false),
            // s3 only has DetA -> should be dropped
            make("s3", "DetA", 1.0, 0.5, true),
        ];

        let (names, joined) = join_detector_scores(&results);
        assert_eq!(names, vec!["DetA", "DetB"]);
        assert_eq!(joined.len(), 2); // s3 dropped (incomplete)
        assert_eq!(joined[0].scores.len(), 2);
    }
}
