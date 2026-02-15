//! Types for streaming partial-text ML experiments.
//!
//! Separate from the benchmark runner types to avoid polluting the
//! existing `BenchmarkResult` / `SampleResult` data model.

use serde::{Deserialize, Serialize};

/// Classify a suite as input-side (direct injection) or output-side
/// (indirect/response-side injection).
///
/// Input: direct prompt injection, jailbreaks -- attacker controls the prompt.
/// Output: indirect injection in documents, tool responses, retrieved content --
/// payload is buried in natural text that the LLM processes mid-stream.
pub fn suite_direction(suite_name: &str) -> &'static str {
    match suite_name {
        "bipia" | "injecagent" | "safeguard_v2" | "deepset_v2" => "output",
        _ => "input",
    }
}

/// Raw scores from a single ML inference call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawScores {
    /// Injection/malicious class score (0.0-1.0).
    pub injection_score: f64,
    /// Predicted label from the model.
    pub predicted_label: String,
    /// For PromptGuard: jailbreak class score. `None` for binary classifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jailbreak_score: Option<f64>,
    /// For PromptGuard: benign class score. `None` for binary classifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub benign_score: Option<f64>,
}

/// Per-sample result for a single truncation level in Experiment A.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruncationSampleResult {
    /// Sample identifier (from dataset).
    pub sample_id: String,
    /// Suite this sample belongs to (for direction analysis).
    #[serde(default)]
    pub suite: String,
    /// Ground truth: is this sample malicious?
    pub actual_malicious: bool,
    /// Original text length in characters.
    pub original_char_len: usize,
    /// Truncation fraction applied (0.2, 0.4, 0.6, 0.8, 1.0).
    pub truncation_fraction: f64,
    /// Character length after truncation.
    pub truncated_char_len: usize,
    /// Detector that produced this result.
    pub detector: String,
    /// Raw model scores at this truncation level.
    pub scores: RawScores,
    /// Inference latency in microseconds.
    pub inference_us: u64,
}

/// Per-sample result for boundary detection in Experiment B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundarySampleResult {
    /// Sample identifier (from dataset).
    pub sample_id: String,
    /// Suite this sample belongs to (for direction analysis).
    #[serde(default)]
    pub suite: String,
    /// Original text length in characters.
    pub original_char_len: usize,
    /// Detector that produced this result.
    pub detector: String,
    /// Full-text injection score (baseline).
    pub full_text_score: f64,
    /// Boundary positions as fraction of full text, per confidence threshold.
    /// Key is threshold (e.g. "0.5", "0.7", "0.9"), value is the first
    /// character fraction where that threshold was crossed, or `None` if
    /// never crossed.
    pub boundaries: Vec<BoundaryThreshold>,
    /// Number of inference calls made during binary search.
    pub inference_calls: u32,
}

/// A single threshold boundary result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryThreshold {
    /// Confidence threshold (e.g. 0.5, 0.7, 0.9).
    pub threshold: f64,
    /// Character fraction at which the threshold was first crossed.
    /// `None` if the threshold was never reached.
    pub boundary_fraction: Option<f64>,
    /// Actual character position.
    pub boundary_char_pos: Option<usize>,
}

/// Aggregated metrics for one (detector, suite, truncation_level) combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruncationLevelMetrics {
    /// Detector name.
    pub detector: String,
    /// Suite name.
    pub suite: String,
    /// Truncation fraction.
    pub truncation_fraction: f64,
    /// Number of samples evaluated.
    pub num_samples: usize,
    /// Accuracy at this truncation level.
    pub accuracy: f64,
    /// True positive rate (recall).
    pub tpr: f64,
    /// False positive rate.
    pub fpr: f64,
    /// F1 score.
    pub f1: f64,
    /// TPR at 1% FPR (deployment-realistic metric).
    pub tpr_at_1pct_fpr: f64,
    /// Mean injection score for malicious samples.
    pub mean_malicious_score: f64,
    /// Mean injection score for benign samples.
    pub mean_benign_score: f64,
}

/// Complete output of Experiment A.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruncationExperimentResult {
    /// Timestamp of the run.
    pub timestamp: String,
    /// Total wall-clock duration in milliseconds.
    pub total_duration_ms: u64,
    /// Aggregated metrics per (detector, suite, truncation_level).
    pub level_metrics: Vec<TruncationLevelMetrics>,
    /// Per-sample raw data (for downstream analysis).
    pub sample_results: Vec<TruncationSampleResult>,
}

/// Complete output of Experiment B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryExperimentResult {
    /// Timestamp of the run.
    pub timestamp: String,
    /// Total wall-clock duration in milliseconds.
    pub total_duration_ms: u64,
    /// Per-sample boundary results.
    pub sample_results: Vec<BoundarySampleResult>,
}

// ---------------------------------------------------------------------------
// Experiment C: Checkpoint interval optimization
// ---------------------------------------------------------------------------

/// A checkpoint strategy: inference runs at these fractions of the text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointStrategy {
    /// Strategy name (e.g., "quintiles", "front_heavy").
    pub name: String,
    /// Sorted checkpoint fractions in (0.0, 1.0] where inference runs.
    pub checkpoints: Vec<f64>,
}

/// Per-sample result for checkpoint simulation in Experiment C.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSampleResult {
    /// Sample identifier (from dataset).
    pub sample_id: String,
    /// Suite this sample belongs to (for direction analysis).
    #[serde(default)]
    pub suite: String,
    /// Ground truth: is this sample malicious?
    pub actual_malicious: bool,
    /// Original text length in characters.
    pub original_char_len: usize,
    /// Detector that produced this result.
    pub detector: String,
    /// Strategy name.
    pub strategy: String,
    /// Full-text injection score (reference baseline).
    pub full_text_score: f64,
    /// Checkpoint fraction at which detection first occurred, or `None`.
    pub detection_checkpoint: Option<f64>,
    /// Injection score at the detection checkpoint.
    pub detection_score: Option<f64>,
    /// Number of inference calls made (with early stopping).
    pub inference_calls: u32,
}

/// Aggregated metrics for one (detector, suite, strategy) in Experiment C.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointStrategyMetrics {
    /// Detector name.
    pub detector: String,
    /// Suite name.
    pub suite: String,
    /// Strategy name.
    pub strategy: String,
    /// Number of checkpoints in this strategy.
    pub num_checkpoints: usize,
    /// Total samples evaluated.
    pub num_samples: usize,
    /// True positives (malicious correctly detected).
    pub tp: usize,
    /// False positives (benign incorrectly detected).
    pub fp: usize,
    /// True positive rate.
    pub tpr: f64,
    /// False positive rate.
    pub fpr: f64,
    /// Mean detection latency as text fraction (over detected malicious only).
    pub mean_detection_latency: f64,
    /// Median detection latency as text fraction.
    pub median_detection_latency: f64,
    /// Mean inference calls per sample (with early stopping).
    pub mean_inference_calls: f64,
    /// Whether this strategy is on the Pareto frontier (cost vs TPR).
    pub is_pareto: bool,
}

/// Complete output of Experiment C.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointExperimentResult {
    /// Timestamp of the run.
    pub timestamp: String,
    /// Total wall-clock duration in milliseconds.
    pub total_duration_ms: u64,
    /// Detection threshold used for the simulation.
    pub detection_threshold: f64,
    /// Aggregated metrics per (detector, suite, strategy).
    pub strategy_metrics: Vec<CheckpointStrategyMetrics>,
    /// Per-sample raw data.
    pub sample_results: Vec<CheckpointSampleResult>,
}

// ---------------------------------------------------------------------------
// Recalibration: Streaming-aware fusion weight re-calibration
// ---------------------------------------------------------------------------

/// Learned logistic regression weights for combining detector scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedWeights {
    /// One weight per detector (ordered by `detector_names`).
    pub detector_weights: Vec<f64>,
    /// Intercept term.
    pub bias: f64,
}

/// Classification metrics for the recalibration comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecalibrationMetrics {
    pub accuracy: f64,
    pub tpr: f64,
    pub fpr: f64,
    pub f1: f64,
}

/// Per-level result comparing streaming-aware vs naive (global) weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecalibrationLevelResult {
    /// Truncation fraction this level corresponds to.
    pub truncation_fraction: f64,
    /// Number of training samples at this level.
    pub num_train: usize,
    /// Number of validation samples at this level.
    pub num_val: usize,
    /// Weights trained specifically at this truncation level.
    pub streaming_weights: LearnedWeights,
    /// Metrics for the streaming-aware (per-level) model on this level's val set.
    pub streaming_metrics: RecalibrationMetrics,
    /// Metrics for the naive (global/full-text) model on this level's val set.
    pub naive_metrics: RecalibrationMetrics,
}

/// Complete output of the recalibration experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecalibrationExperimentResult {
    /// Timestamp of the run.
    pub timestamp: String,
    /// Total wall-clock duration in milliseconds.
    pub total_duration_ms: u64,
    /// Ordered list of detector names (matches weight vector indices).
    pub detector_names: Vec<String>,
    /// Weights trained on full-text (100%) data -- the "naive" baseline.
    pub global_weights: LearnedWeights,
    /// Per-level comparison results.
    pub per_level: Vec<RecalibrationLevelResult>,
}
