//! Experiment A: Truncation degradation study.
//!
//! Measures how ML detector accuracy degrades as input text is truncated
//! to simulate streaming partial-text analysis. Character-level truncation
//! (right-truncation: keep first N% of characters) models the SSE streaming
//! scenario where only the beginning of the response has arrived.

use std::time::Instant;

use crate::datasets::{BenchmarkSample, Label};
use crate::metrics::{tpr_at_fpr, BenchmarkMetrics, ConfusionMatrix};

use super::types::{
    suite_direction, RawScores, TruncationExperimentResult, TruncationLevelMetrics,
    TruncationSampleResult,
};

/// Default truncation levels to evaluate.
pub const DEFAULT_TRUNCATION_LEVELS: &[f64] = &[0.2, 0.4, 0.6, 0.8, 1.0];

/// Truncate text to a fraction of its character length.
///
/// Truncation is right-truncation (keep the first `fraction` of characters),
/// snapped to the nearest UTF-8 char boundary to avoid panics.
pub fn truncate_text(text: &str, fraction: f64) -> &str {
    assert!(
        (0.0..=1.0).contains(&fraction),
        "fraction must be in [0.0, 1.0]"
    );
    if fraction >= 1.0 {
        return text;
    }
    let target_bytes = (text.len() as f64 * fraction) as usize;
    if target_bytes == 0 {
        return "";
    }
    // Find the largest char boundary <= target_bytes
    let end = text
        .char_indices()
        .take_while(|(i, _)| *i < target_bytes)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    &text[..end]
}

/// A detector that can return raw scores for experiments.
///
/// Implemented by thin wrappers around each ML analyzer.
pub trait RawScoreDetector: Send + Sync {
    /// Detector name (e.g. "PromptGuard", "InjecGuard", "PIGuard").
    fn name(&self) -> &str;

    /// Return raw scores for the given text, or `None` if the model is not loaded.
    fn score(&self, text: &str) -> llmtrace_core::Result<Option<RawScores>>;
}

/// Run the truncation degradation experiment.
///
/// For each sample in each suite, truncates at each level, runs each detector,
/// and collects per-sample raw scores. Then aggregates metrics per
/// (detector, suite, truncation_level).
pub fn run_truncation_experiment(
    detectors: &[&dyn RawScoreDetector],
    suites: &[(&str, &[BenchmarkSample])],
    levels: &[f64],
) -> TruncationExperimentResult {
    let start = Instant::now();
    let mut sample_results: Vec<TruncationSampleResult> = Vec::new();

    let total_work = detectors.len() * suites.len() * levels.len();
    let mut work_done = 0;

    for detector in detectors {
        for (suite_name, samples) in suites {
            for &fraction in levels {
                work_done += 1;
                println!(
                    "  [{}/{}] {} | {} | {:.0}%",
                    work_done,
                    total_work,
                    detector.name(),
                    suite_name,
                    fraction * 100.0
                );

                for sample in *samples {
                    let truncated = truncate_text(&sample.text, fraction);
                    if truncated.is_empty() {
                        continue;
                    }

                    let infer_start = Instant::now();
                    let scores = match detector.score(truncated) {
                        Ok(Some(s)) => s,
                        Ok(None) => continue, // model not loaded
                        Err(e) => {
                            eprintln!(
                                "WARN: inference failed for {} (detector={}, trunc={:.0}%): {}",
                                sample.id,
                                detector.name(),
                                fraction * 100.0,
                                e
                            );
                            continue;
                        }
                    };
                    let inference_us = infer_start.elapsed().as_micros() as u64;

                    sample_results.push(TruncationSampleResult {
                        sample_id: sample.id.clone(),
                        suite: suite_name.to_string(),
                        actual_malicious: sample.label == Label::Malicious,
                        original_char_len: sample.text.len(),
                        truncation_fraction: fraction,
                        truncated_char_len: truncated.len(),
                        detector: detector.name().to_string(),
                        scores,
                        inference_us,
                    });
                }
            }
        }
    }

    let level_metrics = aggregate_truncation_metrics(&sample_results, suites, detectors, levels);
    let total_duration_ms = start.elapsed().as_millis() as u64;

    TruncationExperimentResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_duration_ms,
        level_metrics,
        sample_results,
    }
}

/// Aggregate per-sample results into metrics per (detector, suite, level).
fn aggregate_truncation_metrics(
    samples: &[TruncationSampleResult],
    suites: &[(&str, &[BenchmarkSample])],
    detectors: &[&dyn RawScoreDetector],
    levels: &[f64],
) -> Vec<TruncationLevelMetrics> {
    let mut metrics = Vec::new();

    for detector in detectors {
        for (suite_name, _) in suites {
            for &fraction in levels {
                let subset: Vec<&TruncationSampleResult> = samples
                    .iter()
                    .filter(|s| {
                        s.detector == detector.name()
                            && (s.truncation_fraction - fraction).abs() < 1e-6
                    })
                    // Match by suite: sample_id should be from this suite.
                    // We filter by checking membership in the suite samples.
                    .collect();

                // Build suite sample IDs for filtering
                let suite_ids: std::collections::HashSet<&str> = suites
                    .iter()
                    .filter(|(name, _)| *name == *suite_name)
                    .flat_map(|(_, samps)| samps.iter().map(|s| s.id.as_str()))
                    .collect();

                let filtered: Vec<&&TruncationSampleResult> = subset
                    .iter()
                    .filter(|s| suite_ids.contains(s.sample_id.as_str()))
                    .collect();

                if filtered.is_empty() {
                    continue;
                }

                // Build confusion matrix using injection_score >= 0.5 as threshold
                let threshold = 0.5;
                let mut cm = ConfusionMatrix::new();
                let mut score_label_pairs: Vec<(f64, bool)> = Vec::new();
                let mut malicious_scores: Vec<f64> = Vec::new();
                let mut benign_scores: Vec<f64> = Vec::new();

                for s in &filtered {
                    let predicted = s.scores.injection_score >= threshold;
                    cm.record(s.actual_malicious, predicted);
                    score_label_pairs.push((s.scores.injection_score, s.actual_malicious));
                    if s.actual_malicious {
                        malicious_scores.push(s.scores.injection_score);
                    } else {
                        benign_scores.push(s.scores.injection_score);
                    }
                }

                let bm = BenchmarkMetrics::from_confusion_matrix(&cm);
                let (tpr_1pct, _) = tpr_at_fpr(&score_label_pairs, 0.01);

                let mean_malicious = if malicious_scores.is_empty() {
                    0.0
                } else {
                    malicious_scores.iter().sum::<f64>() / malicious_scores.len() as f64
                };
                let mean_benign = if benign_scores.is_empty() {
                    0.0
                } else {
                    benign_scores.iter().sum::<f64>() / benign_scores.len() as f64
                };

                metrics.push(TruncationLevelMetrics {
                    detector: detector.name().to_string(),
                    suite: suite_name.to_string(),
                    truncation_fraction: fraction,
                    num_samples: filtered.len(),
                    accuracy: bm.accuracy,
                    tpr: bm.recall,
                    fpr: bm.fpr,
                    f1: bm.f1,
                    tpr_at_1pct_fpr: tpr_1pct,
                    mean_malicious_score: mean_malicious,
                    mean_benign_score: mean_benign,
                });
            }
        }
    }

    metrics
}

/// Print a summary table of truncation experiment results.
pub fn print_truncation_summary(result: &TruncationExperimentResult) {
    println!("\n{}", "=".repeat(100));
    println!("  EXPERIMENT A: Truncation Degradation Study");
    println!("{}", "=".repeat(100));
    println!(
        "  Total samples: {}  |  Duration: {:.1}s",
        result.sample_results.len(),
        result.total_duration_ms as f64 / 1000.0
    );

    // Group by detector
    let mut detectors: Vec<&str> = result
        .level_metrics
        .iter()
        .map(|m| m.detector.as_str())
        .collect();
    detectors.sort();
    detectors.dedup();

    for detector in detectors {
        println!("\n--- {} ---", detector);
        println!(
            "| {:>12} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>10} | {:>10} |",
            "Suite", "Trunc%", "Acc", "TPR", "FPR", "F1", "MeanMal", "MeanBen"
        );
        println!(
            "|{}|{}|{}|{}|{}|{}|{}|{}|",
            "-".repeat(14),
            "-".repeat(10),
            "-".repeat(10),
            "-".repeat(10),
            "-".repeat(10),
            "-".repeat(10),
            "-".repeat(12),
            "-".repeat(12),
        );

        let detector_metrics: Vec<&TruncationLevelMetrics> = result
            .level_metrics
            .iter()
            .filter(|m| m.detector == detector)
            .collect();

        let mut suites: Vec<&str> = detector_metrics.iter().map(|m| m.suite.as_str()).collect();
        suites.sort();
        suites.dedup();

        for suite in suites {
            let suite_metrics: Vec<&&TruncationLevelMetrics> = detector_metrics
                .iter()
                .filter(|m| m.suite == suite)
                .collect();

            for m in suite_metrics {
                println!(
                    "| {:>12} | {:>7.0}% | {:>7.2}% | {:>7.2}% | {:>7.2}% | {:>7.2}% | {:>10.4} | {:>10.4} |",
                    m.suite,
                    m.truncation_fraction * 100.0,
                    m.accuracy * 100.0,
                    m.tpr * 100.0,
                    m.fpr * 100.0,
                    m.f1 * 100.0,
                    m.mean_malicious_score,
                    m.mean_benign_score,
                );
            }
        }
    }

    // Direction-grouped summary
    print_direction_summary(&result.level_metrics);
}

/// Print direction-grouped (input vs output) summary across suites.
fn print_direction_summary(metrics: &[TruncationLevelMetrics]) {
    println!("\n{}", "=".repeat(100));
    println!("  Direction Analysis (input=direct injection, output=indirect injection)");
    println!("{}", "=".repeat(100));

    let mut detectors: Vec<&str> = metrics.iter().map(|m| m.detector.as_str()).collect();
    detectors.sort();
    detectors.dedup();

    let mut levels: Vec<f64> = metrics.iter().map(|m| m.truncation_fraction).collect();
    levels.sort_by(|a, b| a.partial_cmp(b).unwrap());
    levels.dedup_by(|a, b| (*a - *b).abs() < 1e-6);

    for detector in &detectors {
        println!("\n--- {} ---", detector);
        println!(
            "| {:>10} | {:>8} | {:>5} | {:>8} | {:>8} | {:>8} | {:>8} |",
            "Direction", "Trunc%", "N", "Acc", "TPR", "FPR", "F1"
        );
        println!(
            "|{}|{}|{}|{}|{}|{}|{}|",
            "-".repeat(12),
            "-".repeat(10),
            "-".repeat(7),
            "-".repeat(10),
            "-".repeat(10),
            "-".repeat(10),
            "-".repeat(10),
        );

        for &level in &levels {
            for direction in &["input", "output"] {
                let dir_metrics: Vec<&TruncationLevelMetrics> = metrics
                    .iter()
                    .filter(|m| {
                        m.detector == *detector
                            && (m.truncation_fraction - level).abs() < 1e-6
                            && suite_direction(&m.suite) == *direction
                    })
                    .collect();

                if dir_metrics.is_empty() {
                    continue;
                }

                let total_n: usize = dir_metrics.iter().map(|m| m.num_samples).sum();
                let w_acc = weighted_mean(&dir_metrics, |m| m.accuracy);
                let w_tpr = weighted_mean(&dir_metrics, |m| m.tpr);
                let w_fpr = weighted_mean(&dir_metrics, |m| m.fpr);
                let w_f1 = weighted_mean(&dir_metrics, |m| m.f1);

                println!(
                    "| {:>10} | {:>7.0}% | {:>5} | {:>7.2}% | {:>7.2}% | {:>7.2}% | {:>7.2}% |",
                    direction,
                    level * 100.0,
                    total_n,
                    w_acc * 100.0,
                    w_tpr * 100.0,
                    w_fpr * 100.0,
                    w_f1 * 100.0,
                );
            }
        }
    }
}

/// Weighted mean of a metric across level metrics, weighted by num_samples.
fn weighted_mean(
    metrics: &[&TruncationLevelMetrics],
    f: fn(&TruncationLevelMetrics) -> f64,
) -> f64 {
    let total_n: usize = metrics.iter().map(|m| m.num_samples).sum();
    if total_n == 0 {
        return 0.0;
    }
    metrics
        .iter()
        .map(|m| f(m) * m.num_samples as f64)
        .sum::<f64>()
        / total_n as f64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_text_full() {
        assert_eq!(truncate_text("hello world", 1.0), "hello world");
    }

    #[test]
    fn test_truncate_text_half() {
        let result = truncate_text("hello world", 0.5);
        // "hello world" is 11 bytes, 50% = 5.5 -> snap to 5 -> "hello"
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_truncate_text_zero() {
        assert_eq!(truncate_text("hello world", 0.0), "");
    }

    #[test]
    fn test_truncate_text_unicode() {
        // Ensure truncation doesn't split multi-byte chars
        let text = "cafe\u{0301} world"; // "cafe\u{0301}" is 6 bytes
        let truncated = truncate_text(text, 0.5);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn test_truncate_text_empty() {
        assert_eq!(truncate_text("", 0.5), "");
    }

    #[test]
    #[should_panic(expected = "fraction must be in [0.0, 1.0]")]
    fn test_truncate_text_invalid_fraction() {
        truncate_text("test", 1.5);
    }
}
