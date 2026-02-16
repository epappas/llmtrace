//! Experiment C: Checkpoint interval optimization.
//!
//! Simulates streaming checkpoint strategies where inference runs at
//! predetermined fractions of the text. Uses pre-computed scores at all
//! unique checkpoint fractions, then simulates each strategy with early
//! stopping. Identifies the Pareto frontier of inference cost vs TPR.

use std::time::Instant;

use crate::datasets::{BenchmarkSample, Label};

use super::truncation::{truncate_text, RawScoreDetector};
use super::types::{
    suite_direction, CheckpointExperimentResult, CheckpointSampleResult, CheckpointStrategy,
    CheckpointStrategyMetrics,
};

/// Minimum prefix length in characters for inference.
const MIN_PREFIX_CHARS: usize = 10;

/// Default detection threshold for checkpoint simulation.
pub const DEFAULT_CHECKPOINT_THRESHOLD: f64 = 0.5;

/// Build the default set of checkpoint strategies.
pub fn default_strategies() -> Vec<CheckpointStrategy> {
    vec![
        CheckpointStrategy {
            name: "full_only".into(),
            checkpoints: vec![1.0],
        },
        CheckpointStrategy {
            name: "half_full".into(),
            checkpoints: vec![0.5, 1.0],
        },
        CheckpointStrategy {
            name: "thirds".into(),
            checkpoints: vec![0.33, 0.67, 1.0],
        },
        CheckpointStrategy {
            name: "quarters".into(),
            checkpoints: vec![0.25, 0.5, 0.75, 1.0],
        },
        CheckpointStrategy {
            name: "quintiles".into(),
            checkpoints: vec![0.2, 0.4, 0.6, 0.8, 1.0],
        },
        CheckpointStrategy {
            name: "deciles".into(),
            checkpoints: vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
        },
        CheckpointStrategy {
            name: "front_heavy".into(),
            checkpoints: vec![0.1, 0.2, 0.3, 0.5, 1.0],
        },
    ]
}

/// Collect all unique fractions from strategies, sorted ascending.
fn collect_unique_fractions(strategies: &[CheckpointStrategy]) -> Vec<f64> {
    let mut fractions: Vec<f64> = strategies
        .iter()
        .flat_map(|s| s.checkpoints.iter().copied())
        .collect();
    fractions.sort_by(|a, b| a.partial_cmp(b).unwrap());
    fractions.dedup_by(|a, b| (*a - *b).abs() < 1e-9);
    fractions
}

/// Pre-compute injection scores at all unique fractions for one sample.
///
/// Returns `(fraction, Option<score>)` pairs. `None` means the prefix was
/// too short for inference or inference failed.
fn precompute_scores(
    detector: &dyn RawScoreDetector,
    text: &str,
    fractions: &[f64],
) -> Vec<(f64, Option<f64>)> {
    fractions
        .iter()
        .map(|&frac| {
            let prefix = truncate_text(text, frac);
            if prefix.len() < MIN_PREFIX_CHARS {
                return (frac, None);
            }
            let score = match detector.score(prefix) {
                Ok(Some(s)) => Some(s.injection_score),
                _ => None,
            };
            (frac, score)
        })
        .collect()
}

/// Simulate a single strategy using pre-computed scores.
///
/// Returns `(detection_checkpoint, detection_score, inference_calls)`.
/// Early-stops on first detection (score >= threshold).
fn simulate_strategy(
    precomputed: &[(f64, Option<f64>)],
    strategy: &CheckpointStrategy,
    threshold: f64,
) -> (Option<f64>, Option<f64>, u32) {
    let mut calls = 0u32;
    for &frac in &strategy.checkpoints {
        let score = match lookup_score(precomputed, frac) {
            Some(s) => s,
            None => continue,
        };
        calls += 1;
        if score >= threshold {
            return (Some(frac), Some(score), calls);
        }
    }
    (None, None, calls)
}

/// Look up a pre-computed score by fraction (within floating-point tolerance).
fn lookup_score(precomputed: &[(f64, Option<f64>)], frac: f64) -> Option<f64> {
    precomputed
        .iter()
        .find(|(f, _)| (*f - frac).abs() < 1e-9)
        .and_then(|(_, s)| *s)
}

/// Run the checkpoint experiment.
///
/// Pre-computes scores at all unique fractions per (detector, sample), then
/// simulates each strategy with early stopping.
pub fn run_checkpoint_experiment(
    detectors: &[&dyn RawScoreDetector],
    suites: &[(&str, &[BenchmarkSample])],
    strategies: &[CheckpointStrategy],
    threshold: f64,
) -> CheckpointExperimentResult {
    let start = Instant::now();
    let mut sample_results: Vec<CheckpointSampleResult> = Vec::new();
    let all_fractions = collect_unique_fractions(strategies);

    let total_combos = detectors.len() * suites.len();

    for (d_idx, detector) in detectors.iter().enumerate() {
        for (s_idx, (suite_name, samples)) in suites.iter().enumerate() {
            println!(
                "  [{}/{}] {} | {} | {} samples x {} strategies",
                d_idx * suites.len() + s_idx + 1,
                total_combos,
                detector.name(),
                suite_name,
                samples.len(),
                strategies.len(),
            );

            for sample in *samples {
                let precomputed = precompute_scores(*detector, &sample.text, &all_fractions);
                let full_text_score = lookup_score(&precomputed, 1.0).unwrap_or(0.0);

                for strategy in strategies {
                    let (det_cp, det_score, calls) =
                        simulate_strategy(&precomputed, strategy, threshold);

                    sample_results.push(CheckpointSampleResult {
                        sample_id: sample.id.clone(),
                        suite: suite_name.to_string(),
                        actual_malicious: sample.label == Label::Malicious,
                        original_char_len: sample.text.len(),
                        detector: detector.name().to_string(),
                        strategy: strategy.name.clone(),
                        full_text_score,
                        detection_checkpoint: det_cp,
                        detection_score: det_score,
                        inference_calls: calls,
                    });
                }
            }
        }
    }

    let mut strategy_metrics =
        aggregate_checkpoint_metrics(&sample_results, suites, detectors, strategies);
    mark_pareto_frontier(&mut strategy_metrics);
    let total_duration_ms = start.elapsed().as_millis() as u64;

    CheckpointExperimentResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_duration_ms,
        detection_threshold: threshold,
        strategy_metrics,
        sample_results,
    }
}

/// Count TP/FP/malicious/benign from checkpoint sample results.
fn count_classifications(samples: &[&CheckpointSampleResult]) -> (usize, usize, usize, usize) {
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut num_mal = 0usize;
    let mut num_ben = 0usize;
    for s in samples {
        if s.actual_malicious {
            num_mal += 1;
            if s.detection_checkpoint.is_some() {
                tp += 1;
            }
        } else {
            num_ben += 1;
            if s.detection_checkpoint.is_some() {
                fp += 1;
            }
        }
    }
    (tp, fp, num_mal, num_ben)
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

/// Aggregate per-sample results into metrics per (detector, suite, strategy).
fn aggregate_checkpoint_metrics(
    samples: &[CheckpointSampleResult],
    suites: &[(&str, &[BenchmarkSample])],
    detectors: &[&dyn RawScoreDetector],
    strategies: &[CheckpointStrategy],
) -> Vec<CheckpointStrategyMetrics> {
    let mut metrics = Vec::new();

    for detector in detectors {
        for (suite_name, suite_samples) in suites {
            let suite_ids: std::collections::HashSet<&str> =
                suite_samples.iter().map(|s| s.id.as_str()).collect();

            for strategy in strategies {
                let subset: Vec<&CheckpointSampleResult> = samples
                    .iter()
                    .filter(|s| {
                        s.detector == detector.name()
                            && s.strategy == strategy.name
                            && suite_ids.contains(s.sample_id.as_str())
                    })
                    .collect();

                if subset.is_empty() {
                    continue;
                }

                let (tp, fp, num_mal, num_ben) = count_classifications(&subset);
                let tpr = if num_mal > 0 {
                    tp as f64 / num_mal as f64
                } else {
                    0.0
                };
                let fpr = if num_ben > 0 {
                    fp as f64 / num_ben as f64
                } else {
                    0.0
                };

                let detection_latencies: Vec<f64> = subset
                    .iter()
                    .filter(|s| s.actual_malicious)
                    .filter_map(|s| s.detection_checkpoint)
                    .collect();

                let mean_calls = subset.iter().map(|s| s.inference_calls as f64).sum::<f64>()
                    / subset.len() as f64;

                metrics.push(CheckpointStrategyMetrics {
                    detector: detector.name().to_string(),
                    suite: suite_name.to_string(),
                    strategy: strategy.name.clone(),
                    num_checkpoints: strategy.checkpoints.len(),
                    num_samples: subset.len(),
                    tp,
                    fp,
                    tpr,
                    fpr,
                    mean_detection_latency: mean(&detection_latencies),
                    median_detection_latency: median(&detection_latencies),
                    mean_inference_calls: mean_calls,
                    is_pareto: false,
                });
            }
        }
    }

    metrics
}

/// Mark strategies on the Pareto frontier (per detector+suite group).
///
/// A strategy is Pareto-optimal if no other strategy in the same group has
/// both lower (or equal) cost AND higher (or equal) TPR with at least one
/// strictly better.
fn mark_pareto_frontier(metrics: &mut [CheckpointStrategyMetrics]) {
    let n = metrics.len();
    for i in 0..n {
        let mut dominated = false;
        for j in 0..n {
            if i == j {
                continue;
            }
            if metrics[i].detector != metrics[j].detector || metrics[i].suite != metrics[j].suite {
                continue;
            }
            let lower_cost = metrics[j].mean_inference_calls <= metrics[i].mean_inference_calls;
            let higher_tpr = metrics[j].tpr >= metrics[i].tpr;
            let strictly_better = metrics[j].mean_inference_calls < metrics[i].mean_inference_calls
                || metrics[j].tpr > metrics[i].tpr;
            if lower_cost && higher_tpr && strictly_better {
                dominated = true;
                break;
            }
        }
        metrics[i].is_pareto = !dominated;
    }
}

/// Print a summary of checkpoint experiment results.
pub fn print_checkpoint_summary(result: &CheckpointExperimentResult) {
    println!("\n{}", "=".repeat(100));
    println!("  EXPERIMENT C: Checkpoint Interval Optimization");
    println!("{}", "=".repeat(100));
    println!(
        "  Total samples: {}  |  Duration: {:.1}s  |  Threshold: {}",
        result.sample_results.len(),
        result.total_duration_ms as f64 / 1000.0,
        result.detection_threshold,
    );

    let mut detectors: Vec<&str> = result
        .strategy_metrics
        .iter()
        .map(|m| m.detector.as_str())
        .collect();
    detectors.sort();
    detectors.dedup();

    for detector in detectors {
        let det_metrics: Vec<&CheckpointStrategyMetrics> = result
            .strategy_metrics
            .iter()
            .filter(|m| m.detector == detector)
            .collect();
        print_detector_table(detector, &det_metrics);
    }

    // Direction-grouped summary
    print_checkpoint_direction_summary(&result.strategy_metrics);
}

fn print_detector_table(detector: &str, metrics: &[&CheckpointStrategyMetrics]) {
    let mut suites: Vec<&str> = metrics.iter().map(|m| m.suite.as_str()).collect();
    suites.sort();
    suites.dedup();

    for suite in &suites {
        println!("\n--- {} | {} ---", detector, suite);
        println!(
            "  {:>12} | {:>3} | {:>7} | {:>7} | {:>8} | {:>8} | {:>9} | {:>6}",
            "Strategy", "CPs", "TPR", "FPR", "MedLat", "MeanLat", "MeanCalls", "Pareto"
        );
        println!("  {}", "-".repeat(80));

        let suite_metrics: Vec<&&CheckpointStrategyMetrics> =
            metrics.iter().filter(|m| m.suite == *suite).collect();

        for m in &suite_metrics {
            let pareto = if m.is_pareto { "*" } else { "" };
            println!(
                "  {:>12} | {:>3} | {:>6.1}% | {:>6.1}% | {:>7.1}% | {:>7.1}% | {:>9.1} | {:>6}",
                m.strategy,
                m.num_checkpoints,
                m.tpr * 100.0,
                m.fpr * 100.0,
                m.median_detection_latency * 100.0,
                m.mean_detection_latency * 100.0,
                m.mean_inference_calls,
                pareto,
            );
        }
    }
}

/// Print checkpoint results grouped by direction (input vs output).
fn print_checkpoint_direction_summary(metrics: &[CheckpointStrategyMetrics]) {
    println!("\n{}", "=".repeat(100));
    println!("  Direction Analysis (input=direct injection, output=indirect injection)");
    println!("{}", "=".repeat(100));

    let mut detectors: Vec<&str> = metrics.iter().map(|m| m.detector.as_str()).collect();
    detectors.sort();
    detectors.dedup();

    let mut strategies: Vec<&str> = metrics.iter().map(|m| m.strategy.as_str()).collect();
    strategies.sort();
    strategies.dedup();

    for detector in &detectors {
        println!("\n--- {} ---", detector);
        println!(
            "  {:>12} | {:>9} | {:>5} | {:>7} | {:>7} | {:>8} | {:>9}",
            "Strategy", "Direction", "N", "TPR", "FPR", "MedLat", "MeanCalls"
        );
        println!("  {}", "-".repeat(75));

        for strategy in &strategies {
            for direction in &["input", "output"] {
                let dir_metrics: Vec<&CheckpointStrategyMetrics> = metrics
                    .iter()
                    .filter(|m| {
                        m.detector == *detector
                            && m.strategy == *strategy
                            && suite_direction(&m.suite) == *direction
                    })
                    .collect();

                if dir_metrics.is_empty() {
                    continue;
                }

                let total_n: usize = dir_metrics.iter().map(|m| m.num_samples).sum();
                let total_tp: usize = dir_metrics.iter().map(|m| m.tp).sum();
                let total_fp: usize = dir_metrics.iter().map(|m| m.fp).sum();
                let total_mal: usize = dir_metrics
                    .iter()
                    .map(|m| (m.tpr * m.num_samples as f64).round() as usize)
                    .sum::<usize>()
                    .max(total_tp);
                let total_ben = total_n.saturating_sub(total_mal);

                let agg_tpr = if total_mal > 0 {
                    total_tp as f64 / total_mal as f64
                } else {
                    0.0
                };
                let agg_fpr = if total_ben > 0 {
                    total_fp as f64 / total_ben as f64
                } else {
                    0.0
                };
                let w_med_lat: f64 = dir_metrics
                    .iter()
                    .map(|m| m.median_detection_latency * m.num_samples as f64)
                    .sum::<f64>()
                    / total_n as f64;
                let w_calls: f64 = dir_metrics
                    .iter()
                    .map(|m| m.mean_inference_calls * m.num_samples as f64)
                    .sum::<f64>()
                    / total_n as f64;

                println!(
                    "  {:>12} | {:>9} | {:>5} | {:>6.1}% | {:>6.1}% | {:>7.1}% | {:>9.1}",
                    strategy,
                    direction,
                    total_n,
                    agg_tpr * 100.0,
                    agg_fpr * 100.0,
                    w_med_lat * 100.0,
                    w_calls,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiments::types::RawScores;

    /// A step detector: returns 0.9 above a text-length threshold, 0.1 below.
    struct StepDetector {
        step_len: usize,
    }

    impl RawScoreDetector for StepDetector {
        fn name(&self) -> &str {
            "StepTest"
        }

        fn score(&self, text: &str) -> llmtrace_core::Result<Option<RawScores>> {
            let score = if text.len() >= self.step_len {
                0.9
            } else {
                0.1
            };
            Ok(Some(RawScores {
                injection_score: score,
                predicted_label: if score >= 0.5 {
                    "INJECTION".to_string()
                } else {
                    "BENIGN".to_string()
                },
                jailbreak_score: None,
                benign_score: None,
            }))
        }
    }

    #[test]
    fn test_simulate_strategy_early_stop() {
        let precomputed = vec![
            (0.2, Some(0.1)),
            (0.4, Some(0.3)),
            (0.6, Some(0.8)),
            (0.8, Some(0.9)),
            (1.0, Some(0.95)),
        ];
        let strategy = CheckpointStrategy {
            name: "quintiles".into(),
            checkpoints: vec![0.2, 0.4, 0.6, 0.8, 1.0],
        };
        let (det_cp, det_score, calls) = simulate_strategy(&precomputed, &strategy, 0.5);
        assert_eq!(det_cp, Some(0.6));
        assert_eq!(det_score, Some(0.8));
        assert_eq!(calls, 3);
    }

    #[test]
    fn test_simulate_strategy_no_detection() {
        let precomputed = vec![(0.5, Some(0.1)), (1.0, Some(0.3))];
        let strategy = CheckpointStrategy {
            name: "half_full".into(),
            checkpoints: vec![0.5, 1.0],
        };
        let (det_cp, _det_score, calls) = simulate_strategy(&precomputed, &strategy, 0.5);
        assert!(det_cp.is_none());
        assert_eq!(calls, 2);
    }

    #[test]
    fn test_simulate_strategy_skips_none_scores() {
        let precomputed = vec![
            (0.1, None),      // prefix too short
            (0.5, Some(0.8)), // detected here
            (1.0, Some(0.95)),
        ];
        let strategy = CheckpointStrategy {
            name: "test".into(),
            checkpoints: vec![0.1, 0.5, 1.0],
        };
        let (det_cp, det_score, calls) = simulate_strategy(&precomputed, &strategy, 0.5);
        assert_eq!(det_cp, Some(0.5));
        assert_eq!(det_score, Some(0.8));
        assert_eq!(calls, 1); // only 0.5 counted (0.1 was None, skipped)
    }

    #[test]
    fn test_collect_unique_fractions() {
        let strategies = vec![
            CheckpointStrategy {
                name: "a".into(),
                checkpoints: vec![0.5, 1.0],
            },
            CheckpointStrategy {
                name: "b".into(),
                checkpoints: vec![0.2, 0.5, 1.0],
            },
        ];
        let fractions = collect_unique_fractions(&strategies);
        assert_eq!(fractions.len(), 3);
        assert!((fractions[0] - 0.2).abs() < 1e-9);
        assert!((fractions[1] - 0.5).abs() < 1e-9);
        assert!((fractions[2] - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_pareto_frontier() {
        let base = CheckpointStrategyMetrics {
            detector: "D".into(),
            suite: "S".into(),
            strategy: String::new(),
            num_checkpoints: 0,
            num_samples: 10,
            tp: 0,
            fp: 0,
            tpr: 0.0,
            fpr: 0.0,
            mean_detection_latency: 0.0,
            median_detection_latency: 0.0,
            mean_inference_calls: 0.0,
            is_pareto: false,
        };

        let mut metrics = vec![
            // A: low cost, good TPR -> Pareto
            CheckpointStrategyMetrics {
                strategy: "A".into(),
                tpr: 0.9,
                mean_inference_calls: 1.5,
                ..base.clone()
            },
            // B: higher cost, same TPR -> dominated by A
            CheckpointStrategyMetrics {
                strategy: "B".into(),
                tpr: 0.9,
                mean_inference_calls: 3.0,
                ..base.clone()
            },
            // C: highest cost, higher TPR -> Pareto
            CheckpointStrategyMetrics {
                strategy: "C".into(),
                tpr: 1.0,
                mean_inference_calls: 4.0,
                ..base
            },
        ];

        mark_pareto_frontier(&mut metrics);
        assert!(metrics[0].is_pareto, "A: low cost, good TPR");
        assert!(!metrics[1].is_pareto, "B: dominated by A");
        assert!(metrics[2].is_pareto, "C: highest TPR");
    }

    #[test]
    fn test_precompute_scores() {
        let detector = StepDetector { step_len: 50 };
        let text = "a".repeat(100);
        let fractions = vec![0.2, 0.5, 1.0];
        let precomputed = precompute_scores(&detector, &text, &fractions);
        assert_eq!(precomputed.len(), 3);
        // 20% of 100 = 20 chars -> below step_len 50 -> score 0.1
        assert!((precomputed[0].1.unwrap() - 0.1).abs() < 1e-6);
        // 50% of 100 = 50 chars -> at step_len 50 -> score 0.9
        assert!((precomputed[1].1.unwrap() - 0.9).abs() < 1e-6);
        // 100% of 100 = 100 chars -> above step_len -> score 0.9
        assert!((precomputed[2].1.unwrap() - 0.9).abs() < 1e-6);
    }
}
