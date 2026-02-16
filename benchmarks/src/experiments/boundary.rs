//! Experiment B: Injection boundary detection.
//!
//! For malicious samples that are true positives at full text, uses binary
//! search to find the earliest character position where model confidence
//! first crosses threshold levels (0.5, 0.7, 0.9).
//!
//! Uses first-crossing semantics: the boundary is the smallest prefix
//! where `score >= threshold`.

use std::time::Instant;

use crate::datasets::{BenchmarkSample, Label};

use super::truncation::RawScoreDetector;
use super::types::{
    suite_direction, BoundaryExperimentResult, BoundarySampleResult, BoundaryThreshold,
};

/// Default confidence thresholds for boundary detection.
pub const DEFAULT_BOUNDARY_THRESHOLDS: &[f64] = &[0.5, 0.7, 0.9];

/// Minimum prefix length in characters to attempt inference.
/// Below this, DeBERTa models produce degenerate outputs.
const MIN_PREFIX_CHARS: usize = 10;

/// Binary search resolution: stop when the search window is smaller than
/// this many characters. Keeps inference calls bounded at ~log2(text_len/RESOLUTION).
const SEARCH_RESOLUTION_CHARS: usize = 5;

/// Find the first-crossing boundary for a single threshold using binary search.
///
/// Returns `(boundary_char_pos, inference_calls)` where `boundary_char_pos` is
/// the smallest prefix length (in chars) where `score >= threshold`, or `None`
/// if the threshold is never crossed even at full text.
fn find_boundary(
    detector: &dyn RawScoreDetector,
    text: &str,
    threshold: f64,
) -> (Option<usize>, u32) {
    let text_len = text.len();
    if text_len < MIN_PREFIX_CHARS {
        return (None, 0);
    }

    // Collect char boundary positions for snapping
    let char_positions: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
    let num_chars = char_positions.len();

    // Binary search over char indices
    let mut lo: usize; // index into char_positions
    let mut hi: usize; // exclusive upper bound
    let mut calls: u32 = 0;
    let mut found = false;

    // First: verify that full text crosses the threshold at all
    let full_score = match detector.score(text) {
        Ok(Some(s)) => s.injection_score,
        _ => return (None, 1),
    };
    calls += 1;

    if full_score < threshold {
        return (None, calls);
    }

    // Find the minimum char index lo_idx where char_positions[lo_idx..] gives
    // a prefix with byte length >= MIN_PREFIX_CHARS
    let min_idx = char_positions
        .iter()
        .position(|&pos| pos >= MIN_PREFIX_CHARS)
        .unwrap_or(num_chars);
    lo = min_idx;
    hi = num_chars;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let prefix_byte_end = if mid < num_chars {
            char_positions[mid]
        } else {
            text_len
        };

        // Snap to actual char boundary via truncate_text fraction
        let prefix = &text[..prefix_byte_end];
        if prefix.len() < MIN_PREFIX_CHARS {
            lo = mid + 1;
            continue;
        }

        let score = match detector.score(prefix) {
            Ok(Some(s)) => s.injection_score,
            _ => {
                calls += 1;
                lo = mid + 1;
                continue;
            }
        };
        calls += 1;

        if score >= threshold {
            found = true;
            hi = mid;
        } else {
            lo = mid + 1;
        }

        // Stop if the window is below resolution
        let lo_bytes = if lo < num_chars {
            char_positions[lo]
        } else {
            text_len
        };
        let hi_bytes = if hi < num_chars {
            char_positions[hi]
        } else {
            text_len
        };
        if hi_bytes.saturating_sub(lo_bytes) <= SEARCH_RESOLUTION_CHARS {
            break;
        }
    }

    if found {
        let boundary_bytes = if hi < num_chars {
            char_positions[hi]
        } else {
            text_len
        };
        (Some(boundary_bytes), calls)
    } else {
        // Full text crosses but binary search didn't converge --
        // the boundary is at or near full text length
        (Some(text_len), calls)
    }
}

/// Run the boundary detection experiment.
///
/// For each malicious sample in each suite, checks if the detector classifies
/// it correctly at full text. If yes, runs binary search for each threshold
/// to find the earliest detection point.
pub fn run_boundary_experiment(
    detectors: &[&dyn RawScoreDetector],
    suites: &[(&str, &[BenchmarkSample])],
    thresholds: &[f64],
) -> BoundaryExperimentResult {
    let start = Instant::now();
    let mut sample_results: Vec<BoundarySampleResult> = Vec::new();

    let total_detectors = detectors.len();
    let total_suites = suites.len();

    for (d_idx, detector) in detectors.iter().enumerate() {
        for (s_idx, (suite_name, samples)) in suites.iter().enumerate() {
            let malicious: Vec<&BenchmarkSample> = samples
                .iter()
                .filter(|s| s.label == Label::Malicious)
                .collect();

            println!(
                "  [{}/{}] {} | {} | {} malicious samples",
                d_idx * total_suites + s_idx + 1,
                total_detectors * total_suites,
                detector.name(),
                suite_name,
                malicious.len(),
            );

            for sample in &malicious {
                // Full-text baseline
                let full_score = match detector.score(&sample.text) {
                    Ok(Some(s)) => s.injection_score,
                    Ok(None) => continue,
                    Err(_) => continue,
                };

                // Skip samples where the detector doesn't detect at full text
                // (can't measure boundary if there's no detection)
                let min_threshold = thresholds.iter().copied().fold(f64::INFINITY, f64::min);
                if full_score < min_threshold {
                    continue;
                }

                let mut boundaries: Vec<BoundaryThreshold> = Vec::new();
                let mut total_calls: u32 = 1; // already called full text once

                for &threshold in thresholds {
                    if full_score < threshold {
                        // This threshold is never crossed
                        boundaries.push(BoundaryThreshold {
                            threshold,
                            boundary_fraction: None,
                            boundary_char_pos: None,
                        });
                        continue;
                    }

                    let (boundary_pos, calls) = find_boundary(*detector, &sample.text, threshold);
                    total_calls += calls;

                    boundaries.push(BoundaryThreshold {
                        threshold,
                        boundary_fraction: boundary_pos
                            .map(|pos| pos as f64 / sample.text.len() as f64),
                        boundary_char_pos: boundary_pos,
                    });
                }

                sample_results.push(BoundarySampleResult {
                    sample_id: sample.id.clone(),
                    suite: suite_name.to_string(),
                    original_char_len: sample.text.len(),
                    detector: detector.name().to_string(),
                    full_text_score: full_score,
                    boundaries,
                    inference_calls: total_calls,
                });
            }
        }
    }

    let total_duration_ms = start.elapsed().as_millis() as u64;

    BoundaryExperimentResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_duration_ms,
        sample_results,
    }
}

/// Print a summary of boundary detection results.
pub fn print_boundary_summary(result: &BoundaryExperimentResult) {
    println!("\n{}", "=".repeat(100));
    println!("  EXPERIMENT B: Injection Boundary Detection");
    println!("{}", "=".repeat(100));
    println!(
        "  Total samples: {}  |  Duration: {:.1}s",
        result.sample_results.len(),
        result.total_duration_ms as f64 / 1000.0
    );

    // Group by detector
    let mut detectors: Vec<&str> = result
        .sample_results
        .iter()
        .map(|s| s.detector.as_str())
        .collect();
    detectors.sort();
    detectors.dedup();

    // Collect all thresholds from the results
    let thresholds: Vec<f64> = result
        .sample_results
        .first()
        .map(|s| s.boundaries.iter().map(|b| b.threshold).collect())
        .unwrap_or_default();

    for detector in detectors {
        let detector_results: Vec<&BoundarySampleResult> = result
            .sample_results
            .iter()
            .filter(|s| s.detector == detector)
            .collect();

        println!(
            "\n--- {} ({} samples) ---",
            detector,
            detector_results.len()
        );

        for &threshold in &thresholds {
            let fractions: Vec<f64> = detector_results
                .iter()
                .filter_map(|s| {
                    s.boundaries
                        .iter()
                        .find(|b| (b.threshold - threshold).abs() < 1e-6)
                        .and_then(|b| b.boundary_fraction)
                })
                .collect();

            if fractions.is_empty() {
                println!("  threshold={:.1}: no crossings", threshold);
                continue;
            }

            let mut sorted = fractions.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let n = sorted.len();
            let total_eligible = detector_results.len();

            let median = if n.is_multiple_of(2) {
                (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
            } else {
                sorted[n / 2]
            };
            let p25 = sorted[n / 4];
            let p75 = sorted[3 * n / 4];
            let below_50pct = sorted.iter().filter(|&&f| f < 0.5).count();

            println!(
                "  threshold={:.1}: median={:.1}%, P25={:.1}%, P75={:.1}%, detected_before_50%={}/{} ({:.0}%), coverage={}/{}",
                threshold,
                median * 100.0,
                p25 * 100.0,
                p75 * 100.0,
                below_50pct,
                n,
                below_50pct as f64 / n as f64 * 100.0,
                n,
                total_eligible,
            );
        }

        // Inference cost summary
        let total_calls: u32 = detector_results.iter().map(|s| s.inference_calls).sum();
        let avg_calls = total_calls as f64 / detector_results.len().max(1) as f64;
        println!(
            "  inference: total={}, avg={:.1} calls/sample",
            total_calls, avg_calls
        );
    }

    // Direction-grouped summary
    print_boundary_direction_summary(&result.sample_results, &thresholds);
}

/// Print boundary results grouped by direction (input vs output).
fn print_boundary_direction_summary(samples: &[BoundarySampleResult], thresholds: &[f64]) {
    println!("\n{}", "=".repeat(100));
    println!("  Direction Analysis (input=direct injection, output=indirect injection)");
    println!("{}", "=".repeat(100));

    let mut detectors: Vec<&str> = samples.iter().map(|s| s.detector.as_str()).collect();
    detectors.sort();
    detectors.dedup();

    for detector in &detectors {
        println!("\n--- {} ---", detector);

        for direction in &["input", "output"] {
            let dir_results: Vec<&BoundarySampleResult> = samples
                .iter()
                .filter(|s| s.detector == *detector && suite_direction(&s.suite) == *direction)
                .collect();

            if dir_results.is_empty() {
                continue;
            }

            println!("  [{}] {} samples", direction, dir_results.len());

            for &threshold in thresholds {
                let fractions: Vec<f64> = dir_results
                    .iter()
                    .filter_map(|s| {
                        s.boundaries
                            .iter()
                            .find(|b| (b.threshold - threshold).abs() < 1e-6)
                            .and_then(|b| b.boundary_fraction)
                    })
                    .collect();

                if fractions.is_empty() {
                    println!("    threshold={:.1}: no crossings", threshold);
                    continue;
                }

                let mut sorted = fractions.clone();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let n = sorted.len();
                let median = if n.is_multiple_of(2) {
                    (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
                } else {
                    sorted[n / 2]
                };
                let below_50pct = sorted.iter().filter(|&&f| f < 0.5).count();

                println!(
                    "    threshold={:.1}: median={:.1}%, detected_before_50%={}/{} ({:.0}%)",
                    threshold,
                    median * 100.0,
                    below_50pct,
                    n,
                    below_50pct as f64 / n as f64 * 100.0,
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

    /// A mock detector that returns injection_score = fraction of text length
    /// relative to a fixed "full text" length. Useful for testing binary search.
    struct LinearDetector {
        full_len: usize,
    }

    impl RawScoreDetector for LinearDetector {
        fn name(&self) -> &str {
            "LinearTest"
        }

        fn score(&self, text: &str) -> llmtrace_core::Result<Option<RawScores>> {
            let score = text.len() as f64 / self.full_len as f64;
            Ok(Some(RawScores {
                injection_score: score.min(1.0),
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
    fn test_find_boundary_linear_detector() {
        // For a linear detector where score = prefix_len / full_len,
        // threshold 0.5 should be found at ~50% of text
        let text = "a]".repeat(100); // 200 bytes
        let detector = LinearDetector { full_len: 200 };

        let (boundary, calls) = find_boundary(&detector, &text, 0.5);
        assert!(boundary.is_some());
        let pos = boundary.unwrap();
        // Should be roughly 50% of 200 = 100, with some search resolution tolerance
        assert!(
            (90..=115).contains(&pos),
            "boundary={pos} should be near 100"
        );
        assert!(calls <= 15, "binary search should be O(log n), got {calls}");
    }

    #[test]
    fn test_find_boundary_never_crosses() {
        // Detector that always returns 0.3 -- threshold 0.5 never crossed
        struct LowScoreDetector;
        impl RawScoreDetector for LowScoreDetector {
            fn name(&self) -> &str {
                "LowScore"
            }
            fn score(&self, _text: &str) -> llmtrace_core::Result<Option<RawScores>> {
                Ok(Some(RawScores {
                    injection_score: 0.3,
                    predicted_label: "BENIGN".to_string(),
                    jailbreak_score: None,
                    benign_score: None,
                }))
            }
        }

        let text = "a".repeat(100);
        let (boundary, _) = find_boundary(&LowScoreDetector, &text, 0.5);
        assert!(boundary.is_none());
    }

    #[test]
    fn test_find_boundary_short_text() {
        let detector = LinearDetector { full_len: 5 };
        let (boundary, calls) = find_boundary(&detector, "hi", 0.5);
        assert!(boundary.is_none());
        assert_eq!(calls, 0);
    }
}
