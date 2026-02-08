//! Benchmark runner framework for LLMTrace evaluations.
//!
//! Provides a structured runner that:
//! 1. Loads datasets from the `datasets/` directory
//! 2. Runs LLMTrace security analysis on each sample
//! 3. Computes metrics using the `metrics` module
//! 4. Outputs results in paper-table format
//!
//! # Paper Table Output
//!
//! Results are formatted for direct inclusion in academic papers:
//!
//! ```text
//! | Model / Config                 |     Acc |    Prec |     Rec |      F1 |     FPR |     ASR |
//! |--------------------------------|---------|---------|---------|---------|---------|---------|
//! | LLMTrace Regex                 | 89.29%  | 94.12%  | 88.89%  | 91.43%  |  10.00% |  11.11% |
//! | LLMTrace Ensemble              | 92.14%  | 96.00%  | 90.00%  | 92.90%  |   5.00% |  10.00% |
//! | SOTA: InjecGuard               | 83.48%  | N/A     | 77.39%  | N/A     |  12.68% |  22.61% |
//! | SOTA: ProtectAI v2             | 63.81%  | N/A     | 48.60%  | N/A     |  13.80% |  51.40% |
//! ```

pub mod cyberseceval2;
pub mod notinject;

use crate::datasets::{BenchmarkSample, Label};
use crate::metrics::{BenchmarkMetrics, ConfusionMatrix};
use llmtrace_core::{AnalysisContext, SecurityAnalyzer, TenantId};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Result of a single benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Name of the benchmark.
    pub benchmark_name: String,
    /// Configuration used.
    pub config_name: String,
    /// Metrics computed from the run.
    pub metrics: BenchmarkMetrics,
    /// Total time for the benchmark run.
    pub total_duration_ms: u64,
    /// Average time per sample in microseconds.
    pub avg_sample_us: u64,
    /// Number of samples evaluated.
    pub num_samples: usize,
    /// Timestamp of the run.
    pub timestamp: String,
    /// Per-sample results (for debugging).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sample_results: Vec<SampleResult>,
}

/// Result for a single sample evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleResult {
    /// Sample ID.
    pub sample_id: String,
    /// Ground truth label.
    pub actual_malicious: bool,
    /// Predicted label.
    pub predicted_malicious: bool,
    /// Confidence score from the detector.
    pub confidence: f64,
    /// Number of findings.
    pub num_findings: usize,
    /// Processing time in microseconds.
    pub duration_us: u64,
}

/// Benchmark runner that evaluates security analyzers against test datasets.
pub struct BenchmarkRunner;

impl BenchmarkRunner {
    /// Run a benchmark using the synchronous regex-based detection.
    ///
    /// This uses `detect_injection_patterns` directly (non-async) for
    /// maximum throughput measurement.
    pub fn run_regex_benchmark(
        analyzer: &llmtrace_security::RegexSecurityAnalyzer,
        samples: &[BenchmarkSample],
        benchmark_name: &str,
        config_name: &str,
    ) -> BenchmarkResult {
        let mut cm = ConfusionMatrix::new();
        let mut sample_results = Vec::with_capacity(samples.len());
        let start = Instant::now();

        for sample in samples {
            let sample_start = Instant::now();
            let findings = analyzer.detect_injection_patterns(&sample.text);
            let duration = sample_start.elapsed();

            let predicted_malicious = !findings.is_empty();
            let actual_malicious = sample.label == Label::Malicious;
            cm.record(actual_malicious, predicted_malicious);

            let max_confidence = findings
                .iter()
                .map(|f| f.confidence_score)
                .fold(0.0_f64, f64::max);

            sample_results.push(SampleResult {
                sample_id: sample.id.clone(),
                actual_malicious,
                predicted_malicious,
                confidence: max_confidence,
                num_findings: findings.len(),
                duration_us: duration.as_micros() as u64,
            });
        }

        let total_duration = start.elapsed();
        let metrics = BenchmarkMetrics::from_confusion_matrix(&cm);
        let avg_sample_us = if samples.is_empty() {
            0
        } else {
            total_duration.as_micros() as u64 / samples.len() as u64
        };

        BenchmarkResult {
            benchmark_name: benchmark_name.to_string(),
            config_name: config_name.to_string(),
            metrics,
            total_duration_ms: total_duration.as_millis() as u64,
            avg_sample_us,
            num_samples: samples.len(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            sample_results,
        }
    }

    /// Run a benchmark using the async SecurityAnalyzer trait.
    ///
    /// Works with any analyzer implementing `SecurityAnalyzer` (regex, ML, ensemble).
    pub async fn run_async_benchmark(
        analyzer: &dyn SecurityAnalyzer,
        samples: &[BenchmarkSample],
        benchmark_name: &str,
        config_name: &str,
    ) -> BenchmarkResult {
        let context = AnalysisContext {
            tenant_id: TenantId::new(),
            trace_id: uuid::Uuid::new_v4(),
            span_id: uuid::Uuid::new_v4(),
            provider: llmtrace_core::LLMProvider::OpenAI,
            model_name: "benchmark".to_string(),
            parameters: std::collections::HashMap::new(),
        };

        let mut cm = ConfusionMatrix::new();
        let mut sample_results = Vec::with_capacity(samples.len());
        let start = Instant::now();

        for sample in samples {
            let sample_start = Instant::now();
            let findings = analyzer
                .analyze_request(&sample.text, &context)
                .await
                .unwrap_or_default();
            let duration = sample_start.elapsed();

            let predicted_malicious = !findings.is_empty();
            let actual_malicious = sample.label == Label::Malicious;
            cm.record(actual_malicious, predicted_malicious);

            let max_confidence = findings
                .iter()
                .map(|f| f.confidence_score)
                .fold(0.0_f64, f64::max);

            sample_results.push(SampleResult {
                sample_id: sample.id.clone(),
                actual_malicious,
                predicted_malicious,
                confidence: max_confidence,
                num_findings: findings.len(),
                duration_us: duration.as_micros() as u64,
            });
        }

        let total_duration = start.elapsed();
        let metrics = BenchmarkMetrics::from_confusion_matrix(&cm);
        let avg_sample_us = if samples.is_empty() {
            0
        } else {
            total_duration.as_micros() as u64 / samples.len() as u64
        };

        BenchmarkResult {
            benchmark_name: benchmark_name.to_string(),
            config_name: config_name.to_string(),
            metrics,
            total_duration_ms: total_duration.as_millis() as u64,
            avg_sample_us,
            num_samples: samples.len(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            sample_results,
        }
    }

    /// Print results as a paper-ready table.
    pub fn print_paper_table(results: &[BenchmarkResult]) {
        println!("\n{}", BenchmarkMetrics::table_header());
        println!("{}", BenchmarkMetrics::table_separator());
        for result in results {
            println!(
                "{}",
                result.metrics.to_table_row(&format!(
                    "{} ({})",
                    result.benchmark_name, result.config_name
                ))
            );
        }
    }

    /// Save results to a JSON file.
    pub fn save_results(results: &[BenchmarkResult], path: &std::path::Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(results)
            .map_err(|e| format!("Failed to serialise results: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("Failed to write {}: {e}", path.display()))
    }

    /// Print baseline comparison (what a random/naive classifier would achieve).
    pub fn print_baselines(num_malicious: usize, num_benign: usize) {
        let total = num_malicious + num_benign;
        println!("\n=== Baseline Comparisons ===");
        println!(
            "Dataset: {} malicious + {} benign = {} total",
            num_malicious, num_benign, total
        );

        // Random classifier (50% chance)
        println!("\nRandom Classifier (50%):");
        println!("  Accuracy:  50.00%");
        println!(
            "  Precision: {:.2}%",
            num_malicious as f64 / total as f64 * 100.0
        );
        println!("  Recall:    50.00%");
        println!("  FPR:       50.00%");

        // Always-positive classifier
        println!("\nAlways-Positive (flag everything):");
        println!(
            "  Accuracy:  {:.2}%",
            num_malicious as f64 / total as f64 * 100.0
        );
        println!(
            "  Precision: {:.2}%",
            num_malicious as f64 / total as f64 * 100.0
        );
        println!("  Recall:    100.00%");
        println!("  FPR:       100.00%");

        // Always-negative classifier
        println!("\nAlways-Negative (pass everything):");
        println!(
            "  Accuracy:  {:.2}%",
            num_benign as f64 / total as f64 * 100.0
        );
        println!("  Precision: N/A (no predictions)");
        println!("  Recall:    0.00%");
        println!("  FPR:       0.00%");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result_serialization() {
        let cm = ConfusionMatrix {
            tp: 10,
            tn: 10,
            fp: 1,
            fn_: 1,
        };
        let result = BenchmarkResult {
            benchmark_name: "test".to_string(),
            config_name: "default".to_string(),
            metrics: BenchmarkMetrics::from_confusion_matrix(&cm),
            total_duration_ms: 100,
            avg_sample_us: 1000,
            num_samples: 22,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            sample_results: Vec::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("accuracy"));
    }
}
