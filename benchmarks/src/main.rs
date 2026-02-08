//! Benchmark runner binary for CI regression gates.
//!
//! Runs all benchmark suites against all available analyzers (regex + ML),
//! checks results against regression thresholds, prints paper-table output,
//! saves JSON results, and exits with code 1 on any regression.
//!
//! Usage:
//!   cargo run --bin benchmarks
//!   cargo run --bin benchmarks -- --output-dir benchmarks/results
//!   cargo run --bin benchmarks -- --suite standard --suite encoding

use clap::Parser;
use llmtrace_benchmarks::datasets::{BenchmarkSample, DatasetLoader};
use llmtrace_benchmarks::metrics::{tpr_at_fpr, BenchmarkMetrics};
use llmtrace_benchmarks::regression;
use llmtrace_benchmarks::regression::RegressionResult;
use llmtrace_benchmarks::runners::cyberseceval2;
use llmtrace_benchmarks::runners::notinject::{print_full_report, run_notinject_evaluation_async};
use llmtrace_benchmarks::runners::{BenchmarkResult, BenchmarkRunner};
use llmtrace_core::{AnalysisContext, SecurityAnalyzer, TenantId};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "benchmarks", about = "LLMTrace benchmark regression runner")]
struct Cli {
    /// Directory to write JSON result files.
    #[arg(long, default_value = "benchmarks/results")]
    output_dir: PathBuf,

    /// Path to the datasets directory (defaults to <crate>/datasets).
    #[arg(long)]
    datasets_dir: Option<PathBuf>,

    /// Run only the specified suite(s). Omit to run all.
    /// Valid values: standard, encoding, notinject, fpr, safeguard_v2, deepset_v2,
    /// ivanleomk_v2, cyberseceval2, harmbench, ailuminate, injecagent, asb, bipia
    #[arg(long)]
    suite: Vec<String>,

    /// Fail immediately if no ML analyzer could load its model.
    #[arg(long)]
    require_ml: bool,
}

struct NamedAnalyzer {
    name: &'static str,
    analyzer: Box<dyn SecurityAnalyzer>,
}

/// Configuration for a dataset suite that follows the standard load-run-check pattern.
struct ExternalSuiteConfig {
    suite_key: &'static str,
    display_name: &'static str,
    benchmark_name: &'static str,
    loader: fn(&Path) -> Result<Vec<BenchmarkSample>, String>,
    regression_checker: fn(&BenchmarkMetrics) -> RegressionResult,
}

const EXTERNAL_SUITES: &[ExternalSuiteConfig] = &[
    ExternalSuiteConfig {
        suite_key: "encoding",
        display_name: "Encoding Evasion",
        benchmark_name: "Encoding Evasion",
        loader: DatasetLoader::load_encoding_evasion,
        regression_checker: regression::check_encoding,
    },
    ExternalSuiteConfig {
        suite_key: "safeguard_v2",
        display_name: "SafeGuard",
        benchmark_name: "SafeGuard External",
        loader: DatasetLoader::load_safeguard_samples,
        regression_checker: regression::check_safeguard,
    },
    ExternalSuiteConfig {
        suite_key: "deepset_v2",
        display_name: "Deepset",
        benchmark_name: "Deepset External",
        loader: DatasetLoader::load_deepset_v2_samples,
        regression_checker: regression::check_deepset,
    },
    ExternalSuiteConfig {
        suite_key: "ivanleomk_v2",
        display_name: "IvanLeoMK",
        benchmark_name: "IvanLeoMK External",
        loader: DatasetLoader::load_ivanleomk_v2_samples,
        regression_checker: regression::check_ivanleomk,
    },
    ExternalSuiteConfig {
        suite_key: "harmbench",
        display_name: "HarmBench",
        benchmark_name: "HarmBench External",
        loader: DatasetLoader::load_harmbench_samples,
        regression_checker: regression::check_harmbench,
    },
    ExternalSuiteConfig {
        suite_key: "ailuminate",
        display_name: "AILuminate",
        benchmark_name: "AILuminate External",
        loader: DatasetLoader::load_ailuminate_samples,
        regression_checker: regression::check_ailuminate,
    },
    ExternalSuiteConfig {
        suite_key: "injecagent",
        display_name: "InjecAgent",
        benchmark_name: "InjecAgent External",
        loader: DatasetLoader::load_injecagent_samples,
        regression_checker: regression::check_injecagent,
    },
    ExternalSuiteConfig {
        suite_key: "asb",
        display_name: "ASB",
        benchmark_name: "ASB External",
        loader: DatasetLoader::load_asb_samples,
        regression_checker: regression::check_asb,
    },
    ExternalSuiteConfig {
        suite_key: "bipia",
        display_name: "BIPIA",
        benchmark_name: "BIPIA External",
        loader: DatasetLoader::load_bipia_samples,
        regression_checker: regression::check_bipia,
    },
];

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    let datasets_dir = cli
        .datasets_dir
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    let analyzers = build_analyzers().await;

    let has_ml = analyzers.iter().any(|a| a.name != "Regex");
    if cli.require_ml && !has_ml {
        eprintln!("Error: --require-ml set but no ML analyzer loaded successfully");
        std::process::exit(1);
    }

    let run_all = cli.suite.is_empty();
    let should_run = |name: &str| run_all || cli.suite.iter().any(|s| s == name);

    let mut all_results: Vec<BenchmarkResult> = Vec::new();
    let mut regression_results: Vec<RegressionResult> = Vec::new();

    for named in &analyzers {
        println!("\n{}", "=".repeat(60));
        println!("  Analyzer: {}", named.name);
        println!("{}", "=".repeat(60));

        if should_run("standard") {
            println!(
                "\n=== Suite: Standard Injection/Benign [{}] ===",
                named.name
            );
            match run_standard_suite(named.analyzer.as_ref(), &datasets_dir, named.name).await {
                Ok((result, reg)) => {
                    all_results.push(result);
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!("Standard suite failed for {}: {e}", named.name);
                    regression_results.push(RegressionResult {
                        suite_name: format!("Standard ({})", named.name),
                        passed: false,
                        violations: vec![format!("suite error: {e}")],
                    });
                }
            }
        }

        if should_run("notinject") {
            println!("\n=== Suite: NotInject 3D [{}] ===", named.name);
            match run_notinject_suite(named.analyzer.as_ref(), &datasets_dir, named.name).await {
                Ok(reg) => {
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!("NotInject suite failed for {}: {e}", named.name);
                    regression_results.push(RegressionResult {
                        suite_name: format!("NotInject 3D ({})", named.name),
                        passed: false,
                        violations: vec![format!("suite error: {e}")],
                    });
                }
            }
        }

        if should_run("fpr") {
            println!("\n=== Suite: FPR Calibration [{}] ===", named.name);
            match run_fpr_suite(named.analyzer.as_ref(), &datasets_dir, named.name).await {
                Ok(reg) => {
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!("FPR Calibration suite failed for {}: {e}", named.name);
                    regression_results.push(RegressionResult {
                        suite_name: format!("FPR Calibration ({})", named.name),
                        passed: false,
                        violations: vec![format!("suite error: {e}")],
                    });
                }
            }
        }

        if should_run("cyberseceval2") {
            println!("\n=== Suite: CyberSecEval2 External [{}] ===", named.name);
            match run_cyberseceval2_suite(named.analyzer.as_ref(), &datasets_dir, named.name).await
            {
                Ok((result, reg)) => {
                    all_results.push(result);
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!("CyberSecEval2 suite failed for {}: {e}", named.name);
                    regression_results.push(RegressionResult {
                        suite_name: format!("CyberSecEval2 ({})", named.name),
                        passed: false,
                        violations: vec![format!("suite error: {e}")],
                    });
                }
            }
        }

        for config in EXTERNAL_SUITES {
            if !should_run(config.suite_key) {
                continue;
            }
            println!(
                "\n=== Suite: {} [{}] ===",
                config.benchmark_name, named.name
            );
            match run_external_suite(config, named.analyzer.as_ref(), &datasets_dir, named.name)
                .await
            {
                Ok((result, reg)) => {
                    all_results.push(result);
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!(
                        "{} suite failed for {}: {e}",
                        config.display_name, named.name
                    );
                    regression_results.push(RegressionResult {
                        suite_name: format!("{} ({})", config.display_name, named.name),
                        passed: false,
                        violations: vec![format!("suite error: {e}")],
                    });
                }
            }
        }
    }

    if !all_results.is_empty() {
        BenchmarkRunner::print_paper_table(&all_results);
    }

    if !all_results.is_empty() {
        std::fs::create_dir_all(&cli.output_dir).unwrap_or_else(|e| {
            eprintln!("Warning: could not create output dir: {e}");
        });
        let json_path = cli.output_dir.join("benchmark_results.json");
        if let Err(e) = BenchmarkRunner::save_results(&all_results, &json_path) {
            eprintln!("Failed to save results: {e}");
        } else {
            println!("\nResults saved to {}", json_path.display());
        }
    }

    print_regression_summary(&regression_results);

    let any_failed = regression_results.iter().any(|r| !r.passed);
    if any_failed {
        std::process::exit(1);
    }
}

async fn build_analyzers() -> Vec<NamedAnalyzer> {
    let mut analyzers: Vec<NamedAnalyzer> = Vec::new();

    let regex = llmtrace_security::RegexSecurityAnalyzer::new()
        .expect("Failed to create RegexSecurityAnalyzer");
    analyzers.push(NamedAnalyzer {
        name: "Regex",
        analyzer: Box::new(regex),
    });

    // Ensemble is the default/recommended analyzer: regex + ML fusion.
    match llmtrace_security::EnsembleSecurityAnalyzer::new(
        &llmtrace_security::MLSecurityConfig::default(),
    )
    .await
    {
        Ok(a) => {
            println!(
                "Ensemble (recommended default): ml_active={}",
                a.is_ml_active()
            );
            if a.is_ml_active() {
                analyzers.push(NamedAnalyzer {
                    name: "Ensemble",
                    analyzer: Box::new(a),
                });
            } else {
                eprintln!("Warning: Ensemble ML not active (model not loaded), skipping (would duplicate Regex)");
            }
        }
        Err(e) => eprintln!("Warning: EnsembleSecurityAnalyzer init failed (skipping): {e}"),
    }

    // Standalone ML analyzers below are for comparison only.
    match llmtrace_security::PromptGuardAnalyzer::new(
        &llmtrace_security::PromptGuardConfig::default(),
    )
    .await
    {
        Ok(a) => {
            println!("PromptGuard: model_loaded={}", a.is_model_loaded());
            if a.is_model_loaded() {
                analyzers.push(NamedAnalyzer {
                    name: "PromptGuard",
                    analyzer: Box::new(a),
                });
            } else {
                eprintln!(
                    "Warning: PromptGuard model not loaded, skipping (would duplicate Regex)"
                );
            }
        }
        Err(e) => eprintln!("Warning: PromptGuardAnalyzer init failed (skipping): {e}"),
    }

    match llmtrace_security::InjecGuardAnalyzer::new(
        &llmtrace_security::InjecGuardConfig::default(),
    )
    .await
    {
        Ok(a) => {
            println!("InjecGuard: model_loaded={}", a.is_model_loaded());
            if a.is_model_loaded() {
                analyzers.push(NamedAnalyzer {
                    name: "InjecGuard",
                    analyzer: Box::new(a),
                });
            } else {
                eprintln!("Warning: InjecGuard model not loaded, skipping (would duplicate Regex)");
            }
        }
        Err(e) => eprintln!("Warning: InjecGuardAnalyzer init failed (skipping): {e}"),
    }

    match llmtrace_security::MLSecurityAnalyzer::new(
        &llmtrace_security::MLSecurityConfig::default(),
    )
    .await
    {
        Ok(a) => {
            println!("MLSecurity: model_loaded={}", a.is_model_loaded());
            if a.is_model_loaded() {
                analyzers.push(NamedAnalyzer {
                    name: "MLSecurity",
                    analyzer: Box::new(a),
                });
            } else {
                eprintln!("Warning: MLSecurity model not loaded, skipping (would duplicate Regex)");
            }
        }
        Err(e) => eprintln!("Warning: MLSecurityAnalyzer init failed (skipping): {e}"),
    }

    analyzers
}

fn make_context() -> AnalysisContext {
    AnalysisContext {
        tenant_id: TenantId::new(),
        trace_id: uuid::Uuid::new_v4(),
        span_id: uuid::Uuid::new_v4(),
        provider: llmtrace_core::LLMProvider::OpenAI,
        model_name: "benchmark".to_string(),
        parameters: std::collections::HashMap::new(),
    }
}

async fn run_standard_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<(BenchmarkResult, RegressionResult), String> {
    let mut samples = DatasetLoader::load_injection_samples(datasets_dir)?;
    samples.extend(DatasetLoader::load_benign_samples(datasets_dir)?);
    println!("Loaded {} samples", samples.len());

    let result = BenchmarkRunner::run_async_benchmark(
        analyzer,
        &samples,
        "Standard Injection/Benign",
        analyzer_name,
    )
    .await;
    result
        .metrics
        .print_summary(&format!("Standard Injection/Benign ({})", analyzer_name));

    let reg_result = regression::check_standard(&result.metrics);
    let reg = RegressionResult {
        suite_name: format!("Standard ({})", analyzer_name),
        ..reg_result
    };
    Ok((result, reg))
}

async fn run_notinject_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<RegressionResult, String> {
    let label = format!("LLMTrace {}", analyzer_name);
    let eval = run_notinject_evaluation_async(analyzer, datasets_dir, &label).await?;
    print_full_report(&eval);

    let reg_result = regression::check_notinject(&eval.metrics);
    let reg = RegressionResult {
        suite_name: format!("NotInject 3D ({})", analyzer_name),
        ..reg_result
    };
    Ok(reg)
}

async fn run_fpr_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<RegressionResult, String> {
    let mut all_samples = DatasetLoader::load_injection_samples(datasets_dir)?;
    all_samples.extend(DatasetLoader::load_benign_samples(datasets_dir)?);
    all_samples.extend(DatasetLoader::load_encoding_evasion(datasets_dir)?);
    println!("Loaded {} samples for FPR calibration", all_samples.len());

    let context = make_context();
    let mut scores: Vec<(f64, bool)> = Vec::with_capacity(all_samples.len());

    for s in &all_samples {
        let findings = analyzer
            .analyze_request(&s.text, &context)
            .await
            .unwrap_or_default();
        let max_confidence = findings
            .iter()
            .map(|f| f.confidence_score)
            .fold(0.0_f64, f64::max);
        let is_malicious = s.label == llmtrace_benchmarks::datasets::Label::Malicious;
        scores.push((max_confidence, is_malicious));
    }

    let fpr_thresholds = [0.001, 0.005, 0.01];
    println!("\nFPR Calibration Results ({}):", analyzer_name);
    println!("{:<15} {:<15} {:<15}", "Target FPR", "TPR", "Threshold");
    println!("{:-<45}", "");

    let mut tpr_at_1pct = 0.0;
    for target in &fpr_thresholds {
        let (tpr, threshold) = tpr_at_fpr(&scores, *target);
        println!(
            "{:.3}%          {:.2}%          {:.4}",
            target * 100.0,
            tpr * 100.0,
            threshold
        );
        if (*target - 0.01).abs() < f64::EPSILON {
            tpr_at_1pct = tpr;
        }
    }

    let reg_result = regression::check_fpr_calibration(tpr_at_1pct);
    let reg = RegressionResult {
        suite_name: format!("FPR Calibration ({})", analyzer_name),
        ..reg_result
    };
    Ok(reg)
}

async fn run_cyberseceval2_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<(BenchmarkResult, RegressionResult), String> {
    let label = format!("LLMTrace {}", analyzer_name);
    let eval =
        cyberseceval2::run_cyberseceval2_evaluation_async(analyzer, datasets_dir, &label).await?;
    cyberseceval2::print_full_report(&eval);

    let result = BenchmarkResult {
        benchmark_name: "CyberSecEval2 External".to_string(),
        config_name: analyzer_name.to_string(),
        metrics: eval.metrics.clone(),
        total_duration_ms: eval.duration_ms,
        avg_sample_us: if eval.num_samples > 0 {
            (eval.duration_ms * 1000) / eval.num_samples as u64
        } else {
            0
        },
        num_samples: eval.num_samples,
        timestamp: chrono::Utc::now().to_rfc3339(),
        sample_results: Vec::new(),
    };

    let reg_result = regression::check_cyberseceval2(&eval.metrics);
    let reg = RegressionResult {
        suite_name: format!("CyberSecEval2 ({})", analyzer_name),
        ..reg_result
    };
    Ok((result, reg))
}

async fn run_external_suite(
    config: &ExternalSuiteConfig,
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<(BenchmarkResult, RegressionResult), String> {
    let samples = (config.loader)(datasets_dir)?;
    println!("Loaded {} {} samples", samples.len(), config.display_name);

    let result = BenchmarkRunner::run_async_benchmark(
        analyzer,
        &samples,
        config.benchmark_name,
        analyzer_name,
    )
    .await;
    result
        .metrics
        .print_summary(&format!("{} ({})", config.benchmark_name, analyzer_name));

    let reg_result = (config.regression_checker)(&result.metrics);
    let reg = RegressionResult {
        suite_name: format!("{} ({})", config.display_name, analyzer_name),
        ..reg_result
    };
    Ok((result, reg))
}

fn print_regression_summary(results: &[RegressionResult]) {
    println!("\n{}", "=".repeat(60));
    println!("  Regression Gate Summary");
    println!("{}", "=".repeat(60));

    for r in results {
        let status = if r.passed { "PASS" } else { "FAIL" };
        println!("  [{}] {}", status, r.suite_name);
        for v in &r.violations {
            println!("       - {}", v);
        }
    }

    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();
    println!("\n  Result: {}/{} suites passed", passed, total);

    if passed == total {
        println!("  All regression gates passed.");
    } else {
        println!("  REGRESSION DETECTED -- exiting with code 1.");
    }
    println!("{}", "=".repeat(60));
}
