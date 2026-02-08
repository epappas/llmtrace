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
use llmtrace_benchmarks::datasets::DatasetLoader;
use llmtrace_benchmarks::metrics::tpr_at_fpr;
use llmtrace_benchmarks::regression;
use llmtrace_benchmarks::regression::RegressionResult;
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
    /// Valid values: standard, encoding, notinject, fpr, safeguard_v2, deepset_v2, ivanleomk_v2, cyberseceval2
    #[arg(long)]
    suite: Vec<String>,
}

struct NamedAnalyzer {
    name: &'static str,
    analyzer: Box<dyn SecurityAnalyzer>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let datasets_dir = cli
        .datasets_dir
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    let analyzers = build_analyzers().await;

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

        if should_run("encoding") {
            println!("\n=== Suite: Encoding Evasion [{}] ===", named.name);
            match run_encoding_suite(named.analyzer.as_ref(), &datasets_dir, named.name).await {
                Ok((result, reg)) => {
                    all_results.push(result);
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!("Encoding suite failed for {}: {e}", named.name);
                    regression_results.push(RegressionResult {
                        suite_name: format!("Encoding Evasion ({})", named.name),
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

        if should_run("safeguard_v2") {
            println!("\n=== Suite: SafeGuard External [{}] ===", named.name);
            match run_safeguard_suite(named.analyzer.as_ref(), &datasets_dir, named.name).await {
                Ok((result, reg)) => {
                    all_results.push(result);
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!("SafeGuard suite failed for {}: {e}", named.name);
                    regression_results.push(RegressionResult {
                        suite_name: format!("SafeGuard ({})", named.name),
                        passed: false,
                        violations: vec![format!("suite error: {e}")],
                    });
                }
            }
        }

        if should_run("deepset_v2") {
            println!("\n=== Suite: Deepset External [{}] ===", named.name);
            match run_deepset_suite(named.analyzer.as_ref(), &datasets_dir, named.name).await {
                Ok((result, reg)) => {
                    all_results.push(result);
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!("Deepset suite failed for {}: {e}", named.name);
                    regression_results.push(RegressionResult {
                        suite_name: format!("Deepset ({})", named.name),
                        passed: false,
                        violations: vec![format!("suite error: {e}")],
                    });
                }
            }
        }

        if should_run("ivanleomk_v2") {
            println!("\n=== Suite: IvanLeoMK External [{}] ===", named.name);
            match run_ivanleomk_suite(named.analyzer.as_ref(), &datasets_dir, named.name).await {
                Ok((result, reg)) => {
                    all_results.push(result);
                    regression_results.push(reg);
                }
                Err(e) => {
                    eprintln!("IvanLeoMK suite failed for {}: {e}", named.name);
                    regression_results.push(RegressionResult {
                        suite_name: format!("IvanLeoMK ({})", named.name),
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
            analyzers.push(NamedAnalyzer {
                name: "Ensemble",
                analyzer: Box::new(a),
            });
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
            analyzers.push(NamedAnalyzer {
                name: "PromptGuard",
                analyzer: Box::new(a),
            });
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
            analyzers.push(NamedAnalyzer {
                name: "InjecGuard",
                analyzer: Box::new(a),
            });
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
            analyzers.push(NamedAnalyzer {
                name: "MLSecurity",
                analyzer: Box::new(a),
            });
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

async fn run_encoding_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<(BenchmarkResult, RegressionResult), String> {
    let samples = DatasetLoader::load_encoding_evasion(datasets_dir)?;
    println!("Loaded {} samples", samples.len());

    let result =
        BenchmarkRunner::run_async_benchmark(analyzer, &samples, "Encoding Evasion", analyzer_name)
            .await;
    result
        .metrics
        .print_summary(&format!("Encoding Evasion ({})", analyzer_name));

    let reg_result = regression::check_encoding(&result.metrics);
    let reg = RegressionResult {
        suite_name: format!("Encoding Evasion ({})", analyzer_name),
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

async fn run_safeguard_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<(BenchmarkResult, RegressionResult), String> {
    let samples = DatasetLoader::load_safeguard_samples(datasets_dir)?;
    println!("Loaded {} SafeGuard samples", samples.len());

    let result = BenchmarkRunner::run_async_benchmark(
        analyzer,
        &samples,
        "SafeGuard External",
        analyzer_name,
    )
    .await;
    result
        .metrics
        .print_summary(&format!("SafeGuard External ({})", analyzer_name));

    let reg_result = regression::check_safeguard(&result.metrics);
    let reg = RegressionResult {
        suite_name: format!("SafeGuard ({})", analyzer_name),
        ..reg_result
    };
    Ok((result, reg))
}

async fn run_deepset_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<(BenchmarkResult, RegressionResult), String> {
    let samples = DatasetLoader::load_deepset_samples(datasets_dir)?;
    println!("Loaded {} Deepset samples", samples.len());

    let result =
        BenchmarkRunner::run_async_benchmark(analyzer, &samples, "Deepset External", analyzer_name)
            .await;
    result
        .metrics
        .print_summary(&format!("Deepset External ({})", analyzer_name));

    let reg_result = regression::check_deepset(&result.metrics);
    let reg = RegressionResult {
        suite_name: format!("Deepset ({})", analyzer_name),
        ..reg_result
    };
    Ok((result, reg))
}

async fn run_ivanleomk_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<(BenchmarkResult, RegressionResult), String> {
    let samples = DatasetLoader::load_ivanleomk_samples(datasets_dir)?;
    println!("Loaded {} IvanLeoMK samples", samples.len());

    let result = BenchmarkRunner::run_async_benchmark(
        analyzer,
        &samples,
        "IvanLeoMK External",
        analyzer_name,
    )
    .await;
    result
        .metrics
        .print_summary(&format!("IvanLeoMK External ({})", analyzer_name));

    let reg_result = regression::check_ivanleomk(&result.metrics);
    let reg = RegressionResult {
        suite_name: format!("IvanLeoMK ({})", analyzer_name),
        ..reg_result
    };
    Ok((result, reg))
}

async fn run_cyberseceval2_suite(
    analyzer: &dyn SecurityAnalyzer,
    datasets_dir: &Path,
    analyzer_name: &str,
) -> Result<(BenchmarkResult, RegressionResult), String> {
    let samples = DatasetLoader::load_cyberseceval2_samples(datasets_dir)?;
    println!("Loaded {} CyberSecEval2 samples", samples.len());

    let result = BenchmarkRunner::run_async_benchmark(
        analyzer,
        &samples,
        "CyberSecEval2 External",
        analyzer_name,
    )
    .await;
    result
        .metrics
        .print_summary(&format!("CyberSecEval2 External ({})", analyzer_name));

    let reg_result = regression::check_cyberseceval2(&result.metrics);
    let reg = RegressionResult {
        suite_name: format!("CyberSecEval2 ({})", analyzer_name),
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
