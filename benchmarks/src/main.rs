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
use llmtrace_benchmarks::experiments;
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
    /// ivanleomk_v2, cyberseceval2, harmbench, ailuminate, injecagent, asb, bipia,
    /// transfer_attack, hpi_approx, tensor_trust, jackhhao, wildjailbreak,
    /// hackaprompt, in_the_wild_jailbreak, mindgard_evasion, xstest,
    /// jailbreakbench, advbench, spml, rubend18, satml_ctf
    #[arg(long)]
    suite: Vec<String>,

    /// Fail immediately if no ML analyzer could load its model.
    #[arg(long)]
    require_ml: bool,

    /// Run only the specified analyzer(s). Omit to run all.
    /// Valid values: regex, ensemble, ensemble_ig, ensemble_ig_pg,
    /// promptguard, injecguard, piguard, mlsecurity
    #[arg(long)]
    analyzer: Vec<String>,

    /// Experiment mode. When set, runs the specified experiment instead of
    /// normal benchmark regression gates.
    /// Valid values: truncation, boundary, checkpoint, recalibration
    #[arg(long)]
    mode: Option<String>,

    /// Truncation levels for Experiment A (comma-separated fractions).
    /// Default: 0.2,0.4,0.6,0.8,1.0
    #[arg(long, value_delimiter = ',')]
    truncation_levels: Vec<f64>,

    /// Confidence thresholds for Experiment B boundary detection.
    /// Default: 0.5,0.7,0.9
    #[arg(long, value_delimiter = ',')]
    boundary_thresholds: Vec<f64>,

    /// Detection threshold for Experiment C checkpoint simulation.
    /// Default: 0.5
    #[arg(long)]
    checkpoint_threshold: Option<f64>,

    /// Path to Experiment A truncation results JSON (required for --mode recalibration).
    #[arg(long)]
    truncation_results: Option<PathBuf>,
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
        display_name: "Deepset v2",
        benchmark_name: "Deepset v2 External",
        loader: DatasetLoader::load_deepset_v2_samples,
        regression_checker: regression::check_deepset,
    },
    ExternalSuiteConfig {
        suite_key: "ivanleomk_v2",
        display_name: "IvanLeoMK v2",
        benchmark_name: "IvanLeoMK v2 External",
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
    ExternalSuiteConfig {
        suite_key: "transfer_attack",
        display_name: "Transfer Attack",
        benchmark_name: "Transfer Attack (EV-018)",
        loader: DatasetLoader::load_transfer_attack_samples,
        regression_checker: regression::check_transfer_attack,
    },
    ExternalSuiteConfig {
        suite_key: "hpi_approx",
        display_name: "HPI Approx",
        benchmark_name: "HPI Approx (EV-008)",
        loader: DatasetLoader::load_hpi_approx_samples,
        regression_checker: regression::check_hpi_approx,
    },
    ExternalSuiteConfig {
        suite_key: "tensor_trust",
        display_name: "Tensor Trust",
        benchmark_name: "Tensor Trust (EV-019)",
        loader: DatasetLoader::load_tensor_trust_samples,
        regression_checker: regression::check_tensor_trust,
    },
    // EV-020 (Harelix): blocked -- dataset deleted from HuggingFace.
    ExternalSuiteConfig {
        suite_key: "jackhhao",
        display_name: "Jackhhao Jailbreak",
        benchmark_name: "Jackhhao Jailbreak (EV-021)",
        loader: DatasetLoader::load_jackhhao_samples,
        regression_checker: regression::check_jackhhao,
    },
    ExternalSuiteConfig {
        suite_key: "wildjailbreak",
        display_name: "WildJailbreak",
        benchmark_name: "WildJailbreak (EV-022)",
        loader: DatasetLoader::load_wildjailbreak_samples,
        regression_checker: regression::check_wildjailbreak,
    },
    ExternalSuiteConfig {
        suite_key: "hackaprompt",
        display_name: "HackAPrompt",
        benchmark_name: "HackAPrompt (EV-023)",
        loader: DatasetLoader::load_hackaprompt_samples,
        regression_checker: regression::check_hackaprompt,
    },
    ExternalSuiteConfig {
        suite_key: "in_the_wild_jailbreak",
        display_name: "In-the-Wild Jailbreak",
        benchmark_name: "In-the-Wild Jailbreak (EV-024)",
        loader: DatasetLoader::load_in_the_wild_jailbreak_samples,
        regression_checker: regression::check_in_the_wild_jailbreak,
    },
    ExternalSuiteConfig {
        suite_key: "mindgard_evasion",
        display_name: "Mindgard Evasion",
        benchmark_name: "Mindgard Evasion (EV-025)",
        loader: DatasetLoader::load_mindgard_evasion_samples,
        regression_checker: regression::check_mindgard_evasion,
    },
    ExternalSuiteConfig {
        suite_key: "xstest",
        display_name: "XSTest",
        benchmark_name: "XSTest (EV-026)",
        loader: DatasetLoader::load_xstest_samples,
        regression_checker: regression::check_xstest,
    },
    ExternalSuiteConfig {
        suite_key: "jailbreakbench",
        display_name: "JailbreakBench",
        benchmark_name: "JailbreakBench (EV-027)",
        loader: DatasetLoader::load_jailbreakbench_samples,
        regression_checker: regression::check_jailbreakbench,
    },
    ExternalSuiteConfig {
        suite_key: "advbench",
        display_name: "AdvBench",
        benchmark_name: "AdvBench (EV-028)",
        loader: DatasetLoader::load_advbench_samples,
        regression_checker: regression::check_advbench,
    },
    ExternalSuiteConfig {
        suite_key: "spml",
        display_name: "SPML",
        benchmark_name: "SPML (EV-029)",
        loader: DatasetLoader::load_spml_samples,
        regression_checker: regression::check_spml,
    },
    ExternalSuiteConfig {
        suite_key: "rubend18",
        display_name: "Rubend18",
        benchmark_name: "Rubend18 (EV-030)",
        loader: DatasetLoader::load_rubend18_samples,
        regression_checker: regression::check_rubend18,
    },
    ExternalSuiteConfig {
        suite_key: "satml_ctf",
        display_name: "SaTML CTF",
        benchmark_name: "SaTML CTF (EV-031)",
        loader: DatasetLoader::load_satml_ctf_samples,
        regression_checker: regression::check_satml_ctf,
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
        .clone()
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets"));

    // Dispatch to experiment mode if requested.
    if let Some(ref mode) = cli.mode {
        run_experiment(mode, &cli, &datasets_dir).await;
        return;
    }

    let analyzers = build_analyzers(&cli.analyzer).await;

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
                    regression_results.push(RegressionResult::suite_error(
                        &format!("Standard ({})", named.name),
                        &e,
                    ));
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
                    regression_results.push(RegressionResult::suite_error(
                        &format!("NotInject 3D ({})", named.name),
                        &e,
                    ));
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
                    regression_results.push(RegressionResult::suite_error(
                        &format!("FPR Calibration ({})", named.name),
                        &e,
                    ));
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
                    regression_results.push(RegressionResult::suite_error(
                        &format!("CyberSecEval2 ({})", named.name),
                        &e,
                    ));
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
                Err(e) if e.contains("No such file or directory") => {
                    eprintln!(
                        "{} suite skipped for {}: dataset not downloaded",
                        config.display_name, named.name
                    );
                }
                Err(e) => {
                    eprintln!(
                        "{} suite failed for {}: {e}",
                        config.display_name, named.name
                    );
                    regression_results.push(RegressionResult::suite_error(
                        &format!("{} ({})", config.display_name, named.name),
                        &e,
                    ));
                }
            }
        }
    }

    if !all_results.is_empty() {
        BenchmarkRunner::print_paper_table(&all_results);

        if let Err(e) = std::fs::create_dir_all(&cli.output_dir) {
            eprintln!("Warning: could not create output dir: {e}");
        } else {
            let json_path = cli.output_dir.join("benchmark_results.json");
            if let Err(e) = BenchmarkRunner::save_results(&all_results, &json_path) {
                eprintln!("Failed to save results: {e}");
            } else {
                println!("\nResults saved to {}", json_path.display());
            }
        }
    }

    print_regression_summary(&regression_results);

    let any_failed = regression_results.iter().any(|r| !r.passed);
    if any_failed {
        std::process::exit(1);
    }
}

async fn build_analyzers(filter: &[String]) -> Vec<NamedAnalyzer> {
    let mut analyzers: Vec<NamedAnalyzer> = Vec::new();
    let run_all = filter.is_empty();
    let want = |key: &str| run_all || filter.iter().any(|f| f.eq_ignore_ascii_case(key));

    if want("regex") {
        let regex = llmtrace_security::RegexSecurityAnalyzer::new()
            .expect("Failed to create RegexSecurityAnalyzer");
        analyzers.push(NamedAnalyzer {
            name: "Regex",
            analyzer: Box::new(regex),
        });
    }

    // Ensemble is the default/recommended analyzer: regex + ML fusion.
    if want("ensemble") {
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
    }

    // Ensemble + InjecGuard: majority voting with 3 detectors (ML-006).
    if want("ensemble_ig") {
        match llmtrace_security::EnsembleSecurityAnalyzer::with_injecguard(
            &llmtrace_security::MLSecurityConfig::default(),
            None,
            Some(&llmtrace_security::InjecGuardConfig::default()),
        )
        .await
        {
            Ok(a) => {
                let ml_active = a.is_ml_active();
                let ig_active = a.is_injecguard_active();
                println!(
                    "Ensemble+IG: ml_active={}, injecguard_active={}",
                    ml_active, ig_active
                );
                if ml_active || ig_active {
                    analyzers.push(NamedAnalyzer {
                        name: "Ensemble+IG",
                        analyzer: Box::new(a),
                    });
                } else {
                    eprintln!("Warning: Ensemble+IG has no ML models active, skipping");
                }
            }
            Err(e) => eprintln!("Warning: Ensemble+IG init failed (skipping): {e}"),
        }
    }

    // Standalone ML analyzers below are for comparison only.
    if want("promptguard") {
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
    }

    if want("injecguard") {
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
                    eprintln!(
                        "Warning: InjecGuard model not loaded, skipping (would duplicate Regex)"
                    );
                }
            }
            Err(e) => eprintln!("Warning: InjecGuardAnalyzer init failed (skipping): {e}"),
        }
    }

    // Ensemble + InjecGuard + PIGuard: majority voting with 4 detectors (ML-004).
    if want("ensemble_ig_pg") {
        match llmtrace_security::EnsembleSecurityAnalyzer::with_piguard(
            &llmtrace_security::MLSecurityConfig::default(),
            None,
            Some(&llmtrace_security::InjecGuardConfig::default()),
            Some(&llmtrace_security::PIGuardConfig::default()),
        )
        .await
        {
            Ok(a) => {
                let ml_active = a.is_ml_active();
                let ig_active = a.is_injecguard_active();
                let pg_active = a.is_piguard_active();
                println!(
                    "Ensemble+IG+PG: ml_active={}, injecguard_active={}, piguard_active={}",
                    ml_active, ig_active, pg_active
                );
                if ml_active || ig_active || pg_active {
                    analyzers.push(NamedAnalyzer {
                        name: "Ensemble+IG+PG",
                        analyzer: Box::new(a),
                    });
                } else {
                    eprintln!("Warning: Ensemble+IG+PG has no ML models active, skipping");
                }
            }
            Err(e) => eprintln!("Warning: Ensemble+IG+PG init failed (skipping): {e}"),
        }
    }

    // Standalone PIGuard analyzer (for comparison).
    if want("piguard") {
        match llmtrace_security::PIGuardAnalyzer::new(&llmtrace_security::PIGuardConfig::default())
            .await
        {
            Ok(a) => {
                println!("PIGuard: model_loaded={}", a.is_model_loaded());
                if a.is_model_loaded() {
                    analyzers.push(NamedAnalyzer {
                        name: "PIGuard",
                        analyzer: Box::new(a),
                    });
                } else {
                    eprintln!(
                        "Warning: PIGuard model not loaded, skipping (would duplicate Regex)"
                    );
                }
            }
            Err(e) => eprintln!("Warning: PIGuardAnalyzer init failed (skipping): {e}"),
        }
    }

    if want("mlsecurity") {
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
                    eprintln!(
                        "Warning: MLSecurity model not loaded, skipping (would duplicate Regex)"
                    );
                }
            }
            Err(e) => eprintln!("Warning: MLSecurityAnalyzer init failed (skipping): {e}"),
        }
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

// ---------------------------------------------------------------------------
// Experiment mode
// ---------------------------------------------------------------------------

/// Wrapper: PromptGuard as a RawScoreDetector.
struct PromptGuardDetector(llmtrace_security::PromptGuardAnalyzer);

impl experiments::RawScoreDetector for PromptGuardDetector {
    fn name(&self) -> &str {
        "PromptGuard"
    }

    fn score(&self, text: &str) -> llmtrace_core::Result<Option<experiments::RawScores>> {
        let result = self.0.classify_raw(text)?;
        Ok(result.map(|r| experiments::RawScores {
            injection_score: r.injection_score,
            predicted_label: r.predicted_label,
            jailbreak_score: Some(r.jailbreak_score),
            benign_score: Some(r.benign_score),
        }))
    }
}

/// Wrapper: InjecGuard as a RawScoreDetector.
struct InjecGuardDetector(llmtrace_security::InjecGuardAnalyzer);

impl experiments::RawScoreDetector for InjecGuardDetector {
    fn name(&self) -> &str {
        "InjecGuard"
    }

    fn score(&self, text: &str) -> llmtrace_core::Result<Option<experiments::RawScores>> {
        let result = self.0.classify_raw(text)?;
        Ok(result.map(|(score, label)| experiments::RawScores {
            injection_score: score,
            predicted_label: label,
            jailbreak_score: None,
            benign_score: None,
        }))
    }
}

/// Wrapper: PIGuard as a RawScoreDetector.
struct PIGuardDetector(llmtrace_security::PIGuardAnalyzer);

impl experiments::RawScoreDetector for PIGuardDetector {
    fn name(&self) -> &str {
        "PIGuard"
    }

    fn score(&self, text: &str) -> llmtrace_core::Result<Option<experiments::RawScores>> {
        let result = self.0.classify_raw(text)?;
        Ok(result.map(|(score, label)| experiments::RawScores {
            injection_score: score,
            predicted_label: label,
            jailbreak_score: None,
            benign_score: None,
        }))
    }
}

/// Build experiment detectors (standalone ML models only -- no ensemble).
async fn build_experiment_detectors() -> Vec<Box<dyn experiments::RawScoreDetector>> {
    let mut detectors: Vec<Box<dyn experiments::RawScoreDetector>> = Vec::new();

    match llmtrace_security::PromptGuardAnalyzer::new(
        &llmtrace_security::PromptGuardConfig::default(),
    )
    .await
    {
        Ok(a) if a.is_model_loaded() => {
            println!("  PromptGuard: loaded");
            detectors.push(Box::new(PromptGuardDetector(a)));
        }
        Ok(_) => eprintln!("  PromptGuard: model not loaded, skipping"),
        Err(e) => eprintln!("  PromptGuard: init failed ({e}), skipping"),
    }

    match llmtrace_security::InjecGuardAnalyzer::new(
        &llmtrace_security::InjecGuardConfig::default(),
    )
    .await
    {
        Ok(a) if a.is_model_loaded() => {
            println!("  InjecGuard: loaded");
            detectors.push(Box::new(InjecGuardDetector(a)));
        }
        Ok(_) => eprintln!("  InjecGuard: model not loaded, skipping"),
        Err(e) => eprintln!("  InjecGuard: init failed ({e}), skipping"),
    }

    match llmtrace_security::PIGuardAnalyzer::new(&llmtrace_security::PIGuardConfig::default())
        .await
    {
        Ok(a) if a.is_model_loaded() => {
            println!("  PIGuard: loaded");
            detectors.push(Box::new(PIGuardDetector(a)));
        }
        Ok(_) => eprintln!("  PIGuard: model not loaded, skipping"),
        Err(e) => eprintln!("  PIGuard: init failed ({e}), skipping"),
    }

    detectors
}

/// Load the experiment suites (mixed-label datasets with both benign and malicious).
fn load_experiment_suites(
    datasets_dir: &Path,
    suite_filter: &[String],
) -> Vec<(String, Vec<BenchmarkSample>)> {
    let run_all = suite_filter.is_empty();
    let want = |name: &str| run_all || suite_filter.iter().any(|s| s.eq_ignore_ascii_case(name));

    let mut suites: Vec<(String, Vec<BenchmarkSample>)> = Vec::new();

    // Standard (mixed: injection + benign)
    if want("standard") {
        match DatasetLoader::load_injection_samples(datasets_dir) {
            Ok(mut samples) => {
                if let Ok(benign) = DatasetLoader::load_benign_samples(datasets_dir) {
                    samples.extend(benign);
                }
                println!("  Standard: {} samples", samples.len());
                suites.push(("standard".to_string(), samples));
            }
            Err(e) => eprintln!("  Standard: failed to load ({e})"),
        }
    }

    // Load external suites that have mixed labels
    type SuiteLoader = fn(&Path) -> Result<Vec<BenchmarkSample>, String>;
    let mixed_suites: &[(&str, SuiteLoader)] = &[
        ("safeguard_v2", DatasetLoader::load_safeguard_samples),
        ("deepset_v2", DatasetLoader::load_deepset_v2_samples),
        ("bipia", DatasetLoader::load_bipia_samples),
        ("tensor_trust", DatasetLoader::load_tensor_trust_samples),
        ("jackhhao", DatasetLoader::load_jackhhao_samples),
    ];

    for (name, loader) in mixed_suites {
        if !want(name) {
            continue;
        }
        match loader(datasets_dir) {
            Ok(samples) => {
                let n_mal = samples
                    .iter()
                    .filter(|s| s.label == llmtrace_benchmarks::datasets::Label::Malicious)
                    .count();
                let n_ben = samples.len() - n_mal;
                println!(
                    "  {}: {} samples ({} mal, {} ben)",
                    name,
                    samples.len(),
                    n_mal,
                    n_ben
                );
                suites.push((name.to_string(), samples));
            }
            Err(e) => eprintln!("  {}: failed to load ({e})", name),
        }
    }

    suites
}

async fn run_experiment(mode: &str, cli: &Cli, datasets_dir: &Path) {
    match mode {
        "truncation" => run_truncation_mode(cli, datasets_dir).await,
        "boundary" => run_boundary_mode(cli, datasets_dir).await,
        "checkpoint" => run_checkpoint_mode(cli, datasets_dir).await,
        "recalibration" => run_recalibration_mode(cli),
        other => {
            eprintln!("Unknown experiment mode: {other}");
            eprintln!("Valid modes: truncation, boundary, checkpoint, recalibration");
            std::process::exit(1);
        }
    }
}

async fn run_truncation_mode(cli: &Cli, datasets_dir: &Path) {
    println!("\n{}", "=".repeat(60));
    println!("  Experiment A: Truncation Degradation Study");
    println!("{}", "=".repeat(60));

    println!("\nLoading ML detectors...");
    let detectors = build_experiment_detectors().await;
    if detectors.is_empty() {
        eprintln!("Error: no ML detectors loaded. Cannot run truncation experiment.");
        std::process::exit(1);
    }

    println!("\nLoading datasets...");
    let suites = load_experiment_suites(datasets_dir, &cli.suite);
    if suites.is_empty() {
        eprintln!("Error: no suites loaded. Cannot run truncation experiment.");
        std::process::exit(1);
    }

    let levels = if cli.truncation_levels.is_empty() {
        experiments::DEFAULT_TRUNCATION_LEVELS.to_vec()
    } else {
        cli.truncation_levels.clone()
    };

    println!("\nTruncation levels: {:?}", levels);
    println!("Detectors: {}", detectors.len());
    println!("Suites: {}", suites.len());
    println!("\nRunning experiment...\n");

    // Build refs for the runner
    let detector_refs: Vec<&dyn experiments::RawScoreDetector> =
        detectors.iter().map(|d| d.as_ref()).collect();
    let suite_refs: Vec<(&str, &[BenchmarkSample])> = suites
        .iter()
        .map(|(name, samples)| (name.as_str(), samples.as_slice()))
        .collect();

    let result = experiments::run_truncation_experiment(&detector_refs, &suite_refs, &levels);

    experiments::print_truncation_summary(&result);

    // Save results
    if let Err(e) = std::fs::create_dir_all(&cli.output_dir) {
        eprintln!("Warning: could not create output dir: {e}");
    } else {
        let json_path = cli.output_dir.join("truncation_experiment.json");
        match serde_json::to_string_pretty(&result) {
            Ok(json) => match std::fs::write(&json_path, json) {
                Ok(()) => println!("\nResults saved to {}", json_path.display()),
                Err(e) => eprintln!("Failed to write results: {e}"),
            },
            Err(e) => eprintln!("Failed to serialize results: {e}"),
        }

        // Also save per-sample CSV for downstream analysis
        let csv_path = cli.output_dir.join("truncation_samples.csv");
        match write_truncation_csv(&result.sample_results, &csv_path) {
            Ok(()) => println!("Per-sample CSV saved to {}", csv_path.display()),
            Err(e) => eprintln!("Failed to write CSV: {e}"),
        }
    }

    println!(
        "\nExperiment A complete. {} samples, {:.1}s",
        result.sample_results.len(),
        result.total_duration_ms as f64 / 1000.0
    );
}

fn write_truncation_csv(
    samples: &[experiments::TruncationSampleResult],
    path: &Path,
) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("Failed to create {}: {e}", path.display()))?;
    writeln!(
        f,
        "sample_id,suite,direction,actual_malicious,original_char_len,truncation_fraction,truncated_char_len,detector,injection_score,predicted_label,inference_us"
    )
    .map_err(|e| format!("Write failed: {e}"))?;

    for s in samples {
        writeln!(
            f,
            "{},{},{},{},{},{:.2},{},{},{:.6},{},{}",
            s.sample_id,
            s.suite,
            experiments::suite_direction(&s.suite),
            s.actual_malicious,
            s.original_char_len,
            s.truncation_fraction,
            s.truncated_char_len,
            s.detector,
            s.scores.injection_score,
            s.scores.predicted_label,
            s.inference_us,
        )
        .map_err(|e| format!("Write failed: {e}"))?;
    }
    Ok(())
}

async fn run_boundary_mode(cli: &Cli, datasets_dir: &Path) {
    println!("\n{}", "=".repeat(60));
    println!("  Experiment B: Injection Boundary Detection");
    println!("{}", "=".repeat(60));

    println!("\nLoading ML detectors...");
    let detectors = build_experiment_detectors().await;
    if detectors.is_empty() {
        eprintln!("Error: no ML detectors loaded. Cannot run boundary experiment.");
        std::process::exit(1);
    }

    println!("\nLoading datasets...");
    let suites = load_experiment_suites(datasets_dir, &cli.suite);
    if suites.is_empty() {
        eprintln!("Error: no suites loaded. Cannot run boundary experiment.");
        std::process::exit(1);
    }

    let thresholds = if cli.boundary_thresholds.is_empty() {
        experiments::DEFAULT_BOUNDARY_THRESHOLDS.to_vec()
    } else {
        cli.boundary_thresholds.clone()
    };

    println!("\nBoundary thresholds: {:?}", thresholds);
    println!("Detectors: {}", detectors.len());
    println!("Suites: {}", suites.len());
    println!("\nRunning experiment...\n");

    let detector_refs: Vec<&dyn experiments::RawScoreDetector> =
        detectors.iter().map(|d| d.as_ref()).collect();
    let suite_refs: Vec<(&str, &[BenchmarkSample])> = suites
        .iter()
        .map(|(name, samples)| (name.as_str(), samples.as_slice()))
        .collect();

    let result = experiments::run_boundary_experiment(&detector_refs, &suite_refs, &thresholds);

    experiments::print_boundary_summary(&result);

    // Save results
    if let Err(e) = std::fs::create_dir_all(&cli.output_dir) {
        eprintln!("Warning: could not create output dir: {e}");
    } else {
        let json_path = cli.output_dir.join("boundary_experiment.json");
        match serde_json::to_string_pretty(&result) {
            Ok(json) => match std::fs::write(&json_path, json) {
                Ok(()) => println!("\nResults saved to {}", json_path.display()),
                Err(e) => eprintln!("Failed to write results: {e}"),
            },
            Err(e) => eprintln!("Failed to serialize results: {e}"),
        }

        let csv_path = cli.output_dir.join("boundary_samples.csv");
        match write_boundary_csv(&result.sample_results, &csv_path) {
            Ok(()) => println!("Per-sample CSV saved to {}", csv_path.display()),
            Err(e) => eprintln!("Failed to write CSV: {e}"),
        }
    }

    println!(
        "\nExperiment B complete. {} samples, {:.1}s",
        result.sample_results.len(),
        result.total_duration_ms as f64 / 1000.0
    );
}

async fn run_checkpoint_mode(cli: &Cli, datasets_dir: &Path) {
    println!("\n{}", "=".repeat(60));
    println!("  Experiment C: Checkpoint Interval Optimization");
    println!("{}", "=".repeat(60));

    println!("\nLoading ML detectors...");
    let detectors = build_experiment_detectors().await;
    if detectors.is_empty() {
        eprintln!("Error: no ML detectors loaded. Cannot run checkpoint experiment.");
        std::process::exit(1);
    }

    println!("\nLoading datasets...");
    let suites = load_experiment_suites(datasets_dir, &cli.suite);
    if suites.is_empty() {
        eprintln!("Error: no suites loaded. Cannot run checkpoint experiment.");
        std::process::exit(1);
    }

    let threshold = cli
        .checkpoint_threshold
        .unwrap_or(experiments::checkpoint::DEFAULT_CHECKPOINT_THRESHOLD);
    let strategies = experiments::checkpoint::default_strategies();

    println!("\nDetection threshold: {}", threshold);
    println!("Strategies: {}", strategies.len());
    println!("Detectors: {}", detectors.len());
    println!("Suites: {}", suites.len());
    println!("\nRunning experiment...\n");

    let detector_refs: Vec<&dyn experiments::RawScoreDetector> =
        detectors.iter().map(|d| d.as_ref()).collect();
    let suite_refs: Vec<(&str, &[BenchmarkSample])> = suites
        .iter()
        .map(|(name, samples)| (name.as_str(), samples.as_slice()))
        .collect();

    let result =
        experiments::run_checkpoint_experiment(&detector_refs, &suite_refs, &strategies, threshold);

    experiments::print_checkpoint_summary(&result);

    if let Err(e) = std::fs::create_dir_all(&cli.output_dir) {
        eprintln!("Warning: could not create output dir: {e}");
    } else {
        let json_path = cli.output_dir.join("checkpoint_experiment.json");
        match serde_json::to_string_pretty(&result) {
            Ok(json) => match std::fs::write(&json_path, json) {
                Ok(()) => println!("\nResults saved to {}", json_path.display()),
                Err(e) => eprintln!("Failed to write results: {e}"),
            },
            Err(e) => eprintln!("Failed to serialize results: {e}"),
        }

        let csv_path = cli.output_dir.join("checkpoint_samples.csv");
        match write_checkpoint_csv(&result.sample_results, &csv_path) {
            Ok(()) => println!("Per-sample CSV saved to {}", csv_path.display()),
            Err(e) => eprintln!("Failed to write CSV: {e}"),
        }
    }

    println!(
        "\nExperiment C complete. {} samples, {:.1}s",
        result.sample_results.len(),
        result.total_duration_ms as f64 / 1000.0
    );
}

fn run_recalibration_mode(cli: &Cli) {
    println!("\n{}", "=".repeat(60));
    println!("  Streaming-Aware Fusion Re-calibration");
    println!("{}", "=".repeat(60));

    let results_path = match &cli.truncation_results {
        Some(p) => p.clone(),
        None => {
            eprintln!(
                "Error: --truncation-results is required for recalibration mode.\n\
                 Run --mode truncation first, then pass the JSON path."
            );
            std::process::exit(1);
        }
    };

    println!(
        "\nLoading truncation results from {}...",
        results_path.display()
    );
    let json = match std::fs::read_to_string(&results_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading {}: {e}", results_path.display());
            std::process::exit(1);
        }
    };
    let truncation_result: experiments::TruncationExperimentResult =
        match serde_json::from_str(&json) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error parsing truncation JSON: {e}");
                std::process::exit(1);
            }
        };

    println!("Running recalibration...\n");
    let result = experiments::run_recalibration_experiment(&truncation_result);
    experiments::print_recalibration_summary(&result);

    if let Err(e) = std::fs::create_dir_all(&cli.output_dir) {
        eprintln!("Warning: could not create output dir: {e}");
    } else {
        let json_path = cli.output_dir.join("recalibration_experiment.json");
        match serde_json::to_string_pretty(&result) {
            Ok(json) => match std::fs::write(&json_path, json) {
                Ok(()) => println!("\nResults saved to {}", json_path.display()),
                Err(e) => eprintln!("Failed to write results: {e}"),
            },
            Err(e) => eprintln!("Failed to serialize results: {e}"),
        }

        let csv_path = cli.output_dir.join("recalibration_levels.csv");
        match write_recalibration_csv(&result, &csv_path) {
            Ok(()) => println!("Per-level CSV saved to {}", csv_path.display()),
            Err(e) => eprintln!("Failed to write CSV: {e}"),
        }
    }

    println!(
        "\nRecalibration complete. {} levels, {:.1}s",
        result.per_level.len(),
        result.total_duration_ms as f64 / 1000.0
    );
}

fn write_recalibration_csv(
    result: &experiments::RecalibrationExperimentResult,
    path: &Path,
) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("Failed to create {}: {e}", path.display()))?;

    // Header
    let mut header = "truncation_fraction,num_train,num_val,\
        streaming_acc,streaming_tpr,streaming_fpr,streaming_f1,\
        naive_acc,naive_tpr,naive_fpr,naive_f1"
        .to_string();
    for name in &result.detector_names {
        header.push_str(&format!(",w_{name}"));
    }
    header.push_str(",w_bias");
    writeln!(f, "{header}").map_err(|e| format!("Write failed: {e}"))?;

    for r in &result.per_level {
        let s = &r.streaming_metrics;
        let n = &r.naive_metrics;
        let mut line = format!(
            "{:.2},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}",
            r.truncation_fraction,
            r.num_train,
            r.num_val,
            s.accuracy,
            s.tpr,
            s.fpr,
            s.f1,
            n.accuracy,
            n.tpr,
            n.fpr,
            n.f1,
        );
        for w in &r.streaming_weights.detector_weights {
            line.push_str(&format!(",{:.6}", w));
        }
        line.push_str(&format!(",{:.6}", r.streaming_weights.bias));
        writeln!(f, "{line}").map_err(|e| format!("Write failed: {e}"))?;
    }
    Ok(())
}

fn write_checkpoint_csv(
    samples: &[experiments::CheckpointSampleResult],
    path: &Path,
) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("Failed to create {}: {e}", path.display()))?;
    writeln!(
        f,
        "sample_id,suite,direction,actual_malicious,original_char_len,detector,strategy,full_text_score,detection_checkpoint,detection_score,inference_calls"
    )
    .map_err(|e| format!("Write failed: {e}"))?;

    for s in samples {
        let det_cp = s
            .detection_checkpoint
            .map_or(String::new(), |v| format!("{:.4}", v));
        let det_score = s
            .detection_score
            .map_or(String::new(), |v| format!("{:.6}", v));
        writeln!(
            f,
            "{},{},{},{},{},{},{},{:.6},{},{},{}",
            s.sample_id,
            s.suite,
            experiments::suite_direction(&s.suite),
            s.actual_malicious,
            s.original_char_len,
            s.detector,
            s.strategy,
            s.full_text_score,
            det_cp,
            det_score,
            s.inference_calls,
        )
        .map_err(|e| format!("Write failed: {e}"))?;
    }
    Ok(())
}

fn write_boundary_csv(
    samples: &[experiments::BoundarySampleResult],
    path: &Path,
) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("Failed to create {}: {e}", path.display()))?;

    // Collect threshold columns from first sample
    let threshold_cols: Vec<f64> = samples
        .first()
        .map(|s| s.boundaries.iter().map(|b| b.threshold).collect())
        .unwrap_or_default();

    // Header
    let mut header =
        "sample_id,suite,direction,original_char_len,detector,full_text_score,inference_calls"
            .to_string();
    for t in &threshold_cols {
        header.push_str(&format!(",boundary_{:.0}pct_fraction", t * 100.0));
        header.push_str(&format!(",boundary_{:.0}pct_charpos", t * 100.0));
    }
    writeln!(f, "{header}").map_err(|e| format!("Write failed: {e}"))?;

    for s in samples {
        let mut line = format!(
            "{},{},{},{},{},{:.6},{}",
            s.sample_id,
            s.suite,
            experiments::suite_direction(&s.suite),
            s.original_char_len,
            s.detector,
            s.full_text_score,
            s.inference_calls,
        );
        for b in &s.boundaries {
            match b.boundary_fraction {
                Some(frac) => line.push_str(&format!(",{:.4}", frac)),
                None => line.push(','),
            }
            match b.boundary_char_pos {
                Some(pos) => line.push_str(&format!(",{}", pos)),
                None => line.push(','),
            }
        }
        writeln!(f, "{line}").map_err(|e| format!("Write failed: {e}"))?;
    }
    Ok(())
}
