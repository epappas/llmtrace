use criterion::{criterion_group, criterion_main, Criterion};
use llmtrace_benchmarks::datasets::DatasetLoader;
use llmtrace_benchmarks::runners::notinject::run_notinject_evaluation_from_samples;
use std::path::Path;

/// Benchmark the full three-dimensional NotInject evaluation pipeline.
fn bench_over_defense_evaluation(c: &mut Criterion) {
    let datasets_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets");

    let benign =
        DatasetLoader::load_benign_samples(&datasets_dir).expect("Failed to load benign samples");
    let malicious = DatasetLoader::load_injection_samples(&datasets_dir)
        .expect("Failed to load injection samples");
    let notinject = DatasetLoader::load_notinject_samples(&datasets_dir)
        .expect("Failed to load notinject samples");

    let analyzer =
        llmtrace_security::RegexSecurityAnalyzer::new().expect("Failed to create analyzer");

    // Run once to print results before benchmarking
    let eval = run_notinject_evaluation_from_samples(
        &analyzer,
        &benign,
        &malicious,
        &notinject,
        "LLMTrace Regex",
    );
    llmtrace_benchmarks::runners::notinject::print_full_report(&eval);

    c.bench_function("three_dimensional_evaluation", |b| {
        b.iter(|| {
            run_notinject_evaluation_from_samples(
                &analyzer,
                &benign,
                &malicious,
                &notinject,
                "LLMTrace Regex",
            )
        })
    });
}

/// Benchmark just the over-defense portion (NotInject samples only).
fn bench_over_defense_only(c: &mut Criterion) {
    let datasets_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets");

    let notinject = DatasetLoader::load_notinject_samples(&datasets_dir)
        .expect("Failed to load notinject samples");

    let analyzer =
        llmtrace_security::RegexSecurityAnalyzer::new().expect("Failed to create analyzer");

    c.bench_function("over_defense_notinject_only", |b| {
        b.iter(|| {
            let _results: Vec<(bool, u8)> = notinject
                .iter()
                .map(|s| {
                    let flagged = !analyzer.detect_injection_patterns(&s.text).is_empty();
                    (flagged, s.difficulty.unwrap_or(1))
                })
                .collect();
        })
    });
}

criterion_group!(
    benches,
    bench_over_defense_evaluation,
    bench_over_defense_only
);
criterion_main!(benches);
