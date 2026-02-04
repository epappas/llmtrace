use criterion::{criterion_group, criterion_main, Criterion};
use llmtrace_benchmarks::datasets::DatasetLoader;
use llmtrace_security::fpr_calibration::{
    CalibrationDataset, CalibrationSample, FprTarget, ThresholdCalibrator,
};
use std::path::Path;

fn max_injection_score(analyzer: &llmtrace_security::RegexSecurityAnalyzer, text: &str) -> f64 {
    analyzer
        .detect_injection_patterns(text)
        .iter()
        .map(|f| f.confidence_score)
        .fold(0.0, f64::max)
}

fn build_calibration_dataset(
    analyzer: &llmtrace_security::RegexSecurityAnalyzer,
    datasets_dir: &Path,
) -> Result<CalibrationDataset, String> {
    let benign = DatasetLoader::load_benign_samples(datasets_dir).map_err(|e| e.to_string())?;
    let malicious =
        DatasetLoader::load_injection_samples(datasets_dir).map_err(|e| e.to_string())?;
    let notinject =
        DatasetLoader::load_notinject_samples(datasets_dir).map_err(|e| e.to_string())?;

    let mut samples = Vec::with_capacity(benign.len() + malicious.len() + notinject.len());

    for sample in &benign {
        let score = max_injection_score(analyzer, &sample.text);
        samples.push(CalibrationSample::benign(score));
    }

    for sample in &malicious {
        let score = max_injection_score(analyzer, &sample.text);
        samples.push(CalibrationSample::malicious(score));
    }

    for sample in &notinject {
        let score = max_injection_score(analyzer, &sample.text);
        let difficulty = sample.difficulty.unwrap_or(1);
        samples.push(CalibrationSample::over_defense(score, difficulty));
    }

    let mut dataset = CalibrationDataset::new("regex_notinject");
    dataset.add_many(samples);
    Ok(dataset)
}

fn bench_fpr_calibration(c: &mut Criterion) {
    let datasets_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets");
    let analyzer =
        llmtrace_security::RegexSecurityAnalyzer::new().expect("Failed to create analyzer");

    let dataset =
        build_calibration_dataset(&analyzer, &datasets_dir).expect("Failed to build dataset");
    let calibrator = ThresholdCalibrator::with_targets(FprTarget::standard_targets());

    // Print report once before benchmarking.
    let report = calibrator.calibrate_all(&[dataset.clone()]);
    eprintln!("{}", report);
    let _ = std::io::Write::flush(&mut std::io::stderr());

    c.bench_function("fpr_calibration_report", |b| {
        b.iter(|| {
            let _ = calibrator.calibrate_all(&[dataset.clone()]);
        })
    });
}

criterion_group!(benches, bench_fpr_calibration);
criterion_main!(benches);
