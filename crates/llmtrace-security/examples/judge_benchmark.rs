//! Live performance + accuracy benchmark for the OpenAI-compatible judge.
//!
//! Loads the labeled datasets under `benchmarks/datasets/` and scores
//! the judge against them, reporting a confusion matrix (precision,
//! recall, F1, FPR) alongside the end-to-end latency distribution and
//! token / cost accounting.
//!
//! Datasets used (all labels come from the files themselves):
//!   - `injection_samples.json`   (malicious, prompt_injection / jailbreak / role_injection)
//!   - `benign_samples.json`      (benign, ordinary user prompts)
//!   - `notinject_samples.json`   (benign, prompts that *look* injection-y
//!     but aren't -- the false-positive pressure test)
//!   - `encoding_evasion.json`    (malicious, encoded / obfuscated)
//!
//! Ground truth is the `label` field on each record. `is_threat` is
//! considered correct when `malicious` matches `true` and `benign`
//! matches `false`. Category match is reported separately.
//!
//! Required env var:
//!   LLMTRACE_JUDGE_OPENAI_API_KEY
//!
//! Optional env vars (defaults in parentheses):
//!   JUDGE_BASE_URL    (https://openrouter.ai/api)
//!   JUDGE_MODEL       (openai/gpt-4o-mini)
//!   JUDGE_TIMEOUT_MS  (30000)
//!   BENCH_DATASET_DIR (benchmarks/datasets)
//!   BENCH_MAX_PER_SET (100)    -- downsample per file; 0 = use all
//!   BENCH_CONCURRENCY (4)      -- in-flight requests
//!   BENCH_SEED        (42)     -- reproducible subsampling
//!
//! Run:
//!   cargo run --example judge_benchmark -p llmtrace-security --features judge --release

use llmtrace_core::{JudgeMode, JudgeVerdict, TenantId};
use llmtrace_security::judge::{
    JudgeBackend, JudgeCandidate, OpenAIJudgeBackend, OpenAiJudgeOptions, OPENAI_API_KEY_ENV,
};
use rand::rngs::StdRng;
use rand::{seq::SliceRandom, SeedableRng};
use reqwest::Client;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use uuid::Uuid;

const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api";
const DEFAULT_MODEL: &str = "openai/gpt-4o-mini";
const DEFAULT_DATASET_DIR: &str = "benchmarks/datasets";

// gpt-4o-mini pricing, USD per 1M tokens. Approximate; verify before
// relying on the cost figure for budgeting.
const PRICE_PER_M_INPUT_USD: f64 = 0.15;
const PRICE_PER_M_OUTPUT_USD: f64 = 0.60;

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct Sample {
    id: String,
    text: String,
    label: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    source: String,
}

struct Dataset {
    name: &'static str,
    file: &'static str,
    expected_threat: bool,
}

const DATASETS: &[Dataset] = &[
    Dataset {
        name: "injection",
        file: "injection_samples.json",
        expected_threat: true,
    },
    Dataset {
        name: "encoding_evasion",
        file: "encoding_evasion.json",
        expected_threat: true,
    },
    Dataset {
        name: "benign",
        file: "benign_samples.json",
        expected_threat: false,
    },
    Dataset {
        name: "notinject",
        file: "notinject_samples.json",
        expected_threat: false,
    },
];

struct Scored {
    dataset: &'static str,
    expected_threat: bool,
    verdict: JudgeVerdict,
    latency_ms: u64,
    source: String,
}

#[derive(Default)]
struct Confusion {
    tp: u64,
    fp: u64,
    tn: u64,
    fn_: u64,
    prompt_tokens: u64,
    completion_tokens: u64,
    latencies_ms: Vec<u64>,
    failures: u64,
}

impl Confusion {
    fn record(&mut self, scored: &Scored) {
        self.latencies_ms.push(scored.latency_ms);
        if let Some(p) = scored.verdict.prompt_tokens {
            self.prompt_tokens += u64::from(p);
        }
        if let Some(c) = scored.verdict.completion_tokens {
            self.completion_tokens += u64::from(c);
        }
        match (scored.expected_threat, scored.verdict.is_threat) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
    }

    fn total(&self) -> u64 {
        self.tp + self.fp + self.tn + self.fn_
    }

    fn precision(&self) -> Option<f64> {
        let denom = self.tp + self.fp;
        if denom == 0 {
            None
        } else {
            Some(self.tp as f64 / denom as f64)
        }
    }

    fn recall(&self) -> Option<f64> {
        let denom = self.tp + self.fn_;
        if denom == 0 {
            None
        } else {
            Some(self.tp as f64 / denom as f64)
        }
    }

    fn f1(&self) -> Option<f64> {
        match (self.precision(), self.recall()) {
            (Some(p), Some(r)) if p + r > 0.0 => Some(2.0 * p * r / (p + r)),
            _ => None,
        }
    }

    fn false_positive_rate(&self) -> Option<f64> {
        let denom = self.fp + self.tn;
        if denom == 0 {
            None
        } else {
            Some(self.fp as f64 / denom as f64)
        }
    }

    fn accuracy(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        (self.tp + self.tn) as f64 / total as f64
    }

    fn percentile(&self, p: f64) -> u64 {
        if self.latencies_ms.is_empty() {
            return 0;
        }
        let mut sorted = self.latencies_ms.clone();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn mean_latency(&self) -> f64 {
        if self.latencies_ms.is_empty() {
            return 0.0;
        }
        self.latencies_ms.iter().sum::<u64>() as f64 / self.latencies_ms.len() as f64
    }

    fn cost_usd(&self) -> f64 {
        (self.prompt_tokens as f64 / 1_000_000.0) * PRICE_PER_M_INPUT_USD
            + (self.completion_tokens as f64 / 1_000_000.0) * PRICE_PER_M_OUTPUT_USD
    }
}

fn make_candidate(text: &str) -> JudgeCandidate {
    JudgeCandidate {
        trace_id: Uuid::new_v4(),
        tenant_id: TenantId(Uuid::new_v4()),
        model_name: "bench-upstream".to_string(),
        analysis_text: text.to_string(),
        prior_findings: vec![],
        mode: JudgeMode::Inline,
    }
}

fn load_dataset(dir: &Path, d: &Dataset, max_per_set: usize, rng: &mut StdRng) -> Vec<Sample> {
    let path = dir.join(d.file);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut samples: Vec<Sample> =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    // Sanity: labels must match the expected column for this dataset.
    let wanted = if d.expected_threat {
        "malicious"
    } else {
        "benign"
    };
    samples.retain(|s| s.label == wanted);
    if max_per_set > 0 && samples.len() > max_per_set {
        samples.shuffle(rng);
        samples.truncate(max_per_set);
    }
    samples
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var(OPENAI_API_KEY_ENV)
        .map_err(|_| format!("env var {OPENAI_API_KEY_ENV} must be set"))?;
    let base_url = std::env::var("JUDGE_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let model = std::env::var("JUDGE_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
    let timeout_ms: u64 = std::env::var("JUDGE_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30_000);
    let dataset_dir = PathBuf::from(
        std::env::var("BENCH_DATASET_DIR").unwrap_or_else(|_| DEFAULT_DATASET_DIR.to_string()),
    );
    let max_per_set: usize = std::env::var("BENCH_MAX_PER_SET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let concurrency: usize = std::env::var("BENCH_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let seed: u64 = std::env::var("BENCH_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);

    let backend = Arc::new(OpenAIJudgeBackend::new(
        Client::new(),
        OpenAiJudgeOptions {
            base_url: base_url.clone(),
            model: model.clone(),
            max_tokens: 512,
            temperature: 0.1,
            timeout: Duration::from_millis(timeout_ms),
            max_retries: 1,
            backoff_base_ms: 250,
            total_deadline: Some(Duration::from_millis(timeout_ms.saturating_mul(3))),
            system_prompt_override: None,
            api_key,
        },
    ));

    let mut rng = StdRng::seed_from_u64(seed);
    let mut all: Vec<(&'static Dataset, Sample)> = Vec::new();
    println!("=== LLMTrace judge live benchmark (labeled corpus) ===");
    println!("backend:     {}", backend.name());
    println!("model:       {}", backend.model());
    println!("base_url:    {base_url}");
    println!("dataset_dir: {}", dataset_dir.display());
    println!("max_per_set: {max_per_set}  (0 = all)");
    println!("concurrency: {concurrency}");
    println!("seed:        {seed}");
    println!();
    for d in DATASETS {
        let loaded = load_dataset(&dataset_dir, d, max_per_set, &mut rng);
        println!(
            "  loaded {:5} from {:<28} (expected_threat={})",
            loaded.len(),
            d.file,
            d.expected_threat
        );
        for s in loaded {
            all.push((d, s));
        }
    }
    let total_calls = all.len();
    println!();
    println!("judging {total_calls} samples at {concurrency}-wide concurrency...");
    println!();

    let sem = Arc::new(Semaphore::new(concurrency));
    let wall_started = Instant::now();

    let mut handles = Vec::with_capacity(total_calls);
    for (d, s) in all {
        let backend = Arc::clone(&backend);
        let sem = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore closed");
            let t0 = Instant::now();
            let res = backend.judge(&make_candidate(&s.text)).await;
            let latency_ms = t0.elapsed().as_millis() as u64;
            (d, s, latency_ms, res)
        }));
    }

    let mut scored: Vec<Scored> = Vec::with_capacity(total_calls);
    let mut failures: u64 = 0;
    let mut completed = 0usize;
    for h in handles {
        match h.await {
            Ok((d, sample, latency_ms, Ok(verdict))) => {
                scored.push(Scored {
                    dataset: d.name,
                    expected_threat: d.expected_threat,
                    verdict,
                    latency_ms,
                    source: sample.source,
                });
            }
            Ok((_, sample, _, Err(e))) => {
                failures += 1;
                eprintln!("  fail on id={} source={}: {e}", sample.id, sample.source);
            }
            Err(e) => {
                failures += 1;
                eprintln!("  task join failed: {e}");
            }
        }
        completed += 1;
        if completed.is_multiple_of(25) {
            eprintln!("  progress: {completed}/{total_calls}");
        }
    }
    let wall = wall_started.elapsed();

    // Aggregate overall + per-dataset confusion.
    let mut overall = Confusion {
        failures,
        ..Confusion::default()
    };
    let mut per_dataset: BTreeMap<&'static str, Confusion> = BTreeMap::new();
    let mut per_source: BTreeMap<String, Confusion> = BTreeMap::new();
    for s in &scored {
        overall.record(s);
        per_dataset.entry(s.dataset).or_default().record(s);
        if !s.source.is_empty() {
            per_source.entry(s.source.clone()).or_default().record(s);
        }
    }

    print_overall(&overall, wall, concurrency);
    println!();
    println!("=== per-dataset breakdown ===");
    for (name, c) in &per_dataset {
        print_confusion(name, c);
    }
    if !per_source.is_empty() {
        println!();
        println!("=== per-source breakdown ===");
        // Only show sources with >= 5 samples to keep noise down.
        let mut sources: Vec<_> = per_source.iter().filter(|(_, c)| c.total() >= 5).collect();
        sources.sort_by_key(|(_, c)| std::cmp::Reverse(c.total()));
        for (name, c) in sources {
            print_confusion(name, c);
        }
    }

    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn print_overall(c: &Confusion, wall: Duration, concurrency: usize) {
    println!("=== overall ===");
    println!("  samples judged:     {}", c.total());
    println!("  failures:           {}", c.failures);
    if c.total() == 0 {
        return;
    }
    println!(
        "  wall clock:         {:.2}s  ({:.2} calls/sec at {concurrency}-wide)",
        wall.as_secs_f64(),
        c.total() as f64 / wall.as_secs_f64()
    );
    println!();
    println!(
        "  confusion:          TP={:<4} FP={:<4} TN={:<4} FN={:<4}",
        c.tp, c.fp, c.tn, c.fn_
    );
    println!("  accuracy:           {:.3}", c.accuracy());
    println!(
        "  precision:          {}",
        c.precision()
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "n/a".into())
    );
    println!(
        "  recall:             {}",
        c.recall()
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "n/a".into())
    );
    println!(
        "  f1:                 {}",
        c.f1()
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "n/a".into())
    );
    println!(
        "  false-positive rate:{}",
        c.false_positive_rate()
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "n/a".into())
    );
    println!();
    println!("  latency mean:       {:.0} ms", c.mean_latency());
    println!("  latency p50:        {} ms", c.percentile(0.50));
    println!("  latency p95:        {} ms", c.percentile(0.95));
    println!("  latency p99:        {} ms", c.percentile(0.99));
    println!(
        "  tokens in/out:      {}/{} (avg {}/{} per call)",
        c.prompt_tokens,
        c.completion_tokens,
        c.prompt_tokens.checked_div(c.total()).unwrap_or(0),
        c.completion_tokens.checked_div(c.total()).unwrap_or(0),
    );
    println!("  est cost:           ${:.4} USD", c.cost_usd());
}

fn print_confusion(name: &str, c: &Confusion) {
    let acc = c.accuracy();
    let prec = c
        .precision()
        .map(|v| format!("{v:.3}"))
        .unwrap_or_else(|| "n/a".into());
    let rec = c
        .recall()
        .map(|v| format!("{v:.3}"))
        .unwrap_or_else(|| "n/a".into());
    let fpr = c
        .false_positive_rate()
        .map(|v| format!("{v:.3}"))
        .unwrap_or_else(|| "n/a".into());
    println!(
        "  {name:<32}  n={:<4} TP={:<3} FP={:<3} TN={:<3} FN={:<3}  acc={:.3}  P={prec}  R={rec}  FPR={fpr}",
        c.total(),
        c.tp,
        c.fp,
        c.tn,
        c.fn_,
        acc
    );
}
