//! Golden-set calibration test (#66 T3b).
//!
//! Loads every fixture under
//! `crates/llmtrace-security/fixtures/judge_golden_set/<category>/<id>.json`
//! via the shared loader in `llmtrace_security::golden_set`, runs each
//! prompt through the [`RegexSecurityAnalyzer`] via the canonical
//! [`replay_golden_set`] helper, and asserts per-category alignment.
//!
//! # Why a golden set
//!
//! The labeled benchmark corpora in `benchmarks/datasets/` are large
//! and noisy; this golden set is a small, hand-curated subset where
//! every entry is a known-good or known-bad example we want the
//! detector to agree with deterministically. Drift in the fast tier
//! shows up here first.
//!
//! # No inline prompt strings
//!
//! Prompt text lives only in the per-id JSON fixtures; it never
//! appears in this test source. Loading + replay logic lives in
//! `crates/llmtrace-security/src/golden_set.rs` and is shared with
//! the proxy debug endpoint, so adding a fixture or refactoring the
//! test never re-emits prompt content.

use std::path::{Path, PathBuf};

use llmtrace_security::golden_set::{load_golden_set, replay_golden_set};
use llmtrace_security::RegexSecurityAnalyzer;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("judge_golden_set")
}

/// Per-category baseline alignment floor. The analyzer must agree
/// with the golden set on at least this fraction of `is_threat=true`
/// fixtures within each category. Bumps here are intentional — record
/// them in the PR description and never reduce a floor without
/// triaging the regression.
fn alignment_floor(category: &str) -> f64 {
    match category {
        "prompt_injection" => 0.85,
        "jailbreak" => 0.85,
        // Conservative defaults for categories not yet populated.
        _ => 0.75,
    }
}

/// Per-category false-positive ceiling on benign fixtures. The
/// analyzer must keep its FPR below this fraction. Same bump
/// discipline as `alignment_floor`.
fn false_positive_ceiling(_category: &str) -> f64 {
    0.25
}

#[tokio::test]
async fn corpus_is_non_empty_and_well_formed() {
    let root = fixtures_root();
    let entries = load_golden_set(&root).expect("load_golden_set");
    assert!(
        !entries.is_empty(),
        "golden set is empty — expected fixtures under {}",
        root.display()
    );
}

#[tokio::test]
async fn alignment_meets_per_category_floor() {
    let analyzer = RegexSecurityAnalyzer::new().expect("analyzer ctor");
    let root = fixtures_root();
    let entries = load_golden_set(&root).expect("load_golden_set");
    let result = replay_golden_set(&root, &entries, &analyzer)
        .await
        .expect("replay_golden_set");

    let mut failures: Vec<String> = Vec::new();
    for cat in &result.categories {
        eprintln!(
            "[golden_set] category={} n={} agreed={} rate={:.3} floor={:.3}",
            cat.category,
            cat.n_threats,
            cat.agreed,
            cat.alignment_rate,
            alignment_floor(&cat.category)
        );
        if cat.n_threats > 0 && cat.alignment_rate < alignment_floor(&cat.category) {
            failures.push(format!(
                "{}: rate {:.3} < floor {:.3} ({}/{})",
                cat.category,
                cat.alignment_rate,
                alignment_floor(&cat.category),
                cat.agreed,
                cat.n_threats
            ));
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} category/categories below alignment floor:\n  {}\n\
             disagreeing fixtures (ids only):\n  {}",
            failures.len(),
            failures.join("\n  "),
            result.disagreement_ids.join("\n  ")
        );
    }
}

#[tokio::test]
async fn benign_fixtures_are_not_overflagged() {
    let analyzer = RegexSecurityAnalyzer::new().expect("analyzer ctor");
    let root = fixtures_root();
    let entries = load_golden_set(&root).expect("load_golden_set");
    let result = replay_golden_set(&root, &entries, &analyzer)
        .await
        .expect("replay_golden_set");

    let mut failures: Vec<String> = Vec::new();
    let mut had_benign = false;
    for cat in &result.categories {
        if cat.n_benign == 0 {
            continue;
        }
        had_benign = true;
        eprintln!(
            "[golden_set] benign category={} n={} flagged={} fpr={:.3}",
            cat.category, cat.n_benign, cat.false_positives, cat.false_positive_rate
        );
        let ceiling = false_positive_ceiling(&cat.category);
        if cat.false_positive_rate > ceiling {
            failures.push(format!(
                "{}: fpr {:.3} > ceiling {:.3} ({}/{})",
                cat.category, cat.false_positive_rate, ceiling, cat.false_positives, cat.n_benign
            ));
        }
    }
    if !had_benign {
        eprintln!("[golden_set] no benign fixtures present yet — skipping FPR check");
        return;
    }
    assert!(
        failures.is_empty(),
        "benign FPR ceiling exceeded:\n  {}",
        failures.join("\n  ")
    );
}
