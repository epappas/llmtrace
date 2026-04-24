//! Golden-set calibration test (#66 T3b).
//!
//! Loads every fixture under
//! `crates/llmtrace-security/fixtures/judge_golden_set/<category>/<id>.json`,
//! runs each prompt through the [`RegexSecurityAnalyzer`], and asserts
//! per-category alignment between the analyzer's verdict and the
//! fixture's ground truth.
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
//! appears in this test source. Each test iteration loads one fixture
//! file via `std::fs::read_dir` and feeds the text to the analyzer
//! directly. Editing or extending the corpus changes one file at a
//! time without touching this code.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use llmtrace_core::{AnalysisContext, LLMProvider, SecurityAnalyzer, SecurityFinding, TenantId};
use llmtrace_security::RegexSecurityAnalyzer;
use uuid::Uuid;

#[derive(Debug, serde::Deserialize)]
struct GoldenEntry {
    id: String,
    category: String,
    is_threat: bool,
    text: String,
    #[serde(default)]
    rationale: String,
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

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("judge_golden_set")
}

fn load_entries() -> Vec<(PathBuf, GoldenEntry)> {
    let root = fixtures_root();
    let mut entries: Vec<(PathBuf, GoldenEntry)> = Vec::new();

    for category_dir in read_dir_sorted(&root) {
        if !category_dir.is_dir() {
            continue;
        }
        let category_name = category_dir
            .file_name()
            .and_then(|n| n.to_str())
            .expect("category dir name utf-8")
            .to_string();

        for fixture_path in read_dir_sorted(&category_dir) {
            if fixture_path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = fs::read_to_string(&fixture_path)
                .unwrap_or_else(|e| panic!("read {}: {e}", fixture_path.display()));
            let entry: GoldenEntry = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse {}: {e}", fixture_path.display()));

            assert_eq!(
                entry.category,
                category_name,
                "{}: category {:?} does not match parent dir {:?}",
                fixture_path.display(),
                entry.category,
                category_name,
            );
            let stem = fixture_path
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("file stem utf-8");
            assert_eq!(
                entry.id,
                stem,
                "{}: id {:?} does not match filename stem {:?}",
                fixture_path.display(),
                entry.id,
                stem,
            );
            assert!(
                !entry.text.is_empty(),
                "{}: empty text",
                fixture_path.display()
            );
            assert!(
                !entry.rationale.is_empty(),
                "{}: empty rationale (every fixture must document why)",
                fixture_path.display()
            );
            entries.push((fixture_path, entry));
        }
    }
    entries
}

fn read_dir_sorted(path: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(path)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", path.display()))
        .filter_map(|r| r.ok().map(|e| e.path()))
        .collect();
    paths.sort();
    paths
}

fn test_context() -> AnalysisContext {
    AnalysisContext {
        tenant_id: TenantId::new(),
        trace_id: Uuid::new_v4(),
        span_id: Uuid::new_v4(),
        provider: LLMProvider::OpenAI,
        model_name: "gpt-4".to_string(),
        parameters: HashMap::new(),
    }
}

/// True when the analyzer flagged the prompt as a threat. Used to
/// compare against the fixture's `is_threat` ground truth.
fn analyzer_flagged(findings: &[SecurityFinding]) -> bool {
    !findings.is_empty()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn corpus_is_non_empty_and_well_formed() {
    let entries = load_entries();
    assert!(
        !entries.is_empty(),
        "golden set is empty — expected fixtures under {}",
        fixtures_root().display()
    );

    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (path, entry) in &entries {
        assert!(
            seen_ids.insert(entry.id.clone()),
            "duplicate fixture id {:?} ({})",
            entry.id,
            path.display()
        );
    }
}

#[tokio::test]
async fn alignment_meets_per_category_floor() {
    let analyzer = RegexSecurityAnalyzer::new().expect("analyzer ctor");
    let ctx = test_context();
    let entries = load_entries();

    // category -> (threat_count, agreed_count)
    let mut tally: HashMap<String, (u32, u32)> = HashMap::new();
    let mut disagreements: Vec<String> = Vec::new();

    for (path, entry) in &entries {
        let findings = analyzer
            .analyze_request(&entry.text, &ctx)
            .await
            .expect("analyze_request");
        let flagged = analyzer_flagged(&findings);
        if entry.is_threat {
            let slot = tally.entry(entry.category.clone()).or_insert((0, 0));
            slot.0 += 1;
            if flagged {
                slot.1 += 1;
            } else {
                // Identify the disagreement by id only — never echo the
                // prompt text into test output.
                disagreements.push(format!(
                    "{} (file={})",
                    entry.id,
                    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                        .unwrap_or(path.as_path())
                        .display()
                ));
            }
        }
    }

    let mut failures: Vec<String> = Vec::new();
    let mut categories: Vec<&String> = tally.keys().collect();
    categories.sort();
    for category in categories {
        let (n, agreed) = tally[category];
        let rate = f64::from(agreed) / f64::from(n);
        let floor = alignment_floor(category);
        eprintln!(
            "[golden_set] category={category} n={n} agreed={agreed} rate={rate:.3} floor={floor:.3}"
        );
        if rate < floor {
            failures.push(format!(
                "{category}: rate {rate:.3} < floor {floor:.3} ({agreed}/{n})"
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} category/categories below alignment floor:\n  {}\n\
             disagreeing fixtures (ids only):\n  {}",
            failures.len(),
            failures.join("\n  "),
            disagreements.join("\n  ")
        );
    }
}

#[tokio::test]
async fn benign_fixtures_are_not_overflagged() {
    // Symmetric assertion to the threat alignment: when a fixture is
    // labelled `is_threat: false`, the analyzer should not flag it.
    // Ratchet — false positives must stay below 25% per category until
    // the calibration loop tightens this further (T4).
    let analyzer = RegexSecurityAnalyzer::new().expect("analyzer ctor");
    let ctx = test_context();
    let entries = load_entries();

    let mut tally: HashMap<String, (u32, u32)> = HashMap::new();
    for (_, entry) in &entries {
        if entry.is_threat {
            continue;
        }
        let findings = analyzer
            .analyze_request(&entry.text, &ctx)
            .await
            .expect("analyze_request");
        let slot = tally.entry(entry.category.clone()).or_insert((0, 0));
        slot.0 += 1;
        if analyzer_flagged(&findings) {
            slot.1 += 1;
        }
    }
    if tally.is_empty() {
        eprintln!("[golden_set] no benign fixtures present yet — skipping FPR check");
        return;
    }

    let mut categories: Vec<&String> = tally.keys().collect();
    categories.sort();
    let mut failures: Vec<String> = Vec::new();
    for category in categories {
        let (n, fp) = tally[category];
        let rate = f64::from(fp) / f64::from(n);
        eprintln!("[golden_set] benign category={category} n={n} flagged={fp} fpr={rate:.3}");
        if rate > 0.25 {
            failures.push(format!(
                "{category}: fpr {rate:.3} > ceiling 0.250 ({fp}/{n})"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "benign FPR ceiling exceeded:\n  {}",
        failures.join("\n  ")
    );
}
