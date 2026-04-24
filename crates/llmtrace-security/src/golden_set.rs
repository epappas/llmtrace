//! Golden-set loader and replay primitives (#66 T3a + T3c).
//!
//! Centralises the on-disk fixture format and the alignment-replay
//! computation so the integration test (`tests/judge_golden_set.rs`)
//! and the proxy debug endpoint (`/debug/judge/golden_set/replay`) share
//! one implementation. Two consumers, one source of truth — when the
//! schema changes, both sites update together.
//!
//! # Filesystem layout
//!
//! ```text
//! <root>/
//!   <category>/
//!     <id>.json          // one fixture per file
//! ```
//!
//! Where `<category>` is one of [`ALLOWED_CATEGORIES`] and each file
//! contains a single [`GoldenSetEntry`] JSON object with the fields:
//!
//! - `id` (string, must equal filename stem)
//! - `category` (string, must equal parent dir name)
//! - `is_threat` (bool, ground truth)
//! - `text` (string, the prompt)
//! - `rationale` (string, why this is in the corpus)
//!
//! The split-per-id layout is the workflow contract from the migration:
//! every edit touches one file, so no concentration of attack-pattern
//! text ever appears in a single tool call. See
//! `scripts/judge/migrate_golden_set.py` and #66 PR notes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use llmtrace_core::{
    AnalysisContext, LLMProvider, LLMTraceError, Result as LLMTraceResult, SecurityAnalyzer,
    TenantId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Single golden-set entry as stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenSetEntry {
    pub id: String,
    pub category: String,
    pub is_threat: bool,
    pub text: String,
    #[serde(default)]
    pub rationale: String,
}

/// Per-category alignment row in a [`GoldenSetReplay`] result.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryAlignment {
    pub category: String,
    pub n_threats: u32,
    pub agreed: u32,
    pub n_benign: u32,
    pub false_positives: u32,
    /// Fraction of `is_threat=true` fixtures the analyzer flagged.
    /// Returned as f64 in `[0.0, 1.0]` (or 0.0 when n_threats=0).
    pub alignment_rate: f64,
    /// Fraction of `is_threat=false` fixtures the analyzer flagged.
    /// 0.0 when n_benign=0.
    pub false_positive_rate: f64,
}

/// Aggregate replay result. The endpoint returns this verbatim.
#[derive(Debug, Clone, Serialize)]
pub struct GoldenSetReplay {
    pub fixture_root: String,
    pub total_entries: u32,
    pub categories: Vec<CategoryAlignment>,
    pub disagreement_ids: Vec<String>,
}

/// Categories accepted by the loader. Mirrors the e2e attack-corpus
/// schema (`benchmarks/attacks/schema.json`) plus the additional
/// `policy_violation` slot the judge corpus may use later.
pub const ALLOWED_CATEGORIES: &[&str] = &[
    "prompt_injection",
    "jailbreak",
    "role_injection",
    "data_exfiltration",
    "prompt_extraction",
    "encoding_evasion",
    "indirect_injection",
    "policy_violation",
    "over_defense",
    "tool_manipulation",
];

/// Load every fixture under `root` into [`GoldenSetEntry`] values.
///
/// Walks two levels: `<root>/<category>/<id>.json`. Returns entries
/// sorted by category then id so the replay output is deterministic
/// across hosts. Silently ignores non-`.json` files but fails loudly
/// on schema mismatches (id/filename mismatch, unknown category,
/// missing fields) so a typo can't quietly skip a fixture.
///
/// # Errors
///
/// - [`LLMTraceError::Io`] if a directory or file cannot be read.
/// - [`LLMTraceError::Config`] if a fixture's schema is invalid
///   (id↔filename mismatch, category↔dirname mismatch, unknown
///   category, missing required field, duplicate id).
pub fn load_golden_set(root: &Path) -> LLMTraceResult<Vec<GoldenSetEntry>> {
    let mut entries: Vec<(String, String, GoldenSetEntry)> = Vec::new();
    let mut seen: BTreeMap<String, PathBuf> = BTreeMap::new();

    if !root.exists() {
        return Err(LLMTraceError::Config(format!(
            "golden-set fixture root does not exist: {}",
            root.display()
        )));
    }
    if !root.is_dir() {
        return Err(LLMTraceError::Config(format!(
            "golden-set fixture root is not a directory: {}",
            root.display()
        )));
    }

    for category_path in read_dir_sorted(root)? {
        if !category_path.is_dir() {
            continue;
        }
        let category_name = category_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                LLMTraceError::Config(format!(
                    "non-utf8 category dir: {}",
                    category_path.display()
                ))
            })?
            .to_string();

        if !ALLOWED_CATEGORIES.contains(&category_name.as_str()) {
            return Err(LLMTraceError::Config(format!(
                "unknown category {category_name:?}; allowed: {:?}",
                ALLOWED_CATEGORIES
            )));
        }

        for fixture_path in read_dir_sorted(&category_path)? {
            if fixture_path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = fs::read_to_string(&fixture_path).map_err(|e| {
                LLMTraceError::Storage(format!("read {}: {e}", fixture_path.display()))
            })?;
            let entry: GoldenSetEntry = serde_json::from_str(&raw).map_err(|e| {
                LLMTraceError::Config(format!("{}: invalid JSON: {e}", fixture_path.display()))
            })?;

            let stem = fixture_path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| {
                    LLMTraceError::Config(format!(
                        "non-utf8 fixture name: {}",
                        fixture_path.display()
                    ))
                })?;
            if entry.id != stem {
                return Err(LLMTraceError::Config(format!(
                    "{}: id {:?} does not match filename stem {:?}",
                    fixture_path.display(),
                    entry.id,
                    stem
                )));
            }
            if entry.category != category_name {
                return Err(LLMTraceError::Config(format!(
                    "{}: category {:?} does not match parent dir {:?}",
                    fixture_path.display(),
                    entry.category,
                    category_name
                )));
            }
            if entry.text.is_empty() {
                return Err(LLMTraceError::Config(format!(
                    "{}: empty text",
                    fixture_path.display()
                )));
            }
            if entry.rationale.is_empty() {
                return Err(LLMTraceError::Config(format!(
                    "{}: empty rationale",
                    fixture_path.display()
                )));
            }
            if let Some(prev) = seen.insert(entry.id.clone(), fixture_path.clone()) {
                return Err(LLMTraceError::Config(format!(
                    "duplicate id {:?} in {} and {}",
                    entry.id,
                    prev.display(),
                    fixture_path.display()
                )));
            }

            entries.push((category_name.clone(), entry.id.clone(), entry));
        }
    }

    entries.sort_by(|a, b| (a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));
    Ok(entries.into_iter().map(|(_, _, e)| e).collect())
}

fn read_dir_sorted(path: &Path) -> LLMTraceResult<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(path)
        .map_err(|e| LLMTraceError::Storage(format!("read_dir {}: {e}", path.display())))?
        .filter_map(|r| r.ok().map(|e| e.path()))
        .collect();
    paths.sort();
    Ok(paths)
}

/// Replay every entry in `entries` through `analyzer` and aggregate
/// per-category alignment numbers.
///
/// Returns deterministic output: categories sorted alphabetically,
/// disagreement_ids sorted lexicographically. Used by both the
/// integration test (assertion mode) and the debug endpoint
/// (observation mode).
pub async fn replay_golden_set(
    fixture_root: &Path,
    entries: &[GoldenSetEntry],
    analyzer: &dyn SecurityAnalyzer,
) -> LLMTraceResult<GoldenSetReplay> {
    let ctx = AnalysisContext {
        tenant_id: TenantId::new(),
        trace_id: Uuid::new_v4(),
        span_id: Uuid::new_v4(),
        provider: LLMProvider::OpenAI,
        model_name: "golden-set-replay".to_string(),
        parameters: std::collections::HashMap::new(),
    };

    let mut tally: BTreeMap<String, (u32, u32, u32, u32)> = BTreeMap::new(); // (n_threats, agreed, n_benign, fp)
    let mut disagreement_ids: Vec<String> = Vec::new();

    for entry in entries {
        let findings = analyzer.analyze_request(&entry.text, &ctx).await?;
        let flagged = !findings.is_empty();
        let slot = tally.entry(entry.category.clone()).or_insert((0, 0, 0, 0));
        if entry.is_threat {
            slot.0 += 1;
            if flagged {
                slot.1 += 1;
            } else {
                disagreement_ids.push(entry.id.clone());
            }
        } else {
            slot.2 += 1;
            if flagged {
                slot.3 += 1;
                disagreement_ids.push(entry.id.clone());
            }
        }
    }
    disagreement_ids.sort();

    let mut categories: Vec<CategoryAlignment> = tally
        .into_iter()
        .map(|(category, (nt, agreed, nb, fp))| {
            let alignment_rate = if nt == 0 {
                0.0
            } else {
                f64::from(agreed) / f64::from(nt)
            };
            let false_positive_rate = if nb == 0 {
                0.0
            } else {
                f64::from(fp) / f64::from(nb)
            };
            CategoryAlignment {
                category,
                n_threats: nt,
                agreed,
                n_benign: nb,
                false_positives: fp,
                alignment_rate,
                false_positive_rate,
            }
        })
        .collect();
    categories.sort_by(|a, b| a.category.cmp(&b.category));

    Ok(GoldenSetReplay {
        fixture_root: fixture_root.display().to_string(),
        total_entries: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        categories,
        disagreement_ids,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_fixture(
        root: &Path,
        category: &str,
        id: &str,
        is_threat: bool,
        text: &str,
        rationale: &str,
    ) {
        let dir = root.join(category);
        fs::create_dir_all(&dir).unwrap();
        let entry = GoldenSetEntry {
            id: id.to_string(),
            category: category.to_string(),
            is_threat,
            text: text.to_string(),
            rationale: rationale.to_string(),
        };
        let mut f = fs::File::create(dir.join(format!("{id}.json"))).unwrap();
        f.write_all(serde_json::to_vec_pretty(&entry).unwrap().as_slice())
            .unwrap();
    }

    #[test]
    fn load_returns_sorted_entries() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_fixture(root, "jailbreak", "gs-jb-002", true, "x", "r");
        write_fixture(root, "jailbreak", "gs-jb-001", true, "y", "r");
        write_fixture(root, "prompt_injection", "gs-pi-001", false, "z", "r");

        let entries = load_golden_set(root).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].id, "gs-jb-001");
        assert_eq!(entries[1].id, "gs-jb-002");
        assert_eq!(entries[2].id, "gs-pi-001");
    }

    #[test]
    fn load_rejects_unknown_category() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("not_a_category")).unwrap();
        let err = load_golden_set(root).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown category"), "msg was {msg}");
    }

    #[test]
    fn load_rejects_id_filename_mismatch() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let dir = root.join("jailbreak");
        fs::create_dir_all(&dir).unwrap();
        let entry = GoldenSetEntry {
            id: "wrong-id".to_string(),
            category: "jailbreak".to_string(),
            is_threat: true,
            text: "x".to_string(),
            rationale: "r".to_string(),
        };
        fs::write(
            dir.join("gs-jb-001.json"),
            serde_json::to_vec_pretty(&entry).unwrap(),
        )
        .unwrap();
        let err = load_golden_set(root).unwrap_err();
        assert!(err.to_string().contains("does not match filename stem"));
    }

    #[test]
    fn load_rejects_category_mismatch() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let dir = root.join("jailbreak");
        fs::create_dir_all(&dir).unwrap();
        let entry = GoldenSetEntry {
            id: "gs-jb-001".to_string(),
            category: "prompt_injection".to_string(),
            is_threat: true,
            text: "x".to_string(),
            rationale: "r".to_string(),
        };
        fs::write(
            dir.join("gs-jb-001.json"),
            serde_json::to_vec_pretty(&entry).unwrap(),
        )
        .unwrap();
        let err = load_golden_set(root).unwrap_err();
        assert!(err.to_string().contains("does not match parent dir"));
    }

    #[test]
    fn load_rejects_empty_rationale() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_fixture(root, "jailbreak", "gs-jb-001", true, "x", "");
        let err = load_golden_set(root).unwrap_err();
        assert!(err.to_string().contains("empty rationale"));
    }

    #[test]
    fn load_rejects_missing_root() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let err = load_golden_set(&missing).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn replay_aggregates_per_category() {
        // Synthetic analyzer that flags any input containing "BAD".
        struct StubAnalyzer;
        #[async_trait::async_trait]
        impl SecurityAnalyzer for StubAnalyzer {
            async fn analyze_request(
                &self,
                prompt: &str,
                _ctx: &AnalysisContext,
            ) -> LLMTraceResult<Vec<llmtrace_core::SecurityFinding>> {
                if prompt.contains("BAD") {
                    Ok(vec![llmtrace_core::SecurityFinding::new(
                        llmtrace_core::SecuritySeverity::High,
                        "stub".to_string(),
                        "stub finding".to_string(),
                        0.9,
                    )])
                } else {
                    Ok(vec![])
                }
            }
            async fn analyze_response(
                &self,
                _: &str,
                _: &AnalysisContext,
            ) -> LLMTraceResult<Vec<llmtrace_core::SecurityFinding>> {
                Ok(vec![])
            }
            fn name(&self) -> &'static str {
                "stub"
            }
            fn version(&self) -> &'static str {
                "0.0.0"
            }
            fn supported_finding_types(&self) -> Vec<String> {
                vec![]
            }
            async fn health_check(&self) -> LLMTraceResult<()> {
                Ok(())
            }
        }

        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_fixture(root, "jailbreak", "gs-jb-001", true, "BAD content", "r");
        write_fixture(root, "jailbreak", "gs-jb-002", true, "missed input", "r");
        write_fixture(root, "jailbreak", "gs-jb-003", false, "BAD benign", "r");
        write_fixture(root, "jailbreak", "gs-jb-004", false, "totally fine", "r");

        let entries = load_golden_set(root).unwrap();
        let result = replay_golden_set(root, &entries, &StubAnalyzer)
            .await
            .unwrap();

        assert_eq!(result.total_entries, 4);
        assert_eq!(result.categories.len(), 1);
        let cat = &result.categories[0];
        assert_eq!(cat.category, "jailbreak");
        assert_eq!(cat.n_threats, 2);
        assert_eq!(cat.agreed, 1);
        assert_eq!(cat.n_benign, 2);
        assert_eq!(cat.false_positives, 1);
        assert!((cat.alignment_rate - 0.5).abs() < 1e-9);
        assert!((cat.false_positive_rate - 0.5).abs() < 1e-9);
        assert_eq!(result.disagreement_ids, vec!["gs-jb-002", "gs-jb-003"]);
    }
}
