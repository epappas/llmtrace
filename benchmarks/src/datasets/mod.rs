//! Dataset loading and management for LLMTrace benchmarks.
//!
//! Provides structured dataset loading from JSON files, with support for
//! multiple benchmark datasets referenced in the research literature.
//!
//! # Supported Datasets
//!
//! | Dataset | Source | Samples | Focus |
//! |---------|--------|---------|-------|
//! | `injection_samples.json` | Literature compilation | ~120 | Prompt injection attacks |
//! | `benign_samples.json` | Curated | ~100 | Benign inputs (should NOT trigger) |
//! | `notinject_samples.json` | InjecGuard methodology | 339 | Over-defense test cases |
//! | `encoding_evasion.json` | Bypassing Guardrails | ~80 | Unicode/encoding attacks |
//! | `jailbreak_samples.json` | Multi-source | ~80 | Jailbreak patterns |

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Label for a benchmark sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    /// Benign / safe input — should NOT trigger detection.
    Benign,
    /// Malicious / attack input — SHOULD trigger detection.
    Malicious,
}

/// A single benchmark test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSample {
    /// Unique identifier for this sample.
    pub id: String,
    /// The input text to analyse.
    pub text: String,
    /// Ground truth label.
    pub label: Label,
    /// Attack category (e.g., "prompt_injection", "jailbreak", "encoding_evasion").
    #[serde(default)]
    pub category: Option<String>,
    /// Subcategory for fine-grained analysis.
    #[serde(default)]
    pub subcategory: Option<String>,
    /// Source paper or methodology.
    #[serde(default)]
    pub source: Option<String>,
    /// Difficulty level (1-3, used by NotInject: number of trigger words).
    #[serde(default)]
    pub difficulty: Option<u8>,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// Loads benchmark datasets from JSON files.
pub struct DatasetLoader;

/// NotInject dataset validation results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotInjectValidation {
    /// Total number of samples.
    pub total: usize,
    /// Count by difficulty (index 0 => difficulty 1).
    pub by_difficulty: [usize; 3],
}

impl DatasetLoader {
    /// Load a dataset from a JSON file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from_file(path: &Path) -> Result<Vec<BenchmarkSample>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let samples: Vec<BenchmarkSample> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
        Ok(samples)
    }

    /// Load from a JSON string directly (useful for embedded datasets).
    pub fn load_from_str(json: &str) -> Result<Vec<BenchmarkSample>, String> {
        serde_json::from_str(json).map_err(|e| format!("Failed to parse JSON: {e}"))
    }

    /// Load the injection samples dataset.
    pub fn load_injection_samples(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        Self::load_from_file(&datasets_dir.join("injection_samples.json"))
    }

    /// Load the benign samples dataset.
    pub fn load_benign_samples(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        Self::load_from_file(&datasets_dir.join("benign_samples.json"))
    }

    /// Load the NotInject-style over-defense test cases.
    pub fn load_notinject_samples(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        let samples = Self::load_from_file(&datasets_dir.join("notinject_samples.json"))?;
        validate_notinject_samples(&samples)?;
        Ok(samples)
    }

    /// Load the encoding evasion test cases.
    pub fn load_encoding_evasion(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        Self::load_from_file(&datasets_dir.join("encoding_evasion.json"))
    }

    /// Load the jailbreak test cases.
    pub fn load_jailbreak_samples(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        Self::load_from_file(&datasets_dir.join("jailbreak_samples.json"))
    }

    /// Load the SafeGuard external evaluation dataset (EV-011).
    pub fn load_safeguard_samples(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        Self::load_from_file(&datasets_dir.join("external/safeguard_test.json"))
    }

    /// Load the Deepset external evaluation dataset (EV-012).
    pub fn load_deepset_samples(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        Self::load_from_file(&datasets_dir.join("external/deepset_all.json"))
    }

    /// Load the IvanLeoMK external evaluation dataset (EV-013).
    pub fn load_ivanleomk_samples(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        Self::load_from_file(&datasets_dir.join("external/ivanleomk_all.json"))
    }

    /// Load all datasets and combine them into a single vector.
    pub fn load_all(datasets_dir: &Path) -> Result<Vec<BenchmarkSample>, String> {
        let mut all = Vec::new();
        for file in &[
            "injection_samples.json",
            "benign_samples.json",
            "notinject_samples.json",
            "encoding_evasion.json",
            "jailbreak_samples.json",
        ] {
            let path = datasets_dir.join(file);
            if path.exists() {
                let samples = Self::load_from_file(&path)?;
                all.extend(samples);
            }
        }
        Ok(all)
    }

    /// Filter samples by label.
    pub fn filter_by_label(samples: &[BenchmarkSample], label: Label) -> Vec<&BenchmarkSample> {
        samples.iter().filter(|s| s.label == label).collect()
    }

    /// Filter samples by category.
    pub fn filter_by_category<'a>(
        samples: &'a [BenchmarkSample],
        category: &str,
    ) -> Vec<&'a BenchmarkSample> {
        samples
            .iter()
            .filter(|s| s.category.as_deref() == Some(category))
            .collect()
    }

    /// Filter NotInject samples by difficulty level.
    pub fn filter_by_difficulty(
        samples: &[BenchmarkSample],
        difficulty: u8,
    ) -> Vec<&BenchmarkSample> {
        samples
            .iter()
            .filter(|s| s.difficulty == Some(difficulty))
            .collect()
    }
}

/// Validate NotInject dataset size, labels, and difficulty-tier distribution.
///
/// This enforces the InjecGuard NotInject specification:
/// - 339 benign samples total
/// - 3 difficulty tiers with 113 samples each
/// - difficulty matches trigger-word count in metadata
pub fn validate_notinject_samples(
    samples: &[BenchmarkSample],
) -> Result<NotInjectValidation, String> {
    const EXPECTED_TOTAL: usize = 339;
    const EXPECTED_PER_TIER: usize = 113;

    if samples.len() != EXPECTED_TOTAL {
        return Err(format!(
            "NotInject dataset size mismatch: expected {}, got {}",
            EXPECTED_TOTAL,
            samples.len()
        ));
    }

    let mut by_difficulty = [0usize; 3];
    let mut invalid_labels = Vec::new();
    let mut invalid_difficulty = Vec::new();
    let mut invalid_trigger_counts = Vec::new();

    for sample in samples {
        if sample.label != Label::Benign {
            invalid_labels.push(sample.id.clone());
        }

        let difficulty = match sample.difficulty {
            Some(value @ 1..=3) => value,
            _ => {
                invalid_difficulty.push(sample.id.clone());
                continue;
            }
        };

        let trigger_words = sample.metadata.get("trigger_words").ok_or_else(|| {
            format!(
                "NotInject sample {} missing trigger_words metadata",
                sample.id
            )
        })?;
        let words: Vec<String> = serde_json::from_str(trigger_words).map_err(|e| {
            format!(
                "NotInject sample {} has invalid trigger_words metadata: {}",
                sample.id, e
            )
        })?;

        if words.len() != difficulty as usize {
            invalid_trigger_counts.push(sample.id.clone());
        }

        by_difficulty[(difficulty - 1) as usize] += 1;
    }

    if !invalid_labels.is_empty() {
        return Err(format!(
            "NotInject samples should all be benign, but found {} non-benign: {:?}",
            invalid_labels.len(),
            invalid_labels
        ));
    }

    if !invalid_difficulty.is_empty() {
        return Err(format!(
            "NotInject samples must have difficulty 1-3, but invalid values found: {:?}",
            invalid_difficulty
        ));
    }

    if !invalid_trigger_counts.is_empty() {
        return Err(format!(
            "NotInject samples with trigger-word count mismatch: {:?}",
            invalid_trigger_counts
        ));
    }

    if by_difficulty != [EXPECTED_PER_TIER; 3] {
        return Err(format!(
            "NotInject difficulty distribution mismatch: expected {:?}, got {:?}",
            [EXPECTED_PER_TIER; 3], by_difficulty
        ));
    }

    Ok(NotInjectValidation {
        total: samples.len(),
        by_difficulty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_sample() {
        let json = r#"{
            "id": "test-001",
            "text": "Hello world",
            "label": "benign",
            "category": "general",
            "source": "synthetic"
        }"#;
        let sample: BenchmarkSample = serde_json::from_str(json).unwrap();
        assert_eq!(sample.id, "test-001");
        assert_eq!(sample.label, Label::Benign);
        assert_eq!(sample.category, Some("general".to_string()));
    }

    #[test]
    fn test_load_from_str() {
        let json = r#"[
            {"id": "1", "text": "test", "label": "benign"},
            {"id": "2", "text": "attack", "label": "malicious"}
        ]"#;
        let samples = DatasetLoader::load_from_str(json).unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].label, Label::Benign);
        assert_eq!(samples[1].label, Label::Malicious);
    }

    #[test]
    fn test_filter_by_label() {
        let samples = vec![
            BenchmarkSample {
                id: "1".to_string(),
                text: "benign".to_string(),
                label: Label::Benign,
                category: None,
                subcategory: None,
                source: None,
                difficulty: None,
                metadata: Default::default(),
            },
            BenchmarkSample {
                id: "2".to_string(),
                text: "malicious".to_string(),
                label: Label::Malicious,
                category: None,
                subcategory: None,
                source: None,
                difficulty: None,
                metadata: Default::default(),
            },
        ];
        let benign = DatasetLoader::filter_by_label(&samples, Label::Benign);
        assert_eq!(benign.len(), 1);
        let malicious = DatasetLoader::filter_by_label(&samples, Label::Malicious);
        assert_eq!(malicious.len(), 1);
    }

    #[test]
    fn test_notinject_dataset_validation() {
        let datasets_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets");
        let samples = DatasetLoader::load_notinject_samples(&datasets_dir).unwrap();
        let validation = validate_notinject_samples(&samples).unwrap();
        assert_eq!(validation.total, 339);
        assert_eq!(validation.by_difficulty, [113, 113, 113]);
    }

    #[test]
    fn test_notinject_dataset_size_regression() {
        let datasets_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("datasets");
        let samples = DatasetLoader::load_notinject_samples(&datasets_dir).unwrap();
        assert_eq!(samples.len(), 339);
    }
}
