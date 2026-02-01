//! Toxicity detection for LLM output content.
//!
//! Provides [`ToxicityDetector`], a lightweight BERT-based toxicity classifier
//! that analyses text for toxic content categories (toxic, severe_toxic, obscene,
//! threat, insult, identity_hate).
//!
//! Uses the same Candle framework as the prompt injection ML detector, following
//! the same lazy-load pattern.
//!
//! # Feature Gate
//!
//! This module is only available when the `ml` feature is enabled.

use candle_core::{DType, Device, IndexOp, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use llmtrace_core::{LLMTraceError, OutputSafetyConfig, Result, SecurityFinding, SecuritySeverity};
use tokenizers::Tokenizer;

// ---------------------------------------------------------------------------
// Toxicity categories
// ---------------------------------------------------------------------------

/// The six standard toxicity categories from the Jigsaw toxic comment dataset.
pub const TOXICITY_CATEGORIES: &[&str] = &[
    "toxic",
    "severe_toxic",
    "obscene",
    "threat",
    "insult",
    "identity_hate",
];

// ---------------------------------------------------------------------------
// ToxicityFinding
// ---------------------------------------------------------------------------

/// A single toxicity detection result for one category.
#[derive(Debug, Clone)]
pub struct ToxicityFinding {
    /// The toxicity category (e.g., "toxic", "insult").
    pub category: String,
    /// Confidence score for this category (0.0–1.0).
    pub score: f32,
    /// Whether this score exceeds the configured threshold.
    pub exceeds_threshold: bool,
}

// ---------------------------------------------------------------------------
// ToxicityDetector
// ---------------------------------------------------------------------------

/// Loaded toxicity model with tokenizer and classification head.
struct LoadedToxicityModel {
    tokenizer: Tokenizer,
    model: BertModel,
    classifier: candle_nn::Linear,
    device: Device,
    label_names: Vec<String>,
}

/// BERT-based toxicity classifier for analysing LLM output content.
///
/// Uses a multi-label classification model (e.g., `unitary/toxic-bert`) to
/// detect toxic content across six categories. Falls back to a keyword-based
/// approach when the model cannot be loaded.
///
/// # Example
///
/// ```no_run
/// use llmtrace_security::toxicity_detector::ToxicityDetector;
/// use llmtrace_core::OutputSafetyConfig;
///
/// # async fn example() {
/// let config = OutputSafetyConfig::default();
/// let detector = ToxicityDetector::new(&config).await.unwrap();
/// let findings = detector.detect_toxicity("some text", 0.7);
/// # }
/// ```
pub struct ToxicityDetector {
    model: Option<LoadedToxicityModel>,
    /// Default threshold for toxicity detection. Used when callers don't
    /// specify a per-call threshold.
    _default_threshold: f32,
}

impl ToxicityDetector {
    /// Create a new toxicity detector.
    ///
    /// Attempts to load the toxicity model from HuggingFace Hub. On failure,
    /// logs a warning and enables a keyword-based fallback.
    pub async fn new(config: &OutputSafetyConfig) -> Result<Self> {
        if !config.toxicity_enabled {
            return Ok(Self {
                model: None,
                _default_threshold: config.toxicity_threshold,
            });
        }

        match Self::load_model(config).await {
            Ok(loaded) => {
                tracing::info!("Toxicity detection model loaded successfully");
                Ok(Self {
                    model: Some(loaded),
                    _default_threshold: config.toxicity_threshold,
                })
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to load toxicity model, falling back to keyword-based detection"
                );
                Ok(Self {
                    model: None,
                    _default_threshold: config.toxicity_threshold,
                })
            }
        }
    }

    /// Create a detector in fallback mode (keyword-based, no ML model).
    #[must_use]
    pub fn new_fallback(threshold: f32) -> Self {
        Self {
            model: None,
            _default_threshold: threshold,
        }
    }

    /// Returns `true` if the ML model is loaded and ready for inference.
    #[must_use]
    pub fn is_model_loaded(&self) -> bool {
        self.model.is_some()
    }

    /// Detect toxicity in the given text.
    ///
    /// Returns findings for each category whose score exceeds the threshold.
    pub fn detect_toxicity(&self, text: &str, threshold: f32) -> Vec<ToxicityFinding> {
        if text.is_empty() {
            return Vec::new();
        }

        match &self.model {
            Some(loaded) => self.ml_detect(loaded, text, threshold),
            None => self.keyword_detect(text, threshold),
        }
    }

    /// Convert toxicity findings into security findings suitable for trace storage.
    pub fn findings_to_security_findings(findings: &[ToxicityFinding]) -> Vec<SecurityFinding> {
        findings
            .iter()
            .filter(|f| f.exceeds_threshold)
            .map(|f| {
                let severity = if f.score >= 0.9 || f.category == "severe_toxic" {
                    SecuritySeverity::Critical
                } else if f.score >= 0.8 || f.category == "threat" {
                    SecuritySeverity::High
                } else {
                    SecuritySeverity::Medium
                };

                SecurityFinding::new(
                    severity,
                    "output_toxicity".to_string(),
                    format!(
                        "Toxicity detected in output: {} (score: {:.3})",
                        f.category, f.score
                    ),
                    f64::from(f.score),
                )
                .with_metadata("toxicity_category".to_string(), f.category.clone())
                .with_metadata("toxicity_score".to_string(), format!("{:.4}", f.score))
                .with_location("response.content".to_string())
            })
            .collect()
    }

    // -- ML-based detection -------------------------------------------------

    fn ml_detect(
        &self,
        loaded: &LoadedToxicityModel,
        text: &str,
        threshold: f32,
    ) -> Vec<ToxicityFinding> {
        match Self::run_inference(loaded, text) {
            Ok(scores) => scores
                .into_iter()
                .enumerate()
                .map(|(i, score)| {
                    let category = loaded
                        .label_names
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| format!("category_{i}"));
                    ToxicityFinding {
                        exceeds_threshold: score >= threshold,
                        category,
                        score,
                    }
                })
                .filter(|f| f.exceeds_threshold)
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "Toxicity ML inference failed, falling back to keywords");
                self.keyword_detect(text, threshold)
            }
        }
    }

    fn run_inference(loaded: &LoadedToxicityModel, text: &str) -> Result<Vec<f32>> {
        let encoding = loaded
            .tokenizer
            .encode(text, true)
            .map_err(|e| LLMTraceError::Security(format!("Tokenization failed: {e}")))?;

        let ids = encoding.get_ids();
        let type_ids = encoding.get_type_ids();
        let mask = encoding.get_attention_mask();

        let input_ids = Tensor::new(ids, &loaded.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| LLMTraceError::Security(format!("Tensor creation failed: {e}")))?;

        let token_type_ids = Tensor::new(type_ids, &loaded.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| LLMTraceError::Security(format!("Tensor creation failed: {e}")))?;

        let attention_mask = Tensor::new(mask, &loaded.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| LLMTraceError::Security(format!("Tensor creation failed: {e}")))?;

        // Forward pass through BERT
        let hidden = loaded
            .model
            .forward(&input_ids, &token_type_ids, Some(&attention_mask))
            .map_err(|e| LLMTraceError::Security(format!("Model forward failed: {e}")))?;

        // [CLS] token at position 0
        let cls_output = hidden
            .i((.., 0))
            .map_err(|e| LLMTraceError::Security(format!("CLS extraction failed: {e}")))?;

        let logits = candle_nn::Module::forward(&loaded.classifier, &cls_output)
            .map_err(|e| LLMTraceError::Security(format!("Classifier forward failed: {e}")))?;

        // Apply sigmoid for multi-label classification
        let probs = candle_nn::ops::sigmoid(&logits)
            .map_err(|e| LLMTraceError::Security(format!("Sigmoid failed: {e}")))?;

        let probs_vec: Vec<f32> = probs
            .squeeze(0)
            .and_then(|t| t.to_vec1())
            .map_err(|e| LLMTraceError::Security(format!("Probability extraction failed: {e}")))?;

        Ok(probs_vec)
    }

    // -- Keyword-based fallback detection -----------------------------------

    fn keyword_detect(&self, text: &str, threshold: f32) -> Vec<ToxicityFinding> {
        let lower = text.to_lowercase();
        let mut findings = Vec::new();

        // Simple keyword-based heuristics for each category
        let categories: &[(&str, &[&str], f32)] = &[
            (
                "toxic",
                &[
                    "stupid",
                    "idiot",
                    "shut up",
                    "hate you",
                    "go to hell",
                    "damn",
                    "crap",
                ],
                0.6,
            ),
            (
                "severe_toxic",
                &["kill yourself", "die in a fire", "deserve to die"],
                0.85,
            ),
            ("obscene", &["wtf", "stfu", "lmao", "ass", "bastard"], 0.5),
            (
                "threat",
                &[
                    "i will kill",
                    "i'll kill",
                    "i will hurt",
                    "i'll hurt",
                    "i will find you",
                    "watch your back",
                    "you're dead",
                    "you will pay",
                ],
                0.75,
            ),
            (
                "insult",
                &[
                    "moron",
                    "imbecile",
                    "pathetic",
                    "worthless",
                    "loser",
                    "disgusting",
                ],
                0.6,
            ),
            (
                "identity_hate",
                &[
                    "racist",
                    "sexist",
                    "homophobic",
                    "transphobic",
                    "xenophobic",
                ],
                0.7,
            ),
        ];

        for (category, keywords, base_score) in categories {
            let matches: usize = keywords.iter().filter(|kw| lower.contains(*kw)).count();
            if matches > 0 {
                // Score increases with more keyword matches, capped at 0.95
                let score = (*base_score + 0.1 * (matches as f32 - 1.0)).min(0.95);
                if score >= threshold {
                    findings.push(ToxicityFinding {
                        category: category.to_string(),
                        score,
                        exceeds_threshold: true,
                    });
                }
            }
        }

        findings
    }

    // -- Model loading ------------------------------------------------------

    async fn load_model(config: &OutputSafetyConfig) -> Result<LoadedToxicityModel> {
        use hf_hub::api::tokio::ApiBuilder;

        let model_id = "unitary/toxic-bert";

        let api = ApiBuilder::new()
            .build()
            .map_err(|e| LLMTraceError::Security(format!("Failed to create HF API client: {e}")))?;

        let repo = api.model(model_id.to_string());

        let config_path = repo
            .get("config.json")
            .await
            .map_err(|e| LLMTraceError::Security(format!("Failed to download config.json: {e}")))?;
        let tokenizer_path = repo.get("tokenizer.json").await.map_err(|e| {
            LLMTraceError::Security(format!("Failed to download tokenizer.json: {e}"))
        })?;
        let weights_path = repo.get("model.safetensors").await.map_err(|e| {
            LLMTraceError::Security(format!("Failed to download model.safetensors: {e}"))
        })?;

        let config_str = std::fs::read_to_string(&config_path)
            .map_err(|e| LLMTraceError::Security(format!("Failed to read config.json: {e}")))?;
        let config_json: serde_json::Value = serde_json::from_str(&config_str)
            .map_err(|e| LLMTraceError::Security(format!("Failed to parse config.json: {e}")))?;

        let bert_config: BertConfig = serde_json::from_value(config_json.clone())
            .map_err(|e| LLMTraceError::Security(format!("Invalid BERT config: {e}")))?;

        let num_labels = config_json
            .get("num_labels")
            .and_then(|v| v.as_u64())
            .unwrap_or(6) as usize;

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| LLMTraceError::Security(format!("Failed to load tokenizer: {e}")))?;

        let device = Device::Cpu;
        // SAFETY: memory-mapping safetensors is the standard candle pattern.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DType::F32, &device)
                .map_err(|e| LLMTraceError::Security(format!("Failed to load weights: {e}")))?
        };

        let model = BertModel::load(vb.pp("bert"), &bert_config)
            .map_err(|e| LLMTraceError::Security(format!("Failed to load BERT model: {e}")))?;

        let classifier =
            candle_nn::linear(bert_config.hidden_size, num_labels, vb.pp("classifier")).map_err(
                |e| LLMTraceError::Security(format!("Failed to load classifier head: {e}")),
            )?;

        // Build label names from config or use defaults
        let label_names: Vec<String> = config_json
            .get("id2label")
            .and_then(|v| v.as_object())
            .map(|obj| {
                let mut labels: Vec<(usize, String)> = obj
                    .iter()
                    .filter_map(|(k, v)| {
                        let idx = k.parse::<usize>().ok()?;
                        let label = v.as_str()?.to_string();
                        Some((idx, label))
                    })
                    .collect();
                labels.sort_by_key(|(i, _)| *i);
                labels.into_iter().map(|(_, l)| l).collect()
            })
            .unwrap_or_else(|| TOXICITY_CATEGORIES.iter().map(|s| s.to_string()).collect());

        let _ = config; // suppress unused warning

        Ok(LoadedToxicityModel {
            tokenizer,
            model,
            classifier,
            device,
            label_names,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toxicity_categories_count() {
        assert_eq!(TOXICITY_CATEGORIES.len(), 6);
    }

    #[test]
    fn test_fallback_detector_creation() {
        let detector = ToxicityDetector::new_fallback(0.7);
        assert!(!detector.is_model_loaded());
    }

    #[test]
    fn test_fallback_empty_text_no_findings() {
        let detector = ToxicityDetector::new_fallback(0.5);
        let findings = detector.detect_toxicity("", 0.5);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_fallback_benign_text_no_findings() {
        let detector = ToxicityDetector::new_fallback(0.5);
        let findings = detector.detect_toxicity("The weather is nice today.", 0.5);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_fallback_detects_threat() {
        let detector = ToxicityDetector::new_fallback(0.5);
        let findings = detector.detect_toxicity("I will kill you and your family", 0.5);
        assert!(
            findings.iter().any(|f| f.category == "threat"),
            "Should detect threat keyword; findings: {:?}",
            findings.iter().map(|f| &f.category).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fallback_detects_insult() {
        let detector = ToxicityDetector::new_fallback(0.5);
        let findings = detector.detect_toxicity("You are a worthless moron", 0.5);
        assert!(
            findings.iter().any(|f| f.category == "insult"),
            "Should detect insult; findings: {:?}",
            findings.iter().map(|f| &f.category).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fallback_detects_severe_toxic() {
        let detector = ToxicityDetector::new_fallback(0.5);
        let findings = detector.detect_toxicity("Kill yourself already", 0.5);
        assert!(
            findings.iter().any(|f| f.category == "severe_toxic"),
            "Should detect severe toxicity"
        );
    }

    #[test]
    fn test_threshold_filters_low_score() {
        let detector = ToxicityDetector::new_fallback(0.9);
        // "stupid" gets base score 0.6, which is below 0.9 threshold
        let findings = detector.detect_toxicity("That's stupid", 0.9);
        assert!(
            findings.is_empty(),
            "Low-score finding should be filtered by high threshold"
        );
    }

    #[test]
    fn test_findings_to_security_findings() {
        let toxicity_findings = vec![
            ToxicityFinding {
                category: "threat".to_string(),
                score: 0.85,
                exceeds_threshold: true,
            },
            ToxicityFinding {
                category: "insult".to_string(),
                score: 0.3,
                exceeds_threshold: false,
            },
        ];

        let security_findings = ToxicityDetector::findings_to_security_findings(&toxicity_findings);
        assert_eq!(security_findings.len(), 1);
        assert_eq!(security_findings[0].finding_type, "output_toxicity");
        assert!(security_findings[0]
            .metadata
            .get("toxicity_category")
            .unwrap()
            .contains("threat"));
    }

    #[test]
    fn test_findings_severity_mapping() {
        let findings = vec![
            ToxicityFinding {
                category: "severe_toxic".to_string(),
                score: 0.75,
                exceeds_threshold: true,
            },
            ToxicityFinding {
                category: "threat".to_string(),
                score: 0.82,
                exceeds_threshold: true,
            },
            ToxicityFinding {
                category: "insult".to_string(),
                score: 0.71,
                exceeds_threshold: true,
            },
        ];

        let security_findings = ToxicityDetector::findings_to_security_findings(&findings);
        assert_eq!(security_findings.len(), 3);
        // severe_toxic → Critical
        assert_eq!(security_findings[0].severity, SecuritySeverity::Critical);
        // threat with score 0.82 → High
        assert_eq!(security_findings[1].severity, SecuritySeverity::High);
        // insult with score 0.71 → Medium
        assert_eq!(security_findings[2].severity, SecuritySeverity::Medium);
    }

    #[test]
    fn test_high_score_is_critical() {
        let findings = vec![ToxicityFinding {
            category: "toxic".to_string(),
            score: 0.95,
            exceeds_threshold: true,
        }];
        let sf = ToxicityDetector::findings_to_security_findings(&findings);
        assert_eq!(sf[0].severity, SecuritySeverity::Critical);
    }

    #[tokio::test]
    async fn test_new_with_disabled_config() {
        let config = OutputSafetyConfig {
            enabled: true,
            toxicity_enabled: false,
            toxicity_threshold: 0.7,
            block_on_critical: false,
            ..Default::default()
        };
        let detector = ToxicityDetector::new(&config).await.unwrap();
        assert!(!detector.is_model_loaded());
    }
}
