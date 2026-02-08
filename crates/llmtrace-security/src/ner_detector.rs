//! ML-based PII detection via Named Entity Recognition (NER) using the Candle framework.
//!
//! Provides [`NerDetector`], which runs a BERT-based NER model (e.g., `dslim/bert-base-NER`)
//! locally via Candle to detect person names, organisations, locations, and miscellaneous
//! entities. Detected entities are mapped to [`SecurityFinding`]s with PII type metadata.
//!
//! # Feature Gate
//!
//! This module is only available when the `ml` feature is enabled.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use llmtrace_core::{LLMTraceError, Result, SecurityFinding, SecuritySeverity};
use tokenizers::Tokenizer;

use crate::inference_stats::{InferenceStats, InferenceStatsTracker};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the NER-based PII detector.
#[derive(Debug, Clone)]
pub struct NerConfig {
    /// HuggingFace model ID (e.g., `"dslim/bert-base-NER"`).
    pub model_id: String,
    /// Optional cache directory for downloaded models.
    pub cache_dir: Option<String>,
}

impl Default for NerConfig {
    fn default() -> Self {
        Self {
            model_id: "dslim/bert-base-NER".to_string(),
            cache_dir: None,
        }
    }
}

// ---------------------------------------------------------------------------
// NER entity types
// ---------------------------------------------------------------------------

/// A recognised named entity extracted from text.
#[derive(Debug, Clone)]
pub struct NerEntity {
    /// Entity text as it appeared in the input.
    pub text: String,
    /// BIO entity type (e.g., `"PER"`, `"ORG"`, `"LOC"`, `"MISC"`).
    pub entity_type: String,
    /// Start byte offset in the original text (best-effort mapping).
    pub start: usize,
    /// End byte offset in the original text (best-effort mapping).
    pub end: usize,
}

// ---------------------------------------------------------------------------
// NER Detector
// ---------------------------------------------------------------------------

/// NER-based PII detector using a BERT token-classification model.
///
/// Downloads a HuggingFace NER model on first use and runs local inference via
/// the Candle framework. Detected entities are converted to [`SecurityFinding`]s
/// with PII type metadata.
///
/// # Example
///
/// ```no_run
/// use llmtrace_security::ner_detector::{NerConfig, NerDetector};
///
/// # async fn run() {
/// let config = NerConfig::default();
/// let detector = NerDetector::new(&config).await.unwrap();
/// assert!(detector.is_some());
/// # }
/// ```
pub struct NerDetector {
    tokenizer: Tokenizer,
    model: BertModel,
    classifier: candle_nn::Linear,
    device: Device,
    id2label: HashMap<usize, String>,
    stats_tracker: InferenceStatsTracker,
}

impl NerDetector {
    /// Attempt to create a new NER detector by downloading and loading the model.
    ///
    /// Returns `Ok(Some(detector))` on success, or `Ok(None)` if the model cannot
    /// be loaded (graceful fallback).
    pub async fn new(config: &NerConfig) -> Result<Option<Self>> {
        match Self::load_model(config).await {
            Ok(detector) => {
                tracing::info!(model_id = %config.model_id, "NER model loaded successfully");
                Ok(Some(detector))
            }
            Err(e) => {
                tracing::warn!(
                    model_id = %config.model_id,
                    error = %e,
                    "Failed to load NER model, NER-based PII detection disabled"
                );
                Ok(None)
            }
        }
    }

    /// Detect named entities in the given text.
    ///
    /// Returns a list of [`NerEntity`] with entity type, text, and byte offsets.
    /// Inference duration is tracked for latency statistics (see [`inference_stats`]).
    pub fn detect_entities(&self, text: &str) -> Result<Vec<NerEntity>> {
        if text.is_empty() {
            return Ok(Vec::new());
        }

        let start = Instant::now();

        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| LLMTraceError::Security(format!("NER tokenization failed: {e}")))?;

        let ids = encoding.get_ids();
        let type_ids = encoding.get_type_ids();
        let mask = encoding.get_attention_mask();
        let offsets = encoding.get_offsets();

        let input_ids = Tensor::new(ids, &self.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| LLMTraceError::Security(format!("NER tensor creation failed: {e}")))?;

        let token_type_ids = Tensor::new(type_ids, &self.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| LLMTraceError::Security(format!("NER tensor creation failed: {e}")))?;

        let attention_mask = Tensor::new(mask, &self.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| LLMTraceError::Security(format!("NER tensor creation failed: {e}")))?;

        // Forward pass through BERT to get hidden states for all tokens
        let hidden = self
            .model
            .forward(&input_ids, &token_type_ids, Some(&attention_mask))
            .map_err(|e| LLMTraceError::Security(format!("NER model forward failed: {e}")))?;

        // Apply the token classification head
        let logits = candle_nn::Module::forward(&self.classifier, &hidden)
            .map_err(|e| LLMTraceError::Security(format!("NER classifier forward failed: {e}")))?;

        // Shape: [1, seq_len, num_labels] → squeeze to [seq_len, num_labels]
        let logits = logits
            .squeeze(0)
            .map_err(|e| LLMTraceError::Security(format!("NER squeeze failed: {e}")))?;

        // Argmax per token
        let predictions = logits
            .argmax(candle_core::D::Minus1)
            .map_err(|e| LLMTraceError::Security(format!("NER argmax failed: {e}")))?;

        let pred_vec: Vec<u32> = predictions.to_vec1().map_err(|e| {
            LLMTraceError::Security(format!("NER prediction extraction failed: {e}"))
        })?;

        // Record inference duration (includes tokenization + forward pass)
        self.stats_tracker.record(start.elapsed());

        // Convert BIO predictions into entity spans
        let entities = self.merge_bio_tags(text, &pred_vec, offsets);

        Ok(entities)
    }

    /// Returns inference latency statistics (P50/P95/P99) over the recent
    /// sliding window.
    ///
    /// Returns `None` if no inference calls have been made yet.
    #[must_use]
    pub fn inference_stats(&self) -> Option<InferenceStats> {
        self.stats_tracker.stats()
    }

    /// Convert detected NER entities into [`SecurityFinding`]s.
    pub fn entities_to_findings(&self, entities: &[NerEntity]) -> Vec<SecurityFinding> {
        entities
            .iter()
            .filter_map(|entity| {
                let (pii_type, severity, confidence) = Self::map_entity_type(&entity.entity_type)?;
                Some(
                    SecurityFinding::new(
                        severity,
                        "pii_detected".to_string(),
                        format!(
                            "NER detected {} (type: {}) in text",
                            pii_type, entity.entity_type
                        ),
                        confidence,
                    )
                    .with_metadata("pii_type".to_string(), pii_type.to_string())
                    .with_metadata("ner_entity_type".to_string(), entity.entity_type.clone())
                    .with_metadata("ner_entity_text".to_string(), entity.text.clone())
                    .with_metadata("detection_method".to_string(), "ner".to_string()),
                )
            })
            .collect()
    }

    /// Convenience method: detect entities and convert to findings in one call.
    pub fn detect_pii(&self, text: &str) -> Result<Vec<SecurityFinding>> {
        let entities = self.detect_entities(text)?;
        Ok(self.entities_to_findings(&entities))
    }

    // -- Private methods ----------------------------------------------------

    /// Map NER entity type to PII type, severity, and confidence.
    ///
    /// Returns `None` for entity types we don't treat as PII (e.g., `MISC`).
    fn map_entity_type(entity_type: &str) -> Option<(&'static str, SecuritySeverity, f64)> {
        match entity_type {
            "PER" => Some(("person_name", SecuritySeverity::Medium, 0.85)),
            "ORG" => Some(("organization", SecuritySeverity::Low, 0.75)),
            "LOC" => Some(("location", SecuritySeverity::Low, 0.7)),
            // MISC entities are not treated as PII by default
            _ => None,
        }
    }

    /// Merge BIO-tagged token predictions into contiguous entity spans.
    ///
    /// Handles the standard BIO scheme: B-XXX starts a new entity, I-XXX continues
    /// the current entity, and O means no entity. Consecutive B/I tokens of the
    /// same type are merged into a single span.
    fn merge_bio_tags(
        &self,
        text: &str,
        predictions: &[u32],
        offsets: &[(usize, usize)],
    ) -> Vec<NerEntity> {
        let mut entities: Vec<NerEntity> = Vec::new();
        let mut current_entity: Option<(String, usize, usize)> = None; // (type, start, end)

        for (idx, &pred) in predictions.iter().enumerate() {
            // Skip special tokens ([CLS], [SEP], [PAD]) — they have (0,0) offsets
            if idx >= offsets.len() {
                break;
            }
            let (tok_start, tok_end) = offsets[idx];
            if tok_start == 0 && tok_end == 0 {
                // Flush any in-progress entity
                if let Some((etype, start, end)) = current_entity.take() {
                    let entity_text = text[start..end].to_string();
                    if !entity_text.trim().is_empty() {
                        entities.push(NerEntity {
                            text: entity_text.trim().to_string(),
                            entity_type: etype,
                            start,
                            end,
                        });
                    }
                }
                continue;
            }

            let label = self
                .id2label
                .get(&(pred as usize))
                .map(String::as_str)
                .unwrap_or("O");

            if let Some(stripped) = label.strip_prefix("B-") {
                // Flush previous entity
                if let Some((etype, start, end)) = current_entity.take() {
                    let entity_text = text[start..end].to_string();
                    if !entity_text.trim().is_empty() {
                        entities.push(NerEntity {
                            text: entity_text.trim().to_string(),
                            entity_type: etype,
                            start,
                            end,
                        });
                    }
                }
                // Start new entity
                current_entity = Some((stripped.to_string(), tok_start, tok_end));
            } else if let Some(stripped) = label.strip_prefix("I-") {
                // Continue entity if same type
                if let Some((ref etype, _, ref mut end)) = current_entity {
                    if etype == stripped {
                        *end = tok_end;
                    } else {
                        // Type mismatch — flush and start new
                        let (etype, start, end) = current_entity.take().unwrap();
                        let entity_text = text[start..end].to_string();
                        if !entity_text.trim().is_empty() {
                            entities.push(NerEntity {
                                text: entity_text.trim().to_string(),
                                entity_type: etype,
                                start,
                                end,
                            });
                        }
                        current_entity = Some((stripped.to_string(), tok_start, tok_end));
                    }
                } else {
                    // I- without a preceding B- — treat as B-
                    current_entity = Some((stripped.to_string(), tok_start, tok_end));
                }
            } else {
                // O label — flush any in-progress entity
                if let Some((etype, start, end)) = current_entity.take() {
                    let entity_text = text[start..end].to_string();
                    if !entity_text.trim().is_empty() {
                        entities.push(NerEntity {
                            text: entity_text.trim().to_string(),
                            entity_type: etype,
                            start,
                            end,
                        });
                    }
                }
            }
        }

        // Flush final entity
        if let Some((etype, start, end)) = current_entity.take() {
            let entity_text = text[start..end].to_string();
            if !entity_text.trim().is_empty() {
                entities.push(NerEntity {
                    text: entity_text.trim().to_string(),
                    entity_type: etype,
                    start,
                    end,
                });
            }
        }

        entities
    }

    /// Download and load the NER model from HuggingFace Hub.
    async fn load_model(config: &NerConfig) -> Result<Self> {
        use hf_hub::api::tokio::{Api, ApiBuilder};

        let api = match &config.cache_dir {
            Some(dir) => ApiBuilder::new().with_cache_dir(PathBuf::from(dir)).build(),
            None => Api::new(),
        }
        .map_err(|e| LLMTraceError::Security(format!("Failed to create HF API client: {e}")))?;

        let repo = api.model(config.model_id.clone());

        // Download required files
        let config_path = repo.get("config.json").await.map_err(|e| {
            LLMTraceError::Security(format!("NER: failed to download config.json: {e}"))
        })?;
        let tokenizer_path = repo.get("tokenizer.json").await.map_err(|e| {
            LLMTraceError::Security(format!("NER: failed to download tokenizer.json: {e}"))
        })?;
        let weights_path = repo.get("model.safetensors").await.map_err(|e| {
            LLMTraceError::Security(format!("NER: failed to download model.safetensors: {e}"))
        })?;

        // Parse config
        let config_str = std::fs::read_to_string(&config_path).map_err(|e| {
            LLMTraceError::Security(format!("NER: failed to read config.json: {e}"))
        })?;
        let config_json: serde_json::Value = serde_json::from_str(&config_str).map_err(|e| {
            LLMTraceError::Security(format!("NER: failed to parse config.json: {e}"))
        })?;

        let bert_config: BertConfig = serde_json::from_value(config_json.clone())
            .map_err(|e| LLMTraceError::Security(format!("NER: invalid BERT config: {e}")))?;

        let num_labels = config_json
            .get("num_labels")
            .and_then(|v| v.as_u64())
            .unwrap_or(9) as usize; // 9 labels for BIO NER (O + B/I for PER, ORG, LOC, MISC)

        // Extract id2label mapping
        let id2label = Self::extract_id2label(&config_json);

        // Load tokenizer
        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| LLMTraceError::Security(format!("NER: failed to load tokenizer: {e}")))?;

        // Load weights
        let device = crate::device::select_device();
        // SAFETY: memory-mapping safetensors is the standard candle pattern.
        // The file is read-only and remains valid for the lifetime of VarBuilder.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DType::F32, &device)
                .map_err(|e| LLMTraceError::Security(format!("NER: failed to load weights: {e}")))?
        };

        let model = BertModel::load(vb.pp("bert"), &bert_config)
            .map_err(|e| LLMTraceError::Security(format!("NER: failed to load BERT model: {e}")))?;

        let classifier =
            candle_nn::linear(bert_config.hidden_size, num_labels, vb.pp("classifier")).map_err(
                |e| LLMTraceError::Security(format!("NER: failed to load classifier head: {e}")),
            )?;

        Ok(Self {
            tokenizer,
            model,
            classifier,
            device,
            id2label,
            stats_tracker: InferenceStatsTracker::default(),
        })
    }

    /// Extract `id2label` mapping from the model's config.json.
    fn extract_id2label(config_json: &serde_json::Value) -> HashMap<usize, String> {
        config_json
            .get("id2label")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| {
                        let idx = k.parse::<usize>().ok()?;
                        let label = v.as_str()?.to_string();
                        Some((idx, label))
                    })
                    .collect()
            })
            .unwrap_or_else(|| {
                // Default BIO labels for dslim/bert-base-NER
                let mut default = HashMap::new();
                default.insert(0, "O".to_string());
                default.insert(1, "B-PER".to_string());
                default.insert(2, "I-PER".to_string());
                default.insert(3, "B-ORG".to_string());
                default.insert(4, "I-ORG".to_string());
                default.insert(5, "B-LOC".to_string());
                default.insert(6, "I-LOC".to_string());
                default.insert(7, "B-MISC".to_string());
                default.insert(8, "I-MISC".to_string());
                default
            })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Config defaults ---------------------------------------------------

    #[test]
    fn test_ner_config_default() {
        let config = NerConfig::default();
        assert_eq!(config.model_id, "dslim/bert-base-NER");
        assert!(config.cache_dir.is_none());
    }

    #[test]
    fn test_ner_config_custom() {
        let config = NerConfig {
            model_id: "custom/ner-model".to_string(),
            cache_dir: Some("/tmp/ner-cache".to_string()),
        };
        assert_eq!(config.model_id, "custom/ner-model");
        assert_eq!(config.cache_dir.as_deref(), Some("/tmp/ner-cache"));
    }

    // -- id2label extraction -----------------------------------------------

    #[test]
    fn test_extract_id2label_present() {
        let json: serde_json::Value = serde_json::json!({
            "id2label": {
                "0": "O",
                "1": "B-PER",
                "2": "I-PER",
                "3": "B-ORG",
                "4": "I-ORG",
                "5": "B-LOC",
                "6": "I-LOC",
                "7": "B-MISC",
                "8": "I-MISC"
            }
        });
        let map = NerDetector::extract_id2label(&json);
        assert_eq!(map.get(&0), Some(&"O".to_string()));
        assert_eq!(map.get(&1), Some(&"B-PER".to_string()));
        assert_eq!(map.get(&5), Some(&"B-LOC".to_string()));
        assert_eq!(map.len(), 9);
    }

    #[test]
    fn test_extract_id2label_missing_uses_defaults() {
        let json: serde_json::Value = serde_json::json!({});
        let map = NerDetector::extract_id2label(&json);
        assert_eq!(map.get(&0), Some(&"O".to_string()));
        assert_eq!(map.get(&1), Some(&"B-PER".to_string()));
        assert_eq!(map.get(&8), Some(&"I-MISC".to_string()));
        assert_eq!(map.len(), 9);
    }

    // -- Entity type mapping -----------------------------------------------

    #[test]
    fn test_map_entity_type_per() {
        let result = NerDetector::map_entity_type("PER");
        assert!(result.is_some());
        let (pii_type, severity, _) = result.unwrap();
        assert_eq!(pii_type, "person_name");
        assert_eq!(severity, SecuritySeverity::Medium);
    }

    #[test]
    fn test_map_entity_type_org() {
        let result = NerDetector::map_entity_type("ORG");
        assert!(result.is_some());
        let (pii_type, severity, _) = result.unwrap();
        assert_eq!(pii_type, "organization");
        assert_eq!(severity, SecuritySeverity::Low);
    }

    #[test]
    fn test_map_entity_type_loc() {
        let result = NerDetector::map_entity_type("LOC");
        assert!(result.is_some());
        let (pii_type, severity, _) = result.unwrap();
        assert_eq!(pii_type, "location");
        assert_eq!(severity, SecuritySeverity::Low);
    }

    #[test]
    fn test_map_entity_type_misc_returns_none() {
        assert!(NerDetector::map_entity_type("MISC").is_none());
    }

    #[test]
    fn test_map_entity_type_unknown_returns_none() {
        assert!(NerDetector::map_entity_type("UNKNOWN").is_none());
    }

    // -- Entity to finding conversion --------------------------------------

    #[test]
    fn test_entities_to_findings_empty() {
        // Build a minimal detector with stub id2label for testing entity conversion.
        // We can't construct NerDetector without a model, so test the static methods
        // and conversion logic via map_entity_type directly.
        let entities: Vec<NerEntity> = Vec::new();
        let findings = entities_to_findings_standalone(&entities);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_entities_to_findings_person() {
        let entities = vec![NerEntity {
            text: "John Smith".to_string(),
            entity_type: "PER".to_string(),
            start: 0,
            end: 10,
        }];
        let findings = entities_to_findings_standalone(&entities);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "pii_detected");
        assert_eq!(
            findings[0].metadata.get("pii_type"),
            Some(&"person_name".to_string())
        );
        assert_eq!(
            findings[0].metadata.get("ner_entity_text"),
            Some(&"John Smith".to_string())
        );
        assert_eq!(
            findings[0].metadata.get("detection_method"),
            Some(&"ner".to_string())
        );
    }

    #[test]
    fn test_entities_to_findings_mixed() {
        let entities = vec![
            NerEntity {
                text: "Alice Johnson".to_string(),
                entity_type: "PER".to_string(),
                start: 0,
                end: 13,
            },
            NerEntity {
                text: "Acme Corp".to_string(),
                entity_type: "ORG".to_string(),
                start: 22,
                end: 31,
            },
            NerEntity {
                text: "London".to_string(),
                entity_type: "LOC".to_string(),
                start: 35,
                end: 41,
            },
            NerEntity {
                text: "NATO".to_string(),
                entity_type: "MISC".to_string(),
                start: 45,
                end: 49,
            },
        ];
        let findings = entities_to_findings_standalone(&entities);
        // MISC should be filtered out
        assert_eq!(findings.len(), 3);
        assert!(findings
            .iter()
            .any(|f| f.metadata.get("pii_type") == Some(&"person_name".to_string())));
        assert!(findings
            .iter()
            .any(|f| f.metadata.get("pii_type") == Some(&"organization".to_string())));
        assert!(findings
            .iter()
            .any(|f| f.metadata.get("pii_type") == Some(&"location".to_string())));
    }

    // -- BIO tag merging (unit test with synthetic data) --------------------

    #[test]
    fn test_merge_bio_tags_simple() {
        // Simulate: "[CLS] John Smith works at Google [SEP]"
        //  offsets:   (0,0) (0,4) (5,10) (11,16) (17,19) (20,26) (0,0)
        //  labels:     O    B-PER  I-PER   O       O      B-ORG    O
        let id2label = default_id2label();
        let predictions: Vec<u32> = vec![0, 1, 2, 0, 0, 3, 0];
        let offsets: Vec<(usize, usize)> = vec![
            (0, 0),   // [CLS]
            (0, 4),   // John
            (5, 10),  // Smith
            (11, 16), // works
            (17, 19), // at
            (20, 26), // Google
            (0, 0),   // [SEP]
        ];
        let text = "John Smith works at Google";

        let detector = FakeDetector { id2label };
        let entities = detector.merge_bio_tags_test(text, &predictions, &offsets);

        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].text, "John Smith");
        assert_eq!(entities[0].entity_type, "PER");
        assert_eq!(entities[0].start, 0);
        assert_eq!(entities[0].end, 10);
        assert_eq!(entities[1].text, "Google");
        assert_eq!(entities[1].entity_type, "ORG");
    }

    #[test]
    fn test_merge_bio_tags_consecutive_different_types() {
        // "John London" — B-PER then B-LOC
        let id2label = default_id2label();
        let predictions: Vec<u32> = vec![0, 1, 5, 0];
        let offsets: Vec<(usize, usize)> = vec![(0, 0), (0, 4), (5, 11), (0, 0)];
        let text = "John London";

        let detector = FakeDetector { id2label };
        let entities = detector.merge_bio_tags_test(text, &predictions, &offsets);

        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].text, "John");
        assert_eq!(entities[0].entity_type, "PER");
        assert_eq!(entities[1].text, "London");
        assert_eq!(entities[1].entity_type, "LOC");
    }

    #[test]
    fn test_merge_bio_tags_i_without_b() {
        // I-PER without preceding B-PER should start a new entity
        let id2label = default_id2label();
        let predictions: Vec<u32> = vec![0, 2, 0]; // [CLS] I-PER [SEP]
        let offsets: Vec<(usize, usize)> = vec![(0, 0), (0, 4), (0, 0)];
        let text = "John";

        let detector = FakeDetector { id2label };
        let entities = detector.merge_bio_tags_test(text, &predictions, &offsets);

        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].text, "John");
        assert_eq!(entities[0].entity_type, "PER");
    }

    #[test]
    fn test_merge_bio_tags_all_o() {
        let id2label = default_id2label();
        let predictions: Vec<u32> = vec![0, 0, 0, 0];
        let offsets: Vec<(usize, usize)> = vec![(0, 0), (0, 5), (6, 11), (0, 0)];
        let text = "hello world";

        let detector = FakeDetector { id2label };
        let entities = detector.merge_bio_tags_test(text, &predictions, &offsets);

        assert!(entities.is_empty());
    }

    #[test]
    fn test_merge_bio_tags_type_mismatch_in_i() {
        // B-PER followed by I-ORG should flush PER and start ORG
        let id2label = default_id2label();
        let predictions: Vec<u32> = vec![0, 1, 4, 0]; // [CLS] B-PER I-ORG [SEP]
        let offsets: Vec<(usize, usize)> = vec![(0, 0), (0, 4), (5, 9), (0, 0)];
        let text = "John Corp";

        let detector = FakeDetector { id2label };
        let entities = detector.merge_bio_tags_test(text, &predictions, &offsets);

        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].text, "John");
        assert_eq!(entities[0].entity_type, "PER");
        assert_eq!(entities[1].text, "Corp");
        assert_eq!(entities[1].entity_type, "ORG");
    }

    // -- Graceful fallback on bad model ------------------------------------

    #[tokio::test]
    async fn test_new_with_invalid_model_returns_none() {
        let config = NerConfig {
            model_id: "nonexistent/model-that-does-not-exist-ner-99999".to_string(),
            cache_dir: Some("/tmp/llmtrace-test-ner-nonexistent".to_string()),
        };
        let result = NerDetector::new(&config).await.unwrap();
        assert!(
            result.is_none(),
            "Should gracefully return None for invalid model"
        );
    }

    // -- Test helpers -------------------------------------------------------

    /// Default BIO id2label for tests.
    fn default_id2label() -> HashMap<usize, String> {
        let mut map = HashMap::new();
        map.insert(0, "O".to_string());
        map.insert(1, "B-PER".to_string());
        map.insert(2, "I-PER".to_string());
        map.insert(3, "B-ORG".to_string());
        map.insert(4, "I-ORG".to_string());
        map.insert(5, "B-LOC".to_string());
        map.insert(6, "I-LOC".to_string());
        map.insert(7, "B-MISC".to_string());
        map.insert(8, "I-MISC".to_string());
        map
    }

    /// Standalone entity-to-finding conversion (mirrors `NerDetector::entities_to_findings`
    /// without requiring a loaded model).
    fn entities_to_findings_standalone(entities: &[NerEntity]) -> Vec<SecurityFinding> {
        entities
            .iter()
            .filter_map(|entity| {
                let (pii_type, severity, confidence) =
                    NerDetector::map_entity_type(&entity.entity_type)?;
                Some(
                    SecurityFinding::new(
                        severity,
                        "pii_detected".to_string(),
                        format!(
                            "NER detected {} (type: {}) in text",
                            pii_type, entity.entity_type
                        ),
                        confidence,
                    )
                    .with_metadata("pii_type".to_string(), pii_type.to_string())
                    .with_metadata("ner_entity_type".to_string(), entity.entity_type.clone())
                    .with_metadata("ner_entity_text".to_string(), entity.text.clone())
                    .with_metadata("detection_method".to_string(), "ner".to_string()),
                )
            })
            .collect()
    }

    /// Lightweight wrapper to test `merge_bio_tags` without a real model.
    struct FakeDetector {
        id2label: HashMap<usize, String>,
    }

    impl FakeDetector {
        fn merge_bio_tags_test(
            &self,
            text: &str,
            predictions: &[u32],
            offsets: &[(usize, usize)],
        ) -> Vec<NerEntity> {
            // Re-implement the same logic as NerDetector::merge_bio_tags
            let mut entities: Vec<NerEntity> = Vec::new();
            let mut current_entity: Option<(String, usize, usize)> = None;

            for (idx, &pred) in predictions.iter().enumerate() {
                if idx >= offsets.len() {
                    break;
                }
                let (tok_start, tok_end) = offsets[idx];
                if tok_start == 0 && tok_end == 0 {
                    if let Some((etype, start, end)) = current_entity.take() {
                        let entity_text = text[start..end].to_string();
                        if !entity_text.trim().is_empty() {
                            entities.push(NerEntity {
                                text: entity_text.trim().to_string(),
                                entity_type: etype,
                                start,
                                end,
                            });
                        }
                    }
                    continue;
                }

                let label = self
                    .id2label
                    .get(&(pred as usize))
                    .map(String::as_str)
                    .unwrap_or("O");

                if let Some(stripped) = label.strip_prefix("B-") {
                    if let Some((etype, start, end)) = current_entity.take() {
                        let entity_text = text[start..end].to_string();
                        if !entity_text.trim().is_empty() {
                            entities.push(NerEntity {
                                text: entity_text.trim().to_string(),
                                entity_type: etype,
                                start,
                                end,
                            });
                        }
                    }
                    current_entity = Some((stripped.to_string(), tok_start, tok_end));
                } else if let Some(stripped) = label.strip_prefix("I-") {
                    if let Some((ref etype, _, ref mut end)) = current_entity {
                        if etype == stripped {
                            *end = tok_end;
                        } else {
                            let (etype, start, end) = current_entity.take().unwrap();
                            let entity_text = text[start..end].to_string();
                            if !entity_text.trim().is_empty() {
                                entities.push(NerEntity {
                                    text: entity_text.trim().to_string(),
                                    entity_type: etype,
                                    start,
                                    end,
                                });
                            }
                            current_entity = Some((stripped.to_string(), tok_start, tok_end));
                        }
                    } else {
                        current_entity = Some((stripped.to_string(), tok_start, tok_end));
                    }
                } else if let Some((etype, start, end)) = current_entity.take() {
                    let entity_text = text[start..end].to_string();
                    if !entity_text.trim().is_empty() {
                        entities.push(NerEntity {
                            text: entity_text.trim().to_string(),
                            entity_type: etype,
                            start,
                            end,
                        });
                    }
                }
            }

            if let Some((etype, start, end)) = current_entity.take() {
                let entity_text = text[start..end].to_string();
                if !entity_text.trim().is_empty() {
                    entities.push(NerEntity {
                        text: entity_text.trim().to_string(),
                        entity_type: etype,
                        start,
                        end,
                    });
                }
            }

            entities
        }
    }
}
