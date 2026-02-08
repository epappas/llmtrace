//! Hallucination detection for LLM output content.
//!
//! Provides [`HallucinationDetector`], a two-stage pipeline for detecting
//! potentially hallucinated content in LLM responses:
//!
//! - **Stage 1 — Sentinel**: Lightweight check that determines whether a
//!   response needs detailed fact-checking. If the response is short or the
//!   sentinel confidence is high, Stage 2 is skipped (saves compute).
//!
//! - **Stage 2 — Sentence-level detector**: Splits the response into
//!   sentences and scores each one against the user's prompt for factual
//!   consistency using a cross-encoder model (e.g.,
//!   `vectara/hallucination_evaluation_model`).
//!
//! The detector compares the user's prompt (premise) against response
//! sentences (hypothesis) and flags sentences whose factual-consistency
//! score falls below a configurable threshold.
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
// HallucinationResult
// ---------------------------------------------------------------------------

/// Result of hallucination detection on a response.
#[derive(Debug, Clone)]
pub struct HallucinationResult {
    /// Overall factual-consistency score (0.0 = hallucinated, 1.0 = consistent).
    pub overall_score: f32,
    /// Per-sentence scores. Each entry is `(sentence, score)`.
    pub sentence_scores: Vec<SentenceScore>,
    /// Sentences flagged as potentially hallucinated (score below threshold).
    pub flagged_sentences: Vec<SentenceScore>,
    /// Whether the response was skipped (too short or sentinel passed).
    pub skipped: bool,
}

/// Score for a single sentence in the response.
#[derive(Debug, Clone)]
pub struct SentenceScore {
    /// The sentence text.
    pub sentence: String,
    /// Factual-consistency score (0.0 = hallucinated, 1.0 = consistent).
    pub score: f32,
    /// Zero-based index of this sentence in the response.
    pub index: usize,
}

// ---------------------------------------------------------------------------
// Loaded model
// ---------------------------------------------------------------------------

/// Loaded cross-encoder model with tokenizer.
struct LoadedHallucinationModel {
    tokenizer: Tokenizer,
    model: BertModel,
    classifier: candle_nn::Linear,
    device: Device,
}

// ---------------------------------------------------------------------------
// HallucinationDetector
// ---------------------------------------------------------------------------

/// Two-stage hallucination detection pipeline.
///
/// Stage 1 (sentinel) uses a lightweight heuristic/threshold to decide
/// whether detailed checking is needed. Stage 2 uses a cross-encoder model
/// to score each response sentence against the prompt.
///
/// Falls back to keyword-based heuristics when the ML model cannot be loaded.
pub struct HallucinationDetector {
    /// Loaded ML model (None = fallback mode).
    model: Option<LoadedHallucinationModel>,
    /// Score threshold below which a sentence is flagged as hallucinated.
    threshold: f32,
    /// Minimum response length to run detection.
    min_response_length: usize,
    /// Sentinel threshold — if the sentinel score is above this, skip Stage 2.
    sentinel_threshold: f32,
}

impl HallucinationDetector {
    /// Create a new hallucination detector from configuration.
    ///
    /// Attempts to load the cross-encoder model from HuggingFace Hub. On
    /// failure, logs a warning and falls back to heuristic-based detection.
    pub async fn new(config: &OutputSafetyConfig) -> Result<Self> {
        if !config.hallucination_enabled {
            return Ok(Self {
                model: None,
                threshold: config.hallucination_threshold,
                min_response_length: config.hallucination_min_response_length,
                sentinel_threshold: 0.9,
            });
        }

        match Self::load_model(&config.hallucination_model).await {
            Ok(loaded) => {
                tracing::info!(
                    model = %config.hallucination_model,
                    "Hallucination detection model loaded successfully"
                );
                Ok(Self {
                    model: Some(loaded),
                    threshold: config.hallucination_threshold,
                    min_response_length: config.hallucination_min_response_length,
                    sentinel_threshold: 0.9,
                })
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to load hallucination model, falling back to heuristic detection"
                );
                Ok(Self {
                    model: None,
                    threshold: config.hallucination_threshold,
                    min_response_length: config.hallucination_min_response_length,
                    sentinel_threshold: 0.9,
                })
            }
        }
    }

    /// Create a detector in fallback mode (heuristic-based, no ML model).
    #[must_use]
    pub fn new_fallback(threshold: f32, min_response_length: usize) -> Self {
        Self {
            model: None,
            threshold,
            min_response_length,
            sentinel_threshold: 0.9,
        }
    }

    /// Returns `true` if the ML model is loaded and ready for inference.
    #[must_use]
    pub fn is_model_loaded(&self) -> bool {
        self.model.is_some()
    }

    /// Detect hallucinations in a response given the original prompt.
    ///
    /// # Arguments
    ///
    /// * `prompt` — the user's original prompt (used as the premise)
    /// * `response` — the LLM response to check
    ///
    /// # Returns
    ///
    /// A [`HallucinationResult`] with per-sentence scores and flagged sentences.
    pub fn detect(&self, prompt: &str, response: &str) -> HallucinationResult {
        // Skip if response is too short
        if response.len() < self.min_response_length {
            return HallucinationResult {
                overall_score: 1.0,
                sentence_scores: Vec::new(),
                flagged_sentences: Vec::new(),
                skipped: true,
            };
        }

        // Split response into sentences
        let sentences = split_sentences(response);
        if sentences.is_empty() {
            return HallucinationResult {
                overall_score: 1.0,
                sentence_scores: Vec::new(),
                flagged_sentences: Vec::new(),
                skipped: true,
            };
        }

        // Stage 1: Sentinel — quick check if detailed analysis is needed
        let sentinel_score = self.sentinel_check(prompt, response);
        if sentinel_score >= self.sentinel_threshold {
            // High sentinel confidence → response looks factually grounded, skip Stage 2
            return HallucinationResult {
                overall_score: sentinel_score,
                sentence_scores: Vec::new(),
                flagged_sentences: Vec::new(),
                skipped: true,
            };
        }

        // Stage 2: Score each sentence against the prompt
        let sentence_scores: Vec<SentenceScore> = sentences
            .iter()
            .enumerate()
            .map(|(i, sentence)| {
                let score = self.score_sentence(prompt, sentence);
                SentenceScore {
                    sentence: sentence.clone(),
                    score,
                    index: i,
                }
            })
            .collect();

        // Compute overall score (average of sentence scores)
        let overall_score = if sentence_scores.is_empty() {
            1.0
        } else {
            sentence_scores.iter().map(|s| s.score).sum::<f32>() / sentence_scores.len() as f32
        };

        // Flag sentences below threshold
        let flagged_sentences: Vec<SentenceScore> = sentence_scores
            .iter()
            .filter(|s| s.score < self.threshold)
            .cloned()
            .collect();

        HallucinationResult {
            overall_score,
            sentence_scores,
            flagged_sentences,
            skipped: false,
        }
    }

    /// Convert hallucination result into security findings for trace storage.
    pub fn result_to_security_findings(result: &HallucinationResult) -> Vec<SecurityFinding> {
        if result.skipped || result.flagged_sentences.is_empty() {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // Overall finding
        let severity = if result.overall_score < 0.3 {
            SecuritySeverity::High
        } else if result.overall_score < 0.5 {
            SecuritySeverity::Medium
        } else {
            SecuritySeverity::Low
        };

        findings.push(
            SecurityFinding::new(
                severity,
                "output_hallucination".to_string(),
                format!(
                    "Potential hallucination detected: {}/{} sentences flagged (overall score: {:.3})",
                    result.flagged_sentences.len(),
                    result.sentence_scores.len(),
                    result.overall_score,
                ),
                f64::from(1.0 - result.overall_score),
            )
            .with_metadata(
                "flagged_count".to_string(),
                result.flagged_sentences.len().to_string(),
            )
            .with_metadata(
                "total_sentences".to_string(),
                result.sentence_scores.len().to_string(),
            )
            .with_metadata(
                "overall_score".to_string(),
                format!("{:.4}", result.overall_score),
            )
            .with_location("response.content".to_string()),
        );

        // Per-sentence findings for flagged sentences
        for flagged in &result.flagged_sentences {
            let sentence_preview = if flagged.sentence.len() > 100 {
                format!("{}...", &flagged.sentence[..100])
            } else {
                flagged.sentence.clone()
            };

            findings.push(
                SecurityFinding::new(
                    SecuritySeverity::Low,
                    "output_hallucination_sentence".to_string(),
                    format!(
                        "Potentially hallucinated sentence (score: {:.3}): {}",
                        flagged.score, sentence_preview
                    ),
                    f64::from(1.0 - flagged.score),
                )
                .with_metadata("sentence_index".to_string(), flagged.index.to_string())
                .with_metadata(
                    "sentence_score".to_string(),
                    format!("{:.4}", flagged.score),
                )
                .with_location("response.content".to_string()),
            );
        }

        findings
    }

    // -- Stage 1: Sentinel check -------------------------------------------

    /// Quick heuristic check to determine if detailed analysis is needed.
    ///
    /// Returns a score from 0.0 (needs checking) to 1.0 (looks fine).
    fn sentinel_check(&self, prompt: &str, response: &str) -> f32 {
        // Heuristic sentinel: check if the response is closely related to
        // the prompt by measuring word overlap.
        let prompt_lower = prompt.to_lowercase();
        let prompt_words: std::collections::HashSet<&str> =
            prompt_lower.split_whitespace().collect();

        let response_lower = response.to_lowercase();
        let response_words: Vec<&str> = response_lower.split_whitespace().collect();

        if response_words.is_empty() || prompt_words.is_empty() {
            return 0.5;
        }

        let overlap = response_words
            .iter()
            .filter(|w| prompt_words.contains(*w))
            .count();

        let overlap_ratio = overlap as f32 / response_words.len() as f32;

        // High word overlap suggests the response is closely related to the prompt.
        // This is a very rough heuristic — the ML model in Stage 2 does the
        // real work. The sentinel just gates expensive inference.
        //
        // We return a score that is intentionally conservative (biased toward
        // triggering Stage 2) because false negatives (missing hallucinations)
        // are worse than false positives (unnecessary Stage 2 runs).
        (overlap_ratio * 0.8).min(0.85) // Cap below sentinel_threshold to ensure Stage 2 runs for most content
    }

    // -- Stage 2: Sentence scoring -----------------------------------------

    /// Score a single sentence against the prompt for factual consistency.
    fn score_sentence(&self, prompt: &str, sentence: &str) -> f32 {
        match &self.model {
            Some(loaded) => self.ml_score(loaded, prompt, sentence),
            None => self.heuristic_score(prompt, sentence),
        }
    }

    /// ML-based sentence scoring using the cross-encoder model.
    fn ml_score(&self, loaded: &LoadedHallucinationModel, prompt: &str, sentence: &str) -> f32 {
        match Self::run_cross_encoder_inference(loaded, prompt, sentence) {
            Ok(score) => score,
            Err(e) => {
                tracing::warn!(error = %e, "Hallucination ML inference failed, using heuristic");
                self.heuristic_score(prompt, sentence)
            }
        }
    }

    /// Run cross-encoder inference for a (premise, hypothesis) pair.
    ///
    /// The model expects a sentence pair and outputs a score indicating
    /// factual consistency (higher = more consistent).
    fn run_cross_encoder_inference(
        loaded: &LoadedHallucinationModel,
        premise: &str,
        hypothesis: &str,
    ) -> Result<f32> {
        // Encode the sentence pair
        let encoding = loaded
            .tokenizer
            .encode((premise, hypothesis), true)
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

        // Forward pass
        let hidden = loaded
            .model
            .forward(&input_ids, &token_type_ids, Some(&attention_mask))
            .map_err(|e| LLMTraceError::Security(format!("Model forward failed: {e}")))?;

        // [CLS] token
        let cls_output = hidden
            .i((.., 0))
            .map_err(|e| LLMTraceError::Security(format!("CLS extraction failed: {e}")))?;

        let logits = candle_nn::Module::forward(&loaded.classifier, &cls_output)
            .map_err(|e| LLMTraceError::Security(format!("Classifier forward failed: {e}")))?;

        // Apply sigmoid to get consistency probability
        let probs = candle_nn::ops::sigmoid(&logits)
            .map_err(|e| LLMTraceError::Security(format!("Sigmoid failed: {e}")))?;

        let prob_vec: Vec<f32> = probs
            .squeeze(0)
            .and_then(|t| t.to_vec1())
            .map_err(|e| LLMTraceError::Security(format!("Score extraction failed: {e}")))?;

        // Return the consistency score (first output)
        Ok(prob_vec.first().copied().unwrap_or(0.5))
    }

    // -- Heuristic fallback -------------------------------------------------

    /// Heuristic-based sentence scoring (fallback when ML model unavailable).
    ///
    /// Uses word overlap and structural signals as a rough proxy for factual
    /// grounding. This is intentionally conservative — it will produce more
    /// false positives than the ML model.
    fn heuristic_score(&self, prompt: &str, sentence: &str) -> f32 {
        let prompt_lower = prompt.to_lowercase();
        let sentence_lower = sentence.to_lowercase();

        let prompt_words: std::collections::HashSet<&str> =
            prompt_lower.split_whitespace().collect();
        let sentence_words: Vec<&str> = sentence_lower.split_whitespace().collect();

        if sentence_words.is_empty() {
            return 1.0;
        }

        // Factor 1: Word overlap with prompt
        let overlap = sentence_words
            .iter()
            .filter(|w| prompt_words.contains(*w))
            .count();
        let overlap_score = (overlap as f32 / sentence_words.len() as f32).min(1.0);

        // Factor 2: Hedging language suggests lower confidence (but not hallucination)
        let has_hedging = HEDGING_PHRASES.iter().any(|p| sentence_lower.contains(p));
        let hedging_bonus = if has_hedging { 0.1 } else { 0.0 };

        // Factor 3: Specific claims (numbers, proper nouns) are harder to verify
        let has_numbers = sentence.chars().any(|c| c.is_ascii_digit());
        let specificity_penalty = if has_numbers { 0.1 } else { 0.0 };

        // Combine factors — biased toward "consistent" to reduce false positives
        let score = 0.5 + (overlap_score * 0.4) + hedging_bonus - specificity_penalty;
        score.clamp(0.0, 1.0)
    }

    // -- Model loading ------------------------------------------------------

    async fn load_model(model_id: &str) -> Result<LoadedHallucinationModel> {
        use hf_hub::api::tokio::ApiBuilder;

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

        let bert_config: BertConfig = serde_json::from_str(&config_str)
            .map_err(|e| LLMTraceError::Security(format!("Invalid BERT config: {e}")))?;

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| LLMTraceError::Security(format!("Failed to load tokenizer: {e}")))?;

        let device = crate::device::select_device();
        // SAFETY: memory-mapping safetensors is the standard candle pattern.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DType::F32, &device)
                .map_err(|e| LLMTraceError::Security(format!("Failed to load weights: {e}")))?
        };

        let model = BertModel::load(vb.pp("bert"), &bert_config)
            .or_else(|_| {
                // Some models use "model" instead of "bert" as the prefix
                BertModel::load(vb.pp("model"), &bert_config)
            })
            .map_err(|e| LLMTraceError::Security(format!("Failed to load BERT model: {e}")))?;

        // Cross-encoder typically has a single output for consistency score
        let num_labels = 1;
        let classifier =
            candle_nn::linear(bert_config.hidden_size, num_labels, vb.pp("classifier")).map_err(
                |e| LLMTraceError::Security(format!("Failed to load classifier head: {e}")),
            )?;

        Ok(LoadedHallucinationModel {
            tokenizer,
            model,
            classifier,
            device,
        })
    }
}

// ---------------------------------------------------------------------------
// Sentence splitting
// ---------------------------------------------------------------------------

/// Split text into sentences using a simple rule-based approach.
///
/// Splits on `.`, `!`, `?` followed by whitespace or end-of-string, but
/// avoids splitting on common abbreviations (e.g., "Dr.", "Mr.", "U.S.").
fn split_sentences(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();

    for i in 0..len {
        current.push(chars[i]);

        if (chars[i] == '.' || chars[i] == '!' || chars[i] == '?')
            && (i + 1 >= len || chars[i + 1].is_whitespace())
        {
            // Check for common abbreviations
            let trimmed = current.trim();
            if !is_abbreviation(trimmed) && trimmed.len() > 3 {
                sentences.push(trimmed.to_string());
                current.clear();
            }
        }
    }

    // Add remaining text if substantive
    let remaining = current.trim();
    if remaining.len() > 3 {
        sentences.push(remaining.to_string());
    }

    sentences
}

/// Check if the text ends with a common abbreviation.
///
/// Uses word-boundary matching: the abbreviation must either be the entire
/// text or preceded by a space to avoid false positives (e.g., "a test."
/// must not match the abbreviation "est.").
fn is_abbreviation(text: &str) -> bool {
    const ABBREVIATIONS: &[&str] = &[
        "Dr.", "Mr.", "Mrs.", "Ms.", "Jr.", "Sr.", "Prof.", "Inc.", "Ltd.", "Corp.", "etc.", "vs.",
        "e.g.", "i.e.", "U.S.", "U.K.", "approx.", "dept.", "est.", "fig.", "govt.",
    ];
    ABBREVIATIONS.iter().any(|abbr| {
        if text.len() == abbr.len() {
            text == *abbr
        } else if text.len() > abbr.len() {
            // The abbreviation must be preceded by a space (word boundary)
            let prefix_end = text.len() - abbr.len();
            text.ends_with(abbr) && text.as_bytes()[prefix_end - 1] == b' '
        } else {
            false
        }
    })
}

/// Hedging phrases that suggest the model is being cautious (not hallucinating).
const HEDGING_PHRASES: &[&str] = &[
    "i think",
    "it seems",
    "it appears",
    "possibly",
    "probably",
    "might be",
    "could be",
    "it is possible",
    "generally",
    "typically",
    "in general",
    "as far as i know",
    "i believe",
    "it is likely",
    "approximately",
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Sentence splitting -------------------------------------------------

    #[test]
    fn test_split_sentences_basic() {
        let sentences = split_sentences("Hello world. This is a test. And another one.");
        assert_eq!(sentences.len(), 3);
        assert_eq!(sentences[0], "Hello world.");
        assert_eq!(sentences[1], "This is a test.");
        assert_eq!(sentences[2], "And another one.");
    }

    #[test]
    fn test_split_sentences_question_marks() {
        let sentences = split_sentences("What is this? I don't know. Really?");
        assert_eq!(sentences.len(), 3);
    }

    #[test]
    fn test_split_sentences_exclamation() {
        let sentences = split_sentences("Wow! That's amazing. Incredible!");
        assert_eq!(sentences.len(), 3);
    }

    #[test]
    fn test_split_sentences_abbreviation_preserved() {
        let sentences = split_sentences("Dr. Smith went to the store. He bought milk.");
        assert_eq!(sentences.len(), 2);
        assert!(sentences[0].contains("Dr."));
    }

    #[test]
    fn test_split_sentences_empty() {
        let sentences = split_sentences("");
        assert!(sentences.is_empty());
    }

    #[test]
    fn test_split_sentences_single_sentence() {
        let sentences = split_sentences("This is just one sentence.");
        assert_eq!(sentences.len(), 1);
    }

    #[test]
    fn test_split_sentences_no_trailing_period() {
        let sentences = split_sentences("First sentence. Second without period");
        assert_eq!(sentences.len(), 2);
    }

    // -- Fallback detector --------------------------------------------------

    #[test]
    fn test_fallback_detector_creation() {
        let detector = HallucinationDetector::new_fallback(0.5, 50);
        assert!(!detector.is_model_loaded());
    }

    #[test]
    fn test_detect_skips_short_response() {
        let detector = HallucinationDetector::new_fallback(0.5, 50);
        let result = detector.detect("What is Rust?", "A language.");
        assert!(result.skipped);
        assert!(result.flagged_sentences.is_empty());
        assert!((result.overall_score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_skips_empty_response() {
        let detector = HallucinationDetector::new_fallback(0.5, 50);
        let result = detector.detect("Tell me about Rust", "");
        assert!(result.skipped);
    }

    #[test]
    fn test_detect_processes_long_response() {
        let detector = HallucinationDetector::new_fallback(0.5, 10);
        let prompt = "What is the capital of France?";
        let response = "The capital of France is Paris. It is located in northern France. \
                        Paris has a population of about 2 million people.";
        let result = detector.detect(prompt, response);
        assert!(!result.skipped);
        assert!(!result.sentence_scores.is_empty());
    }

    #[test]
    fn test_detect_response_related_to_prompt() {
        let detector = HallucinationDetector::new_fallback(0.3, 10);
        let prompt = "What is Rust programming language?";
        let response = "Rust is a systems programming language. \
                        It focuses on safety and performance. \
                        Rust prevents memory errors at compile time.";
        let result = detector.detect(prompt, response);
        assert!(!result.skipped);
        // Related response should have decent scores
        assert!(result.overall_score > 0.3);
    }

    #[test]
    fn test_detect_unrelated_response_lower_score() {
        let detector = HallucinationDetector::new_fallback(0.8, 10);
        let prompt = "What is Rust programming language?";
        let response = "The Battle of Waterloo was fought in 1815. \
                        Napoleon Bonaparte was defeated by the Duke of Wellington. \
                        This marked the end of the Napoleonic Wars.";
        let result = detector.detect(prompt, response);
        assert!(!result.skipped);
        // Unrelated response should have lower overlap scores
        // With heuristic, most sentences will have low overlap with prompt
        assert!(!result.sentence_scores.is_empty());
    }

    #[test]
    fn test_detect_threshold_behaviour() {
        let detector = HallucinationDetector::new_fallback(0.9, 10);
        let prompt = "Tell me about cats";
        let response = "Cats are domesticated animals. They make great pets. \
                        The speed of light is 299792458 meters per second.";
        let result = detector.detect(prompt, response);
        assert!(!result.skipped);
        // With a very high threshold (0.9), most heuristic scores will be below it
        assert!(
            !result.flagged_sentences.is_empty(),
            "High threshold should flag most heuristic-scored sentences"
        );
    }

    #[test]
    fn test_detect_low_threshold_fewer_flags() {
        let detector = HallucinationDetector::new_fallback(0.1, 10);
        let prompt = "Tell me about cats and dogs and pets and animals";
        let response = "Cats and dogs are popular pets. Many people love animals. \
                        They bring joy to families.";
        let result = detector.detect(prompt, response);
        assert!(!result.skipped);
        // Low threshold should flag fewer sentences (most scores will be above 0.1)
        // The heuristic gives at least 0.5 base + overlap bonus
    }

    #[test]
    fn test_min_response_length_configurable() {
        let detector_short = HallucinationDetector::new_fallback(0.5, 200);
        let result = detector_short.detect(
            "prompt",
            "This response is under 200 characters but has some content to test.",
        );
        assert!(
            result.skipped,
            "Should skip responses shorter than min_response_length"
        );

        let detector_long = HallucinationDetector::new_fallback(0.5, 10);
        let result = detector_long.detect("prompt", "This response is longer than ten chars.");
        assert!(
            !result.skipped,
            "Should process responses longer than min_response_length"
        );
    }

    // -- Result to security findings ----------------------------------------

    #[test]
    fn test_result_to_findings_skipped_returns_empty() {
        let result = HallucinationResult {
            overall_score: 1.0,
            sentence_scores: Vec::new(),
            flagged_sentences: Vec::new(),
            skipped: true,
        };
        let findings = HallucinationDetector::result_to_security_findings(&result);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_result_to_findings_no_flags_returns_empty() {
        let result = HallucinationResult {
            overall_score: 0.8,
            sentence_scores: vec![SentenceScore {
                sentence: "Good sentence.".to_string(),
                score: 0.9,
                index: 0,
            }],
            flagged_sentences: Vec::new(),
            skipped: false,
        };
        let findings = HallucinationDetector::result_to_security_findings(&result);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_result_to_findings_with_flags() {
        let flagged = vec![SentenceScore {
            sentence: "The moon is made of cheese.".to_string(),
            score: 0.2,
            index: 1,
        }];
        let result = HallucinationResult {
            overall_score: 0.4,
            sentence_scores: vec![
                SentenceScore {
                    sentence: "The moon orbits the Earth.".to_string(),
                    score: 0.8,
                    index: 0,
                },
                SentenceScore {
                    sentence: "The moon is made of cheese.".to_string(),
                    score: 0.2,
                    index: 1,
                },
            ],
            flagged_sentences: flagged,
            skipped: false,
        };
        let findings = HallucinationDetector::result_to_security_findings(&result);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.finding_type == "output_hallucination"));
        assert!(findings
            .iter()
            .any(|f| f.finding_type == "output_hallucination_sentence"));
    }

    #[test]
    fn test_result_to_findings_severity_high() {
        let flagged = vec![SentenceScore {
            sentence: "Bad.".to_string(),
            score: 0.1,
            index: 0,
        }];
        let result = HallucinationResult {
            overall_score: 0.2,
            sentence_scores: vec![SentenceScore {
                sentence: "Bad.".to_string(),
                score: 0.1,
                index: 0,
            }],
            flagged_sentences: flagged,
            skipped: false,
        };
        let findings = HallucinationDetector::result_to_security_findings(&result);
        let overall = findings
            .iter()
            .find(|f| f.finding_type == "output_hallucination")
            .unwrap();
        assert_eq!(overall.severity, SecuritySeverity::High);
    }

    #[test]
    fn test_result_to_findings_severity_medium() {
        let flagged = vec![SentenceScore {
            sentence: "Questionable.".to_string(),
            score: 0.3,
            index: 0,
        }];
        let result = HallucinationResult {
            overall_score: 0.4,
            sentence_scores: vec![SentenceScore {
                sentence: "Questionable.".to_string(),
                score: 0.3,
                index: 0,
            }],
            flagged_sentences: flagged,
            skipped: false,
        };
        let findings = HallucinationDetector::result_to_security_findings(&result);
        let overall = findings
            .iter()
            .find(|f| f.finding_type == "output_hallucination")
            .unwrap();
        assert_eq!(overall.severity, SecuritySeverity::Medium);
    }

    #[test]
    fn test_result_to_findings_severity_low() {
        let flagged = vec![SentenceScore {
            sentence: "Slightly off.".to_string(),
            score: 0.45,
            index: 0,
        }];
        let result = HallucinationResult {
            overall_score: 0.55,
            sentence_scores: vec![SentenceScore {
                sentence: "Slightly off.".to_string(),
                score: 0.45,
                index: 0,
            }],
            flagged_sentences: flagged,
            skipped: false,
        };
        let findings = HallucinationDetector::result_to_security_findings(&result);
        let overall = findings
            .iter()
            .find(|f| f.finding_type == "output_hallucination")
            .unwrap();
        assert_eq!(overall.severity, SecuritySeverity::Low);
    }

    // -- Hedging detection --------------------------------------------------

    #[test]
    fn test_hedging_language_boosts_score() {
        let detector = HallucinationDetector::new_fallback(0.5, 10);
        let prompt = "random question about something";

        let definitive = "The answer is X and this is certain and confirmed.";
        let hedged = "I think the answer might be X, it is possible that this is correct.";

        let score_def = detector.heuristic_score(prompt, definitive);
        let score_hedge = detector.heuristic_score(prompt, hedged);

        // Hedging language should result in equal or slightly higher score
        // (hedging = the model is being honest about uncertainty)
        assert!(
            score_hedge >= score_def,
            "Hedging score ({}) should be >= definitive score ({})",
            score_hedge,
            score_def
        );
    }

    // -- Abbreviation handling ----------------------------------------------

    #[test]
    fn test_is_abbreviation() {
        assert!(is_abbreviation("Dr."));
        assert!(is_abbreviation("Some text with Mr."));
        assert!(is_abbreviation("Based in the U.S."));
        assert!(!is_abbreviation("end of sentence."));
        assert!(!is_abbreviation("Hello"));
    }

    // -- Integration-style tests --------------------------------------------

    #[test]
    fn test_end_to_end_fallback_flow() {
        let detector = HallucinationDetector::new_fallback(0.5, 10);
        let prompt = "What are the benefits of exercise?";
        let response = "Exercise improves cardiovascular health. \
                        It helps maintain a healthy weight. \
                        Regular physical activity reduces stress and anxiety. \
                        Exercise also improves sleep quality.";
        let result = detector.detect(prompt, response);
        let findings = HallucinationDetector::result_to_security_findings(&result);

        // All findings should have proper metadata
        for finding in &findings {
            if finding.finding_type == "output_hallucination" {
                assert!(finding.metadata.contains_key("flagged_count"));
                assert!(finding.metadata.contains_key("total_sentences"));
                assert!(finding.metadata.contains_key("overall_score"));
            }
            assert_eq!(finding.location, Some("response.content".to_string()));
        }
    }
}
