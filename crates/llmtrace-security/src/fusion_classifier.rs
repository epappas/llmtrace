//! Feature-level fusion classifier for prompt injection detection (ADR-013).
//!
//! Implements a fully-connected neural network that concatenates DeBERTa
//! average-pooled embeddings (768-dim) with heuristic feature vectors (10-dim)
//! and produces a 2-class (safe/injection) output.
//!
//! The embedding is produced by masked average pooling over all non-padding
//! tokens, matching the DMPI-PMHFE paper specification (arXiv 2506.06384).
//!
//! # Architecture
//!
//! ```text
//! Input (778) → Linear(256) → ReLU → Linear(2) → Softmax
//! ```
//!
//! # Feature Gate
//!
//! This module is only available when the `ml` feature is enabled.

use candle_core::{DType, Device, Tensor};
use candle_nn::{VarBuilder, VarMap};
use llmtrace_core::{LLMTraceError, Result};

use crate::feature_extraction::HEURISTIC_FEATURE_DIM;

/// Default embedding dimension (DeBERTa-v3-base hidden size).
pub const DEFAULT_EMBEDDING_DIM: usize = 768;

/// Total input dimension: embedding + heuristic features.
pub const FUSION_INPUT_DIM: usize = DEFAULT_EMBEDDING_DIM + HEURISTIC_FEATURE_DIM;

/// Number of output classes (safe, injection).
const NUM_CLASSES: usize = 2;

/// Hidden layer dimension.
const HIDDEN_1: usize = 256;

/// Feature-level fusion classifier.
///
/// A 2-layer fully-connected network that takes concatenated embedding +
/// heuristic features and outputs injection/safe logits.
pub struct FusionClassifier {
    fc1: candle_nn::Linear,
    fc2: candle_nn::Linear,
    device: Device,
}

impl FusionClassifier {
    /// Create a new fusion classifier with random weights.
    ///
    /// Suitable for architecture validation. For production, use
    /// [`FusionClassifier::load`] with trained weights.
    pub fn new_random(device: &Device) -> Result<Self> {
        let varmap = VarMap::new();
        let vb = VarBuilder::from_varmap(&varmap, DType::F32, device);

        let fc1 = candle_nn::linear(FUSION_INPUT_DIM, HIDDEN_1, vb.pp("fc1"))
            .map_err(|e| LLMTraceError::Security(format!("Failed to create fusion fc1: {e}")))?;
        let fc2 = candle_nn::linear(HIDDEN_1, NUM_CLASSES, vb.pp("fc2"))
            .map_err(|e| LLMTraceError::Security(format!("Failed to create fusion fc2: {e}")))?;

        Ok(Self {
            fc1,
            fc2,
            device: device.clone(),
        })
    }

    /// Load a fusion classifier from a safetensors file.
    ///
    /// Returns an error if the file cannot be read or the weights are
    /// incompatible with the expected architecture.
    pub fn load(path: &str, device: &Device) -> Result<Self> {
        let path = std::path::PathBuf::from(path);
        // SAFETY: memory-mapping safetensors is the standard candle pattern.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[path], DType::F32, device).map_err(|e| {
                LLMTraceError::Security(format!("Failed to load fusion weights: {e}"))
            })?
        };

        let fc1 = candle_nn::linear(FUSION_INPUT_DIM, HIDDEN_1, vb.pp("fc1"))
            .map_err(|e| LLMTraceError::Security(format!("Failed to load fusion fc1: {e}")))?;
        let fc2 = candle_nn::linear(HIDDEN_1, NUM_CLASSES, vb.pp("fc2"))
            .map_err(|e| LLMTraceError::Security(format!("Failed to load fusion fc2: {e}")))?;

        Ok(Self {
            fc1,
            fc2,
            device: device.clone(),
        })
    }

    /// Run a forward pass through the fusion classifier.
    ///
    /// # Arguments
    ///
    /// * `embedding` — Pooled embedding tensor of shape `[embedding_dim]` (typically 768)
    /// * `heuristic_features` — Feature vector of length [`HEURISTIC_FEATURE_DIM`]
    ///
    /// # Returns
    ///
    /// `(injection_score, safe_score)` — softmax probabilities for each class.
    pub fn predict(&self, embedding: &Tensor, heuristic_features: &[f32]) -> Result<(f64, f64)> {
        // Build heuristic feature tensor
        let heuristic_tensor = Tensor::new(heuristic_features, &self.device).map_err(|e| {
            LLMTraceError::Security(format!("Failed to create heuristic tensor: {e}"))
        })?;

        // Concatenate: [embedding_dim + heuristic_dim]
        let input = Tensor::cat(&[embedding, &heuristic_tensor], 0).map_err(|e| {
            LLMTraceError::Security(format!("Failed to concatenate fusion input: {e}"))
        })?;

        // Unsqueeze to [1, input_dim] for the linear layers
        let input = input.unsqueeze(0).map_err(|e| {
            LLMTraceError::Security(format!("Failed to unsqueeze fusion input: {e}"))
        })?;

        // Forward pass: fc1 → ReLU → fc2
        let h1 = candle_nn::Module::forward(&self.fc1, &input)
            .map_err(|e| LLMTraceError::Security(format!("Fusion fc1 forward failed: {e}")))?;
        let h1 = h1
            .relu()
            .map_err(|e| LLMTraceError::Security(format!("Fusion ReLU failed: {e}")))?;

        let logits = candle_nn::Module::forward(&self.fc2, &h1)
            .map_err(|e| LLMTraceError::Security(format!("Fusion fc2 forward failed: {e}")))?;

        // Softmax → probabilities
        let probs = candle_nn::ops::softmax(&logits, candle_core::D::Minus1)
            .map_err(|e| LLMTraceError::Security(format!("Fusion softmax failed: {e}")))?;

        let probs_vec: Vec<f32> = probs.squeeze(0).and_then(|t| t.to_vec1()).map_err(|e| {
            LLMTraceError::Security(format!("Failed to extract fusion probabilities: {e}"))
        })?;

        // Class 0 = safe, Class 1 = injection
        let safe_score = f64::from(probs_vec.first().copied().unwrap_or(0.5));
        let injection_score = f64::from(probs_vec.get(1).copied().unwrap_or(0.5));

        Ok((injection_score, safe_score))
    }

    /// Returns a reference to the device this classifier runs on.
    pub fn device(&self) -> &Device {
        &self.device
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fusion_input_dim() {
        assert_eq!(FUSION_INPUT_DIM, 768 + 10);
        assert_eq!(FUSION_INPUT_DIM, 778);
    }

    #[test]
    fn test_new_random_creates_classifier() {
        let device = Device::Cpu;
        let classifier = FusionClassifier::new_random(&device);
        assert!(classifier.is_ok());
    }

    #[test]
    fn test_predict_with_random_weights() {
        let device = Device::Cpu;
        let classifier = FusionClassifier::new_random(&device).unwrap();

        // Create a dummy embedding (768-dim)
        let embedding = Tensor::zeros(DEFAULT_EMBEDDING_DIM, DType::F32, &device).unwrap();
        // Create dummy heuristic features (10-dim)
        let heuristic_features = vec![0.0_f32; HEURISTIC_FEATURE_DIM];

        let result = classifier.predict(&embedding, &heuristic_features);
        assert!(result.is_ok());

        let (injection_score, safe_score) = result.unwrap();
        // Scores should be valid probabilities
        assert!((0.0..=1.0).contains(&injection_score));
        assert!((0.0..=1.0).contains(&safe_score));
        // Should sum to ~1.0
        assert!((injection_score + safe_score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_predict_with_nonzero_features() {
        let device = Device::Cpu;
        let classifier = FusionClassifier::new_random(&device).unwrap();

        let embedding = Tensor::ones(DEFAULT_EMBEDDING_DIM, DType::F32, &device).unwrap();
        let heuristic_features = vec![1.0_f32; HEURISTIC_FEATURE_DIM];

        let result = classifier.predict(&embedding, &heuristic_features);
        assert!(result.is_ok());

        let (injection_score, safe_score) = result.unwrap();
        assert!((0.0..=1.0).contains(&injection_score));
        assert!((0.0..=1.0).contains(&safe_score));
    }

    #[test]
    fn test_load_nonexistent_path_fails() {
        let device = Device::Cpu;
        let result = FusionClassifier::load("/nonexistent/fusion.safetensors", &device);
        assert!(result.is_err());
    }
}
