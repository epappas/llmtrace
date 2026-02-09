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
pub(crate) const NUM_CLASSES: usize = 2;

/// Hidden layer dimension.
pub(crate) const HIDDEN_1: usize = 256;

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

        let logits = self.forward_logits(&input)?;

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

    /// Create a trainable fusion classifier backed by a `VarMap` for gradient tracking.
    ///
    /// The caller owns the `VarMap` and can use it with an optimizer for training.
    /// After training, call `varmap.save(path)` to persist weights.
    pub fn new_trainable(varmap: &VarMap, device: &Device) -> Result<Self> {
        let vb = VarBuilder::from_varmap(varmap, DType::F32, device);

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

    /// Forward pass returning raw logits before softmax.
    ///
    /// Used for training with `cross_entropy` loss (which applies log_softmax internally).
    /// Input shape: `[batch_size, FUSION_INPUT_DIM]`.
    /// Output shape: `[batch_size, NUM_CLASSES]`.
    pub fn forward_logits(&self, input: &Tensor) -> Result<Tensor> {
        let dims = input.dims();
        if dims.len() != 2 || dims[1] != FUSION_INPUT_DIM {
            return Err(LLMTraceError::Security(format!(
                "forward_logits expects [batch, {}], got {:?}",
                FUSION_INPUT_DIM, dims
            )));
        }

        let h1 = candle_nn::Module::forward(&self.fc1, input)
            .map_err(|e| LLMTraceError::Security(format!("Fusion fc1 forward failed: {e}")))?;
        let h1 = h1
            .relu()
            .map_err(|e| LLMTraceError::Security(format!("Fusion ReLU failed: {e}")))?;
        let logits = candle_nn::Module::forward(&self.fc2, &h1)
            .map_err(|e| LLMTraceError::Security(format!("Fusion fc2 forward failed: {e}")))?;
        Ok(logits)
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

    #[test]
    fn test_new_trainable_creates_classifier() {
        let device = Device::Cpu;
        let varmap = VarMap::new();
        let classifier = FusionClassifier::new_trainable(&varmap, &device);
        assert!(classifier.is_ok());
        assert!(!varmap.all_vars().is_empty());
    }

    #[test]
    fn test_forward_logits_shape() {
        let device = Device::Cpu;
        let varmap = VarMap::new();
        let classifier = FusionClassifier::new_trainable(&varmap, &device).unwrap();

        let batch_size = 4;
        let input = Tensor::zeros((batch_size, FUSION_INPUT_DIM), DType::F32, &device).unwrap();
        let logits = classifier.forward_logits(&input).unwrap();
        assert_eq!(logits.dims(), &[batch_size, NUM_CLASSES]);
    }

    #[test]
    fn test_forward_logits_single_sample() {
        let device = Device::Cpu;
        let varmap = VarMap::new();
        let classifier = FusionClassifier::new_trainable(&varmap, &device).unwrap();

        let input = Tensor::zeros((1, FUSION_INPUT_DIM), DType::F32, &device).unwrap();
        let logits = classifier.forward_logits(&input).unwrap();
        assert_eq!(logits.dims(), &[1, NUM_CLASSES]);

        let vals: Vec<Vec<f32>> = logits.to_vec2().unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0].len(), NUM_CLASSES);
    }

    #[test]
    fn test_trainable_save_roundtrip() {
        let device = Device::Cpu;
        let varmap = VarMap::new();
        let classifier = FusionClassifier::new_trainable(&varmap, &device).unwrap();

        let input = Tensor::ones((1, FUSION_INPUT_DIM), DType::F32, &device).unwrap();
        let logits_before = classifier.forward_logits(&input).unwrap();

        let dir = std::env::temp_dir().join("fusion_test_roundtrip");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_fusion.safetensors");
        varmap.save(path.to_str().unwrap()).unwrap();

        let loaded = FusionClassifier::load(path.to_str().unwrap(), &device).unwrap();
        let logits_after = loaded.forward_logits(&input).unwrap();

        let before: Vec<f32> = logits_before.flatten_all().unwrap().to_vec1().unwrap();
        let after: Vec<f32> = logits_after.flatten_all().unwrap().to_vec1().unwrap();
        for (a, b) in before.iter().zip(after.iter()) {
            assert!((a - b).abs() < 1e-6, "Weight mismatch after roundtrip");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_forward_logits_rejects_wrong_shape() {
        let device = Device::Cpu;
        let varmap = VarMap::new();
        let classifier = FusionClassifier::new_trainable(&varmap, &device).unwrap();

        // Wrong feature dim (768 instead of 778)
        let bad_dim = Tensor::zeros((2, 768), DType::F32, &device).unwrap();
        assert!(classifier.forward_logits(&bad_dim).is_err());

        // 1D tensor (missing batch dim)
        let no_batch = Tensor::zeros(FUSION_INPUT_DIM, DType::F32, &device).unwrap();
        assert!(classifier.forward_logits(&no_batch).is_err());
    }

    #[test]
    fn test_gradient_flow_through_forward_logits() {
        let device = Device::Cpu;
        let varmap = VarMap::new();
        let classifier = FusionClassifier::new_trainable(&varmap, &device).unwrap();

        let input = Tensor::ones((2, FUSION_INPUT_DIM), DType::F32, &device).unwrap();
        let labels = Tensor::new(&[0u32, 1u32], &device).unwrap();

        // Compute initial loss.
        let logits = classifier.forward_logits(&input).unwrap();
        let loss = candle_nn::loss::cross_entropy(&logits, &labels).unwrap();
        let loss_before: f32 = loss.to_scalar().unwrap();
        assert!(loss_before.is_finite(), "Initial loss must be finite");

        // One optimizer step -- if gradients don't flow, backward_step errors.
        use candle_nn::Optimizer;
        let params = candle_nn::ParamsAdamW {
            lr: 0.1,
            ..Default::default()
        };
        let mut opt =
            candle_nn::AdamW::new(varmap.all_vars(), params).unwrap();
        opt.backward_step(&loss).unwrap();

        // After the step, the loss on the same input must have changed,
        // proving that weights were updated via gradient flow.
        let logits_after = classifier.forward_logits(&input).unwrap();
        let loss_after: f32 = candle_nn::loss::cross_entropy(&logits_after, &labels)
            .unwrap()
            .to_scalar()
            .unwrap();
        assert!(loss_after.is_finite(), "Post-step loss must be finite");
        assert!(
            (loss_before - loss_after).abs() > 1e-8,
            "Weights did not change after backward step (loss_before={loss_before}, loss_after={loss_after})"
        );
    }
}
