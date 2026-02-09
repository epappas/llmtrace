//! Training loop for the fusion classifier with early stopping.

use crate::training::data::{load_cached_data, stratified_split, BatchIterator};
use crate::training::metrics::{compute_validation_metrics, ValidationMetrics};
use candle_core::{Device, Tensor};
use candle_nn::{Optimizer, VarMap};
use llmtrace_security::FusionClassifier;
use std::path::Path;

/// Training configuration.
pub struct TrainConfig {
    pub lr: f64,
    pub weight_decay: f64,
    pub batch_size: usize,
    pub max_epochs: usize,
    pub patience: usize,
    pub val_ratio: f64,
    pub seed: u64,
    pub output_path: String,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            lr: 1e-3,
            weight_decay: 1e-4,
            batch_size: 256,
            max_epochs: 100,
            patience: 10,
            val_ratio: 0.2,
            seed: 42,
            output_path: "models/fusion_classifier.safetensors".to_string(),
        }
    }
}

/// Per-epoch metrics logged during training.
#[derive(Debug, Clone)]
pub struct EpochMetrics {
    pub epoch: usize,
    pub train_loss: f64,
    pub val_loss: f64,
    pub val_metrics: ValidationMetrics,
}

/// Run the full training pipeline: load data, split, train, save best model.
pub fn train(config: &TrainConfig, cache_dir: &Path) -> Result<Vec<EpochMetrics>, String> {
    let device = Device::Cpu;

    println!("Loading cached data from {}", cache_dir.display());
    let (inputs, labels, manifest) = load_cached_data(cache_dir, &device)?;
    println!(
        "Data: {} samples ({} benign, {} malicious)",
        manifest.total, manifest.benign, manifest.malicious,
    );

    let split = stratified_split(&inputs, &labels, config.val_ratio, config.seed)?;

    let varmap = VarMap::new();
    let model = FusionClassifier::new_trainable(&varmap, &device)
        .map_err(|e| format!("Failed to create trainable model: {e}"))?;

    let mut optimizer = candle_nn::AdamW::new(
        varmap.all_vars(),
        candle_nn::ParamsAdamW {
            lr: config.lr,
            weight_decay: config.weight_decay,
            ..Default::default()
        },
    )
    .map_err(|e| format!("Failed to create optimizer: {e}"))?;
    let mut best_val_loss = f64::MAX;
    let mut patience_counter = 0usize;
    let mut epoch_history: Vec<EpochMetrics> = Vec::new();

    let mut batch_iter = BatchIterator::new(
        split.train_inputs.clone(),
        split.train_labels.clone(),
        config.batch_size,
    );

    println!(
        "\nTraining: lr={}, wd={}, batch={}, max_epochs={}, patience={}",
        config.lr, config.weight_decay, config.batch_size, config.max_epochs, config.patience,
    );
    println!("{:-<80}", "");

    for epoch in 0..config.max_epochs {
        batch_iter.reshuffle(config.seed, epoch);

        let mut epoch_loss = 0.0;
        let mut batch_count = 0;

        while let Some((batch_inputs, batch_labels)) = batch_iter.next_batch() {
            let logits = model
                .forward_logits(&batch_inputs)
                .map_err(|e| format!("Forward pass failed: {e}"))?;

            let loss = candle_nn::loss::cross_entropy(&logits, &batch_labels)
                .map_err(|e| format!("Loss computation failed: {e}"))?;

            optimizer
                .backward_step(&loss)
                .map_err(|e| format!("Backward step failed: {e}"))?;

            let loss_val: f64 =
                loss.to_scalar::<f32>()
                    .map_err(|e| format!("Loss scalar failed: {e}"))? as f64;
            epoch_loss += loss_val;
            batch_count += 1;
        }

        let avg_train_loss = if batch_count > 0 {
            epoch_loss / batch_count as f64
        } else {
            0.0
        };

        let (val_loss, val_metrics) = validate(&model, &split.val_inputs, &split.val_labels)?;

        let improved = val_loss < best_val_loss;
        if improved {
            best_val_loss = val_loss;
            patience_counter = 0;
            save_model(&varmap, &config.output_path)?;
        } else {
            patience_counter += 1;
        }

        let marker = if improved { "*" } else { "" };
        println!(
            "  epoch {:3} | train_loss={:.4} val_loss={:.4} {} | {}",
            epoch + 1,
            avg_train_loss,
            val_loss,
            marker,
            val_metrics,
        );

        epoch_history.push(EpochMetrics {
            epoch: epoch + 1,
            train_loss: avg_train_loss,
            val_loss,
            val_metrics,
        });

        if patience_counter >= config.patience {
            println!(
                "\nEarly stopping at epoch {} (patience={} exhausted)",
                epoch + 1,
                config.patience,
            );
            break;
        }
    }

    println!("{:-<80}", "");
    println!("Best val loss: {:.4}", best_val_loss);
    println!("Model saved to: {}", config.output_path);

    Ok(epoch_history)
}

fn validate(
    model: &FusionClassifier,
    val_inputs: &Tensor,
    val_labels: &Tensor,
) -> Result<(f64, ValidationMetrics), String> {
    let n = val_inputs.dim(0).map_err(|e| format!("val dim: {e}"))?;
    if n == 0 {
        return Ok((
            0.0,
            ValidationMetrics {
                accuracy: 0.0,
                precision: 0.0,
                recall: 0.0,
                f1: 0.0,
                fpr: 0.0,
                tp: 0,
                fp: 0,
                tn: 0,
                fn_count: 0,
            },
        ));
    }

    let logits = model
        .forward_logits(val_inputs)
        .map_err(|e| format!("Val forward failed: {e}"))?;

    let val_loss = candle_nn::loss::cross_entropy(&logits, val_labels)
        .map_err(|e| format!("Val loss failed: {e}"))?;
    let val_loss_val: f64 = val_loss
        .to_scalar::<f32>()
        .map_err(|e| format!("Val loss scalar: {e}"))? as f64;

    let preds = logits
        .argmax(candle_core::D::Minus1)
        .map_err(|e| format!("argmax failed: {e}"))?;
    let preds_vec: Vec<i64> = preds.to_vec1().map_err(|e| format!("preds to vec: {e}"))?;
    let labels_vec: Vec<i64> = val_labels
        .to_vec1()
        .map_err(|e| format!("val labels to vec: {e}"))?;

    let metrics = compute_validation_metrics(&preds_vec, &labels_vec);

    Ok((val_loss_val, metrics))
}

fn save_model(varmap: &VarMap, output_path: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(output_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {e}"))?;
    }
    varmap
        .save(output_path)
        .map_err(|e| format!("Failed to save model: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_train_config_default() {
        let cfg = TrainConfig::default();
        assert!((cfg.lr - 1e-3).abs() < 1e-9);
        assert_eq!(cfg.batch_size, 256);
        assert_eq!(cfg.max_epochs, 100);
        assert_eq!(cfg.patience, 10);
        assert_eq!(cfg.seed, 42);
    }
}
