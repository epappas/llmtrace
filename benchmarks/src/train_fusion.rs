//! CLI entry point for the fusion classifier training pipeline.
//!
//! Subcommands:
//!   precompute  -- Extract DeBERTa embeddings + heuristic features from training dataset
//!   train       -- Train the fusion classifier on precomputed features

use clap::{Parser, Subcommand};
use llmtrace_benchmarks::training::precompute;
use llmtrace_benchmarks::training::trainer::{self, TrainConfig};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "train-fusion", about = "Fusion classifier training pipeline")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Extract embeddings and heuristic features from the training dataset.
    Precompute {
        /// Path to training_dataset.json.
        #[arg(long)]
        dataset: PathBuf,

        /// Output directory for cached tensors.
        #[arg(long, default_value = "benchmarks/datasets/training/cache")]
        output_dir: PathBuf,
    },

    /// Train the fusion classifier on precomputed features.
    Train {
        /// Directory containing precomputed embeddings/features/manifest.
        #[arg(long, default_value = "benchmarks/datasets/training/cache")]
        cache_dir: PathBuf,

        /// Output path for trained model weights.
        #[arg(long, default_value = "models/fusion_classifier.safetensors")]
        output: String,

        /// Learning rate.
        #[arg(long, default_value = "0.001")]
        lr: f64,

        /// Mini-batch size.
        #[arg(long, default_value = "256")]
        batch_size: usize,

        /// Maximum training epochs.
        #[arg(long, default_value = "100")]
        max_epochs: usize,

        /// Early stopping patience (epochs without improvement).
        #[arg(long, default_value = "10")]
        patience: usize,

        /// Random seed.
        #[arg(long, default_value = "42")]
        seed: u64,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Precompute {
            dataset,
            output_dir,
        } => precompute::precompute(&dataset, &output_dir).await,

        Command::Train {
            cache_dir,
            output,
            lr,
            batch_size,
            max_epochs,
            patience,
            seed,
        } => {
            let config = TrainConfig {
                lr,
                weight_decay: 1e-4,
                batch_size,
                max_epochs,
                patience,
                val_ratio: 0.2,
                seed,
                output_path: output,
            };
            trainer::train(&config, &cache_dir).map(|history| {
                if let Some(last) = history.last() {
                    println!("\nFinal epoch {}: {}", last.epoch, last.val_metrics);
                }
            })
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
