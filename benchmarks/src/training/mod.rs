//! Fusion classifier training pipeline.
//!
//! Provides the infrastructure for training the feature-level fusion classifier
//! (778 -> 256 -> 2 FC network) that combines DeBERTa embeddings with heuristic features.

pub mod data;
pub mod metrics;
pub mod precompute;
pub mod trainer;
