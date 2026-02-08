//! Precompute DeBERTa embeddings and heuristic features for training samples.
//!
//! For each sample in the training dataset:
//! 1. Extract 768-dim embedding via MLSecurityAnalyzer (DeBERTa)
//! 2. Extract 10-dim heuristic feature vector via RegexSecurityAnalyzer findings
//! 3. Store as safetensors for fast loading during training

use crate::datasets::{BenchmarkSample, Label};
use crate::training::data::{ManifestEntry, PrecomputeManifest};
use llmtrace_core::{AnalysisContext, LLMProvider, SecurityAnalyzer, TenantId};
use llmtrace_security::{MLSecurityAnalyzer, MLSecurityConfig, RegexSecurityAnalyzer};
use std::collections::HashMap;
use std::path::Path;

/// Run the precompute step: extract embeddings and features, save to cache directory.
pub async fn precompute(dataset_path: &Path, output_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(output_dir).map_err(|e| format!("Failed to create output dir: {e}"))?;

    let content = std::fs::read_to_string(dataset_path)
        .map_err(|e| format!("Failed to read dataset: {e}"))?;
    let samples: Vec<BenchmarkSample> =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse dataset: {e}"))?;

    println!(
        "Loaded {} samples from {}",
        samples.len(),
        dataset_path.display()
    );

    let config = MLSecurityConfig::default();
    let ml_analyzer = MLSecurityAnalyzer::with_fusion(&config, true)
        .await
        .map_err(|e| format!("Failed to init ML analyzer: {e}"))?;

    if !ml_analyzer.is_model_loaded() {
        return Err("ML model not loaded -- cannot extract embeddings".to_string());
    }
    if !ml_analyzer.is_fusion_enabled() {
        return Err("Fusion not enabled -- embedding extraction unavailable".to_string());
    }

    let regex_analyzer =
        RegexSecurityAnalyzer::new().map_err(|e| format!("Failed to init regex analyzer: {e}"))?;

    let embedding_dim = llmtrace_security::fusion_classifier::DEFAULT_EMBEDDING_DIM;
    let feature_dim = llmtrace_security::feature_extraction::HEURISTIC_FEATURE_DIM;

    let mut all_embeddings: Vec<f32> = Vec::with_capacity(samples.len() * embedding_dim);
    let mut all_features: Vec<f32> = Vec::with_capacity(samples.len() * feature_dim);
    let mut manifest_entries: Vec<ManifestEntry> = Vec::with_capacity(samples.len());
    let mut benign_count = 0usize;
    let mut malicious_count = 0usize;
    let mut skipped = 0usize;

    let context = AnalysisContext {
        tenant_id: TenantId::new(),
        trace_id: uuid::Uuid::new_v4(),
        span_id: uuid::Uuid::new_v4(),
        provider: LLMProvider::OpenAI,
        model_name: "training".to_string(),
        parameters: std::collections::HashMap::new(),
    };

    for (i, sample) in samples.iter().enumerate() {
        let embedding = ml_analyzer
            .extract_embedding(&sample.text)
            .await
            .map_err(|e| format!("Embedding extraction failed for {}: {e}", sample.id))?;

        let embedding = match embedding {
            Some(e) => e,
            None => {
                skipped += 1;
                continue;
            }
        };

        let emb_vec: Vec<f32> = embedding
            .flatten_all()
            .and_then(|t| t.to_vec1())
            .map_err(|e| format!("Failed to read embedding for {}: {e}", sample.id))?;

        if emb_vec.len() != embedding_dim {
            return Err(format!(
                "Embedding dim mismatch for {}: expected {}, got {}",
                sample.id,
                embedding_dim,
                emb_vec.len()
            ));
        }

        let regex_findings = regex_analyzer
            .analyze_request(&sample.text, &context)
            .await
            .unwrap_or_default();

        let feat_vec = llmtrace_security::feature_extraction::extract_heuristic_features(
            &regex_findings,
            &sample.text,
        );

        let label: i64 = match sample.label {
            Label::Benign => 0,
            Label::Malicious => 1,
        };

        let index = manifest_entries.len();
        all_embeddings.extend_from_slice(&emb_vec);
        all_features.extend_from_slice(&feat_vec);
        manifest_entries.push(ManifestEntry {
            id: sample.id.clone(),
            label,
            index,
        });

        match sample.label {
            Label::Benign => benign_count += 1,
            Label::Malicious => malicious_count += 1,
        }

        if (i + 1) % 1000 == 0 || i + 1 == samples.len() {
            println!(
                "  [{}/{}] processed ({} benign, {} malicious, {} skipped)",
                i + 1,
                samples.len(),
                benign_count,
                malicious_count,
                skipped,
            );
        }
    }

    let n = manifest_entries.len();
    if n == 0 {
        return Err("No samples processed successfully".to_string());
    }

    save_safetensor(
        &output_dir.join("embeddings.safetensors"),
        "embeddings",
        &all_embeddings,
        &[n, embedding_dim],
    )?;

    save_safetensor(
        &output_dir.join("features.safetensors"),
        "features",
        &all_features,
        &[n, feature_dim],
    )?;

    let manifest = PrecomputeManifest {
        entries: manifest_entries,
        total: n,
        benign: benign_count,
        malicious: malicious_count,
        embedding_dim,
        feature_dim,
    };
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("manifest serialize: {e}"))?;
    std::fs::write(output_dir.join("manifest.json"), manifest_json)
        .map_err(|e| format!("Failed to write manifest: {e}"))?;

    println!(
        "\nPrecompute complete: {} samples ({} benign, {} malicious, {} skipped)",
        n, benign_count, malicious_count, skipped,
    );
    println!("  embeddings: [{}, {}]", n, embedding_dim);
    println!("  features:   [{}, {}]", n, feature_dim);
    println!("  output dir: {}", output_dir.display());

    Ok(())
}

fn save_safetensor(
    path: &Path,
    tensor_name: &str,
    data: &[f32],
    shape: &[usize],
) -> Result<(), String> {
    let byte_data: Vec<u8> = data.iter().flat_map(|f| f.to_le_bytes()).collect();
    let mut tensors = HashMap::new();
    tensors.insert(
        tensor_name.to_string(),
        safetensors::tensor::TensorView::new(safetensors::Dtype::F32, shape.to_vec(), &byte_data)
            .map_err(|e| format!("TensorView create failed: {e}"))?,
    );
    let serialized =
        safetensors::tensor::serialize(&tensors, &None).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(path, serialized).map_err(|e| format!("Failed to write {}: {e}", path.display()))
}
