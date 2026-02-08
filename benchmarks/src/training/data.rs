//! Data loading, stratified splitting, and batch iteration for fusion training.

use candle_core::{DType, Device, Tensor};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Entry in the precomputed manifest, mapping sample ID to tensor row index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub id: String,
    pub label: i64,
    pub index: usize,
}

/// Precompute manifest stored alongside safetensors files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecomputeManifest {
    pub entries: Vec<ManifestEntry>,
    pub total: usize,
    pub benign: usize,
    pub malicious: usize,
    pub embedding_dim: usize,
    pub feature_dim: usize,
}

/// Train/validation split.
pub struct DataSplit {
    pub train_inputs: Tensor,
    pub train_labels: Tensor,
    pub val_inputs: Tensor,
    pub val_labels: Tensor,
    pub train_indices: Vec<usize>,
    pub val_indices: Vec<usize>,
}

/// Mini-batch iterator over pre-loaded tensors. Reshuffles indices each epoch.
pub struct BatchIterator {
    inputs: Tensor,
    labels: Tensor,
    indices: Vec<usize>,
    batch_size: usize,
    pos: usize,
}

impl BatchIterator {
    pub fn new(inputs: Tensor, labels: Tensor, batch_size: usize) -> Self {
        let n = inputs.dim(0).unwrap_or(0);
        Self {
            inputs,
            labels,
            indices: (0..n).collect(),
            batch_size,
            pos: 0,
        }
    }

    /// Reshuffle for a new epoch using a seeded RNG derived from base seed + epoch.
    pub fn reshuffle(&mut self, seed: u64, epoch: usize) {
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(epoch as u64));
        self.indices.shuffle(&mut rng);
        self.pos = 0;
    }

    /// Returns the next mini-batch, or None if the epoch is exhausted.
    pub fn next_batch(&mut self) -> Option<(Tensor, Tensor)> {
        let n = self.indices.len();
        if self.pos >= n {
            return None;
        }

        let end = (self.pos + self.batch_size).min(n);
        let batch_idx: Vec<u32> = self.indices[self.pos..end]
            .iter()
            .map(|&i| i as u32)
            .collect();
        self.pos = end;

        let device = self.inputs.device().clone();
        let idx_tensor = Tensor::new(batch_idx.as_slice(), &device).ok()?;
        let batch_inputs = self.inputs.index_select(&idx_tensor, 0).ok()?;
        let batch_labels = self.labels.index_select(&idx_tensor, 0).ok()?;

        Some((batch_inputs, batch_labels))
    }
}

/// Load precomputed embeddings and features from cache directory.
///
/// Returns concatenated input tensor `[N, 778]`, label tensor `[N]` (i64), and manifest.
pub fn load_cached_data(
    cache_dir: &Path,
    device: &Device,
) -> Result<(Tensor, Tensor, PrecomputeManifest), String> {
    let manifest_path = cache_dir.join("manifest.json");
    let manifest_str = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest: {e}"))?;
    let manifest: PrecomputeManifest = serde_json::from_str(&manifest_str)
        .map_err(|e| format!("Failed to parse manifest: {e}"))?;

    let emb_path = cache_dir.join("embeddings.safetensors");
    let feat_path = cache_dir.join("features.safetensors");

    let embeddings = load_safetensor(&emb_path, "embeddings", device)?;
    let features = load_safetensor(&feat_path, "features", device)?;

    let inputs = Tensor::cat(&[&embeddings, &features], 1)
        .map_err(|e| format!("Failed to concat embeddings+features: {e}"))?;

    let labels_vec: Vec<i64> = manifest.entries.iter().map(|e| e.label).collect();
    let labels = Tensor::new(labels_vec.as_slice(), device)
        .map_err(|e| format!("Failed to create labels tensor: {e}"))?;

    Ok((inputs, labels, manifest))
}

fn load_safetensor(path: &Path, tensor_name: &str, device: &Device) -> Result<Tensor, String> {
    let data =
        std::fs::read(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let tensors = safetensors::SafeTensors::deserialize(&data)
        .map_err(|e| format!("Failed to parse safetensor {}: {e}", path.display()))?;
    let view = tensors.tensor(tensor_name).map_err(|e| {
        format!(
            "Tensor '{}' not found in {}: {e}",
            tensor_name,
            path.display()
        )
    })?;

    let shape: Vec<usize> = view.shape().to_vec();
    let raw_data = view.data();
    let float_data: Vec<f32> = raw_data
        .chunks_exact(4)
        .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect();

    Tensor::from_vec(float_data, shape.as_slice(), device)
        .map_err(|e| format!("Failed to create tensor from {}: {e}", path.display()))
}

/// Perform stratified train/validation split preserving class ratios.
pub fn stratified_split(
    inputs: &Tensor,
    labels: &Tensor,
    val_ratio: f64,
    seed: u64,
) -> Result<DataSplit, String> {
    let _n = inputs.dim(0).map_err(|e| format!("dim error: {e}"))?;
    let labels_vec: Vec<i64> = labels
        .to_vec1()
        .map_err(|e| format!("Failed to read labels: {e}"))?;

    let mut class0: Vec<usize> = Vec::new();
    let mut class1: Vec<usize> = Vec::new();
    for (i, &l) in labels_vec.iter().enumerate() {
        if l == 0 {
            class0.push(i);
        } else {
            class1.push(i);
        }
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    class0.shuffle(&mut rng);
    class1.shuffle(&mut rng);

    let val0 = (class0.len() as f64 * val_ratio).round() as usize;
    let val1 = (class1.len() as f64 * val_ratio).round() as usize;

    let val_indices: Vec<usize> = class0[..val0]
        .iter()
        .chain(class1[..val1].iter())
        .copied()
        .collect();
    let train_indices: Vec<usize> = class0[val0..]
        .iter()
        .chain(class1[val1..].iter())
        .copied()
        .collect();

    let device = inputs.device().clone();

    let train_inputs = gather_rows(inputs, &train_indices, &device)?;
    let val_inputs = gather_rows(inputs, &val_indices, &device)?;

    let train_labels_vec: Vec<i64> = train_indices.iter().map(|&i| labels_vec[i]).collect();
    let val_labels_vec: Vec<i64> = val_indices.iter().map(|&i| labels_vec[i]).collect();

    let train_labels = Tensor::new(train_labels_vec.as_slice(), &device)
        .map_err(|e| format!("train labels tensor: {e}"))?;
    let val_labels = Tensor::new(val_labels_vec.as_slice(), &device)
        .map_err(|e| format!("val labels tensor: {e}"))?;

    println!(
        "Split: train={} ({}+{}) val={} ({}+{})",
        train_indices.len(),
        class0.len() - val0,
        class1.len() - val1,
        val_indices.len(),
        val0,
        val1,
    );

    Ok(DataSplit {
        train_inputs,
        train_labels,
        val_inputs,
        val_labels,
        train_indices,
        val_indices,
    })
}

fn gather_rows(tensor: &Tensor, indices: &[usize], device: &Device) -> Result<Tensor, String> {
    if indices.is_empty() {
        let cols = tensor.dim(1).map_err(|e| format!("dim error: {e}"))?;
        return Tensor::zeros((0, cols), DType::F32, device)
            .map_err(|e| format!("empty tensor: {e}"));
    }
    let idx: Vec<u32> = indices.iter().map(|&i| i as u32).collect();
    let idx_tensor = Tensor::new(idx.as_slice(), device).map_err(|e| format!("idx tensor: {e}"))?;
    tensor
        .index_select(&idx_tensor, 0)
        .map_err(|e| format!("index_select: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_iterator_exhausts() {
        let device = Device::Cpu;
        let inputs = Tensor::zeros((10, 4), DType::F32, &device).unwrap();
        let labels = Tensor::zeros(10, DType::I64, &device).unwrap();

        let mut iter = BatchIterator::new(inputs, labels, 3);
        iter.reshuffle(42, 0);

        let mut count = 0;
        while iter.next_batch().is_some() {
            count += 1;
        }
        assert_eq!(count, 4); // ceil(10/3) = 4
    }

    #[test]
    fn test_stratified_split_preserves_ratio() {
        let device = Device::Cpu;
        // 8 benign (0), 2 malicious (1)
        let labels_vec: Vec<i64> = vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 1];
        let inputs = Tensor::zeros((10, 4), DType::F32, &device).unwrap();
        let labels = Tensor::new(labels_vec.as_slice(), &device).unwrap();

        let split = stratified_split(&inputs, &labels, 0.2, 42).unwrap();

        let val_labels: Vec<i64> = split.val_labels.to_vec1().unwrap();
        let val_benign = val_labels.iter().filter(|&&l| l == 0).count();
        // 20% of 8 benign = 2 (rounded), 20% of 2 malicious = 0 (rounded)
        assert!(val_benign <= 2);
        assert_eq!(split.train_indices.len() + split.val_indices.len(), 10);
    }
}
