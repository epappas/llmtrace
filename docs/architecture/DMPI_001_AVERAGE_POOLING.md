# DMPI-001: CLS Token to Average Pooling

**Status:** Implementation Plan
**Deviation:** DMPI-001 (see TODO.md, FEATURE_ROADMAP.md section 3.4.1a)
**Paper:** DMPI-PMHFE (arXiv 2506.06384), Section III-A

---

## 1. Problem Statement

The DMPI-PMHFE paper specifies **average pooling** over all token embeddings to produce the fixed-dimensional semantic feature vector for fusion. The current LLMTrace implementation extracts the **CLS token** (position 0) for BERT and uses `DebertaV2ContextPooler` (dense + activation on CLS) for DeBERTa.

**Current behaviour:**

```
BERT:     hidden_states[:, 0, :]        -> shape [hidden_size]
DeBERTa:  ContextPooler(hidden[:, 0, :]) -> shape [hidden_size]
```

**Paper-required behaviour:**

```
Both:     mean(hidden_states * mask, dim=seq) / sum(mask, dim=seq)  -> shape [hidden_size]
```

Average pooling captures information from **all** token positions rather than relying on a single CLS position. This is critical because the paper's fusion classifier was designed and evaluated with average-pooled features.

---

## 2. Scope

### In Scope

- Replace CLS extraction with masked average pooling in `EmbeddingModel::extract_embedding`
- Add `PoolingStrategy` enum to allow runtime selection (backward compatibility)
- Remove `DebertaV2ContextPooler` dependency for the average pooling path
- Update `build_embedding_model` to conditionally skip pooler loading
- Update doc comments across affected modules
- Add unit tests for the new pooling logic

### Out of Scope

- Changes to `HEURISTIC_FEATURE_DIM` (that is DMPI-003)
- Changes to the fusion FC layer count (that is DMPI-002)
- Changes to the classification model paths (BERT/DeBERTa classifiers are separate)
- Training or fine-tuning weights

---

## 3. Architecture

### 3.1 PoolingStrategy Enum

```rust
/// Pooling strategy for extracting a fixed-size embedding from transformer hidden states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolingStrategy {
    /// Extract the CLS token at position 0 (legacy behaviour).
    Cls,
    /// Average pool over all non-padding tokens, weighted by attention mask.
    /// This matches the DMPI-PMHFE paper specification.
    MeanPool,
}
```

Default: `MeanPool` (paper-aligned).

### 3.2 Masked Average Pooling Algorithm

```
Input:
  hidden_states: Tensor [batch=1, seq_len, hidden_size]
  attention_mask: Tensor [batch=1, seq_len]  (values: 0 for padding, 1 for real tokens)

Steps:
  1. Cast attention_mask to f32:        mask_f32 [1, seq_len]
  2. Expand mask to hidden dim:         mask_3d  [1, seq_len, hidden_size]
  3. Element-wise multiply:             masked   = hidden_states * mask_3d
  4. Sum over sequence dimension:       summed   [1, hidden_size]
  5. Count valid tokens per position:   counts   [1, hidden_size]  (broadcast from sum of mask)
  6. Divide:                            pooled   = summed / counts
  7. Squeeze batch dim:                 result   [hidden_size]
```

Division-by-zero safety: `counts` is clamped to a minimum of 1e-9 (at least one real token is always present after tokenization).

### 3.3 EmbeddingModel Changes

```
Before:
  enum EmbeddingModel {
      Bert(Box<BertModel>),
      DebertaV2 { model, pooler },
  }

After:
  enum EmbeddingModel {
      Bert { model: Box<BertModel>, strategy: PoolingStrategy },
      DebertaV2 { model: Box<DebertaV2Model>, pooler: Option<Box<DebertaV2ContextPooler>>, strategy: PoolingStrategy },
  }
```

The `pooler` becomes `Option` because it is only needed when `strategy == Cls`.

### 3.4 Data Flow (After Change)

```
LoadedModel::extract_embedding(text)
  |
  +-- tokenizer.encode(text)
  |     -> ids, type_ids, attention_mask (as u32 arrays)
  |
  +-- create Tensor [1, seq_len] for each
  |
  +-- EmbeddingModel::extract_embedding(input_ids, token_type_ids, attention_mask)
        |
        +-- model.forward(input_ids, token_type_ids, Some(attention_mask))
        |     -> hidden_states [1, seq_len, 768]
        |
        +-- match strategy:
              Cls      -> hidden_states[:, 0, :].squeeze(0)  -> [768]
              MeanPool -> masked_mean_pool(hidden_states, attention_mask).squeeze(0)  -> [768]
```

### 3.5 File Change Map

| File | Change | Lines Affected |
|------|--------|---------------|
| `ml_detector.rs` | Add `PoolingStrategy` enum | New, near line 108 |
| `ml_detector.rs` | Add `masked_mean_pool` free function | New |
| `ml_detector.rs` | Refactor `EmbeddingModel` enum variants | Lines 112-121 |
| `ml_detector.rs` | Refactor `extract_embedding` to dispatch on strategy | Lines 123-150 |
| `ml_detector.rs` | Update `build_embedding_model` signature and body | Lines 558-602 |
| `ml_detector.rs` | Add unit tests for pooling | Test module |
| `fusion_classifier.rs` | Update doc comments (CLS -> average pooling) | Lines 1-15, 103 |
| `feature_extraction.rs` | Update doc comment (CLS -> average pooling) | Line 5 |

### 3.6 Output Dimension

Average pooling produces the same output shape as CLS extraction: `[hidden_size]` (768 for DeBERTa-v3-base). No changes needed in:

- `FUSION_INPUT_DIM` (stays 783 = 768 + 15)
- `FusionClassifier` layer dimensions
- `extract_heuristic_features` (unchanged)
- `EnsembleSecurityAnalyzer::analyze_with_fusion` (unchanged)

---

## 4. Implementation Steps

1. Add `PoolingStrategy` enum and `masked_mean_pool` function to `ml_detector.rs`
2. Refactor `EmbeddingModel` enum to carry `PoolingStrategy` per variant
3. Refactor `extract_embedding` to dispatch on strategy for both BERT and DeBERTa
4. Update `build_embedding_model` to accept `PoolingStrategy` and conditionally load pooler
5. Thread `PoolingStrategy` from config (default `MeanPool`)
6. Update doc comments in `fusion_classifier.rs` and `feature_extraction.rs`
7. Add unit tests for `masked_mean_pool` and strategy dispatch
8. Run full test suite (`cargo test --package llmtrace-security`)
9. Run `cargo clippy` and `cargo fmt --check`
10. Update DMPI-001 status in TODO.md and FEATURE_ROADMAP.md

---

## 5. Testing Strategy

### Unit Tests (ml_detector.rs)

| Test | Validates |
|------|-----------|
| `test_masked_mean_pool_shape` | Output shape is [hidden_size] for known input |
| `test_masked_mean_pool_uniform` | Uniform hidden states produce the same value after pooling |
| `test_masked_mean_pool_respects_mask` | Padding tokens (mask=0) are excluded from the average |
| `test_cls_strategy_still_works` | CLS extraction path produces correct shape |

### Existing Tests (must still pass)

- `fusion_classifier::tests` (5 tests) - embedding dim unchanged at 768
- `feature_extraction::tests` (9 tests) - heuristic features unchanged
- `ensemble::tests` (34 tests) - fusion pipeline unchanged
- `owasp_llm_top10` (63 integration tests) - regex path unchanged

---

## 6. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Division by zero in pooling | Clamp denominator to min 1e-9 |
| Candle API incompatibility | Verified: `Tensor::mean`, `broadcast_as`, `to_dtype` all exist in candle-core 0.9.2 |
| Output dimension change | None: average pooling produces same [hidden_size] as CLS |
| Breaking existing fusion weights | Random weights are re-initialised; no trained weights exist yet |
| Performance regression | Average pooling adds one sum + one division over seq_len; negligible vs transformer forward pass |
