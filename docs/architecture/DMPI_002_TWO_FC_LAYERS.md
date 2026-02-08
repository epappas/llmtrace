# DMPI-002: Reduce Fusion Classifier from 3 FC Layers to 2

**Status:** Done
**Deviation:** DMPI-002 (see TODO.md, FEATURE_ROADMAP.md section 3.4.1a)
**Paper:** DMPI-PMHFE (arXiv 2506.06384), Section III

---

## 1. Problem Statement

The DMPI-PMHFE paper specifies exactly **2 FC layers** in the fusion classifier:

```
Concatenation -> FC + ReLU -> FC + SoftMax -> Binary Prediction
```

The previous implementation had 3 FC layers:

```
Input(783) -> FC(256) -> ReLU -> FC(64) -> ReLU -> FC(2) -> Softmax
```

The extra hidden layer (64-dim) with its ReLU activation was not present in the paper architecture. Training on this 3-layer architecture would not reproduce paper results.

---

## 2. Scope

### In Scope

- Remove `HIDDEN_2` constant (was 64)
- Remove `fc3` field from `FusionClassifier` struct
- Change `fc2` from `Linear(256, 64)` to `Linear(256, 2)` -- directly producing class logits
- Remove second hidden layer computation (`h2` + ReLU) from `predict()`
- Update doc comments (module-level, struct-level, forward pass)

### Out of Scope

- Changes to `HEURISTIC_FEATURE_DIM` (that is DMPI-003)
- Changes to pooling strategy (that is DMPI-001, already done)
- Feature naming changes (that is DMPI-006)
- Training or fine-tuning weights

---

## 3. Architecture

### Before (3 FC layers)

```
Input [783] -> fc1 Linear(783, 256) -> ReLU -> fc2 Linear(256, 64) -> ReLU -> fc3 Linear(64, 2) -> Softmax
```

Parameters: 783*256 + 256 + 256*64 + 64 + 64*2 + 2 = 217,474

### After (2 FC layers, paper-aligned)

```
Input [783] -> fc1 Linear(783, 256) -> ReLU -> fc2 Linear(256, 2) -> Softmax
```

Parameters: 783*256 + 256 + 256*2 + 2 = 201,026

### Data Flow

```
predict(embedding: [768], heuristic_features: [15])
  |
  +-- Concatenate -> input [783]
  |
  +-- Unsqueeze -> [1, 783]
  |
  +-- fc1: Linear(783, 256) -> [1, 256]
  |
  +-- ReLU -> [1, 256]
  |
  +-- fc2: Linear(256, 2) -> [1, 2]  (logits)
  |
  +-- Softmax(dim=-1) -> [1, 2]  (probabilities)
  |
  +-- Squeeze -> [2]
  |
  +-- (safe_score, injection_score)
```

---

## 4. File Changes

| File | Change |
|------|--------|
| `fusion_classifier.rs` | Removed `HIDDEN_2` constant, `fc3` field, second hidden layer in forward pass. Changed `fc2` dims from `(256, 64)` to `(256, 2)`. Updated doc comments. |

### Unchanged Interfaces

- `FusionClassifier::new_random(device)` -- same signature
- `FusionClassifier::load(path, device)` -- same signature
- `FusionClassifier::predict(embedding, heuristic_features)` -- same signature and return type
- `ensemble.rs` callers require no changes

---

## 5. Testing

All existing tests pass without modification:

| Test | Validates |
|------|-----------|
| `test_fusion_input_dim` | Input dimension still 783 (768 + 15) |
| `test_new_random_creates_classifier` | Constructor works with 2-layer architecture |
| `test_predict_with_random_weights` | Forward pass produces valid softmax probabilities summing to 1.0 |
| `test_predict_with_nonzero_features` | Non-zero inputs produce valid probabilities |
| `test_load_nonexistent_path_fails` | Error handling unchanged |

---

## 6. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Breaking trained weights | No trained weights exist yet (random initialization only) |
| Changed output distribution | Softmax still produces valid probabilities; tests verify sum-to-1.0 |
| Caller impact | Public API unchanged; `ensemble.rs` uses same `new_random`/`load`/`predict` |
| Input dimension change | Input dim stays 783 until DMPI-003 changes it to 778 |

---

## 7. Paper Reference

DMPI-PMHFE (arXiv 2506.06384), Section III:

> "The concatenated features are passed through two fully connected layers with a ReLU activation function after the first layer and a SoftMax function after the second layer to produce the final binary prediction."

Architecture: `Concatenation -> FC + ReLU -> FC + SoftMax -> Binary Prediction`
