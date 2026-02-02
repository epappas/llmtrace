# Self-Distillation Enables Continual Learning (SDFT)

**Paper:** https://arxiv.org/abs/2601.19897  
**Code:** https://github.com/idanshen/Self-Distillation  
**Added:** 2026-02-02

## Abstract

Self-Distillation Fine-Tuning (SDFT) — a simple method that enables on-policy learning directly from demonstrations. SDFT leverages in-context learning by using a demonstration-conditioned model as its own teacher, generating on-policy training signals that preserve prior capabilities while acquiring new skills.

## Key Findings

- **SDFT outperforms SFT** — higher new-task accuracy with substantially reduced catastrophic forgetting
- **Sequential skill accumulation** without performance regression
- **Simple implementation** — TRL-based, runs on single H200 GPU
- Uses `ref_model_mixup_alpha=0.01` for reference model mixing

## Relevance to LLMTrace

Directly applicable to:
- **R-IS-02 (MOF Training Pipeline)** — SDFT could address the challenge of fine-tuning detection models on new attack patterns without losing performance on existing ones
- **ML-012 (Adversarial Training)** — When adding adversarial training samples, SDFT prevents catastrophic forgetting of original detection capability
- **ML-013 (Robust Training)** — Continual learning approach for incorporating Unicode evasion samples without degrading injection detection

The core insight — using the model as its own teacher during fine-tuning — is directly applicable to our security classifier training pipeline where we need to add new attack categories (InjecGuard MOF, adversarial examples) without regressing on existing detection.

## Architecture

1. Standard SFT training on new task data
2. In-context learning: use demonstration-conditioned model as teacher
3. Generate on-policy training signals (not off-policy like standard SFT)
4. Reference model mixup prevents drift from original capabilities

## Citation

```
@article{shen2025selfdistillation,
  title={Self-Distillation Enables Continual Learning},
  author={Idan Shen et al.},
  journal={arXiv preprint arXiv:2601.19897},
  year={2025}
}
```
