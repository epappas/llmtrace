# DMPI-PMHFE: Dual-Channel Prompt Injection Detection

**Date:** 2026-02-03  
**Paper:** Detection Method for Prompt Injection by Integrating Pre-trained Model and Heuristic Feature Engineering  
**arXiv:** 2506.06384v1  
**URL:** https://arxiv.org/pdf/2506.06384
**Source PDF:** `docs/research/papers/2506.06384.pdf`

## LLMTrace Application Notes

- Required signals/features: raw prompt text, conversation history (optional), prompt metadata (user vs tool), regex features, classifier logits, and model score calibration data.
- Runtime characteristics: low-latency classification if DeBERTa is cached; streaming compatible only for chunk-level heuristics unless full prompt is buffered.
- Integration surface (proxy): run a pre-request detector on normalized prompt text, attach risk score to request metadata, and enforce policy thresholds before forwarding.
- Productizable vs research-only: hybrid ML + heuristic detector is productizable; training-time feature fusion and dataset curation are research-heavy.

## Summary

The paper proposes a dual-channel detection framework (DMPI-PMHFE) that fuses a DeBERTa-based semantic feature extractor with heuristic rules that encode explicit attack patterns. The two feature channels are combined and passed to a classifier to produce the final prediction. The authors report improved accuracy, recall, and F1 on multiple benchmark datasets, and a reduction in attack success rates when the detector is used to screen prompts for several mainstream LLMs.

## Relevance to LLMTrace

LLMTrace can mirror the paper's dual-channel approach by combining learned semantic signals with deterministic rules in its observability pipeline. The results also justify measuring both detection quality and downstream attack success rates as first-class metrics in LLMTrace dashboards.
