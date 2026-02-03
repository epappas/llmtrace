# WASP: Web Agent Security Against Prompt Injection

**Date:** 2026-02-03  
**Paper:** WASP: Benchmarking Web Agent Security Against Prompt Injection Attacks  
**arXiv:** 2504.18575v1  
**URL:** https://arxiv.org/pdf/2504.18575
**Source PDF:** `docs/research/papers/2504.18575.pdf`

## LLMTrace Application Notes

- Required signals/features: tool outputs (web content), tool schemas, agent actions, response text, and outcome labels (task success, attack success).
- Runtime characteristics: benchmark-driven evaluation is offline/async; online deployment can log inputs/outputs with minimal latency impact.
- Integration surface (proxy): capture HTTP tool outputs and tag with provenance so detectors can score indirect injection risk.
- Productizable vs research-only: telemetry capture and attack-success metrics are productizable; benchmark replication and data labeling are research-heavy.

## Summary

WASP introduces a benchmark for web-agent prompt-injection security, targeting realistic browsing workflows where malicious content can manipulate an agent's behavior. The benchmark defines tasks and adversarial webpages to evaluate model robustness, and reports that even strong LLM-based agents remain vulnerable to practical prompt-injection attacks.

## Relevance to LLMTrace

LLMTrace can use WASP-style telemetry to capture task success alongside attack success, enabling risk scoring that reflects real agent outcomes rather than only classifier scores. The benchmark also highlights the need to log tool outputs and web content as first-class inputs to security analysis.
