---
title: Research library
description: The research corpus that informs LLMTrace's defence pipeline, detection models, and threat coverage.
---

# Research library

This is the living research corpus behind LLMTrace — the academic papers, benchmarks, attack taxonomies, and defence techniques that shape what the proxy actually does. Every detector, threshold, and architectural decision is traceable to the material here.

## Landscape & OWASP

- [Landscape](landscape.md) — broad survey of the prompt-injection and agent-security space.
- [State of the art 2026](security-state-of-art-2026.md) — current research frontier.
- [Benchmarks & tools landscape](benchmarks-and-tools-landscape.md) — what exists to measure detectors.
- [OWASP GenAI Top 10 2025 references](owasp-genai-top10-2025-references.md) — primary source index.
- [LLMTrace OWASP GenAI architecture report](llmtrace-owasp-genai-architecture-report.md) — how our design maps to the Top 10.
- [LLMTrace defence pipeline design](llmtrace-defence-pipeline-design.md) — the blueprint the proxy implements.

## Attacks & benchmarks

- [BIPIA — indirect prompt injection](bipia-indirect-prompt-injection-benchmark.md)
- [CyberSecEval2 — LLM security benchmark](cyberseceval2-llm-security-benchmark.md)
- [WASP — web-agent security benchmark](wasp-web-agent-security-benchmark.md)
- [Prompt injections → protocol exploits](prompt-injections-to-protocol-exploits.md)
- [Bypassing LLM guardrails (evasion)](bypassing-llm-guardrails-evasion.md)
- [Agent-as-a-proxy attacks](agent-as-a-proxy-attacks.md)
- [LLM jailbreaks prompt collection](llm-jailbreaks-prompt-collection.md)

## Defence techniques

- [Spotlighting indirect injection](spotlighting-indirect-injection-defence.md)
- [Instruction hierarchy](instruction-hierarchy-defence.md)
- [Task Shield alignment](task-shield-alignment-defence.md)
- [Tool result parsing](defence-tool-result-parsing.md)
- [Indirect injection firewalls](indirect-injection-firewalls.md)
- [Multi-agent defence pipeline](multi-agent-defence-pipeline.md)
- [InjecGuard over-defence mitigation](injecguard-over-defence-mitigation.md)
- [Design patterns for securing agents](design-patterns-securing-agents.md)

## Detection methods

- [DMPI + PMHFE prompt-injection detection](dmpi-pmhfe-prompt-injection-detection.md)
- [Perplexity-based attack detection](perplexity-based-attack-detection.md)
- [Token-level perplexity detection](token-level-perplexity-detection.md)
- [Self-distillation continual learning](self-distillation-continual-learning.md)
- [LLM-judge reliability patterns](llm-judge-reliability-patterns.md)

## Evaluations & results

- [Judge evaluation — `gpt-4o-mini` on 27 corpora (2026-04-20)](results/judge_evaluation_gpt4o_mini_2026-04-20.md) — baseline run of the LLM-as-a-Judge against 23 external academic corpora plus 4 local curated sets (1,274 samples, F1 = 0.856).
- [Regex FPR calibration](results/fpr_calibration_regex.md)

## Roadmap & training plans

- [autoresearch-rl judge fine-tuning plan](autoresearch-rl-judge-training-plan.md) — 6-phase execution plan for training a local Qwen-0.5B LoRA on LLMTrace's 6-field schema; tracked under #90.

## Primary sources

- [Papers](papers.md) — archived PDFs of the cited papers.
- Diagrams (Mermaid source): `research/diagrams/` in the repository.
