# Bypassing AI Control Protocols via Agent-as-a-Proxy Attacks

**Date:** 2026-02-08
**Paper:** Bypassing AI Control Protocols via Agent-as-a-Proxy Attacks
**Authors:** Jafar Isbarov, Murat Kantarcioglu
**arXiv:** [2602.05066v1](https://arxiv.org/abs/2602.05066)
**Published:** February 4, 2026
**Source PDF:** `docs/research/papers/2602.05066v1.pdf`

## LLMTrace Application Notes

- Required signals/features: agent reasoning traces (CoT), tool call parameters, tool outputs, monitor verdicts, adversarial string patterns (high-perplexity tokens).
- Runtime characteristics: attack is offline (GCG optimization); defense evasion happens at inference time with no extra latency. Detection of high-perplexity strings could add minimal overhead.
- Integration surface (proxy): LLMTrace operates as a monitoring proxy -- this paper directly attacks monitoring-based defenses. Key implication: LLMTrace's detection must go beyond observation-based monitoring to include structural defenses (input sanitization, boundary tokens, tool-output filtering). High-perplexity token detection in tool outputs and CoT traces is a viable countermeasure.
- Productizable vs research-only: high-perplexity string detection and tool-output sanitization are productizable; GCG-based adversarial testing is research/red-teaming only.

## Paper Summary

### Problem Statement and Motivation

Monitoring-based defenses for AI agents (hybrid monitors that observe Chain-of-Thought reasoning, tool calls, and outputs) are considered a promising safety approach. This paper demonstrates that these defenses are fundamentally fragile: an attacker can embed adversarial strings in external content that the agent repeats in its traces, causing monitors to classify malicious trajectories as safe.

> "current monitoring-based agentic defenses are fundamentally fragile regardless of model scale"

The key insight is that the agent itself becomes the delivery mechanism -- it repeats adversarial strings within its visible execution traces, manipulating monitors from the inside.

### Threat Model

- **Agent**: processes untrusted external inputs (emails, websites, RAG contexts)
- **Monitor**: observes agent reasoning (CoT), tool calls, and tool outputs
- **Attacker**: can embed instructions in external content that the agent processes; has white-box access to monitor (gradient computation); can optimize adversarial strings offline
- **Attack goal**: force monitor to classify malicious trajectory as safe despite successful indirect prompt injection

### Attack Methodology: Agent-as-a-Proxy

**Step 1: Injection Embedding** -- Attacker embeds malicious instruction with adversarial placeholder in external content (e.g., tool output, email).

**Step 2: Agent Exploitation** -- Agent processes injection and repeats the adversarial string (OPTIM_STR) in its internal reasoning traces, tool call parameters, and intermediate outputs.

**Step 3: Monitor Manipulation** -- The adversarial string, optimized via GCG/Parallel-GCG, appears benign within surrounding context, causing the monitor to accept the malicious trajectory.

**Key distinction from prior work**: Previous attacks (Terekhov et al. 2025) required superior agent capabilities and knowledge of monitoring systems. This approach relies solely on the agent's repetition behavior.

### Parallel-GCG Optimization

Core innovation: optimizes adversarial strings across K insertion sites simultaneously rather than a single static input.

- **Trace construction**: S(a) = c_0 + a + c_1 + a + ... + c_k (concatenation with adversarial string at K sites)
- **Optimization**: aggregate gradients across all K insertion positions
- **Parameters**: initial string of 20 tokens, 500 GCG steps, 512 candidates per iteration, top-k=256

### Monitoring Protocols Attacked

| Protocol | Components | Description |
|----------|-----------|-------------|
| AlignmentCheck | Hybrid monitor | Monitors reasoning, output, tool calls, and call outputs |
| LlamaFirewall | PromptGuard 2 + AlignmentCheck | Layered defense: classifier + monitor |
| Extract-and-Evaluate | Quote extractor + judge | Two-stage: extract suspicious content, then judge scores it |

### Experimental Setup

**Benchmark**: AgentDojo v1.2.1 (Slack suite: 20 user tasks x 5 injection tasks = 100 samples, 89 retained after filtering)

**Monitor models**: Llama-3.1-8B, Qwen2.5-7B, Mistral-7B v0.3

**Proxy agent models** (for capability gap testing): GPT-4o mini, Llama-3.1-70B

### Key Results

**Attack Success Rates (ASR@1 / ASR@5):**

| Monitor | Model | Baseline | ASR@1 | ASR@5 |
|---------|-------|----------|-------|-------|
| AlignmentCheck | Llama-3.1-8B | 0.0% | 42.3% | 42.3% |
| AlignmentCheck | Mistral-7B | 14.4% | 90.2% | 93.3% |
| AlignmentCheck | Qwen2.5-7B | 2.1% | 62.5% | 90.7% |
| PromptGuard 2 + AlignmentCheck | Llama-3.1-8B | 1.0% | 44.3% | 76.3% |
| PromptGuard 2 + AlignmentCheck | Mistral-7B | 12.4% | 86.4% | 99.0% |
| PromptGuard 2 + AlignmentCheck | Qwen2.5-7B | 2.1% | 61.2% | 86.6% |
| Extract-and-Evaluate | Llama-3.1-8B | 0.0% | 11.2% | 54.7% |
| Extract-and-Evaluate | Mistral-7B | 10.3% | 68.2% | 95.5% |
| Extract-and-Evaluate | Qwen2.5-7B | 2.3% | 10.5% | 37.2% |

**Maximum ASR achieved**: 99.0% (PromptGuard 2 + AlignmentCheck vs Mistral-7B)

### Hybrid Monitoring Paradox

CoT-only vs hybrid monitoring under static and adaptive attacks:

| Model | Static CoT | Static Hybrid | Adaptive CoT | Adaptive Hybrid |
|-------|-----------|--------------|-------------|-----------------|
| Qwen2.5-7B | 41.6% | 0.0% | 55.1% | 68.2% |
| Llama-3.1-8B | 32.6% | 0.0% | 65.2% | 69.3% |
| Mistral-7B v0.3 | 83.1% | 12.5% | 88.8% | 98.9% |

**Insight**: hybrid monitoring is superior against static attacks but *worse* against adaptive attacks because observing tool calls expands the attack surface (more insertion sites for adversarial strings).

### No Capability Gap Required

| Agent Model | LMArena Score | ASR@1 | ASR@5 |
|-------------|--------------|-------|-------|
| GPT-4o mini | 1318 | 26.7% | 46.0% |
| Llama-3.1-70B | 1294 | 19.4% | 60.2% |
| Monitor: Qwen2.5-72B | 1303 | - | - |

Agents with comparable or lower capability scores can bypass frontier-scale monitors. Model scaling alone is insufficient for security.

### Transferability

Attack strings generalize across models (Appendix C):
- Llama-3.1-8B -> Llama-3.1-405B: 88.2% ASR@1
- Mistral-7B -> Llama-3.1-405B: 90.9% ASR@1

Cross-model effectiveness suggests fundamental monitor vulnerabilities rather than model-specific weaknesses.

### Limitations

1. **High perplexity**: adversarial strings may be detectable by perplexity classifiers or human review
2. **White-box assumption**: paper attacks white-box monitors; black-box attacks possible but unexplored
3. **Trajectory approximation**: Parallel-GCG assumes fixed trajectories; real agent execution introduces variance (5-8 percentage point ASR drops in live execution)

## Feature Delta with LLMTrace

| Feature | Agent-as-a-Proxy | LLMTrace | Gap Analysis |
|---------|-----------------|----------|--------------|
| **Monitor bypass via agent repetition** | Core attack: agent repeats adversarial strings in traces | LLMTrace monitors request/response traffic | **Critical**: LLMTrace is a monitoring-based defense -- directly vulnerable to this attack class |
| **High-perplexity string detection** | Identified as potential countermeasure | No perplexity-based detection | **Major**: Could detect GCG-optimized strings in tool outputs. **Tracked as IS-050.** |
| **Structural defenses (not monitoring)** | Paper recommends architectural guarantees | Partial (sanitization, boundary tokens) | **Significant**: Validates AS-001/AS-002 sanitization approach over pure monitoring. **Propagation blocking tracked as IS-052.** |
| **Hybrid monitoring paradox** | More observation = more attack surface | Monitors both input and output | **Significant**: Output monitoring may increase attack surface against adaptive attacks. **Tracked as IS-051.** |
| **Multi-objective adversarial optimization** | GCG simultaneously bypasses classifier + monitor | No adversarial robustness testing | **Major**: Ensemble detection may be vulnerable to multi-objective attacks. **Tracked as EV-017, ML-016.** |
| **Transferability across models** | 88-90% ASR across model families | No cross-model attack testing | **Moderate**: Detection model may be bypassable via transfer attacks. **Tracked as EV-018.** |
| **AgentDojo benchmark** | Used for evaluation | Not evaluated against AgentDojo | **Moderate**: Shared evaluation gap with benchmarks landscape. **Tracked as EV-016.** |
| **Tool-output sanitization** | Not explored (attack-focused paper) | Partial (PII, secrets) | **LLMTrace strength**: Sanitization prevents adversarial strings from reaching monitors |
| **Boundary token injection** | Not explored | Not implemented | **Opportunity**: BIPIA-style boundary tokens would limit injection propagation |

### What This Paper Reveals About LLMTrace

1. **LLMTrace's monitoring architecture is directly targeted**: As a proxy that observes traffic, LLMTrace falls into the "monitoring-based defense" category this paper attacks.
2. **Pure observation is insufficient**: The paper validates that structural defenses (sanitization, boundary tokens, tool-output filtering) are more robust than observation-based monitoring.
3. **Ensemble detection is not immune**: Multi-objective GCG can simultaneously optimize against multiple detection layers.
4. **High-perplexity detection is a viable countermeasure**: GCG-optimized strings have characteristically high perplexity that could be detected.

### What LLMTrace Provides That Mitigates This Attack

1. **Tool-output sanitization**: Stripping/transforming tool outputs before they reach the agent prevents adversarial string propagation (AS-001/AS-002).
2. **Input-side detection**: Detecting injections *before* they enter the agent prevents the agent from ever repeating adversarial strings.
3. **Boundary token injection**: BIPIA-style `<data>`/`</data>` tokens create structural separation that GCG cannot optimize across.
4. **Content normalization**: Unicode/encoding normalization may disrupt adversarial string optimization that relies on specific token sequences.

## Actionable Recommendations

### P0 (Critical - Immediate)

1. **Implement Perplexity-Based Anomaly Detection in Tool Outputs** (IS-050, IS-052)
   - **Effort:** 2 weeks
   - GCG-optimized strings have characteristically high perplexity. Add perplexity scoring to tool-output analysis pipeline.
   - Flag tool outputs containing token sequences with perplexity above threshold.
   - **Code Impact:** New detection module in security analyzer, configurable threshold.

2. **Validate Structural Defenses Against GCG Attacks** (AS-001, AS-002, IS-052)
   - **Effort:** 1 week
   - Confirm that AS-001/AS-002 sanitization and BIPIA boundary tokens are resilient to adversarial string propagation.
   - The paper's attack relies on string repetition through the agent -- sanitization that strips or transforms tool outputs breaks this chain.
   - **Code Impact:** Red-team testing, no code changes if sanitization is effective.

### P1 (High Priority - Next Quarter)

3. **Add GCG-Based Adversarial Testing to Evaluation Pipeline** (EV-017, ML-016)
   - **Effort:** 3-4 weeks
   - Use GCG/Parallel-GCG to generate adversarial strings optimized against LLMTrace's detection models.
   - Test whether multi-objective GCG can simultaneously bypass regex + ML ensemble.
   - **Code Impact:** Red-team evaluation harness, adversarial sample generation.

4. **Evaluate Hybrid Monitoring Paradox for LLMTrace** (IS-051)
   - **Effort:** 2 weeks
   - Assess whether LLMTrace's output-side monitoring increases attack surface for adaptive attackers.
   - Consider configurable monitoring scope (input-only vs full hybrid) based on threat model.
   - **Code Impact:** Configuration options, evaluation framework.

5. **AgentDojo Evaluation** (EV-016)
   - **Effort:** 2-3 weeks
   - Evaluate LLMTrace detection against AgentDojo Slack suite attacks (same benchmark used in this paper).
   - Measure detection rates for both static and adaptive (GCG-optimized) attacks.
   - **Code Impact:** Test harness in `tests/benchmarks/`.

### P2 (Medium Priority - Future)

6. **Adversarial Robustness Training Against GCG** (ML-016)
   - **Effort:** 4-6 weeks
   - Generate GCG adversarial samples and include in classifier training data.
   - Test whether adversarial training improves resilience without increasing FPR.
   - **Code Impact:** Training pipeline extension, evaluation.

7. **Cross-Model Transfer Attack Testing** (EV-018)
   - **Effort:** 2 weeks
   - Test whether adversarial strings optimized against one detection model transfer to LLMTrace's ensemble.
   - Evaluate whether model diversity in the ensemble provides transfer resistance.
   - **Code Impact:** Evaluation only.

## Key Takeaways

1. **Monitoring-based defenses are fundamentally fragile**: 90%+ ASR against all tested monitor-model pairs. LLMTrace, as a monitoring proxy, must complement observation with structural defenses.

2. **Hybrid monitoring paradox**: observing more agent traces (tool calls, outputs) improves static attack detection but *increases* attack surface for adaptive attacks. More monitoring is not always better.

3. **Multi-layer defenses offer false security**: PromptGuard 2 + AlignmentCheck bypassed at 99.0% ASR via multi-objective GCG. Stacking classifiers does not prevent coordinated optimization.

4. **No capability gap needed**: similarly-scaled agents (GPT-4o mini, Llama-3.1-70B) bypass frontier monitors (Qwen2.5-72B). Model scaling is not a defense.

5. **Transferability is high**: 88-90% ASR transfers across model families (8B -> 405B). Adversarial strings exploit fundamental vulnerabilities, not model-specific weaknesses.

6. **Structural defenses are the answer**: the paper explicitly recommends "architectures with structural security guarantees" -- validating LLMTrace's sanitization and boundary token approaches (AS-001/AS-002, BIPIA defenses) over pure monitoring.

7. **High-perplexity detection is a countermeasure**: GCG-optimized strings are high-perplexity by nature. Perplexity-based anomaly detection in tool outputs is a viable defense not explored in this paper.
