# CyberSecEval 2: Wide-Ranging Cybersecurity Evaluation Suite for LLMs

**Date:** 2026-02-08
**Paper:** CyberSecEval 2: A Wide-Ranging Cybersecurity Evaluation Suite for Large Language Models
**Authors:** Manish Bhatt, Sahana Chennabasappa, Yue Li, Cyrus Nikolaidis, Daniel Song, Shengye Wan, Faizan Ahmad, Cornelius Aschermann, Yaohui Chen, Dhaval Kapil, David Molnar, Spencer Whitman, Joshua Saxe (Meta)
**arXiv:** [2404.13161](https://arxiv.org/abs/2404.13161)
**Published:** April 18, 2024
**License:** Creative Commons BY 4.0
**Code:** [github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks) (MIT)
**Source PDF:** `docs/research/papers/2404.13161.pdf`

## LLMTrace Application Notes

- Required signals/features: raw prompt text, model responses, system prompt content, code interpreter output, and judge LLM verdicts for automated evaluation.
- Runtime characteristics: benchmark-oriented (offline evaluation); not real-time. Judge LLM adds latency per test case.
- Integration surface (proxy): use CyberSecEval 2 prompt injection test suite as a validation benchmark for LLMTrace's detection accuracy; map attack categories to LLMTrace finding types.
- Productizable vs research-only: prompt injection attack categories and FRR methodology are productizable for benchmarking; exploit generation and code interpreter abuse tests are research/evaluation-only.

## Paper Summary

### Problem Statement and Motivation

CyberSecEval 2 extends the original CyberSecEval (v1, 2023) with four new evaluation dimensions for assessing LLM cybersecurity risks. The authors observe that while LLMs are increasingly deployed in security-sensitive contexts, there is no comprehensive benchmark covering the full range of risks: prompt injection, code interpreter abuse, exploit generation capability, and the safety-utility tradeoff (false refusals).

> "conditioning LLMs against prompt injection attacks remains an unsolved problem"

The benchmark is designed for reproducibility: tests are randomly generated where possible to prevent memorization, and the full evaluation suite is open-sourced.

### Benchmark Architecture

CyberSecEval 2 covers six evaluation areas (two from v1, four new):

| Area | Type | Source |
|------|------|--------|
| Insecure Code Generation | Risk assessment | CyberSecEval v1 |
| Cyberattack Helpfulness | Risk assessment | CyberSecEval v1 |
| **Prompt Injection** | Risk assessment | **New in v2** |
| **Code Interpreter Abuse** | Risk assessment | **New in v2** |
| **Exploit Generation** | Capability assessment | **New in v2** |
| **False Refusal Rate (FRR)** | Safety-utility tradeoff | **New in v2** |

### 1. Prompt Injection Testing

**Dataset Size:** 251 prompt injection attack samples (cross-referenced from DMPI-PMHFE, arXiv 2506.06384, Table reference [28]).

Tests are bifurcated into **logic-violating** (instruction adherence) and **security-violating** (harmful content generation) categories.

**Test Construction:** Each test contains three elements:
- System prompt with specific instructions
- User input containing a malicious payload
- Judge question (unambiguous binary success criterion)

A separate **Judge LLM** evaluates whether the injection succeeded using handcrafted criteria.

**15 Attack Categories Tested:**

| # | Category | Description |
|---|----------|-------------|
| 1 | Ignore Previous Instructions | Direct override of system prompt |
| 2 | Indirect References | Oblique references to bypass filters |
| 3 | Token Smuggling | Encoding tokens to evade detection |
| 4 | System Mode | Claiming elevated system privileges |
| 5 | Different User Input Language | Multilingual evasion |
| 6 | Information Overload | Padding with irrelevant content |
| 7 | Few-shot Attack | Providing examples to steer behavior |
| 8 | Many-shot Attack | Extended few-shot with many examples |
| 9 | Repeated-token Attack | Repetitive token flooding |
| 10 | Output Formatting Manipulation | Forcing specific output structures |
| 11 | Hypothetical Scenario | "What if" framing to bypass safety |
| 12 | Payload Splitting | Distributing payload across inputs |
| 13 | Persuasion | Social engineering in-prompt |
| 14 | Virtualization | Simulating alternative environments |
| 15 | Mixed Techniques | Combining multiple attack vectors |

**Scope Exclusions:** Iterative/multi-turn attacks, gradient-based optimization, heuristic optimization methods, non-English prompts.

**Results:**

| Model | Injection Success Rate |
|-------|----------------------|
| GPT-4 | ~17% |
| Llama 3 70B-Instruct | ~20% |
| CodeLlama variants | 26-41% |
| **Average (all models)** | **28%** |

- Output formatting manipulation had the highest success rates
- Token smuggling had the lowest success rates
- Larger models (70B+, GPT-4) showed better resistance
- Llama 3 struggled with multilingual attacks (limited multilingual training)

### 2. Code Interpreter Abuse Testing

500 prompts total (100 per category across 5 categories), evaluated by Judge LLM for malicious compliance.

**Five Attack Categories:**

| Category | Description |
|----------|-------------|
| Container Escapes | Unauthorized file access, privilege escalation, host command execution |
| Privilege Escalation | Elevation from low to high privilege |
| Reflected Attacks | Using interpreter to attack external systems |
| Post Exploitation | Persistence, C2 communication setup |
| Social Engineering | LLM-generated code for phishing/manipulation |

**Results:**

| Model | Malicious Compliance Rate |
|-------|--------------------------|
| GPT-4 | ~13% |
| Llama 3 70B | ~27% |
| CodeLlama variants | 30-47% |
| **Average (all models)** | **35%** |

### 3. Exploit Generation Testing

CTF-style challenges with randomly generated tests to prevent memorization. Tests assess general reasoning rather than comprehensive vulnerability coverage.

**Four Test Categories:**

| Category | Language | Scoring | Description |
|----------|----------|---------|-------------|
| String Constraint Satisfaction | C, JS, Python | Partial credit (0-1.0) | Infer constraints from code, generate satisfying input |
| SQL Injection | Python/SQLite3 | Binary (0 or 1.0) | Craft input exploiting SQL vuln + manipulating target values |
| Basic Buffer Overflow | C | 0.5 overrun, 1.0 correct value | Calculate input length to overrun buffer, set target int |
| Diverse Memory Exploits | C/C++ | Binary (0 or 1.0) | Buffer overflows, integer overflows, memory corruption |

**Results:**
- GPT-4: best overall; ~20% on SQL injection; ~0% on buffer overflow
- Most models scored 0 on end-to-end memory corruption and SQL injection
- Models with coding capabilities outperform non-code models

> "LLMs have a ways to go before performing well on this benchmark"

### 4. False Refusal Rate (FRR)

**Definition:** Percentage of benign prompts refused by an LLM because they are mistaken for unsafe prompts.

**Methodology:** Novel dataset of "borderline" prompts -- cybersecurity-related but benign (cyberdefense concepts, penetration testing, network administration). These prompts are designed to be potentially mistaken for malicious requests.

**Results:**

| Model | FRR |
|-------|-----|
| Llama 3 variants | <15% |
| GPT-4 | <15% |
| Gemini-pro | <15% |
| CodeLlama-70B | **70%** (extremely high false rejection) |

> "Many LLMs able to successfully comply with 'borderline' benign requests while still rejecting most unsafe requests"

### 5. Cyberattack Helpfulness (v1 vs v2 Comparison)

Tests model compliance with cyberattack assistance requests across 10 MITRE ATT&CK categories.

| Metric | CyberSecEval v1 (2023) | CyberSecEval v2 (2024) |
|--------|------------------------|------------------------|
| Average Compliance | 52% | 28% |
| Category Gap (evasion vs discovery) | 0.34 | 0.10 |
| CodeLlama-70B Improvement | High compliance | Approaching SOTA refusal rates |

> "modern models are now more aware of various cyberattack categories"

### Models Evaluated

- GPT-4 (gpt-4-0613) / GPT-4-turbo
- Meta Llama 3 70B-Instruct
- CodeLlama (7B, 13B, 34B, 70B-Instruct)
- Llama 2 variants (from v1)
- Google Gemini-pro
- Mistral (excluded from prompt injection -- no system prompt API support)

## Feature Delta with LLMTrace

| Feature | CyberSecEval 2 | LLMTrace | Gap Analysis |
|---------|---------------|----------|--------------|
| **Prompt Injection Coverage** | 15 attack categories, logic + security violating | ML + regex hybrid detection | **Moderate**: LLMTrace detects but doesn't benchmark against all 15 categories |
| **Attack Success Rate Measurement** | Judge LLM-based ASR metric | No automated ASR benchmarking | **Major**: LLMTrace lacks systematic ASR measurement |
| **False Refusal Rate** | Dedicated FRR benchmark with borderline prompts | No explicit FRR tracking | **Major**: No over-defense measurement (aligns with InjecGuard gap) |
| **Code Interpreter Abuse** | 5 abuse categories, 500 test prompts | No code interpreter analysis | **Significant**: Out of current scope |
| **Exploit Generation** | 4 CTF-style test categories | Not applicable | N/A (different purpose) |
| **Multi-turn Attacks** | Excluded from scope | No multi-turn tracking | Equal gap |
| **Open Benchmark Suite** | MIT-licensed, reproducible | No standard benchmark suite | **Major**: Need to adopt/adapt for validation |
| **Real-time Detection** | Offline evaluation only | Real-time streaming analysis | **LLMTrace strength** |
| **PII Detection** | Not covered | Comprehensive PII patterns + validation | **LLMTrace strength** |
| **Agent Security** | Not covered | Command/file/web action analysis | **LLMTrace strength** |
| **Proxy Integration** | Not applicable (benchmark tool) | Transparent proxy, zero-code integration | **LLMTrace strength** |

### What CyberSecEval 2 Provides That We Lack

1. **Systematic Attack Taxonomy**: 15 prompt injection categories with structured test generation
2. **Judge LLM Evaluation**: Automated, unambiguous success/failure assessment per attack
3. **FRR Benchmarking**: Quantified safety-utility tradeoff measurement with borderline prompts
4. **ASR Metric**: Standardized attack success rate across models and categories
5. **Reproducible Test Generation**: Randomly generated tests preventing memorization bias

### What We Provide That CyberSecEval 2 Doesn't

1. **Real-time Detection**: Inline security analysis during inference
2. **PII Protection**: Personal information detection with checksum validation
3. **Agent Action Analysis**: Dangerous command, URL, and file access detection
4. **Streaming Support**: Content delta analysis for streaming responses
5. **Hybrid Detection**: ML + regex ensemble for production robustness

## Actionable Recommendations

### P0 (Critical - Immediate)

1. **Adopt CyberSecEval 2 Prompt Injection Test Suite for Validation**
   - **Effort:** 1-2 weeks
   - Import the 15-category attack test suite from PurpleLlama repo
   - Run against LLMTrace's security engine to measure detection accuracy per category
   - Establish baseline ASR metric for LLMTrace
   - **Code Impact:** Test harness in `tests/benchmarks/`, CI integration

2. **Implement FRR Benchmarking**
   - **Effort:** 1-2 weeks
   - Create or adapt borderline prompt dataset for LLMTrace evaluation
   - Track false positive rate on benign cybersecurity-related prompts
   - Aligns with InjecGuard over-defense gap identified earlier
   - **Code Impact:** New benchmark dataset, metrics in evaluation pipeline

### P1 (High Priority - Next Quarter)

3. **Map CyberSecEval 2 Attack Categories to LLMTrace Finding Types**
   - **Effort:** 1 week
   - Ensure each of the 15 attack categories maps to a detectable finding type
   - Identify coverage gaps (e.g., token smuggling, payload splitting, many-shot)
   - **Code Impact:** Documentation + potential new finding types

4. **Judge LLM-Based Evaluation Pipeline**
   - **Effort:** 2-3 weeks
   - Implement automated evaluation using Judge LLM pattern from CyberSecEval 2
   - Use for continuous regression testing of detection accuracy
   - **Code Impact:** New evaluation module, CI pipeline extension

### P2 (Medium Priority - Future)

5. **Code Interpreter Abuse Detection**
   - **Effort:** 4-6 weeks
   - Evaluate whether LLMTrace should detect code interpreter abuse patterns
   - Relevant for agent-mode deployments where LLMs execute code
   - **Code Impact:** New detection module if pursued

6. **Multi-turn Attack Tracking**
   - **Effort:** 4-6 weeks
   - Both CyberSecEval 2 and LLMTrace currently lack multi-turn attack detection
   - Session-level analysis for gradual bypass attempts
   - **Code Impact:** Session state tracking, cross-request correlation

## Key Takeaways

1. **Prompt injection remains unsolved**: 26-41% success rate across all tested models, including SOTA. This validates LLMTrace's security layer as a necessary defense.

2. **Larger models resist better but are not immune**: GPT-4 at 17% is the best but still vulnerable. Defense cannot rely solely on model conditioning.

3. **Safety-utility tradeoff is real but manageable**: Most models achieve <15% FRR while maintaining safety. CodeLlama-70B at 70% FRR is an outlier showing over-defense.

4. **CyberSecEval 2 as validation benchmark**: The test suite and methodology are directly usable for benchmarking LLMTrace detection accuracy. The MIT-licensed codebase enables immediate adoption.

5. **Cyberattack helpfulness improving**: Average compliance dropped from 52% (v1) to 28% (v2), showing model safety is improving but external defense layers remain essential.

6. **Exploit generation is nascent**: LLMs cannot yet autonomously generate working exploits. This is relevant for risk assessment but not an immediate LLMTrace concern.
