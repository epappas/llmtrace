# BIPIA: Benchmarking and Defending Against Indirect Prompt Injection Attacks

**Date:** 2026-02-08
**Paper:** Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models
**Authors:** Jingwei Yi, Yueqi Xie, Bin Zhu, Emre Kiciman, Guangzhong Sun, Xing Xie, Fangzhao Wu (USTC, HKUST, Microsoft)
**arXiv:** [2312.14197](https://arxiv.org/abs/2312.14197)
**Published:** December 21, 2023 (v4 January 27, 2025)
**Venue:** KDD 2025 (August 3-7, Toronto)
**Code:** [github.com/microsoft/BIPIA](https://github.com/microsoft/BIPIA)

## LLMTrace Application Notes

- Required signals/features: external content boundaries (tool outputs, retrieved documents), prompt template structure, user instruction vs third-party content separation, response text for ASR evaluation.
- Runtime characteristics: black-box defenses (prompt rewriting) add zero model latency; white-box defenses require fine-tuned model. Benchmark evaluation is offline.
- Integration surface (proxy): LLMTrace can implement boundary awareness by injecting `<data>`/`</data>` tokens around external content in forwarded requests; explicit reminder injection into system prompts; detection of indirect injection patterns in tool outputs before they reach the LLM.
- Productizable vs research-only: boundary token injection and explicit reminder injection are productizable at proxy level; white-box adversarial fine-tuning is research-only (requires model retraining). BIPIA benchmark is usable for evaluation.

## Paper Summary

### Problem Statement and Motivation

LLMs integrated with external content (Microsoft Copilot, Google Workspace, LangChain agents) are vulnerable to **indirect prompt injection**: malicious instructions embedded in third-party content (emails, web pages, documents, code) that manipulate LLM outputs without the user's knowledge.

This paper introduces **BIPIA** (Benchmark for Indirect Prompt Injection Attacks), the first systematic benchmark for this attack class, evaluates 25 LLMs, identifies two root causes, and proposes both black-box and white-box defenses.

> "the root causes of indirect prompt injection attacks are twofold: (1) the inability of LLMs to effectively differentiate between informational context and actionable instructions; and (2) the lack of awareness in LLMs to avoid executing instructions embedded within external content."

### Threat Model

- **P = Combine(T, C, f(I))** -- prompt template T, external content C (may contain malicious instruction M), user input I
- Attackers can modify external content but cannot tamper with LLMs or applications directly
- LLMs and applications are assumed trustworthy

### BIPIA Benchmark Construction

**Dataset Scale:** 626,250 training + 86,250 test prompts

**Five Application Scenarios:**

| Task | Source | Train/Test | Attack Types |
|------|--------|------------|--------------|
| Email QA | OpenAI Evals | 50/50 samples | 75 text attacks |
| Web QA | NewsQA | 900/100 samples | 75 text attacks |
| Table QA | WikiTableQuestions | 900/100 samples | 75 text attacks |
| Summarization | XSum | 900/100 samples | 75 text attacks |
| Code QA | Self-collected | 50/50 samples | 50 code attacks |

**Attack Construction Factors:**
1. **Position in content:** beginning, middle, end (end position has highest ASR)
2. **Text attacks (30 total: 15 train / 15 test):**
   - Task-irrelevant: redirecting from original task (e.g., task automation, sentiment analysis)
   - Task-relevant: altering responses within task context (e.g., substitution ciphers, base encoding)
   - Targeted: achieving specific malicious outcomes (e.g., scams, misinformation)
3. **Code attacks (20 total: 10 train / 10 test):**
   - Passive: data eavesdropping, keylogging, screen scraping, traffic analysis, system fingerprinting
   - Active: file corruption, ransomware, blocking internet, infrastructure attack, computer compromise

### Vulnerability Analysis: 25 LLMs Evaluated

**Key Results (Overall ASR):**

| Model | Params | Overall ASR |
|-------|--------|-------------|
| GPT-4 | - | 0.3103 |
| GPT-3.5-Turbo | - | 0.2616 |
| Llama2-Chat-70B | 70B | 0.1867 |
| Llama2-Chat-13B | 13B | 0.1681 |
| Vicuna-33B | 33B | 0.1617 |
| MPT-30B-chat | 30B | 0.1600 |
| OpenAssistant-Pythia-12B | 12B | 0.1546 |
| Llama2-Chat-7B | 7B | 0.1498 |
| GPT4All-13B-Snoozy | 13B | 0.1410 |
| Koala-13B | 13B | 0.1352 |
| Vicuna-13B | 13B | 0.1294 |
| MPT-7B-Chat | 7B | 0.1294 |
| Vicuna-7B | 7B | 0.1049 |
| FastChat-T5-3B | 3B | 0.1045 |
| CodeLlama-34B | 34B | 0.1013 |
| Guanaco-33B | 33B | 0.1020 |
| Mistral-7B | 7B | 0.0966 |
| Dolly-V2-12B | 12B | 0.0903 |
| Alpaca-13B | 13B | 0.0796 |
| WizardLM-70B | 70B | 0.0795 |
| WizardLM-13B | 13B | 0.0791 |
| ChatGLM2-6B | 6B | 0.0761 |
| StableLM-Tuned-Alpaca-7B | 7B | 0.0641 |
| RWKV-4-Raven-14B | 14B | 0.0581 |
| ChatGLM-6B | 6B | 0.0532 |
| **Average** | | **0.1179** |

**Counterintuitive Finding: More capable models are MORE vulnerable.**
- Pearson correlation between Elo rating and ASR: r = 0.6423 (p < 0.001) for all tasks
- r = 0.6635 (p < 0.001) for text-only tasks
- r = -0.0254 for code tasks (no correlation)
- GPT-4 has the highest overall ASR (0.3103)

**ASR by Application Task (averages across 25 models):**

| Task | Average ASR | Explanation |
|------|-------------|-------------|
| Code QA | 0.2411 | Code execution intent inherently follows instructions |
| Summarization | 0.1966 | No user instructions appended after content |
| Table QA | 0.0771 | Structured format constrains injection |
| Email QA | 0.0730 | Short content limits injection surface |
| Web QA | 0.0615 | Explicit user question anchors task |

**Injection Position Impact:**
- End position: highest ASR (aligns with training data distribution where instructions appear at end)
- Beginning: medium ASR
- Middle: lowest ASR

### Root Cause Analysis

Two root causes identified:
1. **Boundary confusion:** LLMs cannot distinguish informational context from actionable instructions
2. **Execution awareness gap:** LLMs lack awareness to suppress instruction execution within external content

### Defense Mechanisms

#### Black-Box Defenses (no model access required)

Two components, combinable:

**1. Explicit Reminder:** Add instruction to prompt directing the LLM not to execute commands found in external content.

**2. Boundary Awareness via Prompt Learning:**

- **Multi-Turn Dialogue:** Move external content to a previous conversation turn; place user instructions in the current turn. Creates distance between malicious content and recent user interaction.
- **In-Context Learning:** Provide few-shot examples (1-5) demonstrating correct behavior: responding to external content without following embedded malicious instructions.

**Ablation finding:** Boundary awareness contributes more than explicit reminder (21-23% vs 10-16% impact).

#### White-Box Defenses (model access required)

Four-step adversarial fine-tuning:

1. **Add special tokens:** Introduce `<data>` and `</data>` to mark external content boundaries
2. **Construct training data:** Use BIPIA training set with 3 response construction variants:
   - BIPIA labels (ground truth -- high correctness, low diversity)
   - Original LLM responses on clean prompts (style-consistent)
   - GPT-4 responses on clean prompts (highest quality)
3. **Fine-tune:** AdamW optimizer, lr=2e-5, batch size 128, max seq len 2048, 1 epoch
4. **Add explicit reminder** in inference template

### Defense Evaluation Results

**Black-Box Defenses (ASR reduction):**

| Model | Original ASR | In-Context Learning | Multi-Turn Dialogue |
|-------|-------------|--------------------|--------------------|
| GPT-4 | 0.3103 | 0.2408 (-22.4%) | 0.2056 (-33.7%) |
| GPT-3.5-Turbo | 0.2616 | 0.1884 (-28.0%) | 0.1843 (-29.5%) |
| Vicuna-7B | 0.1237 | 0.0885 (-28.5%) | 0.0617 (-50.1%) |
| Vicuna-13B | 0.1531 | 0.1658 (+8.3%) | 0.1021 (-33.3%) |

- ROUGE-1 impact: minimal (<5% change, often positive)
- In-context learning increases ASR for Vicuna-13B (negative result)
- Multi-turn dialogue consistently reduces ASR across all models

**White-Box Defenses (Vicuna-7B):**

| Response Construction | ASR | ASR Reduction | ROUGE-1 | MT-Bench |
|----------------------|-----|---------------|---------|----------|
| No defense | 0.1237 | - | 0.6187 | 4.8063 |
| BIPIA labels | 0.0214 | -82.7% | 0.5306 (-14.2%) | 4.2938 (-10.7%) |
| Original LLM responses | 0.0240 | -80.6% | 0.6122 (-1.0%) | 4.5687 (-5.0%) |
| GPT-4 responses | **0.0053** | **-95.7%** | 0.6260 (+1.2%) | 4.8312 (+0.5%) |

**White-Box Defenses (Vicuna-13B):**

| Response Construction | ASR | ASR Reduction | ROUGE-1 | MT-Bench |
|----------------------|-----|---------------|---------|----------|
| No defense | 0.1531 | - | 0.6134 | 5.2062 |
| BIPIA labels | 0.0192 | -87.5% | 0.6109 (-0.4%) | 1.6625 (-68.1%) |
| Original LLM responses | 0.0046 | -97.0% | 0.6240 (+1.7%) | 4.3375 (-16.8%) |
| GPT-4 responses | **0.0047** | **-96.9%** | 0.6337 (+3.3%) | 4.5500 (-12.6%) |

**Best configuration:** GPT-4 response construction achieves near-zero ASR (0.47-0.53%) with minimal or positive ROUGE-1 impact and minor MT-Bench loss.

**Ablation: Component importance (white-box, Vicuna-7B, GPT-4 responses):**
- Without explicit reminder: ASR increases from 0.0053 to 0.0069 (+30%)
- Without boundary awareness: ASR increases from 0.0053 to 0.0617 (+1064%)
- Boundary awareness is vastly more critical than explicit reminder

### Evaluation Metrics

| Metric | Purpose |
|--------|---------|
| ASR | Attack success rate (rule-based + LLM-as-judge) |
| ROUGE-1 (recall) | Output quality preservation on benign tasks |
| MT-Bench | General instruction-following capability |

## Feature Delta with LLMTrace

| Feature | BIPIA | LLMTrace | Gap Analysis |
|---------|-------|----------|--------------|
| **Indirect injection benchmark** | 5 scenarios, 50 attack types, 86K test prompts | No indirect injection benchmark | **Major**: No systematic evaluation for indirect injection |
| **Boundary awareness defense** | `<data>`/`</data>` tokens + adversarial training | No content boundary marking | **Major**: Proxy could inject boundary tokens |
| **Explicit reminder injection** | System prompt augmentation | No automatic reminder injection | **Significant**: Trivially implementable at proxy level |
| **Multi-turn dialogue defense** | Move content to previous turn | No multi-turn restructuring | **Moderate**: Proxy could restructure requests |
| **In-context learning defense** | Few-shot examples in prompt | No few-shot injection | **Moderate**: Proxy could inject examples |
| **Content-instruction separation** | Identified as root cause | Detects injection patterns but no separation | **Significant**: Detection vs prevention gap |
| **Adversarial fine-tuning** | Training pipeline with 3 response strategies | No fine-tuning capability | N/A (out of proxy scope) |
| **25-model vulnerability baseline** | Comprehensive ASR per model | No per-model vulnerability tracking | **Moderate**: Could inform model-specific thresholds |
| **Position-aware injection** | Analyzed injection position impact | No position-aware detection | **Minor**: Could weight detection by position |
| **Real-time detection** | Offline evaluation only | Real-time streaming analysis | **LLMTrace strength** |
| **Tool output analysis** | Not covered (content-level only) | Tool call + action analysis | **LLMTrace strength** |
| **PII/secret detection** | Not covered | Comprehensive PII + secrets | **LLMTrace strength** |
| **Unicode normalization** | Not covered | 30+ homoglyph mappings + NFKC | **LLMTrace strength** |

### What BIPIA Provides That We Lack

1. **Systematic indirect injection benchmark**: 5 application scenarios with 50 diverse attack types
2. **Black-box defenses at prompt level**: Boundary awareness and explicit reminder injection require zero model access
3. **Content-instruction boundary marking**: `<data>`/`</data>` tokens as a defense primitive
4. **Capability-vulnerability correlation data**: More capable models are more susceptible (r=0.6423)
5. **Position-aware injection analysis**: End-of-content injections are most effective

### What We Provide That BIPIA Doesn't

1. **Real-time proxy-level detection**: Inline security during inference
2. **Tool output and agent action analysis**: Security beyond content-level injection
3. **PII protection and secret scanning**: Orthogonal security capabilities
4. **Unicode/encoding evasion defense**: Normalization layer BIPIA doesn't address
5. **Multi-model ensemble detection**: Diverse architectures for robustness

## Actionable Recommendations

### P0 (Critical - Immediate)

1. **Implement Boundary Token Injection at Proxy Level**
   - **Effort:** 1 week
   - When LLMTrace detects external content in tool outputs or retrieved documents, wrap it with `<data>`/`</data>` boundary markers before forwarding to the LLM
   - This is the single most impactful defense from the paper (1064% ASR increase without it)
   - **Code Impact:** Request rewriting in proxy forwarding logic, configurable per-tenant

2. **Implement Explicit Reminder Injection**
   - **Effort:** 3 days
   - Inject a system prompt reminder instructing the LLM to ignore instructions found in external content
   - Combinable with boundary tokens for defense-in-depth
   - **Code Impact:** System prompt augmentation in proxy, configurable templates

### P1 (High Priority - Next Quarter)

3. **Adopt BIPIA as Evaluation Benchmark**
   - **Effort:** 2 weeks
   - Import BIPIA test set (86,250 prompts across 5 scenarios) for evaluating LLMTrace's indirect injection detection
   - Use the 50 attack types (30 text + 20 code) as a test suite
   - **Code Impact:** Test harness in `tests/benchmarks/`, CI integration

4. **Position-Aware Detection Weighting**
   - **Effort:** 1 week
   - Weight injection detection higher for content at the end of external data (highest ASR position)
   - Align with paper finding that end-of-content injections exploit training data distribution bias
   - **Code Impact:** Detection scoring in security analyzer

5. **Multi-Turn Dialogue Restructuring**
   - **Effort:** 2 weeks
   - Optionally restructure single-turn requests with external content into multi-turn format
   - Move external content to a "previous turn" context, user instructions to "current turn"
   - **Code Impact:** Request transformation module, configurable per-tenant

### P2 (Medium Priority - Future)

6. **Model-Specific Vulnerability Thresholds**
   - **Effort:** 2 weeks
   - Use BIPIA's per-model ASR data to set model-specific detection sensitivity
   - GPT-4 (31% ASR) needs stricter thresholds than ChatGLM-6B (5.3% ASR)
   - **Code Impact:** Model-aware configuration in security engine

7. **In-Context Learning Example Injection**
   - **Effort:** 2 weeks
   - For high-risk requests, inject 2-3 few-shot examples showing correct behavior (ignoring injected instructions)
   - Paper shows 2-3 examples provide most of the ASR reduction with minimal ROUGE impact
   - **Code Impact:** Example library + injection logic in proxy

## Key Takeaways

1. **All 25 LLMs are universally vulnerable** to indirect prompt injection, with an average 11.8% ASR across all models and scenarios.

2. **More capable models are more vulnerable**: GPT-4 (31% ASR) > GPT-3.5 (26% ASR) > most open-source models. This counterintuitive finding means stronger models need stronger external defenses.

3. **Boundary awareness is the critical defense**: Removing boundary tokens from white-box defense increases ASR by 1064%. This is the single most important intervention -- and it's implementable at proxy level.

4. **Black-box defenses are practical but incomplete**: 22-50% ASR reduction with minimal output quality impact. Multi-turn dialogue is more reliable than in-context learning.

5. **White-box defenses achieve near-zero ASR** (0.47-0.53%) with GPT-4 response construction, while maintaining or improving output quality. This validates adversarial fine-tuning as a viable strategy.

6. **Summarization and code tasks are most vulnerable**: No appended user instructions (summarization) and inherent instruction-following intent (code) make these tasks easier to exploit.

7. **Proxy-level defenses are viable**: Boundary token injection and explicit reminder injection require zero model access and can be implemented entirely at the proxy layer -- directly applicable to LLMTrace.
