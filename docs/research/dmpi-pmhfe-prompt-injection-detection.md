# DMPI-PMHFE: Dual-Channel Prompt Injection Detection

**Date:** 2026-02-03
**Paper:** Detection Method for Prompt Injection by Integrating Pre-trained Model and Heuristic Feature Engineering
**Authors:** Yi Ji, Runzhi Li, Baolei Mao (Zhengzhou University)
**arXiv:** 2506.06384v1
**URL:** https://arxiv.org/pdf/2506.06384
**Source PDF:** `docs/research/papers/2506.06384.pdf`

## Summary

DMPI-PMHFE is a dual-channel feature fusion framework for detecting direct prompt injection attacks. It combines DeBERTa-v3-base semantic feature extraction with heuristic feature engineering (synonym matching + pattern matching) to capture both implicit semantic and explicit structural attack signals. Features from both channels are concatenated and classified via fully connected layers. The paper reports state-of-the-art accuracy, recall, and F1 across three benchmark datasets, and significant attack success rate reductions when deployed as an active defense across five mainstream LLMs.

## Architecture

### Dual-Channel Design

```
Input Text
  |
  +---> DeBERTa Tokenizer --> Word Embedding + Position Embedding
  |       --> Transformer Encoder --> Average Pooling --> Semantic Features (d-dim)
  |
  +---> en_core_web_sm Tokenizer --> Lemmatization + Lowercase
          +---> Synonym Matching --> 8 binary features
          +---> Pattern Matching --> 2 binary features
          --> Heuristic Features (10-dim)
  |
  +--> Concatenation --> FC + ReLU --> FC + SoftMax --> Binary Prediction
```

### DeBERTa Feature Extraction (Channel 1)

- **Model:** DeBERTa-v3-base
- Input tokenized into `{Tok_1, ..., Tok_n}` via DeBERTa tokenizer
- Word embedding + position embedding layers
- Transformer encoder produces contextualized representations `{O_1, ..., O_n}`
- **Average pooling** aggregates into fixed-dimensional feature vector `{F_1, ..., F_d}`

### Heuristic Feature Engineering (Channel 2)

Input tokenized and lemmatized via spaCy `en_core_web_sm`. Two sub-modules:

**Synonym Matching (Algorithm 1):**
1. For each attack type, extract high-frequency keywords from training data
2. Expand keywords using WordNet synonyms
3. Tokenize, lemmatize, lowercase input text
4. For each attack category, check if any token matches synonym list
5. Output: binary vector `V = [V_1, ..., V_n]` where `V_i in {0, 1}`

**Pattern Matching (Algorithm 2):**
1. For each structure-based attack, construct a dedicated regex matching function
2. Tokenize, lemmatize, lowercase input text
3. Apply each matching function; set `V_i = 1` if pattern detected
4. Output: binary vector `V = [V_{n+1}, ..., V_{n+m}]`

Features from both sub-modules are concatenated into the final heuristic feature vector.

### Prediction Output (Fusion + Classifier)

- Concatenation of DeBERTa features and heuristic features
- FC layer + ReLU (nonlinear transformation)
- FC layer + SoftMax (probability distribution over 2 classes)

## Heuristic Features (10 binary features)

### Synonym Matching Features (8 features, Appendix A.1)

| Feature | Attack Type | Selected Keywords |
|---------|-------------|-------------------|
| is_ignore | Asks LLM to ignore system prompts | ignore, reveal, disregard, forget, overlook, regardless |
| is_urgent | Creates urgent scenarios to pressure LLM | urgent, immediate, asap, emergency, critical, time |
| is_incentive | Uses praise/incentives to stimulate malicious actions | excellent, fantastic, nice, awesome, brilliant, great |
| is_covert | Employs covert behaviors for info leakage | secret, hidden, covert, quiet, silent, discreetly, stealth, sneak, confidential, personal |
| is_format_manipulation | Asks LLM to encode/disguise sensitive info | encode, disguising, morse, binary, hexadecimal |
| is_hypothetical | Fictional scenarios/role-playing to rationalize sensitive output | assume, imagine, act, role, play, hypothetical, fictional, scenario |
| is_systemic | Impersonates system admin/developer | developer, boss, manager, administrator, creator |
| is_immoral | Inserts unethical/harmful words | hitting, amoral, immoral, deceit, irresponsible, offensive, violent, unethical, smack, fake, illegal, biased |

Keywords are expanded with WordNet synonyms at build time.

### Pattern Matching Features (2 features, Appendix A.2)

| Feature | Attack Type | Matching Rule | Threshold |
|---------|-------------|---------------|-----------|
| is_shot_attack | Many-shot attack (multiple Q&A examples) | Regex counts Q&A pairs via punctuation patterns | >= 3 Q&A pairs |
| is_repeated_token | Token repetition attack (e.g. "please...please...please") | Regex identifies repeated words/phrases | >= 3 repetitions |

Threshold of 3 selected via systematic sensitivity analysis balancing precision and recall.

## Datasets

### Training and Evaluation

| Dataset | Samples | Source | Role |
|---------|---------|--------|------|
| safeguard-v2 | 13,000 total | Augmented from xTRam1/safeguard-prompt-injections (7K benign + 3K malicious) + 3K GPT-4o generated | Train/val/test |
| deepset-v2 | 354 English | deepset/prompt-injections (HuggingFace) | External generalization |
| Ivanleomk-v2 | 610 English | ivanleomk/prompt_injection_password (HuggingFace) | External generalization |

**safeguard-v2 construction:**
- Base: xTRam1/safeguard-prompt-injections (7,000 benign + 3,000 malicious)
- Incorporated 15 mainstream attack patterns
- Generated 3,000 additional samples using GPT-4o with paired positive/negative examples per attack
- Quality assurance: 3-stage process (manual label verification, dedup + format standardization, balanced distribution via random sampling)
- Split: 10,400 training (80%), 1,300 validation (10%), 1,300 test (10%)

### Defense Evaluation

| Dataset | Samples | Source |
|---------|---------|--------|
| Prompt injection testing benchmark | 251 attacks | CyberSecEval 2 [28] |

Covers attack patterns: "ignore previous instructions", "format manipulation", "hypothetical scenarios", and others.

## Training Configuration

| Parameter | Value |
|-----------|-------|
| Optimizer | Adam |
| Loss | Cross-entropy |
| Learning rate | 2e-5 |
| Batch size | 16 |
| Weight decay | 0.02 |
| Early stopping | Patience = 3 |
| Metrics | Accuracy, Precision, Recall, F1 |

## Baselines

### Detection Baselines

| Model | Description | Reference |
|-------|-------------|-----------|
| Fmops | fmops/distilbert-prompt-injection | [19] |
| ProtectAI | deberta-v3-base-prompt-injection-v2 | [20] |
| SafeGuard | Benchmark suite for LLM safety | [21] |
| InjecGuard | Benchmarking and mitigating over-defense in prompt injection guardrails | [22] |

### Defense Baselines

| Method | Description | Reference |
|--------|-------------|-----------|
| Self-Reminder | Integrates system prompts into user queries as self-reminders | [27] |
| Self-Defense | LLMs evaluate their own generated text for harmful content | [26] |

## Results

### Table 1: Model Performance Comparison

**safeguard-v2:**

| Model | Accuracy | Precision | Recall | F1 |
|-------|----------|-----------|--------|----|
| Fmops | 97.18 | 98.55 | 94.06 | 96.25 |
| ProtectAI | 97.10 | 98.95 | 93.47 | 96.12 |
| SafeGuard | 97.86 | **99.58** | 94.85 | 97.16 |
| InjecGuard | 97.87 | 99.18 | 95.25 | 97.17 |
| DMPI-PMHFE | **97.94** | 98.00 | **98.59** | **98.29** |

**Ivanleomk-v2:**

| Model | Accuracy | Precision | Recall | F1 |
|-------|----------|-----------|--------|----|
| Fmops | 92.30 | 99.46 | 89.08 | 93.98 |
| ProtectAI | 90.49 | 99.44 | 86.41 | 92.47 |
| SafeGuard | 93.77 | **99.47** | 91.26 | 95.19 |
| InjecGuard | 94.26 | 99.22 | 92.23 | 95.60 |
| DMPI-PMHFE | **94.75** | 98.22 | **93.93** | **96.03** |

**deepset-v2:**

| Model | Accuracy | Precision | Recall | F1 |
|-------|----------|-----------|--------|----|
| Fmops | 87.57 | 98.24 | 72.73 | 83.58 |
| ProtectAI | 87.29 | 94.31 | 75.32 | 83.75 |
| SafeGuard | 89.26 | **98.33** | 76.62 | 86.13 |
| InjecGuard | 90.40 | 97.62 | 79.87 | 87.86 |
| DMPI-PMHFE | **91.24** | 96.99 | **84.31** | **90.21** |

**Key finding:** DMPI-PMHFE achieves highest accuracy, recall, and F1 on all three datasets. SafeGuard leads in precision, but DMPI-PMHFE significantly outperforms on recall (e.g. 98.59% vs 94.85% on safeguard-v2), demonstrating reduced false negatives while maintaining high detection rates.

### Table 2: Ablation Study (Module Contributions)

Modules: M1 = DeBERTa feature extraction, M2 = Synonym matching, M3 = Pattern matching.

**safeguard-v2:**

| Configuration | Accuracy | Precision | Recall | F1 |
|---------------|----------|-----------|--------|----|
| M1 | 97.26 | 99.58 | 93.27 | 96.32 |
| M1 + M2 | 97.86 | 98.77 | 95.64 | 97.18 |
| M1 + M2 + M3 | 97.94 | 98.00 | 98.59 | 98.29 |

**Ivanleomk-v2:**

| Configuration | Accuracy | Precision | Recall | F1 |
|---------------|----------|-----------|--------|----|
| M1 | 92.95 | 97.67 | 91.75 | 94.62 |
| M1 + M2 | 93.93 | 98.70 | 92.23 | 95.36 |
| M1 + M2 + M3 | 94.75 | 98.22 | 93.93 | 96.03 |

**deepset-v2:**

| Configuration | Accuracy | Precision | Recall | F1 |
|---------------|----------|-----------|--------|----|
| M1 | 87.29 | 91.60 | 77.92 | 84.21 |
| M1 + M2 | 89.27 | 95.31 | 79.22 | 86.52 |
| M1 + M2 + M3 | 91.24 | 96.99 | 84.31 | 90.21 |

**Key finding:** Each module contributes positively to accuracy, recall, and F1 across all datasets. M3 (pattern matching) slightly decreases precision on safeguard-v2 (99.58% -> 98.00%) and Ivanleomk-v2 (98.70% -> 98.22%) because it expands detection coverage to more attack variants, introducing some false positives. The tradeoff yields higher recall and better overall F1.

### Table 3: Defense Effectiveness (ASR %, total attacks = 251)

| Model | Base Model | Self-Reminder | Self-Defense | DMPI-PMHFE |
|-------|------------|---------------|--------------|------------|
| glm-4-9b-chat | 71.71 (180) | 35.45 (89) | 39.04 (98) | **14.34 (36)** |
| Llama-3-8B-Instruct | 50.19 (126) | 37.45 (94) | 19.92 (50) | **13.54 (34)** |
| Llama-3.3-70B-Instruct | 25.09 (63) | 19.52 (49) | 15.53 (39) | **11.95 (30)** |
| Qwen2.5-7B-Instruct | 43.82 (110) | 39.84 (100) | 41.03 (103) | **13.94 (35)** |
| Chat GPT-4o | 29.08 (73) | 21.91 (55) | 16.33 (41) | **10.35 (26)** |

Numbers in parentheses = count of successful attacks out of 251 total.

**Key findings:**
- All tested LLMs are vulnerable without defense. glm-4-9b-chat is the most susceptible (71.71% base ASR).
- DMPI-PMHFE achieves lowest ASR on all five LLMs, reducing glm-4-9b-chat from 71.71% to 14.34%.
- Self-Reminder and Self-Defense vary significantly across LLMs (e.g. Self-Reminder: 19.52% on Llama-3.3-70B vs 39.84% on Qwen2.5-7B) due to reliance on the model's own capabilities.
- DMPI-PMHFE offers the most consistent defense across diverse LLM architectures and scales.

## Limitations

- Precision requires further enhancement (SafeGuard achieves higher precision on all datasets).
- Future work: refine feature fusion algorithms and incorporate data augmentation to improve overall performance.

## LLMTrace Application Notes

- **Required signals:** raw prompt text, conversation history (optional), prompt metadata (user vs tool), regex features, classifier logits, model score calibration data.
- **Runtime:** low-latency classification if DeBERTa is cached; streaming compatible only for chunk-level heuristics unless full prompt is buffered.
- **Integration surface (proxy):** run a pre-request detector on normalized prompt text, attach risk score to request metadata, enforce policy thresholds before forwarding.
- **Productizable vs research-only:** hybrid ML + heuristic detector is productizable; training-time feature fusion and dataset curation are research-heavy.

## Relevance to LLMTrace

LLMTrace can mirror the paper's dual-channel approach by combining learned semantic signals with deterministic rules in its observability pipeline. The results justify measuring both detection quality and downstream attack success rates as first-class metrics in LLMTrace dashboards. The 10 heuristic features (8 synonym + 2 pattern) are directly portable as a lightweight pre-filter module.
