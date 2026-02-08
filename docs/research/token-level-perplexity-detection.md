# Token-Level Adversarial Prompt Detection Based on Perplexity Measures and Contextual Information -- Research Summary

**Date:** 2026-02-08
**Paper:** Token-Level Adversarial Prompt Detection Based on Perplexity Measures and Contextual Information
**Authors:** Zhengmian Hu, Gang Wu, Saayan Mitra, Ruiyi Zhang, Tong Sun, Heng Huang, Viswanathan Swaminathan (University of Maryland, College Park; Adobe Research)
**arXiv:** [2311.11509](https://arxiv.org/abs/2311.11509)
**Published:** November 2023 (v3: 18 Feb 2024)
**Source PDF:** `docs/research/papers/2311.11509.pdf`

## LLMTrace Application Notes

- **Required signals/features:** per-token next-token log-probabilities from a small language model (GPT-2 124M is sufficient), full token sequence of the input prompt, hyperparameters lambda (contextual coherence weight) and mu (prior belief of adversarial content).
- **Runtime characteristics:** O(n) dynamic programming over token count. GPT-2 124M inference runs on CPU with <1GB memory; no GPU required. The forward+backward DP pass adds negligible latency on top of the perplexity computation pass. Suitable for real-time proxy deployment. Not streaming-compatible in the traditional sense (requires the full token sequence before running DP), but can operate on buffered prompt chunks.
- **Integration surface (proxy):** LLMTrace intercepts the full prompt before forwarding to the target LLM. Run GPT-2 124M to compute per-token log-probabilities, then run DP-based detection (optimization or PGM variant). Attach per-token adversarial probability annotations and a sentence-level p-value to the request metadata. Enforce policy thresholds on the p-value before forwarding. Token-level heatmap data can feed into observability dashboards.
- **Productizable vs research-only:** The core detection algorithm (perplexity + fused-lasso DP) is fully productizable -- small model, O(n) complexity, no training required, deterministic output. The PGM variant adds probabilistic scoring suitable for tiered alerting. Hyperparameter tuning (lambda, mu grid search) is a one-time calibration step. The limitation to GCG-style discrete-optimization attacks is a research constraint; natural-language prompt injections would not be detected by this method alone.

## Paper Summary

### Problem Statement and Motivation

LLMs are vulnerable to adversarial prompt attacks generated through discrete optimization (specifically the GCG attack from Zou et al., 2023). These adversarial suffixes bypass moderation and alignment by appending out-of-distribution (OOD) token sequences to harmful queries. Prior perplexity-based defenses (Alon & Kamfonas, 2023; Jain et al., 2023) operate at the sequence level only -- they flag entire sequences but cannot localize which tokens are adversarial. This paper addresses two gaps: (1) token-level localization of adversarial content, and (2) incorporation of contextual information from neighboring tokens to reduce false positives on isolated high-perplexity tokens in otherwise benign text.

### Proposed Approach

The method operates in two stages:

**Stage 1: Per-Token Perplexity Computation.** Given an input sequence of n tokens, a language model computes the conditional probability p(x_i | x_1, ..., x_{i-1}) for each token. Tokens from normal text are expected to have high probability under the language model. Adversarial tokens are modeled as drawn from a uniform distribution over printable tokens: p_1 = 1/|Sigma_printable|.

**Stage 2: Contextual Agglomeration.** Two algorithms are proposed:

1. **Optimization-based method** -- Solves a minimization problem that combines:
   - Negative log-likelihood under the assigned indicator (normal vs adversarial) for each token
   - A fused-lasso regularization term (lambda * sum |c_{i+1} - c_i|) that penalizes transitions between normal and adversarial labels, encouraging contiguous adversarial segments
   - A prior term (mu * sum c_i) encoding belief about adversarial content prevalence
   - Solved via dynamic programming with one forward pass and one backward pass: O(n) time complexity
   - Output: binary classification per token (adversarial or not)

2. **Probabilistic Graphical Model (PGM) method** -- Extends the optimization formulation to a Bayesian posterior over the indicator variables. The PGM is a chain-structured graphical model where each c_i is connected to c_{i-1}, c_{i+1}, and x_i. Using free-energy computation via DP (also O(n)), it produces:
   - Per-token marginal probability of being adversarial: p(c_i = 1 | x)
   - Sentence-level p-value: p(max_i c_i = 0 | x), representing the probability that no token in the sequence is adversarial

**Edge case handling:** The first token is excluded from perplexity-based detection because it inherently has high perplexity (no preceding context). This is done by setting p_0,1 = p_1,1 so the first token's classification depends only on its neighbor.

**Default hyperparameters:** lambda = 20, mu = -1.0 (for GPT-2 124M).

### Key Results

**Sequence-level detection (Table 2, using GPT-2 124M, default hyperparameters):**

| Metric | Optimization-based | PGM-based |
|--------|-------------------|-----------|
| Precision | 1.00 | 1.00 |
| Recall | 1.00 | 1.00 |
| F1-Score | 1.00 | 1.00 |

Both methods achieve perfect sequence-level detection on 107 adversarial + 107 benign samples from the GCG attack dataset.

**Token-level detection (Table 2, using GPT-2 124M, default hyperparameters):**

| Metric | Optimization-based | PGM-based |
|--------|-------------------|-----------|
| Token Precision | 0.8916 | 0.8995 |
| Token Recall | 0.9838 | 0.9839 |
| Token F1 | 0.9354 | 0.9398 |
| Token IoU | 0.8787 | 0.8864 |

**Sequence-level detection across models (Table 3, with grid-searched hyperparameters):**

All models achieve perfect 1.0 Accuracy/Precision/Recall/F1/AUC at the sequence level, including:
GPT2 124M, GPT2 355M, GPT2 774M, GPT2 1.5B, Llama2 7B, Llama2 13B, Llama2 chat 7B, Llama2 chat 13B.

**Token-level detection across models (Table 4, with grid-searched hyperparameters):**

| Model | Tok Prec (Opt) | Tok Rec (Opt) | Tok F1 (Opt) | IoU (Opt) | Tok Prec (PGM) | Tok Rec (PGM) | Tok F1 (PGM) | IoU (PGM) |
|-------|---------------|--------------|-------------|----------|---------------|--------------|-------------|----------|
| GPT2 124M | 0.9941 | 0.9593 | 0.9764 | 0.9539 | 0.9955 | 0.9590 | 0.9769 | 0.9548 |
| GPT2 355M | 0.9866 | 0.9654 | 0.9759 | 0.9529 | 0.9880 | 0.9657 | 0.9767 | 0.9545 |
| GPT2 774M | 0.9873 | 0.9681 | 0.9776 | 0.9562 | 0.9873 | 0.9681 | 0.9776 | 0.9562 |
| GPT2 1.5B | 0.9859 | 0.9650 | 0.9754 | 0.9519 | 0.9859 | 0.9647 | 0.9752 | 0.9516 |
| Llama2 7B | 0.9991 | 0.9977 | 0.9984 | 0.9967 | 0.9991 | 0.9977 | 0.9984 | 0.9967 |
| Llama2 13B | 1.0000 | 0.9977 | 0.9988 | 0.9977 | 1.0000 | 0.9977 | 0.9988 | 0.9977 |
| Llama2 chat 7B | 0.9995 | 0.9972 | 0.9984 | 0.9967 | 0.9995 | 0.9963 | 0.9979 | 0.9958 |
| Llama2 chat 13B | 0.9991 | 0.9995 | 0.9993 | 0.9986 | 0.9991 | 0.9995 | 0.9993 | 0.9986 |

Larger models improve token-level localization (Llama2 models reach ~0.998+ F1), but even GPT-2 124M achieves 0.976+ F1 at the token level.

**Selected hyperparameters per model (Table 5):**

| Model | lambda | mu |
|-------|--------|----|
| GPT2 124M | 15.89 | 0.0 |
| GPT2 355M | 10.02 | -1.0 |
| GPT2 774M | 20.0 | 0.0 |
| GPT2 1.5B | 15.89 | -0.5 |
| Llama2 7B | 6.32 | -1.5 |
| Llama2 13B | 7.96 | -2.0 |
| Llama2 chat 7B | 6.32 | 0.5 |
| Llama2 chat 13B | 7.96 | -2.0 |

**Computational requirements:** All experiments required less than 1 GPU hour on an NVIDIA A6000. GPT-2 124M detection runs on CPU only.

### Limitations

1. **GCG-specific detection:** The method relies on two assumptions: adversarial prompts exhibit high perplexity and tend to appear in contiguous sequences. Both assumptions hold for discrete-optimization attacks (GCG) but may not hold for human-crafted or natural-language prompt injections, which resemble normal text.
2. **Small evaluation dataset:** Only 107 adversarial prompts from the GCG attack (Zou et al., 2023). No evaluation against other attack types (AutoDAN, PAIR, many-shot, multilingual injections).
3. **Uniform adversarial distribution assumption:** Adversarial tokens are modeled as uniform over printable tokens. More sophisticated attacks may produce tokens with lower perplexity.
4. **No false-positive analysis on diverse benign inputs:** Clean samples are the natural-language queries from Zou et al. No testing on code, multilingual text, technical jargon, or other domains where benign text may have elevated perplexity.
5. **Hyperparameter sensitivity:** lambda and mu require grid search per model; default values may not generalize across domains or attack types.
6. **First-token exclusion:** The workaround for first-token false positives (setting p_0,1 = p_1,1) is a heuristic; adversarial content starting at position 1 would be missed.

## Feature Delta with LLMTrace

| Paper Technique | LLMTrace Coverage | Gap | Planned Feature |
|---|---|---|---|
| Per-token perplexity scoring via small LM | No perplexity-based detection implemented | Major: core capability needed for IS-050 | IS-050 (perplexity-based anomaly detection) |
| Fused-lasso contextual agglomeration (optimization-based) | No contextual token-level aggregation | Major: prevents false positives on isolated high-perplexity tokens | Extension to IS-050 |
| PGM-based probabilistic detection with per-token and sentence-level p-values | No probabilistic adversarial scoring | Medium: enables tiered alerting and confidence-based policies | Extension to IS-050 |
| Token-level heatmap visualization | LLMTrace has observability dashboards but no token-level adversarial annotations | Minor: visualization enhancement | New observability feature |
| GPT-2 124M as perplexity backbone (CPU-only, <1GB) | No dedicated perplexity model deployed | Major: lightweight model needed for IS-050 | IS-050 implementation detail |
| Adversarial string detection in tool outputs | IS-052 planned but not implemented | Major: GCG strings in tool outputs propagate through agent traces | IS-052 (adversarial string propagation blocking) |
| Sentence-level p-value for binary detection | IS-001 (token-entropy gate) tracks entropy but not perplexity-based p-values | Medium: complementary signal to token-entropy | IS-001 extension |
| Binary sequence classification (adversarial vs benign) | ML-001 (binary classifier) uses DeBERTa-based fusion | Low: perplexity detector is complementary, not replacement | ML-001 ensemble input |

## Actionable Recommendations

1. **Implement IS-050 using the PGM variant from this paper as the core algorithm.** The PGM method provides both binary detection and probabilistic scoring (per-token probability + sentence-level p-value) with identical O(n) complexity to the optimization variant. Use GPT-2 124M as the perplexity backbone -- it runs on CPU, requires <1GB memory, and achieves perfect sequence-level detection. The p-value output directly enables tiered policy enforcement (block vs flag vs pass). Priority: P0, estimated effort: 1-2 weeks for core algorithm, +1 week for proxy integration.

2. **Feed perplexity p-value as an input feature to the ML-001 fusion classifier.** The sentence-level p-value from this paper is a single scalar that captures GCG-style adversarial content with near-perfect accuracy. Adding it as a feature to the DeBERTa + heuristic fusion pipeline (ML-001) would provide coverage against discrete-optimization attacks that the semantic classifier may miss, without increasing the fusion model's complexity. This creates a three-channel detection system: semantic (DeBERTa), structural (heuristics), and distributional (perplexity).

3. **Apply the token-level detection to IS-052 (adversarial string propagation blocking).** The agent-as-a-proxy attack relies on GCG-optimized strings surviving in tool outputs and being repeated by agents. Run the perplexity detector on tool outputs before they enter agent traces. Strip or sanitize token spans where p(c_i = 1 | x) exceeds a configurable threshold. This directly addresses the propagation vector identified in the agent-as-a-proxy paper.

4. **Calibrate hyperparameters (lambda, mu) against LLMTrace's FPR targets.** The paper's grid search optimizes for IoU. LLMTrace requires calibration against specific FPR targets (e.g., 0.1% FPR per the existing fpr_calibration_regex analysis). Run the grid search on a representative corpus of benign LLMTrace traffic (code, multilingual, technical) to find lambda/mu values that meet the proxy's false-positive constraints rather than optimizing purely for token-level localization accuracy.

5. **Evaluate against non-GCG attacks to establish detection boundaries.** Before deploying IS-050, benchmark the perplexity detector against AutoDAN, PAIR, many-shot, multilingual, and human-crafted injections from the existing LLMTrace evaluation datasets. This will establish which attack classes require the perplexity signal versus the semantic classifier, informing the ensemble routing logic in ML-006.

## Key Takeaways

- A small language model (GPT-2 124M, CPU-only, <1GB memory) achieves perfect sequence-level detection of GCG-style adversarial suffixes using token perplexity alone. This validates IS-050 as a lightweight, deployable defense layer.

- The fused-lasso contextual regularization is the key contribution beyond naive perplexity thresholding. It reduces false positives by requiring adversarial tokens to appear in contiguous spans, which matches the structure of GCG-optimized suffixes. Isolated high-perplexity tokens in benign text are not flagged.

- The PGM variant provides calibrated per-token and sentence-level probabilities (p-values as low as 9.8 x 10^{-28} for adversarial inputs, 0.999+ for benign inputs), enabling policy-based thresholding rather than hard binary classification. This is directly suitable for LLMTrace's tiered alerting architecture.

- Token-level localization (0.93+ F1 with GPT-2 124M, 0.99+ F1 with Llama2) enables surgical sanitization of adversarial spans rather than blanket rejection, which is critical for IS-052 (propagation blocking) where tool outputs may contain both legitimate data and injected adversarial strings.

- The method is explicitly limited to discrete-optimization attacks (GCG). Natural-language prompt injections that resemble normal text will not be detected. This positions the perplexity detector as a complementary layer to the DeBERTa-based semantic classifier (ML-001), not a replacement.
