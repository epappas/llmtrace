# Defending Against Indirect Prompt Injection Attacks With Spotlighting -- Research Summary

**Date:** 2026-02-08
**Paper:** Defending Against Indirect Prompt Injection Attacks With Spotlighting
**Authors:** Keegan Hines, Gary Lopez, Matthew Hall, Federico Zarfati, Yonatan Zunger, Emre Kiciman (Microsoft)
**arXiv:** [2403.14720](https://arxiv.org/abs/2403.14720)
**Published:** March 20, 2024
**Source PDF:** `docs/research/papers/2403.14720.pdf`

## LLMTrace Application Notes

- Required signals/features: raw external content (tool outputs, retrieved documents, user-supplied files), system prompt template structure, content provenance metadata (which blocks are trusted vs untrusted).
- Runtime characteristics: datamarking adds negligible latency (whitespace replacement is O(n) string operation); base64 encoding adds ~33% token overhead but zero NLP quality loss on high-capacity models. All transformations are synchronous and streaming-compatible (transform before forwarding).
- Integration surface (proxy): LLMTrace can apply spotlighting transformations to untrusted content blocks before forwarding requests to the LLM. Datamarking and encoding are pure input transformations at the proxy layer -- no model access required. System prompt augmentation with provenance instructions is also proxy-injectable.
- Productizable vs research-only: datamarking is immediately productizable (simple string transformation, zero quality impact). Encoding (base64) is productizable for GPT-4-class models but requires per-model validation. Dynamic/randomized marking tokens are productizable. The telecom-inspired "out-of-band signaling" concept is research-only (requires model architecture changes).

## Paper Summary

### Problem Statement and Motivation

LLMs process a single, boundary-less stream of tokens. When applications concatenate system instructions with external data (websites, emails, tool outputs), the model cannot distinguish which tokens are trusted instructions ("code") and which are untrusted data. Indirect prompt injection (XPIA) exploits this: an attacker embeds instructions in external content, and the LLM follows those instructions as if they came from the user or system.

The paper frames this as a code-vs-data separation problem analogous to in-band signaling in early telecommunications. The core insight is that input transformations can provide a continuous, reliable provenance signal that helps the model distinguish trusted from untrusted token blocks.

### Proposed Approach

Spotlighting is a family of three prompt engineering techniques. Each has two components: (1) an optional transformation of the untrusted input text, and (2) system prompt instructions that inform the model about the transformation and how to treat the input.

#### 1. Delimiting

The simplest form. Special tokens (e.g., `<<` and `>>`) are placed before and after the untrusted content. The system prompt instructs the model to never obey instructions between those symbols.

**Limitation:** easily subverted if an adversary knows the delimiter tokens. The attacker can insert matching delimiters in their payload to break out of the data region.

#### 2. Datamarking

A special token is interleaved throughout the entire input text by replacing all whitespace. For example, using `^` as the marker: `"In this manner Cosette traversed"` becomes `"In^this^manner^Cosette^traversed"`. The system prompt explains this transformation and instructs the model that marked text should not be treated as instructions.

**Key properties:**
- The marking pervades the entire document, not just boundaries
- The model can still read and reason over the marked text with no quality loss
- Recommended starting token: Unicode U+E000 (Private Use Area, guaranteed absent from input)
- Can be made dynamic/randomized per-invocation to prevent adversary subversion

#### 3. Encoding

The untrusted input is transformed using a well-known encoding algorithm (e.g., base64) before insertion into the prompt. The system prompt instructs the model to decode and process the content but not follow any instructions within it.

**Key properties:**
- Provides the strongest provenance signal (encoded text is visually and structurally distinct)
- One-way transformation that an attacker cannot subvert (unlike ROT13, which is bidirectional)
- Requires high-capacity models (GPT-4 class) to decode accurately
- Not suitable for earlier-generation models (GPT-3.5 suffers significant quality degradation)

**Adversarial note on encoding choice:** ROT13 is explicitly warned against because an attacker can pre-encode their payload so that the system's ROT13 decoding produces the desired plaintext attack. Base64 is recommended as a one-way transformation the attacker cannot control.

### Key Results

**Models tested:** text-davinci-003, GPT-3.5-Turbo (June 2023), GPT-4 (June 2023). All experiments at temperature 1.0.

**Attack corpus:** 1000 synthetic documents with keyword payload attacks (model urged to forget instructions and return a special keyword "canary"). ASR measured as fraction of corpus where the attack fully overtakes the model.

#### Baseline ASR (no defense)

| Model | Summarization ASR | Q&A ASR |
|-------|-------------------|---------|
| GPT-4 | ~15% | ~10% |
| GPT-3.5-Turbo | ~55% | ~55% |
| Text-003 | ~25% | ~20% |

#### Delimiting Results (GPT-3.5-Turbo, Summarization)

| Condition | ASR |
|-----------|-----|
| Baseline | ~60% |
| + Instructions only | ~55% (negligible effect) |
| + Instructions + Delimiters | ~30% (halved) |

#### Datamarking Results

**Summarization task:**

| Model | Baseline ASR | Datamarking ASR |
|-------|-------------|-----------------|
| GPT-3.5-Turbo | ~50% | 3.10% |
| Text-003 | ~40% | 0.00% |

**Q&A task:**

| Model | Baseline ASR | Datamarking ASR |
|-------|-------------|-----------------|
| GPT-3.5-Turbo | ~25% | 8.0% |
| GPT-4 | ~10% | 1.0% |
| Text-003 | ~20% | 0.00% |

#### Encoding Results (GPT-3.5-Turbo)

| Task | Baseline ASR | Encoding ASR |
|------|-------------|--------------|
| Summarization | ~30% | 0.0% |
| Q&A | ~25% | 1.8% |

#### NLP Task Quality Impact (GPT-3.5-Turbo)

**Datamarking -- no detrimental impact across all benchmarks:**

| Benchmark | Baseline Accuracy | Datamarking Accuracy |
|-----------|-------------------|----------------------|
| SQuAD Q&A | ~0.85 | ~0.85 |
| IMDB Sentiment | ~0.95 | ~0.95 |
| SuperGLUE WIC | ~0.65 | ~0.65 |
| SuperGLUE BoolQ | ~0.85 | ~0.85 |

**Encoding -- model-dependent:**

| Model | SQuAD Q&A | Sentiment | WIC | BoolQ |
|-------|-----------|-----------|-----|-------|
| GPT-4 (encoding) | ~0.85 | ~0.90 | ~0.65 | ~0.80 |
| GPT-3.5 (encoding) | ~0.40 | ~0.55 | ~0.45 | ~0.50 |

GPT-3.5 suffers severe quality degradation with encoding. GPT-4 handles it with minimal impact.

#### Few-Shot Learning (Appendix)

| Condition | ASR (GPT-3.5-Turbo) |
|-----------|---------------------|
| Baseline | ~55% |
| + Instructions | ~50% |
| + Instructions + Few-Shot (FS1) | <5% |
| + Instructions + Few-Shot (FS2) | <5% |

The authors caution against over-reliance on few-shot examples: they reflect current knowledge of attack tactics, may not generalize to novel attacks, and risk label leakage (classic overfitting in few-shot setting).

### Paper Recommendations

1. **Minimum:** use datamarking -- large ASR improvement, zero NLP quality impact, works across models
2. **Optimal (high-capacity models):** use encoding (base64) -- strongest ASR reduction, but validate task performance per use case
3. **Do not rely on delimiting alone** -- easily subverted by adversary with system prompt knowledge
4. **Use dynamic/randomized marking tokens** -- prevents adversary from crafting payloads that match the marking scheme
5. **Use Unicode Private Use Area (U+E000)** as a starting point for marking tokens

### Limitations

1. **Evaluated only on GPT-family models** -- no open-source model evaluation (Llama, Mistral, etc.)
2. **Simple keyword-payload attacks only** -- does not test sophisticated multi-step, semantic, or tool-calling attacks
3. **No adaptive adversary evaluation** -- does not test adversaries who know the defense is in place and craft attacks accordingly (except theoretical analysis)
4. **Encoding is model-capacity-gated** -- GPT-3.5 and below cannot reliably decode base64 while performing tasks
5. **No multi-turn or agent scenarios** -- all experiments are single-turn document processing tasks
6. **No explanation of why spotlighting works** -- the authors acknowledge lacking a mechanistic understanding; the telecom analogy is suggestive but not rigorous
7. **1000-document synthetic corpus** -- limited attack diversity compared to benchmarks like BIPIA (86,250 test prompts, 50 attack types)

## Feature Delta with LLMTrace

| Paper Technique | LLMTrace Coverage | Gap | Planned Feature |
|---|---|---|---|
| Delimiting (boundary tokens around untrusted content) | Partial -- BIPIA-style `<data>`/`</data>` injection planned (AS-001/AS-002) | Delimiting alone is weak; LLMTrace should implement but not rely on it | AS-001, AS-002 cover this as part of tool-boundary firewalling |
| Datamarking (whitespace replacement with special token) | Missing -- no input transformation capability | **Major gap**: datamarking is the best cost/benefit defense and is trivially implementable at proxy level | New feature needed: proxy-level datamarking transformation |
| Encoding (base64 transformation of untrusted content) | Missing -- no encoding transformation | **Moderate gap**: strongest defense but model-capacity-gated | New feature needed: optional encoding mode for high-capacity models |
| Dynamic/randomized marking tokens | Missing | **Significant gap**: static tokens are subvertable if system prompt leaks | Should be part of datamarking implementation |
| System prompt augmentation with provenance instructions | Missing -- no automatic instruction injection for data provenance | Overlaps with BIPIA explicit reminder injection | Extend planned reminder injection to include spotlighting instructions |
| Few-shot injection defense | Missing -- no few-shot example injection | Moderate gap, but paper cautions against over-reliance | Low priority; spotlighting is more generalizable |
| Perplexity/anomaly detection | Missing (IS-050 planned) | Orthogonal to spotlighting; detects GCG strings | IS-050 addresses different attack class |
| Tool output sanitization | Partial (AS-002 planned) | Spotlighting is complementary to sanitization | Datamarking can be applied as pre-sanitization step |

### Primary Connections

- **AS-001/AS-002 (tool-boundary firewalling):** Spotlighting transforms are a natural addition to the tool-output sanitizer pipeline. After sanitizing tool output content (AS-002), apply datamarking before reinserting into the agent prompt.
- **IS-050 (perplexity-based anomaly detection):** Orthogonal defense. Spotlighting handles natural-language XPIA; IS-050 handles gradient-optimized adversarial strings. Both should be layered.
- **IS-005 (three-dimensional evaluation):** Spotlighting's zero NLP quality impact validates that defensive transforms can be evaluated on the benign/malicious/over-defense axes without degrading benign performance.

## Actionable Recommendations

### 1. Implement Datamarking at Proxy Level (P0)

**Effort:** 1 week

Apply datamarking transformation to all untrusted content (tool outputs, retrieved documents, user-supplied files) before forwarding to the LLM. Replace whitespace in untrusted blocks with a configurable marking token. Default to Unicode U+E000. Include system prompt augmentation instructing the model that marked content is data, not instructions.

**Rationale:** Reduces ASR from >50% to <3% with zero NLP quality impact. Pure string transformation, no model access needed, streaming-compatible.

### 2. Add Dynamic/Randomized Marking Tokens (P0)

**Effort:** 3 days (as part of datamarking implementation)

Generate a random k-gram marking token (e.g., 5 characters from a suitable character set) per LLM invocation. Include the token description in the system prompt. This prevents adversaries who have leaked the system prompt from crafting payloads that match the marking scheme.

**Rationale:** Static tokens are subvertable. With a character set of size N and k-gram length k, adversary has 1/N^k chance of guessing correctly.

### 3. Implement Optional Base64 Encoding Mode (P1)

**Effort:** 1 week

Add a configurable encoding mode that base64-encodes untrusted content before insertion. Enable only for GPT-4-class models. Include system prompt instructions for decoding. Require per-tenant/per-model validation of task quality.

**Rationale:** Strongest ASR reduction (0.0% in summarization, 1.8% in Q&A) but model-capacity-gated. Only suitable for frontier models.

### 4. Integrate Spotlighting Into Tool-Output Sanitizer Pipeline (P1)

**Effort:** 2 weeks

Position datamarking as a stage in the AS-002 tool-output firewall pipeline. Execution order: (1) IS-052 perplexity-based stripping, (2) AS-002 pattern-based sanitization, (3) spotlighting datamarking transformation. This provides defense-in-depth: sanitization removes known patterns, datamarking prevents the model from following anything that slips through.

### 5. Benchmark Spotlighting Across Open-Source Models (P2)

**Effort:** 2 weeks

The paper only tested GPT-family models. Validate datamarking and encoding effectiveness on Llama 3.x, Mistral, Qwen 2.5, and other models LLMTrace supports. Use the existing BIPIA benchmark (86,250 test prompts) to measure ASR reduction with spotlighting applied.

**Rationale:** Fills the paper's biggest evaluation gap and ensures LLMTrace's implementation works across its supported model ecosystem.

## Key Takeaways

1. **Datamarking is the best cost/benefit XPIA defense available today.** It reduces ASR from >50% to <3% across models with zero measurable impact on NLP task quality. It requires only a trivial string transformation and system prompt update -- fully implementable at the proxy layer.

2. **Delimiting alone is insufficient.** While easy to implement, delimiter-based boundaries can be trivially subverted by an adversary who knows the system prompt. Datamarking and encoding provide continuous provenance signals throughout the input, not just at boundaries.

3. **Encoding (base64) is the strongest defense but is model-capacity-gated.** It achieves 0.0% ASR on summarization tasks but causes severe quality degradation on GPT-3.5-class models. Reserve for GPT-4-class and above, with per-model validation.

4. **Dynamic/randomized marking tokens are essential for production deployments.** The paper explicitly assumes the system prompt will leak. Static marking tokens become a known constant the adversary can exploit. Randomizing the token per-invocation makes the defense robust against system prompt leakage.

5. **Spotlighting addresses the structural root cause of XPIA** -- the inability of LLMs to distinguish code from data in a shared token stream. This makes it more generalizable than few-shot or instruction-based defenses that depend on knowledge of specific attack tactics. It complements (not replaces) classification-based detection and tool-output sanitization.
