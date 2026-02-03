# InjecGuard: Over-Defense Mitigation for Prompt Injection Detection

**Date:** 2026-02-01  
**Paper:** InjecGuard: Benchmarking and Mitigating Over-defense in Prompt Injection Guardrail Models  
**Authors:** Hao Li, Xiaogeng Liu, Chaowei Xiao (University of Wisconsin-Madison)  
**arXiv:** [2410.22770v1](https://arxiv.org/html/2410.22770v1)  
**Published:** October 29, 2024  
**Source PDF:** `docs/research/papers/2410.22770.pdf`

## LLMTrace Application Notes

- Required signals/features: raw prompt text, classifier logits, trigger-word feature flags, and a benign/malicious/over-defense label set for calibration.
- Runtime characteristics: DeBERTa-class detector with low-latency inference; streaming compatible only if content is buffered or chunked.
- Integration surface (proxy): run pre-request injection classifier and track false-positive rates on benign traffic for guard calibration.
- Productizable vs research-only: over-defense metrics and monitoring are productizable; MOF training data generation is research-heavy.

## Paper Summary

### Problem Statement and Motivation

InjecGuard addresses a critical limitation in existing prompt guard models: **over-defense**, where benign inputs are incorrectly flagged as malicious due to trigger word bias. This phenomenon severely impacts usability as legitimate user requests containing words like "ignore", "cancel", or "override" get blocked, reducing LLM accessibility in real-world applications like virtual assistants and diagnostic tools.

> "Over-defense arises when models misclassify inputs due to reliance on shortcuts, resulting in false positives where benign inputs are incorrectly flagged as threats."

The authors demonstrate that current state-of-the-art models like ProtectAIv2 achieve over-defense accuracy as low as 56.64% (barely better than random guessing at 50%) on their NotInject benchmark.

### Proposed Approach

#### 1. NotInject Benchmark Dataset
- **339 benign samples** containing trigger words common in prompt injection attacks
- **Three difficulty levels**: 1, 2, or 3 trigger words per sample
- Systematically constructed using:
  - Frequency analysis between benign and malicious datasets
  - LLM-based filtering and manual verification
  - GPT-4o-mini generation with safety refinement

#### 2. Mitigating Over-defense for Free (MOF) Training Strategy

MOF is a novel training approach that addresses over-defense without requiring specific over-defense datasets:

1. **Standard Training**: Train model normally on curated dataset (61,089 benign + 15,666 injection samples)
2. **Token-wise Bias Detection**: Test every token in vocabulary individually - tokens predicted as "attack" reveal model bias
3. **Adaptive Data Generation**: Generate 1,000 benign samples using combinations of biased tokens (1-3 tokens)
4. **Retraining from Scratch**: Combine original + generated data for final model training

> "After identifying the biased tokens, we prompt GPT-4o-mini to generate benign data using random combinations of these tokens."

#### 3. Data-Centric Augmentation
Addresses long-tail formats in prompt injection attacks by generating samples in 17 different formats: Email, Document, Chat, JSON, Code, Markdown, HTML, URL, Base64, Table, XML, CSV, Config File, Log File, Image Link, Translation, Website.

### Key Results and Benchmarks

**Performance Metrics (InjecGuard vs. competitors):**
- **Average Accuracy:** 83.48% (vs. ProtectAIv2: 63.81%, +30.8% improvement)
- **Over-defense Accuracy:** 87.32% (vs. ProtectAIv2: 56.64%, +54.17% improvement)  
- **Benign Accuracy:** 85.74%
- **Malicious Accuracy:** 77.39%
- **Inference Time:** 15.34ms (503x faster than GPT-4o at 7907.18ms)
- **GFLOPs:** 60.45 (comparable to other DeBERTa models)

**Baseline Comparison:**
```
Model            | Over-defense | Benign  | Malicious | Average
Fmops           |     5.60%    | 34.63%  |  93.50%   | 44.58%
Deepset         |     5.31%    | 34.06%  |  91.50%   | 43.62%  
PromptGuard     |     0.88%    | 26.82%  |  97.10%   | 41.60%
ProtectAIv2     |    56.64%    | 86.20%  |  48.60%   | 63.81%
InjecGuard      |    87.32%    | 85.74%  |  77.39%   | 83.48%
```

### Architecture Description

- **Backbone:** DeBERTa-v3-base (same as ProtectAI and PromptGuard)
- **Training Details:** 32 batch size, 3 epochs, Adam optimizer, 2e-5 learning rate, 512 max tokens
- **Attention Mechanism:** Unlike ProtectAIv2 which shows excessive attention to trigger words, InjecGuard distributes attention across entire input context

## Feature Delta with LLMTrace

| Feature | InjecGuard | LLMTrace Security | Gap |
|---------|------------|-------------------|-----|
| **Architecture** | DeBERTa-v3-base classification | DeBERTa-v2 + Regex hybrid | Minor - similar transformer base |
| **Over-defense Mitigation** | ✅ MOF strategy with bias detection | ❌ No explicit over-defense handling | **Critical gap** |
| **Trigger Word Analysis** | ✅ Automatic bias token identification | ❌ Static regex patterns only | **Major gap** |
| **Training Strategy** | ✅ Adaptive retraining from scratch | ❌ Standard fine-tuning | **Significant gap** |
| **Evaluation Framework** | ✅ 3D metrics (benign/malicious/over-defense) | ❌ Binary classification only | **Major gap** |
| **Encoding Detection** | ✅ Base64/ROT13/leetspeak/reversed | ✅ Base64 + manual pattern detection | Moderate gap |
| **Multi-language Support** | ✅ Includes Chinese, Russian samples | ❌ English-focused patterns | Moderate gap |
| **Format Coverage** | ✅ 17 data formats (CSV, XML, JSON, etc.) | ✅ Basic format detection | Minor gap |
| **Jailbreak Detection** | ✅ General prompt injection focus | ✅ Dedicated jailbreak detector | **LLMTrace strength** |
| **PII Detection** | ❌ Not covered | ✅ Comprehensive PII patterns + validation | **LLMTrace strength** |
| **Agent Action Analysis** | ❌ Not covered | ✅ Command/file/web analysis | **LLMTrace strength** |
| **Streaming Support** | ❌ Batch processing only | ✅ Real-time streaming analysis | **LLMTrace strength** |
| **Ensemble Approach** | ❌ Single model | ✅ ML + Regex ensemble | **LLMTrace strength** |
| **Open Source** | ✅ Fully open (model, data, code) | ✅ Open source | Equal |

### What InjecGuard Does That We Don't

1. **Systematic Over-defense Mitigation**: MOF training strategy specifically targets and reduces false positives
2. **Bias Token Detection**: Automated identification of problematic tokens that cause over-defense
3. **Three-Dimensional Evaluation**: Separate metrics for benign, malicious, and over-defense scenarios
4. **Adaptive Training Data Generation**: Automatically generates training data to counteract discovered biases
5. **NotInject-style Benchmarking**: Specific evaluation of model performance on benign inputs with trigger words

### What We Do That InjecGuard Doesn't

1. **Specialized Jailbreak Detection**: Dedicated module with encoding evasion detection (Base64, ROT13, leetspeak, reversed text)
2. **PII Detection & Validation**: Comprehensive personal information detection with checksum validation
3. **Agent Security Analysis**: Detection of dangerous commands, suspicious URLs, sensitive file access
4. **Streaming Security Monitoring**: Real-time analysis of content deltas
5. **Hybrid Architecture**: Combination of ML and regex approaches for robustness
6. **Granular Threat Categories**: Multiple finding types (prompt_injection, role_injection, data_leakage, etc.)

### Where We're Aligned

- DeBERTa backbone for ML classification
- Multi-format input support
- Open source approach
- Focus on lightweight, efficient models
- Encoding attack detection capabilities

## Actionable Recommendations

### P0 (Critical - Immediate Implementation)

1. **Implement Over-defense Detection** 
   - **Effort:** 2-3 weeks
   - Add evaluation metric for over-defense accuracy in `MLSecurityAnalyzer`
   - Create benchmark dataset similar to NotInject for LLMTrace testing
   - **Code Impact:** New metric in `AnalysisContext`, test dataset in `tests/`

2. **MOF-Inspired Training Strategy**
   - **Effort:** 3-4 weeks  
   - Implement token-wise bias detection during model training
   - Add adaptive training data generation for biased tokens
   - **Code Impact:** New training pipeline in `ml_detector.rs`, bias detection utilities

### P1 (High Priority - Next Quarter)

3. **Three-Dimensional Evaluation Framework**
   - **Effort:** 2 weeks
   - Separate benign/malicious/over-defense accuracy tracking
   - Update `SecurityFinding` to include over-defense classification
   - **Code Impact:** Enhanced metrics in `inference_stats.rs`

4. **Enhanced Trigger Word Analysis**
   - **Effort:** 3 weeks
   - Extend jailbreak detector to identify problematic trigger words
   - Add attention weight analysis for bias detection
   - **Code Impact:** Updates to `jailbreak_detector.rs`, new attention analysis module

### P2 (Medium Priority - Future Releases)

5. **Multi-language Trigger Detection**
   - **Effort:** 4-5 weeks
   - Extend pattern detection to Chinese, Russian, other languages
   - Add Unicode normalization improvements
   - **Code Impact:** Updates to `normalise.rs`, new language patterns

6. **Format-Specific Training**
   - **Effort:** 2-3 weeks
   - Generate training data for underrepresented formats (CSV, XML, etc.)
   - **Code Impact:** Training data augmentation scripts

### Potential Code/Model Integration

1. **InjecGuard Model Integration**
   - Consider adding InjecGuard as alternative backbone in `MLSecurityConfig`
   - Compare performance against current ProtectAI DeBERTa model
   - **HuggingFace Model:** Not yet available (paper just released)

2. **NotInject Dataset**
   - Use as additional test suite for LLMTrace models
   - Available at: `https://github.com/SaFoLab-WISC/InjecGuard`

3. **MOF Training Code**
   - Adapt their bias detection algorithm for our ensemble approach
   - Integrate with existing `FusionClassifier` architecture

## Key Metrics Comparison

### InjecGuard Reported Performance
- **Precision/Recall:** Not explicitly reported (accuracy-focused evaluation)
- **F1 Score:** Not reported
- **Average Accuracy:** 83.48%
- **Over-defense Accuracy:** 87.32% (most critical metric)
- **Malicious Detection:** 77.39%
- **Benign Recognition:** 85.74%

### Comparison to ProtectAI DeBERTa (Our Current Model)
InjecGuard vs. ProtectAI DeBERTa v2 (which we use):
- **Overall Performance:** +30.8% improvement in average accuracy
- **Over-defense:** +54.17% improvement (87.32% vs 56.64%)
- **Architecture:** Similar (both DeBERTa-based)
- **Efficiency:** Comparable inference time (~15ms)

### NotInject Benchmark Results
Current SOTA models perform poorly on over-defense:
- **PromptGuard (Meta):** 0.88% over-defense accuracy
- **Deepset:** 5.31% over-defense accuracy  
- **Fmops:** 5.60% over-defense accuracy
- **ProtectAI v2:** 56.64% over-defense accuracy

> "None of the existing open-source prompt guard models achieve an over-defense accuracy greater than 60%, where 50% represents random guessing."

## Technical Implementation Notes

### MOF Algorithm Adaptation for LLMTrace

```rust
// Potential integration in MLSecurityAnalyzer
pub struct OverDefenseDetector {
    pub bias_tokens: HashSet<String>,
    pub over_defense_threshold: f64,
}

impl OverDefenseDetector {
    // Test each vocabulary token individually
    pub fn detect_bias_tokens(&self, model: &MLSecurityAnalyzer) -> Vec<String> {
        // Implementation similar to InjecGuard's token-wise recheck
    }
    
    // Generate benign samples with biased tokens
    pub fn generate_debiasing_samples(&self, bias_tokens: &[String]) -> Vec<String> {
        // LLM-based generation for training data augmentation
    }
}
```

### Integration with Existing Architecture

The MOF strategy could be integrated into our ensemble approach:
1. Apply bias detection to our ML models
2. Generate additional training data for problematic patterns
3. Retrain ensemble components with augmented dataset
4. Maintain compatibility with existing regex-based detection

This represents a significant opportunity to improve LLMTrace's robustness against over-defense while maintaining our strengths in PII detection, agent security analysis, and real-time streaming capabilities.
