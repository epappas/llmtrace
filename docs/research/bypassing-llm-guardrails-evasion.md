# Bypassing LLM Guardrails: Research Analysis

**Paper:** "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails"  
**Authors:** William Hackett¹'², Lewis Birch¹'², Stefan Trawicki¹'², Neeraj Suri², Peter Garraghan¹'²  
**Institution:** ¹Mindgard, ²Lancaster University  
**arXiv:** 2504.11168v1  
**Date:** April 2025  

## Executive Summary

This research demonstrates systematic vulnerabilities in LLM guardrail systems through two attack categories: character injection (Unicode/homoglyphs) and algorithmic Adversarial ML evasion. Testing against six prominent guardrail systems revealed up to **100% evasion success rates**, highlighting critical gaps in current defense mechanisms.

## Paper Summary

### Problem Statement

The research conducts an empirical analysis of adversarial approaches for evading prompt injection and jailbreak detection systems in LLM guardrails. The core problem is that guardrails heavily rely on AI-driven detection systems (text classification models) which inherit the same vulnerabilities as other ML models to evasion attacks.

### Attack Vectors Tested

#### 1. Character Injection (12 techniques)
- **Unicode homoglyphs**: Cyrillic/Greek letters that look identical to Latin
- **Zero-width characters**: Invisible characters embedded in keywords
- **Emoji smuggling**: Using emoji to obfuscate malicious content
- **Bidirectional text**: Exploiting Unicode bidirectional controls
- **Full-width characters**: Unicode variants that appear normal
- **Unicode tags**: Special formatting characters
- **Number substitution**: Using Unicode number variants
- **Diacritics**: Adding accent marks to evade detection
- **Unicode underlines**: Invisible underline characters
- **Upside down text**: Flipped character variants
- **Deletion characters**: Characters that affect rendering
- **Character smuggling**: Various Unicode exploitation techniques

#### 2. Adversarial ML Evasion (8 techniques via TextAttack)
- **TextFooler**: Most effective across datasets (46-48% ASR)
- **BERT-Attack**: Leverages BERT embeddings for substitutions
- **BAE (BERT Adversarial Examples)**: BERT-based adversarial generation
- **PWWS**: Probability Weighted Word Saliency attacks
- **TextBugger**: Character-level and word-level perturbations
- **DeepWordBug**: Character-level attacks with word importance
- **Alzantot**: Genetic algorithm-based attacks
- **Pruthi**: Spelling error-based evasion

### Systems Tested

| System | Type | Architecture | Access |
|--------|------|--------------|--------|
| **Azure Prompt Shield** | Commercial | Ensemble neural classification | Black-box |
| **Meta Prompt Guard** | Open-source | mDeBERTa-v3-base (86M params) | White-box |
| **ProtectAI v1** | Open-source | DeBERTa-v3-base (184M params) | White-box |
| **ProtectAI v2** | Open-source | DeBERTa-v3-base (184M params) | White-box |
| **NeMo Guard** | Open-source | Random Forest + embeddings | White-box |
| **Vijil Prompt Injection** | Open-source | ModernBERT-based | White-box |

### Key Results

#### Character Injection Success Rates
- **Emoji Smuggling**: 100% ASR on both prompt injection and jailbreaks
- **Upside Down Text**: 100% ASR on jailbreaks
- **Unicode Tags**: 90.15% / 81.79% ASR
- **Numbers**: 81.18% / 94.62% ASR  
- **Bidirectional Text**: 78.69% / 99.23% ASR

#### Most Vulnerable Systems
- **Vijil**: 87.95% (prompt injection) / 91.67% (jailbreaks)
- **ProtectAI v1**: 77.32% / 51.39%
- **Azure Prompt Shield**: 71.98% / 60.15%
- **Meta Prompt Guard**: 70.44% / 73.08%
- **ProtectAI v2**: Significant improvement at 20.26% (prompt injection only)

#### AML Evasion Results
- **TextFooler**: Most effective at 46.27% (PI) / 48.46% (JB)
- **BERT-Attack**: 57.57% (PI) / 23.85% (JB)  
- **BAE**: 52.56% (PI) / 29.74% (JB)
- Success rates lower than character injection but still significant

#### Word Importance Transferability
Using white-box models (ProtectAI v2) to compute word rankings improved black-box attacks against Azure Prompt Shield:
- **6 out of 8** techniques showed improved ASR for jailbreaks
- **7 out of 8** techniques improved for prompt injections
- **BERT-Attack** achieved 73.11% ASR on prompt injections when using transferred rankings

## Feature Delta with LLMTrace

Comprehensive analysis of our current defenses against the demonstrated attacks:

| Feature | Paper's Attacks | LLMTrace Defense | Coverage |
|---------|----------------|-----------------|----------|
| **Unicode Normalisation** | Homoglyphs (Cyrillic а→a, Greek ο→o) | ✅ NFKC + extensive homoglyph mapping | **STRONG** - Covers Cyrillic & Greek confusables |
| **Zero-width Characters** | Embedding \u{200B} in keywords | ✅ Comprehensive stripping (12 characters) | **STRONG** - Covers all demonstrated zero-width chars |
| **Bidirectional Controls** | Unicode bidi overrides (\u{202A}-\u{202E}) | ✅ Full bidi control stripping | **STRONG** - Complete coverage |
| **Full-width Characters** | Unicode full-width variants | ✅ NFKC normalisation | **STRONG** - Automated via NFKC |
| **Emoji Smuggling** | Using emojis to hide malicious content | ❌ No specific emoji filtering | **GAP** - No emoji normalisation |
| **Unicode Tags** | Special formatting characters | ⚠️ Partial coverage | **WEAK** - May not cover all tag variants |
| **Number Substitution** | Superscript/subscript numbers | ✅ NFKC normalisation | **STRONG** - Covered by NFKC |
| **Upside Down Text** | Flipped character variants | ❌ No specific mapping | **GAP** - Not in homoglyph map |
| **Character Smuggling** | Various Unicode exploitation | ⚠️ Partial coverage | **WEAK** - Coverage depends on specific technique |
| **AML Evasion (TextAttack)** | Synonym substitution, typos | ✅ Ensemble ML detection | **MODERATE** - Our DeBERTa has known vulnerabilities |
| **Word Importance Ranking** | Using white-box to attack black-box | ⚠️ No specific mitigation | **WEAK** - Transferability attacks possible |
| **Base64 Encoding** | Encoded malicious instructions | ✅ Detection + decoding analysis | **STRONG** - Active detection |
| **ROT13/Leetspeak** | Simple encoding schemes | ✅ Detection + decoding analysis | **STRONG** - Multiple encoding schemes |

### Critical Finding: Our ProtectAI Model Vulnerability

**The paper specifically tested ProtectAI DeBERTa models - the same models we use in production.**

From our `ml_detector.rs`:
```rust
model_id: "protectai/deberta-v3-base-prompt-injection-v2".to_string(),
```

**Paper's findings on ProtectAI models:**
- **v1**: 77.32% ASR (prompt injection), 51.39% ASR (jailbreaks)  
- **v2**: 20.26% ASR (prompt injection), not tested on jailbreaks
- **Most vulnerable to**: TextFooler (95.18% ASR), BERT-Attack (67.87% ASR)

**This means our ML layer has documented vulnerabilities to the demonstrated AML attacks.**

## Vulnerability Assessment

### 🔴 Critical Vulnerabilities

1. **Emoji Smuggling** - 100% evasion success, no LLMTrace defense
2. **ProtectAI Model Exploitation** - Our DeBERTa model has documented 20-95% ASR
3. **Upside Down Text** - 100% jailbreak evasion, not in our homoglyph map
4. **Word Importance Transferability** - Attackers can use white-box models to improve black-box attacks

### 🟡 Moderate Vulnerabilities  

1. **Unicode Tag Variants** - Our zero-width stripping may miss some tag characters
2. **Character Smuggling Variants** - Unknown coverage of all Unicode exploitation techniques
3. **AML Ensemble Bypass** - Even with multiple models, sophisticated AML can evade detection

### 🟢 Strong Defenses

1. **Homoglyph Attacks** - Comprehensive Cyrillic/Greek→Latin mapping
2. **Zero-width Injection** - Complete stripping of demonstrated techniques  
3. **Bidirectional Attacks** - Full bidi control character removal
4. **Encoding Evasion** - Strong detection of Base64/ROT13/leetspeak/reversed text

## Actionable Recommendations

### Priority 1: Immediate (Critical Risk)

1. **Add Emoji Normalisation**
   ```rust
   // In normalise.rs, add emoji filtering/replacement
   fn strip_emojis(input: &str) -> String {
       input.chars()
           .filter(|c| !is_emoji(*c))
           .collect()
   }
   ```

2. **Extend Homoglyph Mapping**
   ```rust
   // Add upside down text variants
   '\u{0287}' => 't', // ʇ (upside down t)
   '\u{01DD}' => 'e', // ǝ (upside down e)
   // Add more Unicode confusables
   ```

3. **Expand Zero-width Character List**
   ```rust
   // Add Unicode tag characters and additional zero-width variants
   const ZERO_WIDTH_CHARS: &[char] = &[
       // Existing...
       '\u{E0001}', // Language tag
       '\u{E0020}', // Tag space
       // Unicode tag range \u{E0020}-\u{E007F}
   ];
   ```

### Priority 2: ML Defense Hardening (High Risk)

1. **Ensemble Diversification**
   ```rust
   // Replace single ProtectAI model with ensemble of different architectures
   pub struct EnsembleMLDetector {
       models: Vec<Box<dyn MLDetector>>,
       fusion_strategy: FusionStrategy,
   }
   ```

2. **Adversarial Training Integration**
   - Fine-tune models on TextAttack-generated adversarial examples
   - Implement robust training with character injection variants

3. **Threshold Adaptation**
   ```rust
   // Dynamic thresholding based on input characteristics
   pub fn adaptive_threshold(&self, text: &str) -> f64 {
       match self.detect_evasion_indicators(text) {
           EvasionRisk::High => self.base_threshold - 0.2,
           EvasionRisk::Medium => self.base_threshold - 0.1,
           EvasionRisk::Low => self.base_threshold,
       }
   }
   ```

### Priority 3: Advanced Defense (Medium Risk)

1. **Transferability Mitigation**
   ```rust
   // Add confidence calibration to reduce transferability
   pub struct CalibrationLayer {
       temperature: f64,
       platt_scaling: PlattScaling,
   }
   ```

2. **Input Transformation Pipeline**
   ```rust
   // Multiple normalisation passes with different strategies
   pub fn multi_pass_normalisation(text: &str) -> Vec<String> {
       vec![
           aggressive_normalise(text),
           conservative_normalise(text), 
           semantic_preserving_normalise(text),
       ]
   }
   ```

3. **Detection Confidence Ensemble**
   ```rust
   // Combine normalised and non-normalised analysis
   let raw_score = self.ml_detector.detect(text)?;
   let normalised_score = self.ml_detector.detect(&normalised_text)?;
   let final_score = confidence_fusion(raw_score, normalised_score);
   ```

## Implementation Timeline

**Week 1-2: Critical Fixes**
- Implement emoji normalisation/stripping
- Extend homoglyph mapping for upside down text
- Add Unicode tag character stripping

**Week 3-4: ML Hardening** 
- Implement ensemble voting with multiple model architectures
- Add adaptive thresholding based on evasion risk

**Week 5-8: Advanced Defenses**
- Implement confidence calibration
- Add multi-pass normalisation strategies
- Develop transferability mitigation techniques

## Testing Strategy

1. **Regression Testing**: Validate all paper's attack examples against updated defenses
2. **Adversarial Dataset**: Create comprehensive test suite with character injection + AML variants  
3. **Red Team Exercise**: Manual testing of novel evasion combinations
4. **Performance Monitoring**: Ensure normalisation changes don't impact processing speed

## Conclusion

This research reveals significant vulnerabilities in current LLM guardrail approaches, with LLMTrace having **strong defenses against 60% of demonstrated attacks** but **critical gaps in emoji smuggling and model-specific exploits**. Our use of the ProtectAI DeBERTa model creates a known vulnerability requiring immediate ensemble diversification.

The high success rates of character injection attacks (up to 100%) demonstrate that normalisation-only approaches are insufficient - we need defense-in-depth with multiple detection layers, robust ML ensembles, and proactive adversarial testing.

**Immediate action required on emoji smuggling and ML model diversification to prevent exploitation of documented attack vectors.**