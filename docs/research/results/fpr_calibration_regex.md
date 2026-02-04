# FPR Calibration Report — Regex Baseline (NotInject)

**Run date:** 2026-02-04
**Analyzer:** `LLMTrace Regex`
**Datasets:** 110 benign + 110 malicious + 339 NotInject (over-defense) = 559 total
**FPR targets:** 0.1%, 0.5%, 1.0% (PromptShield methodology)

## Raw Report Output
```
=== FPR-Aware Threshold Calibration Report ===
  (PromptShield methodology: Jacob et al., CODASPY 2025)

  [regex_notinject] 0.1% FPR (Strict) → threshold=0.8500, fpr=0.0000%, tpr=8.18%, od_fpr=0.00% (n_benign=449, n_malicious=110, n_od=339)
  [regex_notinject] 0.5% FPR (Moderate) → threshold=0.7000, fpr=0.2227%, tpr=43.64%, od_fpr=0.29% (n_benign=449, n_malicious=110, n_od=339)
  [regex_notinject] 1.0% FPR (Permissive) → threshold=0.7000, fpr=0.2227%, tpr=43.64%, od_fpr=0.29% (n_benign=449, n_malicious=110, n_od=339)

  ✅ All FPR targets met.

  Reference (PromptShield paper, 0.1% FPR):
    Meta PromptGuard TPR:  9.4%
    PromptShield TPR:     65.3%
```

## Interpretation
- **Strict operating point (0.1% FPR):** TPR is 8.18%, which is too low for production-grade detection. This matches the literature’s warning that detectors can collapse at deployment-realistic FPR thresholds.
- **Moderate/Permissive points:** TPR improves to 43.64%, but still trails literature baselines like PromptShield and InjecGuard.
- **Over-defense control:** od_fpr remains very low, confirming regex is conservative but at the cost of missing real attacks.

## Literature Alignment
- **PromptShield (CODASPY 2025):** demonstrates the need to evaluate at 0.1% FPR and shows Meta PromptGuard at 9.4% TPR; our regex baseline is comparable at 8.18% but far below PromptShield’s 65.3% TPR.
- **InjecGuard:** requires MOF training and over-defense mitigation to maintain high TPR while controlling FPR.

## Improvement Path (per literature)
1. **Replace regex-only baseline with ML detectors** (PromptGuard/InjecGuard) as primary signal.
2. **MOF training** (IS-001–IS-003, ML-010) to reduce trigger-word bias while preserving TPR.
3. **Ensemble diversification** (ML-006) to improve robustness and reduce transferability gaps.
4. **Apply FPR calibration** to ML/ensemble scores (not regex-only) at 0.1/0.5/1% FPR.
