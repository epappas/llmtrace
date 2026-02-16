# Threshold Tuning Guide

This guide covers how to adjust LLMTrace's detection sensitivity for your environment.

## Operating Points

LLMTrace provides three preset operating points that control per-category confidence thresholds:

### `high_recall`

Lowest thresholds. Catches more attacks but produces more false positives.

| Category | Threshold |
|----------|-----------|
| injection | 0.50 |
| jailbreak | 0.50 |
| pii | 0.40 |
| toxicity | 0.45 |
| data_leakage | 0.45 |

**Use when**: you cannot afford to miss any attack, even at the cost of manual review for false positives. Suitable for high-security environments with human review pipelines.

### `balanced` (default)

Recommended starting point. Good trade-off between catching attacks and avoiding false alerts.

| Category | Threshold |
|----------|-----------|
| injection | 0.75 |
| jailbreak | 0.75 |
| pii | 0.60 |
| toxicity | 0.65 |
| data_leakage | 0.65 |

**Use when**: general-purpose production deployment. This is the default.

### `high_precision`

Highest thresholds. Fewest false positives, but may miss lower-confidence attacks.

| Category | Threshold |
|----------|-----------|
| injection | 0.90 |
| jailbreak | 0.90 |
| pii | 0.80 |
| toxicity | 0.85 |
| data_leakage | 0.85 |

**Use when**: false positives are unacceptable (e.g., customer-facing blocking mode), or your traffic is predominantly benign.

### Configuration

```yaml
security_analysis:
  operating_point: "balanced"  # "high_recall" | "balanced" | "high_precision"
```

## Per-Model Thresholds

Each ML model has its own confidence threshold that gates whether its raw detection is forwarded to the ensemble:

```yaml
security_analysis:
  ml_threshold: 0.8            # DeBERTa confidence gate
  jailbreak_threshold: 0.7     # Jailbreak detector gate
  injecguard_threshold: 0.85   # InjecGuard confidence gate
  piguard_threshold: 0.85      # PIGuard confidence gate
```

These are independent of the operating point thresholds. A finding passes through two gates:

1. **Model threshold**: the model must be confident enough to emit a finding at all
2. **Category threshold** (from operating point): the finding must exceed the per-category threshold to survive filtering

## Over-Defence Toggle

The `over_defence` setting controls whether ML-only single-detector findings are suppressed when no regex corroboration exists:

```yaml
security_analysis:
  over_defence: true   # suppress ML-only single-detector findings
```

- **`true`**: reduces false positives from single-model hallucinations. Recommended when you see false positives on security research text, educational content, or benign queries that contain security terminology.
- **`false`** (default): all findings that pass threshold filtering are reported.

When InjecGuard or PIGuard are active, the over-defence logic is automatically bypassed because majority voting among 3+ models already controls false positives.

## Tuning Workflow

### 1. Start Conservative

Begin with `balanced` operating point and `over_defence: false`:

```yaml
security_analysis:
  operating_point: "balanced"
  over_defence: false
```

### 2. Monitor for 7 Days

Review security findings in the dashboard or via the API:

```bash
curl http://localhost:8080/api/v1/security/findings | jq
```

Track:
- **False positives**: benign requests flagged as threats
- **False negatives**: known attacks that were not detected (test with known injection payloads)
- **Finding types**: which categories generate the most noise

### 3. Adjust Incrementally

**Too many false positives?**
- Switch to `high_precision` operating point
- Enable `over_defence: true`
- Raise the specific model threshold (e.g., `ml_threshold: 0.9`)

**Missing attacks?**
- Switch to `high_recall` operating point
- Enable additional detectors (InjecGuard, PIGuard)
- Lower the specific model threshold (e.g., `ml_threshold: 0.7`)

**Specific category is noisy?**
- Raise that category's threshold while keeping others:

```yaml
security_analysis:
  operating_point: "balanced"
  # Override specific categories via per-model thresholds
  ml_threshold: 0.9  # raise DeBERTa gate to reduce injection FPs
```

### 4. Consider Enabling More Models

If false negatives are a concern, enable InjecGuard and PIGuard for additional coverage. With 3+ models, majority voting naturally suppresses single-model false positives:

```yaml
security_analysis:
  ml_enabled: true
  ml_threshold: 0.8
  jailbreak_enabled: true
  jailbreak_threshold: 0.7
  injecguard_enabled: true
  injecguard_threshold: 0.85
  piguard_enabled: true
  piguard_threshold: 0.85
  operating_point: "balanced"
```

## Baseline Expectations

With the full ensemble (DeBERTa + InjecGuard + PIGuard + regex) on the benchmark corpus:

| Metric | Value |
|--------|-------|
| Accuracy | 87.6% |
| Precision | 95.5% |
| Recall | 79.7% |
| F1 Score | 86.9% |

See [Benchmark Methodology](benchmarks.md) for details on the test corpus and how to reproduce these numbers.
