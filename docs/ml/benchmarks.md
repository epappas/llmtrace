# Benchmark Methodology

LLMTrace's security detection pipeline is evaluated against a curated adversarial corpus. This document describes the test methodology and current results.

## Current Results

| Metric | Value |
|--------|-------|
| Accuracy | 87.6% |
| Precision | 95.5% |
| Recall | 79.7% |
| F1 Score | 86.9% |

### Confusion Matrix

|  | Predicted Malicious | Predicted Benign |
|--|-------------------:|----------------:|
| **Actually Malicious** | TP = 63 | FN = 16 |
| **Actually Benign** | FP = 3 | TN = 71 |

Total samples: 153

### Latency

| Percentile | Latency |
|-----------|---------|
| Min | 757.6 ms |
| Median | 1503.8 ms |
| Mean | 1647.5 ms |
| P95 | 2743.7 ms |
| Max | 11514.5 ms |

Latency includes upstream LLM response time (the test sends real requests through the proxy to OpenAI).

## Test Corpus

153 samples total: 79 malicious, 74 benign. Randomly sampled with seed=42, stratified across attack categories and difficulty levels.

### Malicious Samples (79)

| Source | Samples | Description |
|--------|---------|-------------|
| Internal injection corpus | 15 | Curated prompt injection patterns |
| Encoding evasion | 10 | Base64, ROT13, Unicode obfuscation attacks |
| CyberSecEval2 | 8 | Meta's prompt injection evaluation set |
| HPI attack approximation | 8 | Handcrafted prompt injection variants |
| TensorTrust | 8 | Game-derived adversarial prompts |
| JackHHao jailbreak | 6 | Jailbreak prompt collection |
| Transfer attacks | 6 | Cross-model transfer attack samples |
| BIPIA indirect | 6 | Indirect prompt injection attacks |
| InjecAgent | 8 | Agent-targeted injection attacks |
| Edge cases | 4 | Boundary tests (short, buried, delimiter, translation) |

### Benign Samples (74)

| Source | Samples | Description |
|--------|---------|-------------|
| Internal benign corpus | 15 | Standard user prompts |
| NotInject (difficulty 1) | 8 | Easy-to-classify benign samples |
| NotInject (difficulty 2) | 10 | Moderate difficulty benign samples |
| NotInject (difficulty 3) | 12 | Hard benign samples (security terminology, edge cases) |
| DeepSet v2 | 8 | Benign samples from DeepSet dataset |
| Encoding (benign) | 3 | Legitimate encoded content |
| JackHHao (benign) | 6 | Benign samples from jailbreak dataset |
| SafeGuard test | 8 | Benign evaluation samples |
| Edge cases | 4 | Boundary tests (short, long, Unicode, security research) |

## Classification Threshold

A sample is classified as "flagged" (malicious) when `security_score >= 50`. This threshold is applied to the final score after ensemble voting, threshold filtering, and over-defence suppression.

## How to Reproduce

### Prerequisites

- LLMTrace proxy running on port 8080 with `--config config.yaml`
- ClickHouse running on port 8123
- `OPENAI_API_KEY` environment variable set
- Python 3.10+ with `requests` package

### Steps

```bash
# 1. Build and start the proxy with ML models
cargo build --release --features ml
RUST_LOG=info ./target/release/llmtrace-proxy --config config.yaml

# 2. Run the stress test
cd benchmarks
python3 scripts/proxy_stress_test_v2.py
```

Results are saved to `benchmarks/results/proxy_stress_test_v2.json`.

### Configuration Requirements

The proxy must be started with a config that enables the full security pipeline:

```yaml
security_analysis:
  ml_enabled: true
  ml_model: "protectai/deberta-v3-base-prompt-injection-v2"
  ml_threshold: 0.8
  jailbreak_enabled: true
  jailbreak_threshold: 0.7
  injecguard_enabled: true
  injecguard_model: "leolee99/InjecGuard"
  injecguard_threshold: 0.85
  piguard_enabled: true
  piguard_model: "leolee99/PIGuard"
  piguard_threshold: 0.85
  operating_point: "balanced"
```

## Per-Category Detection Rates

The benchmark reports per-category breakdowns:

- **Direct injection**: highest detection rate (regex + ML agreement)
- **Encoding evasion**: tests Base64/ROT13/Unicode obfuscation
- **Indirect injection**: BIPIA-style attacks embedded in data
- **Jailbreak**: DAN-style and role-play bypass attempts
- **Transfer attacks**: cross-model adversarial examples
- **Edge cases**: boundary conditions (very short, very long, buried payloads)
- **Over-defense**: NotInject difficulty-stratified false positive testing

## Raw Data

Full results including per-sample classifications are available in `benchmarks/results/proxy_stress_test_v2.json`. The `benchmarks/` directory also contains the test datasets and analysis scripts.
