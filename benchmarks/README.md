# LLMTrace Security Benchmarks

Evaluation suite for LLMTrace's prompt injection detection pipeline.

## Current Results

| Metric    | Value |
|-----------|-------|
| Accuracy  | 87.6% |
| Precision | 95.5% |
| Recall    | 79.7% |
| F1 Score  | 86.9% |

**Confusion matrix:** TP=63, TN=71, FP=3, FN=16 (n=153)

## Methodology

The stress test sends a 153-sample corpus (79 malicious, 74 benign) through the live proxy, waits for async security analysis to complete, then matches stored findings back to each sample. A sample is "flagged" if its `security_score >= 50`.

The corpus is randomly sampled (seed=42) from internal and external datasets, stratified across attack categories and difficulty levels.

## Dataset Sources

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
| Edge cases | 4 | Synthetic boundary tests (short, buried, delimiter, translation) |

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
| Edge cases | 4 | Synthetic benign boundary tests (short, long, Unicode, security research) |

## How to Run

### Prerequisites

- LLMTrace proxy running on port 8080 with `--config config.yaml`
- ClickHouse running on port 8123
- `OPENAI_API_KEY` environment variable set
- Python 3.10+ with `requests` package

### Steps

```bash
# 1. Start the proxy (with ML models enabled)
RUST_LOG=info ./target/release/llmtrace-proxy --config config.yaml

# 2. Run the stress test
cd benchmarks
python3 scripts/proxy_stress_test_v2.py
```

Results are saved to `results/proxy_stress_test_v2.json`.

### Configuration

The proxy must be started with `config.yaml` to enable the full security pipeline:
- DeBERTa ML model (`protectai/deberta-v3-base-prompt-injection-v2`)
- Jailbreak detection
- InjecGuard and PIGuard models
- Balanced operating point

## Per-Category Detection

The test reports per-category accuracy breakdowns:

- **Direct injection** — highest detection rate (regex + ML agreement)
- **Encoding evasion** — tests Base64/ROT13/Unicode obfuscation
- **Indirect injection** — BIPIA-style attacks embedded in data
- **Jailbreak** — DAN-style and role-play bypass attempts
- **Transfer attacks** — cross-model adversarial examples
- **Edge cases** — boundary conditions (very short, very long, buried payloads)
- **Over-defense** — NotInject difficulty-stratified false positive testing

## Directory Structure

```
benchmarks/
  datasets/           # Internal test datasets
    external/         # Third-party dataset samples
  results/            # Test run outputs (JSON)
  scripts/            # Test runner scripts
    proxy_stress_test_v2.py  # Main stress test
  analysis/           # Analysis notebooks and scripts
```
