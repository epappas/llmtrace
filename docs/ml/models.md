# ML Model Reference

LLMTrace uses an ensemble of ML models alongside regex-based pattern matching for prompt injection detection. Each model can be independently enabled or disabled in the configuration.

## DeBERTa v3

- **Model**: `protectai/deberta-v3-base-prompt-injection-v2`
- **Purpose**: Primary ML detector for prompt injection classification
- **Architecture**: DeBERTa v3 base fine-tuned on prompt injection datasets
- **License**: Apache 2.0
- **Input**: Raw text (role prefixes stripped before analysis)
- **Output**: Binary classification (injection / benign) with confidence score
- **Memory**: ~500MB

### Configuration

```yaml
security_analysis:
  ml_enabled: true
  ml_model: "protectai/deberta-v3-base-prompt-injection-v2"
  ml_threshold: 0.8       # confidence threshold (0.0-1.0)
  ml_cache_dir: "/root/.cache/huggingface/hub"
  ml_preload: true         # download model at startup
  ml_download_timeout_seconds: 600
```

## InjecGuard

- **Model**: `leolee99/InjecGuard`
- **Purpose**: Injection detection with reduced over-defence on benign security-related text
- **Specialization**: Better at distinguishing security research terminology from actual attacks
- **License**: See model card
- **Memory**: ~500MB

### Configuration

```yaml
security_analysis:
  injecguard_enabled: true
  injecguard_model: "leolee99/InjecGuard"
  injecguard_threshold: 0.85
```

## PIGuard

- **Model**: `leolee99/PIGuard`
- **Purpose**: Prompt injection guard with a focus on indirect injection detection
- **Specialization**: Indirect prompt injection embedded in data contexts
- **License**: See model card
- **Memory**: ~500MB

### Configuration

```yaml
security_analysis:
  piguard_enabled: true
  piguard_model: "leolee99/PIGuard"
  piguard_threshold: 0.85
```

## Jailbreak Detector

- **Purpose**: Detects jailbreak attempts (DAN-style, role-play bypasses, etc.)
- **Implementation**: Shares the DeBERTa inference pipeline with jailbreak-specific classification
- **Memory**: Shares model weights with DeBERTa

### Configuration

```yaml
security_analysis:
  jailbreak_enabled: true
  jailbreak_threshold: 0.7
```

## Model Download and Caching

Models are downloaded from Hugging Face Hub on first use. The download location is controlled by `ml_cache_dir`:

```yaml
security_analysis:
  ml_cache_dir: "/root/.cache/huggingface/hub"
  ml_preload: true
  ml_download_timeout_seconds: 600
```

- **`ml_preload: true`** (recommended): downloads all enabled models at proxy startup. The proxy blocks until models are ready.
- **`ml_preload: false`**: downloads models on first request. The first analysis will be slower.

### Offline / Air-Gapped Usage

For environments without internet access:

1. Download models on a machine with access:
   ```bash
   pip install huggingface_hub
   huggingface-cli download protectai/deberta-v3-base-prompt-injection-v2
   huggingface-cli download leolee99/InjecGuard
   huggingface-cli download leolee99/PIGuard
   ```

2. Copy the cache directory to the target machine.

3. Set `ml_cache_dir` to the copied path and `ml_preload: true`.

## Total Memory Footprint

With all models enabled, expect approximately 1.5-1.75 GB of RAM for model weights. The regex-only path uses negligible additional memory.

| Model | Approximate Size |
|-------|-----------------|
| DeBERTa v3 + jailbreak | ~500 MB |
| InjecGuard | ~500 MB |
| PIGuard | ~500 MB |
| Regex patterns | < 1 MB |

## Enabling/Disabling Models

Each model is independently toggled. A minimal config with only regex + DeBERTa:

```yaml
security_analysis:
  ml_enabled: true
  ml_threshold: 0.8
  jailbreak_enabled: true
  jailbreak_threshold: 0.7
  injecguard_enabled: false
  piguard_enabled: false
```

To run regex-only (no ML overhead):

```yaml
security_analysis:
  ml_enabled: false
  jailbreak_enabled: false
  injecguard_enabled: false
  piguard_enabled: false
```

## Build Requirement

ML models require the `ml` feature flag at compile time:

```bash
cargo build --release --features ml
```

Without `--features ml`, the proxy runs regex-only detection regardless of config settings.
