# Pre-Request Enforcement Guide

By default, LLMTrace analyzes requests **asynchronously after forwarding** them to the upstream provider. The enforcement feature adds **synchronous pre-request analysis** that can block or flag requests before they reach the LLM.

## Enforcement Modes

### `log` (default)

No enforcement. Requests are forwarded immediately. Security analysis happens asynchronously. This is the default behavior when the `enforcement` section is omitted from config.

### `block`

Requests that trigger enforcement criteria receive a `403 Forbidden` response and are **not forwarded** to the upstream provider.

Response body:
```json
{
  "error": {
    "message": "Request blocked due to security policy violation",
    "type": "security_violation",
    "code": "prompt_injection_detected",
    "details": {
      "finding_type": "prompt_injection",
      "severity": "high",
      "description": "System prompt override attempt detected"
    }
  }
}
```

### `flag`

Requests are forwarded to the upstream provider, but finding metadata is attached as response headers:

- `X-LLMTrace-Flagged: true`
- `X-LLMTrace-Finding-Type: prompt_injection`
- `X-LLMTrace-Severity: high`

Your application can inspect these headers and take action (e.g., log, alert, suppress the response).

## Configuration

```yaml
enforcement:
  mode: "block"              # "log" | "block" | "flag"
  analysis_depth: "fast"     # "fast" | "full"
  min_severity: "high"       # minimum severity to enforce
  min_confidence: 0.8        # minimum confidence to enforce (0.0-1.0)
  timeout_ms: 2000           # fail-open on timeout
  categories:                # per-finding-type overrides
    - finding_type: "prompt_injection"
      action: "block"
    - finding_type: "shell_injection"
      action: "block"
    - finding_type: "data_leakage"
      action: "log"
```

## Analysis Depth

### `fast`

Runs regex-only analysis. Near-zero added latency (microseconds). Catches known patterns but misses novel attacks.

### `full`

Runs the full ensemble (regex + ML models). Adds ML inference latency (typically 50-200ms depending on model count and hardware). Better detection coverage.

```yaml
enforcement:
  analysis_depth: "full"
```

Use `full` when you need ML-quality detection for blocking decisions. Use `fast` when latency is critical and regex coverage is sufficient.

## Severity and Confidence Gates

Enforcement only triggers when a finding meets **both** the minimum severity and minimum confidence:

```yaml
enforcement:
  min_severity: "high"     # info | low | medium | high | critical
  min_confidence: 0.8      # 0.0 to 1.0
```

A finding with `severity: medium` and `confidence: 0.95` will **not** trigger enforcement if `min_severity` is `high`.

Defaults:
- `min_severity`: `high`
- `min_confidence`: `0.8`

## Timeout and Fail-Open

If enforcement analysis exceeds `timeout_ms`, the request is **forwarded without enforcement** (fail-open):

```yaml
enforcement:
  timeout_ms: 2000  # 2 seconds, then fail-open
```

Default: 2000ms. This prevents enforcement from becoming a reliability bottleneck.

## Per-Category Overrides

Override the enforcement action for specific finding types:

```yaml
enforcement:
  mode: "flag"               # default action for all categories
  categories:
    - finding_type: "prompt_injection"
      action: "block"        # override: block injections
    - finding_type: "shell_injection"
      action: "block"        # override: block shell injection
    - finding_type: "pii_detected"
      action: "flag"         # flag PII but don't block
    - finding_type: "data_leakage"
      action: "log"          # just log data leakage
```

The `categories` list takes precedence over the top-level `mode`. Finding types not listed fall back to the top-level `mode`.

## Example Configurations

### Block injections, log everything else

```yaml
enforcement:
  mode: "log"
  analysis_depth: "fast"
  min_severity: "high"
  min_confidence: 0.8
  categories:
    - finding_type: "prompt_injection"
      action: "block"
    - finding_type: "role_injection"
      action: "block"
    - finding_type: "shell_injection"
      action: "block"
```

### Full ML enforcement with strict thresholds

```yaml
enforcement:
  mode: "block"
  analysis_depth: "full"
  min_severity: "medium"
  min_confidence: 0.9
  timeout_ms: 5000
```

### Flag everything for monitoring (no blocking)

```yaml
enforcement:
  mode: "flag"
  analysis_depth: "fast"
  min_severity: "low"
  min_confidence: 0.5
```

## Interaction with Async Analysis

Enforcement runs **before** the request is forwarded. The standard async analysis pipeline still runs **after** the response, regardless of enforcement settings. This means:

- Enforcement findings may appear in the security findings API before async analysis findings
- A request blocked by enforcement will still have its content analyzed asynchronously for audit/logging purposes
- The async pipeline uses the full ensemble regardless of the enforcement `analysis_depth` setting
