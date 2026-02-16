# Troubleshooting

Common issues and diagnostic steps for LLMTrace.

## Proxy Won't Start

### Config file errors

```
Error: Failed to parse config file
```

Validate your YAML syntax. The proxy requires a valid config file:

```bash
./target/release/llmtrace-proxy --config config.yaml
```

Common config mistakes:
- Indentation errors in YAML
- Missing required `upstream_url` field
- Invalid storage profile name (valid: `lite`, `production`, `memory`)

### Port already in use

```
Error: Address already in use (os error 98)
```

Another process is using port 8080. Find and stop it:

```bash
lsof -i :8080
kill <PID>
```

Or change the listen address in config:

```yaml
listen_addr: "0.0.0.0:9090"
```

### ML model download failures

```
Error: Failed to download model
```

The proxy downloads ML models from Hugging Face Hub on first startup. If this fails:

1. Check internet connectivity
2. Increase the download timeout:
   ```yaml
   security_analysis:
     ml_download_timeout_seconds: 1200
   ```
3. Pre-download models and set the cache directory (see [ML Model Reference](../ml/models.md#offline--air-gapped-usage))
4. Disable ML to run regex-only:
   ```yaml
   security_analysis:
     ml_enabled: false
   ```

## Connection Refused / Timeouts

### Proxy not reachable

```bash
# Verify the proxy is running and listening
curl http://localhost:8080/health
```

If connection refused:
- Confirm the proxy process is running
- Check `listen_addr` in config matches the URL you're hitting
- If running in Docker, ensure port mapping (`-p 8080:8080`)

### Upstream provider timeouts

If requests to the LLM provider time out, increase timeouts:

```yaml
timeout_ms: 60000              # request timeout
connection_timeout_ms: 10000   # connection timeout
```

## Security Findings Not Appearing

### Async analysis delay

Security analysis runs asynchronously after the response is forwarded. Findings may take 1-5 seconds to appear after the request completes.

```bash
# Wait briefly, then check findings
sleep 3
curl http://localhost:8080/api/v1/security/findings | jq
```

### Storage not configured

If `enable_trace_storage: false` or no storage backend is configured, findings are analyzed but not persisted.

```yaml
enable_security_analysis: true
enable_trace_storage: true

storage:
  profile: "lite"
  database_path: "llmtrace.db"
```

### ML not compiled in

If you built without `--features ml`, only regex detection is active:

```bash
cargo build --release --features ml
```

## False Positives

Benign requests flagged as threats.

### Quick fixes

1. **Switch to a higher-precision operating point**:
   ```yaml
   security_analysis:
     operating_point: "high_precision"
   ```

2. **Enable over-defence suppression**:
   ```yaml
   security_analysis:
     over_defence: true
   ```

3. **Raise the per-model threshold**:
   ```yaml
   security_analysis:
     ml_threshold: 0.9
   ```

See [Threshold Tuning](../ml/tuning.md) for a detailed tuning workflow.

## False Negatives

Known attacks not being detected.

### Quick fixes

1. **Enable additional detectors**:
   ```yaml
   security_analysis:
     ml_enabled: true
     injecguard_enabled: true
     piguard_enabled: true
   ```

2. **Switch to high-recall operating point**:
   ```yaml
   security_analysis:
     operating_point: "high_recall"
   ```

3. **Lower per-model thresholds**:
   ```yaml
   security_analysis:
     ml_threshold: 0.7
     injecguard_threshold: 0.75
   ```

## Rate Limiting / Cost Cap Errors

### 429 Too Many Requests

The proxy's rate limiter is rejecting requests. Adjust limits in config:

```yaml
rate_limiting:
  enabled: true
  requests_per_second: 200   # increase limit
  burst_size: 400
```

### Budget exceeded

If cost caps are configured and exceeded, the proxy returns a budget error. Check current spend:

```bash
curl http://localhost:8080/api/v1/costs/current | jq
```

## Streaming Issues

### SSE not working

Ensure streaming is enabled in config:

```yaml
enable_streaming: true

streaming_analysis:
  enabled: true
  token_interval: 50
  output_enabled: true
```

Use `-N` flag with curl to disable buffering:

```bash
curl -N http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

## Storage Connectivity

### ClickHouse

```bash
# Test ClickHouse connectivity
curl http://localhost:8123/ping
```

Verify the URL in config:

```yaml
storage:
  profile: "production"
  clickhouse_url: "http://localhost:8123"
  clickhouse_database: "llmtrace"
```

### PostgreSQL

```bash
# Test PostgreSQL connectivity
psql "postgres://llmtrace:llmtrace@localhost:5432/llmtrace" -c "SELECT 1"
```

### Redis

```bash
# Test Redis connectivity
redis-cli ping
```

## Dashboard Not Loading

### Proxy URL configuration

The dashboard needs to connect to the proxy API. Verify the proxy URL is correct in the dashboard settings page, or set the environment variable:

```bash
NEXT_PUBLIC_PROXY_URL=http://localhost:8080 npm run dev
```

### CORS errors

The proxy enables CORS by default. If you see CORS errors in the browser console, ensure the proxy is running and reachable from the browser's network.

## Diagnostic Commands

### Health check

```bash
curl http://localhost:8080/health | jq
```

Returns proxy status, storage connectivity, circuit breaker state, and ML model status.

### Prometheus metrics

```bash
curl http://localhost:8080/metrics
```

Returns request counts, latency histograms, error rates, and circuit breaker state in Prometheus exposition format.

### Log levels

Increase log verbosity for debugging:

```bash
RUST_LOG=debug ./target/release/llmtrace-proxy --config config.yaml
```

Available levels: `error`, `warn`, `info`, `debug`, `trace`.

For production, use structured JSON logs:

```yaml
logging:
  level: "info"
  format: "json"
```
