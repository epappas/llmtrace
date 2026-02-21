# A/B Performance Report: Direct vs LLMTrace Proxy

- Generated: 2026-02-20T00:48:15.367890
- Tenant: `today`
- Model: `glm-4.7-flash`
- Direct: `http://192.168.1.107:6969/v1/chat/completions`
- Proxy: `http://192.168.1.107:8080/v1/chat/completions` (authenticated bearer token)
- Dashboard: `http://192.168.1.107:8081`

## Dataset Scope
- Suite: `all`
- Label filter: `malicious`
- Total malicious prompts tested (full non-stream): **8480**
- Dataset files covered: **17**

## Non-Streaming A/B (Full Malicious Set)

| Metric | Direct | Proxy |
|---|---:|---:|
| requests | 8480 | 8480 |
| ok | 8480 | 199 |
| errors | 0 | 8281 |
| mean_ms | 6594.81 | 81951.94 |
| p50_ms | 6626.14 | 81908.12 |
| p95_ms | 8715.39 | 130816.29 |
| p99_ms | 9300.13 | 136785.85 |
| max_ms | 9954.06 | 140479.13 |

### Per-Prompt Delta (Proxy - Direct)
- Paired prompts: **8480**
- Paired success rows: **199**
- Mean delta: **77245.73 ms**
- P50 delta: **77166.87 ms**
- P95 delta: **126074.33 ms**
- P99 delta: **132045.60 ms**
- Proxy faster count: **0**
- Proxy slower count: **199**

## SSE A/B (Malicious Subset)
- SSE subset size: **300**
- Concurrency: **12**

| Metric | Direct SSE | Proxy SSE |
|---|---:|---:|
| requests | 300 | 300 |
| ok | 300 | 300 |
| errors | 0 | 0 |
| mean_ms | 5480.42 | 6720.87 |
| p50_ms | 5503.16 | 6263.00 |
| p95_ms | 5765.19 | 10394.27 |
| p99_ms | 5774.11 | 12698.84 |
| mean_ttft_ms | 341.57 | 283.70 |
| p50_ttft_ms | 330.13 | 261.63 |
| p95_ttft_ms | 524.35 | 381.47 |

## Notes
- Proxy requests were authenticated with the provided bearer token.
- SSE metrics report TTFT as time to first non-empty streamed line from the endpoint.
- Full per-prompt A/B rows are available in CSV/JSON artifacts for deep analysis.