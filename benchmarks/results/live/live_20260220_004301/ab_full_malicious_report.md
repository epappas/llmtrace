# A/B Performance Report: Direct vs LLMTrace Proxy

- Run ID: `live_20260220_004301`
- Generated: `2026-02-20T09:53:01.684317`
- Dataset: all malicious prompts from `benchmarks/datasets/**/*.json`
- Samples: **8480**
- Authentication: proxy requests used bearer token

## Non-Stream Summary

| Metric | Direct | Proxy |
|---|---:|---:|
| requests | 8480 | 8480 |
| ok | 8480 | 8480 |
| errors | 0 | 0 |
| mean_ms | 4269.48 | 9522.70 |
| p50_ms | 4174.71 | 3854.52 |
| p95_ms | 5796.73 | 20182.57 |
| p99_ms | 5996.06 | 24075.16 |
| max_ms | 7248.66 | 37251.77 |
| avg_total_tokens | 168.75 | 168.65 |

## Same-Prompt Delta (Proxy - Direct)

- Paired rows: **8480**
- Successful paired rows: **8480**
- Mean delta: **5253.22 ms**
- P50 delta: **-7.64 ms**
- P95 delta: **16197.56 ms**
- P99 delta: **19142.46 ms**
- Proxy faster rows: **4284**
- Proxy slower rows: **4196**
- Same rows: **0**

## Runtime
- Proxy concurrency: **12**
- Proxy timeout: **35 s**
- Proxy duration: **6730.9 s**

## Artifacts
- `benchmarks/results/live/live_20260220_004301/direct_full_malicious_rows.json`
- `benchmarks/results/live/live_20260220_004301/proxy_full_malicious_rows.json`
- `benchmarks/results/live/live_20260220_004301/proxy_run_meta.json`
- `benchmarks/results/live/live_20260220_004301/ab_full_malicious_summary.json`