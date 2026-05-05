# Judge Golden-Set Drift — Operator Runbook

This runbook covers the three alerts emitted by the LLMTrace Helm chart's PrometheusRule for the **judge golden-set calibration loop** (issue [#66][66]):

| Alert | Triggers when | Severity |
|---|---|---|
| `LLMTraceJudgeGoldenSetAlignmentDrift` | per-category alignment < 0.85 for 15 min | warning |
| `LLMTraceJudgeGoldenSetFprDrift` | per-category false-positive rate > 0.25 for 15 min | warning |
| `LLMTraceJudgeGoldenSetReplayStale` | gauges not updated in 24h | warning |

[66]: https://github.com/epappas/llmtrace/issues/66

## Background

The **golden set** (`crates/llmtrace-security/fixtures/judge_golden_set/`) is a small, hand-curated corpus where every entry is a known-good or known-bad example we expect the security analyzer to agree with deterministically. Drift in the fast tier (regex / DeBERTa) shows up here first, before it shows up in production findings counts or in the much-noisier full benchmark corpora.

The endpoint `GET /debug/judge/golden_set/replay` (see [E2E testing guide](../guides/e2e-testing.md#get-debugjudgegoldenset-replay)) loads every fixture, runs each prompt through the configured `state.security` analyzer, and updates two Prometheus gauges:

- `llmtrace_judge_golden_set_alignment{category=...}` — fraction of `is_threat=true` fixtures the analyzer flagged
- `llmtrace_judge_golden_set_false_positive_rate{category=...}` — fraction of `is_threat=false` fixtures the analyzer flagged

The PrometheusRule alerts on these gauges. The alert thresholds (`0.85`, `0.25`) mirror the per-category floor / ceiling pinned in `crates/llmtrace-security/tests/judge_golden_set.rs::alignment_floor` and `false_positive_ceiling`. Keep them in sync.


## `LLMTraceJudgeGoldenSetAlignmentDrift`

**Symptom**: Alignment for at least one category dropped below 0.85.

**Most common causes** (in order of frequency):

**Detector tier weakened**: — a recent regex change, a new DeBERTa weight rev, or a feature-flag flip relaxed the fast tier. The golden set is now flagging fewer of the prompts it used to catch.


**Corpus drift**: — somebody added new fixtures the fast tier doesn't yet cover. Expected during initial corpus growth; not expected once a category is stable.


**Stale gauge**: — the replay endpoint hasn't run in a while and the gauge reflects an old run when the corpus was different. Confirm with `LLMTraceJudgeGoldenSetReplayStale`.


### Diagnose

```bash
# Identify the failing category from the alert.
PROXY=https://proxy.example.com   # or kubectl port-forward
curl -s "${PROXY}/debug/judge/golden_set/replay" | jq .

# The response includes per-category alignment + a list of disagreeing fixture ids:
# {
#   "categories": [
#     {"category": "jailbreak", "n_threats": 8, "agreed": 6, "alignment_rate": 0.75, ...}
#   ],
#   "disagreement_ids": ["gs-jb-003", "gs-jb-005"]
# }
```

Then re-run the offending fixtures locally against the analyzer to confirm:

```bash
cargo test -p llmtrace-security --test judge_golden_set -- --nocapture 2>&1 \
  | grep "\[golden_set\]"
# [golden_set] category=jailbreak n=8 agreed=6 rate=0.750 floor=0.850
```

Read the disagreement-ids' fixture files (`crates/llmtrace-security/fixtures/judge_golden_set/<category>/<id>.json`) — each carries a `rationale` field documenting why the prompt is in the corpus.

### Mitigate

**If a recent regex / model change is the cause**: revert or refine the change. The golden-set is the calibration check the change should have passed in CI; that it didn't means the floor is too loose or the test was bypassed.


**If new fixtures expose a real gap**: tighten the regex / retrain the ML tier to cover the gap, then re-run the replay endpoint to clear the alert. **Do not lower the alignment floor** without a documented rationale in the PR — the floor is the contract.


**If the gauge is stale**: see section 3.



## `LLMTraceJudgeGoldenSetFprDrift`

**Symptom**: False-positive rate against benign fixtures exceeded 0.25 for 15 min.

**Most common causes**:

**Detector tier tightened**: — a regex was widened or an ML threshold lowered, and the analyzer now flags benign content.


**Benign-fixture corpus extended**: — somebody added benign fixtures that resemble attacks (e.g. legitimate questions about security). The detector legitimately can't distinguish without more context.


### Diagnose

```bash
curl -s "${PROXY}/debug/judge/golden_set/replay" | jq '.categories[] | {category, false_positive_rate, false_positives, n_benign}'
```

The disagreement-ids list includes both *missed threats* AND *false positives*; cross-reference with `is_threat=false` in the fixture JSON to find the false positives.

### Mitigate

**If a regex was over-widened**: tighten or add a context-sensitive guard.


**If a new benign fixture is genuinely ambiguous**: that's the calibration loop's purpose. Either (a) split the fixture into clearly-benign and clearly-attack variants, (b) raise the ceiling above 0.25 with a documented PR rationale, or (c) move the fixture to the `over_defense` category where higher FPR is expected.



## `LLMTraceJudgeGoldenSetReplayStale`

**Symptom**: the replay endpoint has not updated the alignment gauges in over 24 hours.

**Most common causes**:

**Nightly CronJob is failing**: — check Kubernetes job status.


**`LLMTRACE_GOLDEN_SET_PATH` is unset**: on the running proxy — the endpoint returns 503 and the gauges never update.


**`server.debug_endpoints: false`**: — the endpoint isn't even mounted in production. **Intentional** (debug routes return data un-auth-gated by trace_id; production must not enable them) — in that case run the replay against a staging proxy or a local instance and ship the alignment via a different metric pipeline.


### Diagnose

```bash
# 1. Check CronJob status (if you ship the recommended cron).
kubectl get cronjob -n llmtrace llmtrace-judge-golden-set-replay
kubectl logs -n llmtrace -l job-name=llmtrace-judge-golden-set-replay --tail=100

# 2. Hit the endpoint directly. A 503 tells you the env var is unset.
curl -i "${PROXY}/debug/judge/golden_set/replay"

# 3. Confirm the proxy was started with debug endpoints enabled.
kubectl exec -n llmtrace deploy/llmtrace-proxy -- \
  env | grep -E '^LLMTRACE_(GOLDEN_SET_PATH|DEBUG)'
# also check the running config:
kubectl exec -n llmtrace deploy/llmtrace-proxy -- \
  cat /etc/llmtrace/config.yaml | grep -A2 server:
```

### Mitigate

**If the CronJob failed**: triage the job log. Common failures are network / DNS issues hitting `/debug/...` or the proxy returning 503 because of (2) below.


**If `LLMTRACE_GOLDEN_SET_PATH` is unset**: set it via the Helm chart values (`extraEnv`) or the deployment spec. The path must point at a directory shipped alongside the binary — the recommended layout is to bake the fixtures into a sidecar ConfigMap or a baked-in image path like `/etc/llmtrace/golden_set/`.


**If `server.debug_endpoints: false` in production**: (the right default): silence this alert in production and run the replay loop in staging only. The drift question is *"is the analyzer drifting"* — that question doesn't need production data; the calibration corpus is the same everywhere.



## How the alerts are wired

The PrometheusRule lives in the LLMTrace Helm chart at `deployments/helm/llmtrace/templates/prometheusrule.yaml` and is gated on:

```yaml
monitoring:
  enabled: true
  prometheusRule:
    enabled: true
```

Alert thresholds in the Helm chart **must equal** the per-category floor / ceiling in the integration test (`crates/llmtrace-security/tests/judge_golden_set.rs`). When you change one, change the other in the same PR. The alerts have `runbook_url: https://docs.llmtrace.io/runbooks/judge-golden-set-drift/` so this page is reachable from the PagerDuty / Alertmanager UI.

## Recommended cron

The replay endpoint is intended to be invoked periodically (the gauges only update on call). Ship a Kubernetes CronJob alongside the Helm release:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: llmtrace-judge-golden-set-replay
spec:
  schedule: "*/30 * * * *"          # every 30 minutes
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: replay
              image: curlimages/curl:8.10.1
              args:
                - -fsS
                - http://llmtrace-proxy.llmtrace.svc.cluster.local/debug/judge/golden_set/replay
          restartPolicy: OnFailure
```

The 30-minute cadence is well below the 15-min `for:` window of the drift alerts and the 24h staleness window — a single failed run stays under the threshold; two consecutive failures trip `LLMTraceJudgeGoldenSetReplayStale`.


## Related

- Issue [#66 — Judge reliability patterns][66]
- E2E framework guide: [`docs/guides/e2e-testing.md`](../guides/e2e-testing.md)
- Integration test source: [`crates/llmtrace-security/tests/judge_golden_set.rs`](https://github.com/epappas/llmtrace/blob/main/crates/llmtrace-security/tests/judge_golden_set.rs)
- Loader / replay implementation: [`crates/llmtrace-security/src/golden_set.rs`](https://github.com/epappas/llmtrace/blob/main/crates/llmtrace-security/src/golden_set.rs)
- Endpoint handler: [`crates/llmtrace-proxy/src/debug.rs`](https://github.com/epappas/llmtrace/blob/main/crates/llmtrace-proxy/src/debug.rs)
