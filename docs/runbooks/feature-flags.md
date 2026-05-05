# Runtime Feature Flags (issue #42) — Operator Runbook

The runtime feature-flag admin API at `/api/v1/config/features` lets an
operator toggle analyser behaviour, enforcement mode, rate limiting,
cost caps, and ensemble tuning without restarting the proxy. This
runbook covers the four operational failure modes flagged in the
review of PR #64.

All flag values are persisted to a sidecar `config.runtime.yaml` and
reapplied at startup. Base `config.yaml` is never modified. The full
precedence order (highest wins) is **CLI flags > environment variables
> sidecar overlay > base config file > built-in defaults**.

## "Runtime overlay didn't persist"

**Symptom**: a PUT to `/api/v1/config/features[/…]` returns `200 OK`
but the response `warnings` array includes
`"runtime overlay persistence failed: …; change applied in memory only"`.
After a pod restart the change is gone.

**Cause**: the filesystem location the proxy tried to write
(`config.runtime.yaml` next to `--config`, or the path from
`--runtime-config` / `LLMTRACE_RUNTIME_CONFIG`) is not writable. The
typical trigger under Kubernetes is a read-only ConfigMap mount at
`/etc/llmtrace/` inheriting to the runtime overlay path.

**Diagnosis**:

```bash
# Confirm the proxy saw the same symptom at startup:
kubectl logs deploy/llmtrace-proxy | grep 'Runtime feature-flag overlay path is not writable'

# Inspect /health for the cached probe result:
curl -s http://llmtrace:8080/health | jq '.runtime_overlay'
# {
#   "status": "not_writable",
#   "persistence": false,
#   "writable": false,
#   "reason": "runtime overlay parent /etc/llmtrace is not writable: Read-only file system (os error 30)"
# }

# Verify the error counter:
curl -s http://llmtrace:8080/metrics | grep llmtrace_config_persist_errors_total
```

**Remediation**:

- Mount a writable volume at the runtime overlay parent directory —
   `emptyDir` works for single-replica pods; a `PersistentVolumeClaim`
   is required for multi-replica stability.
- Point `--runtime-config` / `LLMTRACE_RUNTIME_CONFIG` at a location
   inside that volume (for example `/var/lib/llmtrace/config.runtime.yaml`)
   so the derived path does not inherit the ConfigMap mount.
- Redeploy. Confirm `/health` now reports `"status": "writable"` and
   `llmtrace_config_persist_errors_total` stops incrementing on new
   PUTs.

## "`analyzer_ml_enabled` flip did nothing"

**Symptom**: a PUT flipping `analyzer_ml_enabled`, `analyzer_injecguard_enabled`,
`analyzer_piguard_enabled`, `operating_point`, or `over_defence` from
their startup state to `true` returns `200 OK`, but live traffic shows
no behaviour change. The PUT response `warnings` array includes
`"flag 'X' is inert: the backing subsystem was not loaded at startup"`.

**Cause**: the ML-backed flags are gated at the ensemble voting site
by atomics, but the ensemble itself only constructs a model when
`config.security_analysis.*_enabled` is `true` at startup. Flipping
the atomic at runtime from an off-at-startup state is a documented
no-op — the model was never loaded.

**Diagnosis**:

```bash
# Read the live effective state:
curl -s http://llmtrace:8080/api/v1/config/features \
  -H 'Authorization: Bearer <admin-key>' \
  | jq '.effective'
# {
#   "analyzer_ml_enabled": false,    # inert on this deployment
#   "analyzer_injecguard_enabled": false,
#   ...
#   "enforcement_mode": true,        # HOT flags are always effective
#   "rate_limiting_enabled": true
# }

# Confirm ml_status on /health:
curl -s http://llmtrace:8080/health | jq '.ml'
```

**Remediation**:

- Edit the base `config.yaml` (or the Helm values) to enable the
   model at startup:
   ```yaml
   security_analysis:
     ml_enabled: true
     ml_preload: true
   ```
- Trigger a rolling restart. On the next startup the model loads and
   the runtime flag becomes truly hot-swappable.
- Re-issue the PUT. The `warnings` array should now be empty and
   `effective.analyzer_ml_enabled` should report `true`.

The same remediation applies to `analyzer_injecguard_enabled`,
`analyzer_piguard_enabled`, `operating_point`, and `over_defence`.
`analyzer_jailbreak_enabled`, `enforcement_mode`, `boundary_defense_*`,
`rate_limiting_enabled`, and `cost_caps_enabled` are always effective
— they never show the inert warning.

`llm_judge_enabled` is intentionally always inert until issue #43
lands the backend.

## "How do I reset all feature flags?"

**Symptom**: you want to revert every runtime flag to what
`config.yaml` says, discarding any PUTs made since startup.

**Remediation**:

```bash
# 1. Delete the sidecar overlay on every pod (use a DaemonSet or
#    exec loop if you run more than one replica):
kubectl exec deploy/llmtrace-proxy -- rm -f /var/lib/llmtrace/config.runtime.yaml

# 2. Rolling restart so the next startup skips the overlay load:
kubectl rollout restart deploy/llmtrace-proxy
```

Alternatively, PUT the known-good values back directly — use the
bulk endpoint for atomicity:

```bash
curl -X PUT http://llmtrace:8080/api/v1/config/features \
  -H 'Authorization: Bearer <admin-key>' \
  -H 'Content-Type: application/json' \
  --data @baseline-features.json
```

A dedicated `DELETE /api/v1/config/features` endpoint is tracked as a
follow-up; for now deletion plus restart is the supported flow.

## "CLI/ENV override is shadowing my PUT"

**Symptom**: a PUT succeeds and the sidecar file reflects the new
value, but after a pod restart the flag reverts to whatever the
operator set via `LLMTRACE_*` environment variables or `--<flag>`
CLI arguments.

**Cause**: the config precedence is **CLI > ENV > sidecar overlay >
base config**. Env and CLI layers are applied *after* the sidecar
overlay at startup, so they always win. Today no environment variable
in `config::apply_env_overrides` writes into a field exposed on the
feature-flag surface — the shadow-detection infrastructure is in place
(`FeatureFlagsView.overridden_by`) and will surface the shadow as soon
as such an env var is added.

**Diagnosis** (when the detection is wired in):

```bash
curl -s http://llmtrace:8080/api/v1/config/features \
  -H 'Authorization: Bearer <admin-key>' \
  | jq '.overridden_by'
# {
#   "enforcement_mode": "env",  # e.g. LLMTRACE_ENFORCEMENT_MODE=log
#   ...
# }
```

**Remediation**:

- Unset the shadowing env var or CLI arg in the Deployment /
   Helm values.
- Rolling restart. The next startup will honor the sidecar overlay.
- Confirm `overridden_by` is empty for the affected flag.

## "Flag flipped on one replica only" (multi-replica inconsistency)

**Symptom**: an admin PUT returns `200 OK`, but live traffic shows
intermittent behaviour — e.g. `enforcement_mode=block` is observed on
some requests and `log` on others, or a feature-flag state gauge in
Grafana shows different values per pod.

**Cause**: the runtime overlay is a **per-pod file**. `ConfigHandle`
is constructed once at process startup from the overlay that
**that pod** sees. An admin PUT hits exactly one pod (whichever the
Kubernetes Service load-balanced to), swaps that pod's in-memory
`Arc<ProxyConfig>`, and writes that pod's overlay file. Every other
replica still runs the config it started with.

Restart amplifies the drift: the pod that took the PUT restarts
against its own updated overlay; the N-1 pods that did not take the
PUT restart against whatever their overlay says (usually: the last
PUT *they* received, or the base `config.yaml` if they never received
one).

**Diagnosis**:

```bash
# 1. Scrape every pod individually through their Pod IPs or a
#    headless Service, and compare the feature-flag state gauge:
for pod in $(kubectl get pods -l app=llmtrace-proxy -o name); do
  echo "=== $pod ==="
  kubectl exec "$pod" -- curl -s localhost:8080/api/v1/config/features \
    -H "Authorization: Bearer $ADMIN_KEY" | jq '.values.enforcement_mode'
done

# 2. Or scrape each pod's metrics endpoint:
kubectl exec <pod> -- curl -s localhost:8080/metrics \
  | grep llmtrace_feature_flag_string_state
```

If the values diverge across pods, the PUT only landed on one pod.

**Remediation** — pick the pattern that matches your deployment:

- **Single-replica admin gate (recommended for dev/staging)**. Scale
   the deployment to 1 replica before running admin operations:

   ```bash
   kubectl scale deploy/llmtrace-proxy --replicas=1
   curl -X PUT ... /api/v1/config/features/enforcement_mode ...
   kubectl scale deploy/llmtrace-proxy --replicas=<original>
   ```

   The rolling restart after scaling back up pulls every new pod
   through the updated overlay (assuming the overlay volume is a
   writable PVC, not an emptyDir — emptyDir is per-pod and loses
   state).

**Fan-out via `kubectl exec`**: (works with default chart). Loop

   over all pods and issue the PUT against each pod's localhost
   endpoint, using the authentication key mounted in-pod:

   ```bash
   ADMIN_KEY=$(kubectl get secret llmtrace-admin-key -o jsonpath='{.data.key}' | base64 -d)
   for pod in $(kubectl get pods -l app=llmtrace-proxy -o name); do
     kubectl exec "$pod" -- curl -sS -X PUT \
       http://localhost:8080/api/v1/config/features/enforcement_mode \
       -H "Authorization: Bearer $ADMIN_KEY" \
       -H "Content-Type: application/json" \
       -d '{"value":"block"}' || echo "FAILED on $pod"
   done
   ```

   Each pod independently writes its own overlay and swaps its own
   `ConfigHandle`. Verify with the diagnosis loop above. This is the
   supported pattern as of PR #64; a control-plane broadcast is
   tracked as a follow-up.

**Shared overlay via ReadWriteMany PVC**: (single-writer required).

   Mount a shared PVC at the runtime overlay parent, with
   `accessMode: ReadWriteMany`. Every pod reads and writes the same
   `config.runtime.yaml`. Only one pod should PUT at a time — the
   API is already serialized by `ConfigHandle`'s writer mutex per
   pod, but *cross-pod* concurrent PUTs can still race on the file
   rename. Use a PodDisruptionBudget of `maxUnavailable: 1` and an
   application-layer lock (Redis distributed lock, etcd lease) if
   you need tighter guarantees.

   This pattern is **not yet wired into the default Helm chart** —
   that is issue #42 follow-up. Use pattern 1 or 2 until the chart
   lands.

**Invariants the runbook cannot hide**:

- `llm_judge_enabled`, `analyzer_*_enabled` remain subject to the
  inert-flag rules in section 2. Multi-replica consistency is an
  additional failure mode, not a replacement for them.
- `listen_addr`, `grpc.enabled`, `storage.profile`, and other
  **startup-only** settings are unaffected by the feature-flag
  admin API and only change via a base config rollout.

## See also

- Issue tracking this surface: [#42](https://github.com/epappas/llmtrace/issues/42)
- Future LLM Judge backend: [#43](https://github.com/epappas/llmtrace/issues/43)
- Prometheus metrics:
  `llmtrace_feature_flag_updates_total{feature}`,
  `llmtrace_feature_flag_bool_state{feature}`,
  `llmtrace_feature_flag_string_state{feature,value}`,
  `llmtrace_config_persist_errors_total`,
  `llmtrace_audit_event_dropped_total{event_type}`
- Audit events: query `AuditEvent` where
  `event_type = "feature_flag_changed"`.
- `/health` surface: `runtime_overlay.status` is `disabled |
  writable | not_writable`. On failure, `reason_code` is one of
  `read_only_filesystem | permission_denied | parent_missing |
  unknown` — the raw filesystem error is logged server-side at
  startup and never exposed to the unauthenticated endpoint
  (issue #42 C1).
