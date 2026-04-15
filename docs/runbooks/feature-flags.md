# Runtime Feature Flags (issue #42) — Operator Runbook

The runtime feature-flag admin API at `/api/v1/config/features` lets an
operator toggle analyzer behavior, enforcement mode, rate limiting,
cost caps, and ensemble tuning without restarting the proxy. This
runbook covers the four operational failure modes flagged in the
review of PR #64.

All flag values are persisted to a sidecar `config.runtime.yaml` and
reapplied at startup. Base `config.yaml` is never modified. The full
precedence order (highest wins) is **CLI flags > environment variables
> sidecar overlay > base config file > built-in defaults**.

## 1. "Runtime overlay didn't persist"

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

1. Mount a writable volume at the runtime overlay parent directory —
   `emptyDir` works for single-replica pods; a `PersistentVolumeClaim`
   is required for multi-replica stability.
2. Point `--runtime-config` / `LLMTRACE_RUNTIME_CONFIG` at a location
   inside that volume (for example `/var/lib/llmtrace/config.runtime.yaml`)
   so the derived path does not inherit the ConfigMap mount.
3. Redeploy. Confirm `/health` now reports `"status": "writable"` and
   `llmtrace_config_persist_errors_total` stops incrementing on new
   PUTs.

## 2. "`analyzer_ml_enabled` flip did nothing"

**Symptom**: a PUT flipping `analyzer_ml_enabled`, `analyzer_injecguard_enabled`,
`analyzer_piguard_enabled`, `operating_point`, or `over_defence` from
their startup state to `true` returns `200 OK`, but live traffic shows
no behavior change. The PUT response `warnings` array includes
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

1. Edit the base `config.yaml` (or the Helm values) to enable the
   model at startup:
   ```yaml
   security_analysis:
     ml_enabled: true
     ml_preload: true
   ```
2. Trigger a rolling restart. On the next startup the model loads and
   the runtime flag becomes truly hot-swappable.
3. Re-issue the PUT. The `warnings` array should now be empty and
   `effective.analyzer_ml_enabled` should report `true`.

The same remediation applies to `analyzer_injecguard_enabled`,
`analyzer_piguard_enabled`, `operating_point`, and `over_defence`.
`analyzer_jailbreak_enabled`, `enforcement_mode`, `boundary_defense_*`,
`rate_limiting_enabled`, and `cost_caps_enabled` are always effective
— they never show the inert warning.

`llm_judge_enabled` is intentionally always inert until issue #43
lands the backend.

## 3. "How do I reset all feature flags?"

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

## 4. "CLI/ENV override is shadowing my PUT"

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

1. Unset the shadowing env var or CLI arg in the Deployment /
   Helm values.
2. Rolling restart. The next startup will honor the sidecar overlay.
3. Confirm `overridden_by` is empty for the affected flag.

## See also

- Issue tracking this surface: [#42](https://github.com/epappas/llmtrace/issues/42)
- Future LLM Judge backend: [#43](https://github.com/epappas/llmtrace/issues/43)
- Prometheus metrics:
  `llmtrace_feature_flag_updates_total{feature}`,
  `llmtrace_feature_flag_bool_state{feature}`,
  `llmtrace_feature_flag_string_state{feature,value}`,
  `llmtrace_config_persist_errors_total`
- Audit events: query `AuditEvent` where
  `event_type = "feature_flag_changed"`.
