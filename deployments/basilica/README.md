# Basilica tenant lifecycle

Multi-tenant provisioning of LLMTrace pairs (proxy + dashboard) on
[Basilica](https://basilica.ai), triggered from your application via the GitHub
API. Each tenant gets their own pair of public URLs and runs LLMTrace with
their own upstream provider + API key, with no per-tenant config baked into the
platform.

## Status

End-to-end verified on 2026-05-17 against a live Basilica account:

| Step | Trigger | Outcome |
|---|---|---|
| Provision | `repository_dispatch` event_type=`tenant-lifecycle` with per-tenant `LLMTRACE_UPSTREAM_URL=https://generativelanguage.googleapis.com` + `OPENAI_API_KEY=sk-test-marker-...` in `tenant_secrets` | Proxy + dashboard ready in ~60s each; tenant-supplied upstream override took effect (proxy `/` returned Google's 404 HTML, not OpenAI's welcome JSON) |
| Status | direct CLI | matched live state |
| Deprovision | same dispatch path with `action=deprovision` + provisioned UUIDs | both deployments gone |

## Contents

```text
deployments/basilica/
├── README.md                # this file
├── lifecycle.py             # stateless Python library; wraps the Basilica SDK
├── cli.py                   # argparse wrapper; loads YAML/JSON config with ${VAR} substitution
├── __init__.py
├── configs/
│   └── examples/
│       ├── starter.yaml     # single-replica tier
│       └── pro.yaml         # multi-replica, datamarking active, debug logging
├── deploy.py                # legacy single-tenant operator script (kept for one-off ops)
├── deploy_dashboard.py      # ditto, dashboard
├── status.py                # ditto, status
├── teardown.py              # ditto, delete
└── .env.example             # template for the legacy scripts; not used by the lifecycle library
```

The new lifecycle library + CLI + workflow are the multi-tenant path. The
`deploy.py` / `deploy_dashboard.py` / `teardown.py` scripts predate this work
and remain as a single-tenant operator escape hatch.

## Architecture

Three layers, each a thin wrapper around the next:

1. **`lifecycle.py`** — stateless Python. `provision(spec) → InstanceInfo
   pair`, `update(spec, proxy_id, dashboard_id, strategy)`,
   `deprovision(tenant_id, proxy_id?, dashboard_id?)`, `status(...)`.
2. **`cli.py`** — argparse over the library. Loads YAML/JSON config from a
   file or inline JSON; runs `${VAR}` / `${VAR:-default}` substitution against
   process environment so secrets stay out of the config file.
3. **`.github/workflows/tenant-lifecycle.yml`** — accepts a tenant payload via
   `workflow_dispatch` (test) or `repository_dispatch` (production), masks any
   per-tenant secrets in step logs via `::add-mask::`, exports them into
   `GITHUB_ENV`, runs the CLI, returns UUIDs + URLs as step outputs.

### Why the library is stateless

The Basilica SDK addresses deployments **only by server-assigned UUID**. The
friendly name supplied at create time is accepted by the API but is not
echoed back on read (`DeploymentSummary` / `DeploymentResponse` expose
`instance_name` = the UUID, no `friendly_name` attribute), and
`get_deployment` accepts only UUIDs — passing a friendly name returns `404
Not found`.

Consequence: **identity lives in the caller's database**, not in Basilica and
not in the lifecycle library. After `provision`, your app stores `(tenant_id,
proxy_instance_id, dashboard_instance_id)` and passes the UUIDs back on every
subsequent lifecycle call.

## Quick start

### 1. One-time platform setup

You only do this once per repo:

- Add `BASILICA_API_TOKEN` as a repo secret:
  ```bash
  gh secret set BASILICA_API_TOKEN < ~/.basilica/token
  ```
- Confirm the proxy + dashboard container images are pullable from
  `ghcr.io/techlab-innov/llmtrace-{proxy,dashboard}` (they're built and pushed
  by `.github/workflows/publish-images.yml` on every push to main that
  touches `crates/`, `Dockerfile`, `dashboard/`, or
  `publish-images.yml` itself). GHCR packages must be public — see
  *Operational notes* below.
- (Optional but recommended) Add platform-wide fallback secrets that any
  tenant config can reference: `LLMTRACE_UPSTREAM_URL`, `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, `LLMTRACE_AUTH_ADMIN_KEY`. The tenant_secrets payload
  overrides these per-trigger.

### 2. Provision a tenant from your app (production path)

The calling app sends a `repository_dispatch` event. The payload is **not**
visible to anyone with `actions:read` (unlike `workflow_dispatch` inputs).

```bash
gh api -X POST /repos/techlab-innov/llmtrace/dispatches \
  --raw-field event_type=tenant-lifecycle \
  --raw-field 'client_payload={
    "tenant_id":"acme",
    "action":"provision",
    "config_path":"deployments/basilica/configs/examples/starter.yaml",
    "tenant_secrets":{
      "LLMTRACE_UPSTREAM_URL":"https://api.openai.com",
      "OPENAI_API_KEY":"sk-..."
    }
  }'
```

The workflow run will:

1. Mask each `tenant_secrets` value via `::add-mask::`.
2. Write them to `GITHUB_ENV` with a per-value random delimiter.
3. Run the CLI, which loads `starter.yaml` and resolves `${OPENAI_API_KEY}`
   and `${LLMTRACE_UPSTREAM_URL}` against the freshly-injected env.
4. Provision the deployment pair on Basilica.
5. Print result JSON to the step summary and expose the
   `proxy_instance_id`, `dashboard_instance_id`, `proxy_url`, `dashboard_url`
   as step outputs (consumable via the Actions API).

Your app reads the run's outputs and persists the UUIDs against `tenant_id`.

### 3. Subsequent lifecycle ops (still via repository_dispatch)

`status`:

```bash
gh api -X POST /repos/techlab-innov/llmtrace/dispatches \
  --raw-field event_type=tenant-lifecycle \
  --raw-field 'client_payload={
    "tenant_id":"acme","action":"status",
    "proxy_instance_id":"<uuid>","dashboard_instance_id":"<uuid>"
  }'
```

`update` (recreate — URL changes, new UUIDs):

```bash
gh api -X POST /repos/techlab-innov/llmtrace/dispatches \
  --raw-field event_type=tenant-lifecycle \
  --raw-field 'client_payload={
    "tenant_id":"acme","action":"update","strategy":"recreate",
    "proxy_instance_id":"<old>","dashboard_instance_id":"<old>",
    "config_path":"deployments/basilica/configs/examples/pro.yaml",
    "tenant_secrets":{"OPENAI_API_KEY":"sk-..."}
  }'
```

After recreate, the run output returns the **new** UUIDs — overwrite the
caller's DB with them.

`deprovision`:

```bash
gh api -X POST /repos/techlab-innov/llmtrace/dispatches \
  --raw-field event_type=tenant-lifecycle \
  --raw-field 'client_payload={
    "tenant_id":"acme","action":"deprovision",
    "proxy_instance_id":"<uuid>","dashboard_instance_id":"<uuid>"
  }'
```

## Tenant config format

YAML or JSON, two required top-level mappings: `proxy` and `dashboard`. Every
runtime knob is **required from the caller** — the library has no defaults
for image / port / CPU / memory / replicas / env. Probe and timeout fields
have structural defaults because they describe *how to wait*, not *what to
deploy*.

Minimal valid shape:

```yaml
proxy:
  image: ghcr.io/techlab-innov/llmtrace-proxy:latest
  port: 8080
  cpu: "2"
  memory: 4Gi
  replicas: 1
  env:
    LLMTRACE_UPSTREAM_URL: "${LLMTRACE_UPSTREAM_URL}"   # resolved at deploy time

dashboard:
  image: ghcr.io/techlab-innov/llmtrace-dashboard:latest
  port: 3000
  cpu: "1"
  memory: 1Gi
  replicas: 1
  env: {}
```

Optional top-level fields:

| Field | Default | Purpose |
|---|---|---|
| `proxy_name_template` | `"llmtrace-proxy-{tenant_id}"` | Friendly name passed to Basilica on create. Only visible in Basilica's UI/billing |
| `dashboard_name_template` | `"llmtrace-dashboard-{tenant_id}"` | Same for dashboard |
| `inject_proxy_url_into_dashboard` | `true` | If true, the resolved proxy URL is auto-injected into the dashboard's env after the proxy is up |
| `proxy_url_env_var` | `"LLMTRACE_PROXY_URL"` | Which env var to inject the proxy URL under |
| `rate_limit` | unset | Optional per-tenant rate-limit override surfaced to the proxy as env vars (see below) |

Optional per-component fields (override the defaults shown):

| Field | Default | Purpose |
|---|---|---|
| `health_check_path` | `/health` | Path probed by Basilica liveness/readiness |
| `startup_timeout_seconds` | `600` | How long `provision` will wait for the deployment to become ready before timing out |
| `startup_initial_delay_seconds` | `30` | Wait before first startup probe |
| `startup_period_seconds` | `30` | Startup probe interval |
| `startup_failure_threshold` | `15` | Startup probe failures before declaring failed |
| `liveness_period_seconds` | `30` | Liveness probe interval after startup |
| `liveness_failure_threshold` | `3` | Liveness probe failures before restart |
| `readiness_period_seconds` | `10` | Readiness probe interval |
| `readiness_failure_threshold` | `3` | Readiness probe failures before removing from service |

### Per-tenant `rate_limit`

Optional top-level block. When present, the lifecycle library injects two
env vars into the proxy's `ComponentSpec` at `provision()` and
`update(..., strategy="recreate")` time:

| Env var | Source | Effect on the proxy |
|---|---|---|
| `LLMTRACE_RATE_LIMIT_RPS` | `rate_limit.requests_per_second` | Overrides `rate_limiting.requests_per_second` (default 100) |
| `LLMTRACE_RATE_LIMIT_BURST` | `rate_limit.burst_size` | Overrides `rate_limiting.burst_size` (default 200) |

Shape:

```yaml
rate_limit:
  requests_per_second: 50   # strictly > 0
  burst_size: 100           # strictly > 0
```

Behaviour:

- Both fields are **required when the block is present** and must be
  strictly positive — `RateLimitSpec.__post_init__` raises `ValueError`
  otherwise.
- The injected env vars **override** any same-named values the caller
  put in `proxy.env` (same precedence as the auth-key injection).
- On the proxy side, `LLMTRACE_RATE_LIMIT_RPS`/`_BURST` are parsed in
  `crates/llmtrace-proxy/src/config.rs::apply_env_overrides`. Non-positive
  or unparseable values are silently ignored so a typo cannot disable
  rate limiting wholesale.
- Omit the block to keep the proxy's built-in `RateLimitConfig::default()`
  (100 rps / 200 burst). Per-tenant `tenant_overrides` set via
  `RateLimitConfig::tenant_overrides` in the proxy's YAML are unaffected.

### Request body cap

The proxy enforces a hard request body cap before any handler executes
(see `crates/llmtrace-proxy/src/main.rs::resolve_max_request_bytes`).
The cap protects downstream ML detectors and the trace pipeline from
a single oversized payload.

- Default: **1 MiB** (1,048,576 bytes).
- Configurable per-deployment via the `LLMTRACE_MAX_REQUEST_BYTES` env
  var. Invalid / non-positive values fall back to the default — set this
  in your tenant's `proxy.env` if you need a different cap.
- Requests over the cap are rejected with HTTP `413 Payload Too Large`
  when the `Content-Length` header is honest. Chunked / streamed bodies
  that exceed the cap are aborted mid-stream and surface as `400 Bad
  Request` from the proxy handler.

### `${VAR}` substitution

In any string value (env values, image tags, URLs):

- `${VAR}` — required. If the env var is not set at CLI load time, the CLI
  errors out with `KeyError: env var 'VAR' required by config is not set`.
- `${VAR:-default}` — optional with fallback. If the env var is not set, uses
  `default` (which may be empty).

Substitution happens **once at CLI load**, against the process environment.
The resolved values flow into Basilica's create-deployment env exactly as
text — Basilica does no further substitution.

Where the env comes from:

1. The repo secrets configured at platform setup time (passed as job env).
2. The `tenant_secrets` payload (injected per-trigger, **overrides** repo
   secrets for that run).

So `LLMTRACE_UPSTREAM_URL` set as a repo secret is the platform default; if
the tenant_secrets payload contains a different `LLMTRACE_UPSTREAM_URL`, that
wins for that tenant.

### Reading the included examples

- `configs/examples/starter.yaml` — single-replica, in-memory storage, ML
  preload on, debug-free logging. Sensible defaults for a hobby/eval tenant.
- `configs/examples/pro.yaml` — 2 proxy replicas, version-pinned via
  `${LLMTRACE_VERSION:-latest}`, SQLite storage by default
  (`${LLMTRACE_STORAGE_PROFILE:-sqlite}`), datamarking active, optional
  Anthropic key.

Both demonstrate `${VAR}` substitution and the optional override pattern.

## Per-tenant API key auth (secure by default)

LLMTrace's proxy has built-in API-key auth (`crates/llmtrace-proxy/src/auth.rs`).
Without it, the public Basilica URL accepts any request — anyone with the
URL can burn the tenant's upstream quota and pollute their traces. With it
on, every non-`/health` request must carry `Authorization: Bearer llmt_<key>`
or get a 401.

The lifecycle library enables this **by default** at provision time:

1. Resolves a key, in priority order:
   - Explicit `spec.api_key` from the caller (or `api_key:` field in the
     YAML config), used for plan-recreates that must preserve the tenant's
     existing key
   - Existing `LLMTRACE_AUTH_ADMIN_KEY` in `proxy.env` (rare — caller wrote
     it themselves)
   - Auto-generated `llmt_<64-hex>` via `generate_api_key()` matching the
     format produced by the Rust proxy at `auth.rs:44`
2. Injects `LLMTRACE_AUTH_ENABLED=true` + `LLMTRACE_AUTH_ADMIN_KEY=<key>`
   into the proxy's env, and the same `LLMTRACE_AUTH_ADMIN_KEY` into the
   dashboard's env (so the dashboard can authenticate to the proxy's admin
   endpoints)
3. Returns the plaintext key in `TenantInstances.api_key` — **this is the
   only time it's exposed**. Persist it in your app DB and ship it to the
   tenant.

```python
result = lifecycle.provision(spec)
tenant_record.api_key = result.api_key      # llmt_xxxxxxxxxxxx... — only exposed here
tenant_record.proxy_url = result.proxy.url
db.session.commit()
```

The CLI emits it in the result JSON:

```json
{
  "tenant_id": "acme",
  "proxy_url": "https://...basilica.ai",
  "dashboard_url": "https://...basilica.ai",
  "api_key": "llmt_d34c8a..."
}
```

The workflow registers `::add-mask::` for the key before any `cat`
operation, so it never appears in run logs — only in step outputs (which
the calling app fetches via the Actions API).

### Tenant-side usage

The tenant programs their downstream apps to send their API key on every
request to their proxy URL:

```bash
curl -X POST https://<proxy_uuid>.deployments.basilica.ai/v1/chat/completions \
  -H "Authorization: Bearer llmt_d34c8a..." \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

A 401 means they used the wrong key. A 200 means LLMTrace authenticated
them, then forwarded upstream (with whatever upstream auth was configured
in `tenant_secrets`).

### Disabling auth

For a trusted-network deploy where the proxy URL won't leak (a VPC-only
mesh, a dev sandbox, etc.), turn auth off:

```yaml
enable_proxy_auth: false
```

The library skips key generation, doesn't inject `LLMTRACE_AUTH_*`, and
returns `api_key: null` in the result. The proxy URL is then wide open;
own the consequences.

### Preserving the key across recreates

`update(..., strategy="recreate")` calls `provision()` under the hood,
which will auto-generate a fresh key unless you pass the existing one.
For plan upgrades where the tenant's apps shouldn't break, fetch the
current key from your DB and put it in the spec:

```python
spec = build_spec_from_tenant_record(tenant_record)
spec = dataclasses.replace(spec, api_key=tenant_record.api_key)  # preserve
new_instances = lifecycle.update(spec, proxy_id=..., dashboard_id=..., strategy="recreate")
# new_instances.api_key == tenant_record.api_key  (carried forward)
```

### Caveats

- **Admin-key-as-runtime-key is overpowered.** The auto-generated key
  takes the `auth.admin_key` slot (bootstrap admin role), meaning the
  tenant's apps technically have admin scope on their own instance.
  Hardening: after provision, POST a scoped non-admin key via the
  proxy's `/admin/keys` endpoint and hand THAT to the tenant. Tracked
  as a follow-up.
- **Defence-in-depth** still worth doing separately: per-tenant rate
  limits (LLMTrace likely has them — configure), and DoS protection
  against CPU burn from ML detectors running before the upstream call.
  The proxy now bounds intra-pod ML detection concurrency via a tokio
  semaphore — tune the cap per-pod with the
  `LLMTRACE_ML_MAX_CONCURRENT` env var (default `8`). Excess requests
  receive `503 Service Unavailable` with `Retry-After: 1` instead of
  every concurrent request stalling on contended CPU; the counter
  `llmtrace_ml_rejected_total` and the gauge
  `llmtrace_ml_inflight_requests` are exposed on `/metrics` for
  alerting on sustained saturation.

## Per-tenant secret injection

Two trigger paths, pick by intended audience:

| Path | Where secrets ride | Run UI visibility | Use for |
|---|---|---|---|
| `workflow_dispatch` with `tenant_secrets_json` input | string-encoded JSON input field | **YES** — input *values* are shown on the run page to anyone with `actions:read` | Testing, manual ops, trusted-tenant tiers |
| `repository_dispatch` event_type=`tenant-lifecycle` with `client_payload.tenant_secrets` | `client_payload` object | **NO** — payload is not rendered in the run UI | Production multi-tenant |

Both paths funnel into the same `Resolve inputs` step that normalises them
into shared env vars (`TENANT_ID`, `ACTION`, `CFG_PATH`, `CFG_JSON`,
`PROXY_ID`, `DASHBOARD_ID`, `STRATEGY`) plus a staging file for the secret
map.

The `Inject tenant secrets` step then:

1. Reads the staging file.
2. For each `(key, value)`: prints `::add-mask::<value>` so any later log line
   containing the value is redacted.
3. Writes `KEY<<<random_delim>\n<value>\n<random_delim>` to `GITHUB_ENV` so
   the value is exported as an env var for subsequent steps. The random
   per-value delimiter (`secrets.token_hex(8)`) prevents EOF collision if a
   secret value happens to contain a static delimiter token.

By the time the CLI runs, every `${VAR}` reference in the tenant config
resolves against the merged env (platform defaults overridden by
tenant-supplied values).

### Security caveats

- `workflow_dispatch` input *values* are stored in the run's metadata. The
  `::add-mask::` only affects subsequent log lines; the input field itself
  is visible to any user with read access to Actions. For real per-tenant
  secrets, use `repository_dispatch`.
- `repository_dispatch` `client_payload` is **not** rendered in the run UI,
  but is sent over GitHub's API in plaintext (TLS in transit). The PAT used
  to dispatch needs `repo` scope.
- The masking is per-runner per-job. Secrets injected in one job are not
  available to other jobs in the same workflow.
- LLMTrace's deployment env (where the bearer ends up) is stored by
  Basilica. Treat the Basilica account as a trust boundary; revoke + rotate
  any tenant key that leaks if the account is compromised.

## Embedding in your app (skip GitHub Actions)

The GitHub Actions workflow is a convenience wrapper around `lifecycle.py`.
If your app already has a worker / queue / scheduler, you can drive
provisioning directly and skip the workflow entirely. Reasons you might
want this:

- **Zero public log surface** — workflow runs in a public repo leak
  tenant IDs, URLs, and timestamps; in-process leaves no public trace.
- **Lower latency** — no Actions runner cold-start (typically 10–30s of
  startup before the CLI even runs).
- **Tighter secret handling** — bearers never leave the app's process or
  its secret store; nothing rides through GitHub's webhook surface.
- **Native error handling** — Python exceptions instead of parsing
  step-output JSON.
- **Your app's auth/RBAC/idempotency** wraps the trigger — no
  duplicate dispatch issues.

### Dependency footprint

Just two pip packages:

```bash
pip install basilica-sdk PyYAML
```

`PyYAML` is only needed if you load configs from YAML files; if you
construct `TenantSpec` directly in code, you can drop it.

### Distribution options

| Option | When |
|---|---|
| **Vendor** `deployments/basilica/{__init__,lifecycle,cli}.py` + `configs/examples/*.yaml` into your app's repo | Simplest; ~700 LoC total. Lets your app evolve the library independently. Pin the upstream commit in a comment for traceability |
| **Git submodule / subtree** | If you want upstream changes to flow in semi-automatically |
| **`pip install git+https://github.com/techlab-innov/llmtrace.git`** | Not currently set up — the repo isn't packaged as a pip-installable; would need a top-level `pyproject.toml` exposing `deployments.basilica`. Open an issue if you want this |
| **Re-implement using `basilica-sdk` directly** in your app's language (Node, Go, Rust, etc.) | If your app isn't Python. The Python library is ~400 LoC of wrapping; the underlying SDK is what does the work. See `lifecycle.py:213-249` (`_create_component`) for the minimum shape |

### Library API at a glance

```python
from deployments.basilica.lifecycle import (
    ComponentSpec, TenantSpec, TenantInstances, InstanceInfo,
    provision, update, deprovision, status, make_client,
)

# Make a client once (uses BASILICA_API_TOKEN env, or pass api_key explicitly).
client = make_client(api_key="basilica_...")

# Build a spec for the tenant (everything is required from you — no defaults).
spec = TenantSpec(
    tenant_id="acme",
    proxy=ComponentSpec(
        image="ghcr.io/techlab-innov/llmtrace-proxy:latest",
        port=8080,
        cpu="2",
        memory="4Gi",
        replicas=1,
        env={
            "LLMTRACE_UPSTREAM_URL": "https://api.openai.com",
            "OPENAI_API_KEY": tenant_record.openai_api_key,  # from your DB
            "LLMTRACE_STORAGE_PROFILE": "memory",
            "LLMTRACE_ML_ENABLED": "1",
            "LLMTRACE_LOG_LEVEL": "info",
            "LLMTRACE_LOG_FORMAT": "json",
            "RUST_LOG": "info",
        },
        startup_timeout_seconds=600,
    ),
    dashboard=ComponentSpec(
        image="ghcr.io/techlab-innov/llmtrace-dashboard:latest",
        port=3000,
        cpu="1",
        memory="1Gi",
        replicas=1,
        env={
            "HOSTNAME": "0.0.0.0",
            "NODE_ENV": "production",
            "LLMTRACE_AUTH_ADMIN_KEY": tenant_record.dashboard_admin_key,
        },
        startup_timeout_seconds=300,
    ),
    # inject_proxy_url_into_dashboard defaults to True
)

# Provision (blocking — see below for the async pattern).
instances: TenantInstances = provision(spec, client=client)

# Persist the UUIDs to your DB — they're the only handle for future ops.
tenant_record.proxy_instance_id = instances.proxy.instance_id
tenant_record.proxy_url = instances.proxy.url
tenant_record.dashboard_instance_id = instances.dashboard.instance_id
tenant_record.dashboard_url = instances.dashboard.url
tenant_record.save()
```

Subsequent ops use the persisted UUIDs:

```python
# Health check before sending traffic
current = status(
    tenant_id=tenant_record.id,
    proxy_instance_id=tenant_record.proxy_instance_id,
    dashboard_instance_id=tenant_record.dashboard_instance_id,
    client=client,
)
if current.proxy is None or current.proxy.state != "Active":
    # tenant's proxy went missing — recover

# Plan upgrade — recreates with new spec; URL changes
new_instances = update(
    spec=upgraded_spec,
    proxy_instance_id=tenant_record.proxy_instance_id,
    dashboard_instance_id=tenant_record.dashboard_instance_id,
    strategy="recreate",
    client=client,
)
tenant_record.proxy_instance_id = new_instances.proxy.instance_id    # overwrite!
tenant_record.proxy_url = new_instances.proxy.url
# ... same for dashboard, then save

# Stripe cancellation → deprovision
deprovision(
    tenant_id=tenant_record.id,
    proxy_instance_id=tenant_record.proxy_instance_id,
    dashboard_instance_id=tenant_record.dashboard_instance_id,
    client=client,
)
```

### Subprocess invocation (language-agnostic)

If your app isn't Python, fork the CLI as a subprocess with the secrets in
the child's environment. The CLI emits JSON to stdout; parse and persist:

```bash
# From a Node / Go / Rust / Ruby worker
OPENAI_API_KEY="$tenant_openai_key" \
LLMTRACE_UPSTREAM_URL="https://api.openai.com" \
BASILICA_API_TOKEN="$platform_token" \
python -m deployments.basilica.cli provision \
  --tenant-id "$tenant_id" \
  --config /etc/llmtrace/tenant-config.yaml
# stdout is JSON:
# { "tenant_id": "...", "proxy_instance_id": "...", "proxy_url": "...", ... }
```

Exit codes: `0` success, `2` usage error, `3` lifecycle error. The CLI's
`${VAR}` substitution reads from the child's env — same secret-injection
shape as the workflow, just driven by your app instead of the
`Inject tenant secrets` workflow step.

### Async wrapping (FastAPI / Starlette / aiohttp)

The library is synchronous and blocks on `_wait_until_ready` (up to
`startup_timeout_seconds`, default 600s for the proxy). Don't call
`provision` from a request handler — wrap it in a background worker.

Quick adapter for async code:

```python
import asyncio
from deployments.basilica import lifecycle

async def provision_async(spec: lifecycle.TenantSpec) -> lifecycle.TenantInstances:
    return await asyncio.to_thread(lifecycle.provision, spec)
```

This runs the blocking call in a thread pool so the event loop stays free.
Same pattern for `update`, `deprovision`, `status`.

### Background-worker pattern (recommended)

The real shape for production:

```python
# Worker task (Celery / RQ / dramatiq / Hatchet / Temporal / etc.)
@worker.task(bind=True, max_retries=3, soft_time_limit=900)
def provision_tenant(self, tenant_id: str) -> None:
    tenant = db.session.query(Tenant).get(tenant_id)
    if tenant.proxy_instance_id:
        return  # idempotent: already provisioned

    spec = build_spec_from_tenant_record(tenant)
    try:
        result = lifecycle.provision(spec)
    except lifecycle.RuntimeError as exc:
        tenant.last_error = str(exc)
        tenant.state = "provision_failed"
        db.session.commit()
        raise self.retry(exc=exc, countdown=60)

    tenant.proxy_instance_id = result.proxy.instance_id
    tenant.proxy_url = result.proxy.url
    tenant.dashboard_instance_id = result.dashboard.instance_id
    tenant.dashboard_url = result.dashboard.url
    tenant.state = "active"
    db.session.commit()
```

Flow: Stripe webhook → enqueue task → worker pulls → calls
`lifecycle.provision()` → persists UUIDs → updates tenant state. Request
handlers stay sub-100ms; the actual provision happens out-of-band.

### Error handling

The library raises three exception classes that your worker should map:

| Exception | Meaning | Recommended action |
|---|---|---|
| `ValueError` | Bad input (invalid `tenant_id` slug, unknown `strategy`, missing required spec field) | 4xx to caller; don't retry |
| `RuntimeError` | Basilica-side failure (deployment entered terminal `Failed` state, `BASILICA_API_TOKEN` missing, etc.) | 5xx + alert; retry with backoff if transient |
| `TimeoutError` | `startup_timeout_seconds` elapsed without ready | 5xx; check Basilica's UI for stuck deployment; consider a manual `deprovision` to clean up |

The CLI maps both `RuntimeError` and `TimeoutError` to exit code 3 with
the message in the JSON output. From a subprocess caller, key on the exit
code rather than parsing the error string.

### Secret handling without the workflow

When the workflow runs, the `Inject tenant secrets` step + `::add-mask::`
machinery exists to keep per-tenant values out of public logs. In your
app, you can do better: keep the values in process memory, pass them
directly into the `ComponentSpec.env` dict, and never serialise them to
anywhere except the Basilica API call itself.

Recommended pattern:

1. Stripe webhook arrives with `tenant_id` + plan.
2. App fetches per-tenant secrets from its store (Vault / AWS Secrets
   Manager / encrypted Postgres column).
3. Worker builds `ComponentSpec.env` with the resolved values.
4. `lifecycle.provision()` ships them once to Basilica's
   `create_deployment`.
5. The values are never logged. (Basilica stores them as deployment
   env — that's the boundary the Basilica account owns.)

No environment variables, no `${VAR}` substitution layer, no GitHub
secrets. Just dict-passing. This is the cleanest secret-flow path you
can build.

### Auth — how the app holds `BASILICA_API_TOKEN`

The token is the only platform-side credential. Store it the same way
your app stores its other infrastructure secrets (env var, secret
manager, IAM-role-derived). Pass it to `make_client(api_key=...)`
explicitly, or set `BASILICA_API_TOKEN` in the worker's env and let
`make_client()` pick it up.

Rotate periodically. Compromised token = whoever holds it can list /
read / modify / delete every tenant's deployment. Treat it like a root
key.

### When to still use the workflow

- You don't have a worker infrastructure yet and want to get a first
  tenant up without writing one.
- You want GitHub's audit log of every dispatch (in addition to your
  app's own log) — useful for compliance.
- You want operators to fire ad-hoc lifecycle ops via the `gh` CLI from
  their laptop.
- You're in early prototyping and the workflow's 25-minute timeout is a
  useful safety net.

## Provider examples

Per-tenant `tenant_secrets` shape for each provider. The proxy forwards
client-supplied `Authorization` headers transparently, so most providers work
with just the URL set — the bearer in `tenant_secrets` is for tenants whose
own apps don't supply auth at the LLMTrace endpoint.

### OpenAI / OpenAI-compatible (OpenRouter, Together, vLLM, Ollama-OAI shim)

```json
{
  "LLMTRACE_UPSTREAM_URL": "https://api.openai.com",
  "OPENAI_API_KEY": "sk-..."
}
```

For OpenRouter:

```json
{
  "LLMTRACE_UPSTREAM_URL": "https://openrouter.ai/api",
  "OPENAI_API_KEY": "sk-or-..."
}
```

For self-hosted vLLM (assuming reachable from Basilica):

```json
{
  "LLMTRACE_UPSTREAM_URL": "https://your-vllm.example.com/v1"
}
```

### Anthropic

```json
{
  "LLMTRACE_UPSTREAM_URL": "https://api.anthropic.com",
  "ANTHROPIC_API_KEY": "sk-ant-..."
}
```

Note: Anthropic auth uses `x-api-key` (not `Authorization: Bearer`).
LLMTrace's Anthropic provider-boundary support has gaps tracked in
`crates/llmtrace-security/src/boundary.rs:94`; header passthrough works,
provider-specific behaviour is uneven.

### Google Gemini

```json
{
  "LLMTRACE_UPSTREAM_URL": "https://generativelanguage.googleapis.com"
}
```

Gemini auth uses `x-goog-api-key` header or `?key=` query param. The proxy
forwards client headers transparently.

### AWS Bedrock

Not supported today — Bedrock uses SigV4 signing which the proxy doesn't
handle. Tracked as a separate workstream.

## Lifecycle operations in detail

### `provision`

Always creates **fresh** Basilica deployments. Returns the new UUIDs in the
step output. The library never deduplicates by tenant_id — if you call
`provision` twice for the same `tenant_id`, you get two deployment pairs.
**The caller is responsible for checking its own DB before triggering a
second provision** (and using `status` instead if the tenant already has a
pair).

### `status`

Reads state for the supplied UUIDs via `get_deployment`. Missing UUIDs
return `null` in the response. Useful for the app to confirm a tenant's pair
is still healthy or detect drift.

### `update`

Updates the pair, addressed by caller-supplied UUIDs. Two strategies:

| `strategy` | What happens | URL stable? | Caveats |
|---|---|---|---|
| `restart` | `client.restart_deployment(uuid)` on each side, then wait for ready. Rolls existing pods | YES | **Fails on freshly-provisioned deployments** — Basilica returns 404 `deployments.apps "ud-<uuid>-deployment" not found` because the k8s Deployment CR isn't materialised yet. Empirically settles after the deployment has been running long enough. The library reports the error via exit 3 + JSON; callers should fall back to `recreate` or retry after warm-up |
| `recreate` | `delete_deployment` both UUIDs, then `provision(spec)` returns fresh UUIDs | NO — URLs change | Required for any config change (replicas, CPU, memory, env, image tag). `tenant_secrets` re-applied. **Returns new UUIDs that the caller must persist over the old ones** |

### `deprovision`

`delete_deployment` for each supplied UUID. Missing UUIDs are skipped
(idempotent — re-running deprovision on already-deleted UUIDs is safe and
returns 0).

## Operational notes

### Image publishing

`.github/workflows/publish-images.yml` builds and pushes
`ghcr.io/techlab-innov/llmtrace-{proxy,dashboard}` on every push to `main`
that touches `crates/`, `Cargo.toml`, `Cargo.lock`, `Dockerfile`,
`dashboard/`, or `publish-images.yml` itself. Tags published: `main`,
`sha-<short>`, `latest`. Multi-arch: amd64 + arm64.

Manual rebuild via `workflow_dispatch`:

```bash
gh workflow run publish-images.yml \
  -f tag=rc1 \
  -f mark_latest=false
```

This adds `:rc1` without overwriting `:latest`.

### GHCR package visibility

When `publish-images.yml` first runs against a fresh repo, GHCR creates the
packages as **private**. Basilica cannot pull them anonymously. Flip to
public via the GitHub web UI (org → Packages → package → settings → Change
visibility → Public) or via `gh api`:

```bash
gh api -X PATCH /orgs/techlab-innov/packages/container/llmtrace-proxy \
  -f visibility=public
gh api -X PATCH /orgs/techlab-innov/packages/container/llmtrace-dashboard \
  -f visibility=public
```

(The `PATCH` endpoint requires a token with `admin:packages` scope. If you
get 404, that's almost certainly missing scope — refresh via
`gh auth refresh -s admin:packages`. The UI path always works.)

Verify with:

```bash
TOK=$(curl -s "https://ghcr.io/token?scope=repository:techlab-innov/llmtrace-proxy:pull" | jq -r .token)
curl -sI -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  https://ghcr.io/v2/techlab-innov/llmtrace-proxy/manifests/latest
# Expect: HTTP/2 200
```

Note the `Accept: application/vnd.oci.image.index.v1+json` header — the
multi-arch image is an OCI index, and ghcr.io returns 404 (not 415) if the
client doesn't accept that media type.

### ML preload behaviour

The proxy image has `LLMTRACE_ML_ENABLED=1` and `LLMTRACE_ML_PRELOAD=1` by
default in `starter.yaml`. Cold-boot includes model warm-up; in live tests
the proxy hit `phase=ready` in ~60s. If your tenant config sets a smaller
`startup_timeout_seconds`, the deployment may legitimately time out — bump
the timeout or set `LLMTRACE_ML_PRELOAD=0` to defer model load to
first-request time.

### Cleanup of orphans

The library only deletes UUIDs the caller hands back. If your app loses the
UUID mapping (e.g. DB restore from before the provision), the deployments
keep running. Recover via:

```bash
basilica deploy ls                                # list everything on the account
basilica deploy rm <uuid>                         # delete by UUID
```

…or directly via the Basilica SDK from a one-off Python repl. The library
does not implement a "garbage-collect deployments matching naming pattern"
sweep because that would silently delete deployments your app forgot about
*and* legitimately wants to keep.

## Repo secrets reference

| Secret | Set by | Purpose |
|---|---|---|
| `BASILICA_API_TOKEN` | platform | Auth for the Basilica SDK. Required |
| `LLMTRACE_UPSTREAM_URL` | platform | Default upstream URL when a tenant doesn't override |
| `OPENAI_API_KEY` | platform | Default OpenAI key when a tenant doesn't bring their own |
| `ANTHROPIC_API_KEY` | platform | Default Anthropic key |
| `LLMTRACE_AUTH_ADMIN_KEY` | platform | Default dashboard admin key |

All five are exposed as job-level env in `tenant-lifecycle.yml`. The
`tenant_secrets` payload overrides any of them per-trigger via `GITHUB_ENV`
writes that happen *after* the job-level env is established (GitHub
Actions resolves `GITHUB_ENV` writes after job-level env, so later writes
win).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Workflow fails at `Validate inputs` with `BASILICA_API_TOKEN secret is not configured` | Repo secret missing | `gh secret set BASILICA_API_TOKEN < ~/.basilica/token` |
| `Inject tenant secrets` step succeeds but the CLI errors with `env var 'X' required by config is not set` | Config references `${X}` but tenant_secrets didn't supply it and there's no fallback (`${X:-default}`) | Either add `X` to tenant_secrets, or change config to `${X:-default}`, or set as repo secret + job env |
| Deployment stuck in `phase=health_check` until startup_timeout_seconds | Image not pullable from Basilica, or `/health` not responding on the configured port | Verify image visibility (`Operational notes` above); confirm port + path; check image logs via Basilica's UI or `basilica deploy logs <uuid>` |
| `update --strategy=restart` returns `404 deployments.apps "ud-<uuid>-deployment" not found` | Basilica's k8s Deployment CR not yet materialised on a fresh deployment | Use `--strategy=recreate` instead, or retry restart after the deployment has been live for a few minutes |
| `provision` succeeds, but `status` later returns `proxy: null` | Deployment was deleted out-of-band, or UUID mismatch | Check Basilica's UI; the library is honest — null means Basilica returned 404 on the UUID |
| `gh api ... PATCH /orgs/.../packages/container/.../visibility` returns 404 | gh token lacks `admin:packages` scope | `gh auth refresh -s admin:packages` |

## File index

| File | Purpose |
|---|---|
| `lifecycle.py:66` | `ComponentSpec` dataclass — one component's full deployment shape |
| `lifecycle.py:91` | `TenantSpec` dataclass — tenant's pair (incl. `enable_proxy_auth` + `api_key`) |
| `lifecycle.py:55` | `generate_api_key()` — `llmt_<64-hex>` matching the Rust proxy |
| `lifecycle.py:343` | `provision(spec)` |
| `lifecycle.py:387` | `update(spec, proxy_id, dashboard_id, strategy)` |
| `lifecycle.py:438` | `deprovision(tenant_id, proxy_id?, dashboard_id?)` |
| `lifecycle.py:452` | `status(tenant_id, proxy_id?, dashboard_id?)` |
| `cli.py:40` | `_substitute_env` — `${VAR}` resolver |
| `cli.py:60` | `_load_config` — YAML/JSON loader |
| `cli.py:113` | `_tenant_spec_from_config` — dict → `TenantSpec` |
| `cli.py:154` | `_build_parser` — argparse subcommand wiring |
| `.github/workflows/tenant-lifecycle.yml` | Spawn workflow (workflow_dispatch + repository_dispatch) |
| `.github/workflows/publish-images.yml` | Image build/push pipeline |
