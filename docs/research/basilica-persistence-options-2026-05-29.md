# Basilica persistence options for LLMTrace tenant + trace state (2026-05-29)

## Problem

On Basilica, LLMTrace proxy storage is ephemeral. The proxy defaults to the
SQLite (`lite`/`sqlite`) profile writing `llmtrace.db` to the container's
local working directory (`/home/llmtrace/llmtrace.db` — see Evidence E5).
There is no mounted durable volume today. On `update(strategy="recreate")`
the lifecycle layer deletes both Basilica deployments and re-provisions fresh
ones (`deployments/basilica/lifecycle.py:1063-1068`), which:

1. wipes all traces stored in the per-pod SQLite file, and
2. re-bootstraps a brand-new internal tenant row (the proxy mints a fresh
   tenant UUID on `POST /api/v1/tenants`), so tenant identity is lost.

Goal: make tenant + trace state survive a redeploy.

## What the Basilica SDK actually offers (evidence)

SDK version inspected: `basilica-sdk` at
`/home/epappas/.local/lib/python3.12/site-packages/basilica/`.

### E1 — `create_deployment` accepts a `storage` spec

`basilica/__init__.py:1825-1851` — the low-level `create_deployment(...)`
signature includes:

```python
storage: Optional[Union[str, StorageSpec]] = None,
```

`basilica/__init__.py:1903-1918` builds a `StorageSpec` from it: if `storage`
is a `str` it is treated as a mount path and wrapped in a
`PersistentStorageSpec(enabled=True, backend=StorageBackend.R2, bucket="",
credentials_secret=None, sync_interval_ms=1000, cache_size_mb=1024,
mount_path=storage)`. If it is already a `StorageSpec` it is passed through.

### E2 — persistent storage is OBJECT-STORE backed, not a raw block volume

`_basilica.pyi:577-617` — `PersistentStorageSpec.__new__`:

```python
def __new__(cls, enabled, backend: StorageBackend, bucket: str='',
            region=None, endpoint=None, credentials_secret=None,
            sync_interval_ms: int=1000, cache_size_mb: int=1024,
            mount_path: str='/data') -> PersistentStorageSpec: ...
```

`_basilica.pyi:1107-1113` — `StorageBackend` enum is `{R2, S3, GCS}`. So the
only persistent backend is an object store (Cloudflare R2 / AWS S3 / GCS),
synced on an interval (`sync_interval_ms`) with a local cache
(`cache_size_mb`). It REQUIRES a `bucket` and (in practice) a
`credentials_secret` naming a pre-provisioned secret on the Basilica side
(the `deploy_vllm`/`deploy_sglang` paths hard-code
`credentials_secret="basilica-r2-credentials"`, `__init__.py:915,1071`).

There is NO local-disk / PVC / hostPath persistent-volume option on
`CreateDeploymentRequest`. `VolumeMountRequest(host_path, container_path,
read_only)` exists (`_basilica.pyi:1058-1074`) but it is ONLY a field of
`StartRentalApiRequest` (raw GPU rentals, `_basilica.pyi:983`), NOT of
`CreateDeploymentRequest` (`_basilica.pyi:126-190` — its fields are
`instance_name, image, replicas, port, command, args, env, resources,
ttl_seconds, public, storage, topology_spread, health_check, websocket,
public_metadata`; no `volumes`). The `Volume.from_name(...)` helper
(`basilica/volume.py`) is consumed only by the `@basilica.deployment`
decorator's `volumes={}` kwarg, a code path the lifecycle library does not
use (it calls the low-level `create_deployment`).

### E3 — `create_deployment` does NOT thread storage today

`deployments/basilica/lifecycle.py:438-447` (`_create_component`) calls
`client.create_deployment(...)` with no `storage=` argument. So even though
the SDK supports it, LLMTrace never requests any persistent storage.

### E4 — restart vs recreate disk semantics

`lifecycle.py:1031-1068`:

- `strategy="restart"` calls `client.restart_deployment(uuid)` on each side
  (rolling restart of existing pods). The pods keep their identity; the
  Basilica deployment (and whatever disk is attached to it) is not deleted.
  The library's own restart path (`_verify_or_remint_operator_key`,
  `lifecycle.py:961-1003`) is built on the assumption that the tenant row
  and operator key SURVIVE a restart and only need re-minting if absent.
- `strategy="recreate"` calls `_safe_delete` on both UUIDs then
  `provision(spec)` (`lifecycle.py:1063-1068`). Deleting the Basilica
  deployment destroys the pod and its container-local disk.

The shipped README already states this contract (`deployments/basilica/
README.md:647-650`): recreate → "DB volume is destroyed alongside the pods";
restart → "Same DB volume — rows survive".

IMPORTANT CAVEAT — restart does NOT survive a node reschedule. A Basilica
rolling restart keeps the deployment object, but the proxy's SQLite file
lives on the container's ephemeral local filesystem (`emptyDir`-class, E5).
If the pod is rescheduled to another node (eviction, node failure, image
update via recreate) the local file is gone. "restart preserves the DB" is
only true for an in-place pod roll on the same node with the same writable
layer. It is NOT a durability guarantee equivalent to a real volume.
Additionally the README documents (`README.md:1248`) that `restart` returns
`404 deployments.apps ... not found` on a freshly-provisioned deployment
until the k8s Deployment CR has materialised — so restart is not always
available even when desired.

### E5 — where the SQLite file lives

`Dockerfile:64-72` — the proxy image runs as user `llmtrace` (uid 1000) with
`WORKDIR /home/llmtrace`. The default DB path is the RELATIVE string
`llmtrace.db` (`crates/llmtrace-core/src/lib.rs:1853-1855`,
`default_database_path() -> "llmtrace.db"`), so it resolves to
`/home/llmtrace/llmtrace.db` on the container-local writable layer. The image
already creates and chowns `/home/llmtrace/.cache/llmtrace/models` for the ML
weights (`Dockerfile:69`) — that directory is likewise ephemeral.

### E6 — external DB profile is wired, but no endpoints are available here

`crates/llmtrace-proxy/src/config.rs:49-64` reads `LLMTRACE_STORAGE_PROFILE`,
`LLMTRACE_STORAGE_DATABASE_PATH`, `LLMTRACE_CLICKHOUSE_URL`,
`LLMTRACE_POSTGRES_URL`, `LLMTRACE_REDIS_URL`. `crates/llmtrace-proxy/src/
main.rs:438-464` maps `profile=="production"` to `StorageProfile::Production
{ clickhouse_url, postgres_url, redis_url }` — a fully durable external
backend. This is the only LLMTrace storage mode that is unconditionally
durable across recreate.

BUT: no external Postgres/ClickHouse/Redis endpoints are credentialed in this
environment. `/home/epappas/workspace/spacejar/autojepa/.env` is readable and
contains 9 keys, NONE matching `POSTGRES|CLICKHOUSE|REDIS|DATABASE|DB_*|
DSN|*_URL` (verified by grepping key names only; no values inspected). No R2
/ S3 / GCS bucket or `*-r2-credentials` secret is referenced anywhere in
`deployments/`. So neither the production profile nor the R2-backed
persistent mount can be wired with real, working credentials right now.

### E7 — tenant create does NOT yet accept an explicit id

`crates/llmtrace-proxy/src/tenant_api.rs:24-35` — `CreateTenantRequest` has
only `name`, `plan`, `config`. There is no `id` field, so the proxy mints a
fresh UUID per create. The struct is NOT `#[serde(deny_unknown_fields)]`, so
sending an extra `id` key in the JSON body is currently IGNORED (safe, no
error). Making create idempotent on a caller-supplied stable id is owned by
the parallel proxy agent; this work provides the stable id over the wire so
that, once the proxy honours it, identity persists across recreate.

## Durable options, ranked

| Rank | Option | Survives recreate? | Requires | Status here |
|---|---|---|---|---|
| 1 | External production profile (Postgres + ClickHouse + Redis) via `LLMTRACE_*_URL` env | YES (fully) | Real, reachable, credentialed DB endpoints | BLOCKED — no endpoints in this env (E6) |
| 2 | R2/S3/GCS-backed `StorageSpec` mount, point SQLite db at the mount path | YES (synced to object store) | A bucket + a Basilica-side `credentials_secret` | BLOCKED — no bucket/credentials in this env (E2, E6) |
| 3 | `strategy="restart"` for updates + deterministic SQLite path on the pod | PARTIAL — survives in-place pod roll, NOT recreate, NOT node reschedule | Operator must use restart, never recreate, for updates | AVAILABLE but weak (E4) |
| 4 | Deterministic/stable tenant id passed to tenant create | Identity only (not traces); needs proxy-side idempotent create | Proxy to honour an `id` field on create (parallel agent) | WIRED here; proxy support pending (E7) |

## Decision

- Options 1 and 2 are the only ways to make TRACES survive `recreate`. Both
  are BLOCKED in this environment for lack of real credentials/endpoints. We
  will NOT invent connection strings or bucket names.
- We make the deployment FORWARD-READY for both: `lifecycle.py` gains a
  first-class, validated way to attach a Basilica `StorageSpec` (object-store
  persistent mount) and to set `LLMTRACE_STORAGE_DATABASE_PATH` onto the
  mount, and `pro.yaml` documents the production-profile env switch. Neither
  is turned on by default because doing so without real credentials would
  break deploys.
- We pass the STABLE tenant id on tenant create so that, the moment the proxy
  makes create idempotent on it (parallel agent, E7), tenant IDENTITY
  survives recreate. This is safe to ship now (E7: unknown field ignored).
- We document the restart-vs-recreate disk contract and the deterministic
  SQLite path so an operator who chooses restart-based updates retains state
  in-place, with the honest caveat that this is not node-reschedule durable.

## Honest verdict

With the credentials available in THIS environment, TRACES do not survive a
`--strategy recreate` — there is no durable substrate (no external DB, no
object-store bucket) to point at, and Basilica deployments have no raw
persistent block volume on `CreateDeploymentRequest`. What this change does
deliver:

- A deterministic, configurable SQLite path and a first-class
  `StorageSpec` attachment point, so durability is a one-line config change
  once a bucket or external DB exists.
- The stable tenant id on the wire, so tenant identity persists across
  recreate as soon as the proxy honours it.
- The production-profile switch documented end-to-end in `pro.yaml`.

To actually persist traces across recreate, EITHER provision an external
Postgres+ClickHouse+Redis and set the `LLMTRACE_*_URL` env (Option 1), OR
provision an R2/S3/GCS bucket + Basilica `credentials_secret` and enable the
`StorageSpec` mount with the SQLite db on it (Option 2).
