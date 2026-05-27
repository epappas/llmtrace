"""Multi-tenant lifecycle for LLMTrace on Basilica.

This module is a stateless mechanism. The caller (typically an app + DB or
the GitHub Actions workflow) owns the mapping from `tenant_id` to the
Basilica-assigned instance UUIDs.

Why caller-owned identity: Basilica's SDK only addresses deployments by
their server-assigned UUID. The friendly name supplied at create time is
accepted but not echoed back on read, and `get_deployment` only resolves
UUIDs. Idempotent lookup by friendly name is not possible against this SDK.

Configuration is also caller-owned: every field of `ComponentSpec` must
come from the caller. No defaults for image, env, resources, ports.
Probe/timeout fields have structural defaults because they describe *how
to wait*, not *what to deploy*.

Update semantics: the Basilica SDK has no patch endpoint, so
`update(..., strategy="recreate")` deletes the old UUIDs and creates new
ones (URLs change — Basilica URLs are UUID-keyed). `strategy="restart"`
does a rolling restart of the existing pods (URL stable, no config change).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import re
import secrets as _secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from basilica import (
    BasilicaClient,
    HealthCheckConfig,
    ProbeConfig,
)

LOGGER = logging.getLogger(__name__)

# Maximum length accepted by `validate_tenant_id`. The library accepts any
# caller-supplied identifier (UUID, email, opaque string); slugging to a
# DNS-safe Basilica deployment name happens internally in `_basilica_slug`.
MAX_TENANT_ID_LEN = 256

# DNS-safe Basilica deployment slug guarantee. `_basilica_slug` always
# returns a value matching this regex; downstream Basilica friendly-name
# templates need a stable k8s-compatible string.
_BASILICA_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")

# Maximum slug length (matches the regex's 30-char ceiling). Splits into
# a sanitised prefix and a 6-hex collision-resistant suffix joined by `-`.
_SLUG_MAX_LEN = 30
_SLUG_HASH_HEX = 6
_SLUG_PREFIX_MAX = _SLUG_MAX_LEN - 1 - _SLUG_HASH_HEX  # 23

# Anything not in `[a-z0-9-]` after lowercasing is rewritten to `-` in the
# slug prefix.
_SLUG_INVALID_CHARS = re.compile(r"[^a-z0-9-]")
_SLUG_DASH_RUN = re.compile(r"-+")

POLL_INTERVAL_SECONDS = 10

DEFAULT_PROXY_NAME_TEMPLATE = "llmtrace-proxy-{tenant_id}"
DEFAULT_DASHBOARD_NAME_TEMPLATE = "llmtrace-dashboard-{tenant_id}"

# LLMTrace API key format — matches `crates/llmtrace-proxy/src/auth.rs::generate_api_key`.
API_KEY_PREFIX = "llmt_"
API_KEY_RANDOM_BYTES = 32

# Minimum startup window the lifecycle library will apply when the resolved
# proxy env requests ML preload (`LLMTRACE_ML_ENABLED=1`,
# `LLMTRACE_ML_PRELOAD=1`). On a cpu=2 shape, loading the prompt_injection +
# ner + injecguard + piguard weights regularly exceeds the
# `ComponentSpec.startup_timeout_seconds` default of 600s, so callers who
# leave it at the default would silently time out. 1500s covers the observed
# worst case with margin. Callers who explicitly set a higher value win.
ML_PRELOAD_STARTUP_FLOOR_SECONDS = 1500

# Env values that count as "enabled" for the ML preload flags. Matches the
# truthiness rules in `crates/llmtrace-proxy/src/config.rs::env_flag`.
_ML_FLAG_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes"})

# Storage profiles that hold metadata on pod-local disk. Replicas using one
# of these profiles cannot share state across Basilica pods (no shared
# volume); `replicas > 1` will round-robin to diverging files. Empty string
# means "profile not set" which falls through to the sqlite default in the
# proxy's `StorageConfig::from_env`. See README "Replica count and metadata
# storage" for the live-reproduced symptom + the postgres-backed fix.
_UNSHARED_STORAGE_PROFILES: frozenset[str] = frozenset(
    {"", "sqlite", "lite", "memory"}
)

# Proxy admin API endpoints (see `crates/llmtrace-proxy/src/main.rs` routing).
TENANTS_PATH = "/api/v1/tenants"
AUTH_KEYS_PATH = "/api/v1/auth/keys"
# Default name applied to the minted operator key. Visible in audit logs.
OPERATOR_KEY_NAME = "tenant-runtime"
# How long we'll wait on an admin HTTP call before bailing.
ADMIN_HTTP_TIMEOUT_SECONDS = 30


def generate_api_key() -> str:
    """Generate an LLMTrace-compatible API key.

    Format: `llmt_` + 32 random bytes hex-encoded (64 hex chars).
    Matches the layout produced by the Rust proxy so a generated key drops
    straight into `LLMTRACE_AUTH_ADMIN_KEY` without translation.
    """
    return API_KEY_PREFIX + _secrets.token_hex(API_KEY_RANDOM_BYTES)


@dataclass(frozen=True)
class RateLimitSpec:
    """Per-tenant rate-limit knobs surfaced to the proxy as env vars.

    `requests_per_second` is the steady-state allowance and `burst_size`
    is the token-bucket headroom. Both must be strictly positive — the
    proxy's `RateLimiter::check` treats non-positive values as
    misconfiguration and falls back to the global default.

    When present on `TenantSpec.rate_limit`, the lifecycle library
    injects `LLMTRACE_RATE_LIMIT_RPS` and `LLMTRACE_RATE_LIMIT_BURST`
    into the proxy ComponentSpec's env at provision/recreate time.
    """

    requests_per_second: int
    burst_size: int

    def __post_init__(self) -> None:
        if self.requests_per_second <= 0:
            raise ValueError(
                f"rate_limit.requests_per_second must be > 0, got {self.requests_per_second}"
            )
        if self.burst_size <= 0:
            raise ValueError(
                f"rate_limit.burst_size must be > 0, got {self.burst_size}"
            )


@dataclass(frozen=True)
class ComponentSpec:
    """Full deployment spec for one component (proxy or dashboard).

    Every business-meaning field is required from the caller. Probe and
    timeout fields default because they describe wait-mechanics.
    """

    image: str
    port: int
    cpu: str
    memory: str
    replicas: int
    env: Mapping[str, str]
    health_check_path: str = "/health"
    startup_timeout_seconds: int = 600
    startup_initial_delay_seconds: int = 30
    startup_period_seconds: int = 30
    startup_failure_threshold: int = 15
    liveness_period_seconds: int = 30
    liveness_failure_threshold: int = 3
    readiness_period_seconds: int = 10
    readiness_failure_threshold: int = 3


@dataclass(frozen=True)
class TenantSpec:
    """Full per-tenant deployment specification."""

    tenant_id: str
    proxy: ComponentSpec
    dashboard: ComponentSpec
    proxy_name_template: str = DEFAULT_PROXY_NAME_TEMPLATE
    dashboard_name_template: str = DEFAULT_DASHBOARD_NAME_TEMPLATE
    # If True, the resolved proxy URL is injected into the dashboard's env
    # under `proxy_url_env_var` before the dashboard is created.
    inject_proxy_url_into_dashboard: bool = True
    proxy_url_env_var: str = "LLMTRACE_PROXY_URL"
    # If True, the proxy is provisioned with LLMTRACE_AUTH_ENABLED=true plus
    # an admin key (caller-supplied via `api_key`, or auto-generated). The
    # same key is also injected into the dashboard env so it can authenticate
    # to the proxy's admin endpoints. Set False to deploy an open proxy
    # (anyone with the URL can use it — only do this for trusted networks).
    enable_proxy_auth: bool = True
    api_key: Optional[str] = None
    # Optional per-tenant rate-limit knobs. When set, the lifecycle
    # library injects `LLMTRACE_RATE_LIMIT_RPS` and
    # `LLMTRACE_RATE_LIMIT_BURST` into the proxy ComponentSpec env at
    # provision time. The proxy reads these env vars in
    # `config::apply_env_overrides` and applies them on top of any YAML
    # `rate_limiting:` block. Unset means the proxy keeps whatever it
    # was built with (default 100 rps / 200 burst).
    rate_limit: Optional[RateLimitSpec] = None
    # If True, after `provision()` brings the pair up, the proxy is rotated
    # to a freshly-generated admin key. The key returned by `provision()` at
    # bootstrap is then INVALIDATED — only the post-rotation key is live.
    # Trade-off: adds one proxy re-roll (~30s) to provisioning. Opt-in
    # because most callers will not need it.
    rotate_admin_after_bootstrap: bool = False
    # Display identifier seeded into the dashboard login form. The
    # dashboard's `/api/auth/login` route checks the submitted value matches
    # `LLMTRACE_DASHBOARD_ADMIN_USERNAME` (case-insensitive) AND that the
    # submitted password validates against the proxy as an admin key.
    # Free string — the app decides whether to seed an email, a username,
    # or any other identifier. The library does not validate format. The
    # dashboard login form accepts whatever was seeded. Defaults to "admin".
    admin_username: str = "admin"


@dataclass(frozen=True)
class InstanceInfo:
    """Lifecycle-relevant view of a single Basilica deployment.

    `instance_id` is the Basilica-assigned UUID — the only stable handle
    for subsequent SDK calls. The caller is responsible for persisting it.
    """

    instance_id: str
    state: str
    url: str
    ready_replicas: int
    desired_replicas: int
    phase: Optional[str] = None
    message: Optional[str] = None


@dataclass(frozen=True)
class TenantInstances:
    """A tenant's deployment pair. Either side may be None when absent.

    Two-tier key model (PR-3 hardening on bootstrap-admin-as-runtime):

    - `api_key` — plaintext OPERATOR-scoped key the tenant uses for runtime
      traffic (`Authorization: Bearer <key>` on every non-`/health` request).
      Cannot manage tenants, mint keys, or read audit logs. Populated on
      `provision()` and `update(..., strategy="recreate")`. Re-minted on
      restart only if the previous operator key cannot be located. None on
      `status` / `deprovision` and when `enable_proxy_auth=False`.
    - `admin_key` — plaintext bootstrap ADMIN-scoped key the lifecycle layer
      uses to mint/list/revoke per-tenant operator keys. The caller retains
      it for self-service / admin portal flows; it must NOT be given to the
      tenant's runtime apps. Populated on the same paths as `api_key`.

    Both keys are exposed only at provision/recreate time. Persist them in
    the caller's secret store immediately.
    """

    tenant_id: str
    proxy: Optional[InstanceInfo]
    dashboard: Optional[InstanceInfo]
    api_key: Optional[str] = None
    admin_key: Optional[str] = None
    # Display username seeded into the dashboard's login form (server-side
    # checked against `LLMTRACE_DASHBOARD_ADMIN_USERNAME`). Defaults to
    # "admin"; set per-tenant via `TenantSpec.admin_username`.
    admin_username: Optional[str] = None


@dataclass(frozen=True)
class RotationResult:
    """Outcome of a proxy admin-key rotation.

    `admin_key` is the new plaintext bearer the tenant must now use. The
    previous key is invalidated as soon as the new proxy pod is ready.

    `proxy` carries the new `InstanceInfo` — note that under the Basilica
    SDK the rotation goes through a delete+create cycle, so `proxy.instance_id`
    and `proxy.url` change. Callers MUST persist these new values.
    """

    tenant_id: str
    proxy: InstanceInfo
    admin_key: str


def validate_tenant_id(tenant_id: str) -> str:
    """Permissive validation for the caller-supplied tenant identifier.

    The library accepts any non-empty string up to `MAX_TENANT_ID_LEN`
    chars with no whitespace or control characters. The DNS-safe Basilica
    deployment slug is derived internally via `_basilica_slug` — the two
    namespaces are intentionally distinct (see issue #259).
    """
    if not isinstance(tenant_id, str):
        raise ValueError(
            f"tenant_id must be a str, got {type(tenant_id).__name__}"
        )
    if not tenant_id:
        raise ValueError("tenant_id must be non-empty")
    if len(tenant_id) > MAX_TENANT_ID_LEN:
        raise ValueError(
            f"tenant_id length {len(tenant_id)} exceeds max {MAX_TENANT_ID_LEN}"
        )
    for ch in tenant_id:
        if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError(
                f"tenant_id contains whitespace or control character: {tenant_id!r}"
            )
    return tenant_id


def _basilica_slug(tenant_id: str) -> str:
    """Derive a DNS-safe Basilica deployment slug from any caller identifier.

    Deterministic for the same input. Result matches
    `^[a-z0-9][a-z0-9-]{0,29}$` — Basilica's k8s naming rule. The slug is
    `<sanitised-prefix>-<6-char-blake2b-hex>` capped at 30 chars; the hash
    suffix prevents collisions between two callers whose identifiers
    sanitise to the same prefix (e.g. `alice@acme` and `alice_acme`).
    """
    lowered = tenant_id.lower()
    cleaned = _SLUG_INVALID_CHARS.sub("-", lowered)
    cleaned = _SLUG_DASH_RUN.sub("-", cleaned).strip("-")
    prefix = cleaned or "tenant"
    prefix = prefix[:_SLUG_PREFIX_MAX]
    # Trailing dash from truncation is fine (joined by `-` next); leading
    # dash would break the leading-alnum requirement.
    if prefix.startswith("-"):
        prefix = ("x" + prefix)[:_SLUG_PREFIX_MAX]
    hash6 = hashlib.blake2b(
        tenant_id.encode("utf-8"), digest_size=_SLUG_HASH_HEX // 2
    ).hexdigest()
    slug = f"{prefix}-{hash6}"
    if not _BASILICA_SLUG_PATTERN.match(slug):
        raise RuntimeError(
            f"internal: derived slug {slug!r} fails Basilica naming rule"
        )
    return slug


def make_client(api_key: Optional[str] = None) -> BasilicaClient:
    key = api_key or os.environ.get("BASILICA_API_TOKEN")
    if not key:
        raise RuntimeError("BASILICA_API_TOKEN is not set")
    return BasilicaClient(api_key=key)


def _to_info(detail) -> InstanceInfo:
    return InstanceInfo(
        instance_id=detail.instance_name,
        state=detail.state,
        url=detail.url,
        ready_replicas=detail.replicas.ready,
        desired_replicas=detail.replicas.desired,
        phase=getattr(detail, "phase", None),
        message=getattr(detail, "message", None),
    )


def _build_health_check(spec: ComponentSpec) -> HealthCheckConfig:
    return HealthCheckConfig(
        startup=ProbeConfig(
            path=spec.health_check_path,
            port=spec.port,
            initial_delay_seconds=spec.startup_initial_delay_seconds,
            period_seconds=spec.startup_period_seconds,
            failure_threshold=spec.startup_failure_threshold,
        ),
        liveness=ProbeConfig(
            path=spec.health_check_path,
            port=spec.port,
            period_seconds=spec.liveness_period_seconds,
            failure_threshold=spec.liveness_failure_threshold,
        ),
        readiness=ProbeConfig(
            path=spec.health_check_path,
            port=spec.port,
            period_seconds=spec.readiness_period_seconds,
            failure_threshold=spec.readiness_failure_threshold,
        ),
    )


def _wait_until_ready(
    client: BasilicaClient,
    instance_id: str,
    timeout_seconds: int,
    expected_replicas: int,
) -> InstanceInfo:
    """Poll until `ready >= expected` and `desired >= expected`.

    The post-create GET can race ahead of the Basilica operator's
    reconciliation, briefly reporting `desired=0` even when the caller
    requested 1+. Gating on `desired >= expected_replicas` prevents an
    early false-positive return.
    """
    elapsed = 0
    while elapsed < timeout_seconds:
        detail = client.get_deployment(instance_id)
        replicas = detail.replicas
        LOGGER.info(
            "deployment=%s state=%s phase=%s replicas=%d/%d expected=%d elapsed=%ds",
            instance_id,
            detail.state,
            getattr(detail, "phase", None),
            replicas.ready,
            replicas.desired,
            expected_replicas,
            elapsed,
        )
        if (
            detail.state in ("running", "Active")
            and replicas.desired >= expected_replicas
            and replicas.ready >= expected_replicas
        ):
            return _to_info(detail)
        if detail.state in ("failed", "error", "Failed"):
            raise RuntimeError(
                f"deployment {instance_id} entered terminal failure: "
                f"state={detail.state} message={detail.message or 'n/a'}"
            )
        time.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS
    raise TimeoutError(
        f"deployment {instance_id} not ready after {timeout_seconds}s "
        f"(expected_replicas={expected_replicas})"
    )


def _create_component(
    client: BasilicaClient, friendly_name: str, spec: ComponentSpec
) -> InstanceInfo:
    LOGGER.info(
        "creating friendly=%s image=%s cpu=%s memory=%s replicas=%d port=%d env_keys=%s",
        friendly_name,
        spec.image,
        spec.cpu,
        spec.memory,
        spec.replicas,
        spec.port,
        sorted(spec.env.keys()),
    )
    response = client.create_deployment(
        instance_name=friendly_name,
        image=spec.image,
        replicas=spec.replicas,
        port=spec.port,
        env=dict(spec.env),
        cpu=spec.cpu,
        memory=spec.memory,
        health_check=_build_health_check(spec),
    )
    LOGGER.info(
        "created friendly=%s instance_id=%s initial_state=%s",
        friendly_name,
        response.instance_name,
        response.state,
    )
    return _wait_until_ready(
        client,
        response.instance_name,
        spec.startup_timeout_seconds,
        expected_replicas=spec.replicas,
    )


def _safe_get(client: BasilicaClient, instance_id: Optional[str]) -> Optional[InstanceInfo]:
    """Read instance state by UUID. Returns None if the UUID is None or 404."""
    if not instance_id:
        return None
    try:
        return _to_info(client.get_deployment(instance_id))
    except KeyError as exc:
        if "Not found" in str(exc):
            LOGGER.info("instance %s not found", instance_id)
            return None
        raise


def _safe_delete(client: BasilicaClient, instance_id: Optional[str], label: str) -> bool:
    """Delete by UUID. Returns True if deletion was attempted, False if absent."""
    if not instance_id:
        LOGGER.info("%s instance_id not provided — skipping delete", label)
        return False
    try:
        result = client.delete_deployment(instance_id)
        LOGGER.info("deleted %s instance_id=%s state=%s", label, instance_id, result.state)
        return True
    except KeyError as exc:
        if "Not found" in str(exc):
            LOGGER.info("%s instance_id=%s already absent", label, instance_id)
            return False
        raise


def _resolve_api_key(spec: TenantSpec) -> Optional[str]:
    """Resolve the LLMTrace tenant API key for `provision`.

    Priority: explicit `spec.api_key` > existing `LLMTRACE_AUTH_ADMIN_KEY`
    in `spec.proxy.env` > newly generated. Returns None when
    `enable_proxy_auth` is False.
    """
    if not spec.enable_proxy_auth:
        return None
    if spec.api_key:
        return spec.api_key
    env_key = spec.proxy.env.get("LLMTRACE_AUTH_ADMIN_KEY", "")
    if env_key:
        return env_key
    return generate_api_key()


def _apply_proxy_auth(
    proxy_spec: ComponentSpec, dashboard_spec: ComponentSpec, admin_key: str
) -> tuple[ComponentSpec, ComponentSpec]:
    """Inject `LLMTRACE_AUTH_ENABLED=true` + the bootstrap admin key into envs.

    The admin key is set unconditionally on both sides so the dashboard
    can still talk to the proxy's admin endpoints (key management,
    tenant CRUD) on behalf of the portal/self-service UI;
    `LLMTRACE_AUTH_ENABLED` is only defaulted (caller may explicitly turn
    it off in env). The operator key is returned to the caller in
    `TenantInstances.api_key` for tenant runtime apps to use against
    `/v1/*`; it is intentionally NOT injected into the dashboard env
    because no dashboard code path consumes it today.
    """
    proxy_env = {**proxy_spec.env, "LLMTRACE_AUTH_ADMIN_KEY": admin_key}
    proxy_env.setdefault("LLMTRACE_AUTH_ENABLED", "true")
    dashboard_env = {**dashboard_spec.env, "LLMTRACE_AUTH_ADMIN_KEY": admin_key}
    return (
        dataclasses.replace(proxy_spec, env=proxy_env),
        dataclasses.replace(dashboard_spec, env=dashboard_env),
    )


def _apply_ml_preload_startup_floor(
    spec: ComponentSpec,
    *,
    tenant_id: Optional[str] = None,
    floor: int = ML_PRELOAD_STARTUP_FLOOR_SECONDS,
) -> ComponentSpec:
    """Raise `startup_timeout_seconds` when the proxy env requests ML preload.

    When both `LLMTRACE_ML_ENABLED` and `LLMTRACE_ML_PRELOAD` resolve to a
    truthy value in `spec.env`, the proxy will block readiness on model
    weight load before flipping `/health` to ready. On small CPU shapes that
    can take well over the library's 600s default, so we floor the timeout
    at `floor` (default `ML_PRELOAD_STARTUP_FLOOR_SECONDS`).

    Callers who explicitly set `startup_timeout_seconds >= floor` keep their
    value and no warning is emitted. The bump is a pure function on the spec
    — no SDK calls — so it's safe to apply in any code path that creates the
    proxy deployment.
    """
    ml_enabled = spec.env.get("LLMTRACE_ML_ENABLED", "").strip().lower() in _ML_FLAG_TRUTHY
    ml_preload = spec.env.get("LLMTRACE_ML_PRELOAD", "").strip().lower() in _ML_FLAG_TRUTHY
    if not (ml_enabled and ml_preload):
        return spec
    if spec.startup_timeout_seconds >= floor:
        return spec
    LOGGER.warning(
        "ML preload detected (LLMTRACE_ML_ENABLED=1, LLMTRACE_ML_PRELOAD=1) "
        "on tenant=%s; raising startup_timeout_seconds from %d to %d to "
        "accommodate model load. Set explicitly to silence.",
        tenant_id or "<unknown>",
        spec.startup_timeout_seconds,
        floor,
    )
    return dataclasses.replace(spec, startup_timeout_seconds=floor)


def _warn_on_unsharable_replicas(
    proxy_spec: ComponentSpec, tenant_id: str
) -> None:
    """Emit a warning when replicas > 1 with a non-shared metadata profile.

    The proxy's sqlite/memory backends store metadata on the pod's local
    filesystem. Basilica does not share volumes between replicas, so
    `replicas > 1` with one of these profiles produces diverging state:
    bootstrap writes land on one pod, subsequent admin reads round-robin
    and return stale results from the replicas that never saw the write.
    See README "Replica count and metadata storage" for the live-repro
    evidence + the postgres-backed fix.

    Not an error: operators running with `LLMTRACE_STORAGE_PROFILE=postgres`
    + `LLMTRACE_POSTGRES_URL` legitimately want replicas > 1. The check is
    a guard rail for the default-sqlite case.
    """
    if proxy_spec.replicas <= 1:
        return
    profile = proxy_spec.env.get("LLMTRACE_STORAGE_PROFILE", "").strip().lower()
    if profile not in _UNSHARED_STORAGE_PROFILES:
        return
    LOGGER.warning(
        "tenant=%s proxy.replicas=%d with LLMTRACE_STORAGE_PROFILE=%r — "
        "replicas WILL diverge because this profile is per-pod. Either "
        "set replicas=1 or switch to a shared backend (postgres) via "
        "LLMTRACE_STORAGE_PROFILE + LLMTRACE_POSTGRES_URL.",
        tenant_id,
        proxy_spec.replicas,
        profile or "sqlite (default)",
    )


def _apply_dashboard_admin_username(
    dashboard_spec: ComponentSpec, username: str
) -> ComponentSpec:
    """Inject `LLMTRACE_DASHBOARD_ADMIN_USERNAME` into the dashboard env.

    The dashboard's `/api/auth/login` route reads this env at request time
    and requires the submitted username to match (case-insensitive) before
    it even attempts to validate the password against the proxy. Caller-
    supplied env entries with the same key are overwritten — `TenantSpec`
    is the source of truth.
    """
    env = {**dashboard_spec.env, "LLMTRACE_DASHBOARD_ADMIN_USERNAME": username}
    return dataclasses.replace(dashboard_spec, env=env)


def _apply_rate_limit(
    proxy_spec: ComponentSpec, rate_limit: RateLimitSpec
) -> ComponentSpec:
    """Inject `LLMTRACE_RATE_LIMIT_RPS` and `LLMTRACE_RATE_LIMIT_BURST`
    into the proxy env.

    The `TenantSpec.rate_limit` block is the source of truth for this
    deployment, so it overwrites any same-named values the caller put
    in `ComponentSpec.env` — same precedence model as `_apply_proxy_auth`.
    """
    proxy_env = {
        **proxy_spec.env,
        "LLMTRACE_RATE_LIMIT_RPS": str(rate_limit.requests_per_second),
        "LLMTRACE_RATE_LIMIT_BURST": str(rate_limit.burst_size),
    }
    return dataclasses.replace(proxy_spec, env=proxy_env)


def _admin_http_request(
    proxy_url: str,
    path: str,
    method: str,
    admin_key: str,
    *,
    tenant_uuid: Optional[str] = None,
    body: Optional[Mapping[str, Any]] = None,
    timeout: int = ADMIN_HTTP_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any]]:
    """Send an authenticated admin request to the proxy. Returns (status, json).

    Uses urllib so we don't add a dependency on `requests` / `httpx`. On
    non-2xx responses the body is still parsed (best-effort) and returned
    so callers can surface the proxy's structured error.
    """
    url = proxy_url.rstrip("/") + path
    headers = {
        "Authorization": f"Bearer {admin_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if tenant_uuid:
        headers["X-LLMTrace-Tenant-ID"] = tenant_uuid
    data = json.dumps(dict(body)).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8") or "{}"
            parsed = json.loads(payload) if payload.strip() else {}
            return resp.status, parsed if isinstance(parsed, dict) else {"_list": parsed}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return exc.code, parsed if isinstance(parsed, dict) else {"_list": parsed}


def _bootstrap_tenant_in_proxy(
    proxy_url: str, admin_key: str, tenant_label: str
) -> str:
    """Create the per-pod tenant row via `POST /api/v1/tenants`.

    The proxy's `create_api_key` handler verifies the tenant exists, so we
    must materialise one. Returns the tenant UUID. The bootstrap admin
    key authenticates this call; the resulting tenant row owns all
    operator keys minted afterwards.
    """
    status, payload = _admin_http_request(
        proxy_url,
        TENANTS_PATH,
        "POST",
        admin_key,
        body={"name": tenant_label, "plan": "default", "config": {}},
    )
    if status != 201:
        raise RuntimeError(
            f"tenant bootstrap failed: status={status} body={payload}"
        )
    tenant_uuid = payload.get("id")
    if not isinstance(tenant_uuid, str) or not tenant_uuid:
        raise RuntimeError(
            f"tenant bootstrap response missing 'id': body={payload}"
        )
    LOGGER.info("bootstrapped tenant in proxy uuid=%s label=%s", tenant_uuid, tenant_label)
    return tenant_uuid


def _mint_operator_key(
    proxy_url: str, admin_key: str, tenant_uuid: str
) -> str:
    """Mint a scoped Operator-role key via `POST /api/v1/auth/keys`.

    The plaintext key is returned only once (see `auth.rs::create_api_key`);
    after this call the proxy stores only a hash. Caller must persist.
    """
    status, payload = _admin_http_request(
        proxy_url,
        AUTH_KEYS_PATH,
        "POST",
        admin_key,
        tenant_uuid=tenant_uuid,
        body={
            "name": OPERATOR_KEY_NAME,
            "role": "operator",
            "tenant_id": tenant_uuid,
        },
    )
    if status != 201:
        raise RuntimeError(
            f"operator key mint failed: status={status} body={payload}"
        )
    key = payload.get("key")
    if not isinstance(key, str) or not key.startswith(API_KEY_PREFIX):
        raise RuntimeError(
            f"operator key mint returned unexpected body: {payload}"
        )
    LOGGER.info(
        "minted operator key tenant_uuid=%s key_prefix=%s",
        tenant_uuid,
        payload.get("key_prefix"),
    )
    return key


def _find_operator_key_record(
    proxy_url: str, admin_key: str, tenant_uuid: str
) -> Optional[dict[str, Any]]:
    """Look up a non-revoked operator key named `tenant-runtime` for the tenant.

    Used by the restart-update path to decide whether the existing
    operator key survived (rolling restart on same DB volume) or whether
    we need to re-mint. Returns the record dict if found, None otherwise.
    """
    status, payload = _admin_http_request(
        proxy_url,
        AUTH_KEYS_PATH,
        "GET",
        admin_key,
        tenant_uuid=tenant_uuid,
    )
    if status != 200:
        raise RuntimeError(
            f"list keys failed: status={status} body={payload}"
        )
    keys = payload.get("_list", payload) if isinstance(payload, dict) else payload
    if not isinstance(keys, list):
        return None
    for record in keys:
        if not isinstance(record, dict):
            continue
        if (
            record.get("name") == OPERATOR_KEY_NAME
            and record.get("role") == "operator"
            and record.get("revoked_at") is None
        ):
            return record
    return None


def _find_tenant_by_label(
    proxy_url: str, admin_key: str, tenant_label: str
) -> Optional[str]:
    """Find an existing tenant row in the proxy DB by its `name` field.

    Used on `update(strategy="restart")`: the lifecycle layer doesn't
    track the proxy-side tenant UUID (the proxy creates it during
    `provision`). To rediscover it after a rolling restart, we list all
    tenants (admin-only) and match by the human-readable label we
    supplied at create time. Returns the UUID string, or None if no
    tenant carries this label.
    """
    status, payload = _admin_http_request(
        proxy_url, TENANTS_PATH, "GET", admin_key
    )
    if status != 200:
        raise RuntimeError(
            f"list tenants failed: status={status} body={payload}"
        )
    tenants = payload.get("_list", payload) if isinstance(payload, dict) else payload
    if not isinstance(tenants, list):
        return None
    for record in tenants:
        if isinstance(record, dict) and record.get("name") == tenant_label:
            tenant_uuid = record.get("id")
            if isinstance(tenant_uuid, str) and tenant_uuid:
                return tenant_uuid
    return None


def rotate_admin_key(
    *,
    tenant_id: str,
    proxy_instance_id: str,
    proxy_spec: ComponentSpec,
    new_key: Optional[str] = None,
    proxy_name_template: str = DEFAULT_PROXY_NAME_TEMPLATE,
    client: Optional[BasilicaClient] = None,
) -> RotationResult:
    """Rotate the admin key on a live proxy deployment.

    Generates a fresh `llmt_<64-hex>` key if `new_key` is not supplied,
    rebuilds the proxy with `LLMTRACE_AUTH_ADMIN_KEY=<new_key>` in its env,
    waits for readiness, and returns the new plaintext + new InstanceInfo.

    Mechanism: the Basilica SDK exposes no env-patch primitive — only
    `create_deployment`, `delete_deployment`, and `restart_deployment`
    (which rolls pods without touching env). Rotation therefore deletes
    the existing proxy UUID and creates a fresh one with the rotated env.
    Consequence: `proxy_instance_id` and `proxy.url` change. The caller
    MUST persist `result.proxy.instance_id` over the old UUID.

    Idempotent on retry only insofar as the caller passes the (possibly
    already-deleted) old UUID — `_safe_delete` no-ops on 404. A successful
    re-run still creates a fresh proxy with a fresh key.
    """
    tenant_id = validate_tenant_id(tenant_id)
    if not proxy_instance_id:
        raise ValueError("proxy_instance_id is required")
    client = client or make_client()
    rotated_key = new_key or generate_api_key()

    new_env = {**proxy_spec.env, "LLMTRACE_AUTH_ADMIN_KEY": rotated_key}
    new_env.setdefault("LLMTRACE_AUTH_ENABLED", "true")
    rotated_spec = dataclasses.replace(proxy_spec, env=new_env)
    rotated_spec = _apply_ml_preload_startup_floor(rotated_spec, tenant_id=tenant_id)

    proxy_name = proxy_name_template.format(tenant_id=_basilica_slug(tenant_id))
    LOGGER.info(
        "rotating admin key tenant=%s old_proxy=%s", tenant_id, proxy_instance_id
    )
    _safe_delete(client, proxy_instance_id, "proxy")
    new_proxy = _create_component(client, proxy_name, rotated_spec)
    LOGGER.info(
        "rotated admin key tenant=%s new_proxy=%s", tenant_id, new_proxy.instance_id
    )
    return RotationResult(tenant_id=tenant_id, proxy=new_proxy, admin_key=rotated_key)


def provision(
    spec: TenantSpec, client: Optional[BasilicaClient] = None
) -> TenantInstances:
    """Provision a fresh proxy + dashboard pair with scoped runtime auth.

    This always creates new Basilica deployments. The caller MUST track
    the returned `instance_id`s to perform any subsequent lifecycle
    operations (status / update / deprovision) — Basilica does not expose
    a friendly-name → UUID lookup, so the IDs cannot be rediscovered.

    When `spec.enable_proxy_auth` is True (default), the function:

    1. Resolves a bootstrap admin key (explicit `spec.api_key` > existing
       `LLMTRACE_AUTH_ADMIN_KEY` in proxy env > auto-generated). Injects
       it into both proxy and dashboard envs as `LLMTRACE_AUTH_ADMIN_KEY`.
    2. Creates the proxy and waits for it to become ready.
    3. Calls `POST /api/v1/tenants` on the live proxy to materialise a
       tenant row (the operator-key mint requires the tenant to exist).
    4. Calls `POST /api/v1/auth/keys` to mint a scoped Operator-role key
       named `tenant-runtime`. This is the key the tenant gets.
    5. Deploys the dashboard. Only the admin key is in the dashboard env
       because the dashboard's only call path today is the proxy's admin
       endpoints; the operator key is returned to the caller for the
       tenant's external runtime apps.

    Returns both keys: `api_key` is the operator key (runtime traffic);
    `admin_key` is the bootstrap admin key (retained by the caller for
    self-service / admin portal use, never given to tenants).
    """
    tenant_id = validate_tenant_id(spec.tenant_id)
    client = client or make_client()
    slug = _basilica_slug(tenant_id)
    proxy_name = spec.proxy_name_template.format(tenant_id=slug)
    dashboard_name = spec.dashboard_name_template.format(tenant_id=slug)

    admin_key = _resolve_api_key(spec)
    proxy_spec, dashboard_spec = (spec.proxy, spec.dashboard)
    if admin_key is not None:
        proxy_spec, dashboard_spec = _apply_proxy_auth(
            proxy_spec, dashboard_spec, admin_key
        )
    if spec.rate_limit is not None:
        proxy_spec = _apply_rate_limit(proxy_spec, spec.rate_limit)
    proxy_spec = _apply_ml_preload_startup_floor(proxy_spec, tenant_id=tenant_id)
    _warn_on_unsharable_replicas(proxy_spec, tenant_id)

    proxy = _create_component(client, proxy_name, proxy_spec)

    operator_key: Optional[str] = None
    if admin_key is not None:
        # Rotate admin key BEFORE minting the operator key. Rotation
        # deletes + recreates the proxy (the Basilica SDK has no env-patch
        # primitive), which resets the proxy DB — so any tenant / operator
        # key minted beforehand would be lost. Sequencing rotation first
        # also ensures the dashboard is only ever deployed with the
        # post-rotation operator key.
        if spec.rotate_admin_after_bootstrap:
            rotation = rotate_admin_key(
                tenant_id=tenant_id,
                proxy_instance_id=proxy.instance_id,
                proxy_spec=proxy_spec,
                proxy_name_template=spec.proxy_name_template,
                client=client,
            )
            proxy = rotation.proxy
            admin_key = rotation.admin_key

        tenant_uuid = _bootstrap_tenant_in_proxy(proxy.url, admin_key, tenant_id)
        operator_key = _mint_operator_key(proxy.url, admin_key, tenant_uuid)
    else:
        tenant_uuid = None

    dashboard_spec = _apply_dashboard_admin_username(
        dashboard_spec, spec.admin_username
    )

    if spec.inject_proxy_url_into_dashboard:
        merged_env = {**dashboard_spec.env, spec.proxy_url_env_var: proxy.url}
        dashboard_spec = dataclasses.replace(dashboard_spec, env=merged_env)

    # Pin the dashboard's upstream calls to the provisioned tenant. Without
    # this, admin-key calls (the dashboard's only auth path today) cause the
    # proxy to attribute each request to a new "phantom" tenant — see the
    # /traces emptiness incident: traces persist correctly but scatter across
    # 16+ tenants per day, making the dashboard's tenant-filtered views
    # appear empty. The proxy honours `X-LLMTrace-Tenant-ID` when supplied
    # alongside an admin key; the dashboard injects this env value as that
    # header in `proxy-helpers.ts::buildHeaders`.
    if tenant_uuid:
        merged_env = {
            **dashboard_spec.env,
            "LLMTRACE_DASHBOARD_TENANT_ID": tenant_uuid,
        }
        dashboard_spec = dataclasses.replace(dashboard_spec, env=merged_env)

    dashboard = _create_component(client, dashboard_name, dashboard_spec)

    return TenantInstances(
        tenant_id=tenant_id,
        proxy=proxy,
        dashboard=dashboard,
        api_key=operator_key,
        admin_key=admin_key,
        admin_username=spec.admin_username,
    )


def _verify_or_remint_operator_key(
    spec: TenantSpec, proxy_url: str
) -> tuple[Optional[str], Optional[str]]:
    """For restart-strategy updates, check whether the operator key survived.

    Returns `(admin_key, operator_key_plaintext_or_None)`. The plaintext
    operator key is only present when this function had to re-mint it
    (the prior key plaintext is unknown to the platform — only its hash
    lives in the proxy DB). When the key record is still present, we
    return `None` for the operator key to signal "carry forward the
    previous value from the caller's DB; nothing changed".

    Tenant rediscovery: the proxy assigns the tenant UUID at create time;
    the lifecycle layer doesn't persist that UUID across calls. We
    therefore list tenants by admin and match on the supplied
    `spec.tenant_id` label (the same label used at provision time). If
    the label isn't found (DB was wiped despite the volume being
    "persistent"), we bootstrap a fresh tenant + operator key.
    """
    if not spec.enable_proxy_auth:
        return (None, None)
    admin_key = _resolve_api_key(spec)
    if admin_key is None:
        return (None, None)
    tenant_uuid = _find_tenant_by_label(proxy_url, admin_key, spec.tenant_id)
    if tenant_uuid is None:
        LOGGER.info(
            "restart: tenant label=%s not found in proxy DB — bootstrapping",
            spec.tenant_id,
        )
        tenant_uuid = _bootstrap_tenant_in_proxy(
            proxy_url, admin_key, spec.tenant_id
        )
        return (admin_key, _mint_operator_key(proxy_url, admin_key, tenant_uuid))
    existing = _find_operator_key_record(proxy_url, admin_key, tenant_uuid)
    if existing is not None:
        LOGGER.info(
            "restart: existing operator key found prefix=%s — keeping",
            existing.get("key_prefix"),
        )
        return (admin_key, None)
    LOGGER.info("restart: no operator key found — re-minting")
    return (admin_key, _mint_operator_key(proxy_url, admin_key, tenant_uuid))


def update(
    spec: TenantSpec,
    proxy_instance_id: str,
    dashboard_instance_id: str,
    strategy: str = "recreate",
    client: Optional[BasilicaClient] = None,
) -> TenantInstances:
    """Update the pair, addressed by caller-supplied UUIDs.

    `strategy="restart"` rolls the existing pods on the same volume; URLs
    and most config stay untouched. The proxy's DB survives, so the
    operator key minted at provision time persists. The function verifies
    the key record still exists; if absent (e.g. DB wipe), a fresh
    operator key is minted and returned via `api_key`. When the key is
    intact, `api_key` is None — the caller carries forward the
    previously-stored plaintext from its own secret store.

    `strategy="recreate"` deletes both UUIDs and creates fresh ones from
    `spec`. The DB is gone, so the operator key is always re-minted.
    URLs change — return value carries the NEW UUIDs the caller must
    persist along with the new `api_key`.
    """
    tenant_id = validate_tenant_id(spec.tenant_id)
    client = client or make_client()

    if strategy == "restart":
        LOGGER.info("restarting proxy instance_id=%s", proxy_instance_id)
        client.restart_deployment(proxy_instance_id)
        LOGGER.info("restarting dashboard instance_id=%s", dashboard_instance_id)
        client.restart_deployment(dashboard_instance_id)
        proxy = _wait_until_ready(
            client,
            proxy_instance_id,
            spec.proxy.startup_timeout_seconds,
            expected_replicas=spec.proxy.replicas,
        )
        dashboard = _wait_until_ready(
            client,
            dashboard_instance_id,
            spec.dashboard.startup_timeout_seconds,
            expected_replicas=spec.dashboard.replicas,
        )
        admin_key, operator_key = _verify_or_remint_operator_key(spec, proxy.url)
        return TenantInstances(
            tenant_id=tenant_id,
            proxy=proxy,
            dashboard=dashboard,
            api_key=operator_key,
            admin_key=admin_key,
            admin_username=spec.admin_username,
        )

    if strategy != "recreate":
        raise ValueError(
            f"strategy must be 'restart' or 'recreate', got {strategy!r}"
        )

    LOGGER.info(
        "recreating tenant=%s — deleting dashboard then proxy", tenant_id
    )
    _safe_delete(client, dashboard_instance_id, "dashboard")
    _safe_delete(client, proxy_instance_id, "proxy")
    return provision(spec, client=client)


def deprovision(
    tenant_id: str,
    proxy_instance_id: Optional[str] = None,
    dashboard_instance_id: Optional[str] = None,
    client: Optional[BasilicaClient] = None,
) -> TenantInstances:
    """Delete the supplied UUIDs. Missing IDs are skipped (idempotent)."""
    tenant_id = validate_tenant_id(tenant_id)
    client = client or make_client()
    _safe_delete(client, dashboard_instance_id, "dashboard")
    _safe_delete(client, proxy_instance_id, "proxy")
    return TenantInstances(tenant_id=tenant_id, proxy=None, dashboard=None)


def status(
    tenant_id: str,
    proxy_instance_id: Optional[str] = None,
    dashboard_instance_id: Optional[str] = None,
    client: Optional[BasilicaClient] = None,
) -> TenantInstances:
    """Read state for the supplied UUIDs. Returns None for absent/missing IDs."""
    tenant_id = validate_tenant_id(tenant_id)
    client = client or make_client()
    return TenantInstances(
        tenant_id=tenant_id,
        proxy=_safe_get(client, proxy_instance_id),
        dashboard=_safe_get(client, dashboard_instance_id),
    )
