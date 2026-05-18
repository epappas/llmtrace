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
import logging
import os
import re
import secrets as _secrets
import time
from dataclasses import dataclass
from typing import Mapping, Optional

from basilica import (
    BasilicaClient,
    HealthCheckConfig,
    ProbeConfig,
)

LOGGER = logging.getLogger(__name__)

# DNS-safe slug, ≤30 chars to leave headroom for friendly-name prefixes.
TENANT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")

POLL_INTERVAL_SECONDS = 10

DEFAULT_PROXY_NAME_TEMPLATE = "llmtrace-proxy-{tenant_id}"
DEFAULT_DASHBOARD_NAME_TEMPLATE = "llmtrace-dashboard-{tenant_id}"

# LLMTrace API key format — matches `crates/llmtrace-proxy/src/auth.rs::generate_api_key`.
API_KEY_PREFIX = "llmt_"
API_KEY_RANDOM_BYTES = 32


def generate_api_key() -> str:
    """Generate an LLMTrace-compatible API key.

    Format: `llmt_` + 32 random bytes hex-encoded (64 hex chars).
    Matches the layout produced by the Rust proxy so a generated key drops
    straight into `LLMTRACE_AUTH_ADMIN_KEY` without translation.
    """
    return API_KEY_PREFIX + _secrets.token_hex(API_KEY_RANDOM_BYTES)


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

    `api_key` is populated only on `provision()` and `update(..., strategy="recreate")`;
    it is the plaintext bearer the tenant must send as `Authorization: Bearer <key>`
    on every non-`/health` request to the proxy. None on `status` / `deprovision`
    and when `enable_proxy_auth=False`.
    """

    tenant_id: str
    proxy: Optional[InstanceInfo]
    dashboard: Optional[InstanceInfo]
    api_key: Optional[str] = None


def validate_tenant_id(tenant_id: str) -> str:
    if not TENANT_ID_PATTERN.match(tenant_id):
        raise ValueError(
            f"tenant_id {tenant_id!r} must match {TENANT_ID_PATTERN.pattern}"
        )
    return tenant_id


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
    proxy_spec: ComponentSpec, dashboard_spec: ComponentSpec, api_key: str
) -> tuple[ComponentSpec, ComponentSpec]:
    """Inject `LLMTRACE_AUTH_ENABLED=true` + the admin key into both envs.

    The admin key is set unconditionally (we want proxy + dashboard
    consistent); `LLMTRACE_AUTH_ENABLED` is only defaulted (caller may
    explicitly turn it off in env).
    """
    proxy_env = {**proxy_spec.env, "LLMTRACE_AUTH_ADMIN_KEY": api_key}
    proxy_env.setdefault("LLMTRACE_AUTH_ENABLED", "true")
    dashboard_env = {**dashboard_spec.env, "LLMTRACE_AUTH_ADMIN_KEY": api_key}
    return (
        dataclasses.replace(proxy_spec, env=proxy_env),
        dataclasses.replace(dashboard_spec, env=dashboard_env),
    )


def provision(
    spec: TenantSpec, client: Optional[BasilicaClient] = None
) -> TenantInstances:
    """Provision a fresh proxy + dashboard pair.

    This always creates new Basilica deployments. The caller MUST track
    the returned `instance_id`s to perform any subsequent lifecycle
    operations (status / update / deprovision) — Basilica does not expose
    a friendly-name → UUID lookup, so the IDs cannot be rediscovered.

    If `spec.enable_proxy_auth` is True (default), an LLMTrace API key
    is resolved (explicit > env > auto-generated) and injected into both
    component envs as `LLMTRACE_AUTH_ADMIN_KEY`. The plaintext key is
    returned in `TenantInstances.api_key` so the caller can persist it
    and hand it to the tenant — it's the only time the key is exposed.

    To make provision *idempotent at the caller*: before calling, check
    your own DB for existing IDs; if found, call `status(...)` with those
    IDs instead.
    """
    tenant_id = validate_tenant_id(spec.tenant_id)
    client = client or make_client()
    proxy_name = spec.proxy_name_template.format(tenant_id=tenant_id)
    dashboard_name = spec.dashboard_name_template.format(tenant_id=tenant_id)

    api_key = _resolve_api_key(spec)
    proxy_spec, dashboard_spec = (spec.proxy, spec.dashboard)
    if api_key is not None:
        proxy_spec, dashboard_spec = _apply_proxy_auth(
            proxy_spec, dashboard_spec, api_key
        )

    proxy = _create_component(client, proxy_name, proxy_spec)

    if spec.inject_proxy_url_into_dashboard:
        merged_env = {**dashboard_spec.env, spec.proxy_url_env_var: proxy.url}
        dashboard_spec = dataclasses.replace(dashboard_spec, env=merged_env)
    dashboard = _create_component(client, dashboard_name, dashboard_spec)

    return TenantInstances(
        tenant_id=tenant_id, proxy=proxy, dashboard=dashboard, api_key=api_key
    )


def update(
    spec: TenantSpec,
    proxy_instance_id: str,
    dashboard_instance_id: str,
    strategy: str = "recreate",
    client: Optional[BasilicaClient] = None,
) -> TenantInstances:
    """Update the pair, addressed by caller-supplied UUIDs.

    `strategy="restart"` rolls the existing pods; URLs and config stay
    untouched. `spec` is consulted only for timeouts.

    `strategy="recreate"` deletes both UUIDs and creates fresh ones from
    `spec`. URLs change — return value carries the NEW UUIDs the caller
    must persist.
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
        return TenantInstances(tenant_id=tenant_id, proxy=proxy, dashboard=dashboard)

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
