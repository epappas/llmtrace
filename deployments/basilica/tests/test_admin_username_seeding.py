"""Tests for the admin-credential seeding feature.

Verifies that:
- `TenantSpec.admin_username` defaults to `"admin"` and is propagated to the
  dashboard env as `LLMTRACE_DASHBOARD_ADMIN_USERNAME`.
- A caller-supplied `admin_username` overrides the default.
- The same value flows through to `TenantInstances.admin_username` and the
  CLI's serialised result JSON.
- `_apply_dashboard_admin_username` overwrites a caller-supplied env entry
  with the same key (TenantSpec is the source of truth).

These tests exercise the real lifecycle code paths against a fake Basilica
SDK + the existing fake-proxy fixture. No production logic is stubbed.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from deployments.basilica import cli, lifecycle

# Re-use the helpers from the existing test module.
from deployments.basilica.tests.test_operator_key_minting import (  # type: ignore[import-not-found]
    ADMIN_KEY,
    OPERATOR_KEY,
    _FakeBasilicaClient,
    _key_create_payload,
    _make_dashboard_spec,
    _tenant_create_payload,
)


def _proxy_spec() -> lifecycle.ComponentSpec:
    return lifecycle.ComponentSpec(
        image="ghcr.io/example/proxy:latest",
        port=8080,
        cpu="1",
        memory="1Gi",
        replicas=1,
        env={"LLMTRACE_UPSTREAM_URL": "https://upstream.example"},
    )


def test_apply_dashboard_admin_username_injects_env_var() -> None:
    base = lifecycle.ComponentSpec(
        image="i", port=3000, cpu="1", memory="1Gi", replicas=1,
        env={"HOSTNAME": "0.0.0.0"},
    )
    result = lifecycle._apply_dashboard_admin_username(base, "alice@acme.example")
    assert result.env["LLMTRACE_DASHBOARD_ADMIN_USERNAME"] == "alice@acme.example"
    assert result.env["HOSTNAME"] == "0.0.0.0", "unrelated env entries preserved"
    assert base.env.get("LLMTRACE_DASHBOARD_ADMIN_USERNAME") is None, "input spec unchanged"


def test_apply_dashboard_admin_username_overrides_caller_env() -> None:
    base = lifecycle.ComponentSpec(
        image="i", port=3000, cpu="1", memory="1Gi", replicas=1,
        env={"LLMTRACE_DASHBOARD_ADMIN_USERNAME": "stale"},
    )
    result = lifecycle._apply_dashboard_admin_username(base, "fresh")
    assert result.env["LLMTRACE_DASHBOARD_ADMIN_USERNAME"] == "fresh"


def test_tenant_spec_admin_username_defaults_to_admin() -> None:
    spec = lifecycle.TenantSpec(
        tenant_id="t",
        proxy=_proxy_spec(),
        dashboard=_make_dashboard_spec(),
    )
    assert spec.admin_username == "admin"


def test_provision_seeds_default_admin_username(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        if method == "POST" and path == "/api/v1/tenants":
            return 201, _tenant_create_payload()
        if method == "POST" and path == "/api/v1/auth/keys":
            return 201, _key_create_payload()
        raise AssertionError(f"unexpected request: {method} {path}")

    proxy = fake_proxy(responder)
    fake_client = _FakeBasilicaClient(
        proxy_url=proxy.url, dashboard_url="https://dashboard.example"
    )
    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=_proxy_spec(),
        dashboard=_make_dashboard_spec(),
        api_key=ADMIN_KEY,
    )
    result = lifecycle.provision(spec, client=fake_client)

    assert result.admin_username == "admin"
    dash_create = next(c for c in fake_client.creates if "dashboard" in c["instance_name"])
    assert dash_create["env"]["LLMTRACE_DASHBOARD_ADMIN_USERNAME"] == "admin"


def test_provision_seeds_custom_admin_username(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        if method == "POST" and path == "/api/v1/tenants":
            return 201, _tenant_create_payload()
        if method == "POST" and path == "/api/v1/auth/keys":
            return 201, _key_create_payload()
        raise AssertionError(f"unexpected request: {method} {path}")

    proxy = fake_proxy(responder)
    fake_client = _FakeBasilicaClient(
        proxy_url=proxy.url, dashboard_url="https://dashboard.example"
    )
    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=_proxy_spec(),
        dashboard=_make_dashboard_spec(),
        api_key=ADMIN_KEY,
        admin_username="ops@acme.example",
    )
    result = lifecycle.provision(spec, client=fake_client)

    assert result.admin_username == "ops@acme.example"
    dash_create = next(c for c in fake_client.creates if "dashboard" in c["instance_name"])
    assert dash_create["env"]["LLMTRACE_DASHBOARD_ADMIN_USERNAME"] == "ops@acme.example"
    # Operator + admin keys still flow through unchanged.
    assert result.api_key == OPERATOR_KEY
    assert result.admin_key == ADMIN_KEY


def test_cli_serialise_emits_admin_username() -> None:
    inst = lifecycle.TenantInstances(
        tenant_id="t",
        proxy=lifecycle.InstanceInfo(
            instance_id="p", state="Active", url="https://p.example",
            ready_replicas=1, desired_replicas=1,
        ),
        dashboard=lifecycle.InstanceInfo(
            instance_id="d", state="Active", url="https://d.example",
            ready_replicas=1, desired_replicas=1,
        ),
        api_key=OPERATOR_KEY,
        admin_key=ADMIN_KEY,
        admin_username="ops@acme.example",
    )
    payload = cli._serialise(inst)
    assert payload["admin_username"] == "ops@acme.example"


def test_cli_serialise_admin_username_defaults_none_when_unset() -> None:
    inst = lifecycle.TenantInstances(
        tenant_id="t", proxy=None, dashboard=None,
    )
    payload = cli._serialise(inst)
    assert payload["admin_username"] is None


def test_cli_loads_admin_username_from_config() -> None:
    cfg = {
        "proxy": {
            "image": "i", "port": 8080, "cpu": "1", "memory": "1Gi",
            "replicas": 1, "env": {},
        },
        "dashboard": {
            "image": "i", "port": 3000, "cpu": "1", "memory": "1Gi",
            "replicas": 1, "env": {},
        },
        "admin_username": "alice@acme.example",
    }
    spec = cli._tenant_spec_from_config("t", cfg)
    assert spec.admin_username == "alice@acme.example"
