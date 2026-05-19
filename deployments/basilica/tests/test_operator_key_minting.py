"""Tests for the lifecycle library's proxy admin-API client.

Scope: the HTTP boundary against the LLMTrace proxy admin API
(`POST /api/v1/tenants`, `POST /api/v1/auth/keys`, `GET /api/v1/auth/keys`,
`GET /api/v1/tenants`). We spin up a real `http.server` on a loopback
port so the helpers exercise their actual urllib code path including
header serialisation, JSON encoding, and HTTP error handling. The proxy
itself is replaced by a deterministic handler so assertions are stable.

The Basilica SDK boundary is mocked via fake client objects in the
provision integration test; we never hit Basilica or a real proxy here.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Optional

import pytest

from deployments.basilica import lifecycle


# ---------------------------------------------------------------------------
# Test fixtures: in-process fake proxy admin API
# ---------------------------------------------------------------------------


class _RecordingHandler(BaseHTTPRequestHandler):
    """HTTP handler that delegates routing to a `responder` callable."""

    responder: Callable[[str, str, dict[str, str], bytes], tuple[int, dict[str, Any]]]
    recorded: list[dict[str, Any]]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Silence default stderr logging during tests.
        return

    def _dispatch(self, method: str) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        headers = {k.lower(): v for k, v in self.headers.items()}
        self.recorded.append(
            {"method": method, "path": self.path, "headers": headers, "body": body}
        )
        status, payload = self.responder(method, self.path, headers, body)
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")


class FakeProxy:
    """Wraps an HTTPServer thread so tests can drive it programmatically."""

    def __init__(
        self,
        responder: Callable[[str, str, dict[str, str], bytes], tuple[int, dict[str, Any]]],
    ) -> None:
        self.recorded: list[dict[str, Any]] = []
        handler_cls = type(
            "Handler",
            (_RecordingHandler,),
            {"responder": staticmethod(responder), "recorded": self.recorded},
        )
        self.server = HTTPServer(("127.0.0.1", 0), handler_cls)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@pytest.fixture
def fake_proxy() -> Any:
    """Build a fake proxy via a `make(responder)` callable. Cleanup is automatic."""
    servers: list[FakeProxy] = []

    def make(responder: Callable[..., tuple[int, dict[str, Any]]]) -> FakeProxy:
        s = FakeProxy(responder)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.shutdown()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


ADMIN_KEY = "llmt_" + "a" * 64
OPERATOR_KEY = "llmt_" + "b" * 64
TENANT_UUID = "11111111-1111-4111-8111-111111111111"


def _tenant_create_payload() -> dict[str, Any]:
    return {
        "id": TENANT_UUID,
        "name": "acme",
        "api_token": "x-llmtrace-token-stub",
        "plan": "default",
        "created_at": "2026-01-01T00:00:00Z",
        "config": {},
        "api_key": "llmt_" + "c" * 64,
    }


def _key_create_payload() -> dict[str, Any]:
    return {
        "id": "22222222-2222-4222-8222-222222222222",
        "key": OPERATOR_KEY,
        "key_prefix": OPERATOR_KEY[:8],
        "tenant_id": TENANT_UUID,
        "role": "operator",
        "created_at": "2026-01-01T00:00:00Z",
    }


# ---------------------------------------------------------------------------
# _admin_http_request: header / encoding contract
# ---------------------------------------------------------------------------


def test_admin_http_request_sends_bearer_and_tenant_header(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 200, {"echo": path}

    proxy = fake_proxy(responder)
    status, payload = lifecycle._admin_http_request(
        proxy.url, "/api/v1/auth/keys", "GET", ADMIN_KEY, tenant_uuid=TENANT_UUID
    )
    assert status == 200
    assert payload == {"echo": "/api/v1/auth/keys"}
    rec = proxy.recorded[-1]
    assert rec["headers"]["authorization"] == f"Bearer {ADMIN_KEY}"
    assert rec["headers"]["x-llmtrace-tenant-id"] == TENANT_UUID


def test_admin_http_request_parses_error_body(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 404, {"error": {"message": "Tenant not found", "type": "api_error"}}

    proxy = fake_proxy(responder)
    status, payload = lifecycle._admin_http_request(
        proxy.url, "/api/v1/auth/keys", "POST", ADMIN_KEY,
        tenant_uuid=TENANT_UUID, body={"name": "x", "role": "operator", "tenant_id": TENANT_UUID},
    )
    assert status == 404
    assert payload["error"]["message"] == "Tenant not found"


# ---------------------------------------------------------------------------
# _bootstrap_tenant_in_proxy
# ---------------------------------------------------------------------------


def test_bootstrap_tenant_returns_uuid(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        assert method == "POST" and path == "/api/v1/tenants"
        assert headers["authorization"] == f"Bearer {ADMIN_KEY}"
        decoded = json.loads(body)
        assert decoded["name"] == "acme"
        assert decoded["plan"] == "default"
        return 201, _tenant_create_payload()

    proxy = fake_proxy(responder)
    uuid = lifecycle._bootstrap_tenant_in_proxy(proxy.url, ADMIN_KEY, "acme")
    assert uuid == TENANT_UUID


def test_bootstrap_tenant_raises_on_non_201(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 500, {"error": {"message": "boom"}}

    proxy = fake_proxy(responder)
    with pytest.raises(RuntimeError, match="tenant bootstrap failed"):
        lifecycle._bootstrap_tenant_in_proxy(proxy.url, ADMIN_KEY, "acme")


def test_bootstrap_tenant_raises_when_id_missing(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 201, {"name": "acme"}  # malformed: no id

    proxy = fake_proxy(responder)
    with pytest.raises(RuntimeError, match="missing 'id'"):
        lifecycle._bootstrap_tenant_in_proxy(proxy.url, ADMIN_KEY, "acme")


# ---------------------------------------------------------------------------
# _mint_operator_key
# ---------------------------------------------------------------------------


def test_mint_operator_key_sends_correct_body(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        assert method == "POST" and path == "/api/v1/auth/keys"
        assert headers["x-llmtrace-tenant-id"] == TENANT_UUID
        decoded = json.loads(body)
        assert decoded == {
            "name": "tenant-runtime",
            "role": "operator",
            "tenant_id": TENANT_UUID,
        }
        return 201, _key_create_payload()

    proxy = fake_proxy(responder)
    key = lifecycle._mint_operator_key(proxy.url, ADMIN_KEY, TENANT_UUID)
    assert key == OPERATOR_KEY


def test_mint_operator_key_rejects_bad_response(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 201, {"id": "abc"}  # no `key` field

    proxy = fake_proxy(responder)
    with pytest.raises(RuntimeError, match="unexpected body"):
        lifecycle._mint_operator_key(proxy.url, ADMIN_KEY, TENANT_UUID)


def test_mint_operator_key_rejects_wrong_prefix(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 201, {**_key_create_payload(), "key": "wrong-prefix-key"}

    proxy = fake_proxy(responder)
    with pytest.raises(RuntimeError, match="unexpected body"):
        lifecycle._mint_operator_key(proxy.url, ADMIN_KEY, TENANT_UUID)


def test_mint_operator_key_propagates_http_error(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 403, {"error": {"message": "Insufficient permissions"}}

    proxy = fake_proxy(responder)
    with pytest.raises(RuntimeError, match="mint failed"):
        lifecycle._mint_operator_key(proxy.url, ADMIN_KEY, TENANT_UUID)


# ---------------------------------------------------------------------------
# Restart-flow helpers
# ---------------------------------------------------------------------------


def test_find_tenant_by_label_matches_existing(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        # List returned as a top-level JSON array.
        return 200, {
            "_list": [
                {"id": "other-uuid", "name": "not-acme"},
                {"id": TENANT_UUID, "name": "acme"},
            ]
        }

    # The fake returns dict-wrapped to exercise the `_list` shim path
    # we use for top-level arrays in `_admin_http_request`. Real proxy
    # returns a JSON array which becomes `{"_list": [...]}` after our
    # parser massages it.
    proxy = fake_proxy(responder)
    uuid = lifecycle._find_tenant_by_label(proxy.url, ADMIN_KEY, "acme")
    assert uuid == TENANT_UUID


def test_find_tenant_by_label_returns_none_when_absent(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 200, {"_list": []}

    proxy = fake_proxy(responder)
    assert lifecycle._find_tenant_by_label(proxy.url, ADMIN_KEY, "acme") is None


def test_find_operator_key_record_filters_by_name_role_and_revoked(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        return 200, {
            "_list": [
                {"name": "tenant-runtime", "role": "admin", "revoked_at": None, "key_prefix": "p1"},
                {"name": "other", "role": "operator", "revoked_at": None, "key_prefix": "p2"},
                {"name": "tenant-runtime", "role": "operator", "revoked_at": "2026-01-01T00:00:00Z", "key_prefix": "p3"},
                {"name": "tenant-runtime", "role": "operator", "revoked_at": None, "key_prefix": "p4"},
            ]
        }

    proxy = fake_proxy(responder)
    record = lifecycle._find_operator_key_record(proxy.url, ADMIN_KEY, TENANT_UUID)
    assert record is not None and record["key_prefix"] == "p4"


# ---------------------------------------------------------------------------
# Dashboard env injection
# ---------------------------------------------------------------------------


def _make_dashboard_spec(env: Optional[dict[str, str]] = None) -> lifecycle.ComponentSpec:
    return lifecycle.ComponentSpec(
        image="ghcr.io/example/dashboard:latest",
        port=3000,
        cpu="1",
        memory="1Gi",
        replicas=1,
        env=env or {"HOSTNAME": "0.0.0.0"},
    )


def test_inject_runtime_key_adds_var_without_dropping_existing() -> None:
    spec = _make_dashboard_spec({"HOSTNAME": "0.0.0.0", "LLMTRACE_AUTH_ADMIN_KEY": ADMIN_KEY})
    updated = lifecycle._inject_runtime_key_into_dashboard(spec, OPERATOR_KEY)
    assert updated.env["HOSTNAME"] == "0.0.0.0"
    assert updated.env["LLMTRACE_AUTH_ADMIN_KEY"] == ADMIN_KEY
    assert updated.env["LLMTRACE_AUTH_RUNTIME_KEY"] == OPERATOR_KEY


def test_apply_proxy_auth_sets_admin_key_on_both_sides() -> None:
    proxy_spec = lifecycle.ComponentSpec(
        image="i", port=8080, cpu="1", memory="1Gi", replicas=1, env={"X": "1"}
    )
    dash_spec = _make_dashboard_spec()
    p, d = lifecycle._apply_proxy_auth(proxy_spec, dash_spec, ADMIN_KEY)
    assert p.env["LLMTRACE_AUTH_ADMIN_KEY"] == ADMIN_KEY
    assert p.env["LLMTRACE_AUTH_ENABLED"] == "true"
    assert d.env["LLMTRACE_AUTH_ADMIN_KEY"] == ADMIN_KEY
    # Runtime key is NOT injected here; that happens after the proxy is
    # live and the operator key has been minted.
    assert "LLMTRACE_AUTH_RUNTIME_KEY" not in d.env


# ---------------------------------------------------------------------------
# TenantInstances shape
# ---------------------------------------------------------------------------


def test_tenant_instances_carries_both_keys() -> None:
    inst = lifecycle.TenantInstances(
        tenant_id="acme",
        proxy=None,
        dashboard=None,
        api_key=OPERATOR_KEY,
        admin_key=ADMIN_KEY,
    )
    assert inst.api_key == OPERATOR_KEY
    assert inst.admin_key == ADMIN_KEY


def test_tenant_instances_admin_key_defaults_to_none() -> None:
    inst = lifecycle.TenantInstances(
        tenant_id="acme",
        proxy=None,
        dashboard=None,
    )
    assert inst.api_key is None
    assert inst.admin_key is None


# ---------------------------------------------------------------------------
# CLI serialisation
# ---------------------------------------------------------------------------


def test_cli_serialise_emits_admin_key_alongside_api_key() -> None:
    from deployments.basilica import cli

    inst = lifecycle.TenantInstances(
        tenant_id="acme",
        proxy=lifecycle.InstanceInfo(
            instance_id="proxy-uuid",
            state="running",
            url="https://proxy.example",
            ready_replicas=1,
            desired_replicas=1,
        ),
        dashboard=lifecycle.InstanceInfo(
            instance_id="dash-uuid",
            state="running",
            url="https://dash.example",
            ready_replicas=1,
            desired_replicas=1,
        ),
        api_key=OPERATOR_KEY,
        admin_key=ADMIN_KEY,
    )
    payload = cli._serialise(inst)
    assert payload["api_key"] == OPERATOR_KEY
    assert payload["admin_key"] == ADMIN_KEY
    assert payload["proxy_instance_id"] == "proxy-uuid"
    assert payload["dashboard_instance_id"] == "dash-uuid"
    assert payload["proxy_url"] == "https://proxy.example"
    assert payload["dashboard_url"] == "https://dash.example"


# ---------------------------------------------------------------------------
# provision() integration: real lifecycle code, mocked HTTP + Basilica client
# ---------------------------------------------------------------------------


class _FakeReplicas:
    def __init__(self, ready: int, desired: int) -> None:
        self.ready = ready
        self.desired = desired


class _FakeDetail:
    def __init__(self, instance_name: str, url: str) -> None:
        self.instance_name = instance_name
        self.state = "running"
        self.url = url
        self.replicas = _FakeReplicas(1, 1)
        self.phase = "ready"
        self.message = None


class _FakeBasilicaClient:
    """Captures create_deployment / get_deployment calls and returns canned details."""

    def __init__(self, proxy_url: str, dashboard_url: str) -> None:
        self.proxy_url = proxy_url
        self.dashboard_url = dashboard_url
        self.creates: list[dict[str, Any]] = []

    def create_deployment(self, **kwargs: Any) -> _FakeDetail:
        name = kwargs.get("instance_name", "")
        self.creates.append(kwargs)
        if "proxy" in name:
            return _FakeDetail(instance_name="proxy-uuid", url=self.proxy_url)
        return _FakeDetail(instance_name="dash-uuid", url=self.dashboard_url)

    def get_deployment(self, instance_name: str) -> _FakeDetail:
        if instance_name == "proxy-uuid":
            return _FakeDetail(instance_name="proxy-uuid", url=self.proxy_url)
        return _FakeDetail(instance_name="dash-uuid", url=self.dashboard_url)


def test_provision_returns_operator_key_as_api_key_and_admin_key_separately(
    fake_proxy: Any,
) -> None:
    """End-to-end provision flow: bootstrap tenant -> mint operator -> inject into dashboard."""

    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        if method == "POST" and path == "/api/v1/tenants":
            return 201, _tenant_create_payload()
        if method == "POST" and path == "/api/v1/auth/keys":
            return 201, _key_create_payload()
        raise AssertionError(f"unexpected request: {method} {path}")

    proxy = fake_proxy(responder)
    fake_client = _FakeBasilicaClient(
        proxy_url=proxy.url,
        dashboard_url="https://dashboard.example",
    )

    proxy_spec = lifecycle.ComponentSpec(
        image="ghcr.io/example/proxy:latest",
        port=8080,
        cpu="1",
        memory="1Gi",
        replicas=1,
        env={"LLMTRACE_UPSTREAM_URL": "https://upstream.example"},
    )
    dash_spec = _make_dashboard_spec()
    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=proxy_spec,
        dashboard=dash_spec,
        api_key=ADMIN_KEY,  # pin admin key so we can assert exact value
    )

    result = lifecycle.provision(spec, client=fake_client)

    assert result.api_key == OPERATOR_KEY, "operator key returned as runtime api_key"
    assert result.admin_key == ADMIN_KEY, "bootstrap admin key returned separately"
    assert result.tenant_id == "acme"
    assert result.proxy is not None and result.proxy.instance_id == "proxy-uuid"
    assert result.dashboard is not None and result.dashboard.instance_id == "dash-uuid"

    # Verify proxy was created with the admin key in env.
    proxy_create = next(c for c in fake_client.creates if "proxy" in c["instance_name"])
    assert proxy_create["env"]["LLMTRACE_AUTH_ADMIN_KEY"] == ADMIN_KEY
    assert proxy_create["env"]["LLMTRACE_AUTH_ENABLED"] == "true"

    # Verify dashboard was created with BOTH admin and runtime keys in env.
    dash_create = next(c for c in fake_client.creates if "dashboard" in c["instance_name"])
    assert dash_create["env"]["LLMTRACE_AUTH_ADMIN_KEY"] == ADMIN_KEY
    assert dash_create["env"]["LLMTRACE_AUTH_RUNTIME_KEY"] == OPERATOR_KEY


def test_provision_skips_key_flow_when_proxy_auth_disabled(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        raise AssertionError(f"no HTTP call expected: {method} {path}")

    proxy = fake_proxy(responder)
    fake_client = _FakeBasilicaClient(
        proxy_url=proxy.url, dashboard_url="https://dashboard.example"
    )
    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=lifecycle.ComponentSpec(
            image="i", port=8080, cpu="1", memory="1Gi", replicas=1, env={},
        ),
        dashboard=_make_dashboard_spec(),
        enable_proxy_auth=False,
    )
    result = lifecycle.provision(spec, client=fake_client)
    assert result.api_key is None
    assert result.admin_key is None
    # No HTTP calls were made (no recorded requests because the fake never received any).
    assert proxy.recorded == []
