"""Tests for the provision-time catch-all tenant and operator-tenant sourcing.

Scope:
- `provision()` generates a fresh catch-all uuid, sets it on the proxy env as
  `LLMTRACE_DEFAULT_TENANT_ID` BEFORE the proxy is created, materialises a
  `catch-all` tenant row via `POST /api/v1/tenants`, and returns the id.
- The operator tenant id is caller-owned: a supplied `tenant_uuid` is used as
  the stable `id`; an empty one is freshly generated, used, returned, and a
  WARNING is logged.
- A guard test asserting the previously-hardcoded UUID `6ae1ab34...` appears
  nowhere in `pro.yaml`.

The proxy admin API is a real in-process `http.server` (reused pattern from
`test_operator_key_minting`); the Basilica SDK is a fake client. We never hit
a real backend.
"""

from __future__ import annotations

import json
import logging
import pathlib
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Optional

import pytest

from deployments.basilica import lifecycle


# ---------------------------------------------------------------------------
# In-process fake proxy admin API (mirrors test_operator_key_minting)
# ---------------------------------------------------------------------------


class _RecordingHandler(BaseHTTPRequestHandler):
    responder: Callable[[str, str, dict[str, str], bytes], tuple[int, dict[str, Any]]]
    recorded: list[dict[str, Any]]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
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
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
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
    servers: list[FakeProxy] = []

    def make(responder: Callable[..., tuple[int, dict[str, Any]]]) -> FakeProxy:
        s = FakeProxy(responder)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.shutdown()


# ---------------------------------------------------------------------------
# Fake Basilica client
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


ADMIN_KEY = "llmt_" + "a" * 64
OPERATOR_KEY = "llmt_" + "b" * 64


def _proxy_spec() -> lifecycle.ComponentSpec:
    return lifecycle.ComponentSpec(
        image="ghcr.io/example/proxy:latest",
        port=8080,
        cpu="1",
        memory="1Gi",
        replicas=1,
        env={"LLMTRACE_UPSTREAM_URL": "https://upstream.example"},
    )


def _dashboard_spec() -> lifecycle.ComponentSpec:
    return lifecycle.ComponentSpec(
        image="ghcr.io/example/dashboard:latest",
        port=3000,
        cpu="1",
        memory="1Gi",
        replicas=1,
        env={"HOSTNAME": "0.0.0.0"},
    )


def _echo_id_responder(
    tenants_seen: list[dict[str, Any]],
) -> Callable[..., tuple[int, dict[str, Any]]]:
    """Responder that echoes the posted tenant `id` (or mints one) so the
    lifecycle's "trust the returned id" path is exercised faithfully.

    Records each `POST /api/v1/tenants` body into `tenants_seen` so tests can
    assert which tenants were created (operator + catch-all) and with which
    explicit ids.
    """

    def responder(
        method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, Any]]:
        if method == "POST" and path == "/api/v1/tenants":
            decoded = json.loads(body)
            tenants_seen.append(decoded)
            tenant_id = decoded.get("id") or str(uuid.uuid4())
            return 201, {
                "id": tenant_id,
                "name": decoded.get("name"),
                "plan": decoded.get("plan", "default"),
                "config": {},
            }
        if method == "POST" and path == "/api/v1/auth/keys":
            return 201, {
                "id": "key-uuid",
                "key": OPERATOR_KEY,
                "key_prefix": OPERATOR_KEY[:8],
                "tenant_id": json.loads(body).get("tenant_id"),
                "role": "operator",
            }
        raise AssertionError(f"unexpected request: {method} {path}")

    return responder


# ---------------------------------------------------------------------------
# Catch-all tenant at provision (Option A)
# ---------------------------------------------------------------------------


def test_provision_generates_sets_creates_and_returns_catch_all(
    fake_proxy: Any,
) -> None:
    tenants_seen: list[dict[str, Any]] = []
    proxy = fake_proxy(_echo_id_responder(tenants_seen))
    client = _FakeBasilicaClient(proxy.url, "https://dashboard.example")

    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=_proxy_spec(),
        dashboard=_dashboard_spec(),
        api_key=ADMIN_KEY,
        tenant_uuid="33333333-3333-4333-8333-333333333333",
    )
    result = lifecycle.provision(spec, client=client)

    # A fresh catch-all id was returned, distinct from the operator tenant id.
    assert result.catch_all_tenant_id
    uuid.UUID(result.catch_all_tenant_id)  # parses as a real uuid
    assert result.catch_all_tenant_id != result.operator_tenant_id

    # It was set on the proxy env BEFORE create (so the proxy reads it at boot).
    proxy_create = next(c for c in client.creates if "proxy" in c["instance_name"])
    assert (
        proxy_create["env"]["LLMTRACE_DEFAULT_TENANT_ID"]
        == result.catch_all_tenant_id
    )

    # The catch-all tenant row was created via POST /api/v1/tenants with the
    # explicit id and the "catch-all" label.
    catch_all_posts = [
        t
        for t in tenants_seen
        if t.get("name") == lifecycle.CATCH_ALL_TENANT_LABEL
    ]
    assert len(catch_all_posts) == 1
    assert catch_all_posts[0]["id"] == result.catch_all_tenant_id

    # Exactly two tenant rows are created: the operator tenant and catch-all.
    assert len(tenants_seen) == 2


def test_provision_no_catch_all_when_auth_disabled(fake_proxy: Any) -> None:
    def responder(
        method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, Any]]:
        raise AssertionError(f"no HTTP call expected: {method} {path}")

    proxy = fake_proxy(responder)
    client = _FakeBasilicaClient(proxy.url, "https://dashboard.example")
    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=_proxy_spec(),
        dashboard=_dashboard_spec(),
        enable_proxy_auth=False,
    )
    result = lifecycle.provision(spec, client=client)

    assert result.catch_all_tenant_id is None
    assert result.operator_tenant_id is None
    proxy_create = next(c for c in client.creates if "proxy" in c["instance_name"])
    assert "LLMTRACE_DEFAULT_TENANT_ID" not in proxy_create["env"]


# ---------------------------------------------------------------------------
# Operator tenant id sourcing (caller-owned, no hardcode)
# ---------------------------------------------------------------------------


def test_supplied_tenant_uuid_is_used_as_stable_id(fake_proxy: Any) -> None:
    supplied = "44444444-4444-4444-8444-444444444444"
    tenants_seen: list[dict[str, Any]] = []
    proxy = fake_proxy(_echo_id_responder(tenants_seen))
    client = _FakeBasilicaClient(proxy.url, "https://dashboard.example")

    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=_proxy_spec(),
        dashboard=_dashboard_spec(),
        api_key=ADMIN_KEY,
        tenant_uuid=supplied,
    )
    result = lifecycle.provision(spec, client=client)

    assert result.operator_tenant_id == supplied
    operator_posts = [t for t in tenants_seen if t.get("name") == "acme"]
    assert len(operator_posts) == 1
    assert operator_posts[0]["id"] == supplied


def test_empty_tenant_uuid_generates_used_returned_and_warns(
    fake_proxy: Any, caplog: pytest.LogCaptureFixture
) -> None:
    tenants_seen: list[dict[str, Any]] = []
    proxy = fake_proxy(_echo_id_responder(tenants_seen))
    client = _FakeBasilicaClient(proxy.url, "https://dashboard.example")

    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=_proxy_spec(),
        dashboard=_dashboard_spec(),
        api_key=ADMIN_KEY,
        tenant_uuid=None,  # caller did not supply one
    )
    with caplog.at_level(logging.WARNING, logger=lifecycle.LOGGER.name):
        result = lifecycle.provision(spec, client=client)

    # A fresh uuid was generated and returned.
    assert result.operator_tenant_id
    uuid.UUID(result.operator_tenant_id)
    # It was actually used as the explicit `id` for the operator tenant row.
    operator_posts = [t for t in tenants_seen if t.get("name") == "acme"]
    assert len(operator_posts) == 1
    assert operator_posts[0]["id"] == result.operator_tenant_id
    # A clear ephemeral-identity warning was emitted.
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("ephemeral" in m.lower() for m in warnings)


def test_resolve_operator_tenant_id_treats_whitespace_as_empty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        proxy=_proxy_spec(),
        dashboard=_dashboard_spec(),
        tenant_uuid="   ",
    )
    with caplog.at_level(logging.WARNING, logger=lifecycle.LOGGER.name):
        resolved = lifecycle._resolve_operator_tenant_id(spec)
    uuid.UUID(resolved)  # generated a real uuid rather than using whitespace
    assert any(
        "ephemeral" in r.message.lower()
        for r in caplog.records
        if r.levelno == logging.WARNING
    )


# ---------------------------------------------------------------------------
# Guard: no hardcoded tenant UUID remains in pro.yaml
# ---------------------------------------------------------------------------


def test_pro_yaml_has_no_hardcoded_tenant_uuid() -> None:
    pro_yaml = (
        pathlib.Path(__file__).resolve().parents[1]
        / "configs"
        / "examples"
        / "pro.yaml"
    )
    text = pro_yaml.read_text()
    assert "6ae1ab34" not in text, (
        "the previously-hardcoded catch-all/default tenant UUID must not "
        "appear anywhere in pro.yaml"
    )
