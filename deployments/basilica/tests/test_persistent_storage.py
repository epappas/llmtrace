"""Tests for the durable-storage substrate wiring.

Scope: the `PersistentVolumeSpec` dataclass, its `StorageSpec` projection,
the `LLMTRACE_STORAGE_DATABASE_PATH` repointing helper, the storage threading
through `_create_component`, and the stable-tenant-id field on tenant
bootstrap. The Basilica SDK boundary is the conftest stub; no real backend is
contacted.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable

import pytest

from deployments.basilica import lifecycle


# ---------------------------------------------------------------------------
# In-process fake proxy admin API (mirrors test_operator_key_minting.py)
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


class _FakeProxy:
    def __init__(self, responder: Callable[..., tuple[int, dict[str, Any]]]) -> None:
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
    servers: list[_FakeProxy] = []

    def make(responder: Callable[..., tuple[int, dict[str, Any]]]) -> _FakeProxy:
        s = _FakeProxy(responder)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.shutdown()


# ---------------------------------------------------------------------------
# PersistentVolumeSpec validation + projection
# ---------------------------------------------------------------------------


def _pv(**overrides: Any) -> lifecycle.PersistentVolumeSpec:
    kwargs: dict[str, Any] = {
        "bucket": "llmtrace-traces",
        "credentials_secret": "basilica-r2-credentials",
    }
    kwargs.update(overrides)
    return lifecycle.PersistentVolumeSpec(**kwargs)


def test_database_path_joins_mount_and_filename() -> None:
    pv = _pv(mount_path="/data", db_filename="llmtrace.db")
    assert pv.database_path == "/data/llmtrace.db"
    pv2 = _pv(mount_path="/mnt/store/", db_filename="t.db")
    assert pv2.database_path == "/mnt/store/t.db"


def test_to_storage_spec_passes_all_fields_to_sdk() -> None:
    pv = _pv(
        bucket="b1",
        credentials_secret="sec1",
        mount_path="/data",
        backend="s3",
        region="eu-west-1",
        endpoint="https://s3.example",
        sync_interval_ms=2000,
        cache_size_mb=2048,
    )
    spec = pv.to_storage_spec()
    persistent = spec.persistent
    assert persistent.enabled is True
    assert str(persistent.backend) == "StorageBackend.S3"
    assert persistent.bucket == "b1"
    assert persistent.credentials_secret == "sec1"
    assert persistent.mount_path == "/data"
    assert persistent.region == "eu-west-1"
    assert persistent.endpoint == "https://s3.example"
    assert persistent.sync_interval_ms == 2000
    assert persistent.cache_size_mb == 2048


def test_backend_is_case_insensitive() -> None:
    assert (
        str(_pv(backend="R2").to_storage_spec().persistent.backend)
        == "StorageBackend.R2"
    )
    assert (
        str(_pv(backend="gcs").to_storage_spec().persistent.backend)
        == "StorageBackend.GCS"
    )


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"bucket": ""}, "bucket"),
        ({"credentials_secret": ""}, "credentials_secret"),
        ({"mount_path": "data"}, "absolute"),
        ({"backend": "azure"}, "backend"),
        ({"sync_interval_ms": 0}, "sync_interval_ms"),
        ({"cache_size_mb": -1}, "cache_size_mb"),
        ({"db_filename": "a/b.db"}, "db_filename"),
        ({"db_filename": ""}, "db_filename"),
    ],
)
def test_validation_rejects_bad_specs(overrides: dict[str, Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        _pv(**overrides)


# ---------------------------------------------------------------------------
# _apply_persistent_db_path
# ---------------------------------------------------------------------------


def _proxy_spec(**overrides: Any) -> lifecycle.ComponentSpec:
    kwargs: dict[str, Any] = {
        "image": "ghcr.io/example/proxy:latest",
        "port": 8080,
        "cpu": "1",
        "memory": "1Gi",
        "replicas": 1,
        "env": {"LLMTRACE_UPSTREAM_URL": "https://upstream.example"},
    }
    kwargs.update(overrides)
    return lifecycle.ComponentSpec(**kwargs)


def test_apply_persistent_db_path_noop_without_volume() -> None:
    spec = _proxy_spec()
    assert lifecycle._apply_persistent_db_path(spec) is spec


def test_apply_persistent_db_path_sets_env_to_mount() -> None:
    spec = _proxy_spec(persistent_volume=_pv(mount_path="/data", db_filename="x.db"))
    out = lifecycle._apply_persistent_db_path(spec)
    assert out.env[lifecycle.STORAGE_DB_PATH_ENV] == "/data/x.db"
    # original env preserved
    assert out.env["LLMTRACE_UPSTREAM_URL"] == "https://upstream.example"


def test_apply_persistent_db_path_overrides_caller_env() -> None:
    spec = _proxy_spec(
        env={lifecycle.STORAGE_DB_PATH_ENV: "/home/llmtrace/stale.db"},
        persistent_volume=_pv(mount_path="/data"),
    )
    out = lifecycle._apply_persistent_db_path(spec)
    assert out.env[lifecycle.STORAGE_DB_PATH_ENV] == "/data/llmtrace.db"


# ---------------------------------------------------------------------------
# Stable tenant id on bootstrap
# ---------------------------------------------------------------------------


_STABLE_ID = "user-uuid-550e8400-e29b-41d4-a716-446655440000"
_RETURNED_UUID = "11111111-1111-4111-8111-111111111111"


def test_bootstrap_sends_stable_id_when_set(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes):
        decoded = json.loads(body)
        assert decoded["id"] == _STABLE_ID
        assert decoded["name"] == "acme"
        return 201, {"id": _RETURNED_UUID, "name": "acme"}

    proxy = fake_proxy(responder)
    out = lifecycle._bootstrap_tenant_in_proxy(
        proxy.url, "llmt_" + "a" * 64, "acme", stable_id=_STABLE_ID
    )
    assert out == _RETURNED_UUID


def test_bootstrap_omits_id_field_when_unset(fake_proxy: Any) -> None:
    def responder(method: str, path: str, headers: dict[str, str], body: bytes):
        decoded = json.loads(body)
        assert "id" not in decoded
        return 201, {"id": _RETURNED_UUID, "name": "acme"}

    proxy = fake_proxy(responder)
    out = lifecycle._bootstrap_tenant_in_proxy(proxy.url, "llmt_" + "a" * 64, "acme")
    assert out == _RETURNED_UUID


# ---------------------------------------------------------------------------
# Storage threading through _create_component (via provision)
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


def test_provision_attaches_storage_and_repoints_db_and_sends_stable_id(
    fake_proxy: Any,
) -> None:
    seen: dict[str, Any] = {"tenant_bodies": []}

    def responder(method: str, path: str, headers: dict[str, str], body: bytes):
        if method == "POST" and path == "/api/v1/tenants":
            decoded = json.loads(body)
            seen["tenant_bodies"].append(decoded)
            # Echo the posted id so the operator and catch-all rows resolve
            # to their explicit ids (the catch-all carries a fresh uuid).
            return 201, {"id": decoded.get("id") or _RETURNED_UUID, "name": decoded.get("name")}
        if method == "POST" and path == "/api/v1/auth/keys":
            return 201, {"key": "llmt_" + "b" * 64, "key_prefix": "llmt_bbb"}
        raise AssertionError(f"unexpected: {method} {path}")

    proxy = fake_proxy(responder)
    client = _FakeBasilicaClient(proxy.url, "https://dashboard.example")

    proxy_spec = _proxy_spec(
        persistent_volume=_pv(mount_path="/data", db_filename="llmtrace.db")
    )
    dash_spec = lifecycle.ComponentSpec(
        image="ghcr.io/example/dashboard:latest",
        port=3000,
        cpu="1",
        memory="1Gi",
        replicas=1,
        env={"HOSTNAME": "0.0.0.0"},
    )
    spec = lifecycle.TenantSpec(
        tenant_id="acme",
        tenant_uuid=_STABLE_ID,
        proxy=proxy_spec,
        dashboard=dash_spec,
        api_key="llmt_" + "a" * 64,
    )

    lifecycle.provision(spec, client=client)

    proxy_create = next(c for c in client.creates if "proxy" in c["instance_name"])
    # Storage spec was attached to the proxy create.
    assert "storage" in proxy_create
    persistent = proxy_create["storage"].persistent
    assert persistent.bucket == "llmtrace-traces"
    assert persistent.mount_path == "/data"
    # DB path repointed onto the mount.
    assert proxy_create["env"][lifecycle.STORAGE_DB_PATH_ENV] == "/data/llmtrace.db"
    # Stable id forwarded on the OPERATOR tenant create (name == tenant_id).
    operator_bodies = [
        b for b in seen["tenant_bodies"] if b.get("name") == "acme"
    ]
    assert len(operator_bodies) == 1
    assert operator_bodies[0]["id"] == _STABLE_ID
    # Dashboard has no storage attached (only proxy carries the DB).
    dash_create = next(c for c in client.creates if "dashboard" in c["instance_name"])
    assert "storage" not in dash_create
