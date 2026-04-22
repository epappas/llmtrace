"""Pytest fixtures for the LLMTrace e2e adversarial test framework.

Owns the per-session lifecycle of two subprocesses:

  1. The FastAPI mock upstream (tests/e2e/mock_upstream.py).
  2. The LLMTrace proxy release binary, configured to forward to the
     mock and persist traces under a temp SQLite file.

Both run on free ports allocated by `socket.bind((..., 0))`. The proxy
fixture polls `/health` until 200 or 60 s, then yields a `ProxyHandle`.

Teardown is reliable: SIGTERM-then-wait for both subprocesses inside a
`finally` block, with stdout/stderr captured to `tests/e2e/.logs/`.

Loaded scenarios come from `benchmarks/attacks/**/*.yaml` and respect
two CLI markers: `--family=` and `--tag=` (comma-separated, repeatable).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACKS_DIR = REPO_ROOT / "benchmarks" / "attacks"
LOGS_DIR = Path(__file__).resolve().parent / ".logs"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
MOCK_UPSTREAM_PATH = Path(__file__).resolve().parent / "mock_upstream.py"

PROXY_BIN_ENV = "LLMTRACE_PROXY_BIN"
DEFAULT_PROXY_BINARIES = (
    REPO_ROOT / "target" / "release" / "llmtrace-proxy",
    REPO_ROOT / "target" / "debug" / "llmtrace-proxy",
)

PROXY_HEALTH_TIMEOUT_SECS = 60
PROXY_HEALTH_POLL_INTERVAL_SECS = 0.5
PROXY_TEARDOWN_TIMEOUT_SECS = 10
MOCK_HEALTH_TIMEOUT_SECS = 10


# ---------------------------------------------------------------------------
# CLI / collection
# ---------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--family",
        action="append",
        default=[],
        help=(
            "Restrict scenarios to one or more families (e.g. "
            "--family=prompt_injection --family=jailbreak). Repeatable."
        ),
    )
    parser.addoption(
        "--tag",
        action="append",
        default=[],
        help=(
            "Restrict scenarios by tag (e.g. --tag=pr-gate). "
            "Repeatable; logical OR across tags."
        ),
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Ensure the harness runs serially.

    Counter-diff observability (Loop E2E-L4) relies on serial scenario
    execution. Detect pytest-xdist activation and fail loudly rather
    than silently producing nonsense.
    """
    if config.getoption("-n", default=None) not in (None, 0, "0"):
        raise pytest.UsageError(
            "tests/e2e must run serially: counter-diff observability is global. "
            "Remove -n / pytest-xdist flags."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Return a port that is currently free on 127.0.0.1.

    Closes the bound socket immediately; brief race window is acceptable
    for serial e2e runs.
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _resolve_proxy_binary() -> Path:
    override = os.environ.get(PROXY_BIN_ENV)
    if override:
        path = Path(override)
        if not path.is_file():
            raise FileNotFoundError(
                f"{PROXY_BIN_ENV}={override} does not point to a file"
            )
        return path
    for candidate in DEFAULT_PROXY_BINARIES:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "llmtrace-proxy binary not found. Build it first:\n"
        "  cargo build --release -p llmtrace\n"
        "or set the LLMTRACE_PROXY_BIN env var to an existing binary."
    )


def _wait_for_health(url: str, timeout_secs: float, label: str) -> None:
    import requests  # local import keeps top-level import deps minimal

    deadline = time.monotonic() + timeout_secs
    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            resp = requests.get(url, timeout=2.0)
            if resp.status_code == 200:
                return
            last_error = f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            last_error = str(e)
        time.sleep(PROXY_HEALTH_POLL_INTERVAL_SECS)
    raise TimeoutError(
        f"{label} did not become healthy within {timeout_secs}s "
        f"(last error: {last_error})"
    )


def _terminate(process: subprocess.Popen, label: str) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=PROXY_TEARDOWN_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    if process.returncode not in (0, -15, None):
        # -15 is SIGTERM on POSIX; treat as a clean shutdown.
        # Loud but non-fatal — the test session has already finished.
        print(
            f"[e2e] {label} exited with code {process.returncode}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Mock upstream fixture
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MockUpstreamHandle:
    base_url: str
    port: int


@pytest.fixture(scope="session")
def mock_upstream() -> Iterator[MockUpstreamHandle]:
    LOGS_DIR.mkdir(exist_ok=True)
    port = _free_port()
    log_path = LOGS_DIR / "mock_upstream.log"

    process = subprocess.Popen(
        [sys.executable, str(MOCK_UPSTREAM_PATH), "--port", str(port)],
        stdout=log_path.open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_health(
            f"{base_url}/health", MOCK_HEALTH_TIMEOUT_SECS, "mock_upstream"
        )
        yield MockUpstreamHandle(base_url=base_url, port=port)
    finally:
        _terminate(process, "mock_upstream")


# ---------------------------------------------------------------------------
# Proxy fixture
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProxyHandle:
    base_url: str
    health_url: str
    metrics_url: str
    config_path: Path
    log_path: Path

    def post_chat(
        self,
        prompt: str,
        *,
        trace_id: uuid.UUID | None = None,
        timeout: float = 30.0,
    ):
        """Send a single-turn chat completion request and return the response."""
        import requests

        headers = {"content-type": "application/json"}
        if trace_id is not None:
            headers["x-llmtrace-trace-id"] = str(trace_id)
        body = {
            "model": "mock-model",
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        return requests.post(
            f"{self.base_url}/v1/chat/completions",
            data=json.dumps(body),
            headers=headers,
            timeout=timeout,
        )


@pytest.fixture(scope="session")
def proxy_config_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Render the e2e (judge-off) config into a per-session temp file.

    The base config is copied as-is; runtime networking + storage paths
    are passed via env vars to the proxy subprocess.
    """
    src = FIXTURES_DIR / "config-e2e.yaml"
    dst = tmp_path_factory.mktemp("e2e-config") / "config.yaml"
    shutil.copyfile(src, dst)
    return dst


@pytest.fixture(scope="session")
def proxy(
    mock_upstream: MockUpstreamHandle,
    proxy_config_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[ProxyHandle]:
    LOGS_DIR.mkdir(exist_ok=True)
    binary = _resolve_proxy_binary()

    listen_port = _free_port()
    listen_addr = f"127.0.0.1:{listen_port}"
    db_dir = tmp_path_factory.mktemp("e2e-db")
    db_path = db_dir / "llmtrace-e2e.db"
    log_path = LOGS_DIR / "proxy.log"

    env = os.environ.copy()
    env["LLMTRACE_LISTEN_ADDR"] = listen_addr
    env["LLMTRACE_UPSTREAM_URL"] = mock_upstream.base_url
    env["LLMTRACE_STORAGE_DATABASE_PATH"] = str(db_path)
    env["LLMTRACE_STORAGE_PROFILE"] = "lite"
    env["RUST_LOG"] = env.get("RUST_LOG", "llmtrace_proxy=info,info")

    process = subprocess.Popen(
        [str(binary), "--config", str(proxy_config_path)],
        stdout=log_path.open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        env=env,
    )

    base_url = f"http://{listen_addr}"
    try:
        _wait_for_health(
            f"{base_url}/health", PROXY_HEALTH_TIMEOUT_SECS, "llmtrace-proxy"
        )
        yield ProxyHandle(
            base_url=base_url,
            health_url=f"{base_url}/health",
            metrics_url=f"{base_url}/metrics",
            config_path=proxy_config_path,
            log_path=log_path,
        )
    finally:
        _terminate(process, "llmtrace-proxy")


# ---------------------------------------------------------------------------
# Scenarios fixture
# ---------------------------------------------------------------------------


def _load_scenario(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _matches_filters(
    scenario: dict, families: list[str], tags: list[str]
) -> bool:
    if families and scenario.get("family") not in families:
        return False
    if tags:
        scenario_tags = set(scenario.get("tags") or [])
        if not scenario_tags.intersection(tags):
            return False
    return True


def _is_skipped(scenario: dict) -> tuple[bool, str | None]:
    skip = scenario.get("skip")
    if not skip:
        return False, None
    return True, skip.get("reason") or "no reason provided"


def discover_scenarios(
    families: list[str] | None = None, tags: list[str] | None = None
) -> list[dict]:
    """Return all scenarios under benchmarks/attacks/ matching the filters."""
    families = families or []
    tags = tags or []
    scenarios: list[dict] = []
    for path in sorted(ATTACKS_DIR.rglob("*.yaml")):
        if not path.is_file():
            continue
        scenario = _load_scenario(path)
        if not isinstance(scenario, dict):
            continue
        scenario["__path__"] = str(path.relative_to(REPO_ROOT))
        if _matches_filters(scenario, families, tags):
            scenarios.append(scenario)
    return scenarios


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrise any test that requests a `scenario` fixture."""
    if "scenario" not in metafunc.fixturenames:
        return
    families = metafunc.config.getoption("--family") or []
    tags = metafunc.config.getoption("--tag") or []
    scenarios = discover_scenarios(families=families, tags=tags)
    ids = [s["id"] for s in scenarios]
    metafunc.parametrize("scenario", scenarios, ids=ids)
