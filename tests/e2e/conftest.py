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
    parser.addoption(
        "--scenario-results-json",
        action="store",
        default=None,
        help=(
            "Path to write per-scenario results as JSON (Loop E2E-L10). "
            "Sidecar consumed by scripts/e2e/generate_nightly_report.py."
        ),
    )
    parser.addoption(
        "--cost-cap-usd",
        action="store",
        type=float,
        default=None,
        help=(
            "Per-session cost cap in USD (Loop E2E-L10). When the proxy's "
            "llmtrace_cost_usd_total exceeds this value the session is "
            "aborted. Unset = no cap."
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
    """Render the e2e (judge-on, debug-on) config into a per-session temp file.

    The base config is copied as-is; runtime networking + storage paths
    are passed via env vars to the proxy subprocess. We default to the
    cascade-null-slow judge configuration (matches the L9 PR-gate matrix
    dimension) so verdict assertions and shadow-mode helpers are
    exercised on every run. Loop E2E-L5 also requires
    `server.debug_endpoints: true` for the verdict poller to work.
    """
    src = FIXTURES_DIR / "config-e2e-judge.yaml"
    dst = tmp_path_factory.mktemp("e2e-config") / "config.yaml"
    shutil.copyfile(src, dst)

    # IS-060 PR-1: when the operator opts in via env, overlay
    # `security_analysis.zone_detection.enabled: true` into the temp
    # config so the proxy under test actually runs the zone-aware
    # request path. Default off; the harness skip-gate at
    # tests/e2e/test_cascade.py:55 keeps PR-gate runs green when this
    # env is not set.
    if os.environ.get("LLMTRACE_ZONE_DETECTION_ENABLED", "").lower() in (
        "1",
        "true",
        "yes",
    ):
        with open(dst, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        sec = cfg.setdefault("security_analysis", {})
        zd = sec.setdefault("zone_detection", {})
        zd["enabled"] = True
        zd.setdefault("mode", "both")
        zd.setdefault("scan_instruction_zones", False)
        with open(dst, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, sort_keys=False)
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
    # Loop E2E-L10: when LLMTRACE_E2E_REAL_UPSTREAM_URL is set, point
    # the proxy at that real LLM (used by the nightly workflow).
    # Otherwise fall back to the in-process FastAPI mock so PR-gate
    # runs stay self-contained and free.
    real_upstream = os.environ.get("LLMTRACE_E2E_REAL_UPSTREAM_URL")
    env["LLMTRACE_UPSTREAM_URL"] = real_upstream or mock_upstream.base_url
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


# ---------------------------------------------------------------------------
# Per-scenario sidecar collector + cost cap (Loop E2E-L10)
# ---------------------------------------------------------------------------


_SCENARIO_BY_ID: dict[str, dict] = {}
_RESULTS: list[dict] = []


def pytest_configure(config: pytest.Config) -> None:
    """Pre-populate the scenario lookup so the report has family/tags
    even for scenarios that never invoked a fixture (e.g. errored at
    collection)."""
    families = config.getoption("--family") or []
    tags = config.getoption("--tag") or []
    for s in discover_scenarios(families=families, tags=tags):
        _SCENARIO_BY_ID[s["id"]] = s


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    """Capture per-scenario outcome into the session results list.

    Records once per item (the `call` phase). Setup/teardown phases are
    folded into the same row via outcome priority: error > failed >
    skipped > passed. The row carries enough data for L10's report
    generator to produce family roll-ups and regression diffs without
    re-reading any YAML."""
    outcome = yield
    report = outcome.get_result()
    if report.when != "call" and not (
        report.when == "setup" and report.outcome in ("failed", "skipped")
    ):
        return

    scenario_id = _scenario_id_from_item(item)
    if scenario_id is None:
        return

    scenario = _SCENARIO_BY_ID.get(scenario_id, {})
    existing = next(
        (r for r in _RESULTS if r["id"] == scenario_id), None
    )
    row = existing or {
        "id": scenario_id,
        "family": scenario.get("family"),
        "tags": sorted(scenario.get("tags") or []),
        "outcome": "passed",
        "duration_secs": 0.0,
    }
    _merge_outcome(row, report)
    for key, value in getattr(report, "user_properties", []) or []:
        row[key] = value
    if existing is None:
        _RESULTS.append(row)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write the JSON sidecar at session end."""
    out_path = session.config.getoption("--scenario-results-json")
    if not out_path:
        return
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "scenarios": sorted(_RESULTS, key=lambda r: r["id"]),
    }
    with out.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def _scenario_id_from_item(item: pytest.Item) -> str | None:
    """Extract the scenario id from a parametrised pytest item.

    Item ids look like `tests/e2e/test_cascade.py::test_scenario[<id>]`.
    The bracketed segment is the scenario id we used in `parametrize`.
    Non-parametrised items (e.g. unit tests) return None.
    """
    name = item.name
    if "[" not in name:
        return None
    return name[name.index("[") + 1 : -1]


_OUTCOME_PRIORITY = {"passed": 0, "skipped": 1, "failed": 2, "error": 3}


def _merge_outcome(row: dict, report) -> None:
    """Promote the row's outcome if `report` is more severe."""
    incoming = "error" if (report.when == "setup" and report.failed) else report.outcome
    if _OUTCOME_PRIORITY.get(incoming, 0) > _OUTCOME_PRIORITY.get(
        row["outcome"], 0
    ):
        row["outcome"] = incoming
        if getattr(report, "longrepr", None):
            row["longrepr"] = str(report.longrepr)[:2000]
    row["duration_secs"] = round(
        row.get("duration_secs", 0.0) + float(getattr(report, "duration", 0.0)),
        3,
    )


@pytest.fixture(autouse=True)
def _cost_cap_check(request):
    """After each scenario, scrape /metrics and abort if the session
    exceeds `--cost-cap-usd`. No-op when the option is unset OR the
    test doesn't request the `proxy` fixture (unit tests under
    test_*_unit.py don't talk to the proxy).
    """
    yield
    cap = request.config.getoption("--cost-cap-usd")
    if cap is None:
        return
    if "proxy" not in request.fixturenames:
        return
    proxy = request.getfixturevalue("proxy")
    try:
        import requests
        from prometheus_client.parser import text_string_to_metric_families
    except ImportError:
        return
    try:
        text = requests.get(proxy.metrics_url, timeout=2.0).text
    except Exception:
        return
    spent = 0.0
    for family in text_string_to_metric_families(text):
        if family.name != "llmtrace_cost_usd":
            continue
        for sample in family.samples:
            if sample.name == "llmtrace_cost_usd_total":
                spent += float(sample.value)
    if spent > cap:
        pytest.exit(
            f"[e2e] cost cap exceeded: spent ${spent:.4f} > cap ${cap:.4f}",
            returncode=2,
        )
