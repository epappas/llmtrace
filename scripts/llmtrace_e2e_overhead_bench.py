#!/usr/bin/env python3
"""
LLMTrace E2E Overhead Benchmark
===============================

This script load-tests an OpenAI-compatible Chat Completions endpoint and can
optionally compare a "direct" LLM endpoint vs an LLMTrace proxy endpoint to
estimate overhead (added latency, throughput impact, error rate changes).

It uses only the Python standard library (no external deps).

Examples
--------
Single target (proxy only):
  python3 scripts/llmtrace_e2e_overhead_bench.py \
    --url http://127.0.0.1:8081/v1/chat/completions \
    --model glm-4.7-flash \
    --token llmt_... \
    --agent-id laptop-test-user \
    --concurrency 20 \
    --requests 200

Compare direct vs proxy:
  python3 scripts/llmtrace_e2e_overhead_bench.py \
    --direct-url http://192.168.1.107:8000/v1/chat/completions \
    --proxy-url  http://192.168.1.107:8081/v1/chat/completions \
    --model glm-4.7-flash \
    --token llmt_... \
    --concurrency-list 1,2,5,10,20,50 \
    --requests 200
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import random
import statistics
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Endpoint:
    name: str
    url: str


@dataclass(frozen=True)
class RequestSpec:
    model: str
    system_prompt: str
    temperature: float
    max_tokens: int


@dataclass(frozen=True)
class RequestResult:
    ok: bool
    status: int | None
    latency_ms: float
    error: str | None


@dataclass(frozen=True)
class ResponseSummary:
    blocked: bool | None
    preview: str | None


@dataclass(frozen=True)
class ProbeRow:
    case: str
    attempt: int
    http: int | None
    blocked: bool | None
    expected: str
    latency_ms: float
    prompt_preview: str
    preview: str | None


@dataclass(frozen=True)
class BenchmarkSample:
    sample_id: str
    text: str
    label: str
    category: str | None
    subcategory: str | None
    source: str | None


def _discover_dataset_paths(suite: str) -> list[Path]:
    base = Path("benchmarks/datasets")
    if suite == "core":
        # Everything under benchmarks/datasets except the external/ subtree.
        paths = [p for p in base.rglob("*.json") if "external" not in p.parts]
    elif suite == "external":
        paths = list((base / "external").rglob("*.json"))
    elif suite == "all":
        paths = list(base.rglob("*.json"))
    else:
        raise ValueError("Unknown dataset suite. Use: core, external, all.")

    paths = sorted({p for p in paths})
    return paths


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


def _percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return float("nan")
    if p <= 0:
        return sorted_values[0]
    if p >= 100:
        return sorted_values[-1]
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1


def _format_ms(x: float) -> str:
    if math.isnan(x):
        return "n/a"
    return f"{x:.1f}ms"


def _format_float(x: float) -> str:
    if math.isnan(x):
        return "n/a"
    return f"{x:.3f}"


def make_payload(spec: RequestSpec, user_prompt: str) -> dict[str, Any]:
    return {
        "model": spec.model,
        "messages": [
            {"role": "system", "content": spec.system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": spec.temperature,
        "max_tokens": spec.max_tokens,
    }


def build_headers(token: str | None, agent_id: str | None) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if token:
        # Do not log token value; only indicate presence in output.
        h["Authorization"] = f"Bearer {token}"
    if agent_id:
        h["X-LLMTrace-Agent-ID"] = agent_id
    return h

def send_chat_request(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_seconds: float,
) -> RequestResult:
    start_ms = _now_ms()
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", None)
            # Read fully to include server time, not just time-to-first-byte.
            resp.read()
            end_ms = _now_ms()
            return RequestResult(ok=True, status=status, latency_ms=end_ms - start_ms, error=None)
    except urllib.error.HTTPError as e:
        end_ms = _now_ms()
        return RequestResult(
            ok=False,
            status=getattr(e, "code", None),
            latency_ms=end_ms - start_ms,
            error=f"HTTPError: {e}",
        )
    except Exception as e:
        end_ms = _now_ms()
        return RequestResult(ok=False, status=None, latency_ms=end_ms - start_ms, error=f"{type(e).__name__}: {e}")


def send_chat_request_capture(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_seconds: float,
) -> tuple[RequestResult, bytes | None]:
    start_ms = _now_ms()
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", None)
            body = resp.read()
            end_ms = _now_ms()
            return RequestResult(ok=True, status=status, latency_ms=end_ms - start_ms, error=None), body
    except urllib.error.HTTPError as e:
        end_ms = _now_ms()
        try:
            body = e.read()
        except Exception:
            body = None
        return (
            RequestResult(
                ok=False,
                status=getattr(e, "code", None),
                latency_ms=end_ms - start_ms,
                error=f"HTTPError: {e}",
            ),
            body,
        )
    except Exception as e:
        end_ms = _now_ms()
        return (
            RequestResult(ok=False, status=None, latency_ms=end_ms - start_ms, error=f"{type(e).__name__}: {e}"),
            None,
        )

def _collapse_ws(s: str) -> str:
    return " ".join(s.split())

def _truncate(s: str, n: int) -> str:
    s = _collapse_ws(s)
    if n <= 0:
        return ""
    if len(s) <= n:
        return s
    return s[: max(0, n - 3)] + "..."

def summarize_response(body: bytes | None, preview_chars: int) -> ResponseSummary:
    if not body:
        return ResponseSummary(blocked=None, preview=None)
    try:
        obj = json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        return ResponseSummary(blocked=None, preview=_truncate(body.decode("utf-8", errors="ignore"), preview_chars))
    if not isinstance(obj, dict):
        return ResponseSummary(blocked=None, preview=_truncate(str(obj), preview_chars))

    # Heuristics:
    # - Some servers set explicit fields (e.g., `blocked: true`).
    # - OpenAI-style responses include choices[0].message.{content,refusal,...}
    blocked: bool | None = obj.get("blocked") if isinstance(obj.get("blocked"), bool) else None
    preview_src: str | None = None

    choices = obj.get("choices")
    if isinstance(choices, list) and choices:
        c0 = choices[0] if isinstance(choices[0], dict) else {}
        msg = c0.get("message") if isinstance(c0, dict) else None
        if isinstance(msg, dict):
            refusal = msg.get("refusal")
            content = msg.get("content")
            reasoning = msg.get("reasoning")
            if isinstance(refusal, str) and refusal.strip():
                blocked = True if blocked is None else blocked
                preview_src = refusal
            elif isinstance(content, str) and content.strip():
                preview_src = content
            elif isinstance(reasoning, str) and reasoning.strip():
                # Some models return reasoning-only; treat as "blocked-ish" but not definitive.
                blocked = blocked if blocked is not None else True
                preview_src = "[reasoning-only response] " + reasoning
        elif isinstance(c0, dict) and isinstance(c0.get("text"), str):
            preview_src = c0.get("text")

    if preview_src is None:
        preview_src = json.dumps(obj, ensure_ascii=True)

    return ResponseSummary(blocked=blocked, preview=_truncate(preview_src, preview_chars))

@dataclass
class RunStats:
    endpoint: str
    concurrency: int
    requests: int
    duration_s: float
    ok: int
    errors: int
    rps_ok: float
    mean_ms: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    statuses: dict[str, int]

def compute_stats(
    endpoint: str,
    concurrency: int,
    results: list[RequestResult],
    wall_start_ms: float,
    wall_end_ms: float,
) -> RunStats:
    lat_ok = [r.latency_ms for r in results if r.ok]
    lat_ok_sorted = sorted(lat_ok)

    statuses: dict[str, int] = {}
    for r in results:
        key = str(r.status) if r.status is not None else "none"
        statuses[key] = statuses.get(key, 0) + 1

    duration_s = max(0.001, (wall_end_ms - wall_start_ms) / 1000.0)
    ok = sum(1 for r in results if r.ok)
    errors = len(results) - ok
    mean_ms = statistics.fmean(lat_ok) if lat_ok else float("nan")
    p50 = _percentile(lat_ok_sorted, 50.0)
    p90 = _percentile(lat_ok_sorted, 90.0)
    p95 = _percentile(lat_ok_sorted, 95.0)
    p99 = _percentile(lat_ok_sorted, 99.0)
    max_ms = max(lat_ok_sorted) if lat_ok_sorted else float("nan")

    return RunStats(
        endpoint=endpoint,
        concurrency=concurrency,
        requests=len(results),
        duration_s=duration_s,
        ok=ok,
        errors=errors,
        rps_ok=ok / duration_s,
        mean_ms=mean_ms,
        p50_ms=p50,
        p90_ms=p90,
        p95_ms=p95,
        p99_ms=p99,
        max_ms=max_ms,
        statuses=statuses,
    )

def _read_benchmark_dataset(path: Path) -> list[BenchmarkSample]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"dataset must be a JSON array, got {type(raw).__name__}")
    out: list[BenchmarkSample] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"dataset item #{i} must be an object, got {type(item).__name__}")
        sample_id = str(item.get("id", f"row-{i}"))
        text = item.get("text")
        label = str(item.get("label", "unknown"))
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"dataset item #{i} (id={sample_id}) missing non-empty 'text'")
        out.append(
            BenchmarkSample(
                sample_id=sample_id,
                text=text,
                label=label,
                category=item.get("category"),
                subcategory=item.get("subcategory"),
                source=item.get("source"),
            )
        )
    return out

def _filter_samples(samples: list[BenchmarkSample], label_filter: str) -> list[BenchmarkSample]:
    lf = label_filter.strip().lower()
    if lf == "all":
        return samples
    if lf not in ("benign", "malicious"):
        raise ValueError("dataset label filter must be one of: benign, malicious, all")
    return [s for s in samples if s.label.strip().lower() == lf]

def _load_datasets(paths: list[Path]) -> list[BenchmarkSample]:
    samples: list[BenchmarkSample] = []
    for p in paths:
        samples.extend(_read_benchmark_dataset(p))
    return samples

def _parse_csv_lower(s: str | None) -> list[str]:
    if not s:
        return []
    out: list[str] = []
    for part in s.split(","):
        part = part.strip().lower()
        if part:
            out.append(part)
    return out

def _matches_any(hay: str | None, needles: list[str]) -> bool:
    if not needles:
        return True
    if hay is None:
        return False
    h = hay.lower()
    return any(n in h for n in needles)

def _filter_by_category(
    samples: list[BenchmarkSample],
    category_contains: list[str],
    subcategory_contains: list[str],
) -> list[BenchmarkSample]:
    if not category_contains and not subcategory_contains:
        return samples
    out: list[BenchmarkSample] = []
    for s in samples:
        if category_contains and not _matches_any(s.category, category_contains):
            continue
        if subcategory_contains and not _matches_any(s.subcategory, subcategory_contains):
            continue
        out.append(s)
    return out


def run_load(
    endpoint: Endpoint,
    spec: RequestSpec,
    headers: dict[str, str],
    concurrency: int,
    total_requests: int,
    timeout_seconds: float,
    jitter_ms: int,
    user_prompts: list[str],
    progress_every: int,
) -> tuple[RunStats, list[RequestResult]]:
    if not user_prompts:
        raise ValueError("user_prompts must be non-empty")

    payloads = [make_payload(spec, user_prompts[i % len(user_prompts)]) for i in range(total_requests)]

    def one(payload: dict[str, Any]) -> RequestResult:
        if jitter_ms > 0:
            time.sleep(random.random() * (jitter_ms / 1000.0))
        return send_chat_request(
            url=endpoint.url,
            headers=headers,
            payload=payload,
            timeout_seconds=timeout_seconds,
        )

    results: list[RequestResult] = []
    wall_start = _now_ms()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(one, p) for p in payloads]
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())
            done += 1
            if progress_every > 0 and done % progress_every == 0:
                print(f"progress: {done}/{total_requests} completed", file=sys.stderr, flush=True)
    wall_end = _now_ms()
    stats = compute_stats(endpoint.name, concurrency, results, wall_start, wall_end)
    return stats, results

def print_stats_table(title: str, stats_list: list[RunStats]) -> None:
    print(f"\n## {title}")
    print("| endpoint | conc | req | ok | err | ok_rps | mean | p50 | p95 | p99 | max |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for s in stats_list:
        print(
            "| {endpoint} | {conc} | {req} | {ok} | {err} | {rps} | {mean} | {p50} | {p95} | {p99} | {max} |".format(
                endpoint=s.endpoint,
                conc=s.concurrency,
                req=s.requests,
                ok=s.ok,
                err=s.errors,
                rps=_format_float(s.rps_ok),
                mean=_format_ms(s.mean_ms),
                p50=_format_ms(s.p50_ms),
                p95=_format_ms(s.p95_ms),
                p99=_format_ms(s.p99_ms),
                max=_format_ms(s.max_ms),
            )
        )


def print_overhead_table(direct: RunStats, proxy: RunStats) -> None:
    def d(a: float, b: float) -> float:
        if math.isnan(a) or math.isnan(b):
            return float("nan")
        return b - a

    print("\n## Estimated Overhead (proxy - direct)")
    print("| metric | direct | proxy | delta |")
    print("|---|---:|---:|---:|")
    print(f"| ok_rps | {_format_float(direct.rps_ok)} | {_format_float(proxy.rps_ok)} | {_format_float(proxy.rps_ok - direct.rps_ok)} |")
    print(f"| mean | {_format_ms(direct.mean_ms)} | {_format_ms(proxy.mean_ms)} | {_format_ms(d(direct.mean_ms, proxy.mean_ms))} |")
    print(f"| p50 | {_format_ms(direct.p50_ms)} | {_format_ms(proxy.p50_ms)} | {_format_ms(d(direct.p50_ms, proxy.p50_ms))} |")
    print(f"| p95 | {_format_ms(direct.p95_ms)} | {_format_ms(proxy.p95_ms)} | {_format_ms(d(direct.p95_ms, proxy.p95_ms))} |")
    print(f"| p99 | {_format_ms(direct.p99_ms)} | {_format_ms(proxy.p99_ms)} | {_format_ms(d(direct.p99_ms, proxy.p99_ms))} |")
    print(f"| err_rate | {direct.errors/direct.requests:.3%} | {proxy.errors/proxy.requests:.3%} | {(proxy.errors/proxy.requests - direct.errors/direct.requests):.3%} |")

def parse_concurrency_list(s: str) -> list[int]:
    out: list[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        n = int(part)
        if n <= 0:
            raise ValueError("concurrency must be positive")
        out.append(n)
    if not out:
        raise ValueError("empty concurrency list")
    return out


def _expected_from_label(label: str) -> str:
    l = label.strip().lower()
    if l == "benign":
        return "allow"
    if l == "malicious":
        return "block"
    return "unknown"


def run_probe(
    endpoint: Endpoint,
    spec: RequestSpec,
    headers: dict[str, str],
    samples: list[BenchmarkSample],
    workers: int,
    retries: int,
    timeout_seconds: float,
    preview_chars: int,
) -> list[ProbeRow]:
    def do_one(sample: BenchmarkSample) -> ProbeRow:
        payload = make_payload(spec, sample.text)
        expected = _expected_from_label(sample.label)
        last: RequestResult | None = None
        last_summary: ResponseSummary = ResponseSummary(blocked=None, preview=None)
        last_attempt = 1
        for attempt in range(1, max(1, retries + 1) + 1):
            rr, body = send_chat_request_capture(endpoint.url, headers, payload, timeout_seconds)
            last = rr
            last_summary = summarize_response(body, preview_chars)
            last_attempt = attempt
            # Retry only on transport/non-2xx errors.
            if rr.ok:
                break
        assert last is not None
        return ProbeRow(
            case=sample.sample_id,
            attempt=last_attempt,
            http=last.status,
            blocked=last_summary.blocked,
            expected=expected,
            latency_ms=last.latency_ms,
            prompt_preview=_truncate(sample.text, 60),
            preview=last_summary.preview,
        )

    rows: list[ProbeRow] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(do_one, s) for s in samples]
        for fut in concurrent.futures.as_completed(futs):
            rows.append(fut.result())
    # Stable order by case id.
    rows.sort(key=lambda r: r.case)
    return rows

def print_probe_markdown(
    endpoint: Endpoint,
    model: str,
    agent_id: str | None,
    token_present: bool,
    workers: int,
    rows: list[ProbeRow],
    show_prompt: bool,
) -> None:
    print(f"\nRunning probe against: {endpoint.url}")
    print(f"Model: {model}")
    print(f"Agent ID: {agent_id or ''}")
    print(f"Token present: {token_present}")
    print(f"Workers: {workers}\n")

    # Monospace table (Markdown code block), similar to the example.
    if show_prompt:
        header = (
            "Case  Try  HTTP   Blocked?  Expected  Latency(ms)  Prompt  Preview\n"
            + "-" * 120
        )
    else:
        header = (
            "Case  Try  HTTP   Blocked?  Expected  Latency(ms)  Preview\n"
            + "-" * 100
        )
    print("```")
    print(header)
    for r in rows:
        blocked = "True" if r.blocked is True else ("False" if r.blocked is False else "")
        http = str(r.http) if r.http is not None else ""
        preview = r.preview or ""
        if show_prompt:
            line = (
                f"{r.case:<24} {r.attempt:<4} {http:<5} {blocked:<8} {r.expected:<8} "
                f"{r.latency_ms:>10.1f}  {r.prompt_preview:<24}  {preview}"
            )
        else:
            line = (
                f"{r.case:<24} {r.attempt:<4} {http:<5} {blocked:<8} {r.expected:<8} "
                f"{r.latency_ms:>10.1f}  {preview}"
            )
        print(line)
    print("```")

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["load", "probe"], default="load", help="load = latency/rps stats; probe = per-case request/response table")
    ap.add_argument("--url", help="Single target URL (OpenAI-compatible /v1/chat/completions).")
    ap.add_argument("--direct-url", help="Direct LLM URL for comparison (no proxy).")
    ap.add_argument("--proxy-url", help="LLMTrace proxy URL for comparison.")
    ap.add_argument("--model", required=True, help="Model name.")
    ap.add_argument("--system", default="You are a helpful assistant.", help="System prompt.")
    ap.add_argument("--prompt", default="Return a one-word response: OK.", help="User prompt (used when no dataset is provided).")
    ap.add_argument(
        "--dataset-file",
        default=None,
        help="Path to a benchmarks dataset JSON (array of {id,text,label,...}). If provided, prompts are taken from dataset.",
    )
    ap.add_argument(
        "--dataset-suite",
        default=None,
        help="Load a built-in suite of datasets from this repo: core, external, all (core+external).",
    )
    ap.add_argument(
        "--dataset-label",
        default="all",
        help="Filter dataset samples by label: benign, malicious, all (default: all).",
    )
    ap.add_argument(
        "--category-contains",
        default=None,
        help="Comma-separated substrings to match in sample category (case-insensitive).",
    )
    ap.add_argument(
        "--subcategory-contains",
        default=None,
        help="Comma-separated substrings to match in sample subcategory (case-insensitive). Example: role_injection,system_override",
    )
    ap.add_argument(
        "--dataset-limit",
        type=int,
        default=0,
        help="If >0, limit to N samples from the dataset (after filtering).",
    )
    ap.add_argument(
        "--dataset-shuffle-seed",
        type=int,
        default=0,
        help="If non-zero, shuffle dataset samples deterministically with this seed.",
    )
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--max-tokens", type=int, default=16)
    ap.add_argument(
        "--token",
        default=None,
        help="Bearer token (sent as Authorization header). If omitted, uses env var LLMTRACE_TOKEN when set.",
    )
    ap.add_argument("--agent-id", default=None, help="Sent as X-LLMTrace-Agent-ID header.")
    ap.add_argument("--timeout-seconds", type=float, default=60.0)
    ap.add_argument("--requests", type=int, default=100, help="Total requests per endpoint+concurrency.")
    ap.add_argument("--concurrency", type=int, default=10, help="Concurrency for fixed mode.")
    ap.add_argument("--concurrency-list", default=None, help="Comma-separated sweep list, e.g. 1,2,5,10,20")
    ap.add_argument("--workers", type=int, default=0, help="Probe workers (default: use --concurrency).")
    ap.add_argument("--retries", type=int, default=0, help="Probe retries per case on error.")
    ap.add_argument("--preview-chars", type=int, default=90, help="Probe preview length.")
    ap.add_argument("--show-prompt", action="store_true", help="Probe mode: include a prompt preview column (request<>response view).")
    ap.add_argument("--progress-every", type=int, default=0, help="Print progress every N completed requests (load mode).")
    ap.add_argument("--jitter-ms", type=int, default=0, help="Random per-request sleep (0..jitter) to avoid lockstep.")
    ap.add_argument("--output-json", default=None, help="Write full results JSON to this path.")
    args = ap.parse_args(argv)

    # Convenience: avoid putting tokens in shell history.
    if not args.token:
        args.token = os.environ.get("LLMTRACE_TOKEN")

    if args.url and (args.direct_url or args.proxy_url):
        ap.error("Use either --url or (--direct-url and/or --proxy-url), not both.")
    if not args.url and not (args.direct_url or args.proxy_url):
        ap.error("Provide --url, or --direct-url/--proxy-url.")
    if args.dataset_file and args.dataset_suite:
        ap.error("Use either --dataset-file or --dataset-suite, not both.")
    if (args.direct_url is None) != (args.proxy_url is None) and args.concurrency_list is None:
        # Comparison runs are easier to interpret as sweeps, but fixed is still ok.
        pass

    spec = RequestSpec(
        model=args.model,
        system_prompt=args.system,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
    )

    headers = build_headers(token=args.token, agent_id=args.agent_id)

    endpoints: list[Endpoint] = []
    if args.url:
        endpoints = [Endpoint(name="target", url=args.url)]
    else:
        if args.direct_url:
            endpoints.append(Endpoint(name="direct", url=args.direct_url))
        if args.proxy_url:
            endpoints.append(Endpoint(name="proxy", url=args.proxy_url))

    concs = parse_concurrency_list(args.concurrency_list) if args.concurrency_list else [args.concurrency]

    user_prompts: list[str]
    dataset_meta: dict[str, Any] | None = None
    category_contains = _parse_csv_lower(args.category_contains)
    subcategory_contains = _parse_csv_lower(args.subcategory_contains)

    if args.dataset_file or args.dataset_suite:
        if args.dataset_file:
            ds_paths = [Path(args.dataset_file)]
            if not ds_paths[0].exists():
                ap.error(f"--dataset-file not found: {ds_paths[0]}")
        else:
            suite = str(args.dataset_suite).strip().lower()
            try:
                ds_paths = _discover_dataset_paths(suite)
            except Exception:
                ap.error("Unknown --dataset-suite. Use: core, external, all.")
                raise
            missing = [str(p) for p in ds_paths if not p.exists()]
            if missing:
                ap.error(f"Dataset suite has missing files: {', '.join(missing)}")
            if not ds_paths:
                ap.error("Dataset suite matched 0 files.")

        samples = _load_datasets(ds_paths)
        samples = _filter_samples(samples, args.dataset_label)
        samples = _filter_by_category(samples, category_contains, subcategory_contains)
        if args.dataset_shuffle_seed:
            rnd = random.Random(args.dataset_shuffle_seed)
            rnd.shuffle(samples)
        if args.dataset_limit and args.dataset_limit > 0:
            samples = samples[: args.dataset_limit]
        if not samples:
            ap.error("dataset selection produced 0 samples")
        user_prompts = [s.text for s in samples]
        dataset_meta = {
            "dataset_file": str(Path(args.dataset_file)) if args.dataset_file else None,
            "dataset_suite": args.dataset_suite,
            "dataset_files": [str(p) for p in ds_paths],
            "dataset_label": args.dataset_label,
            "category_contains": category_contains,
            "subcategory_contains": subcategory_contains,
            "dataset_limit": args.dataset_limit,
            "dataset_shuffle_seed": args.dataset_shuffle_seed,
            "dataset_samples": len(samples),
        }
    else:
        user_prompts = [args.prompt]

    if args.mode == "probe":
        if not (args.dataset_file or args.dataset_suite):
            ap.error("probe mode requires --dataset-file or --dataset-suite")
        workers = args.workers if args.workers > 0 else args.concurrency
        for ep in endpoints:
            rows = run_probe(
                endpoint=ep,
                spec=spec,
                headers=headers,
                samples=samples,  # type: ignore[name-defined]
                workers=workers,
                retries=args.retries,
                timeout_seconds=args.timeout_seconds,
                preview_chars=args.preview_chars,
            )
            print_probe_markdown(
                endpoint=ep,
                model=args.model,
                agent_id=args.agent_id,
                token_present=bool(args.token),
                workers=workers,
                rows=rows,
                show_prompt=bool(args.show_prompt),
            )
        return 0

    all_stats: list[RunStats] = []
    raw_results: dict[str, Any] = {
        "spec": {
            "model": spec.model,
            "system": spec.system_prompt,
            "prompt": args.prompt,
            "temperature": spec.temperature,
            "max_tokens": spec.max_tokens,
        },
        "headers": {
            "has_token": bool(args.token),
            "agent_id": args.agent_id,
        },
        "dataset": dataset_meta,
        "runs": [],
    }

    print(f"token_present={bool(args.token)} agent_id={args.agent_id!r}")

    for conc in concs:
        for ep in endpoints:
            print(f"\nRunning endpoint={ep.name} conc={conc} requests={args.requests} ...")
            s, results = run_load(
                endpoint=ep,
                spec=spec,
                headers=headers,
                concurrency=conc,
                total_requests=args.requests,
                timeout_seconds=args.timeout_seconds,
                jitter_ms=args.jitter_ms,
                user_prompts=user_prompts,
                progress_every=args.progress_every,
            )
            all_stats.append(s)
            raw_results["runs"].append(
                {
                    "endpoint": ep.name,
                    "url": ep.url,
                    "concurrency": conc,
                    "requests": s.requests,
                    "ok": s.ok,
                    "errors": s.errors,
                    "duration_s": s.duration_s,
                    "ok_rps": s.rps_ok,
                    "latencies_ms_ok": [r.latency_ms for r in results if r.ok],
                    "statuses": s.statuses,
                    "errors_sample": [r.error for r in results if not r.ok][:10],
                }
            )

        # If comparing direct+proxy at same conc, print overhead row.
        if any(s.endpoint == "direct" and s.concurrency == conc for s in all_stats) and any(
            s.endpoint == "proxy" and s.concurrency == conc for s in all_stats
        ):
            dstat = next(s for s in all_stats if s.endpoint == "direct" and s.concurrency == conc)
            pstat = next(s for s in all_stats if s.endpoint == "proxy" and s.concurrency == conc)
            print_stats_table(f"Results (concurrency={conc})", [dstat, pstat])
            print_overhead_table(dstat, pstat)

    if args.url:
        print_stats_table("Results", all_stats)
    else:
        # Print a compact sweep view per endpoint.
        print_stats_table("Sweep Results", all_stats)

    if args.output_json:
        out_path = os.fspath(args.output_json)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(raw_results, f, indent=2, sort_keys=True)
        print(f"\nWrote {out_path}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
