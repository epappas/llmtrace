"""Per-scenario observability for the e2e adversarial test framework.

Wraps `/metrics` snapshots so harness assertions can talk in terms of
"this scenario produced N findings of type X". Counter / histogram /
gauge semantics are honoured by `MetricsSnapshot.diff`:

  * Counters: subtract values; result is the delta over the window.
  * Histograms: same as counters at the sample level — `_count` and
    `_sum` flatten to counter samples in the Prometheus exposition
    parser, so they diff naturally.
  * Gauges: the *latest* (right-hand) snapshot wins.

`series(name, labels)` does a *subset-label match*: a query with
`{"finding_type": "prompt_injection"}` against a metric labelled by
`{"severity", "finding_type"}` returns the **sum** across all matching
severities. This is the most useful default for harness assertions
("at least 1 prompt_injection finding regardless of severity").

Loop E2E-L4 of #91. Built on top of L3's harness; consumed by L6's
expectation DSL.
"""

from __future__ import annotations

import textwrap
import time
from dataclasses import dataclass, field
from typing import Iterable, Mapping

import requests
from prometheus_client.parser import text_string_to_metric_families

# Sample key: (metric_name, frozenset of label items).
SampleKey = tuple[str, frozenset[tuple[str, str]]]


@dataclass
class MetricsSnapshot:
    """Immutable snapshot of /metrics at a point in time.

    Constructed via `fetch(url)` (live HTTP) or `parse(text)` (recorded
    text). All comparison helpers are pure; no I/O after construction.
    """

    samples: dict[SampleKey, float] = field(default_factory=dict)
    metric_types: dict[str, str] = field(default_factory=dict)

    # ---- factories ---------------------------------------------------

    @classmethod
    def fetch(cls, metrics_url: str, timeout: float = 5.0) -> "MetricsSnapshot":
        response = requests.get(metrics_url, timeout=timeout)
        response.raise_for_status()
        return cls.parse(response.text)

    @classmethod
    def parse(cls, text: str) -> "MetricsSnapshot":
        samples: dict[SampleKey, float] = {}
        metric_types: dict[str, str] = {}
        for family in text_string_to_metric_families(text):
            metric_types[family.name] = family.type
            for sample in family.samples:
                key = (sample.name, frozenset(sample.labels.items()))
                samples[key] = float(sample.value)
        return cls(samples=samples, metric_types=metric_types)

    # ---- diff --------------------------------------------------------

    def diff(self, before: "MetricsSnapshot") -> "MetricsSnapshot":
        """Return self minus `before` per Prometheus semantics."""
        diff_samples: dict[SampleKey, float] = {}
        for key, after_value in self.samples.items():
            metric_name = key[0]
            metric_family = self._family_name(metric_name)
            kind = self.metric_types.get(metric_family) or before.metric_types.get(
                metric_family
            )
            if kind == "gauge":
                diff_samples[key] = after_value
            else:
                diff_samples[key] = after_value - before.samples.get(key, 0.0)
        # Samples present only in `before` collapse to zero in the delta and
        # are dropped — they cannot affect counter assertions.
        return MetricsSnapshot(
            samples=diff_samples,
            metric_types=dict(self.metric_types),
        )

    @staticmethod
    def _family_name(sample_name: str) -> str:
        # Order matters: longer suffixes first so `_count` strips before `_t`.
        # `_total` is the canonical counter suffix that the Prometheus parser
        # already strips on the family name; we mirror it on sample names so
        # users can query either form.
        for suffix in ("_bucket", "_count", "_sum", "_created", "_total"):
            if sample_name.endswith(suffix):
                return sample_name[: -len(suffix)]
        return sample_name

    # ---- queries -----------------------------------------------------

    def __contains__(self, metric_name: str) -> bool:
        for key in self.samples:
            if key[0] == metric_name or self._family_name(key[0]) == metric_name:
                return True
        return False

    def series(
        self, name: str, labels: Mapping[str, str] | None = None
    ) -> float | None:
        """Return the (sum across) samples matching `name` + label subset.

        `name` matches against the per-sample name first (exact match for
        the histogram-flattened `_count`/`_sum`/`_bucket` form), and falls
        back to the metric family name for counters/gauges. `labels` is a
        subset match: a query specifying one label sums across all other
        labels' cardinality. Returns `None` when no sample matches so
        callers can distinguish "not observed" from "observed as zero".
        """
        wanted = frozenset((labels or {}).items())
        total = 0.0
        matched = False
        for (sample_name, sample_labels), value in self.samples.items():
            family = self._family_name(sample_name)
            if name not in (sample_name, family):
                continue
            if not wanted.issubset(sample_labels):
                continue
            total += value
            matched = True
        return total if matched else None

    # ---- pretty-printing --------------------------------------------

    def nonzero_items(self) -> list[tuple[str, dict[str, str], float]]:
        items: list[tuple[str, dict[str, str], float]] = []
        for (name, labels), value in self.samples.items():
            if value == 0.0:
                continue
            items.append((name, dict(labels), value))
        items.sort(key=lambda row: (row[0], sorted(row[1].items())))
        return items

    def render_nonzero(self, indent: int = 2) -> str:
        rows = self.nonzero_items()
        if not rows:
            return "  (no non-zero samples)"
        lines: list[str] = []
        for name, labels, value in rows:
            label_str = (
                "{" + ",".join(f"{k}={v!r}" for k, v in sorted(labels.items())) + "}"
                if labels
                else ""
            )
            lines.append(f"{name}{label_str} {_format_value(value)}")
        return textwrap.indent("\n".join(lines), " " * indent)


def _format_value(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return f"{value:.6g}"


def collect_finding_types(delta: MetricsSnapshot) -> set[str]:
    """Return the set of `finding_type` labels seen in `llmtrace_security_findings_total` deltas."""
    out: set[str] = set()
    for (name, labels), value in delta.samples.items():
        if name != "llmtrace_security_findings_total":
            continue
        if value <= 0:
            continue
        finding_type = dict(labels).get("finding_type")
        if finding_type:
            out.add(finding_type)
    return out


def poll_judge_verdict(
    proxy_base_url: str,
    trace_id,
    *,
    timeout_secs: float = 10.0,
    poll_interval_secs: float = 0.25,
) -> dict | None:
    """Poll `GET /debug/judge/verdicts?trace_id=<uuid>` until verdict found.

    The judge worker runs asynchronously after the upstream response
    returns to the client, so the verdict for a request typically lands
    in the store 10s–500ms later. The harness polls until either:

      * the proxy returns 200 with a verdict body (returned as a dict),
      * the proxy returns 404 for the entire `timeout_secs` window
        (returned as None — caller decides whether that's a soft
        skip-the-assertion or a hard failure),
      * the proxy returns 4xx/5xx other than 404 (raised as
        `requests.HTTPError` so misconfigurations surface loudly).

    Returns the raw verdict dict (matches LLMTrace's JudgeVerdict
    serialisation) or None on timeout. Requires `server.debug_endpoints:
    true` in the proxy config — without it the endpoint returns 404
    immediately and this helper times out.
    """
    url = f"{proxy_base_url.rstrip('/')}/debug/judge/verdicts"
    deadline = time.monotonic() + timeout_secs
    while time.monotonic() < deadline:
        response = requests.get(url, params={"trace_id": str(trace_id)}, timeout=2.0)
        if response.status_code == 200:
            return response.json()
        if response.status_code != 404:
            response.raise_for_status()
        time.sleep(poll_interval_secs)
    return None


def shadow_would_block_count(
    delta: MetricsSnapshot,
    *,
    category: str | None = None,
    recommended_action: str | None = None,
) -> float:
    """Sum the `llmtrace_judge_shadow_would_block_total` delta.

    Returns 0.0 when the metric is absent so callers can treat
    "no shadow-mode signal" symmetrically with "judge tier disabled".
    The optional `category` / `recommended_action` filters narrow the
    sum; with both `None` the result is the total across all label sets.
    """
    labels: dict[str, str] = {}
    if category is not None:
        labels["category"] = category
    if recommended_action is not None:
        labels["recommended_action"] = recommended_action
    observed = delta.series(
        "llmtrace_judge_shadow_would_block_total", labels
    )
    return observed if observed is not None else 0.0


def judge_backend_errored(delta: MetricsSnapshot) -> bool:
    """Return True iff the judge tier reported a backend error in the window.

    Signals that a verdict assertion should be softened to a warning
    (degraded mode) rather than fail the scenario. Per the #91 design
    note: provider/upstream flakes must not turn e2e red — only
    LLMTrace-side regressions should.
    """
    observed = delta.series(
        "llmtrace_judge_requests_total", {"status": "backend_error"}
    )
    return observed is not None and observed > 0


def fetch_after_until_settled(
    metrics_url: str,
    *,
    before: MetricsSnapshot,
    expect_metric_change: bool,
    timeout_secs: float = 10.0,
    poll_interval_secs: float = 0.25,
) -> MetricsSnapshot:
    """Fetch /metrics, polling until the delta stops changing.

    LLMTrace records security findings + costs in a background task that
    runs *after* the upstream response returns to the client. A naive
    `MetricsSnapshot.fetch` immediately after `proxy.post_chat()` will
    miss those updates. This helper polls until either:

      * `expect_metric_change=True`: the delta against `before` becomes
        non-empty (background task wrote something), then waits one more
        poll interval to confirm the writes settled.
      * `expect_metric_change=False`: a single poll is taken (any
        background-only metrics stay zero, which is what we want for
        scenarios expected to produce no findings).

    On timeout the most recent snapshot is returned so callers still see
    something to assert against. The returned `MetricsSnapshot` is the
    raw `after` snapshot (call `.diff(before)` to get the delta).
    """
    after = MetricsSnapshot.fetch(metrics_url)
    if not expect_metric_change:
        return after
    deadline = time.monotonic() + timeout_secs
    last_nonzero = len(after.diff(before).nonzero_items())
    settle_seen = False
    while time.monotonic() < deadline:
        time.sleep(poll_interval_secs)
        after = MetricsSnapshot.fetch(metrics_url)
        nonzero = len(after.diff(before).nonzero_items())
        if nonzero > 0 and nonzero == last_nonzero:
            if settle_seen:
                return after
            settle_seen = True
        else:
            settle_seen = False
            last_nonzero = nonzero
    return after


def render_assertion_context(
    delta: MetricsSnapshot,
    *,
    families_of_interest: Iterable[str] = (
        "llmtrace_security_findings_total",
        "llmtrace_action_executions_total",
        "llmtrace_judge_requests_total",
        "llmtrace_judge_verdicts_total",
        "llmtrace_judge_shadow_would_block_total",
        "llmtrace_judge_promotion_rejected_total",
        "llmtrace_judge_dropped_total",
    ),
) -> str:
    """Format the subset of the delta most useful for triaging a failure."""
    # Accept either the user-visible `_total`-suffixed name or the family
    # form the Prometheus parser produces.
    wanted = {MetricsSnapshot._family_name(name) for name in families_of_interest}
    wanted.update(families_of_interest)
    relevant = MetricsSnapshot(
        samples={
            key: value
            for key, value in delta.samples.items()
            if key[0] in wanted or MetricsSnapshot._family_name(key[0]) in wanted
        },
        metric_types=dict(delta.metric_types),
    )
    if not relevant.samples:
        return "  (no security/judge/action deltas observed)"
    return relevant.render_nonzero()
