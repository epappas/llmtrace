# LLM Judge — Setup & Operations

The **LLM Judge** is LLMTrace's third security detector alongside the
regex tier and the DeBERTa classifier. It sends the candidate text to
a dedicated language model that returns a structured verdict
(`is_threat`, `category`, `confidence`, `security_score`,
`recommended_action`, `reasoning`). The proxy then merges the verdict
into the ensemble and, optionally, promotes it into a Block decision
through a promotion gate.

This guide covers **how to turn it on in practice**. For the design
rationale, see [`architecture/LLM_JUDGE.md`](../architecture/LLM_JUDGE.md).
For real performance numbers against published corpora, see the
[evaluation report](../research/results/judge_evaluation_gpt4o_mini_2026-04-20.md).

---

## The three-tier cascade (what this looks like in production)

The judge is not a single remote call. It's a cascade:

```
elevated candidate
  → Tier 2: fast-judge (DeBERTa local, 20–50 ms)
    → high or low confidence → final
    → ambiguous band         → Tier 3: slow-judge (local Qwen / remote LLM)
```

Operators pick one of three shipping patterns depending on what
they have available:

| Pattern | `backend` | `cascade.slow_backend` | When |
|---|---|---|---|
| Fast-only (ships today) | `cascade` | `null` | You have DeBERTa but no fine-tuned local LLM judge yet |
| Fast + remote reasoned | `cascade` | `openai` or `anthropic` | Cheap fast path, expensive reasoning only on ambiguous cases |
| Fast + local reasoned | `cascade` | `vllm` pointing at a local Qwen LoRA | Zero-cost steady state, no egress, issue #90 |
| Single backend | `openai` / `anthropic` / `vllm` / `deberta` | — | No cascade, just pick one |

The rationale and per-tier responsibilities are documented in
[`architecture/JUDGE_CASCADE.md`](../architecture/JUDGE_CASCADE.md).

## Before you enable it

The judge is fail-open, runtime-toggleable, and shadow-capable. That
means you can turn it on without risking request flow. But it still
has real cost and real latency, so some decisions are worth making
up front.

### 1. Pick a backend

| Backend | When to use | Typical p95 | Approx $/call (April 2026) |
|---|---|---|---|
| `openai` (incl. OpenAI-compatible gateways like OpenRouter, Azure, LiteLLM) | Fastest start, no infra; strict-JSON-schema mode for reliability | ~2.5 s | $0.0001 (gpt-4o-mini) — $0.004 (gpt-4o) |
| `anthropic` | When you want cross-family diversity from the upstream model under test; native prompt caching | ~2–3 s | $0.0003 (claude-3-5-haiku) |
| `vllm` | Self-hosted, data never leaves your network, cost is GPU-hours | network-RTT dominated | $0 at runtime |

You can run a different judge family than the upstream LLM you're
protecting — that's the point. If the upstream is GPT-4o, judge with
Claude. If upstream is Claude, judge with a local Llama via vLLM.

### 2. Choose inline vs async

The judge defaults to **async**. Verdicts arrive after the request
completes, are persisted to `judge_verdicts`, and feed the ensemble
for future decisions. This is the right mode for production.

Inline mode (`judge.enabled=true` + the action-router
`judge_route.inline_await=true`) waits up to
`judge_route.inline_timeout_ms` for a verdict before proceeding.
Useful when you want the judge to gate individual requests, but be
aware of the latency profile in the evaluation report —
`gpt-4o-mini` p95 is 2.6 s, which exceeds the default 2 s timeout.
Either raise `inline_timeout_ms` to ≥ 4000 on slower providers, or
keep inline off.

### 3. Plan the rollout

**We strongly recommend shadow mode for the first 1 000 verdicts.**
`promotion.shadow=true` runs the judge end-to-end (persists verdicts,
emits metrics) but never promotes Block. You collect real data
without affecting enforcement. Once you've reviewed the
`judge_shadow_would_block_total` rate and fitted calibration, flip
`shadow=false`.

---

## Minimal configs

All examples assume the proxy is built with the `judge` feature
enabled. The default build from `cargo build -p llmtrace --release`
already has it on.

### OpenAI (or OpenAI-compatible)

```yaml
judge:
  enabled: true
  backend: openai
  openai:
    base_url: "https://api.openai.com"   # or https://openrouter.ai/api
    model: "gpt-4o-mini"                 # prefix with openai/ for OpenRouter
    max_tokens: 512
    temperature: 0.1
  promotion:
    shadow: true                         # keep shadow for first rollout
```

Then set the API key as an environment variable **before starting
the proxy** — never in the config file:

```bash
export LLMTRACE_JUDGE_OPENAI_API_KEY='sk-...'
```

### Anthropic

```yaml
judge:
  enabled: true
  backend: anthropic
  anthropic:
    model: "claude-3-5-haiku-20241022"
    max_tokens: 512
    temperature: 0.1
  promotion:
    shadow: true
```

```bash
export LLMTRACE_JUDGE_ANTHROPIC_API_KEY='...'
```

The Anthropic backend enables prompt caching automatically (issue
#82, the hardened system prompt is flagged `cache_control:
ephemeral`), which materially reduces cost on repeat traffic.

### Cascade (DeBERTa fast-judge → optional LLM slow-judge)

The production-recommended default. Set `backend: cascade` and pick
which inner backends fill the two tiers. The slow tier is `null` on
day one (fast-only); you flip it on later without any code change.

```yaml
judge:
  enabled: true
  backend: cascade
  cascade:
    fast_backend: deberta
    # slow_backend: null            # today: fast-only, no reasoned second opinion
    # slow_backend: openai          # tomorrow: use OpenAI for ambiguous cases
    # slow_backend: vllm            # once Qwen judge (#90) is deployed locally
    ambiguous_low: 0.3
    ambiguous_high: 0.7

  deberta:
    model_id: "protectai/deberta-v3-base-prompt-injection-v2"
    threshold: 0.5
    # cache_dir: "~/.cache/llmtrace/models"

  # Configure whichever slow backend you pick above; unused
  # backend blocks are ignored.
  openai:
    base_url: "https://api.openai.com"
    model: "gpt-4o-mini"
  vllm:
    base_url: "http://vllm.internal:8000"
    model: "llmtrace-qwen-judge-v1"

  promotion:
    shadow: true   # shadow-first, always
```

Tuning notes:

- **Ambiguous band defaults to `[0.3, 0.7]`.** Tighten it (e.g.
  `[0.4, 0.6]`) if you want the slow tier to fire less often; widen
  it if you're seeing too many unreviewed fast-tier blocks in
  production. The calibration workflow in
  [§ Shadow-mode rollout](#shadow-mode-rollout-recommended) produces
  the curve you need to pick good bounds.
- **On fast-tier errors** the cascade automatically tries the slow
  tier as a resilience fallback, if one is configured. On slow-tier
  errors mid-escalation it keeps the fast verdict. Either way the
  judge never *fails* — it just degrades.
- **DeBERTa as the fast-judge is a classifier.** It cannot produce
  `category` or `reasoning`; the cascade synthesises those from a
  fixed template. See
  [`architecture/JUDGE_CASCADE.md §3.5`](../architecture/JUDGE_CASCADE.md).
  If you need an LLM-style verdict with natural-language reasoning,
  the slow tier is where it belongs.

### DeBERTa fast-judge (classifier-only, standalone)

Useful for local-only or air-gapped deployments that want the
judge's governance (shadow mode, promotion gate, verdict
persistence) without any LLM involvement.

```yaml
judge:
  enabled: true
  backend: deberta
  deberta:
    model_id: "protectai/deberta-v3-base-prompt-injection-v2"
    threshold: 0.5
  promotion:
    shadow: true
```

Requires the proxy to be built with both the `judge` and `ml`
features (the default release profile already has both).

### vLLM (self-hosted)

```yaml
judge:
  enabled: true
  backend: vllm
  vllm:
    base_url: "http://vllm.internal:8000"
    model: "meta-llama/Llama-3.1-8B-Instruct"
    max_tokens: 512
    temperature: 0.1
    allow_plaintext: false               # set true only for loopback
  promotion:
    shadow: true
```

No API key. If `base_url` is plaintext `http://` and the host is not
loopback (`localhost`, `127.0.0.1`, `::1`), the proxy will refuse to
start unless `allow_plaintext: true` is explicitly set. This is
issue #77: it prevents silent interception of judge traffic.

---

## Production config (all fields)

Every field has a sensible default. This is what you'd set when
tuning explicitly.

```yaml
judge:
  enabled: true
  backend: openai
  openai:
    base_url: "https://api.openai.com"
    model: "gpt-4o-mini"
    max_tokens: 512
    temperature: 0.1

  worker:
    channel_buffer: 1000          # bounded queue of pending judge requests
    max_concurrency: 4            # in-flight requests to the backend
    timeout_ms: 30000             # per-call HTTP timeout
    max_analysis_text_bytes: 65536   # 64 KiB; candidate text is truncated above this
    total_deadline_ms: 45000      # hard ceiling on one judge call incl. retries + backoff

  retry:
    max_retries: 2
    backoff_base_ms: 1000         # exponential with full jitter, honours Retry-After

  promotion:
    min_confidence: 0.7           # pre-calibration placeholder (see calibration-status)
    min_security_score: 60
    require_ensemble_support: true  # require a Medium+ prior finding to promote Block
    shadow: false                 # flip to true during rollout

  system_prompt: ""               # "" uses the hardened default in prompt.rs
  min_score_threshold: 30         # only judge prompts with ensemble score >= 30
  persist_verdicts: true
```

### Worker tuning rules of thumb

- `channel_buffer × max_analysis_text_bytes` bounds the judge's
  in-flight memory. Default: `1000 × 64 KiB ≈ 64 MiB`. Fits the
  default 512 MiB Helm pod limit with headroom.
- `max_concurrency = 4` gives ~2.5 req/s with `gpt-4o-mini`. Raise
  it if your provider's RPM allows and you want more throughput.
- `total_deadline_ms ≥ timeout_ms × (max_retries + 1) + backoff`.
  The default 45 000 ms covers `30 000 + 30 000 + jitter`.

---

## Turning it on at runtime

The judge is hot-reloadable via the admin feature-flag API — no
restart:

```bash
# Confirm current state
curl -s https://llmtrace/admin/feature-flags | jq '.llm_judge_enabled'

# Enable
curl -s -X PUT https://llmtrace/admin/feature-flags/llm_judge_enabled \
  -H 'content-type: application/json' \
  -d '{"enabled": true}'

# Check health — should report judge = healthy with a spawned worker
curl -s https://llmtrace/health | jq '.judge'
```

The `enabled` field in the config file and the `llm_judge_enabled`
admin flag are the same value (one wire name, one source of truth).
Toggling via the admin API takes effect on the next request.

---

## Shadow-mode rollout (recommended)

This is the safest way to introduce the judge on live traffic.

1. **Enable with `shadow: true`.** Verdicts are recorded and metrics
   fire, but the promotion gate never flips an outcome to Block.
2. **Watch `llmtrace_judge_shadow_would_block_total{category,
   recommended_action}`.** This counter increments every time the
   judge would have blocked under current thresholds. Compare it to
   your baseline block rate; if it's 10 × higher, do not flip yet.
3. **Collect ≥ 1 000 verdicts** across your traffic profile. Export
   them from the `judge_verdicts` table:

    ```sql
    SELECT confidence, is_threat, recommended_action, category
    FROM judge_verdicts
    WHERE created_at > now() - INTERVAL '7 days';
    ```

4. **Calibrate** `promotion.min_confidence`. Group verdicts by
   confidence bucket, compute observed precision per bucket, pick
   the threshold at your target false-positive rate. See the
   [calibration status section of the design doc][calibration-status].
   Golden-set work is tracked in [issue #66][issue-66].
5. **Flip `shadow: false`.** Keep monitoring the
   `judge_promotion_rejected_total` counter — it tells you how many
   verdicts *tried* to promote but were held back by your gates.

[calibration-status]: ../architecture/LLM_JUDGE.md#49-calibration-status
[issue-66]: https://github.com/epappas/llmtrace/issues/66

---

## Metrics to watch

All metrics carry the `backend` and `model` labels (issue #83), so
you can compare judges without grouping yourself.

| Metric | Type | What it tells you |
|---|---|---|
| `llmtrace_judge_requests_total{backend,model,mode,status}` | counter | Verdict volume + error class (success, timeout, backend_error, parse_error, misconfigured, transport_error, shutdown) |
| `llmtrace_judge_latency_seconds{backend,model,mode}` | histogram | End-to-end latency distribution; watch p95/p99 vs. your inline budget |
| `llmtrace_judge_tokens_total{direction,backend,model}` | counter | Input + output tokens; multiply by your provider's published rates for cost |
| `llmtrace_judge_verdicts_total{category,recommended_action,is_threat,model}` | counter | Distribution of what the judge is saying |
| `llmtrace_judge_queue_depth` | gauge | Outstanding items in the worker channel; non-zero sustained = you're rate-limited |
| `llmtrace_judge_verdict_agreement{agreement}` | counter | Whether the judge agreed with the prior ensemble decision (`agree_block`, `disagree_block`, etc.) |
| `llmtrace_judge_dropped_total{reason}` | counter | Requests the worker never sent a backend call for; reasons: disabled, below_threshold, channel_full, channel_closed, persist_failure, semaphore_closed, shutdown, analysis_text_truncated |
| `llmtrace_judge_promotion_rejected_total{reason}` | counter | Verdicts the gate held back: not_threat_or_block, below_confidence, below_score, no_ensemble_support |
| `llmtrace_judge_shadow_would_block_total{category,recommended_action}` | counter | Shadow-mode would-block rate — your primary calibration signal |

### Dashboards

- **Volume & cost:** `rate(llmtrace_judge_requests_total{status="success"}[5m])`
  and `sum(rate(llmtrace_judge_tokens_total[5m])) by (direction, model)`.
- **Latency headroom:** `histogram_quantile(0.95,
  rate(llmtrace_judge_latency_seconds_bucket[5m]))`.
- **Failure triage:** `sum by (status)
  (rate(llmtrace_judge_requests_total[5m]))`.
- **Shadow signal:** `rate(llmtrace_judge_shadow_would_block_total[1h])`
  vs. your existing regex/ML block rate.

---

## Validating a new backend — the smoke binary

Before wiring the judge into your proxy, confirm the backend
actually works against your chosen provider:

```bash
export LLMTRACE_JUDGE_OPENAI_API_KEY='...'
cargo run --example judge_smoke -p llmtrace-security \
  --features judge --release
```

The binary judges one benign prompt and one obvious injection and
prints both verdicts. If you see categorised verdicts with token
counts, the provider contract is working. This is especially useful
when pointing at an OpenAI-compatible gateway (OpenRouter, LiteLLM,
Azure) to verify its response-format passthrough.

For a quantitative run against the shipped labeled corpora:

```bash
BENCH_MAX_PER_SET=50 BENCH_EXTERNAL_DIR=benchmarks/datasets/external \
cargo run --example judge_benchmark -p llmtrace-security \
  --features judge --release
```

Budget ~$0.15 for the full sweep on `gpt-4o-mini`. See the
[evaluation report](../research/results/judge_evaluation_gpt4o_mini_2026-04-20.md)
for one reference run.

---

## Troubleshooting

### `judge backend=openai requires env var LLMTRACE_JUDGE_OPENAI_API_KEY to be set`

The proxy refused to start because the judge is configured with
`backend: openai` but the environment variable is missing. Either:

- Export the key before starting the proxy, or
- Leave the judge disabled (`enabled: false`) until you're ready.

The analogous message for `backend: anthropic` uses
`LLMTRACE_JUDGE_ANTHROPIC_API_KEY`.

### `judge base_url uses plaintext HTTP to a non-loopback host`

Issue #77's guardrail. Either switch to HTTPS, set `base_url` to a
loopback host (`http://localhost:...` is fine), or explicitly opt in
with `vllm.allow_plaintext: true`.

### `judge_requests_total{status="parse_error"}` is non-zero

The backend returned something that didn't match the verdict JSON
schema.

- For **OpenAI** this should be near-zero because strict
  `json_schema` is enforced (issue #81).
- For **vLLM** this can happen with older models that don't reliably
  follow `response_format: json_object`. Try a stronger instruction
  model or fine-tune a judge.
- For **Anthropic** it can happen when the model wraps JSON in a
  code fence; the parser tolerates fences but not every variant.

Check `parser.rs` for what it accepts; increase `max_tokens` if the
verdict was truncated (look for truncated `reasoning` strings).

### `judge_dropped_total{reason="channel_full"}` spikes

The worker channel is saturated. Three knobs, in order of impact:

1. Raise `worker.max_concurrency` if your provider's RPM allows.
2. Raise `worker.channel_buffer` (costs memory).
3. Raise `min_score_threshold` to fire the judge on fewer prompts.

### p95 latency exceeds `inline_timeout_ms`

The judge is slower than you budgeted. Either raise the inline
timeout or keep the judge in async mode. The evaluation report
shows `gpt-4o-mini` at p95 ≈ 2.6 s; smaller inline budgets will
systematically drop verdicts.

### The judge blocks legitimate traffic

First check `llmtrace_judge_verdicts_total` — is the judge actually
saying `is_threat=true, recommended_action=block` on benign
prompts? If so:

1. **Are you in shadow mode?** If yes, you're only seeing metrics;
   real traffic is untouched.
2. **Is `require_ensemble_support: true`?** That's the default. It
   requires a Medium+ prior regex/ML finding before the judge can
   block on its own. If you set it `false`, the judge becomes a
   single detector with single-detector risk.
3. **Is the over-refusal profile the cause?** Run the smoke or
   benchmark against the `xstest` set and check the FPR — if it's
   high, the model itself is over-refusing. Try a different model.

### `judge_error_status="misconfigured"`

The backend rejected the config at construction time. Most common
cause is a base URL without a scheme (`api.openai.com` instead of
`https://api.openai.com`) or a model name the provider doesn't
know. The error message is logged at WARN.

---

## Cost discipline

On `gpt-4o-mini` the judge costs **≈ $0.00012 per call** at
~500 input + 60 output tokens. Real cost is much lower than
call-volume × that number because the judge only fires when prior
ensemble score ≥ `min_score_threshold`.

Practical tuning:

- Raise `min_score_threshold` from 30 → 50 if you want to judge
  only clearly suspicious traffic.
- Enable Anthropic's prompt caching (automatic — just use
  `backend: anthropic`).
- For self-hosted, use a small instruction model (Llama-3.1-8B,
  Qwen-2.5-7B) rather than a flagship.
- Set `persist_verdicts: false` if you're running in shadow mode
  and don't need long-term verdict history; the ensemble still
  sees the verdict in-memory.

---

## Related pages

- [Architecture: LLM Judge design](../architecture/LLM_JUDGE.md) — why it works the way it does.
- [Evaluation report (gpt-4o-mini, 27 corpora)](../research/results/judge_evaluation_gpt4o_mini_2026-04-20.md) — concrete numbers.
- [LLM-Judge Reliability Patterns](../research/llm-judge-reliability-patterns.md) — research background.
- [Configuration reference](../getting-started/configuration.md) — full config schema summary.
- [Feature flags runbook](../runbooks/feature-flags.md) — admin API details.

---
