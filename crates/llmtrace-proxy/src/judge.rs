//! LLM-as-a-Judge worker loop (issue #43 Phase 4).
//!
//! The worker owns the receiving end of the mpsc channel whose sending
//! end lives inside the `JudgeRouteAction` registered with the
//! `ActionRouter`. It pulls `JudgeRequest` envelopes off the channel,
//! gates them through the runtime config (`ConfigHandle`), applies the
//! `min_score_threshold` filter, dispatches to the configured
//! `JudgeBackend`, persists the verdict to the `JudgeVerdictStore`,
//! and (on the inline path) returns the verdict to the caller via a
//! oneshot.
//!
//! All failure paths are fail-open: a judge failure never changes the
//! outcome of the current request versus the no-judge baseline. Each
//! failure class is recorded as a labelled metric so the operator can
//! see the drop rate without digging through logs.

use llmtrace_core::{
    AnthropicBackendConfig, JudgeBackendKind, JudgeConfig, JudgeVerdictStore, OpenAiBackendConfig,
    ProxyConfig, VllmBackendConfig,
};
use llmtrace_security::judge::{
    AnthropicJudgeBackend, AnthropicJudgeOptions, JudgeBackend, JudgeCandidate, JudgeError,
    OpenAIJudgeBackend, OpenAiJudgeOptions, VllmJudgeBackend, ANTHROPIC_API_KEY_ENV,
    OPENAI_API_KEY_ENV,
};
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::action_router::{JudgeRequest, JudgeResponse};
use crate::metrics::Metrics;
use crate::shutdown::ShutdownCoordinator;

/// Snapshot provider for the worker. Decouples the worker from the
/// full `AppState` so unit tests can drive it with a stand-alone
/// `ArcSwap`-backed snapshotter.
pub trait ConfigSnapshotSource: Send + Sync {
    fn snapshot(&self) -> Arc<ProxyConfig>;
}

impl ConfigSnapshotSource for crate::config_handle::ConfigHandle {
    fn snapshot(&self) -> Arc<ProxyConfig> {
        crate::config_handle::ConfigHandle::snapshot(self)
    }
}

/// Worker loop that drives judge invocations.
pub struct JudgeWorker {
    rx: mpsc::Receiver<JudgeRequest>,
    backend: Arc<dyn JudgeBackend>,
    store: Arc<dyn JudgeVerdictStore>,
    config: Arc<dyn ConfigSnapshotSource>,
    metrics: Metrics,
    concurrency: Arc<Semaphore>,
    /// Shared shutdown coordinator. The outer `run()` loop exits when
    /// the token fires; each per-request backend task registers a
    /// `TaskGuard` with the coordinator so `wait_for_tasks()` actually
    /// waits for them to drain on SIGTERM. See issue #68.
    shutdown: ShutdownCoordinator,
}

impl JudgeWorker {
    /// Construct a worker. Ownership of `rx` is taken from the
    /// [`ActionRouter`] via `take_judge_receiver()`.
    #[must_use]
    pub fn new(
        rx: mpsc::Receiver<JudgeRequest>,
        backend: Arc<dyn JudgeBackend>,
        store: Arc<dyn JudgeVerdictStore>,
        config: Arc<dyn ConfigSnapshotSource>,
        metrics: Metrics,
        max_concurrency: usize,
        shutdown: ShutdownCoordinator,
    ) -> Self {
        Self {
            rx,
            backend,
            store,
            config,
            metrics,
            concurrency: Arc::new(Semaphore::new(max_concurrency.max(1))),
            shutdown,
        }
    }

    /// Run the worker until the channel closes or shutdown is signaled.
    ///
    /// On shutdown the loop exits promptly; in-flight per-request
    /// tasks are tracked via `ShutdownCoordinator::track_task` so
    /// `wait_for_tasks()` blocks until they drain (or the grace window
    /// expires).
    pub async fn run(mut self) {
        let token = self.shutdown.token();
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    debug!("JudgeWorker shutdown signaled; draining");
                    break;
                }
                req = self.rx.recv() => {
                    match req {
                        Some(r) => self.handle(r).await,
                        None => {
                            debug!("JudgeWorker channel closed; loop exiting");
                            break;
                        }
                    }
                }
            }
        }
        // Reset the queue-depth gauge so dashboards do not show stale
        // depth after the process drains.
        self.metrics.judge_queue_depth.set(0);
    }

    async fn handle(&self, req: JudgeRequest) {
        let cfg = self.config.snapshot();
        let judge_cfg = &cfg.judge;
        self.metrics.judge_queue_depth.set(self.rx.len() as i64);

        // Disabled gate
        if !judge_cfg.enabled {
            respond_skipped(req, "judge_disabled");
            self.metrics.record_judge_dropped("disabled");
            return;
        }

        // Min-score threshold gate
        let candidate = into_candidate(&req);
        let peak = candidate.peak_prior_severity_score();
        if peak < judge_cfg.min_score_threshold {
            respond_skipped(req, "below_threshold");
            self.metrics.record_judge_dropped("below_threshold");
            return;
        }

        let permit = match self.concurrency.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                warn!("JudgeWorker semaphore closed; dropping request");
                self.metrics.record_judge_dropped("semaphore_closed");
                respond_error(req, "semaphore closed");
                return;
            }
        };

        let backend = Arc::clone(&self.backend);
        let store = Arc::clone(&self.store);
        let metrics = self.metrics.clone();
        let persist = judge_cfg.persist_verdicts;
        let task_guard = self.shutdown.track_task();
        let cancel = self.shutdown.token();

        tokio::spawn(async move {
            let _permit = permit; // release semaphore slot on task completion
            let _task_guard = task_guard; // decrements in_flight count on drop
            run_one(&backend, &store, persist, &metrics, req, candidate, cancel).await;
        });
    }
}

fn into_candidate(req: &JudgeRequest) -> JudgeCandidate {
    JudgeCandidate {
        trace_id: req.trace_id,
        tenant_id: req.tenant_id,
        model_name: req.model_name.clone(),
        analysis_text: req.analysis_text.clone(),
        prior_findings: req.prior_findings.clone(),
        mode: req.mode,
    }
}

fn respond_skipped(req: JudgeRequest, reason: &str) {
    if let Some(tx) = req.response_tx {
        let _ = tx.send(JudgeResponse::Skipped {
            reason: reason.to_string(),
        });
    }
}

fn respond_error(req: JudgeRequest, message: &str) {
    if let Some(tx) = req.response_tx {
        let _ = tx.send(JudgeResponse::Error {
            message: message.to_string(),
        });
    }
}

async fn run_one(
    backend: &Arc<dyn JudgeBackend>,
    store: &Arc<dyn JudgeVerdictStore>,
    persist: bool,
    metrics: &Metrics,
    req: JudgeRequest,
    candidate: JudgeCandidate,
    cancel: CancellationToken,
) {
    let backend_name = backend.name();
    let model_label = backend.model();
    let mode_label = candidate.mode.as_str();
    let response_tx = req.response_tx;
    let started = Instant::now();

    // Race the backend call against shutdown; if the token fires first
    // the request is abandoned cleanly and surfaces as a `shutdown`
    // drop metric. The caller on the inline path receives an Error so
    // it can fail open.
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            metrics.record_judge_request(backend_name, model_label, mode_label, "shutdown");
            metrics.record_judge_dropped("shutdown");
            if let Some(tx) = response_tx {
                let _ = tx.send(JudgeResponse::Error {
                    message: "judge worker shutting down".to_string(),
                });
            }
            return;
        }
        r = backend.judge(&candidate) => r,
    };
    let elapsed = started.elapsed();

    match result {
        Ok(verdict) => {
            metrics.record_judge_request(backend_name, model_label, mode_label, "success");
            metrics.record_judge_latency(backend_name, model_label, mode_label, elapsed);
            metrics.record_judge_tokens(
                backend_name,
                model_label,
                verdict.prompt_tokens,
                verdict.completion_tokens,
            );
            metrics.record_judge_verdict(&verdict);
            if persist {
                if let Err(e) = store.insert_verdict(&verdict).await {
                    warn!(error = %e, trace_id = %verdict.trace_id, "Failed to persist judge verdict (fail-open)");
                    metrics.record_judge_dropped("persist_failure");
                }
            }
            if let Some(tx) = response_tx {
                let _ = tx.send(JudgeResponse::Verdict(verdict));
            }
        }
        Err(e) => {
            let status = judge_error_status(&e);
            metrics.record_judge_request(backend_name, model_label, mode_label, status);
            warn!(error = %e, backend = backend_name, model = model_label, mode = mode_label, "Judge backend failure (fail-open)");
            if let Some(tx) = response_tx {
                let _ = tx.send(JudgeResponse::Error {
                    message: e.to_string(),
                });
            }
        }
    }
}

fn judge_error_status(err: &JudgeError) -> &'static str {
    match err {
        JudgeError::Timeout { .. } => "timeout",
        JudgeError::BackendError { .. } => "backend_error",
        JudgeError::ParseError(_) => "parse_error",
        JudgeError::Misconfigured(_) => "misconfigured",
        JudgeError::Transport(_) => "transport_error",
    }
}

// ---------------------------------------------------------------------------
// Plaintext vLLM guardrail (issue #77)
// ---------------------------------------------------------------------------

/// Classification of a judge `base_url` for the plaintext guardrail.
#[derive(Debug, PartialEq, Eq)]
pub enum TransportSafety {
    /// TLS or loopback — no data exposure concern.
    Safe,
    /// `http://` to a non-loopback host — requires opt-in.
    PlaintextNonLoopback,
}

/// Classify a judge `base_url` for transport-security purposes.
///
/// Returns `PlaintextNonLoopback` iff the scheme is `http://` AND the
/// host is not a loopback literal. Loopback hosts (`127.0.0.1`, `::1`,
/// `localhost`) are always `Safe` because the data cannot leave the
/// host. TLS URLs are `Safe` regardless of host.
///
/// Intentionally uses string inspection rather than a URL-parser
/// dependency; the check only distinguishes three cases and does not
/// need RFC-3986-complete URL handling.
#[must_use]
pub fn classify_base_url(base_url: &str) -> TransportSafety {
    let lower = base_url.trim().to_ascii_lowercase();
    if lower.starts_with("https://") {
        return TransportSafety::Safe;
    }
    if !lower.starts_with("http://") {
        // Unrecognised scheme; treat as non-plaintext-relevant — the
        // reqwest client will reject it at send time with a clearer
        // error than we could produce here.
        return TransportSafety::Safe;
    }
    // Extract the host token between "http://" and the port/path.
    // IPv6 literals are bracketed: `[addr]:port`. Parse brackets first
    // so the port colon after `]` does not get mistaken for an IPv6
    // segment separator.
    let after_scheme = &lower["http://".len()..];
    let host = if let Some(rest) = after_scheme.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => &rest[..end],
            None => rest, // malformed; fall through to loopback check
        }
    } else {
        let host_end = after_scheme.find([':', '/']).unwrap_or(after_scheme.len());
        &after_scheme[..host_end]
    };

    let is_loopback =
        host == "localhost" || host == "127.0.0.1" || host == "::1" || host.starts_with("127.");

    if is_loopback {
        TransportSafety::Safe
    } else {
        TransportSafety::PlaintextNonLoopback
    }
}

/// Validate the vLLM backend's plaintext posture before constructing the
/// backend. Fails startup when the base URL is plaintext on a
/// non-loopback host and the operator has not explicitly opted in via
/// `judge.vllm.allow_plaintext=true`. Emits a `warn!` log on opt-in to
/// keep the risk visible in operational logs.
fn validate_vllm_transport(cfg: &VllmBackendConfig) -> anyhow::Result<()> {
    match classify_base_url(&cfg.base_url) {
        TransportSafety::Safe => Ok(()),
        TransportSafety::PlaintextNonLoopback if cfg.allow_plaintext => {
            tracing::warn!(
                base_url = %cfg.base_url,
                reason_code = "vllm_plaintext_non_loopback",
                "vLLM judge backend configured with plaintext http:// on a non-loopback host. \
                 Candidate prompts and prior findings will traverse the network unencrypted. \
                 Operator opted in via judge.vllm.allow_plaintext=true."
            );
            Ok(())
        }
        TransportSafety::PlaintextNonLoopback => Err(anyhow::anyhow!(
            "vLLM judge base_url is plaintext HTTP on a non-loopback host \
             ({url}). Candidate prompts and prior findings would traverse the \
             network unencrypted. Either switch to https://, point at a \
             loopback address, or opt in via judge.vllm.allow_plaintext=true.",
            url = cfg.base_url
        )),
    }
}

// ---------------------------------------------------------------------------
// Backend factory
// ---------------------------------------------------------------------------

/// Construct the concrete backend from the operator config. Returns
/// `Ok(None)` when `judge.enabled == false` at startup, avoiding
/// unnecessary HTTP client setup.
///
/// The `Option` path allows the caller to skip spawning the worker
/// entirely when the judge is off; runtime-enabling later via the
/// admin API would require a proxy restart. Hot-flip support is a
/// follow-up phase.
pub fn build_judge_backend(
    config: &JudgeConfig,
    http_client: Client,
) -> anyhow::Result<Option<Arc<dyn JudgeBackend>>> {
    if !config.enabled {
        return Ok(None);
    }
    let timeout = Duration::from_millis(config.worker.timeout_ms);
    // `total_deadline_ms == 0` disables the ceiling; translate to None
    // so `retry::with_retry` skips the deadline check entirely.
    let total_deadline = if config.worker.total_deadline_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(config.worker.total_deadline_ms))
    };
    let backend: Arc<dyn JudgeBackend> = match config.backend {
        JudgeBackendKind::Vllm => {
            validate_vllm_transport(&config.vllm)?;
            Arc::new(build_vllm(
                &config.vllm,
                &config.retry,
                timeout,
                total_deadline,
                http_client,
                &config.system_prompt,
            ))
        }
        JudgeBackendKind::Openai => Arc::new(build_openai(
            &config.openai,
            &config.retry,
            timeout,
            total_deadline,
            http_client,
            &config.system_prompt,
        )?),
        JudgeBackendKind::Anthropic => Arc::new(build_anthropic(
            &config.anthropic,
            &config.retry,
            timeout,
            total_deadline,
            http_client,
            &config.system_prompt,
        )?),
    };
    Ok(Some(backend))
}

fn build_vllm(
    cfg: &VllmBackendConfig,
    retry: &llmtrace_core::JudgeRetryConfig,
    timeout: Duration,
    total_deadline: Option<Duration>,
    http_client: Client,
    system_prompt: &Option<String>,
) -> VllmJudgeBackend {
    VllmJudgeBackend::new(
        http_client,
        llmtrace_security::judge::VllmJudgeOptions {
            base_url: cfg.base_url.clone(),
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            temperature: cfg.temperature,
            timeout,
            retry: retry.clone(),
            total_deadline,
            system_prompt_override: system_prompt.clone(),
        },
    )
}

fn build_openai(
    cfg: &OpenAiBackendConfig,
    retry: &llmtrace_core::JudgeRetryConfig,
    timeout: Duration,
    total_deadline: Option<Duration>,
    http_client: Client,
    system_prompt: &Option<String>,
) -> anyhow::Result<OpenAIJudgeBackend> {
    let api_key = std::env::var(OPENAI_API_KEY_ENV).map_err(|_| {
        anyhow::anyhow!("judge backend=openai requires env var {OPENAI_API_KEY_ENV} to be set")
    })?;
    Ok(OpenAIJudgeBackend::new(
        http_client,
        OpenAiJudgeOptions {
            base_url: cfg.base_url.clone(),
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            temperature: cfg.temperature,
            timeout,
            max_retries: retry.max_retries,
            backoff_base_ms: retry.backoff_base_ms,
            total_deadline,
            system_prompt_override: system_prompt.clone(),
            api_key,
        },
    ))
}

fn build_anthropic(
    cfg: &AnthropicBackendConfig,
    retry: &llmtrace_core::JudgeRetryConfig,
    timeout: Duration,
    total_deadline: Option<Duration>,
    http_client: Client,
    system_prompt: &Option<String>,
) -> anyhow::Result<AnthropicJudgeBackend> {
    let api_key = std::env::var(ANTHROPIC_API_KEY_ENV).map_err(|_| {
        anyhow::anyhow!(
            "judge backend=anthropic requires env var {ANTHROPIC_API_KEY_ENV} to be set"
        )
    })?;
    Ok(AnthropicJudgeBackend::new(
        http_client,
        AnthropicJudgeOptions {
            base_url: "https://api.anthropic.com".to_string(),
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            temperature: cfg.temperature,
            timeout,
            max_retries: retry.max_retries,
            backoff_base_ms: retry.backoff_base_ms,
            total_deadline,
            system_prompt_override: system_prompt.clone(),
            api_key,
        },
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use chrono::Utc;
    use llmtrace_core::{JudgeMode, JudgeVerdict, SecurityFinding, SecuritySeverity, TenantId};
    use llmtrace_storage::InMemoryJudgeVerdictStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;
    use uuid::Uuid;

    // Issue #77: plaintext vLLM guardrail.

    #[test]
    fn classify_loopback_urls_as_safe() {
        assert_eq!(
            classify_base_url("http://localhost:8000"),
            TransportSafety::Safe
        );
        assert_eq!(
            classify_base_url("http://127.0.0.1:8000"),
            TransportSafety::Safe
        );
        assert_eq!(
            classify_base_url("http://[::1]:8000"),
            TransportSafety::Safe
        );
        assert_eq!(classify_base_url("http://127.0.0.1"), TransportSafety::Safe);
    }

    #[test]
    fn classify_non_loopback_http_as_plaintext() {
        assert_eq!(
            classify_base_url("http://vllm.internal:8000"),
            TransportSafety::PlaintextNonLoopback
        );
        assert_eq!(
            classify_base_url("http://10.0.0.5:8000"),
            TransportSafety::PlaintextNonLoopback
        );
        assert_eq!(
            classify_base_url("HTTP://Vllm.Internal"),
            TransportSafety::PlaintextNonLoopback
        );
    }

    #[test]
    fn classify_https_as_safe() {
        assert_eq!(
            classify_base_url("https://vllm.internal:8443"),
            TransportSafety::Safe
        );
        assert_eq!(
            classify_base_url("HTTPS://api.openai.com"),
            TransportSafety::Safe
        );
    }

    #[test]
    fn validate_vllm_transport_allows_loopback_http() {
        let cfg = VllmBackendConfig {
            base_url: "http://localhost:8000".to_string(),
            ..VllmBackendConfig::default()
        };
        validate_vllm_transport(&cfg).unwrap();
    }

    #[test]
    fn validate_vllm_transport_rejects_non_loopback_plaintext_without_opt_in() {
        let cfg = VllmBackendConfig {
            base_url: "http://vllm.internal:8000".to_string(),
            allow_plaintext: false,
            ..VllmBackendConfig::default()
        };
        let err = validate_vllm_transport(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("allow_plaintext"));
        assert!(msg.contains("vllm.internal"));
    }

    #[test]
    fn validate_vllm_transport_allows_non_loopback_plaintext_with_opt_in() {
        let cfg = VllmBackendConfig {
            base_url: "http://vllm.internal:8000".to_string(),
            allow_plaintext: true,
            ..VllmBackendConfig::default()
        };
        // Should succeed (warning emitted server-side; not asserted here).
        validate_vllm_transport(&cfg).unwrap();
    }

    #[test]
    fn validate_vllm_transport_allows_https_always() {
        let cfg = VllmBackendConfig {
            base_url: "https://vllm.internal:8443".to_string(),
            allow_plaintext: false,
            ..VllmBackendConfig::default()
        };
        validate_vllm_transport(&cfg).unwrap();
    }

    /// Minimal snapshot source backed by an ArcSwap so tests can drive
    /// the worker without constructing a full `ConfigHandle`.
    struct SwapConfigSource {
        inner: ArcSwap<ProxyConfig>,
    }

    impl SwapConfigSource {
        fn new(cfg: ProxyConfig) -> Self {
            Self {
                inner: ArcSwap::from_pointee(cfg),
            }
        }
    }

    impl ConfigSnapshotSource for SwapConfigSource {
        fn snapshot(&self) -> Arc<ProxyConfig> {
            self.inner.load_full()
        }
    }

    struct StubBackend {
        verdict_factory: Arc<dyn Fn() -> Result<JudgeVerdict, JudgeError> + Send + Sync>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl JudgeBackend for StubBackend {
        async fn judge(&self, _candidate: &JudgeCandidate) -> Result<JudgeVerdict, JudgeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.verdict_factory)()
        }

        fn name(&self) -> &'static str {
            "stub"
        }

        fn model(&self) -> &str {
            "stub-model"
        }

        async fn health_check(&self) -> Result<(), JudgeError> {
            Ok(())
        }
    }

    fn judge_config_enabled(threshold: u8) -> llmtrace_core::ProxyConfig {
        let mut cfg = llmtrace_core::ProxyConfig::default();
        cfg.judge.enabled = true;
        cfg.judge.min_score_threshold = threshold;
        cfg.judge.persist_verdicts = true;
        cfg
    }

    fn verdict(trace_id: Uuid, tenant_id: TenantId) -> JudgeVerdict {
        JudgeVerdict {
            id: Uuid::new_v4(),
            trace_id,
            tenant_id,
            is_threat: true,
            category: "prompt_injection".to_string(),
            confidence: 0.9,
            security_score: 85,
            recommended_action: "block".to_string(),
            reasoning: "stub".to_string(),
            mode: JudgeMode::Inline,
            model_used: "stub-model".to_string(),
            latency_ms: 10,
            prompt_tokens: Some(10),
            completion_tokens: Some(5),
            created_at: Utc::now(),
        }
    }

    fn judge_request(
        mode: JudgeMode,
        tx: Option<oneshot::Sender<JudgeResponse>>,
        high_prior: bool,
    ) -> JudgeRequest {
        let findings = if high_prior {
            vec![SecurityFinding::new(
                SecuritySeverity::High,
                "prompt_injection".to_string(),
                "prior regex hit".to_string(),
                0.8,
            )]
        } else {
            vec![]
        };
        JudgeRequest {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            model_name: "gpt-4".to_string(),
            analysis_text: "ignore previous".to_string(),
            prior_findings: findings,
            mode,
            response_tx: tx,
        }
    }

    fn setup(
        cfg: ProxyConfig,
        backend: Arc<dyn JudgeBackend>,
        store: Arc<dyn JudgeVerdictStore>,
    ) -> (mpsc::Sender<JudgeRequest>, JudgeWorker, Metrics) {
        let (tx, worker, metrics, _shutdown) = setup_with_shutdown(cfg, backend, store);
        (tx, worker, metrics)
    }

    fn setup_with_shutdown(
        cfg: ProxyConfig,
        backend: Arc<dyn JudgeBackend>,
        store: Arc<dyn JudgeVerdictStore>,
    ) -> (
        mpsc::Sender<JudgeRequest>,
        JudgeWorker,
        Metrics,
        ShutdownCoordinator,
    ) {
        let (tx, rx) = mpsc::channel::<JudgeRequest>(4);
        let metrics = Metrics::new();
        let config: Arc<dyn ConfigSnapshotSource> = Arc::new(SwapConfigSource::new(cfg));
        let shutdown = ShutdownCoordinator::new(30);
        let worker = JudgeWorker::new(
            rx,
            backend,
            store,
            config,
            metrics.clone(),
            2,
            shutdown.clone(),
        );
        (tx, worker, metrics, shutdown)
    }

    #[tokio::test]
    async fn worker_returns_verdict_on_inline_path() {
        let trace_id = Uuid::new_v4();
        let tenant_id = TenantId(Uuid::new_v4());
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(StubBackend {
            verdict_factory: Arc::new(move || Ok(verdict(trace_id, tenant_id))),
            calls: Arc::clone(&calls),
        }) as Arc<dyn JudgeBackend>;
        let store = Arc::new(InMemoryJudgeVerdictStore::new()) as Arc<dyn JudgeVerdictStore>;
        let (tx, worker, metrics) = setup(judge_config_enabled(30), backend, store);

        let (resp_tx, resp_rx) = oneshot::channel();
        let mut req = judge_request(JudgeMode::Inline, Some(resp_tx), true);
        req.trace_id = trace_id;
        req.tenant_id = tenant_id;
        let h = tokio::spawn(worker.run());
        tx.send(req).await.unwrap();
        drop(tx);

        let response = resp_rx.await.expect("worker should respond");
        match response {
            JudgeResponse::Verdict(v) => {
                assert_eq!(v.trace_id, trace_id);
                assert_eq!(v.category, "prompt_injection");
            }
            other => panic!("expected Verdict, got {other:?}"),
        }
        h.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let text = metrics.gather_text().unwrap();
        assert!(text.contains("llmtrace_judge_requests_total"));
        assert!(text.contains("backend=\"stub\""));
        assert!(text.contains("status=\"success\""));
        assert!(text.contains("llmtrace_judge_verdicts_total"));
    }

    #[tokio::test]
    async fn worker_skips_when_disabled() {
        let calls = Arc::new(AtomicUsize::new(0));
        let trace_id = Uuid::new_v4();
        let tenant_id = TenantId(Uuid::new_v4());
        let backend = Arc::new(StubBackend {
            verdict_factory: Arc::new(move || Ok(verdict(trace_id, tenant_id))),
            calls: Arc::clone(&calls),
        }) as Arc<dyn JudgeBackend>;
        let store = Arc::new(InMemoryJudgeVerdictStore::new()) as Arc<dyn JudgeVerdictStore>;
        let cfg = ProxyConfig::default(); // judge.enabled defaults to false
        let (tx, worker, metrics) = setup(cfg, backend, store);

        let (resp_tx, resp_rx) = oneshot::channel();
        let req = judge_request(JudgeMode::Inline, Some(resp_tx), true);
        let h = tokio::spawn(worker.run());
        tx.send(req).await.unwrap();
        drop(tx);
        let resp = resp_rx.await.unwrap();
        match resp {
            JudgeResponse::Skipped { reason } => assert_eq!(reason, "judge_disabled"),
            other => panic!("expected Skipped, got {other:?}"),
        }
        h.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(metrics
            .gather_text()
            .unwrap()
            .contains("reason=\"disabled\""));
    }

    #[tokio::test]
    async fn worker_skips_below_min_score_threshold() {
        let calls = Arc::new(AtomicUsize::new(0));
        let trace_id = Uuid::new_v4();
        let tenant_id = TenantId(Uuid::new_v4());
        let backend = Arc::new(StubBackend {
            verdict_factory: Arc::new(move || Ok(verdict(trace_id, tenant_id))),
            calls: Arc::clone(&calls),
        }) as Arc<dyn JudgeBackend>;
        let store = Arc::new(InMemoryJudgeVerdictStore::new()) as Arc<dyn JudgeVerdictStore>;
        // Threshold 50; prior findings empty -> peak = 0 < 50.
        let (tx, worker, _metrics) = setup(judge_config_enabled(50), backend, store);

        let (resp_tx, resp_rx) = oneshot::channel();
        let req = judge_request(JudgeMode::Inline, Some(resp_tx), false);
        let h = tokio::spawn(worker.run());
        tx.send(req).await.unwrap();
        drop(tx);
        let resp = resp_rx.await.unwrap();
        match resp {
            JudgeResponse::Skipped { reason } => assert_eq!(reason, "below_threshold"),
            other => panic!("expected Skipped, got {other:?}"),
        }
        h.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn worker_returns_error_on_backend_failure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(StubBackend {
            verdict_factory: Arc::new(|| Err(JudgeError::ParseError("bad json".to_string()))),
            calls: Arc::clone(&calls),
        }) as Arc<dyn JudgeBackend>;
        let store = Arc::new(InMemoryJudgeVerdictStore::new()) as Arc<dyn JudgeVerdictStore>;
        let (tx, worker, metrics) = setup(judge_config_enabled(30), backend, store);

        let (resp_tx, resp_rx) = oneshot::channel();
        let req = judge_request(JudgeMode::Inline, Some(resp_tx), true);
        let h = tokio::spawn(worker.run());
        tx.send(req).await.unwrap();
        drop(tx);
        let resp = resp_rx.await.unwrap();
        match resp {
            JudgeResponse::Error { message } => assert!(message.contains("bad json")),
            other => panic!("expected Error, got {other:?}"),
        }
        h.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let text = metrics.gather_text().unwrap();
        assert!(text.contains("status=\"parse_error\""));
    }

    #[tokio::test]
    async fn worker_persists_verdict_to_store() {
        let trace_id = Uuid::new_v4();
        let tenant_id = TenantId(Uuid::new_v4());
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(StubBackend {
            verdict_factory: Arc::new(move || Ok(verdict(trace_id, tenant_id))),
            calls: Arc::clone(&calls),
        }) as Arc<dyn JudgeBackend>;
        let store_inner = Arc::new(InMemoryJudgeVerdictStore::new());
        let store = Arc::clone(&store_inner) as Arc<dyn JudgeVerdictStore>;
        let (tx, worker, _metrics) = setup(judge_config_enabled(30), backend, store);

        let mut req = judge_request(JudgeMode::Async, None, true);
        req.trace_id = trace_id;
        req.tenant_id = tenant_id;
        let h = tokio::spawn(worker.run());
        tx.send(req).await.unwrap();
        drop(tx);
        h.await.unwrap();

        // Detached backend task may still be running — poll the store.
        for _ in 0..40 {
            let results = store_inner
                .query_verdicts(&llmtrace_core::JudgeVerdictQuery {
                    tenant_id: Some(tenant_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            if !results.is_empty() {
                assert_eq!(results[0].trace_id, trace_id);
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("verdict was never persisted");
    }

    /// Issue #68: an in-flight backend call must be cancelled cleanly
    /// when the coordinator fires; the inline caller must receive an
    /// Error response rather than block past the grace window.
    #[tokio::test]
    async fn worker_cancels_in_flight_backend_on_shutdown() {
        // A stub backend that sleeps 30s — long enough that the test
        // will hang if shutdown isn't honored.
        struct SleepyBackend;
        #[async_trait]
        impl JudgeBackend for SleepyBackend {
            async fn judge(
                &self,
                _c: &JudgeCandidate,
            ) -> Result<JudgeVerdict, llmtrace_security::judge::JudgeError> {
                tokio::time::sleep(Duration::from_secs(30)).await;
                unreachable!("shutdown should cancel this long before 30s")
            }
            fn name(&self) -> &'static str {
                "sleepy"
            }
            fn model(&self) -> &str {
                "sleepy-model"
            }
            async fn health_check(&self) -> Result<(), llmtrace_security::judge::JudgeError> {
                Ok(())
            }
        }

        let backend: Arc<dyn JudgeBackend> = Arc::new(SleepyBackend);
        let store = Arc::new(InMemoryJudgeVerdictStore::new()) as Arc<dyn JudgeVerdictStore>;
        let (tx, worker, metrics, shutdown) =
            setup_with_shutdown(judge_config_enabled(30), backend, store);

        let (resp_tx, resp_rx) = oneshot::channel();
        let req = judge_request(JudgeMode::Inline, Some(resp_tx), true);
        let worker_handle = tokio::spawn(worker.run());
        tx.send(req).await.unwrap();
        // Let the worker dispatch the request before triggering shutdown.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.trigger();

        // Caller must receive the Error response within a short budget
        // (the cancel branch responds immediately; no wait for the 30s backend).
        let start = Instant::now();
        let resp = tokio::time::timeout(Duration::from_secs(2), resp_rx)
            .await
            .expect("worker must respond within 2s on shutdown")
            .expect("oneshot channel must not be dropped");
        assert!(start.elapsed() < Duration::from_secs(2));
        match resp {
            JudgeResponse::Error { message } => assert!(message.contains("shutting down")),
            other => panic!("expected Error(shutdown), got {other:?}"),
        }

        // wait_for_tasks must return true within the configured window
        // because the per-request task's TaskGuard has dropped.
        assert!(shutdown.wait_for_tasks().await);
        drop(tx);
        worker_handle.await.unwrap();

        let text = metrics.gather_text().unwrap();
        assert!(text.contains("reason=\"shutdown\""));
    }
}
