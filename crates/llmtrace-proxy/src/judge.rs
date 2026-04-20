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
            metrics.record_judge_request(backend_name, mode_label, "shutdown");
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
            metrics.record_judge_request(backend_name, mode_label, "success");
            metrics.record_judge_latency(backend_name, mode_label, elapsed);
            metrics.record_judge_tokens(
                backend_name,
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
            metrics.record_judge_request(backend_name, mode_label, status);
            warn!(error = %e, backend = backend_name, mode = mode_label, "Judge backend failure (fail-open)");
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
    let backend: Arc<dyn JudgeBackend> = match config.backend {
        JudgeBackendKind::Vllm => Arc::new(build_vllm(
            &config.vllm,
            &config.retry,
            timeout,
            http_client,
            &config.system_prompt,
        )),
        JudgeBackendKind::Openai => Arc::new(build_openai(
            &config.openai,
            &config.retry,
            timeout,
            http_client,
            &config.system_prompt,
        )?),
        JudgeBackendKind::Anthropic => Arc::new(build_anthropic(
            &config.anthropic,
            &config.retry,
            timeout,
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
            system_prompt_override: system_prompt.clone(),
        },
    )
}

fn build_openai(
    cfg: &OpenAiBackendConfig,
    retry: &llmtrace_core::JudgeRetryConfig,
    timeout: Duration,
    http_client: Client,
    system_prompt: &Option<String>,
) -> anyhow::Result<OpenAIJudgeBackend> {
    let api_key = std::env::var(OPENAI_API_KEY_ENV).map_err(|_| {
        anyhow::anyhow!("judge backend=openai requires env var {OPENAI_API_KEY_ENV} to be set")
    })?;
    Ok(OpenAIJudgeBackend::new(
        http_client,
        OpenAiJudgeOptions {
            base_url: "https://api.openai.com".to_string(),
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            temperature: cfg.temperature,
            timeout,
            max_retries: retry.max_retries,
            backoff_base_ms: retry.backoff_base_ms,
            system_prompt_override: system_prompt.clone(),
            api_key,
        },
    ))
}

fn build_anthropic(
    cfg: &AnthropicBackendConfig,
    retry: &llmtrace_core::JudgeRetryConfig,
    timeout: Duration,
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
