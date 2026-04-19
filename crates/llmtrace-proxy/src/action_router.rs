use async_trait::async_trait;
use futures_util::FutureExt;
use llmtrace_core::{
    ActionRouterConfig, ActionRuleConfig, CacheLayer, JudgeMode, JudgeVerdict, SecurityFinding,
    SecuritySeverity, TenantId,
};
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::enforcement::EnforcementDecision;

/// Finding-type key emitted when a judge verdict is promoted into the
/// ensemble. Kept in sync with `llmtrace_security::judge::JUDGE_FINDING_TYPE`
/// so operators can write enforcement category overrides for one key.
pub const JUDGE_FINDING_TYPE: &str = "llm_judge_verdict";

/// Context provided to all Actions.
///
/// `analysis_text` is the candidate prompt the ensemble evaluated; it
/// is passed into actions so components like the LLM Judge can re-use
/// the same string the detectors analysed without re-parsing the
/// request body.
pub struct ActionContext<'a> {
    pub trace_id: Uuid,
    pub tenant_id: TenantId,
    pub findings: &'a [SecurityFinding],
    pub analysis_text: &'a str,
    pub source_ip: Option<IpAddr>,
    pub model_name: String,
    pub provider: llmtrace_core::LLMProvider,
    pub execution_mode: ExecutionMode,
    pub cache: Option<Arc<dyn CacheLayer>>,
    pub metrics: Option<crate::metrics::Metrics>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionMode {
    Inline,
    Async,
}

#[derive(Debug)]
pub enum ActionOutcome {
    Completed {
        message: String,
    },
    Skipped {
        reason: String,
    },
    Enqueued {
        queue_id: String,
    },
    BlockRequested {
        reason: String,
        findings: Vec<SecurityFinding>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    #[error("Action failed: {0}")]
    Failed(String),
    #[error("Action panicked")]
    Panicked,
}

#[async_trait]
pub trait Action: Send + Sync {
    fn action_type(&self) -> &str;
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<ActionOutcome, ActionError>;
    fn supports_inline(&self) -> bool;
    fn supports_async(&self) -> bool;
}

// ---------------------------------------------------------------------------
// ActionRouter
// ---------------------------------------------------------------------------

pub struct ActionRouter {
    pub enabled: bool,
    actions: HashMap<String, Arc<dyn Action>>,
    rules: Vec<ActionRuleConfig>,
    default_actions: Vec<String>,
    cache: Option<Arc<dyn CacheLayer>>,
    /// Judge receiver held only between construction and `take_judge_receiver`.
    /// Consumed by [`JudgeWorker`](crate::judge::JudgeWorker) during proxy startup.
    judge_rx: Option<mpsc::Receiver<JudgeRequest>>,
}

impl ActionRouter {
    pub fn new(
        config: &ActionRouterConfig,
        cache: Option<Arc<dyn CacheLayer>>,
        http_client: Client,
    ) -> Self {
        let mut router = Self {
            enabled: config.enabled,
            actions: HashMap::new(),
            rules: config.rules.clone(),
            default_actions: config.default_actions.clone(),
            cache,
            judge_rx: None,
        };

        if !config.enabled {
            return router;
        }

        // Register built-in actions
        router.register_action(Arc::new(BlockAction));
        router.register_action(Arc::new(LogAction));

        let block_ip = Arc::new(BlockIpAction {
            ttl_seconds: config.ip_block.ttl_seconds,
            max_offenses: config.ip_block.max_offenses,
        });
        router.register_action(block_ip);

        let webhook = Arc::new(WebhookAction {
            url: config.webhook.url.clone(),
            timeout_ms: config.webhook.timeout_ms,
            http_client,
        });
        router.register_action(webhook);

        // The judge channel is created here but the receiver is handed to
        // `JudgeWorker` at startup via [`take_judge_receiver`]. If no worker
        // claims the receiver the channel is still functional and
        // `JudgeRouteAction::execute` will emit `Error` / `Skipped` outcomes
        // once the channel fills or closes.
        let (judge_tx, judge_rx) = mpsc::channel::<JudgeRequest>(DEFAULT_JUDGE_CHANNEL_BUFFER);
        router.judge_rx = Some(judge_rx);
        let judge_route = Arc::new(JudgeRouteAction {
            tx: judge_tx,
            inline_await: config.judge_route.inline_await,
            inline_timeout_ms: config.judge_route.inline_timeout_ms,
        });
        router.register_action(judge_route);

        router
    }

    /// Take ownership of the judge request receiver. Returns `None` if
    /// the router is disabled or the receiver has already been claimed.
    /// Called once during proxy startup to wire the channel into
    /// [`JudgeWorker`](crate::judge::JudgeWorker).
    pub fn take_judge_receiver(&mut self) -> Option<mpsc::Receiver<JudgeRequest>> {
        self.judge_rx.take()
    }

    pub fn register_action(&mut self, action: Arc<dyn Action>) {
        self.actions
            .insert(action.action_type().to_string(), action);
    }

    // Identify which actions apply based on findings.
    fn resolve_actions(&self, findings: &[SecurityFinding]) -> ResolvedActions {
        let mut selected = HashSet::new();
        let mut rule_matches = Vec::new();

        if !self.enabled {
            return ResolvedActions::default();
        }

        // Always add default actions if findings exist
        if !findings.is_empty() {
            for a in &self.default_actions {
                selected.insert(a.clone());
            }
        }

        for finding in findings {
            for rule in &self.rules {
                // Check finding type if specified
                if let Some(ft) = &rule.finding_type {
                    if ft != &finding.finding_type {
                        continue;
                    }
                }

                if finding.severity < rule.min_severity {
                    continue;
                }
                if finding.confidence_score < rule.min_confidence {
                    continue;
                }

                for a in &rule.actions {
                    selected.insert(a.clone());
                    rule_matches.push((finding.finding_type.clone(), a.clone()));
                }
            }
        }

        ResolvedActions {
            actions: selected
                .into_iter()
                .filter_map(|name| self.actions.get(&name).cloned())
                .collect(),
            rule_matches,
        }
    }

    pub async fn execute_inline(
        &self,
        decision: EnforcementDecision,
        ctx: &ActionContext<'_>,
    ) -> EnforcementDecision {
        if !self.enabled {
            return decision;
        }

        let resolved = self.resolve_actions(ctx.findings);
        let mut final_decision = decision;
        self.record_rule_matches(ctx, &resolved.rule_matches);

        for action in resolved.actions {
            if !action.supports_inline() {
                continue;
            }

            match self.execute_action(&action, ctx, "inline").await {
                Ok(ActionOutcome::BlockRequested { reason, findings }) => {
                    final_decision = EnforcementDecision::Block { reason, findings };
                    if let Some(m) = &ctx.metrics {
                        m.record_action_execution(
                            action.action_type(),
                            "block_requested",
                            "inline",
                        );
                    }
                }
                Ok(outcome) => {
                    debug!(
                        action = action.action_type(),
                        ?outcome,
                        "Action executed successfully"
                    );
                    if let Some(m) = &ctx.metrics {
                        m.record_action_execution(action.action_type(), "success", "inline");
                    }
                }
                Err(e) => {
                    warn!(
                        action = action.action_type(),
                        error = %e,
                        "Inline action failed (fail-open semantics)"
                    );
                    if let Some(m) = &ctx.metrics {
                        let status = if matches!(e, ActionError::Panicked) {
                            "panic"
                        } else {
                            "error"
                        };
                        m.record_action_execution(action.action_type(), status, "inline");
                    }
                }
            }
        }

        final_decision
    }

    pub async fn execute_async(&self, ctx: &ActionContext<'_>) {
        if !self.enabled {
            return;
        }

        let resolved = self.resolve_actions(ctx.findings);
        self.record_rule_matches(ctx, &resolved.rule_matches);

        for action in resolved.actions {
            if !action.supports_async() {
                continue;
            }

            match self.execute_action(&action, ctx, "async").await {
                Ok(outcome) => {
                    debug!(
                        action = action.action_type(),
                        ?outcome,
                        "Async action executed successfully"
                    );
                    if let Some(m) = &ctx.metrics {
                        m.record_action_execution(action.action_type(), "success", "async");
                    }
                }
                Err(e) => {
                    warn!(action = action.action_type(), error = %e, "Async action failed");
                    if let Some(m) = &ctx.metrics {
                        let status = if matches!(e, ActionError::Panicked) {
                            "panic"
                        } else {
                            "error"
                        };
                        m.record_action_execution(action.action_type(), status, "async");
                    }
                }
            }
        }
    }

    pub async fn is_ip_blocked(
        &self,
        source_ip: Option<IpAddr>,
        _dummy_cache: &Option<Arc<dyn CacheLayer>>, // Legacy param to not break callers yet
    ) -> bool {
        if !self.enabled {
            return false;
        }
        let (ip, cache) = match (source_ip, &self.cache) {
            (Some(i), Some(c)) => (i, c.as_ref()),
            _ => return false,
        };

        let key = format!("blocked_ip:{}", ip);
        matches!(cache.get(&key).await, Ok(Some(_)))
    }

    fn record_rule_matches(&self, ctx: &ActionContext<'_>, rule_matches: &[(String, String)]) {
        if let Some(metrics) = &ctx.metrics {
            for (finding_type, action_type) in rule_matches {
                metrics.record_action_rule_match(finding_type, action_type);
            }
        }
    }

    async fn execute_action(
        &self,
        action: &Arc<dyn Action>,
        ctx: &ActionContext<'_>,
        mode: &str,
    ) -> Result<ActionOutcome, ActionError> {
        let started_at = Instant::now();
        let result = AssertUnwindSafe(action.execute(ctx)).catch_unwind().await;
        if let Some(metrics) = &ctx.metrics {
            metrics.record_action_latency(action.action_type(), started_at.elapsed());
        }
        match result {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    action = action.action_type(),
                    mode, "Action panicked; continuing with fail-open semantics"
                );
                Err(ActionError::Panicked)
            }
        }
    }
}

#[derive(Default)]
struct ResolvedActions {
    actions: Vec<Arc<dyn Action>>,
    rule_matches: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Built-in Actions
// ---------------------------------------------------------------------------

pub struct BlockAction;

#[async_trait]
impl Action for BlockAction {
    fn action_type(&self) -> &str {
        "block"
    }

    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<ActionOutcome, ActionError> {
        let reason = "Security enforcement requested block".to_string();
        Ok(ActionOutcome::BlockRequested {
            reason,
            findings: ctx.findings.to_vec(),
        })
    }

    fn supports_inline(&self) -> bool {
        true
    }
    fn supports_async(&self) -> bool {
        false
    }
}

pub struct BlockIpAction {
    pub ttl_seconds: u64,
    pub max_offenses: u32,
}

#[async_trait]
impl Action for BlockIpAction {
    fn action_type(&self) -> &str {
        "block_ip"
    }

    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<ActionOutcome, ActionError> {
        let ip = match ctx.source_ip {
            Some(i) => i,
            None => {
                return Ok(ActionOutcome::Skipped {
                    reason: "No source IP available".to_string(),
                })
            }
        };

        let cache = match &ctx.cache {
            Some(c) => c,
            None => return Err(ActionError::Failed("No CacheLayer provided".to_string())),
        };

        let off_key = format!("offenses_ip:{}", ip);
        let count_str = match cache
            .get(&off_key)
            .await
            .map_err(|e| ActionError::Failed(format!("Failed reading offense count: {e}")))?
        {
            Some(v) => String::from_utf8_lossy(&v).to_string(),
            None => "0".to_string(),
        };
        let count: u32 = count_str.parse().unwrap_or(0) + 1;

        cache
            .set(
                &off_key,
                count.to_string().as_bytes(),
                Duration::from_secs(self.ttl_seconds),
            )
            .await
            .map_err(|e| ActionError::Failed(format!("Failed storing offense count: {e}")))?;

        if count >= self.max_offenses {
            let block_key = format!("blocked_ip:{}", ip);
            let was_blocked = cache
                .get(&block_key)
                .await
                .map_err(|e| ActionError::Failed(format!("Failed checking block state: {e}")))?
                .is_some();
            cache
                .set(&block_key, b"1", Duration::from_secs(self.ttl_seconds))
                .await
                .map_err(|e| ActionError::Failed(format!("Failed storing IP block: {e}")))?;
            if !was_blocked {
                if let Some(metrics) = &ctx.metrics {
                    metrics.ip_blocks_active.inc();
                }
            }
            return Ok(ActionOutcome::Completed {
                message: format!("IP {} blocked after {} offenses", ip, count),
            });
        }

        Ok(ActionOutcome::Completed {
            message: format!("Recorded offense {} for IP {}", count, ip),
        })
    }

    fn supports_inline(&self) -> bool {
        true
    }
    fn supports_async(&self) -> bool {
        true
    }
}

pub struct WebhookAction {
    pub url: String,
    pub timeout_ms: u64,
    pub http_client: Client,
}

#[async_trait]
impl Action for WebhookAction {
    fn action_type(&self) -> &str {
        "webhook"
    }

    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<ActionOutcome, ActionError> {
        if self.url.is_empty() {
            return Ok(ActionOutcome::Skipped {
                reason: "Webhook URL not configured".to_string(),
            });
        }

        let payload = serde_json::json!({
            "trace_id": ctx.trace_id,
            "tenant_id": ctx.tenant_id,
            "findings": ctx.findings,
            "source_ip": ctx.source_ip,
            "model": ctx.model_name,
            "provider": ctx.provider,
        });

        let url_clone = self.url.clone();
        let client_clone = self.http_client.clone();
        let timeout = std::time::Duration::from_millis(self.timeout_ms);

        // Fire and forget
        tokio::spawn(async move {
            let _ = client_clone
                .post(&url_clone)
                .json(&payload)
                .timeout(timeout)
                .send()
                .await;
        });

        Ok(ActionOutcome::Completed {
            message: "Webhook fired async".to_string(),
        })
    }

    fn supports_inline(&self) -> bool {
        true
    }
    fn supports_async(&self) -> bool {
        true
    }
}

pub struct LogAction;

#[async_trait]
impl Action for LogAction {
    fn action_type(&self) -> &str {
        "log"
    }

    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<ActionOutcome, ActionError> {
        warn!(trace_id = %ctx.trace_id, findings_len = ctx.findings.len(), "LogAction: Findings reported.");
        Ok(ActionOutcome::Completed {
            message: "Logged findings".to_string(),
        })
    }

    fn supports_inline(&self) -> bool {
        true
    }
    fn supports_async(&self) -> bool {
        true
    }
}

/// Default size of the bounded mpsc buffer connecting [`JudgeRouteAction`]
/// to [`JudgeWorker`](crate::judge::JudgeWorker). Matches the design
/// doc's `judge.worker.channel_buffer` default; when the channel is
/// full, async enqueue drops the request and increments
/// `llmtrace_judge_dropped_total{reason="channel_full"}` (fail-open).
const DEFAULT_JUDGE_CHANNEL_BUFFER: usize = 1000;

/// Map the judge's `security_score` onto a [`SecuritySeverity`] using the
/// bands from `docs/architecture/LLM_JUDGE.md` section 6. Kept in sync
/// with `llmtrace_security::judge::severity_from_score`; duplicated here
/// so the promotion path stays feature-flag independent.
fn severity_from_judge_score(score: u8) -> SecuritySeverity {
    match score {
        0..=29 => SecuritySeverity::Low,
        30..=59 => SecuritySeverity::Medium,
        60..=79 => SecuritySeverity::High,
        _ => SecuritySeverity::Critical,
    }
}

/// Convert a judge verdict into a `SecurityFinding` carrying the
/// judge's voting metadata. Returns a finding stamped with
/// `finding_type = "llm_judge_verdict"` so operators can hook it into
/// enforcement category overrides identically to any other finding.
fn judge_verdict_to_finding(verdict: &JudgeVerdict) -> SecurityFinding {
    let severity = severity_from_judge_score(verdict.security_score);
    let description = if verdict.reasoning.is_empty() {
        format!("LLM Judge verdict: {}", verdict.category)
    } else {
        verdict.reasoning.clone()
    };
    SecurityFinding::new(
        severity,
        JUDGE_FINDING_TYPE.to_string(),
        description,
        verdict.confidence,
    )
    .with_metadata("voting_result".to_string(), "llm_judge".to_string())
    .with_metadata("category".to_string(), verdict.category.clone())
    .with_metadata("model_used".to_string(), verdict.model_used.clone())
    .with_metadata(
        "recommended_action".to_string(),
        verdict.recommended_action.clone(),
    )
    .with_metadata("mode".to_string(), verdict.mode.as_str().to_string())
    .with_metadata(
        "security_score".to_string(),
        verdict.security_score.to_string(),
    )
}

/// Convert an inline judge verdict into an [`ActionOutcome`].
///
/// Promotion rules (design doc section 4.3):
/// - Judge recommends "block" and `is_threat=true` -> [`ActionOutcome::BlockRequested`]
///   with the prior findings augmented by the judge finding, so enforcement
///   can cite both signals in the 403 body.
/// - Otherwise -> [`ActionOutcome::Completed`], preserving the prior
///   enforcement decision. The judge never *downgrades* an existing Block;
///   the only influence it has on the current request is promotion when
///   the verdict is unambiguous.
fn verdict_to_outcome(prior_findings: &[SecurityFinding], verdict: &JudgeVerdict) -> ActionOutcome {
    let judge_finding = judge_verdict_to_finding(verdict);
    if verdict.is_threat && verdict.recommended_action == "block" {
        let mut merged: Vec<SecurityFinding> = prior_findings.to_vec();
        merged.push(judge_finding);
        ActionOutcome::BlockRequested {
            reason: format!(
                "LLM Judge confirmed {} (score={}, conf={:.2})",
                verdict.category, verdict.security_score, verdict.confidence,
            ),
            findings: merged,
        }
    } else {
        ActionOutcome::Completed {
            message: format!(
                "Judge verdict: category={} action={} score={}",
                verdict.category, verdict.recommended_action, verdict.security_score,
            ),
        }
    }
}

/// Classify agreement between the judge verdict and prior ensemble findings
/// for the `llmtrace_judge_verdict_agreement` metric.
///
/// - `confirm`: ensemble flagged at least one threat AND judge also says `is_threat`
/// - `suppress`: ensemble flagged at least one threat AND judge says `is_threat=false`
/// - `elevate`: ensemble was clean AND judge says `is_threat=true`
/// - `clean`: ensemble was clean AND judge says `is_threat=false`
fn agreement_label(prior_findings: &[SecurityFinding], verdict: &JudgeVerdict) -> &'static str {
    let ensemble_hot = prior_findings.iter().any(|f| {
        matches!(
            f.severity,
            SecuritySeverity::High | SecuritySeverity::Critical | SecuritySeverity::Medium
        )
    });
    match (ensemble_hot, verdict.is_threat) {
        (true, true) => "confirm",
        (true, false) => "suppress",
        (false, true) => "elevate",
        (false, false) => "clean",
    }
}

/// Outcome returned by [`JudgeWorker`](crate::judge::JudgeWorker) over
/// the inline-path oneshot channel. The worker emits exactly one variant
/// per request.
#[derive(Debug)]
pub enum JudgeResponse {
    /// Judge produced a full verdict. Callers can convert it to a
    /// [`SecurityFinding`] and re-run enforcement.
    Verdict(JudgeVerdict),
    /// Judge elected not to call the backend (disabled, below
    /// `min_score_threshold`, etc.).
    Skipped { reason: String },
    /// Backend call failed in a fail-open way. No verdict is available
    /// and enforcement must proceed with the prior decision.
    Error { message: String },
}

/// Envelope placed on the action router -> judge-worker channel.
#[derive(Debug)]
pub struct JudgeRequest {
    pub trace_id: Uuid,
    pub tenant_id: TenantId,
    pub model_name: String,
    pub analysis_text: String,
    pub prior_findings: Vec<SecurityFinding>,
    pub mode: JudgeMode,
    pub response_tx: Option<oneshot::Sender<JudgeResponse>>,
}

pub struct JudgeRouteAction {
    pub tx: mpsc::Sender<JudgeRequest>,
    pub inline_await: bool,
    pub inline_timeout_ms: u64,
}

impl JudgeRouteAction {
    fn build_request(
        &self,
        ctx: &ActionContext<'_>,
        mode: JudgeMode,
        response_tx: Option<oneshot::Sender<JudgeResponse>>,
    ) -> JudgeRequest {
        JudgeRequest {
            trace_id: ctx.trace_id,
            tenant_id: ctx.tenant_id,
            model_name: ctx.model_name.clone(),
            analysis_text: ctx.analysis_text.to_string(),
            prior_findings: ctx.findings.to_vec(),
            mode,
            response_tx,
        }
    }
}

#[async_trait]
impl Action for JudgeRouteAction {
    fn action_type(&self) -> &str {
        "judge_route"
    }

    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<ActionOutcome, ActionError> {
        let inline = matches!(ctx.execution_mode, ExecutionMode::Inline);
        let should_await = self.inline_await && inline;
        // Mode reflects whether the verdict influences the current
        // request. `Inline` requires both the execution mode and the
        // operator-enabled `inline_await` knob; otherwise we're
        // fire-and-forget and the verdict only affects storage.
        let mode = if should_await {
            JudgeMode::Inline
        } else {
            JudgeMode::Async
        };

        if should_await {
            let (response_tx, response_rx) = oneshot::channel();
            let req = self.build_request(ctx, mode, Some(response_tx));
            self.tx.send(req).await.map_err(|_| {
                ActionError::Failed("Judge route channel closed before enqueue".to_string())
            })?;

            let response =
                tokio::time::timeout(Duration::from_millis(self.inline_timeout_ms), response_rx)
                    .await
                    .map_err(|_| {
                        ActionError::Failed("Timed out waiting for judge verdict".to_string())
                    })?
                    .map_err(|_| {
                        ActionError::Failed("Judge response channel closed".to_string())
                    })?;

            match response {
                JudgeResponse::Verdict(verdict) => {
                    if let Some(metrics) = &ctx.metrics {
                        metrics.record_judge_agreement(agreement_label(ctx.findings, &verdict));
                    }
                    Ok(verdict_to_outcome(ctx.findings, &verdict))
                }
                JudgeResponse::Skipped { reason } => Ok(ActionOutcome::Skipped { reason }),
                JudgeResponse::Error { message } => Err(ActionError::Failed(message)),
            }
        } else {
            let req = self.build_request(ctx, mode, None);
            if let Err(e) = self.tx.try_send(req) {
                if let Some(metrics) = &ctx.metrics {
                    let reason = match e {
                        mpsc::error::TrySendError::Full(_) => "channel_full",
                        mpsc::error::TrySendError::Closed(_) => "channel_closed",
                    };
                    metrics.record_judge_dropped(reason);
                }
                return Err(ActionError::Failed("Channel full or closed".to_string()));
            }
            Ok(ActionOutcome::Enqueued {
                queue_id: format!("judge_{}", ctx.trace_id),
            })
        }
    }

    fn supports_inline(&self) -> bool {
        true
    }
    fn supports_async(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::Router;
    use llmtrace_core::SecuritySeverity;
    use llmtrace_storage::InMemoryCacheLayer;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex as AsyncMutex;

    fn finding(t: &str, s: SecuritySeverity, c: f64) -> SecurityFinding {
        SecurityFinding::new(s, t.to_string(), "desc".into(), c)
    }

    fn test_ctx<'a>(
        findings: &'a [SecurityFinding],
        cache: Option<Arc<dyn CacheLayer>>,
        metrics: Option<crate::metrics::Metrics>,
    ) -> ActionContext<'a> {
        ActionContext {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            findings,
            analysis_text: "test prompt",
            source_ip: Some("127.0.0.1".parse().unwrap()),
            model_name: "gpt-4".to_string(),
            provider: llmtrace_core::LLMProvider::OpenAI,
            execution_mode: ExecutionMode::Inline,
            cache,
            metrics,
        }
    }

    enum TestActionBehavior {
        Success,
        Error,
        Panic,
    }

    struct RecordingAction {
        name: &'static str,
        behavior: TestActionBehavior,
        supports_inline: bool,
        supports_async: bool,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Action for RecordingAction {
        fn action_type(&self) -> &str {
            self.name
        }

        async fn execute(&self, _ctx: &ActionContext<'_>) -> Result<ActionOutcome, ActionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                TestActionBehavior::Success => Ok(ActionOutcome::Completed {
                    message: format!("{} ok", self.name),
                }),
                TestActionBehavior::Error => {
                    Err(ActionError::Failed(format!("{} failed", self.name)))
                }
                TestActionBehavior::Panic => panic!("{} panicked", self.name),
            }
        }

        fn supports_inline(&self) -> bool {
            self.supports_inline
        }

        fn supports_async(&self) -> bool {
            self.supports_async
        }
    }

    async fn simple_mock(path: &str) -> (String, Arc<AsyncMutex<Vec<serde_json::Value>>>) {
        let received: Arc<AsyncMutex<Vec<serde_json::Value>>> =
            Arc::new(AsyncMutex::new(Vec::new()));
        let store = Arc::clone(&received);
        let app = Router::new().route(
            path,
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let store = Arc::clone(&store);
                async move {
                    store.lock().await.push(body);
                    axum::http::StatusCode::OK
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (format!("http://{addr}{path}"), received)
    }

    #[tokio::test]
    async fn test_resolve_actions_unions_rule_matches() {
        let config = ActionRouterConfig {
            enabled: true,
            default_actions: vec!["log".into()],
            rules: vec![
                ActionRuleConfig {
                    finding_type: Some("inj".into()),
                    min_severity: SecuritySeverity::High,
                    min_confidence: 0.8,
                    actions: vec!["block".into(), "webhook".into()],
                },
                ActionRuleConfig {
                    finding_type: Some("inj".into()),
                    min_severity: SecuritySeverity::High,
                    min_confidence: 0.8,
                    actions: vec!["judge_route".into(), "webhook".into()],
                },
            ],
            ..ActionRouterConfig::default()
        };

        let client = reqwest::Client::new();
        let router = ActionRouter::new(&config, None, client);

        let findings = [finding("inj", SecuritySeverity::High, 0.9)];
        let acts = router.resolve_actions(&findings);
        // Includes: log, block, webhook mapped from valid rules
        let names: std::collections::HashSet<_> =
            acts.actions.iter().map(|a| a.action_type()).collect();
        assert!(names.contains("log"));
        assert!(names.contains("block"));
        assert!(names.contains("webhook"));
        assert!(names.contains("judge_route"));
        assert_eq!(
            acts.rule_matches
                .iter()
                .filter(|(_, action)| action == "webhook")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn test_execute_inline_continues_after_action_error() {
        let findings = [finding("inj", SecuritySeverity::High, 0.9)];
        let mut router = ActionRouter::new(
            &ActionRouterConfig {
                enabled: true,
                default_actions: vec!["one".into(), "two".into(), "three".into()],
                ..ActionRouterConfig::default()
            },
            None,
            Client::new(),
        );
        let one_calls = Arc::new(AtomicUsize::new(0));
        let two_calls = Arc::new(AtomicUsize::new(0));
        let three_calls = Arc::new(AtomicUsize::new(0));
        router.register_action(Arc::new(RecordingAction {
            name: "one",
            behavior: TestActionBehavior::Success,
            supports_inline: true,
            supports_async: true,
            calls: Arc::clone(&one_calls),
        }));
        router.register_action(Arc::new(RecordingAction {
            name: "two",
            behavior: TestActionBehavior::Error,
            supports_inline: true,
            supports_async: true,
            calls: Arc::clone(&two_calls),
        }));
        router.register_action(Arc::new(RecordingAction {
            name: "three",
            behavior: TestActionBehavior::Success,
            supports_inline: true,
            supports_async: true,
            calls: Arc::clone(&three_calls),
        }));

        let ctx = test_ctx(&findings, None, Some(crate::metrics::Metrics::new()));
        let decision = router
            .execute_inline(EnforcementDecision::Allow, &ctx)
            .await;

        assert!(matches!(decision, EnforcementDecision::Allow));
        assert_eq!(one_calls.load(Ordering::SeqCst), 1);
        assert_eq!(two_calls.load(Ordering::SeqCst), 1);
        assert_eq!(three_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_execute_async_skips_inline_only_actions() {
        let findings = [finding("inj", SecuritySeverity::High, 0.9)];
        let mut router = ActionRouter::new(
            &ActionRouterConfig {
                enabled: true,
                default_actions: vec!["inline_only".into(), "async_ok".into()],
                ..ActionRouterConfig::default()
            },
            None,
            Client::new(),
        );
        let inline_only_calls = Arc::new(AtomicUsize::new(0));
        let async_calls = Arc::new(AtomicUsize::new(0));
        router.register_action(Arc::new(RecordingAction {
            name: "inline_only",
            behavior: TestActionBehavior::Success,
            supports_inline: true,
            supports_async: false,
            calls: Arc::clone(&inline_only_calls),
        }));
        router.register_action(Arc::new(RecordingAction {
            name: "async_ok",
            behavior: TestActionBehavior::Success,
            supports_inline: true,
            supports_async: true,
            calls: Arc::clone(&async_calls),
        }));

        let mut ctx = test_ctx(&findings, None, None);
        ctx.execution_mode = ExecutionMode::Async;
        router.execute_async(&ctx).await;

        assert_eq!(inline_only_calls.load(Ordering::SeqCst), 0);
        assert_eq!(async_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_register_custom_action_executes() {
        let findings = [finding("inj", SecuritySeverity::High, 0.9)];
        let mut router = ActionRouter::new(
            &ActionRouterConfig {
                enabled: true,
                default_actions: vec!["custom".into()],
                ..ActionRouterConfig::default()
            },
            None,
            Client::new(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        router.register_action(Arc::new(RecordingAction {
            name: "custom",
            behavior: TestActionBehavior::Success,
            supports_inline: true,
            supports_async: true,
            calls: Arc::clone(&calls),
        }));

        let ctx = test_ctx(&findings, None, None);
        router
            .execute_inline(EnforcementDecision::Allow, &ctx)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_execute_inline_panicking_action_fails_open() {
        let findings = [finding("inj", SecuritySeverity::High, 0.9)];
        let mut router = ActionRouter::new(
            &ActionRouterConfig {
                enabled: true,
                default_actions: vec!["panic_action".into(), "after".into()],
                ..ActionRouterConfig::default()
            },
            None,
            Client::new(),
        );
        let panic_calls = Arc::new(AtomicUsize::new(0));
        let after_calls = Arc::new(AtomicUsize::new(0));
        router.register_action(Arc::new(RecordingAction {
            name: "panic_action",
            behavior: TestActionBehavior::Panic,
            supports_inline: true,
            supports_async: true,
            calls: Arc::clone(&panic_calls),
        }));
        router.register_action(Arc::new(RecordingAction {
            name: "after",
            behavior: TestActionBehavior::Success,
            supports_inline: true,
            supports_async: true,
            calls: Arc::clone(&after_calls),
        }));

        let ctx = test_ctx(&findings, None, Some(crate::metrics::Metrics::new()));
        let decision = router
            .execute_inline(EnforcementDecision::Allow, &ctx)
            .await;

        assert!(matches!(decision, EnforcementDecision::Allow));
        assert_eq!(panic_calls.load(Ordering::SeqCst), 1);
        assert_eq!(after_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_block_ip_action_sets_and_expires_block() {
        let cache: Arc<dyn CacheLayer> = Arc::new(InMemoryCacheLayer::new());
        let router = ActionRouter::new(
            &ActionRouterConfig {
                enabled: true,
                default_actions: vec!["block_ip".into()],
                ip_block: llmtrace_core::IpBlockActionConfig {
                    ttl_seconds: 1,
                    max_offenses: 1,
                },
                ..ActionRouterConfig::default()
            },
            Some(Arc::clone(&cache)),
            Client::new(),
        );
        let findings = [finding("inj", SecuritySeverity::High, 0.9)];
        let ctx = test_ctx(
            &findings,
            Some(Arc::clone(&cache)),
            Some(crate::metrics::Metrics::new()),
        );

        assert!(!router.is_ip_blocked(ctx.source_ip, &None).await);
        router
            .execute_inline(EnforcementDecision::Allow, &ctx)
            .await;
        assert!(router.is_ip_blocked(ctx.source_ip, &None).await);

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(!router.is_ip_blocked(ctx.source_ip, &None).await);
    }

    #[tokio::test]
    async fn test_webhook_action_delivers_payload() {
        let (url, received) = simple_mock("/action-webhook").await;
        let action = WebhookAction {
            url,
            timeout_ms: 500,
            http_client: Client::new(),
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let ctx = test_ctx(&findings, None, None);

        let outcome = action.execute(&ctx).await.unwrap();
        assert!(matches!(outcome, ActionOutcome::Completed { .. }));

        tokio::time::sleep(Duration::from_millis(100)).await;
        let payloads = received.lock().await;
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["tenant_id"], ctx.tenant_id.0.to_string());
        assert_eq!(
            payloads[0]["findings"][0]["finding_type"],
            "prompt_injection"
        );
    }

    #[tokio::test]
    async fn test_judge_route_enqueue_succeeds_and_receiver_gets_request() {
        let (tx, mut rx) = mpsc::channel(4);
        let action = JudgeRouteAction {
            tx,
            inline_await: false,
            inline_timeout_ms: 100,
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let ctx = test_ctx(&findings, None, None);

        let outcome = action.execute(&ctx).await.unwrap();
        assert!(matches!(outcome, ActionOutcome::Enqueued { .. }));

        let req = rx.recv().await.expect("request should be queued");
        assert_eq!(req.trace_id, ctx.trace_id);
        assert_eq!(req.tenant_id, ctx.tenant_id);
        assert_eq!(req.model_name, "gpt-4");
        assert_eq!(req.analysis_text, "test prompt");
        assert_eq!(req.prior_findings.len(), 1);
        assert_eq!(req.prior_findings[0].finding_type, "prompt_injection");
        // inline_await=false => mode should be Async regardless of execution_mode
        assert_eq!(req.mode, JudgeMode::Async);
        assert!(req.response_tx.is_none());
    }

    #[tokio::test]
    async fn test_judge_route_inline_await_returns_verdict() {
        use chrono::Utc;
        let (tx, mut rx) = mpsc::channel(4);
        let action = JudgeRouteAction {
            tx,
            inline_await: true,
            inline_timeout_ms: 500,
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let ctx = test_ctx(&findings, None, None);
        let trace_id = ctx.trace_id;
        let tenant_id = ctx.tenant_id;

        // Simulate a worker replying with a Verdict on the oneshot.
        let worker = tokio::spawn(async move {
            let req = rx.recv().await.expect("request should be queued");
            assert_eq!(req.mode, JudgeMode::Inline);
            assert!(req.response_tx.is_some());
            let tx = req.response_tx.unwrap();
            let verdict = JudgeVerdict {
                id: Uuid::new_v4(),
                trace_id,
                tenant_id,
                is_threat: true,
                category: "prompt_injection".to_string(),
                confidence: 0.9,
                security_score: 85,
                recommended_action: "block".to_string(),
                reasoning: "test".to_string(),
                mode: JudgeMode::Inline,
                model_used: "security-judge-v1".to_string(),
                latency_ms: 50,
                prompt_tokens: None,
                completion_tokens: None,
                created_at: Utc::now(),
            };
            let _ = tx.send(JudgeResponse::Verdict(verdict));
        });

        let outcome = action.execute(&ctx).await.unwrap();
        // Verdict has is_threat=true and recommended_action="block", so
        // phase 5 promotion fires: the outcome must be BlockRequested
        // with the judge finding appended to the prior ensemble findings.
        match outcome {
            ActionOutcome::BlockRequested { reason, findings } => {
                assert!(reason.contains("prompt_injection"));
                assert_eq!(findings.len(), 2); // prior + judge
                let judge_finding = findings.last().unwrap();
                assert_eq!(judge_finding.finding_type, JUDGE_FINDING_TYPE);
                assert_eq!(
                    judge_finding
                        .metadata
                        .get("voting_result")
                        .map(String::as_str),
                    Some("llm_judge")
                );
            }
            other => panic!("expected BlockRequested, got {other:?}"),
        }
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn test_judge_route_inline_verdict_allow_preserves_outcome() {
        use chrono::Utc;
        let (tx, mut rx) = mpsc::channel(4);
        let action = JudgeRouteAction {
            tx,
            inline_await: true,
            inline_timeout_ms: 500,
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let ctx = test_ctx(&findings, None, None);
        let trace_id = ctx.trace_id;
        let tenant_id = ctx.tenant_id;

        // Worker replies with a benign verdict (judge disagrees with regex).
        let worker = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            let tx = req.response_tx.unwrap();
            let verdict = JudgeVerdict {
                id: Uuid::new_v4(),
                trace_id,
                tenant_id,
                is_threat: false,
                category: "benign".to_string(),
                confidence: 0.95,
                security_score: 10,
                recommended_action: "allow".to_string(),
                reasoning: "legitimate request".to_string(),
                mode: JudgeMode::Inline,
                model_used: "security-judge-v1".to_string(),
                latency_ms: 50,
                prompt_tokens: None,
                completion_tokens: None,
                created_at: Utc::now(),
            };
            let _ = tx.send(JudgeResponse::Verdict(verdict));
        });

        let outcome = action.execute(&ctx).await.unwrap();
        // is_threat=false: no promotion, outcome is Completed and the
        // caller keeps whatever decision the prior enforcement produced.
        match outcome {
            ActionOutcome::Completed { message } => assert!(message.contains("allow")),
            other => panic!("expected Completed, got {other:?}"),
        }
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn test_judge_route_records_agreement_metric() {
        use chrono::Utc;
        let (tx, mut rx) = mpsc::channel(4);
        let action = JudgeRouteAction {
            tx,
            inline_await: true,
            inline_timeout_ms: 500,
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let metrics = crate::metrics::Metrics::new();
        let ctx = test_ctx(&findings, None, Some(metrics.clone()));
        let trace_id = ctx.trace_id;
        let tenant_id = ctx.tenant_id;

        let worker = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            let tx = req.response_tx.unwrap();
            // Ensemble had a High finding; judge also says threat -> "confirm".
            let verdict = JudgeVerdict {
                id: Uuid::new_v4(),
                trace_id,
                tenant_id,
                is_threat: true,
                category: "prompt_injection".to_string(),
                confidence: 0.9,
                security_score: 85,
                recommended_action: "block".to_string(),
                reasoning: "test".to_string(),
                mode: JudgeMode::Inline,
                model_used: "security-judge-v1".to_string(),
                latency_ms: 50,
                prompt_tokens: None,
                completion_tokens: None,
                created_at: Utc::now(),
            };
            let _ = tx.send(JudgeResponse::Verdict(verdict));
        });

        action.execute(&ctx).await.unwrap();
        worker.await.unwrap();

        let text = metrics.gather_text().unwrap();
        assert!(text.contains("llmtrace_judge_verdict_agreement"));
        assert!(text.contains("agreement=\"confirm\""));
    }

    #[tokio::test]
    async fn test_judge_route_inline_await_skipped_is_outcome_skipped() {
        let (tx, mut rx) = mpsc::channel(4);
        let action = JudgeRouteAction {
            tx,
            inline_await: true,
            inline_timeout_ms: 500,
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let ctx = test_ctx(&findings, None, None);

        let worker = tokio::spawn(async move {
            let req = rx.recv().await.expect("request should be queued");
            let tx = req.response_tx.unwrap();
            let _ = tx.send(JudgeResponse::Skipped {
                reason: "disabled".to_string(),
            });
        });

        let outcome = action.execute(&ctx).await.unwrap();
        match outcome {
            ActionOutcome::Skipped { reason } => assert_eq!(reason, "disabled"),
            other => panic!("expected Skipped, got {other:?}"),
        }
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn test_judge_route_channel_full_records_drop_metric() {
        let (tx, _rx) = mpsc::channel::<JudgeRequest>(1);
        // Fill the channel with a placeholder so try_send fails.
        tx.try_send(JudgeRequest {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            model_name: "filler".to_string(),
            analysis_text: String::new(),
            prior_findings: vec![],
            mode: JudgeMode::Async,
            response_tx: None,
        })
        .unwrap();

        let action = JudgeRouteAction {
            tx,
            inline_await: false,
            inline_timeout_ms: 100,
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let metrics = crate::metrics::Metrics::new();
        let mut ctx = test_ctx(&findings, None, Some(metrics.clone()));
        ctx.execution_mode = ExecutionMode::Async;

        let err = action.execute(&ctx).await.unwrap_err();
        assert!(matches!(err, ActionError::Failed(_)));
        let text = metrics.gather_text().unwrap();
        assert!(text.contains("llmtrace_judge_dropped_total"));
        assert!(text.contains("reason=\"channel_full\""));
    }

    #[tokio::test]
    async fn test_action_metrics_record_rule_matches_and_latency() {
        let findings = [finding("inj", SecuritySeverity::High, 0.9)];
        let metrics = crate::metrics::Metrics::new();
        let router = ActionRouter::new(
            &ActionRouterConfig {
                enabled: true,
                default_actions: vec!["log".into()],
                rules: vec![ActionRuleConfig {
                    finding_type: Some("inj".into()),
                    min_severity: SecuritySeverity::High,
                    min_confidence: 0.8,
                    actions: vec!["webhook".into()],
                }],
                webhook: llmtrace_core::WebhookActionConfig {
                    url: "http://127.0.0.1:9/unreachable".to_string(),
                    timeout_ms: 10,
                },
                ..ActionRouterConfig::default()
            },
            None,
            Client::new(),
        );
        let ctx = test_ctx(&findings, None, Some(metrics.clone()));

        router
            .execute_inline(EnforcementDecision::Allow, &ctx)
            .await;

        let text = metrics.gather_text().unwrap();
        assert!(text.contains("llmtrace_action_rule_matches_total"));
        assert!(text.contains("finding_type=\"inj\""));
        assert!(text.contains("action_type=\"webhook\""));
        assert!(text.contains("llmtrace_action_latency_seconds"));
    }
}
