use async_trait::async_trait;
use futures_util::FutureExt;
use llmtrace_core::{
    ActionRouterConfig, ActionRuleConfig, CacheLayer, JudgeMode, JudgePromotionConfig,
    JudgeVerdict, SecurityFinding, SecuritySeverity, TenantId,
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

/// Re-export of the canonical finding-type constant from `llmtrace-core`
/// so existing callers of `llmtrace_proxy::action_router::JUDGE_FINDING_TYPE`
/// keep working after the deduplication in issue #76.
pub use llmtrace_core::JUDGE_FINDING_TYPE;

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
        judge_promotion: JudgePromotionConfig,
        judge_max_analysis_text_bytes: u32,
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
            promotion: judge_promotion,
            max_analysis_text_bytes: judge_max_analysis_text_bytes as usize,
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
///
/// Issue #70: the promotion is additionally gated by
/// [`JudgePromotionConfig`]. A verdict that fails any gate increments
/// `llmtrace_judge_promotion_rejected_total{reason}` and falls through
/// to `ActionOutcome::Completed`, preserving the prior enforcement
/// decision. This protects against compromised, drifted, or
/// uncalibrated judges.
fn verdict_to_outcome(
    prior_findings: &[SecurityFinding],
    verdict: &JudgeVerdict,
    promotion: &JudgePromotionConfig,
    metrics: Option<&crate::metrics::Metrics>,
) -> ActionOutcome {
    if let Some(rejection) = promotion_rejection(prior_findings, verdict, promotion) {
        if let Some(m) = metrics {
            m.record_judge_promotion_rejected(rejection);
        }
        return ActionOutcome::Completed {
            message: format!(
                "Judge verdict not promoted ({}): category={} action={} score={} conf={:.2}",
                rejection,
                verdict.category,
                verdict.recommended_action,
                verdict.security_score,
                verdict.confidence,
            ),
        };
    }

    if promotion.shadow {
        if let Some(m) = metrics {
            m.record_judge_shadow_would_block(&verdict.category, &verdict.recommended_action);
        }
        return ActionOutcome::Completed {
            message: format!(
                "Judge verdict would block (shadow mode): category={} action={} score={} conf={:.2}",
                verdict.category,
                verdict.recommended_action,
                verdict.security_score,
                verdict.confidence,
            ),
        };
    }

    let judge_finding = llmtrace_core::verdict_to_finding(verdict);
    let mut merged: Vec<SecurityFinding> = prior_findings.to_vec();
    merged.push(judge_finding);
    ActionOutcome::BlockRequested {
        reason: format!(
            "LLM Judge confirmed {} (score={}, conf={:.2})",
            verdict.category, verdict.security_score, verdict.confidence,
        ),
        findings: merged,
    }
}

/// Return `Some(reason)` when the verdict fails the promotion gate;
/// `None` when all gates pass. Rejection reasons are stable wire
/// strings used as metric labels — do not rename without updating the
/// pre-initialised labels in `Metrics::new`.
fn promotion_rejection(
    prior_findings: &[SecurityFinding],
    verdict: &JudgeVerdict,
    promotion: &JudgePromotionConfig,
) -> Option<&'static str> {
    if !verdict.is_threat || verdict.recommended_action != "block" {
        return Some("not_threat_or_block");
    }
    if verdict.confidence < promotion.min_confidence {
        return Some("below_confidence");
    }
    if verdict.security_score < promotion.min_security_score {
        return Some("below_score");
    }
    if promotion.require_ensemble_support && !has_medium_or_higher(prior_findings) {
        return Some("no_ensemble_support");
    }
    None
}

fn has_medium_or_higher(findings: &[SecurityFinding]) -> bool {
    findings.iter().any(|f| {
        matches!(
            f.severity,
            SecuritySeverity::Medium | SecuritySeverity::High | SecuritySeverity::Critical
        )
    })
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
    /// Inline-path Block-promotion policy. Captured at construction so
    /// verdicts are evaluated against a stable policy for the lifetime
    /// of the process; runtime tuning requires restart (hot-flip is
    /// tracked separately in #46).
    pub promotion: JudgePromotionConfig,
    /// Issue #78: upper bound on `analysis_text` bytes copied into the
    /// envelope. Caps worst-case memory when the channel saturates.
    /// Truncation is byte-bounded but UTF-8-safe (splits at char
    /// boundaries), and increments the `analysis_text_truncated`
    /// drop-reason counter.
    pub max_analysis_text_bytes: usize,
}

impl JudgeRouteAction {
    fn build_request(
        &self,
        ctx: &ActionContext<'_>,
        mode: JudgeMode,
        response_tx: Option<oneshot::Sender<JudgeResponse>>,
    ) -> JudgeRequest {
        let analysis_text = truncate_analysis_text(ctx.analysis_text, self.max_analysis_text_bytes);
        if analysis_text.len() < ctx.analysis_text.len() {
            if let Some(metrics) = &ctx.metrics {
                metrics.record_judge_dropped("analysis_text_truncated");
            }
        }
        JudgeRequest {
            trace_id: ctx.trace_id,
            tenant_id: ctx.tenant_id,
            model_name: ctx.model_name.clone(),
            analysis_text,
            prior_findings: ctx.findings.to_vec(),
            mode,
            response_tx,
        }
    }
}

/// Truncate an analysis text to at most `max_bytes` bytes at a UTF-8
/// char boundary. If `text.len() <= max_bytes` the input is returned
/// unchanged; otherwise the returned string is byte-bounded and
/// ends at a valid char boundary (never mid-codepoint).
fn truncate_analysis_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
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
            // Non-blocking enqueue on the inline path. If the channel is
            // full we fail open immediately rather than stalling the
            // request thread — see issue #69: `send().await` can block
            // inline callers past their `inline_timeout_ms` budget when
            // the judge worker is slow or saturated, degrading hot-path
            // latency for legitimate traffic.
            if let Err(e) = self.tx.try_send(req) {
                if let Some(metrics) = &ctx.metrics {
                    let reason = match e {
                        mpsc::error::TrySendError::Full(_) => "channel_full",
                        mpsc::error::TrySendError::Closed(_) => "channel_closed",
                    };
                    metrics.record_judge_dropped(reason);
                }
                return Err(ActionError::Failed(
                    "Judge route channel full or closed on inline path".to_string(),
                ));
            }

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
                    Ok(verdict_to_outcome(
                        ctx.findings,
                        &verdict,
                        &self.promotion,
                        ctx.metrics.as_ref(),
                    ))
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

    /// Mock webhook server.
    ///
    /// Returns the URL, the shared store of received payloads, and an mpsc
    /// receiver that the handler signals on each received payload so callers
    /// can synchronize on delivery instead of sleeping.
    async fn simple_mock(
        path: &str,
    ) -> (
        String,
        Arc<AsyncMutex<Vec<serde_json::Value>>>,
        mpsc::Receiver<()>,
    ) {
        let received: Arc<AsyncMutex<Vec<serde_json::Value>>> =
            Arc::new(AsyncMutex::new(Vec::new()));
        let store = Arc::clone(&received);
        let (tx, rx) = mpsc::channel::<()>(8);
        let app = Router::new().route(
            path,
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let store = Arc::clone(&store);
                let tx = tx.clone();
                async move {
                    store.lock().await.push(body);
                    // Signal delivery; ignore if the receiver is gone.
                    let _ = tx.send(()).await;
                    axum::http::StatusCode::OK
                }
            }),
        );

        // Bind synchronously before spawning serve so the socket is already
        // accepting connections by the time the URL is handed back.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (format!("http://{addr}{path}"), received, rx)
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
        let router = ActionRouter::new(
            &config,
            llmtrace_core::JudgePromotionConfig::default(),
            64 * 1024,
            None,
            client,
        );

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
            llmtrace_core::JudgePromotionConfig::default(),
            64 * 1024,
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
            llmtrace_core::JudgePromotionConfig::default(),
            64 * 1024,
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
            llmtrace_core::JudgePromotionConfig::default(),
            64 * 1024,
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
            llmtrace_core::JudgePromotionConfig::default(),
            64 * 1024,
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
            llmtrace_core::JudgePromotionConfig::default(),
            64 * 1024,
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
        let (url, received, mut delivered) = simple_mock("/action-webhook").await;
        let action = WebhookAction {
            url,
            timeout_ms: 500,
            http_client: Client::new(),
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let ctx = test_ctx(&findings, None, None);

        let outcome = action.execute(&ctx).await.unwrap();
        assert!(matches!(outcome, ActionOutcome::Completed { .. }));

        // Wait for the mock handler to signal it received the payload, with a
        // bounded timeout that fails loudly rather than racing on a sleep.
        tokio::time::timeout(Duration::from_secs(5), delivered.recv())
            .await
            .expect("webhook payload was not delivered within 5s")
            .expect("mock handler signal channel closed before delivery");
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
            promotion: JudgePromotionConfig::default(),
            max_analysis_text_bytes: 64 * 1024,
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
            promotion: JudgePromotionConfig::default(),
            max_analysis_text_bytes: 64 * 1024,
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
            promotion: JudgePromotionConfig::default(),
            max_analysis_text_bytes: 64 * 1024,
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
            promotion: JudgePromotionConfig::default(),
            max_analysis_text_bytes: 64 * 1024,
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

    // Issue #70: tests for the promotion gate. Uses the synchronous
    // verdict_to_outcome path directly to pin the logic independently
    // of the action router.

    fn sample_verdict(is_threat: bool, action: &str, confidence: f64, score: u8) -> JudgeVerdict {
        use chrono::Utc;
        JudgeVerdict {
            id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            is_threat,
            category: "prompt_injection".to_string(),
            confidence,
            security_score: score,
            recommended_action: action.to_string(),
            reasoning: "test".to_string(),
            mode: JudgeMode::Inline,
            model_used: "security-judge-v1".to_string(),
            latency_ms: 10,
            prompt_tokens: None,
            completion_tokens: None,
            created_at: Utc::now(),
        }
    }

    // Issue #78: analysis_text envelope cap.

    #[test]
    fn truncate_analysis_text_leaves_short_strings_untouched() {
        assert_eq!(truncate_analysis_text("hello", 64), "hello");
        assert_eq!(truncate_analysis_text("", 64), "");
    }

    #[test]
    fn truncate_analysis_text_caps_long_strings_at_byte_limit() {
        let s = "a".repeat(200);
        let out = truncate_analysis_text(&s, 64);
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn truncate_analysis_text_respects_utf8_boundaries() {
        let s = "a\u{1F600}b\u{1F600}c"; // 1 + 4 + 1 + 4 + 1 = 11 bytes
        let out = truncate_analysis_text(s, 5);
        assert_eq!(out, "a\u{1F600}");
        assert_eq!(out.len(), 5);
    }

    #[tokio::test]
    async fn judge_route_build_request_truncates_and_records_metric() {
        let (tx, _rx) = mpsc::channel::<JudgeRequest>(4);
        let action = JudgeRouteAction {
            tx,
            inline_await: false,
            inline_timeout_ms: 100,
            promotion: JudgePromotionConfig::default(),
            max_analysis_text_bytes: 16,
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let metrics = crate::metrics::Metrics::new();
        let mut ctx = test_ctx(&findings, None, Some(metrics.clone()));
        let long: &str = "this text is definitely longer than sixteen bytes, trust me";
        ctx.analysis_text = long;
        let req = action.build_request(&ctx, JudgeMode::Async, None);
        assert_eq!(req.analysis_text.len(), 16);
        assert!(long.starts_with(req.analysis_text.as_str()));

        let text = metrics.gather_text().unwrap();
        assert!(text.contains("reason=\"analysis_text_truncated\""));
    }

    #[test]
    fn promotion_rejects_when_not_threat_or_block() {
        let v = sample_verdict(false, "allow", 0.95, 80);
        assert_eq!(
            promotion_rejection(&[], &v, &JudgePromotionConfig::default()),
            Some("not_threat_or_block"),
        );

        let v = sample_verdict(true, "flag", 0.95, 80);
        assert_eq!(
            promotion_rejection(&[], &v, &JudgePromotionConfig::default()),
            Some("not_threat_or_block"),
        );
    }

    #[test]
    fn promotion_rejects_when_below_confidence() {
        let prior = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let v = sample_verdict(true, "block", 0.5, 80);
        assert_eq!(
            promotion_rejection(&prior, &v, &JudgePromotionConfig::default()),
            Some("below_confidence"),
        );
    }

    #[test]
    fn promotion_rejects_when_below_score() {
        let prior = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let v = sample_verdict(true, "block", 0.9, 30);
        assert_eq!(
            promotion_rejection(&prior, &v, &JudgePromotionConfig::default()),
            Some("below_score"),
        );
    }

    #[test]
    fn promotion_rejects_when_no_ensemble_support() {
        // require_ensemble_support=true (default), but prior findings are
        // empty -> gate rejects even though the verdict is strong.
        let v = sample_verdict(true, "block", 0.95, 85);
        assert_eq!(
            promotion_rejection(&[], &v, &JudgePromotionConfig::default()),
            Some("no_ensemble_support"),
        );
    }

    #[test]
    fn promotion_passes_when_all_gates_satisfied() {
        let prior = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let v = sample_verdict(true, "block", 0.95, 85);
        assert_eq!(
            promotion_rejection(&prior, &v, &JudgePromotionConfig::default()),
            None,
        );
    }

    #[test]
    fn promotion_ensemble_support_opt_out_allows_pure_judge_block() {
        // When require_ensemble_support=false, a strong judge verdict
        // can Block even without supporting ensemble findings.
        let mut promotion = JudgePromotionConfig::default();
        promotion.require_ensemble_support = false;
        let v = sample_verdict(true, "block", 0.95, 85);
        assert_eq!(promotion_rejection(&[], &v, &promotion), None);
    }

    #[test]
    fn verdict_to_outcome_records_rejection_metric_and_returns_completed() {
        let metrics = crate::metrics::Metrics::new();
        let v = sample_verdict(true, "block", 0.3, 85); // below default min_confidence 0.7
        let prior = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let outcome =
            verdict_to_outcome(&prior, &v, &JudgePromotionConfig::default(), Some(&metrics));
        assert!(matches!(outcome, ActionOutcome::Completed { .. }));
        let text = metrics.gather_text().unwrap();
        assert!(text.contains("llmtrace_judge_promotion_rejected_total"));
        assert!(text.contains("reason=\"below_confidence\""));
    }

    #[test]
    fn verdict_to_outcome_promotes_when_all_gates_pass() {
        let metrics = crate::metrics::Metrics::new();
        let v = sample_verdict(true, "block", 0.95, 85);
        let prior = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let outcome =
            verdict_to_outcome(&prior, &v, &JudgePromotionConfig::default(), Some(&metrics));
        match outcome {
            ActionOutcome::BlockRequested { reason, findings } => {
                assert!(reason.contains("prompt_injection"));
                assert_eq!(findings.len(), 2); // prior + judge
            }
            other => panic!("expected BlockRequested, got {other:?}"),
        }
        // Sanity: the same scenario must not bump the shadow counter when
        // shadow mode is off. An IntCounterVec without any recorded
        // sample does not appear in the text exposition, so we only
        // assert the negative (no incremented shadow sample).
        let text = metrics.gather_text().unwrap();
        assert!(!text.contains(
            "llmtrace_judge_shadow_would_block_total{category=\"prompt_injection\",recommended_action=\"block\"} 1"
        ));
    }

    #[test]
    fn verdict_to_outcome_shadow_suppresses_promotion_and_records_counter() {
        let metrics = crate::metrics::Metrics::new();
        let v = sample_verdict(true, "block", 0.95, 85);
        let prior = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let promotion = JudgePromotionConfig {
            shadow: true,
            ..JudgePromotionConfig::default()
        };
        let outcome = verdict_to_outcome(&prior, &v, &promotion, Some(&metrics));
        match outcome {
            ActionOutcome::Completed { message } => {
                assert!(
                    message.contains("shadow mode"),
                    "message should explain shadow: {message}"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        let text = metrics.gather_text().unwrap();
        assert!(text.contains(
            "llmtrace_judge_shadow_would_block_total{category=\"prompt_injection\",recommended_action=\"block\"} 1"
        ));
    }

    #[test]
    fn verdict_to_outcome_shadow_does_not_bypass_rejection_gate() {
        let metrics = crate::metrics::Metrics::new();
        // Below min_confidence -> must still be rejected before shadow branch runs.
        let v = sample_verdict(true, "block", 0.3, 85);
        let prior = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let promotion = JudgePromotionConfig {
            shadow: true,
            ..JudgePromotionConfig::default()
        };
        let outcome = verdict_to_outcome(&prior, &v, &promotion, Some(&metrics));
        assert!(matches!(outcome, ActionOutcome::Completed { .. }));
        let text = metrics.gather_text().unwrap();
        assert!(text.contains("reason=\"below_confidence\""));
        assert!(!text.contains(
            "llmtrace_judge_shadow_would_block_total{category=\"prompt_injection\",recommended_action=\"block\"} 1"
        ));
    }

    #[tokio::test]
    async fn test_judge_route_inline_await_skipped_is_outcome_skipped() {
        let (tx, mut rx) = mpsc::channel(4);
        let action = JudgeRouteAction {
            tx,
            inline_await: true,
            inline_timeout_ms: 500,
            promotion: JudgePromotionConfig::default(),
            max_analysis_text_bytes: 64 * 1024,
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
            promotion: JudgePromotionConfig::default(),
            max_analysis_text_bytes: 64 * 1024,
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
    async fn test_judge_route_inline_channel_full_fails_fast_not_on_timeout() {
        // Issue #69: inline path must fail open immediately when the
        // channel is full instead of stalling until `inline_timeout_ms`
        // on `send().await`.
        let (tx, _rx) = mpsc::channel::<JudgeRequest>(1);
        // Pre-fill so try_send returns Full.
        tx.try_send(JudgeRequest {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            model_name: "filler".to_string(),
            analysis_text: String::new(),
            prior_findings: vec![],
            mode: JudgeMode::Inline,
            response_tx: None,
        })
        .unwrap();

        // Large inline_timeout_ms: the fix must return fast despite the
        // generous budget; if the implementation ever regresses to
        // `send().await`, the channel has no receiver so the send would
        // block indefinitely and the test would time out rather than
        // returning within 50ms.
        let action = JudgeRouteAction {
            tx,
            inline_await: true,
            inline_timeout_ms: 30_000,
            promotion: JudgePromotionConfig::default(),
            max_analysis_text_bytes: 64 * 1024,
        };
        let findings = [finding("prompt_injection", SecuritySeverity::High, 0.9)];
        let metrics = crate::metrics::Metrics::new();
        let ctx = test_ctx(&findings, None, Some(metrics.clone()));

        let started = std::time::Instant::now();
        let err = action.execute(&ctx).await.unwrap_err();
        let elapsed = started.elapsed();

        assert!(matches!(err, ActionError::Failed(_)));
        assert!(
            elapsed < Duration::from_millis(50),
            "inline path took {elapsed:?} — expected <50ms fail-fast"
        );
        let text = metrics.gather_text().unwrap();
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
            llmtrace_core::JudgePromotionConfig::default(),
            64 * 1024,
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
