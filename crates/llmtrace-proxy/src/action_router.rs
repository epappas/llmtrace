use async_trait::async_trait;
use futures_util::FutureExt;
use llmtrace_core::{ActionRouterConfig, ActionRuleConfig, CacheLayer, SecurityFinding, TenantId};
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::enforcement::EnforcementDecision;

/// Context provided to all Actions
pub struct ActionContext<'a> {
    pub trace_id: Uuid,
    pub tenant_id: TenantId,
    pub findings: &'a [SecurityFinding],
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
    _judge_rx: Option<Arc<Mutex<mpsc::Receiver<JudgeRequest>>>>,
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
            _judge_rx: None,
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

        let (judge_tx, judge_rx) = mpsc::channel::<JudgeRequest>(100);
        let judge_rx = Arc::new(Mutex::new(judge_rx));
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let judge_rx_task = Arc::clone(&judge_rx);
            handle.spawn(async move {
                loop {
                    let req = {
                        let mut receiver = judge_rx_task.lock().await;
                        receiver.recv().await
                    };
                    let Some(req) = req else {
                        break;
                    };
                    debug!(
                        trace_id = %req.trace_id,
                        tenant_id = %req.tenant_id,
                        model_name = %req.model_name,
                        "Received JudgeRouteAction request"
                    );
                    if let Some(response_tx) = req.response_tx {
                        let _ = response_tx.send(JudgeResponse { accepted: true });
                    }
                }
            });
        }
        router._judge_rx = Some(judge_rx);
        let judge_route = Arc::new(JudgeRouteAction {
            tx: judge_tx,
            inline_await: config.judge_route.inline_await,
            inline_timeout_ms: config.judge_route.inline_timeout_ms,
        });
        router.register_action(judge_route);

        router
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

#[derive(Debug, Clone)]
pub struct JudgeResponse {
    pub accepted: bool,
}

#[derive(Debug)]
pub struct JudgeRequest {
    pub trace_id: Uuid,
    pub tenant_id: TenantId,
    pub model_name: String,
    pub response_tx: Option<oneshot::Sender<JudgeResponse>>,
}

pub struct JudgeRouteAction {
    pub tx: mpsc::Sender<JudgeRequest>,
    pub inline_await: bool,
    pub inline_timeout_ms: u64,
}

#[async_trait]
impl Action for JudgeRouteAction {
    fn action_type(&self) -> &str {
        "judge_route"
    }

    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<ActionOutcome, ActionError> {
        let should_await = self.inline_await && matches!(ctx.execution_mode, ExecutionMode::Inline);

        if should_await {
            let (response_tx, response_rx) = oneshot::channel();
            let req = JudgeRequest {
                trace_id: ctx.trace_id,
                tenant_id: ctx.tenant_id,
                model_name: ctx.model_name.clone(),
                response_tx: Some(response_tx),
            };
            self.tx.send(req).await.map_err(|_| {
                ActionError::Failed("Judge route channel closed before enqueue".to_string())
            })?;

            let ack =
                tokio::time::timeout(Duration::from_millis(self.inline_timeout_ms), response_rx)
                    .await
                    .map_err(|_| {
                        ActionError::Failed("Timed out waiting for judge ack".to_string())
                    })?
                    .map_err(|_| ActionError::Failed("Judge ack channel closed".to_string()))?;

            if !ack.accepted {
                return Err(ActionError::Failed(
                    "Judge route worker rejected the request".to_string(),
                ));
            }
        } else {
            let req = JudgeRequest {
                trace_id: ctx.trace_id,
                tenant_id: ctx.tenant_id,
                model_name: ctx.model_name.clone(),
                response_tx: None,
            };
            if self.tx.try_send(req).is_err() {
                return Err(ActionError::Failed("Channel full or closed".to_string()));
            }
        }

        Ok(ActionOutcome::Enqueued {
            queue_id: format!("judge_{}", ctx.trace_id),
        })
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
