use async_trait::async_trait;
use llmtrace_core::{ActionRouterConfig, ActionRuleConfig, CacheLayer, SecurityFinding, TenantId};
use reqwest::Client;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
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

        let (judge_tx, _judge_rx) = mpsc::channel(100);
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

    // Identify which actions apply based on findings
    fn resolve_actions(&self, findings: &[SecurityFinding]) -> Vec<Arc<dyn Action>> {
        let mut selected = std::collections::HashSet::new();

        if !self.enabled {
            return vec![];
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
                }
            }
        }

        selected
            .into_iter()
            .filter_map(|name| self.actions.get(&name).cloned())
            .collect()
    }

    pub async fn execute_inline(
        &self,
        decision: EnforcementDecision,
        ctx: &ActionContext<'_>,
    ) -> EnforcementDecision {
        if !self.enabled {
            return decision;
        }

        let actions_to_run = self.resolve_actions(ctx.findings);
        let mut final_decision = decision;

        // Note: Concurrent execution via `futures::future::join_all` could be used,
        // but for inline simplicity and safety we await in loop or join. Let's use loop.
        for action in actions_to_run {
            if !action.supports_inline() {
                continue;
            }

            match action.execute(ctx).await {
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
                    warn!(action = action.action_type(), error = %e, "Inline action failed (fail-open semantics)");
                    if let Some(m) = &ctx.metrics {
                        m.record_action_execution(action.action_type(), "error", "inline");
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

        let actions_to_run = self.resolve_actions(ctx.findings);

        for action in actions_to_run {
            if !action.supports_async() {
                continue;
            }

            match action.execute(ctx).await {
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
                        m.record_action_execution(action.action_type(), "error", "async");
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
        let count_str = match cache.get(&off_key).await {
            Ok(Some(v)) => String::from_utf8_lossy(&v).to_string(),
            _ => "0".to_string(),
        };
        let count: u32 = count_str.parse().unwrap_or(0) + 1;

        let _ = cache
            .set(
                &off_key,
                count.to_string().as_bytes(),
                std::time::Duration::from_secs(self.ttl_seconds),
            )
            .await;

        if count >= self.max_offenses {
            let block_key = format!("blocked_ip:{}", ip);
            let _ = cache
                .set(
                    &block_key,
                    b"1",
                    std::time::Duration::from_secs(self.ttl_seconds),
                )
                .await;
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
pub struct JudgeRequest {
    pub trace_id: Uuid,
    pub tenant_id: TenantId,
    pub model_name: String,
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
        let req = JudgeRequest {
            trace_id: ctx.trace_id,
            tenant_id: ctx.tenant_id,
            model_name: ctx.model_name.clone(),
        };

        if self.tx.try_send(req).is_err() {
            // Note: failing on channel full is fine
            return Err(ActionError::Failed("Channel full or closed".to_string()));
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
    use llmtrace_core::SecuritySeverity;

    fn finding(t: &str, s: SecuritySeverity, c: f64) -> SecurityFinding {
        SecurityFinding::new(s, t.to_string(), "desc".into(), c)
    }

    #[tokio::test]
    async fn test_resolve_actions() {
        let config = ActionRouterConfig {
            enabled: true,
            default_actions: vec!["log".into()],
            rules: vec![ActionRuleConfig {
                finding_type: Some("inj".into()),
                min_severity: SecuritySeverity::High,
                min_confidence: 0.8,
                actions: vec!["block".into(), "webhook".into()],
            }],
            ..ActionRouterConfig::default()
        };

        let client = reqwest::Client::new();
        let router = ActionRouter::new(&config, None, client);

        let findings = [finding("inj", SecuritySeverity::High, 0.9)];
        let acts = router.resolve_actions(&findings);
        // Includes: log, block, webhook mapped from valid rules
        let names: std::collections::HashSet<_> = acts.iter().map(|a| a.action_type()).collect();
        assert!(names.contains("log"));
        assert!(names.contains("block"));
        assert!(names.contains("webhook"));
    }
}
