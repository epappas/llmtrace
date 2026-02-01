//! Cost cap enforcement and spend tracking.
//!
//! Provides pre-request token cap enforcement, budget cap checking against
//! cache-backed spend totals, and post-request async spend recording.
//! Period keys auto-expire via cache TTL.

use chrono::Utc;
use llmtrace_core::{
    AgentCostCap, BudgetCap, BudgetWindow, CacheLayer, CostCapConfig, TenantId, TokenCap,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Enforcement results
// ---------------------------------------------------------------------------

/// Result of a pre-request cap check.
#[derive(Debug, Clone)]
pub enum CapCheckResult {
    /// Request is allowed.
    Allowed,
    /// Request is allowed but a soft cap or 80 % threshold was breached.
    AllowedWithWarning {
        /// Human-readable warning messages.
        warnings: Vec<String>,
    },
    /// Request is rejected — hard budget cap exceeded.
    Rejected {
        /// Which window was exceeded.
        window: BudgetWindow,
        /// Current spend in USD.
        current_spend_usd: f64,
        /// Hard limit in USD.
        hard_limit_usd: f64,
        /// Seconds until the current period resets.
        retry_after_secs: u64,
    },
    /// Request is rejected — per-request token cap exceeded.
    TokenCapExceeded {
        /// Human-readable explanation.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Spend snapshot (for the visibility API)
// ---------------------------------------------------------------------------

/// Current spend for a single budget window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSpend {
    /// The budget window.
    pub window: BudgetWindow,
    /// Current spend in USD.
    pub current_spend_usd: f64,
    /// Hard limit in USD.
    pub hard_limit_usd: f64,
    /// Soft limit in USD (if configured).
    pub soft_limit_usd: Option<f64>,
    /// Percentage of hard limit consumed.
    pub utilization_pct: f64,
    /// Seconds until this period resets.
    pub resets_in_secs: u64,
}

/// Spend snapshot across all windows for a tenant/agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendSnapshot {
    /// Tenant ID.
    pub tenant_id: String,
    /// Agent ID (empty string for tenant-level defaults).
    pub agent_id: String,
    /// Per-window spend data.
    pub windows: Vec<WindowSpend>,
}

// ---------------------------------------------------------------------------
// CostTracker
// ---------------------------------------------------------------------------

/// Cache-backed spend tracker and cap enforcer.
///
/// Uses the [`CacheLayer`] to store running spend totals keyed by
/// `tenant_id / agent_id / window / period`. Period keys auto-expire
/// via cache TTL so old windows are automatically garbage-collected.
pub struct CostTracker {
    /// Cost cap configuration.
    config: CostCapConfig,
    /// Cache layer for persisting spend totals.
    cache: Arc<dyn CacheLayer>,
}

impl CostTracker {
    /// Create a new cost tracker.
    ///
    /// Returns `None` if cost caps are disabled.
    pub fn new(config: &CostCapConfig, cache: Arc<dyn CacheLayer>) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            config: config.clone(),
            cache,
        })
    }

    /// Enforce token caps on a request **before** it is forwarded upstream.
    ///
    /// Returns `CapCheckResult::TokenCapExceeded` if any per-request token
    /// cap is violated.
    #[must_use]
    pub fn check_token_caps(
        &self,
        agent_id: Option<&str>,
        prompt_tokens: Option<u32>,
        completion_tokens: Option<u32>,
        total_tokens: Option<u32>,
    ) -> CapCheckResult {
        let token_cap = self.resolve_token_cap(agent_id);
        let token_cap = match token_cap {
            Some(tc) => tc,
            None => return CapCheckResult::Allowed,
        };

        if let Some(max) = token_cap.max_prompt_tokens {
            if let Some(actual) = prompt_tokens {
                if actual > max {
                    return CapCheckResult::TokenCapExceeded {
                        reason: format!("Prompt tokens ({actual}) exceed cap ({max})"),
                    };
                }
            }
        }
        if let Some(max) = token_cap.max_completion_tokens {
            if let Some(actual) = completion_tokens {
                if actual > max {
                    return CapCheckResult::TokenCapExceeded {
                        reason: format!("Completion tokens ({actual}) exceed cap ({max})"),
                    };
                }
            }
        }
        if let Some(max) = token_cap.max_total_tokens {
            if let Some(actual) = total_tokens {
                if actual > max {
                    return CapCheckResult::TokenCapExceeded {
                        reason: format!("Total tokens ({actual}) exceed cap ({max})"),
                    };
                }
            }
        }
        CapCheckResult::Allowed
    }

    /// Check budget caps against running spend totals in the cache.
    ///
    /// Returns `CapCheckResult::Rejected` on hard-cap breach,
    /// `CapCheckResult::AllowedWithWarning` on soft-cap or 80 % threshold
    /// breach, otherwise `CapCheckResult::Allowed`.
    pub async fn check_budget_caps(
        &self,
        tenant_id: TenantId,
        agent_id: Option<&str>,
    ) -> CapCheckResult {
        let caps = self.resolve_budget_caps(agent_id);
        if caps.is_empty() {
            return CapCheckResult::Allowed;
        }

        let agent_key = agent_id.unwrap_or("_default");
        let mut warnings: Vec<String> = Vec::new();

        for cap in &caps {
            let period_key = build_period_key(tenant_id, agent_key, cap.window);
            let current_spend = self.get_spend(&period_key).await;
            let resets_in = seconds_until_period_reset(cap.window);

            // Hard cap check
            if current_spend >= cap.hard_limit_usd {
                return CapCheckResult::Rejected {
                    window: cap.window,
                    current_spend_usd: current_spend,
                    hard_limit_usd: cap.hard_limit_usd,
                    retry_after_secs: resets_in,
                };
            }

            // Soft cap check
            if let Some(soft) = cap.soft_limit_usd {
                if current_spend >= soft {
                    warnings.push(format!(
                        "{} soft cap exceeded: ${:.4} / ${:.2}",
                        cap.window, current_spend, soft,
                    ));
                }
            }

            // 80% threshold warning
            let threshold = cap.hard_limit_usd * 0.8;
            if current_spend >= threshold && cap.soft_limit_usd.is_none_or(|s| current_spend < s) {
                warnings.push(format!(
                    "{} budget at {:.1}%: ${:.4} / ${:.2}",
                    cap.window,
                    (current_spend / cap.hard_limit_usd) * 100.0,
                    current_spend,
                    cap.hard_limit_usd,
                ));
            }
        }

        if warnings.is_empty() {
            CapCheckResult::Allowed
        } else {
            CapCheckResult::AllowedWithWarning { warnings }
        }
    }

    /// Record spend after a successful upstream response.
    ///
    /// Adds `cost_usd` to the running total for each configured budget
    /// window. This is intended to be called asynchronously from the
    /// background trace-capture task.
    pub async fn record_spend(&self, tenant_id: TenantId, agent_id: Option<&str>, cost_usd: f64) {
        if cost_usd <= 0.0 {
            return;
        }
        let agent_key = agent_id.unwrap_or("_default");
        let caps = self.resolve_budget_caps(agent_id);

        for cap in &caps {
            let period_key = build_period_key(tenant_id, agent_key, cap.window);
            let current = self.get_spend(&period_key).await;
            let new_total = current + cost_usd;

            let ttl = cap.window.cache_ttl();
            let bytes = new_total.to_le_bytes();
            if let Err(e) = self.cache.set(&period_key, &bytes, ttl).await {
                warn!(
                    %period_key,
                    "Failed to record spend in cache: {e}"
                );
            } else {
                debug!(
                    %period_key,
                    cost_usd,
                    new_total,
                    "Spend recorded"
                );
            }
        }
    }

    /// Get the current spend snapshot for the visibility API.
    pub async fn current_spend(
        &self,
        tenant_id: TenantId,
        agent_id: Option<&str>,
    ) -> SpendSnapshot {
        let caps = self.resolve_budget_caps(agent_id);
        let agent_key = agent_id.unwrap_or("_default");

        let mut windows = Vec::with_capacity(caps.len());
        for cap in &caps {
            let period_key = build_period_key(tenant_id, agent_key, cap.window);
            let current = self.get_spend(&period_key).await;
            let utilization = if cap.hard_limit_usd > 0.0 {
                (current / cap.hard_limit_usd) * 100.0
            } else {
                0.0
            };
            windows.push(WindowSpend {
                window: cap.window,
                current_spend_usd: current,
                hard_limit_usd: cap.hard_limit_usd,
                soft_limit_usd: cap.soft_limit_usd,
                utilization_pct: utilization,
                resets_in_secs: seconds_until_period_reset(cap.window),
            });
        }

        SpendSnapshot {
            tenant_id: tenant_id.to_string(),
            agent_id: agent_key.to_string(),
            windows,
        }
    }

    // -- private helpers ---------------------------------------------------

    /// Resolve the effective budget caps: agent override if present, else defaults.
    fn resolve_budget_caps(&self, agent_id: Option<&str>) -> Vec<BudgetCap> {
        if let Some(aid) = agent_id {
            if let Some(agent_cap) = self.find_agent_cap(aid) {
                if !agent_cap.budget_caps.is_empty() {
                    return agent_cap.budget_caps.clone();
                }
            }
        }
        self.config.default_budget_caps.clone()
    }

    /// Resolve the effective token cap: agent override if present, else default.
    fn resolve_token_cap(&self, agent_id: Option<&str>) -> Option<TokenCap> {
        if let Some(aid) = agent_id {
            if let Some(agent_cap) = self.find_agent_cap(aid) {
                if agent_cap.token_cap.is_some() {
                    return agent_cap.token_cap.clone();
                }
            }
        }
        self.config.default_token_cap.clone()
    }

    /// Find the agent-specific cap config.
    fn find_agent_cap(&self, agent_id: &str) -> Option<&AgentCostCap> {
        self.config.agents.iter().find(|a| a.agent_id == agent_id)
    }

    /// Read the current spend from cache, returning 0.0 on miss or error.
    async fn get_spend(&self, key: &str) -> f64 {
        match self.cache.get(key).await {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                f64::from_le_bytes(bytes.try_into().unwrap_or([0u8; 8]))
            }
            Ok(_) => 0.0,
            Err(e) => {
                warn!(%key, "Failed to read spend from cache: {e}");
                0.0
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Period key helpers
// ---------------------------------------------------------------------------

/// Build a cache key for a spend period.
///
/// Format: `cost:{tenant_id}:{agent_key}:{window}:{period_start_epoch}`
#[must_use]
pub fn build_period_key(tenant_id: TenantId, agent_key: &str, window: BudgetWindow) -> String {
    let period_start = current_period_start(window);
    format!("cost:{tenant_id}:{agent_key}:{window}:{period_start}")
}

/// Compute the epoch timestamp for the start of the current period.
#[must_use]
pub fn current_period_start(window: BudgetWindow) -> u64 {
    let now = Utc::now().timestamp() as u64;
    let duration = window.duration_secs();
    // Align to period boundaries (epoch-aligned)
    (now / duration) * duration
}

/// Seconds remaining until the current period resets.
#[must_use]
pub fn seconds_until_period_reset(window: BudgetWindow) -> u64 {
    let now = Utc::now().timestamp() as u64;
    let duration = window.duration_secs();
    let period_start = (now / duration) * duration;
    let period_end = period_start + duration;
    period_end - now
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::{BudgetCap, BudgetWindow, CostCapConfig, TokenCap};
    use llmtrace_storage::InMemoryCacheLayer;

    fn make_cache() -> Arc<dyn CacheLayer> {
        Arc::new(InMemoryCacheLayer::new())
    }

    fn enabled_config() -> CostCapConfig {
        CostCapConfig {
            enabled: true,
            default_budget_caps: vec![
                BudgetCap {
                    window: BudgetWindow::Hourly,
                    hard_limit_usd: 10.0,
                    soft_limit_usd: Some(8.0),
                },
                BudgetCap {
                    window: BudgetWindow::Daily,
                    hard_limit_usd: 100.0,
                    soft_limit_usd: None,
                },
            ],
            default_token_cap: Some(TokenCap {
                max_prompt_tokens: Some(4096),
                max_completion_tokens: Some(4096),
                max_total_tokens: Some(8192),
            }),
            agents: vec![AgentCostCap {
                agent_id: "premium-agent".to_string(),
                budget_caps: vec![BudgetCap {
                    window: BudgetWindow::Daily,
                    hard_limit_usd: 500.0,
                    soft_limit_usd: Some(400.0),
                }],
                token_cap: Some(TokenCap {
                    max_prompt_tokens: Some(16384),
                    max_completion_tokens: None,
                    max_total_tokens: None,
                }),
            }],
        }
    }

    // -- constructor -------------------------------------------------------

    #[test]
    fn test_disabled_config_returns_none() {
        let cache = make_cache();
        assert!(CostTracker::new(&CostCapConfig::default(), cache).is_none());
    }

    #[test]
    fn test_enabled_config_returns_tracker() {
        let cache = make_cache();
        assert!(CostTracker::new(&enabled_config(), cache).is_some());
    }

    // -- period key --------------------------------------------------------

    #[test]
    fn test_period_key_format() {
        let tid = TenantId::new();
        let key = build_period_key(tid, "_default", BudgetWindow::Hourly);
        assert!(key.starts_with("cost:"));
        assert!(key.contains("_default"));
        assert!(key.contains("hourly"));
    }

    #[test]
    fn test_period_start_is_aligned() {
        let start = current_period_start(BudgetWindow::Hourly);
        assert_eq!(start % 3600, 0);
    }

    #[test]
    fn test_seconds_until_reset_within_window() {
        let remaining = seconds_until_period_reset(BudgetWindow::Hourly);
        assert!(remaining > 0);
        assert!(remaining <= 3600);
    }

    // -- token cap enforcement ---------------------------------------------

    #[test]
    fn test_token_cap_allowed_when_within_limits() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        let result = tracker.check_token_caps(None, Some(1000), Some(500), Some(1500));
        assert!(matches!(result, CapCheckResult::Allowed));
    }

    #[test]
    fn test_token_cap_prompt_exceeded() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        let result = tracker.check_token_caps(None, Some(5000), None, None);
        assert!(matches!(result, CapCheckResult::TokenCapExceeded { .. }));
        if let CapCheckResult::TokenCapExceeded { reason } = result {
            assert!(reason.contains("Prompt tokens"));
            assert!(reason.contains("5000"));
        }
    }

    #[test]
    fn test_token_cap_completion_exceeded() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        let result = tracker.check_token_caps(None, None, Some(5000), None);
        assert!(matches!(result, CapCheckResult::TokenCapExceeded { .. }));
    }

    #[test]
    fn test_token_cap_total_exceeded() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        let result = tracker.check_token_caps(None, None, None, Some(9000));
        assert!(matches!(result, CapCheckResult::TokenCapExceeded { .. }));
    }

    #[test]
    fn test_token_cap_none_tokens_always_allowed() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        let result = tracker.check_token_caps(None, None, None, None);
        assert!(matches!(result, CapCheckResult::Allowed));
    }

    #[test]
    fn test_token_cap_no_cap_configured() {
        let config = CostCapConfig {
            enabled: true,
            default_token_cap: None,
            ..CostCapConfig::default()
        };
        let tracker = CostTracker::new(&config, make_cache()).unwrap();
        let result = tracker.check_token_caps(None, Some(999999), Some(999999), Some(999999));
        assert!(matches!(result, CapCheckResult::Allowed));
    }

    #[test]
    fn test_token_cap_agent_override() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        // Premium agent has max_prompt=16384, no completion or total cap
        let result =
            tracker.check_token_caps(Some("premium-agent"), Some(10000), Some(999999), None);
        assert!(matches!(result, CapCheckResult::Allowed));
    }

    #[test]
    fn test_token_cap_agent_prompt_exceeded() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        let result = tracker.check_token_caps(Some("premium-agent"), Some(20000), None, None);
        assert!(matches!(result, CapCheckResult::TokenCapExceeded { .. }));
    }

    #[test]
    fn test_token_cap_unknown_agent_uses_defaults() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        // Unknown agent should use default caps (4096 prompt)
        let result = tracker.check_token_caps(Some("unknown-agent"), Some(5000), None, None);
        assert!(matches!(result, CapCheckResult::TokenCapExceeded { .. }));
    }

    // -- budget cap enforcement --------------------------------------------

    #[tokio::test]
    async fn test_budget_allowed_when_no_spend() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        let tid = TenantId::new();
        let result = tracker.check_budget_caps(tid, None).await;
        assert!(matches!(result, CapCheckResult::Allowed));
    }

    #[tokio::test]
    async fn test_budget_rejected_on_hard_cap() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        // Seed spend above the hourly hard cap ($10)
        tracker.record_spend(tid, None, 10.5).await;

        let result = tracker.check_budget_caps(tid, None).await;
        assert!(matches!(result, CapCheckResult::Rejected { .. }));
        if let CapCheckResult::Rejected {
            window,
            current_spend_usd,
            hard_limit_usd,
            retry_after_secs,
        } = result
        {
            assert_eq!(window, BudgetWindow::Hourly);
            assert!(current_spend_usd >= 10.0);
            assert!((hard_limit_usd - 10.0).abs() < f64::EPSILON);
            assert!(retry_after_secs > 0);
        }
    }

    #[tokio::test]
    async fn test_budget_soft_cap_warning() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        // Spend $8.5 — above soft cap ($8) but below hard cap ($10)
        tracker.record_spend(tid, None, 8.5).await;

        let result = tracker.check_budget_caps(tid, None).await;
        assert!(
            matches!(result, CapCheckResult::AllowedWithWarning { .. }),
            "Expected AllowedWithWarning, got {:?}",
            result
        );
        if let CapCheckResult::AllowedWithWarning { warnings } = result {
            assert!(!warnings.is_empty());
            assert!(warnings[0].contains("soft cap exceeded"));
        }
    }

    #[tokio::test]
    async fn test_budget_80_percent_warning() {
        let cache = make_cache();
        // Config with no soft cap so only 80% threshold fires
        let config = CostCapConfig {
            enabled: true,
            default_budget_caps: vec![BudgetCap {
                window: BudgetWindow::Hourly,
                hard_limit_usd: 10.0,
                soft_limit_usd: None,
            }],
            default_token_cap: None,
            agents: Vec::new(),
        };
        let tracker = CostTracker::new(&config, Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        // Spend $8.5 — above 80% ($8) but below hard cap ($10)
        tracker.record_spend(tid, None, 8.5).await;

        let result = tracker.check_budget_caps(tid, None).await;
        assert!(matches!(result, CapCheckResult::AllowedWithWarning { .. }));
        if let CapCheckResult::AllowedWithWarning { warnings } = result {
            assert!(warnings[0].contains("85.0%"));
        }
    }

    #[tokio::test]
    async fn test_budget_agent_override_caps() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        // Premium agent has daily cap $500. Spend $200 — should be fine.
        tracker
            .record_spend(tid, Some("premium-agent"), 200.0)
            .await;

        let result = tracker.check_budget_caps(tid, Some("premium-agent")).await;
        assert!(matches!(result, CapCheckResult::Allowed));
    }

    #[tokio::test]
    async fn test_budget_agent_hard_cap_rejected() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        // Premium agent daily hard cap = $500
        tracker
            .record_spend(tid, Some("premium-agent"), 550.0)
            .await;

        let result = tracker.check_budget_caps(tid, Some("premium-agent")).await;
        assert!(matches!(result, CapCheckResult::Rejected { .. }));
    }

    // -- spend recording ---------------------------------------------------

    #[tokio::test]
    async fn test_record_spend_accumulates() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        tracker.record_spend(tid, None, 1.0).await;
        tracker.record_spend(tid, None, 2.5).await;

        let snapshot = tracker.current_spend(tid, None).await;
        // Hourly window
        let hourly = snapshot
            .windows
            .iter()
            .find(|w| w.window == BudgetWindow::Hourly)
            .unwrap();
        assert!((hourly.current_spend_usd - 3.5).abs() < 1e-6);
    }

    #[tokio::test]
    async fn test_record_spend_zero_ignored() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        tracker.record_spend(tid, None, 0.0).await;
        tracker.record_spend(tid, None, -5.0).await;

        let snapshot = tracker.current_spend(tid, None).await;
        let hourly = snapshot
            .windows
            .iter()
            .find(|w| w.window == BudgetWindow::Hourly)
            .unwrap();
        assert!((hourly.current_spend_usd).abs() < 1e-10);
    }

    // -- visibility API (current_spend) ------------------------------------

    #[tokio::test]
    async fn test_current_spend_empty() {
        let tracker = CostTracker::new(&enabled_config(), make_cache()).unwrap();
        let tid = TenantId::new();
        let snapshot = tracker.current_spend(tid, None).await;

        assert_eq!(snapshot.agent_id, "_default");
        assert_eq!(snapshot.windows.len(), 2); // hourly + daily
        for w in &snapshot.windows {
            assert!((w.current_spend_usd).abs() < 1e-10);
            assert!((w.utilization_pct).abs() < 1e-10);
            assert!(w.resets_in_secs > 0);
        }
    }

    #[tokio::test]
    async fn test_current_spend_with_data() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        tracker.record_spend(tid, None, 5.0).await;

        let snapshot = tracker.current_spend(tid, None).await;
        let hourly = snapshot
            .windows
            .iter()
            .find(|w| w.window == BudgetWindow::Hourly)
            .unwrap();
        assert!((hourly.current_spend_usd - 5.0).abs() < 1e-6);
        assert!((hourly.utilization_pct - 50.0).abs() < 1e-6);
        assert!((hourly.hard_limit_usd - 10.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_current_spend_agent() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        tracker
            .record_spend(tid, Some("premium-agent"), 100.0)
            .await;

        let snapshot = tracker.current_spend(tid, Some("premium-agent")).await;
        assert_eq!(snapshot.agent_id, "premium-agent");
        assert_eq!(snapshot.windows.len(), 1); // only daily for premium-agent
        assert!((snapshot.windows[0].current_spend_usd - 100.0).abs() < 1e-6);
    }

    // -- tenant isolation --------------------------------------------------

    #[tokio::test]
    async fn test_spend_isolated_between_tenants() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid1 = TenantId::new();
        let tid2 = TenantId::new();

        tracker.record_spend(tid1, None, 5.0).await;

        let snap1 = tracker.current_spend(tid1, None).await;
        let snap2 = tracker.current_spend(tid2, None).await;

        let h1 = snap1
            .windows
            .iter()
            .find(|w| w.window == BudgetWindow::Hourly)
            .unwrap();
        let h2 = snap2
            .windows
            .iter()
            .find(|w| w.window == BudgetWindow::Hourly)
            .unwrap();
        assert!((h1.current_spend_usd - 5.0).abs() < 1e-6);
        assert!((h2.current_spend_usd).abs() < 1e-10);
    }

    #[tokio::test]
    async fn test_spend_isolated_between_agents() {
        let cache = make_cache();
        let tracker = CostTracker::new(&enabled_config(), Arc::clone(&cache)).unwrap();
        let tid = TenantId::new();

        tracker.record_spend(tid, Some("agent-a"), 5.0).await;
        tracker.record_spend(tid, Some("agent-b"), 3.0).await;

        let snap_a = tracker.current_spend(tid, Some("agent-a")).await;
        let snap_b = tracker.current_spend(tid, Some("agent-b")).await;

        // Both use default caps (agent-a and agent-b are not in config)
        let h_a = snap_a
            .windows
            .iter()
            .find(|w| w.window == BudgetWindow::Hourly)
            .unwrap();
        let h_b = snap_b
            .windows
            .iter()
            .find(|w| w.window == BudgetWindow::Hourly)
            .unwrap();
        assert!((h_a.current_spend_usd - 5.0).abs() < 1e-6);
        assert!((h_b.current_spend_usd - 3.0).abs() < 1e-6);
    }

    // -- no budget caps configured -----------------------------------------

    #[tokio::test]
    async fn test_no_budget_caps_always_allowed() {
        let config = CostCapConfig {
            enabled: true,
            default_budget_caps: Vec::new(),
            default_token_cap: None,
            agents: Vec::new(),
        };
        let tracker = CostTracker::new(&config, make_cache()).unwrap();
        let tid = TenantId::new();
        let result = tracker.check_budget_caps(tid, None).await;
        assert!(matches!(result, CapCheckResult::Allowed));
    }
}
