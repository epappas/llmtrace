//! Action-selector policy enforcement and context minimization.
//!
//! Implements two patterns from "Design Patterns for Securing LLM Agents"
//! (IBM/EPFL/ETH/Google/Microsoft):
//!
//! 1. **Action-Selector Pattern** — enforce that agents can only invoke tools
//!    from a predefined allowlist. Any tool call not on the list is blocked.
//! 2. **Context-Minimization Pattern** — strip unnecessary context from
//!    requests to reduce attack surface.
//!
//! The [`PolicyEngine`] orchestrates multiple [`ActionPolicy`] instances and
//! a [`ContextMinimizer`], producing [`PolicyDecision`]s with attached
//! [`SecurityFinding`]s.
//!
//! # Example
//!
//! ```
//! use llmtrace_security::action_policy::{ActionPolicy, PolicyEngine, ContextMinimizer, Message};
//! use llmtrace_core::{AgentAction, AgentActionType};
//!
//! let mut engine = PolicyEngine::new();
//! engine.add_policy(ActionPolicy::restrictive("prod", "Production Policy"));
//!
//! let action = AgentAction::new(AgentActionType::ToolCall, "unknown_tool".to_string());
//! let decision = engine.evaluate_action(&action, None, "session-1");
//! assert!(decision.is_denied());
//!
//! let messages = vec![
//!     Message::new("system", "You are helpful."),
//!     Message::new("user", "Hello"),
//! ];
//! let minimized = engine.minimize_context(&messages);
//! assert!(!minimized.is_empty());
//! ```

use crate::tool_registry::ToolDefinition;
use llmtrace_core::{AgentAction, AgentActionType, SecurityFinding, SecuritySeverity};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// EnforcementMode
// ---------------------------------------------------------------------------

/// Enforcement mode for action policies.
///
/// Controls whether violations are logged, blocked, or handled adaptively
/// based on risk level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Log violations but allow all actions.
    Audit,
    /// Block violations and return a deny decision.
    Enforce,
    /// Block only high-risk violations, warn on others.
    Adaptive,
}

impl fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit => write!(f, "audit"),
            Self::Enforce => write!(f, "enforce"),
            Self::Adaptive => write!(f, "adaptive"),
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyVerdict
// ---------------------------------------------------------------------------

/// Verdict from a single policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// Action is allowed.
    Allow,
    /// Action is denied with a reason.
    Deny(String),
    /// Action is allowed but with a warning.
    Warn(String),
}

impl fmt::Display for PolicyVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny(reason) => write!(f, "deny: {}", reason),
            Self::Warn(reason) => write!(f, "warn: {}", reason),
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyDecision
// ---------------------------------------------------------------------------

/// Full decision from policy evaluation, including verdict and findings.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The overall verdict.
    pub verdict: PolicyVerdict,
    /// Security findings produced during evaluation.
    pub findings: Vec<SecurityFinding>,
    /// Which policy ID produced the decision (empty if from the engine).
    pub policy_id: String,
}

impl PolicyDecision {
    /// Create an allow decision with no findings.
    pub fn allow() -> Self {
        Self {
            verdict: PolicyVerdict::Allow,
            findings: Vec::new(),
            policy_id: String::new(),
        }
    }

    /// Create a deny decision with a reason and findings.
    pub fn deny(reason: String, findings: Vec<SecurityFinding>, policy_id: String) -> Self {
        Self {
            verdict: PolicyVerdict::Deny(reason),
            findings,
            policy_id,
        }
    }

    /// Create a warn decision with a reason and findings.
    pub fn warn(reason: String, findings: Vec<SecurityFinding>, policy_id: String) -> Self {
        Self {
            verdict: PolicyVerdict::Warn(reason),
            findings,
            policy_id,
        }
    }

    /// Returns `true` if the verdict is [`PolicyVerdict::Allow`].
    pub fn is_allowed(&self) -> bool {
        matches!(self.verdict, PolicyVerdict::Allow)
    }

    /// Returns `true` if the verdict is [`PolicyVerdict::Deny`].
    pub fn is_denied(&self) -> bool {
        matches!(self.verdict, PolicyVerdict::Deny(_))
    }

    /// Returns `true` if the verdict is [`PolicyVerdict::Warn`].
    pub fn is_warned(&self) -> bool {
        matches!(self.verdict, PolicyVerdict::Warn(_))
    }
}

// ---------------------------------------------------------------------------
// ActionPolicy
// ---------------------------------------------------------------------------

/// Policy for controlling which actions an agent can take.
///
/// Combines allowlist/blocklist enforcement, risk score thresholds, action
/// type filtering, and session-level rate limiting into a single evaluable
/// policy.
///
/// Use the builder methods to configure, or the convenience constructors
/// [`ActionPolicy::permissive`] and [`ActionPolicy::restrictive`].
#[derive(Debug, Clone)]
pub struct ActionPolicy {
    /// Policy identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Enforcement mode.
    pub mode: EnforcementMode,
    /// Allowed tool IDs (if set, only these tools are permitted).
    pub allowed_tools: Option<HashSet<String>>,
    /// Blocked tool IDs (these tools are always denied).
    pub blocked_tools: HashSet<String>,
    /// Maximum risk score allowed (tools with higher risk are blocked).
    pub max_risk_score: f64,
    /// Allowed action types (if set, only these types are permitted).
    pub allowed_action_types: Option<HashSet<AgentActionType>>,
    /// Maximum total actions per session.
    pub max_actions_per_session: Option<u32>,
    /// Whether to allow actions on unregistered tools.
    pub allow_unregistered: bool,
}

impl ActionPolicy {
    /// Create a new action policy with sensible defaults.
    ///
    /// Defaults: enforce mode, no allowlist, no blocklist, max risk 1.0,
    /// all action types allowed, no session limit, unregistered tools allowed.
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            mode: EnforcementMode::Enforce,
            allowed_tools: None,
            blocked_tools: HashSet::new(),
            max_risk_score: 1.0,
            allowed_action_types: None,
            max_actions_per_session: None,
            allow_unregistered: true,
        }
    }

    /// Create a permissive policy that allows everything in audit mode.
    ///
    /// All actions are allowed; violations are only logged as findings.
    pub fn permissive(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            mode: EnforcementMode::Audit,
            allowed_tools: None,
            blocked_tools: HashSet::new(),
            max_risk_score: 1.0,
            allowed_action_types: None,
            max_actions_per_session: None,
            allow_unregistered: true,
        }
    }

    /// Create a restrictive policy that denies by default.
    ///
    /// Requires explicit allowlist, blocks unregistered tools, and enforces
    /// a conservative risk threshold of 0.7.
    pub fn restrictive(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            mode: EnforcementMode::Enforce,
            allowed_tools: Some(HashSet::new()),
            blocked_tools: HashSet::new(),
            max_risk_score: 0.7,
            allowed_action_types: None,
            max_actions_per_session: None,
            allow_unregistered: false,
        }
    }

    /// Set the enforcement mode.
    pub fn with_mode(mut self, mode: EnforcementMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the allowed tool IDs. Only these tools will be permitted.
    pub fn with_allowed_tools(mut self, tools: HashSet<String>) -> Self {
        self.allowed_tools = Some(tools);
        self
    }

    /// Set the blocked tool IDs. These tools are always denied.
    pub fn with_blocked_tools(mut self, tools: HashSet<String>) -> Self {
        self.blocked_tools = tools;
        self
    }

    /// Set the maximum risk score allowed.
    pub fn with_max_risk_score(mut self, score: f64) -> Self {
        self.max_risk_score = score.clamp(0.0, 1.0);
        self
    }

    /// Set the allowed action types.
    pub fn with_allowed_action_types(mut self, types: HashSet<AgentActionType>) -> Self {
        self.allowed_action_types = Some(types);
        self
    }

    /// Set the maximum actions per session.
    pub fn with_max_actions_per_session(mut self, max: u32) -> Self {
        self.max_actions_per_session = Some(max);
        self
    }

    /// Set whether unregistered tools are allowed.
    pub fn with_allow_unregistered(mut self, allow: bool) -> Self {
        self.allow_unregistered = allow;
        self
    }

    /// Evaluate an action against this policy.
    ///
    /// Returns a [`PolicyDecision`] indicating whether the action is allowed,
    /// denied, or warned, along with any [`SecurityFinding`]s.
    pub fn evaluate(
        &self,
        action: &AgentAction,
        tool_def: Option<&ToolDefinition>,
    ) -> PolicyDecision {
        let mut findings = Vec::new();
        let mut violations: Vec<String> = Vec::new();

        // 1. Check action type allowlist
        if let Some(ref allowed_types) = self.allowed_action_types {
            if !allowed_types.contains(&action.action_type) {
                let reason = format!("Action type '{}' not in allowed types", action.action_type);
                violations.push(reason.clone());
                findings.push(self.make_finding(
                    SecuritySeverity::High,
                    "action_type_blocked",
                    &reason,
                    &action.name,
                ));
            }
        }

        // 2. Check blocklist
        if self.blocked_tools.contains(&action.name) {
            let reason = format!("Tool '{}' is on the blocklist", action.name);
            violations.push(reason.clone());
            findings.push(self.make_finding(
                SecuritySeverity::High,
                "tool_blocked",
                &reason,
                &action.name,
            ));
        }

        // 3. Check allowlist (only for tool calls and skill invocations)
        if let Some(ref allowed) = self.allowed_tools {
            let is_tool_like = action.action_type == AgentActionType::ToolCall
                || action.action_type == AgentActionType::SkillInvocation;
            if is_tool_like && !allowed.contains(&action.name) {
                let reason = format!("Tool '{}' not in allowlist", action.name);
                violations.push(reason.clone());
                findings.push(self.make_finding(
                    SecuritySeverity::High,
                    "tool_not_allowed",
                    &reason,
                    &action.name,
                ));
            }
        }

        // 4. Check unregistered tool
        if !self.allow_unregistered && tool_def.is_none() {
            let is_tool_like = action.action_type == AgentActionType::ToolCall
                || action.action_type == AgentActionType::SkillInvocation;
            if is_tool_like {
                let reason = format!("Unregistered tool '{}' not allowed", action.name);
                violations.push(reason.clone());
                findings.push(self.make_finding(
                    SecuritySeverity::High,
                    "unregistered_tool_blocked",
                    &reason,
                    &action.name,
                ));
            }
        }

        // 5. Check risk score
        if let Some(tool) = tool_def {
            if tool.risk_score > self.max_risk_score {
                let reason = format!(
                    "Tool '{}' risk score {:.2} exceeds max {:.2}",
                    action.name, tool.risk_score, self.max_risk_score
                );
                violations.push(reason.clone());
                findings.push(self.make_finding(
                    SecuritySeverity::High,
                    "risk_score_exceeded",
                    &reason,
                    &action.name,
                ));
            }
        }

        // Apply enforcement mode
        if violations.is_empty() {
            PolicyDecision {
                verdict: PolicyVerdict::Allow,
                findings,
                policy_id: self.id.clone(),
            }
        } else {
            let combined_reason = violations.join("; ");
            match self.mode {
                EnforcementMode::Audit => {
                    // Log but allow
                    PolicyDecision {
                        verdict: PolicyVerdict::Warn(combined_reason),
                        findings,
                        policy_id: self.id.clone(),
                    }
                }
                EnforcementMode::Enforce => PolicyDecision {
                    verdict: PolicyVerdict::Deny(combined_reason),
                    findings,
                    policy_id: self.id.clone(),
                },
                EnforcementMode::Adaptive => {
                    // Block if any finding is High or Critical, warn otherwise
                    let has_high = findings
                        .iter()
                        .any(|f| f.severity >= SecuritySeverity::High);
                    if has_high {
                        PolicyDecision {
                            verdict: PolicyVerdict::Deny(combined_reason),
                            findings,
                            policy_id: self.id.clone(),
                        }
                    } else {
                        PolicyDecision {
                            verdict: PolicyVerdict::Warn(combined_reason),
                            findings,
                            policy_id: self.id.clone(),
                        }
                    }
                }
            }
        }
    }

    /// Create a security finding for a policy violation.
    fn make_finding(
        &self,
        severity: SecuritySeverity,
        finding_type: &str,
        description: &str,
        tool_name: &str,
    ) -> SecurityFinding {
        SecurityFinding::new(
            severity,
            format!("policy_{}", finding_type),
            format!("[{}] {}", self.name, description),
            0.95,
        )
        .with_location("action_policy".to_string())
        .with_metadata("policy_id".to_string(), self.id.clone())
        .with_metadata("policy_name".to_string(), self.name.clone())
        .with_metadata("tool_name".to_string(), tool_name.to_string())
        .with_metadata("enforcement_mode".to_string(), self.mode.to_string())
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// A simple message with a role and content, used for context minimization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Message role (e.g., `"system"`, `"user"`, `"assistant"`, `"tool"`).
    pub role: String,
    /// Message content.
    pub content: String,
}

impl Message {
    /// Create a new message.
    pub fn new(role: &str, content: &str) -> Self {
        Self {
            role: role.to_string(),
            content: content.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// ContextMinimizer
// ---------------------------------------------------------------------------

/// Strips unnecessary context from LLM request messages to reduce attack surface.
///
/// Implements the context-minimization pattern: only the minimum necessary
/// context is forwarded to the LLM, reducing the window for prompt injection
/// attacks embedded in prior conversation turns.
pub struct ContextMinimizer {
    /// Maximum number of conversation turns to keep.
    pub max_turns: usize,
    /// Whether to strip system prompts from forwarded tool contexts.
    pub strip_system_prompts: bool,
    /// Whether to strip prior tool results from context.
    pub strip_prior_tool_results: bool,
    /// Maximum total context characters.
    pub max_context_chars: usize,
    /// Patterns to always strip (compiled regex).
    strip_patterns: Vec<Regex>,
}

impl ContextMinimizer {
    /// Create a new context minimizer with custom settings.
    pub fn new(
        max_turns: usize,
        strip_system_prompts: bool,
        strip_prior_tool_results: bool,
        max_context_chars: usize,
    ) -> Self {
        Self {
            max_turns,
            strip_system_prompts,
            strip_prior_tool_results,
            max_context_chars,
            strip_patterns: Self::default_strip_patterns(),
        }
    }

    /// Add a custom strip pattern.
    pub fn with_strip_pattern(mut self, pattern: &str) -> Self {
        if let Ok(re) = Regex::new(pattern) {
            self.strip_patterns.push(re);
        }
        self
    }

    /// Build the default set of strip patterns.
    ///
    /// These remove common injection payloads and sensitive metadata that
    /// should not be forwarded in context.
    fn default_strip_patterns() -> Vec<Regex> {
        let patterns = [
            // API keys and tokens in context
            r"(?i)(api[_\s]?key|secret[_\s]?key|auth[_\s]?token)\s*[:=]\s*\S+",
            // Bearer tokens
            r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*",
            // Connection strings
            r"(?i)(mongodb|postgres|mysql|redis)://\S+",
        ];
        patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
    }

    /// Minimize a sequence of messages according to the configured policy.
    ///
    /// Applies the following transformations in order:
    /// 1. Strip system prompts (if configured)
    /// 2. Strip tool results (if configured)
    /// 3. Keep only the last `max_turns` user/assistant pairs
    /// 4. Apply strip patterns to all remaining content
    /// 5. Truncate to `max_context_chars` total
    pub fn minimize_context(&self, messages: &[Message]) -> Vec<Message> {
        let mut result: Vec<Message> = Vec::new();

        // Phase 1: Filter by role
        for msg in messages {
            if self.strip_system_prompts && msg.role == "system" {
                continue;
            }
            if self.strip_prior_tool_results && msg.role == "tool" {
                continue;
            }
            result.push(msg.clone());
        }

        // Phase 2: Keep only the last max_turns conversation turns.
        // A "turn" is a user message followed by an assistant response.
        if result.len() > self.max_turns {
            let skip = result.len() - self.max_turns;
            result = result.into_iter().skip(skip).collect();
        }

        // Phase 3: Apply strip patterns to content
        for msg in &mut result {
            msg.content = self.minimize_text(&msg.content);
        }

        // Phase 4: Truncate to max_context_chars
        let mut total_chars: usize = 0;
        let mut truncated_result: Vec<Message> = Vec::new();
        for msg in result {
            let msg_chars = msg.content.chars().count();
            if total_chars + msg_chars > self.max_context_chars {
                let remaining = self.max_context_chars.saturating_sub(total_chars);
                if remaining > 0 {
                    let truncated_content: String = msg.content.chars().take(remaining).collect();
                    truncated_result.push(Message {
                        role: msg.role,
                        content: truncated_content,
                    });
                }
                break;
            }
            total_chars += msg_chars;
            truncated_result.push(msg);
        }

        truncated_result
    }

    /// Strip patterns from a single text string.
    pub fn minimize_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in &self.strip_patterns {
            result = pattern.replace_all(&result, "[REDACTED]").to_string();
        }
        result
    }
}

impl Default for ContextMinimizer {
    /// Create a context minimizer with sensible defaults.
    ///
    /// - Keep last 10 turns
    /// - Strip system prompts from tool contexts
    /// - Do not strip tool results by default
    /// - 50,000 character maximum
    fn default() -> Self {
        Self::new(10, true, false, 50_000)
    }
}

impl fmt::Debug for ContextMinimizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContextMinimizer")
            .field("max_turns", &self.max_turns)
            .field("strip_system_prompts", &self.strip_system_prompts)
            .field("strip_prior_tool_results", &self.strip_prior_tool_results)
            .field("max_context_chars", &self.max_context_chars)
            .field("strip_pattern_count", &self.strip_patterns.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------

/// Combines multiple [`ActionPolicy`] instances with a [`ContextMinimizer`]
/// into a single evaluation engine.
///
/// Policies are evaluated in order. The first deny verdict wins; if none
/// deny, the last warn wins; if none warn, the action is allowed. Session
/// action counters track per-session usage for rate limiting.
pub struct PolicyEngine {
    /// Named policies (evaluated in order).
    policies: Vec<ActionPolicy>,
    /// Context minimizer.
    context_minimizer: ContextMinimizer,
    /// Session action counters: session_id -> count.
    session_counters: RwLock<HashMap<String, u32>>,
}

impl PolicyEngine {
    /// Create a new policy engine with default context minimization and no policies.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            context_minimizer: ContextMinimizer::default(),
            session_counters: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new policy engine with a custom context minimizer.
    pub fn with_context_minimizer(context_minimizer: ContextMinimizer) -> Self {
        Self {
            policies: Vec::new(),
            context_minimizer,
            session_counters: RwLock::new(HashMap::new()),
        }
    }

    /// Add a policy to the engine. Policies are evaluated in insertion order.
    pub fn add_policy(&mut self, policy: ActionPolicy) {
        self.policies.push(policy);
    }

    /// Return the number of configured policies.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Evaluate an action against all configured policies.
    ///
    /// Returns a combined [`PolicyDecision`]:
    /// - First deny verdict wins (short-circuit).
    /// - If no deny, the last warn verdict is returned.
    /// - If no violations at all, allow is returned.
    ///
    /// Also checks session-level rate limits if any policy has
    /// `max_actions_per_session` configured.
    pub fn evaluate_action(
        &self,
        action: &AgentAction,
        tool_def: Option<&ToolDefinition>,
        session_id: &str,
    ) -> PolicyDecision {
        // Check session limits first
        let session_count = self.get_session_count(session_id);

        let mut all_findings: Vec<SecurityFinding> = Vec::new();
        let mut last_warn: Option<PolicyDecision> = None;

        for policy in &self.policies {
            // Check session limit for this policy
            if let Some(max) = policy.max_actions_per_session {
                if session_count >= max {
                    let reason = format!(
                        "Session '{}' exceeded max actions ({}/{})",
                        session_id, session_count, max
                    );
                    let finding = SecurityFinding::new(
                        SecuritySeverity::High,
                        "policy_session_limit_exceeded".to_string(),
                        format!("[{}] {}", policy.name, reason),
                        0.95,
                    )
                    .with_location("action_policy".to_string())
                    .with_metadata("policy_id".to_string(), policy.id.clone())
                    .with_metadata("session_id".to_string(), session_id.to_string())
                    .with_metadata("session_count".to_string(), session_count.to_string())
                    .with_metadata("max_actions".to_string(), max.to_string());

                    return match policy.mode {
                        EnforcementMode::Audit => {
                            PolicyDecision::warn(reason, vec![finding], policy.id.clone())
                        }
                        EnforcementMode::Enforce | EnforcementMode::Adaptive => {
                            PolicyDecision::deny(reason, vec![finding], policy.id.clone())
                        }
                    };
                }
            }

            let decision = policy.evaluate(action, tool_def);
            all_findings.extend(decision.findings.clone());

            match &decision.verdict {
                PolicyVerdict::Deny(_) => {
                    // First deny wins — return immediately
                    return PolicyDecision {
                        verdict: decision.verdict,
                        findings: all_findings,
                        policy_id: decision.policy_id,
                    };
                }
                PolicyVerdict::Warn(_) => {
                    last_warn = Some(decision);
                }
                PolicyVerdict::Allow => {}
            }
        }

        // If there were warnings, return the last one with all findings
        if let Some(warn) = last_warn {
            return PolicyDecision {
                verdict: warn.verdict,
                findings: all_findings,
                policy_id: warn.policy_id,
            };
        }

        // All clear
        PolicyDecision {
            verdict: PolicyVerdict::Allow,
            findings: all_findings,
            policy_id: String::new(),
        }
    }

    /// Minimize a sequence of messages using the configured context minimizer.
    pub fn minimize_context(&self, messages: &[Message]) -> Vec<Message> {
        self.context_minimizer.minimize_context(messages)
    }

    /// Record an action for a session (increment counter).
    pub fn record_action(&self, session_id: &str) {
        let mut counters = self
            .session_counters
            .write()
            .expect("session counters lock poisoned");
        let count = counters.entry(session_id.to_string()).or_insert(0);
        *count += 1;
    }

    /// Reset the action counter for a session.
    pub fn reset_session(&self, session_id: &str) {
        let mut counters = self
            .session_counters
            .write()
            .expect("session counters lock poisoned");
        counters.remove(session_id);
    }

    /// Get the current action count for a session.
    fn get_session_count(&self, session_id: &str) -> u32 {
        let counters = self
            .session_counters
            .read()
            .expect("session counters lock poisoned");
        counters.get(session_id).copied().unwrap_or(0)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("policy_count", &self.policies.len())
            .field("context_minimizer", &self.context_minimizer)
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_registry::{ToolCategory, ToolDefinition};
    use llmtrace_core::{AgentAction, AgentActionType};

    // ---------------------------------------------------------------
    // EnforcementMode
    // ---------------------------------------------------------------

    #[test]
    fn test_enforcement_mode_display() {
        assert_eq!(EnforcementMode::Audit.to_string(), "audit");
        assert_eq!(EnforcementMode::Enforce.to_string(), "enforce");
        assert_eq!(EnforcementMode::Adaptive.to_string(), "adaptive");
    }

    #[test]
    fn test_enforcement_mode_equality() {
        assert_eq!(EnforcementMode::Audit, EnforcementMode::Audit);
        assert_ne!(EnforcementMode::Audit, EnforcementMode::Enforce);
    }

    // ---------------------------------------------------------------
    // PolicyVerdict
    // ---------------------------------------------------------------

    #[test]
    fn test_policy_verdict_display() {
        assert_eq!(PolicyVerdict::Allow.to_string(), "allow");
        assert_eq!(
            PolicyVerdict::Deny("blocked".to_string()).to_string(),
            "deny: blocked"
        );
        assert_eq!(
            PolicyVerdict::Warn("caution".to_string()).to_string(),
            "warn: caution"
        );
    }

    // ---------------------------------------------------------------
    // PolicyDecision
    // ---------------------------------------------------------------

    #[test]
    fn test_policy_decision_allow() {
        let decision = PolicyDecision::allow();
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(!decision.is_warned());
        assert!(decision.findings.is_empty());
    }

    #[test]
    fn test_policy_decision_deny() {
        let decision = PolicyDecision::deny(
            "blocked".to_string(),
            vec![SecurityFinding::new(
                SecuritySeverity::High,
                "test".to_string(),
                "test".to_string(),
                0.9,
            )],
            "policy-1".to_string(),
        );
        assert!(decision.is_denied());
        assert!(!decision.is_allowed());
        assert!(!decision.is_warned());
        assert_eq!(decision.findings.len(), 1);
        assert_eq!(decision.policy_id, "policy-1");
    }

    #[test]
    fn test_policy_decision_warn() {
        let decision = PolicyDecision::warn("caution".to_string(), Vec::new(), "p1".to_string());
        assert!(decision.is_warned());
        assert!(!decision.is_allowed());
        assert!(!decision.is_denied());
    }

    // ---------------------------------------------------------------
    // ActionPolicy — constructors
    // ---------------------------------------------------------------

    #[test]
    fn test_action_policy_new() {
        let policy = ActionPolicy::new("test", "Test Policy");
        assert_eq!(policy.id, "test");
        assert_eq!(policy.name, "Test Policy");
        assert_eq!(policy.mode, EnforcementMode::Enforce);
        assert!(policy.allowed_tools.is_none());
        assert!(policy.blocked_tools.is_empty());
        assert!((policy.max_risk_score - 1.0).abs() < f64::EPSILON);
        assert!(policy.allowed_action_types.is_none());
        assert!(policy.max_actions_per_session.is_none());
        assert!(policy.allow_unregistered);
    }

    #[test]
    fn test_action_policy_permissive() {
        let policy = ActionPolicy::permissive("perm", "Permissive");
        assert_eq!(policy.mode, EnforcementMode::Audit);
        assert!(policy.allowed_tools.is_none());
        assert!(policy.allow_unregistered);
        assert!((policy.max_risk_score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_action_policy_restrictive() {
        let policy = ActionPolicy::restrictive("strict", "Strict");
        assert_eq!(policy.mode, EnforcementMode::Enforce);
        assert!(policy.allowed_tools.is_some());
        assert!(policy.allowed_tools.as_ref().unwrap().is_empty());
        assert!(!policy.allow_unregistered);
        assert!((policy.max_risk_score - 0.7).abs() < f64::EPSILON);
    }

    // ---------------------------------------------------------------
    // ActionPolicy — builder
    // ---------------------------------------------------------------

    #[test]
    fn test_action_policy_builder() {
        let mut allowed = HashSet::new();
        allowed.insert("web_search".to_string());
        allowed.insert("file_read".to_string());

        let mut blocked = HashSet::new();
        blocked.insert("shell_exec".to_string());

        let mut action_types = HashSet::new();
        action_types.insert(AgentActionType::ToolCall);

        let policy = ActionPolicy::new("custom", "Custom Policy")
            .with_mode(EnforcementMode::Adaptive)
            .with_allowed_tools(allowed.clone())
            .with_blocked_tools(blocked.clone())
            .with_max_risk_score(0.5)
            .with_allowed_action_types(action_types.clone())
            .with_max_actions_per_session(100)
            .with_allow_unregistered(false);

        assert_eq!(policy.mode, EnforcementMode::Adaptive);
        assert_eq!(policy.allowed_tools.as_ref().unwrap().len(), 2);
        assert!(policy.blocked_tools.contains("shell_exec"));
        assert!((policy.max_risk_score - 0.5).abs() < f64::EPSILON);
        assert!(policy
            .allowed_action_types
            .as_ref()
            .unwrap()
            .contains(&AgentActionType::ToolCall));
        assert_eq!(policy.max_actions_per_session, Some(100));
        assert!(!policy.allow_unregistered);
    }

    #[test]
    fn test_action_policy_max_risk_score_clamped() {
        let policy = ActionPolicy::new("t", "T").with_max_risk_score(1.5);
        assert!((policy.max_risk_score - 1.0).abs() < f64::EPSILON);

        let policy = ActionPolicy::new("t", "T").with_max_risk_score(-0.5);
        assert!(policy.max_risk_score.abs() < f64::EPSILON);
    }

    // ---------------------------------------------------------------
    // ActionPolicy — evaluate: allowlist
    // ---------------------------------------------------------------

    #[test]
    fn test_evaluate_allowlist_permits_listed_tool() {
        let mut allowed = HashSet::new();
        allowed.insert("web_search".to_string());

        let policy = ActionPolicy::new("p", "P").with_allowed_tools(allowed);
        let action = AgentAction::new(AgentActionType::ToolCall, "web_search".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_evaluate_allowlist_blocks_unlisted_tool() {
        let mut allowed = HashSet::new();
        allowed.insert("web_search".to_string());

        let policy = ActionPolicy::new("p", "P").with_allowed_tools(allowed);
        let action = AgentAction::new(AgentActionType::ToolCall, "shell_exec".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_denied());
        assert!(decision
            .findings
            .iter()
            .any(|f| f.finding_type == "policy_tool_not_allowed"));
    }

    #[test]
    fn test_evaluate_allowlist_skips_non_tool_actions() {
        let mut allowed = HashSet::new();
        allowed.insert("web_search".to_string());

        let policy = ActionPolicy::new("p", "P").with_allowed_tools(allowed);
        let action = AgentAction::new(AgentActionType::CommandExecution, "ls -la".to_string());
        let decision = policy.evaluate(&action, None);
        // CommandExecution is not a tool-like action, allowlist should not apply
        assert!(decision.is_allowed());
    }

    // ---------------------------------------------------------------
    // ActionPolicy — evaluate: blocklist
    // ---------------------------------------------------------------

    #[test]
    fn test_evaluate_blocklist_denies_blocked_tool() {
        let mut blocked = HashSet::new();
        blocked.insert("dangerous_tool".to_string());

        let policy = ActionPolicy::new("p", "P").with_blocked_tools(blocked);
        let action = AgentAction::new(AgentActionType::ToolCall, "dangerous_tool".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_denied());
        assert!(decision
            .findings
            .iter()
            .any(|f| f.finding_type == "policy_tool_blocked"));
    }

    #[test]
    fn test_evaluate_blocklist_allows_non_blocked_tool() {
        let mut blocked = HashSet::new();
        blocked.insert("dangerous_tool".to_string());

        let policy = ActionPolicy::new("p", "P").with_blocked_tools(blocked);
        let action = AgentAction::new(AgentActionType::ToolCall, "safe_tool".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_allowed());
    }

    // ---------------------------------------------------------------
    // ActionPolicy — evaluate: unregistered tools
    // ---------------------------------------------------------------

    #[test]
    fn test_evaluate_unregistered_blocked_when_not_allowed() {
        let policy = ActionPolicy::new("p", "P").with_allow_unregistered(false);
        let action = AgentAction::new(AgentActionType::ToolCall, "unknown".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_denied());
        assert!(decision
            .findings
            .iter()
            .any(|f| f.finding_type == "policy_unregistered_tool_blocked"));
    }

    #[test]
    fn test_evaluate_unregistered_allowed_when_permitted() {
        let policy = ActionPolicy::new("p", "P").with_allow_unregistered(true);
        let action = AgentAction::new(AgentActionType::ToolCall, "unknown".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_evaluate_unregistered_check_skips_non_tool_actions() {
        let policy = ActionPolicy::new("p", "P").with_allow_unregistered(false);
        let action = AgentAction::new(AgentActionType::FileAccess, "/etc/passwd".to_string());
        let decision = policy.evaluate(&action, None);
        // FileAccess is not tool-like, unregistered check should not apply
        assert!(decision.is_allowed());
    }

    // ---------------------------------------------------------------
    // ActionPolicy — evaluate: risk score
    // ---------------------------------------------------------------

    #[test]
    fn test_evaluate_risk_score_blocks_high_risk() {
        let policy = ActionPolicy::new("p", "P").with_max_risk_score(0.5);
        let tool =
            ToolDefinition::new("risky", "Risky", ToolCategory::CodeExecution).with_risk_score(0.9);
        let action = AgentAction::new(AgentActionType::ToolCall, "risky".to_string());
        let decision = policy.evaluate(&action, Some(&tool));
        assert!(decision.is_denied());
        assert!(decision
            .findings
            .iter()
            .any(|f| f.finding_type == "policy_risk_score_exceeded"));
    }

    #[test]
    fn test_evaluate_risk_score_allows_within_threshold() {
        let policy = ActionPolicy::new("p", "P").with_max_risk_score(0.5);
        let tool =
            ToolDefinition::new("safe", "Safe", ToolCategory::DataRetrieval).with_risk_score(0.3);
        let action = AgentAction::new(AgentActionType::ToolCall, "safe".to_string());
        let decision = policy.evaluate(&action, Some(&tool));
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_evaluate_risk_score_at_boundary() {
        let policy = ActionPolicy::new("p", "P").with_max_risk_score(0.5);
        let tool =
            ToolDefinition::new("border", "Border", ToolCategory::WebAccess).with_risk_score(0.5);
        let action = AgentAction::new(AgentActionType::ToolCall, "border".to_string());
        let decision = policy.evaluate(&action, Some(&tool));
        // Exactly at boundary should be allowed (not >)
        assert!(decision.is_allowed());
    }

    // ---------------------------------------------------------------
    // ActionPolicy — evaluate: action types
    // ---------------------------------------------------------------

    #[test]
    fn test_evaluate_action_type_allowed() {
        let mut types = HashSet::new();
        types.insert(AgentActionType::ToolCall);
        types.insert(AgentActionType::WebAccess);

        let policy = ActionPolicy::new("p", "P").with_allowed_action_types(types);
        let action = AgentAction::new(AgentActionType::ToolCall, "search".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_evaluate_action_type_blocked() {
        let mut types = HashSet::new();
        types.insert(AgentActionType::ToolCall);

        let policy = ActionPolicy::new("p", "P").with_allowed_action_types(types);
        let action = AgentAction::new(AgentActionType::CommandExecution, "rm -rf /".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_denied());
        assert!(decision
            .findings
            .iter()
            .any(|f| f.finding_type == "policy_action_type_blocked"));
    }

    // ---------------------------------------------------------------
    // ActionPolicy — evaluate: enforcement modes
    // ---------------------------------------------------------------

    #[test]
    fn test_evaluate_audit_mode_warns_instead_of_deny() {
        let mut blocked = HashSet::new();
        blocked.insert("bad_tool".to_string());

        let policy = ActionPolicy::new("p", "P")
            .with_mode(EnforcementMode::Audit)
            .with_blocked_tools(blocked);

        let action = AgentAction::new(AgentActionType::ToolCall, "bad_tool".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_warned());
        assert!(!decision.findings.is_empty());
    }

    #[test]
    fn test_evaluate_adaptive_mode_denies_high_risk() {
        let mut blocked = HashSet::new();
        blocked.insert("bad_tool".to_string());

        let policy = ActionPolicy::new("p", "P")
            .with_mode(EnforcementMode::Adaptive)
            .with_blocked_tools(blocked);

        let action = AgentAction::new(AgentActionType::ToolCall, "bad_tool".to_string());
        let decision = policy.evaluate(&action, None);
        // The blocklist finding is High severity, so adaptive should deny
        assert!(decision.is_denied());
    }

    #[test]
    fn test_evaluate_multiple_violations() {
        let mut blocked = HashSet::new();
        blocked.insert("shell_exec".to_string());

        let policy = ActionPolicy::new("p", "P")
            .with_blocked_tools(blocked)
            .with_max_risk_score(0.5);

        let tool = ToolDefinition::new("shell_exec", "Shell", ToolCategory::CodeExecution)
            .with_risk_score(0.9);
        let action = AgentAction::new(AgentActionType::ToolCall, "shell_exec".to_string());
        let decision = policy.evaluate(&action, Some(&tool));
        assert!(decision.is_denied());
        // Should have findings for both blocklist and risk score
        assert!(decision.findings.len() >= 2);
    }

    // ---------------------------------------------------------------
    // Message
    // ---------------------------------------------------------------

    #[test]
    fn test_message_new() {
        let msg = Message::new("user", "Hello!");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content, "Hello!");
    }

    #[test]
    fn test_message_equality() {
        let a = Message::new("user", "hi");
        let b = Message::new("user", "hi");
        assert_eq!(a, b);

        let c = Message::new("assistant", "hi");
        assert_ne!(a, c);
    }

    // ---------------------------------------------------------------
    // ContextMinimizer — defaults
    // ---------------------------------------------------------------

    #[test]
    fn test_context_minimizer_default() {
        let minimizer = ContextMinimizer::default();
        assert_eq!(minimizer.max_turns, 10);
        assert!(minimizer.strip_system_prompts);
        assert!(!minimizer.strip_prior_tool_results);
        assert_eq!(minimizer.max_context_chars, 50_000);
    }

    // ---------------------------------------------------------------
    // ContextMinimizer — minimize_context
    // ---------------------------------------------------------------

    #[test]
    fn test_minimize_strips_system_prompts() {
        let minimizer = ContextMinimizer::new(10, true, false, 50_000);
        let messages = vec![
            Message::new("system", "You are helpful."),
            Message::new("user", "Hello"),
            Message::new("assistant", "Hi there!"),
        ];
        let result = minimizer.minimize_context(&messages);
        assert!(!result.iter().any(|m| m.role == "system"));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_minimize_keeps_system_prompts_when_disabled() {
        let minimizer = ContextMinimizer::new(10, false, false, 50_000);
        let messages = vec![
            Message::new("system", "You are helpful."),
            Message::new("user", "Hello"),
        ];
        let result = minimizer.minimize_context(&messages);
        assert!(result.iter().any(|m| m.role == "system"));
    }

    #[test]
    fn test_minimize_strips_tool_results() {
        let minimizer = ContextMinimizer::new(10, false, true, 50_000);
        let messages = vec![
            Message::new("user", "Search for cats"),
            Message::new("tool", "{\"results\": [\"cat1\", \"cat2\"]}"),
            Message::new("assistant", "Here are the results."),
        ];
        let result = minimizer.minimize_context(&messages);
        assert!(!result.iter().any(|m| m.role == "tool"));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_minimize_limits_turns() {
        let minimizer = ContextMinimizer::new(3, false, false, 50_000);
        let messages = vec![
            Message::new("user", "msg1"),
            Message::new("assistant", "resp1"),
            Message::new("user", "msg2"),
            Message::new("assistant", "resp2"),
            Message::new("user", "msg3"),
        ];
        let result = minimizer.minimize_context(&messages);
        assert_eq!(result.len(), 3);
        // Should keep the last 3 messages: msg2, resp2, msg3
        assert_eq!(result[0].content, "msg2");
        assert_eq!(result[1].content, "resp2");
        assert_eq!(result[2].content, "msg3");
        // Verify the first two were dropped
        assert!(!result.iter().any(|m| m.content == "msg1"));
        assert!(!result.iter().any(|m| m.content == "resp1"));
    }

    #[test]
    fn test_minimize_truncates_to_max_chars() {
        let minimizer = ContextMinimizer::new(10, false, false, 20);
        let messages = vec![
            Message::new("user", "Hello World!"), // 12 chars
            Message::new("assistant", "This is a long response."), // 24 chars
        ];
        let result = minimizer.minimize_context(&messages);
        // First message is 12 chars, second is 24 chars, total would be 36 > 20
        assert!(result.len() <= 2);
        let total: usize = result.iter().map(|m| m.content.chars().count()).sum();
        assert!(total <= 20);
    }

    #[test]
    fn test_minimize_text_strips_api_keys() {
        let minimizer = ContextMinimizer::default();
        let text = "Use api_key=sk-abc123xyz789 for access";
        let result = minimizer.minimize_text(text);
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("sk-abc123xyz789"));
    }

    #[test]
    fn test_minimize_text_strips_bearer_tokens() {
        let minimizer = ContextMinimizer::default();
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.sig";
        let result = minimizer.minimize_text(text);
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_minimize_text_strips_connection_strings() {
        let minimizer = ContextMinimizer::default();
        let text = "connect to postgres://user:pass@host:5432/db";
        let result = minimizer.minimize_text(text);
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("postgres://"));
    }

    #[test]
    fn test_minimize_with_custom_pattern() {
        let minimizer = ContextMinimizer::default().with_strip_pattern(r"(?i)SECRET_VALUE_\w+");
        let text = "The value is SECRET_VALUE_ABC123 here";
        let result = minimizer.minimize_text(text);
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("SECRET_VALUE_ABC123"));
    }

    #[test]
    fn test_minimize_empty_messages() {
        let minimizer = ContextMinimizer::default();
        let result = minimizer.minimize_context(&[]);
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------
    // PolicyEngine — basic
    // ---------------------------------------------------------------

    #[test]
    fn test_engine_new_no_policies() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn test_engine_add_policy() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(ActionPolicy::new("p1", "Policy 1"));
        engine.add_policy(ActionPolicy::new("p2", "Policy 2"));
        assert_eq!(engine.policy_count(), 2);
    }

    #[test]
    fn test_engine_allows_when_no_policies() {
        let engine = PolicyEngine::new();
        let action = AgentAction::new(AgentActionType::ToolCall, "any_tool".to_string());
        let decision = engine.evaluate_action(&action, None, "session-1");
        assert!(decision.is_allowed());
    }

    // ---------------------------------------------------------------
    // PolicyEngine — evaluate
    // ---------------------------------------------------------------

    #[test]
    fn test_engine_first_deny_wins() {
        let mut blocked1 = HashSet::new();
        blocked1.insert("tool_a".to_string());

        let mut blocked2 = HashSet::new();
        blocked2.insert("tool_b".to_string());

        let mut engine = PolicyEngine::new();
        engine.add_policy(ActionPolicy::new("p1", "P1").with_blocked_tools(blocked1));
        engine.add_policy(ActionPolicy::new("p2", "P2").with_blocked_tools(blocked2));

        let action = AgentAction::new(AgentActionType::ToolCall, "tool_a".to_string());
        let decision = engine.evaluate_action(&action, None, "s1");
        assert!(decision.is_denied());
        assert_eq!(decision.policy_id, "p1");
    }

    #[test]
    fn test_engine_warn_returned_when_no_deny() {
        let mut blocked = HashSet::new();
        blocked.insert("tool_a".to_string());

        let mut engine = PolicyEngine::new();
        engine.add_policy(
            ActionPolicy::new("audit_p", "Audit Policy")
                .with_mode(EnforcementMode::Audit)
                .with_blocked_tools(blocked),
        );

        let action = AgentAction::new(AgentActionType::ToolCall, "tool_a".to_string());
        let decision = engine.evaluate_action(&action, None, "s1");
        assert!(decision.is_warned());
    }

    #[test]
    fn test_engine_allows_when_all_pass() {
        let mut allowed = HashSet::new();
        allowed.insert("web_search".to_string());

        let mut engine = PolicyEngine::new();
        engine.add_policy(ActionPolicy::new("p1", "P1").with_allowed_tools(allowed));

        let action = AgentAction::new(AgentActionType::ToolCall, "web_search".to_string());
        let decision = engine.evaluate_action(&action, None, "s1");
        assert!(decision.is_allowed());
    }

    // ---------------------------------------------------------------
    // PolicyEngine — session counters
    // ---------------------------------------------------------------

    #[test]
    fn test_engine_session_counter() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(ActionPolicy::new("p1", "P1").with_max_actions_per_session(3));

        engine.record_action("session-1");
        engine.record_action("session-1");
        engine.record_action("session-1");

        let action = AgentAction::new(AgentActionType::ToolCall, "tool".to_string());
        let decision = engine.evaluate_action(&action, None, "session-1");
        assert!(decision.is_denied());
        assert!(decision
            .findings
            .iter()
            .any(|f| f.finding_type == "policy_session_limit_exceeded"));
    }

    #[test]
    fn test_engine_session_counter_independent_sessions() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(ActionPolicy::new("p1", "P1").with_max_actions_per_session(2));

        engine.record_action("session-1");
        engine.record_action("session-1");

        let action = AgentAction::new(AgentActionType::ToolCall, "tool".to_string());

        // session-1 should be at limit
        let decision = engine.evaluate_action(&action, None, "session-1");
        assert!(decision.is_denied());

        // session-2 should be fine
        let decision = engine.evaluate_action(&action, None, "session-2");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_engine_reset_session() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(ActionPolicy::new("p1", "P1").with_max_actions_per_session(2));

        engine.record_action("session-1");
        engine.record_action("session-1");

        let action = AgentAction::new(AgentActionType::ToolCall, "tool".to_string());
        let decision = engine.evaluate_action(&action, None, "session-1");
        assert!(decision.is_denied());

        engine.reset_session("session-1");
        let decision = engine.evaluate_action(&action, None, "session-1");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_engine_session_limit_audit_mode() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            ActionPolicy::new("p1", "P1")
                .with_mode(EnforcementMode::Audit)
                .with_max_actions_per_session(1),
        );

        engine.record_action("s1");

        let action = AgentAction::new(AgentActionType::ToolCall, "tool".to_string());
        let decision = engine.evaluate_action(&action, None, "s1");
        // Audit mode should warn, not deny
        assert!(decision.is_warned());
    }

    // ---------------------------------------------------------------
    // PolicyEngine — minimize_context
    // ---------------------------------------------------------------

    #[test]
    fn test_engine_minimize_context() {
        let engine = PolicyEngine::new();
        let messages = vec![
            Message::new("system", "You are helpful."),
            Message::new("user", "Hello"),
            Message::new("assistant", "Hi!"),
        ];
        let result = engine.minimize_context(&messages);
        // Default minimizer strips system prompts
        assert!(!result.iter().any(|m| m.role == "system"));
    }

    #[test]
    fn test_engine_with_custom_minimizer() {
        let minimizer = ContextMinimizer::new(2, false, false, 50_000);
        let engine = PolicyEngine::with_context_minimizer(minimizer);

        let messages = vec![
            Message::new("user", "msg1"),
            Message::new("assistant", "resp1"),
            Message::new("user", "msg2"),
            Message::new("assistant", "resp2"),
        ];
        let result = engine.minimize_context(&messages);
        assert_eq!(result.len(), 2);
    }

    // ---------------------------------------------------------------
    // PolicyEngine — debug
    // ---------------------------------------------------------------

    #[test]
    fn test_engine_debug() {
        let engine = PolicyEngine::new();
        let debug = format!("{:?}", engine);
        assert!(debug.contains("PolicyEngine"));
        assert!(debug.contains("policy_count"));
    }

    // ---------------------------------------------------------------
    // PolicyEngine — default
    // ---------------------------------------------------------------

    #[test]
    fn test_engine_default() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.policy_count(), 0);
    }

    // ---------------------------------------------------------------
    // Integration: restrictive policy + tool definition
    // ---------------------------------------------------------------

    #[test]
    fn test_integration_restrictive_with_registered_tool() {
        let mut allowed = HashSet::new();
        allowed.insert("web_search".to_string());

        let policy = ActionPolicy::restrictive("strict", "Strict").with_allowed_tools(allowed);

        let tool = ToolDefinition::new("web_search", "Web Search", ToolCategory::WebAccess)
            .with_risk_score(0.3);

        let action = AgentAction::new(AgentActionType::ToolCall, "web_search".to_string());
        let decision = policy.evaluate(&action, Some(&tool));
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_integration_restrictive_blocks_unregistered() {
        let policy = ActionPolicy::restrictive("strict", "Strict");
        let action = AgentAction::new(AgentActionType::ToolCall, "unknown_tool".to_string());
        let decision = policy.evaluate(&action, None);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_integration_restrictive_blocks_high_risk() {
        let mut allowed = HashSet::new();
        allowed.insert("shell_exec".to_string());

        let policy = ActionPolicy::restrictive("strict", "Strict").with_allowed_tools(allowed);

        let tool = ToolDefinition::new("shell_exec", "Shell", ToolCategory::CodeExecution)
            .with_risk_score(0.9);

        let action = AgentAction::new(AgentActionType::ToolCall, "shell_exec".to_string());
        let decision = policy.evaluate(&action, Some(&tool));
        // Tool is in allowlist but risk exceeds 0.7 threshold
        assert!(decision.is_denied());
        assert!(decision
            .findings
            .iter()
            .any(|f| f.finding_type == "policy_risk_score_exceeded"));
    }

    // ---------------------------------------------------------------
    // Integration: engine with multiple policies
    // ---------------------------------------------------------------

    #[test]
    fn test_integration_engine_multi_policy() {
        let mut blocked = HashSet::new();
        blocked.insert("dangerous_tool".to_string());

        let mut engine = PolicyEngine::new();
        // First policy: audit-only blocklist
        engine.add_policy(
            ActionPolicy::permissive("audit", "Audit").with_blocked_tools(blocked.clone()),
        );
        // Second policy: enforce blocklist
        engine.add_policy(ActionPolicy::new("enforce", "Enforce").with_blocked_tools(blocked));

        let action = AgentAction::new(AgentActionType::ToolCall, "dangerous_tool".to_string());
        let decision = engine.evaluate_action(&action, None, "s1");
        // Audit policy warns, enforce policy denies — deny wins
        assert!(decision.is_denied());
    }

    #[test]
    fn test_integration_full_pipeline() {
        let mut allowed = HashSet::new();
        allowed.insert("web_search".to_string());
        allowed.insert("file_read".to_string());

        let mut engine = PolicyEngine::new();
        engine.add_policy(
            ActionPolicy::new("prod", "Production")
                .with_allowed_tools(allowed)
                .with_max_risk_score(0.6)
                .with_max_actions_per_session(5)
                .with_allow_unregistered(false),
        );

        let search_tool = ToolDefinition::new("web_search", "Search", ToolCategory::WebAccess)
            .with_risk_score(0.3);

        // Allowed action
        let action = AgentAction::new(AgentActionType::ToolCall, "web_search".to_string());
        let decision = engine.evaluate_action(&action, Some(&search_tool), "session-1");
        assert!(decision.is_allowed());
        engine.record_action("session-1");

        // Blocked action (not in allowlist)
        let action = AgentAction::new(AgentActionType::ToolCall, "shell_exec".to_string());
        let decision = engine.evaluate_action(&action, None, "session-1");
        assert!(decision.is_denied());

        // Context minimization
        let messages = vec![
            Message::new("system", "Be helpful."),
            Message::new("user", "Search for cats"),
            Message::new("assistant", "Here are results."),
        ];
        let minimized = engine.minimize_context(&messages);
        assert!(!minimized.iter().any(|m| m.role == "system"));
    }

    // ---------------------------------------------------------------
    // ContextMinimizer — edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_minimize_single_message() {
        let minimizer = ContextMinimizer::default();
        let messages = vec![Message::new("user", "Hello")];
        let result = minimizer.minimize_context(&messages);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].content, "Hello");
    }

    #[test]
    fn test_minimize_preserves_order() {
        let minimizer = ContextMinimizer::new(10, false, false, 50_000);
        let messages = vec![
            Message::new("user", "first"),
            Message::new("assistant", "second"),
            Message::new("user", "third"),
        ];
        let result = minimizer.minimize_context(&messages);
        assert_eq!(result[0].content, "first");
        assert_eq!(result[1].content, "second");
        assert_eq!(result[2].content, "third");
    }

    #[test]
    fn test_minimize_zero_max_chars() {
        let minimizer = ContextMinimizer::new(10, false, false, 0);
        let messages = vec![Message::new("user", "Hello")];
        let result = minimizer.minimize_context(&messages);
        assert!(result.is_empty());
    }

    #[test]
    fn test_minimize_text_no_patterns_match() {
        let minimizer = ContextMinimizer::default();
        let text = "Just a normal message with no secrets.";
        let result = minimizer.minimize_text(text);
        assert_eq!(result, text);
    }
}
