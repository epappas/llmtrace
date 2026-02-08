//! Multi-step action correlation for cross-request attack sequence detection.
//!
//! Implements R-AS-05 from "Design Patterns for Securing LLM Agents":
//! cross-request attack sequence detection, action pattern matching,
//! and temporal correlation.
//!
//! The [`ActionCorrelator`] tracks agent actions across sessions, matches them
//! against known multi-step attack patterns (e.g. data exfiltration chains,
//! credential theft), and detects temporal anomalies like rapid-fire actions
//! and privilege escalation sequences.
//!
//! # Example
//!
//! ```
//! use llmtrace_security::action_correlator::{
//!     ActionCorrelator, TrackedAction, CorrelationConfig,
//! };
//! use llmtrace_core::AgentActionType;
//! use std::time::Instant;
//!
//! let mut correlator = ActionCorrelator::with_defaults();
//! let action = TrackedAction {
//!     action_type: AgentActionType::FileAccess,
//!     target: "/etc/passwd".to_string(),
//!     timestamp: Instant::now(),
//!     session_id: "sess-1".to_string(),
//!     risk_score: 0.8,
//! };
//! let result = correlator.record_action(action);
//! assert!(result.pattern_matches.is_empty());
//! ```

use llmtrace_core::{AgentActionType, SecurityFinding, SecuritySeverity};
use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// TrackedAction
// ---------------------------------------------------------------------------

/// A single agent action tracked for correlation analysis.
#[derive(Debug, Clone)]
pub struct TrackedAction {
    /// Type of agent action.
    pub action_type: AgentActionType,
    /// Target of the action (tool name, URL, file path, etc.).
    pub target: String,
    /// When the action occurred.
    pub timestamp: Instant,
    /// Session this action belongs to.
    pub session_id: String,
    /// Risk score assigned to this action (0.0 - 1.0).
    pub risk_score: f64,
}

// ---------------------------------------------------------------------------
// PatternStep
// ---------------------------------------------------------------------------

/// A single step in an attack pattern definition.
#[derive(Debug, Clone)]
pub struct PatternStep {
    /// Required action type (None = matches any type).
    pub action_type: Option<AgentActionType>,
    /// Regex pattern to match the target string (None = matches any target).
    pub target_pattern: Option<String>,
    /// Minimum risk score for this step (0.0 = matches any risk).
    pub min_risk: f64,
}

// ---------------------------------------------------------------------------
// AttackPattern
// ---------------------------------------------------------------------------

/// Defines a known multi-step attack sequence.
#[derive(Debug, Clone)]
pub struct AttackPattern {
    /// Unique name for this pattern.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Ordered steps that must occur to trigger the pattern.
    pub steps: Vec<PatternStep>,
    /// All steps must occur within this time window.
    pub max_time_window: Duration,
    /// Severity level when this pattern is matched.
    pub severity: SecuritySeverity,
    /// Base confidence score for a match (0.0 - 1.0).
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// CorrelationConfig
// ---------------------------------------------------------------------------

/// Configuration for the action correlator.
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Maximum number of actions to retain per session.
    pub max_history_per_session: usize,
    /// Sessions with no activity beyond this duration are eligible for cleanup.
    pub session_timeout: Duration,
    /// Attack patterns to match against.
    pub patterns: Vec<AttackPattern>,
    /// Whether temporal analysis (rapid action detection) is enabled.
    pub enable_temporal_analysis: bool,
    /// Actions arriving faster than this interval are considered suspicious.
    pub rapid_action_threshold: Duration,
    /// This many rapid actions in a row triggers an alert.
    pub rapid_action_count: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            max_history_per_session: 500,
            session_timeout: Duration::from_secs(3600),
            patterns: Vec::new(),
            enable_temporal_analysis: true,
            rapid_action_threshold: Duration::from_secs(1),
            rapid_action_count: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of correlating a newly recorded action against known patterns.
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    /// Session the action was recorded in.
    pub session_id: String,
    /// Attack patterns matched after this action.
    pub pattern_matches: Vec<PatternMatch>,
    /// Rapid-fire action alert, if triggered.
    pub rapid_actions: Option<RapidActionAlert>,
    /// Privilege escalation sequence, if detected.
    pub escalation: Option<EscalationSequence>,
    /// Aggregate risk score for this result.
    pub total_risk: f64,
}

/// A matched attack pattern with supporting evidence.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Name of the matched pattern.
    pub pattern_name: String,
    /// Indices into the session history of the actions that matched each step.
    pub matched_actions: Vec<usize>,
    /// Confidence score for this match.
    pub confidence: f64,
    /// Severity of the matched pattern.
    pub severity: SecuritySeverity,
    /// Time span between the first and last matched action.
    pub time_span: Duration,
}

/// Alert for an abnormally high rate of actions.
#[derive(Debug, Clone)]
pub struct RapidActionAlert {
    /// Number of rapid actions detected.
    pub action_count: usize,
    /// Time window over which the rapid actions occurred.
    pub time_window: Duration,
    /// Average interval between consecutive rapid actions.
    pub avg_interval: Duration,
}

/// A detected privilege escalation sequence.
#[derive(Debug, Clone)]
pub struct EscalationSequence {
    /// Steps in the escalation: (action_type, target, risk_score).
    pub steps: Vec<(AgentActionType, String, f64)>,
    /// Risk scores over time, showing upward trajectory.
    pub risk_trajectory: Vec<f64>,
}

// ---------------------------------------------------------------------------
// CompiledStep / CompiledPattern (internal)
// ---------------------------------------------------------------------------

/// A pattern step with pre-compiled regex.
#[derive(Debug)]
struct CompiledStep {
    action_type: Option<AgentActionType>,
    target_regex: Option<Regex>,
    min_risk: f64,
}

/// An attack pattern with pre-compiled regex steps.
#[derive(Debug)]
struct CompiledPattern {
    pattern: AttackPattern,
    compiled_steps: Vec<CompiledStep>,
}

// ---------------------------------------------------------------------------
// ActionCorrelator
// ---------------------------------------------------------------------------

/// Correlates agent actions across sessions to detect multi-step attack
/// sequences, rapid-fire abuse, and privilege escalation.
pub struct ActionCorrelator {
    config: CorrelationConfig,
    session_histories: HashMap<String, VecDeque<TrackedAction>>,
    compiled_patterns: Vec<CompiledPattern>,
}

impl std::fmt::Debug for ActionCorrelator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionCorrelator")
            .field("config", &self.config)
            .field("session_count", &self.session_histories.len())
            .field("pattern_count", &self.compiled_patterns.len())
            .finish()
    }
}

impl ActionCorrelator {
    /// Create a new correlator with custom configuration.
    pub fn new(config: CorrelationConfig) -> Self {
        let compiled_patterns = config
            .patterns
            .iter()
            .filter_map(|p| compile_pattern(p.clone()))
            .collect();

        Self {
            config,
            session_histories: HashMap::new(),
            compiled_patterns,
        }
    }

    /// Create a correlator with built-in default attack patterns.
    pub fn with_defaults() -> Self {
        let config = CorrelationConfig {
            patterns: default_attack_patterns(),
            ..Default::default()
        };
        Self::new(config)
    }

    /// Record an action and check for pattern matches, rapid actions,
    /// and escalation sequences.
    pub fn record_action(&mut self, action: TrackedAction) -> CorrelationResult {
        let session_id = action.session_id.clone();

        let history = self
            .session_histories
            .entry(session_id.clone())
            .or_default();
        history.push_back(action);

        // Enforce max history
        while history.len() > self.config.max_history_per_session {
            history.pop_front();
        }

        let pattern_matches = self.check_patterns(&session_id);

        let rapid_actions = if self.config.enable_temporal_analysis {
            self.detect_rapid_actions(&session_id)
        } else {
            None
        };

        let escalation = self.detect_privilege_escalation_sequence(&session_id);

        let total_risk = compute_total_risk(&pattern_matches, &rapid_actions, &escalation);

        CorrelationResult {
            session_id,
            pattern_matches,
            rapid_actions,
            escalation,
            total_risk,
        }
    }

    /// Check all compiled patterns against the given session's history.
    #[must_use]
    pub fn check_patterns(&self, session_id: &str) -> Vec<PatternMatch> {
        let history = match self.session_histories.get(session_id) {
            Some(h) if !h.is_empty() => h,
            _ => return Vec::new(),
        };

        let mut matches = Vec::new();

        for cp in &self.compiled_patterns {
            if let Some(m) = match_pattern(cp, history) {
                matches.push(m);
            }
        }

        matches
    }

    /// Detect rapid-fire actions within the configured thresholds.
    #[must_use]
    pub fn detect_rapid_actions(&self, session_id: &str) -> Option<RapidActionAlert> {
        let history = self.session_histories.get(session_id)?;

        if history.len() < self.config.rapid_action_count {
            return None;
        }

        // Look at the last `rapid_action_count` actions
        let start = history.len() - self.config.rapid_action_count;
        let window: Vec<&TrackedAction> = history.iter().skip(start).collect();

        let first_ts = window.first()?.timestamp;
        let last_ts = window.last()?.timestamp;
        let time_window = last_ts.duration_since(first_ts);

        // Check if all consecutive intervals are below the threshold
        let mut all_rapid = true;
        for pair in window.windows(2) {
            let interval = pair[1].timestamp.duration_since(pair[0].timestamp);
            if interval > self.config.rapid_action_threshold {
                all_rapid = false;
                break;
            }
        }

        if !all_rapid {
            return None;
        }

        let count = window.len();
        let avg_interval = if count > 1 {
            time_window / (count as u32 - 1)
        } else {
            Duration::ZERO
        };

        Some(RapidActionAlert {
            action_count: count,
            time_window,
            avg_interval,
        })
    }

    /// Detect a privilege escalation sequence: a series of actions
    /// with monotonically increasing risk scores (at least 3 steps,
    /// final risk >= 0.7).
    #[must_use]
    pub fn detect_privilege_escalation_sequence(
        &self,
        session_id: &str,
    ) -> Option<EscalationSequence> {
        let history = self.session_histories.get(session_id)?;

        if history.len() < 3 {
            return None;
        }

        // Find the longest suffix of increasing risk scores
        let mut escalation_steps: Vec<(AgentActionType, String, f64)> = Vec::new();
        let mut trajectory: Vec<f64> = Vec::new();

        for action in history.iter() {
            let extends = trajectory
                .last()
                .is_none_or(|&prev| action.risk_score > prev);

            if extends {
                escalation_steps.push((
                    action.action_type.clone(),
                    action.target.clone(),
                    action.risk_score,
                ));
                trajectory.push(action.risk_score);
            } else {
                // Reset the sequence
                escalation_steps.clear();
                trajectory.clear();
                escalation_steps.push((
                    action.action_type.clone(),
                    action.target.clone(),
                    action.risk_score,
                ));
                trajectory.push(action.risk_score);
            }
        }

        if escalation_steps.len() < 3 {
            return None;
        }

        let final_risk = trajectory.last().copied().unwrap_or(0.0);
        if final_risk < 0.7 {
            return None;
        }

        Some(EscalationSequence {
            steps: escalation_steps,
            risk_trajectory: trajectory,
        })
    }

    /// Remove sessions that have been inactive beyond the configured timeout.
    pub fn cleanup_expired_sessions(&mut self) {
        let timeout = self.config.session_timeout;
        let now = Instant::now();

        self.session_histories.retain(|_session_id, history| {
            match history.back() {
                Some(last_action) => now.duration_since(last_action.timestamp) < timeout,
                None => false, // empty history = remove
            }
        });
    }

    /// Number of sessions currently tracked.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.session_histories.len()
    }

    /// Convert a correlation result into security findings.
    #[must_use]
    pub fn to_security_findings(result: &CorrelationResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for pm in &result.pattern_matches {
            let finding = SecurityFinding::new(
                pm.severity.clone(),
                format!("attack_pattern_{}", pm.pattern_name),
                format!(
                    "Multi-step attack pattern '{}' matched in session '{}' \
                     ({} actions over {:.1}s, confidence {:.2})",
                    pm.pattern_name,
                    result.session_id,
                    pm.matched_actions.len(),
                    pm.time_span.as_secs_f64(),
                    pm.confidence,
                ),
                pm.confidence,
            )
            .with_location(format!("session:{}", result.session_id))
            .with_metadata("pattern_name".to_string(), pm.pattern_name.clone())
            .with_metadata(
                "matched_action_count".to_string(),
                pm.matched_actions.len().to_string(),
            )
            .with_metadata(
                "time_span_ms".to_string(),
                pm.time_span.as_millis().to_string(),
            );

            findings.push(finding);
        }

        if let Some(ref rapid) = result.rapid_actions {
            let finding = SecurityFinding::new(
                SecuritySeverity::Medium,
                "rapid_action_alert".to_string(),
                format!(
                    "Rapid-fire actions detected in session '{}': \
                     {} actions in {:.1}s (avg interval {:.0}ms)",
                    result.session_id,
                    rapid.action_count,
                    rapid.time_window.as_secs_f64(),
                    rapid.avg_interval.as_secs_f64() * 1000.0,
                ),
                0.8,
            )
            .with_location(format!("session:{}", result.session_id))
            .with_metadata("action_count".to_string(), rapid.action_count.to_string())
            .with_metadata(
                "time_window_ms".to_string(),
                rapid.time_window.as_millis().to_string(),
            );

            findings.push(finding);
        }

        if let Some(ref esc) = result.escalation {
            let finding = SecurityFinding::new(
                SecuritySeverity::High,
                "privilege_escalation_sequence".to_string(),
                format!(
                    "Privilege escalation detected in session '{}': \
                     {} steps with risk trajectory {:?}",
                    result.session_id,
                    esc.steps.len(),
                    esc.risk_trajectory,
                ),
                0.85,
            )
            .with_location(format!("session:{}", result.session_id))
            .with_metadata("step_count".to_string(), esc.steps.len().to_string())
            .with_metadata(
                "final_risk".to_string(),
                esc.risk_trajectory
                    .last()
                    .map_or("0.0".to_string(), |r| format!("{r:.2}")),
            );

            findings.push(finding);
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Pattern matching helpers
// ---------------------------------------------------------------------------

/// Compile an attack pattern's regex steps.
fn compile_pattern(pattern: AttackPattern) -> Option<CompiledPattern> {
    let mut compiled_steps = Vec::with_capacity(pattern.steps.len());

    for step in &pattern.steps {
        let target_regex = match &step.target_pattern {
            Some(pat) => Some(Regex::new(pat).ok()?),
            None => None,
        };
        compiled_steps.push(CompiledStep {
            action_type: step.action_type.clone(),
            target_regex,
            min_risk: step.min_risk,
        });
    }

    Some(CompiledPattern {
        pattern,
        compiled_steps,
    })
}

/// Check if a compiled step matches a tracked action.
fn step_matches(step: &CompiledStep, action: &TrackedAction) -> bool {
    if let Some(ref required_type) = step.action_type {
        if &action.action_type != required_type {
            return false;
        }
    }

    if let Some(ref re) = step.target_regex {
        if !re.is_match(&action.target) {
            return false;
        }
    }

    if action.risk_score < step.min_risk {
        return false;
    }

    true
}

/// Try to match a compiled pattern against a session history.
/// Steps must match in order (but not necessarily consecutively)
/// and the first-to-last matched action must fall within the time window.
fn match_pattern(
    compiled: &CompiledPattern,
    history: &VecDeque<TrackedAction>,
) -> Option<PatternMatch> {
    if compiled.compiled_steps.is_empty() {
        return None;
    }

    let mut step_idx = 0;
    let mut matched_indices: Vec<usize> = Vec::new();

    for (i, action) in history.iter().enumerate() {
        if step_idx >= compiled.compiled_steps.len() {
            break;
        }
        if step_matches(&compiled.compiled_steps[step_idx], action) {
            matched_indices.push(i);
            step_idx += 1;
        }
    }

    // All steps must have matched
    if step_idx < compiled.compiled_steps.len() {
        return None;
    }

    // Enforce time window
    let first = &history[matched_indices[0]];
    let last = &history[*matched_indices.last().unwrap()];
    let time_span = last.timestamp.duration_since(first.timestamp);

    if time_span > compiled.pattern.max_time_window {
        return None;
    }

    Some(PatternMatch {
        pattern_name: compiled.pattern.name.clone(),
        matched_actions: matched_indices,
        confidence: compiled.pattern.confidence,
        severity: compiled.pattern.severity.clone(),
        time_span,
    })
}

/// Aggregate total risk from matches, rapid actions, and escalation.
fn compute_total_risk(
    matches: &[PatternMatch],
    rapid: &Option<RapidActionAlert>,
    escalation: &Option<EscalationSequence>,
) -> f64 {
    let mut risk = 0.0_f64;

    for m in matches {
        risk += m.confidence
            * match m.severity {
                SecuritySeverity::Critical => 1.0,
                SecuritySeverity::High => 0.8,
                SecuritySeverity::Medium => 0.5,
                SecuritySeverity::Low => 0.3,
                SecuritySeverity::Info => 0.1,
            };
    }

    if rapid.is_some() {
        risk += 0.3;
    }

    if let Some(ref esc) = escalation {
        risk += esc.risk_trajectory.last().copied().unwrap_or(0.0);
    }

    risk.min(1.0)
}

// ---------------------------------------------------------------------------
// Built-in attack patterns
// ---------------------------------------------------------------------------

/// Returns the default set of built-in attack patterns.
fn default_attack_patterns() -> Vec<AttackPattern> {
    vec![
        // data exfiltration: file read followed by web access to external URL
        AttackPattern {
            name: "data_exfiltration_chain".to_string(),
            description: "File read followed by web access to an external URL".to_string(),
            steps: vec![
                PatternStep {
                    action_type: Some(AgentActionType::FileAccess),
                    target_pattern: None,
                    min_risk: 0.0,
                },
                PatternStep {
                    action_type: Some(AgentActionType::WebAccess),
                    target_pattern: Some(r"(?i)https?://".to_string()),
                    min_risk: 0.0,
                },
            ],
            max_time_window: Duration::from_secs(300),
            severity: SecuritySeverity::High,
            confidence: 0.8,
        },
        // credential theft: reading sensitive files then exfiltrating
        AttackPattern {
            name: "credential_theft".to_string(),
            description: "Access to credential/secret files followed by web or skill call"
                .to_string(),
            steps: vec![
                PatternStep {
                    action_type: Some(AgentActionType::FileAccess),
                    target_pattern: Some(r"(?i)\.(env|key|pem|credentials|secret)".to_string()),
                    min_risk: 0.0,
                },
                PatternStep {
                    action_type: Some(AgentActionType::WebAccess),
                    target_pattern: None,
                    min_risk: 0.0,
                },
            ],
            max_time_window: Duration::from_secs(300),
            severity: SecuritySeverity::Critical,
            confidence: 0.9,
        },
        // reconnaissance then exploit: tool calls with increasing risk then command
        AttackPattern {
            name: "reconnaissance_then_exploit".to_string(),
            description: "Multiple tool calls with increasing risk followed by command execution"
                .to_string(),
            steps: vec![
                PatternStep {
                    action_type: Some(AgentActionType::ToolCall),
                    target_pattern: None,
                    min_risk: 0.2,
                },
                PatternStep {
                    action_type: Some(AgentActionType::ToolCall),
                    target_pattern: None,
                    min_risk: 0.5,
                },
                PatternStep {
                    action_type: Some(AgentActionType::CommandExecution),
                    target_pattern: None,
                    min_risk: 0.6,
                },
            ],
            max_time_window: Duration::from_secs(600),
            severity: SecuritySeverity::High,
            confidence: 0.75,
        },
        // lateral movement: skill invocation then privileged tool call
        AttackPattern {
            name: "lateral_movement".to_string(),
            description: "Skill invocation to another agent followed by privileged tool call"
                .to_string(),
            steps: vec![
                PatternStep {
                    action_type: Some(AgentActionType::SkillInvocation),
                    target_pattern: None,
                    min_risk: 0.0,
                },
                PatternStep {
                    action_type: Some(AgentActionType::ToolCall),
                    target_pattern: Some(r"(?i)(admin|sudo|escalat|privil)".to_string()),
                    min_risk: 0.5,
                },
            ],
            max_time_window: Duration::from_secs(300),
            severity: SecuritySeverity::High,
            confidence: 0.85,
        },
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{Duration, Instant};

    // Helper to build a tracked action quickly.
    fn make_action(
        action_type: AgentActionType,
        target: &str,
        session_id: &str,
        risk: f64,
    ) -> TrackedAction {
        TrackedAction {
            action_type,
            target: target.to_string(),
            timestamp: Instant::now(),
            session_id: session_id.to_string(),
            risk_score: risk,
        }
    }

    fn make_action_at(
        action_type: AgentActionType,
        target: &str,
        session_id: &str,
        risk: f64,
        timestamp: Instant,
    ) -> TrackedAction {
        TrackedAction {
            action_type,
            target: target.to_string(),
            timestamp,
            session_id: session_id.to_string(),
            risk_score: risk,
        }
    }

    // ---------------------------------------------------------------
    // 1. Action recording and history tracking
    // ---------------------------------------------------------------

    #[test]
    fn test_action_recording_and_history() {
        let mut correlator = ActionCorrelator::new(CorrelationConfig::default());

        let a1 = make_action(AgentActionType::ToolCall, "search", "s1", 0.1);
        correlator.record_action(a1);

        let a2 = make_action(AgentActionType::FileAccess, "/tmp/file", "s1", 0.3);
        correlator.record_action(a2);

        assert_eq!(correlator.session_count(), 1);
        let history = correlator.session_histories.get("s1").unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].target, "search");
        assert_eq!(history[1].target, "/tmp/file");
    }

    // ---------------------------------------------------------------
    // 2. Pattern matching - data exfiltration chain detected
    // ---------------------------------------------------------------

    #[test]
    fn test_data_exfiltration_chain_detected() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        let a1 = make_action_at(AgentActionType::FileAccess, "/etc/shadow", "s1", 0.7, now);
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::WebAccess,
            "https://evil.example.com/upload",
            "s1",
            0.6,
            now + Duration::from_secs(30),
        );
        let result = correlator.record_action(a2);

        assert!(
            result
                .pattern_matches
                .iter()
                .any(|m| m.pattern_name == "data_exfiltration_chain"),
            "Expected data_exfiltration_chain to match"
        );
    }

    // ---------------------------------------------------------------
    // 3. Pattern matching - benign sequence not matched
    // ---------------------------------------------------------------

    #[test]
    fn test_benign_sequence_not_matched() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        // Two tool calls, no file+web pattern
        let a1 = make_action_at(AgentActionType::ToolCall, "search", "s1", 0.1, now);
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::ToolCall,
            "calculator",
            "s1",
            0.1,
            now + Duration::from_secs(5),
        );
        let result = correlator.record_action(a2);

        assert!(
            result.pattern_matches.is_empty(),
            "Benign tool calls should not match any attack pattern"
        );
    }

    // ---------------------------------------------------------------
    // 4. Rapid action detection
    // ---------------------------------------------------------------

    #[test]
    fn test_rapid_action_detection() {
        let config = CorrelationConfig {
            rapid_action_threshold: Duration::from_millis(500),
            rapid_action_count: 5,
            ..Default::default()
        };
        let mut correlator = ActionCorrelator::new(config);

        let base = Instant::now();
        for i in 0..5 {
            let action = make_action_at(
                AgentActionType::ToolCall,
                &format!("tool_{i}"),
                "s1",
                0.1,
                base + Duration::from_millis(i * 100), // 100ms apart
            );
            correlator.record_action(action);
        }

        let rapid = correlator.detect_rapid_actions("s1");
        assert!(rapid.is_some(), "Should detect rapid actions");
        let alert = rapid.unwrap();
        assert_eq!(alert.action_count, 5);
        assert!(alert.avg_interval < Duration::from_millis(200));
    }

    // ---------------------------------------------------------------
    // 5. Rapid action not triggered for slow actions
    // ---------------------------------------------------------------

    #[test]
    fn test_rapid_action_not_triggered_for_slow_actions() {
        let config = CorrelationConfig {
            rapid_action_threshold: Duration::from_millis(100),
            rapid_action_count: 3,
            ..Default::default()
        };
        let mut correlator = ActionCorrelator::new(config);

        let base = Instant::now();
        for i in 0..3u64 {
            let action = make_action_at(
                AgentActionType::ToolCall,
                &format!("tool_{i}"),
                "s1",
                0.1,
                base + Duration::from_secs(i * 5), // 5 seconds apart
            );
            correlator.record_action(action);
        }

        let rapid = correlator.detect_rapid_actions("s1");
        assert!(
            rapid.is_none(),
            "Slow actions should not trigger rapid alert"
        );
    }

    // ---------------------------------------------------------------
    // 6. Privilege escalation sequence detection
    // ---------------------------------------------------------------

    #[test]
    fn test_privilege_escalation_sequence_detection() {
        let mut correlator = ActionCorrelator::new(CorrelationConfig::default());
        let now = Instant::now();

        let actions = [
            (AgentActionType::ToolCall, "list_users", 0.2),
            (AgentActionType::ToolCall, "read_config", 0.4),
            (AgentActionType::ToolCall, "modify_permissions", 0.6),
            (AgentActionType::CommandExecution, "sudo rm -rf", 0.9),
        ];

        for (i, (atype, target, risk)) in actions.iter().enumerate() {
            let action = make_action_at(
                atype.clone(),
                target,
                "s1",
                *risk,
                now + Duration::from_secs(i as u64),
            );
            correlator.record_action(action);
        }

        let esc = correlator.detect_privilege_escalation_sequence("s1");
        assert!(esc.is_some(), "Should detect escalation");
        let seq = esc.unwrap();
        assert_eq!(seq.steps.len(), 4);
        assert_eq!(seq.risk_trajectory, vec![0.2, 0.4, 0.6, 0.9]);
    }

    // ---------------------------------------------------------------
    // 7. Time window enforcement (pattern expires)
    // ---------------------------------------------------------------

    #[test]
    fn test_time_window_enforcement() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        // File access now
        let a1 = make_action_at(AgentActionType::FileAccess, "/data/secret", "s1", 0.5, now);
        correlator.record_action(a1);

        // Web access 10 minutes later (beyond the 5-minute window)
        let a2 = make_action_at(
            AgentActionType::WebAccess,
            "https://evil.com/exfil",
            "s1",
            0.5,
            now + Duration::from_secs(601),
        );
        let result = correlator.record_action(a2);

        let exfil = result
            .pattern_matches
            .iter()
            .find(|m| m.pattern_name == "data_exfiltration_chain");
        assert!(
            exfil.is_none(),
            "Pattern should not match when outside time window"
        );
    }

    // ---------------------------------------------------------------
    // 8. Multiple sessions tracked independently
    // ---------------------------------------------------------------

    #[test]
    fn test_multiple_sessions_independent() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        // Session 1: file read
        let a1 = make_action_at(AgentActionType::FileAccess, "/etc/passwd", "s1", 0.5, now);
        correlator.record_action(a1);

        // Session 2: web access (should NOT combine with s1's file read)
        let a2 = make_action_at(
            AgentActionType::WebAccess,
            "https://evil.com",
            "s2",
            0.5,
            now + Duration::from_secs(10),
        );
        let result = correlator.record_action(a2);

        assert_eq!(correlator.session_count(), 2);
        assert!(
            result.pattern_matches.is_empty(),
            "Cross-session actions should not match patterns"
        );
    }

    // ---------------------------------------------------------------
    // 9. Session cleanup of expired data
    // ---------------------------------------------------------------

    #[test]
    fn test_session_cleanup_expired() {
        let config = CorrelationConfig {
            session_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut correlator = ActionCorrelator::new(config);

        let a1 = make_action(AgentActionType::ToolCall, "tool_a", "expired_session", 0.1);
        correlator.record_action(a1);

        assert_eq!(correlator.session_count(), 1);

        // Wait for session to expire
        thread::sleep(Duration::from_millis(60));

        // Record a fresh action in another session to establish "now"
        let a2 = make_action(AgentActionType::ToolCall, "tool_b", "fresh_session", 0.1);
        correlator.record_action(a2);

        correlator.cleanup_expired_sessions();

        // Expired session should have been cleaned; fresh one should remain
        assert_eq!(correlator.session_count(), 1);
        assert!(correlator.session_histories.contains_key("fresh_session"));
        assert!(!correlator.session_histories.contains_key("expired_session"));
    }

    // ---------------------------------------------------------------
    // 10. Max history enforcement
    // ---------------------------------------------------------------

    #[test]
    fn test_max_history_enforcement() {
        let config = CorrelationConfig {
            max_history_per_session: 5,
            ..Default::default()
        };
        let mut correlator = ActionCorrelator::new(config);

        for i in 0..10 {
            let action = make_action(AgentActionType::ToolCall, &format!("tool_{i}"), "s1", 0.1);
            correlator.record_action(action);
        }

        let history = correlator.session_histories.get("s1").unwrap();
        assert_eq!(history.len(), 5);
        // Oldest entries should have been evicted, so the first remaining is tool_5
        assert_eq!(history[0].target, "tool_5");
    }

    // ---------------------------------------------------------------
    // 11. Custom pattern creation and matching
    // ---------------------------------------------------------------

    #[test]
    fn test_custom_pattern_matching() {
        let pattern = AttackPattern {
            name: "custom_test".to_string(),
            description: "Test pattern".to_string(),
            steps: vec![
                PatternStep {
                    action_type: Some(AgentActionType::CommandExecution),
                    target_pattern: Some(r"^whoami$".to_string()),
                    min_risk: 0.0,
                },
                PatternStep {
                    action_type: Some(AgentActionType::CommandExecution),
                    target_pattern: Some(r"(?i)cat /etc/".to_string()),
                    min_risk: 0.3,
                },
            ],
            max_time_window: Duration::from_secs(60),
            severity: SecuritySeverity::Medium,
            confidence: 0.7,
        };

        let config = CorrelationConfig {
            patterns: vec![pattern],
            ..Default::default()
        };
        let mut correlator = ActionCorrelator::new(config);
        let now = Instant::now();

        let a1 = make_action_at(AgentActionType::CommandExecution, "whoami", "s1", 0.2, now);
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::CommandExecution,
            "cat /etc/shadow",
            "s1",
            0.5,
            now + Duration::from_secs(10),
        );
        let result = correlator.record_action(a2);

        assert_eq!(result.pattern_matches.len(), 1);
        assert_eq!(result.pattern_matches[0].pattern_name, "custom_test");
        assert_eq!(result.pattern_matches[0].matched_actions, vec![0, 1]);
    }

    // ---------------------------------------------------------------
    // 12. SecurityFinding generation
    // ---------------------------------------------------------------

    #[test]
    fn test_security_finding_generation() {
        let result = CorrelationResult {
            session_id: "s1".to_string(),
            pattern_matches: vec![PatternMatch {
                pattern_name: "data_exfiltration_chain".to_string(),
                matched_actions: vec![0, 1],
                confidence: 0.8,
                severity: SecuritySeverity::High,
                time_span: Duration::from_secs(30),
            }],
            rapid_actions: Some(RapidActionAlert {
                action_count: 10,
                time_window: Duration::from_secs(5),
                avg_interval: Duration::from_millis(500),
            }),
            escalation: Some(EscalationSequence {
                steps: vec![
                    (AgentActionType::ToolCall, "ls".to_string(), 0.3),
                    (
                        AgentActionType::CommandExecution,
                        "sudo rm".to_string(),
                        0.9,
                    ),
                ],
                risk_trajectory: vec![0.3, 0.9],
            }),
            total_risk: 0.9,
        };

        let findings = ActionCorrelator::to_security_findings(&result);
        assert_eq!(findings.len(), 3);

        // Pattern match finding
        assert_eq!(
            findings[0].finding_type,
            "attack_pattern_data_exfiltration_chain"
        );
        assert_eq!(findings[0].severity, SecuritySeverity::High);
        assert!((findings[0].confidence_score - 0.8).abs() < f64::EPSILON);

        // Rapid action finding
        assert_eq!(findings[1].finding_type, "rapid_action_alert");
        assert_eq!(findings[1].severity, SecuritySeverity::Medium);

        // Escalation finding
        assert_eq!(findings[2].finding_type, "privilege_escalation_sequence");
        assert_eq!(findings[2].severity, SecuritySeverity::High);
    }

    // ---------------------------------------------------------------
    // 13. Compiled pattern regex matching
    // ---------------------------------------------------------------

    #[test]
    fn test_compiled_pattern_regex_matching() {
        let pattern = AttackPattern {
            name: "regex_test".to_string(),
            description: "Regex test".to_string(),
            steps: vec![PatternStep {
                action_type: Some(AgentActionType::FileAccess),
                target_pattern: Some(r"\.env$".to_string()),
                min_risk: 0.0,
            }],
            max_time_window: Duration::from_secs(60),
            severity: SecuritySeverity::Medium,
            confidence: 0.7,
        };

        let compiled = compile_pattern(pattern).unwrap();
        assert!(compiled.compiled_steps[0].target_regex.is_some());

        // Should match
        let action_match = TrackedAction {
            action_type: AgentActionType::FileAccess,
            target: "/app/.env".to_string(),
            timestamp: Instant::now(),
            session_id: "s1".to_string(),
            risk_score: 0.5,
        };
        assert!(step_matches(&compiled.compiled_steps[0], &action_match));

        // Should not match
        let action_no_match = TrackedAction {
            action_type: AgentActionType::FileAccess,
            target: "/app/config.json".to_string(),
            timestamp: Instant::now(),
            session_id: "s1".to_string(),
            risk_score: 0.5,
        };
        assert!(!step_matches(&compiled.compiled_steps[0], &action_no_match));

        // Wrong action type should not match
        let action_wrong_type = TrackedAction {
            action_type: AgentActionType::WebAccess,
            target: "/app/.env".to_string(),
            timestamp: Instant::now(),
            session_id: "s1".to_string(),
            risk_score: 0.5,
        };
        assert!(!step_matches(
            &compiled.compiled_steps[0],
            &action_wrong_type
        ));
    }

    // ---------------------------------------------------------------
    // 14. Multiple patterns matching same sequence
    // ---------------------------------------------------------------

    #[test]
    fn test_multiple_patterns_matching_same_sequence() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        // This sequence matches both data_exfiltration_chain and credential_theft
        let a1 = make_action_at(AgentActionType::FileAccess, "/app/.env", "s1", 0.5, now);
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::WebAccess,
            "https://attacker.com/collect",
            "s1",
            0.6,
            now + Duration::from_secs(10),
        );
        let result = correlator.record_action(a2);

        let pattern_names: Vec<&str> = result
            .pattern_matches
            .iter()
            .map(|m| m.pattern_name.as_str())
            .collect();

        assert!(
            pattern_names.contains(&"data_exfiltration_chain"),
            "Should match data_exfiltration_chain"
        );
        assert!(
            pattern_names.contains(&"credential_theft"),
            "Should match credential_theft (.env file pattern)"
        );
        assert!(result.pattern_matches.len() >= 2);
    }

    // ---------------------------------------------------------------
    // 15. Edge case: empty history
    // ---------------------------------------------------------------

    #[test]
    fn test_empty_history_check_patterns() {
        let correlator = ActionCorrelator::with_defaults();
        let matches = correlator.check_patterns("nonexistent");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_empty_history_detect_rapid() {
        let correlator = ActionCorrelator::with_defaults();
        let rapid = correlator.detect_rapid_actions("nonexistent");
        assert!(rapid.is_none());
    }

    #[test]
    fn test_empty_history_detect_escalation() {
        let correlator = ActionCorrelator::with_defaults();
        let esc = correlator.detect_privilege_escalation_sequence("nonexistent");
        assert!(esc.is_none());
    }

    // ---------------------------------------------------------------
    // 16. Edge case: single action
    // ---------------------------------------------------------------

    #[test]
    fn test_single_action_no_match() {
        let mut correlator = ActionCorrelator::with_defaults();

        let action = make_action(AgentActionType::FileAccess, "/etc/passwd", "s1", 0.8);
        let result = correlator.record_action(action);

        assert!(result.pattern_matches.is_empty());
        assert!(result.escalation.is_none());
    }

    // ---------------------------------------------------------------
    // 17. Temporal ordering validation
    // ---------------------------------------------------------------

    #[test]
    fn test_temporal_ordering_required() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        // Web access BEFORE file access - should NOT match exfiltration pattern
        // (pattern requires file access first, then web access)
        let a1 = make_action_at(
            AgentActionType::WebAccess,
            "https://example.com",
            "s1",
            0.5,
            now,
        );
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::FileAccess,
            "/etc/passwd",
            "s1",
            0.5,
            now + Duration::from_secs(10),
        );
        let result = correlator.record_action(a2);

        let exfil = result
            .pattern_matches
            .iter()
            .find(|m| m.pattern_name == "data_exfiltration_chain");
        assert!(
            exfil.is_none(),
            "Reversed order should not match the exfiltration pattern"
        );
    }

    // ---------------------------------------------------------------
    // 18. CorrelationResult aggregation
    // ---------------------------------------------------------------

    #[test]
    fn test_correlation_result_aggregation() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        // Build a sequence that triggers exfiltration pattern
        let a1 = make_action_at(AgentActionType::FileAccess, "/etc/shadow", "s1", 0.7, now);
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::WebAccess,
            "https://evil.com",
            "s1",
            0.6,
            now + Duration::from_secs(10),
        );
        let result = correlator.record_action(a2);

        assert_eq!(result.session_id, "s1");
        assert!(!result.pattern_matches.is_empty());
        assert!(result.total_risk > 0.0);

        // Verify time_span on the match
        let m = &result.pattern_matches[0];
        assert_eq!(m.time_span, Duration::from_secs(10));
    }

    // ---------------------------------------------------------------
    // 19. Credential theft pattern
    // ---------------------------------------------------------------

    #[test]
    fn test_credential_theft_pattern() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        let a1 = make_action_at(
            AgentActionType::FileAccess,
            "/home/user/.credentials",
            "s1",
            0.6,
            now,
        );
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::WebAccess,
            "http://internal-api/store",
            "s1",
            0.5,
            now + Duration::from_secs(60),
        );
        let result = correlator.record_action(a2);

        assert!(result
            .pattern_matches
            .iter()
            .any(|m| m.pattern_name == "credential_theft"));
    }

    // ---------------------------------------------------------------
    // 20. Reconnaissance then exploit pattern
    // ---------------------------------------------------------------

    #[test]
    fn test_reconnaissance_then_exploit_pattern() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        let a1 = make_action_at(AgentActionType::ToolCall, "scan_network", "s1", 0.3, now);
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::ToolCall,
            "enumerate_services",
            "s1",
            0.5,
            now + Duration::from_secs(30),
        );
        correlator.record_action(a2);

        let a3 = make_action_at(
            AgentActionType::CommandExecution,
            "exploit_payload",
            "s1",
            0.8,
            now + Duration::from_secs(60),
        );
        let result = correlator.record_action(a3);

        assert!(result
            .pattern_matches
            .iter()
            .any(|m| m.pattern_name == "reconnaissance_then_exploit"));
    }

    // ---------------------------------------------------------------
    // 21. Lateral movement pattern
    // ---------------------------------------------------------------

    #[test]
    fn test_lateral_movement_pattern() {
        let mut correlator = ActionCorrelator::with_defaults();
        let now = Instant::now();

        let a1 = make_action_at(
            AgentActionType::SkillInvocation,
            "agent_b_proxy",
            "s1",
            0.4,
            now,
        );
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::ToolCall,
            "admin_panel_access",
            "s1",
            0.7,
            now + Duration::from_secs(20),
        );
        let result = correlator.record_action(a2);

        assert!(result
            .pattern_matches
            .iter()
            .any(|m| m.pattern_name == "lateral_movement"));
    }

    // ---------------------------------------------------------------
    // 22. Escalation not triggered for insufficient steps
    // ---------------------------------------------------------------

    #[test]
    fn test_escalation_not_triggered_for_two_steps() {
        let mut correlator = ActionCorrelator::new(CorrelationConfig::default());
        let now = Instant::now();

        let a1 = make_action_at(AgentActionType::ToolCall, "a", "s1", 0.3, now);
        correlator.record_action(a1);

        let a2 = make_action_at(
            AgentActionType::ToolCall,
            "b",
            "s1",
            0.9,
            now + Duration::from_secs(1),
        );
        correlator.record_action(a2);

        let esc = correlator.detect_privilege_escalation_sequence("s1");
        assert!(
            esc.is_none(),
            "Two steps should be insufficient for escalation"
        );
    }

    // ---------------------------------------------------------------
    // 23. Escalation not triggered when risk stays below threshold
    // ---------------------------------------------------------------

    #[test]
    fn test_escalation_not_triggered_low_risk() {
        let mut correlator = ActionCorrelator::new(CorrelationConfig::default());
        let now = Instant::now();

        let actions = [0.1, 0.2, 0.3, 0.4];
        for (i, risk) in actions.iter().enumerate() {
            let a = make_action_at(
                AgentActionType::ToolCall,
                &format!("t{i}"),
                "s1",
                *risk,
                now + Duration::from_secs(i as u64),
            );
            correlator.record_action(a);
        }

        let esc = correlator.detect_privilege_escalation_sequence("s1");
        assert!(
            esc.is_none(),
            "Escalation should not trigger when final risk < 0.7"
        );
    }

    // ---------------------------------------------------------------
    // 24. with_defaults has all 4 built-in patterns
    // ---------------------------------------------------------------

    #[test]
    fn test_with_defaults_has_builtin_patterns() {
        let correlator = ActionCorrelator::with_defaults();
        assert_eq!(correlator.compiled_patterns.len(), 4);

        let names: Vec<&str> = correlator
            .compiled_patterns
            .iter()
            .map(|cp| cp.pattern.name.as_str())
            .collect();
        assert!(names.contains(&"data_exfiltration_chain"));
        assert!(names.contains(&"credential_theft"));
        assert!(names.contains(&"reconnaissance_then_exploit"));
        assert!(names.contains(&"lateral_movement"));
    }

    // ---------------------------------------------------------------
    // 25. SecurityFinding generation with no alerts
    // ---------------------------------------------------------------

    #[test]
    fn test_security_finding_empty_result() {
        let result = CorrelationResult {
            session_id: "s1".to_string(),
            pattern_matches: Vec::new(),
            rapid_actions: None,
            escalation: None,
            total_risk: 0.0,
        };

        let findings = ActionCorrelator::to_security_findings(&result);
        assert!(findings.is_empty());
    }

    // ---------------------------------------------------------------
    // 26. Pattern step with min_risk filter
    // ---------------------------------------------------------------

    #[test]
    fn test_pattern_step_min_risk_filter() {
        let step = CompiledStep {
            action_type: Some(AgentActionType::ToolCall),
            target_regex: None,
            min_risk: 0.5,
        };

        let low_risk = TrackedAction {
            action_type: AgentActionType::ToolCall,
            target: "tool".to_string(),
            timestamp: Instant::now(),
            session_id: "s1".to_string(),
            risk_score: 0.3,
        };
        assert!(!step_matches(&step, &low_risk));

        let high_risk = TrackedAction {
            action_type: AgentActionType::ToolCall,
            target: "tool".to_string(),
            timestamp: Instant::now(),
            session_id: "s1".to_string(),
            risk_score: 0.6,
        };
        assert!(step_matches(&step, &high_risk));
    }

    // ---------------------------------------------------------------
    // 27. Wildcard pattern step (all None)
    // ---------------------------------------------------------------

    #[test]
    fn test_wildcard_pattern_step_matches_anything() {
        let step = CompiledStep {
            action_type: None,
            target_regex: None,
            min_risk: 0.0,
        };

        let action = TrackedAction {
            action_type: AgentActionType::WebAccess,
            target: "https://any.url".to_string(),
            timestamp: Instant::now(),
            session_id: "s1".to_string(),
            risk_score: 0.0,
        };
        assert!(step_matches(&step, &action));
    }

    // ---------------------------------------------------------------
    // 28. Invalid regex in pattern step is rejected
    // ---------------------------------------------------------------

    #[test]
    fn test_invalid_regex_pattern_rejected() {
        let pattern = AttackPattern {
            name: "bad_regex".to_string(),
            description: "Pattern with invalid regex".to_string(),
            steps: vec![PatternStep {
                action_type: None,
                target_pattern: Some("[invalid(regex".to_string()),
                min_risk: 0.0,
            }],
            max_time_window: Duration::from_secs(60),
            severity: SecuritySeverity::Low,
            confidence: 0.5,
        };

        let compiled = compile_pattern(pattern);
        assert!(
            compiled.is_none(),
            "Invalid regex should cause pattern compilation to fail"
        );
    }

    // ---------------------------------------------------------------
    // 29. compute_total_risk capping at 1.0
    // ---------------------------------------------------------------

    #[test]
    fn test_total_risk_capped_at_one() {
        let matches = vec![
            PatternMatch {
                pattern_name: "a".to_string(),
                matched_actions: vec![0],
                confidence: 1.0,
                severity: SecuritySeverity::Critical,
                time_span: Duration::ZERO,
            },
            PatternMatch {
                pattern_name: "b".to_string(),
                matched_actions: vec![0],
                confidence: 1.0,
                severity: SecuritySeverity::Critical,
                time_span: Duration::ZERO,
            },
        ];

        let risk = compute_total_risk(&matches, &None, &None);
        assert!(
            (risk - 1.0).abs() < f64::EPSILON,
            "Risk should be capped at 1.0"
        );
    }
}
