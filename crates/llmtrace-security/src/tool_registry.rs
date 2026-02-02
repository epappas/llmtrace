//! Tool registry and action-type rate limiting for agent security.
//!
//! Provides a thread-safe [`ToolRegistry`] that classifies tools by security level
//! (category, risk score, required permissions) and an [`ActionRateLimiter`] that
//! enforces per-action-type sliding-window rate limits.
//!
//! # Example
//!
//! ```
//! use llmtrace_security::tool_registry::{ToolRegistry, ActionRateLimiter, ToolDefinition, ToolCategory};
//!
//! // Pre-populated registry with sensible defaults
//! let registry = ToolRegistry::with_defaults();
//! assert!(registry.is_registered("web_search"));
//!
//! // Custom tool
//! let tool = ToolDefinition::new("my_tool", "My Tool", ToolCategory::DataRetrieval)
//!     .with_risk_score(0.1)
//!     .with_description("A safe read-only tool".to_string());
//! let mut registry = ToolRegistry::new();
//! registry.register(tool);
//! assert!(registry.is_registered("my_tool"));
//!
//! // Rate limiter
//! let limiter = ActionRateLimiter::new(60, std::time::Duration::from_secs(60));
//! assert!(limiter.check_rate_limit("tool_call").is_ok());
//! ```

use llmtrace_core::{AgentAction, AgentActionType, SecurityFinding, SecuritySeverity};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::RwLock;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// ToolCategory
// ---------------------------------------------------------------------------

/// Security category for a tool.
///
/// Categories group tools by the type of operation they perform, which
/// directly correlates with their inherent risk level.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ToolCategory {
    /// Read-only data retrieval (low risk).
    DataRetrieval,
    /// Web browsing, HTTP requests (medium risk).
    WebAccess,
    /// File system operations (medium-high risk).
    FileSystem,
    /// Database operations (medium-high risk).
    Database,
    /// Code execution, shell commands (high risk).
    CodeExecution,
    /// Communication — sending emails, messages (high risk).
    Communication,
    /// System administration (critical risk).
    SystemAdmin,
    /// Custom user-defined category.
    Custom(String),
}

impl fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataRetrieval => write!(f, "data_retrieval"),
            Self::WebAccess => write!(f, "web_access"),
            Self::FileSystem => write!(f, "file_system"),
            Self::Database => write!(f, "database"),
            Self::CodeExecution => write!(f, "code_execution"),
            Self::Communication => write!(f, "communication"),
            Self::SystemAdmin => write!(f, "system_admin"),
            Self::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

// ---------------------------------------------------------------------------
// ToolDefinition
// ---------------------------------------------------------------------------

/// Definition of a tool with security metadata.
///
/// Each tool registered in the [`ToolRegistry`] carries metadata that the
/// security engine uses to assess risk, enforce rate limits, and decide
/// whether user approval is required.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    /// Unique tool identifier (e.g., `"web_search"`, `"file_read"`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Security category.
    pub category: ToolCategory,
    /// Risk score 0.0–1.0 (0 = safe, 1 = dangerous).
    pub risk_score: f64,
    /// Whether this tool requires explicit user approval before execution.
    pub requires_approval: bool,
    /// Maximum calls per minute (`None` = unlimited).
    pub rate_limit: Option<u32>,
    /// List of permission strings required to use this tool.
    pub required_permissions: Vec<String>,
    /// Description of what this tool does.
    pub description: String,
}

impl ToolDefinition {
    /// Create a new tool definition with sensible defaults.
    ///
    /// The risk score defaults to `0.5`, approval is not required, and
    /// no per-tool rate limit is set.
    pub fn new(id: &str, name: &str, category: ToolCategory) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            category,
            risk_score: 0.5,
            requires_approval: false,
            rate_limit: None,
            required_permissions: Vec::new(),
            description: String::new(),
        }
    }

    /// Set the risk score (clamped to 0.0–1.0).
    pub fn with_risk_score(mut self, score: f64) -> Self {
        self.risk_score = score.clamp(0.0, 1.0);
        self
    }

    /// Set whether this tool requires user approval.
    pub fn with_requires_approval(mut self, requires: bool) -> Self {
        self.requires_approval = requires;
        self
    }

    /// Set a per-tool rate limit (calls per minute).
    pub fn with_rate_limit(mut self, limit: u32) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Add a required permission string.
    pub fn with_permission(mut self, permission: String) -> Self {
        self.required_permissions.push(permission);
        self
    }

    /// Set the tool description.
    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }
}

// ---------------------------------------------------------------------------
// ToolRegistry
// ---------------------------------------------------------------------------

/// Thread-safe registry of tool definitions.
///
/// Tools are stored in a `RwLock<HashMap<String, ToolDefinition>>` keyed by
/// the tool's unique identifier. The registry supports concurrent reads and
/// exclusive writes, making it safe to share across async tasks.
///
/// Use [`ToolRegistry::with_defaults`] to create a registry pre-populated
/// with common agent tools.
pub struct ToolRegistry {
    /// Tool definitions keyed by tool ID.
    tools: RwLock<HashMap<String, ToolDefinition>>,
}

impl ToolRegistry {
    /// Create an empty tool registry.
    pub fn new() -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
        }
    }

    /// Create a tool registry pre-populated with sensible defaults for
    /// common agent tool names.
    pub fn with_defaults() -> Self {
        let registry = Self::new();
        let defaults = vec![
            ToolDefinition::new("web_search", "Web Search", ToolCategory::WebAccess)
                .with_risk_score(0.3)
                .with_description("Search the web for information".to_string()),
            ToolDefinition::new("web_browse", "Web Browse", ToolCategory::WebAccess)
                .with_risk_score(0.4)
                .with_description("Browse a web page and extract content".to_string()),
            ToolDefinition::new("file_read", "File Read", ToolCategory::FileSystem)
                .with_risk_score(0.3)
                .with_description("Read contents of a file".to_string()),
            ToolDefinition::new("file_write", "File Write", ToolCategory::FileSystem)
                .with_risk_score(0.6)
                .with_requires_approval(true)
                .with_description("Write content to a file".to_string())
                .with_permission("file:write".to_string()),
            ToolDefinition::new("file_delete", "File Delete", ToolCategory::FileSystem)
                .with_risk_score(0.8)
                .with_requires_approval(true)
                .with_description("Delete a file from the filesystem".to_string())
                .with_permission("file:delete".to_string()),
            ToolDefinition::new("shell_exec", "Shell Execute", ToolCategory::CodeExecution)
                .with_risk_score(0.9)
                .with_requires_approval(true)
                .with_rate_limit(10)
                .with_description("Execute a shell command".to_string())
                .with_permission("exec:shell".to_string()),
            ToolDefinition::new("code_exec", "Code Execute", ToolCategory::CodeExecution)
                .with_risk_score(0.85)
                .with_requires_approval(true)
                .with_rate_limit(20)
                .with_description("Execute code in a sandboxed environment".to_string())
                .with_permission("exec:code".to_string()),
            ToolDefinition::new("send_email", "Send Email", ToolCategory::Communication)
                .with_risk_score(0.7)
                .with_requires_approval(true)
                .with_rate_limit(5)
                .with_description("Send an email message".to_string())
                .with_permission("comms:email".to_string()),
            ToolDefinition::new("send_message", "Send Message", ToolCategory::Communication)
                .with_risk_score(0.6)
                .with_requires_approval(true)
                .with_rate_limit(10)
                .with_description("Send a chat or messaging platform message".to_string())
                .with_permission("comms:message".to_string()),
            ToolDefinition::new("database_query", "Database Query", ToolCategory::Database)
                .with_risk_score(0.5)
                .with_description("Execute a read-only database query".to_string())
                .with_permission("db:read".to_string()),
            ToolDefinition::new("database_write", "Database Write", ToolCategory::Database)
                .with_risk_score(0.7)
                .with_requires_approval(true)
                .with_description("Execute a database write operation".to_string())
                .with_permission("db:write".to_string()),
            ToolDefinition::new("api_call", "API Call", ToolCategory::WebAccess)
                .with_risk_score(0.4)
                .with_description("Make an HTTP API call".to_string()),
            ToolDefinition::new("data_lookup", "Data Lookup", ToolCategory::DataRetrieval)
                .with_risk_score(0.1)
                .with_description("Look up data from a knowledge base".to_string()),
            ToolDefinition::new(
                "system_config",
                "System Configuration",
                ToolCategory::SystemAdmin,
            )
            .with_risk_score(0.95)
            .with_requires_approval(true)
            .with_rate_limit(5)
            .with_description("Modify system configuration".to_string())
            .with_permission("admin:config".to_string()),
        ];
        for tool in defaults {
            registry.register(tool);
        }
        registry
    }

    /// Register a tool definition.
    ///
    /// If a tool with the same ID already exists, it is replaced.
    pub fn register(&self, tool: ToolDefinition) {
        let mut tools = self.tools.write().expect("tool registry lock poisoned");
        tools.insert(tool.id.clone(), tool);
    }

    /// Unregister a tool by its ID.
    ///
    /// Returns `true` if the tool was present and removed.
    pub fn unregister(&self, id: &str) -> bool {
        let mut tools = self.tools.write().expect("tool registry lock poisoned");
        tools.remove(id).is_some()
    }

    /// Get a cloned copy of a tool definition by ID.
    pub fn get(&self, id: &str) -> Option<ToolDefinition> {
        let tools = self.tools.read().expect("tool registry lock poisoned");
        tools.get(id).cloned()
    }

    /// Check whether a tool is registered.
    pub fn is_registered(&self, id: &str) -> bool {
        let tools = self.tools.read().expect("tool registry lock poisoned");
        tools.contains_key(id)
    }

    /// Look up all tools in a given category.
    ///
    /// Returns cloned definitions because the internal lock cannot be held
    /// across the returned references.
    pub fn lookup_by_category(&self, category: &ToolCategory) -> Vec<ToolDefinition> {
        let tools = self.tools.read().expect("tool registry lock poisoned");
        tools
            .values()
            .filter(|t| &t.category == category)
            .cloned()
            .collect()
    }

    /// Return the number of registered tools.
    pub fn len(&self) -> usize {
        let tools = self.tools.read().expect("tool registry lock poisoned");
        tools.len()
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validate an agent action against the registry.
    ///
    /// Produces [`SecurityFinding`]s for:
    /// - **Unregistered tool usage** (`"unregistered_tool"`, severity `High`)
    /// - **High-risk tool** with `risk_score > 0.8` (`"high_risk_tool"`, severity `High`)
    /// - **Tool requiring approval** (`"tool_requires_approval"`, severity `Info`)
    pub fn validate_action(&self, action: &AgentAction) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let tool_name = &action.name;

        let tools = self.tools.read().expect("tool registry lock poisoned");

        match tools.get(tool_name) {
            None => {
                // Only flag tool calls and skill invocations as unregistered.
                // Other action types (command, web, file) use their own name
                // semantics and are validated by the regex analyzer.
                if action.action_type == AgentActionType::ToolCall
                    || action.action_type == AgentActionType::SkillInvocation
                {
                    findings.push(
                        SecurityFinding::new(
                            SecuritySeverity::High,
                            "unregistered_tool".to_string(),
                            format!("Unregistered tool used: {}", tool_name),
                            0.9,
                        )
                        .with_location("agent_action.tool_call".to_string())
                        .with_metadata("tool_name".to_string(), tool_name.clone()),
                    );
                }
            }
            Some(tool) => {
                if tool.risk_score > 0.8 {
                    findings.push(
                        SecurityFinding::new(
                            SecuritySeverity::High,
                            "high_risk_tool".to_string(),
                            format!(
                                "High-risk tool used: {} (risk score: {:.2})",
                                tool_name, tool.risk_score
                            ),
                            tool.risk_score,
                        )
                        .with_location("agent_action.tool_call".to_string())
                        .with_metadata("tool_name".to_string(), tool_name.clone())
                        .with_metadata("risk_score".to_string(), format!("{:.2}", tool.risk_score))
                        .with_metadata("category".to_string(), tool.category.to_string()),
                    );
                }
                if tool.requires_approval {
                    findings.push(
                        SecurityFinding::new(
                            SecuritySeverity::Info,
                            "tool_requires_approval".to_string(),
                            format!("Tool requires user approval: {}", tool_name),
                            1.0,
                        )
                        .with_location("agent_action.tool_call".to_string())
                        .with_metadata("tool_name".to_string(), tool_name.clone())
                        .with_alert_required(false),
                    );
                }
            }
        }

        findings
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ToolRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tools = self.tools.read().expect("tool registry lock poisoned");
        f.debug_struct("ToolRegistry")
            .field("tool_count", &tools.len())
            .field("tool_ids", &tools.keys().collect::<Vec<_>>())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// RateLimitExceeded
// ---------------------------------------------------------------------------

/// Error returned when an action-type rate limit is exceeded.
#[derive(Debug, Clone)]
pub struct RateLimitExceeded {
    /// The action type that exceeded its rate limit.
    pub action_type: String,
    /// The configured limit (calls per window).
    pub limit: u32,
    /// Duration of the rate-limit window.
    pub window: Duration,
}

impl fmt::Display for RateLimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rate limit exceeded for action type '{}': {} calls per {:?}",
            self.action_type, self.limit, self.window
        )
    }
}

impl std::error::Error for RateLimitExceeded {}

impl RateLimitExceeded {
    /// Convert this rate limit violation into a [`SecurityFinding`].
    pub fn to_security_finding(&self) -> SecurityFinding {
        SecurityFinding::new(
            SecuritySeverity::Medium,
            "action_rate_limit_exceeded".to_string(),
            format!(
                "Rate limit exceeded for action type '{}': limit is {} calls per {:?}",
                self.action_type, self.limit, self.window
            ),
            0.95,
        )
        .with_metadata("action_type".to_string(), self.action_type.clone())
        .with_metadata("limit".to_string(), self.limit.to_string())
        .with_metadata("window_secs".to_string(), self.window.as_secs().to_string())
    }
}

// ---------------------------------------------------------------------------
// ActionRateLimiter
// ---------------------------------------------------------------------------

/// Per-action-type sliding-window rate limiter.
///
/// Tracks timestamps of recent action invocations and enforces a maximum
/// number of calls within a configurable time window. Each action type
/// (e.g. `"tool_call"`, `"web_access"`) has its own independent window.
///
/// # Thread Safety
///
/// All methods acquire the internal `RwLock` and are safe to call from
/// multiple threads or async tasks.
pub struct ActionRateLimiter {
    /// Per-action-type sliding windows: `action_type -> VecDeque<Instant>`.
    windows: RwLock<HashMap<String, VecDeque<Instant>>>,
    /// Default rate limit (calls per window) for action types without an override.
    default_limit: u32,
    /// Per-action-type limit overrides.
    limits: HashMap<String, u32>,
    /// Duration of the sliding window.
    window: Duration,
}

impl ActionRateLimiter {
    /// Create a new rate limiter with the given default limit and window duration.
    pub fn new(default_limit: u32, window: Duration) -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            default_limit,
            limits: HashMap::new(),
            window,
        }
    }

    /// Create a rate limiter with per-action-type overrides.
    pub fn with_limits(default_limit: u32, window: Duration, limits: HashMap<String, u32>) -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            default_limit,
            limits,
            window,
        }
    }

    /// Get the effective limit for an action type.
    fn effective_limit(&self, action_type: &str) -> u32 {
        self.limits
            .get(action_type)
            .copied()
            .unwrap_or(self.default_limit)
    }

    /// Prune expired entries from a deque, keeping only timestamps within
    /// the current window relative to `now`.
    fn prune(deque: &mut VecDeque<Instant>, cutoff: Instant) {
        while let Some(&front) = deque.front() {
            if front < cutoff {
                deque.pop_front();
            } else {
                break;
            }
        }
    }

    /// Check the rate limit for an action type and record the action if allowed.
    ///
    /// Returns `Ok(())` if the action is within the limit, or
    /// `Err(RateLimitExceeded)` if the limit has been reached.
    pub fn check_rate_limit(
        &self,
        action_type: &str,
    ) -> std::result::Result<(), RateLimitExceeded> {
        let limit = self.effective_limit(action_type);
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut windows = self.windows.write().expect("rate limiter lock poisoned");
        let deque = windows.entry(action_type.to_string()).or_default();
        Self::prune(deque, cutoff);

        if deque.len() >= limit as usize {
            Err(RateLimitExceeded {
                action_type: action_type.to_string(),
                limit,
                window: self.window,
            })
        } else {
            deque.push_back(now);
            Ok(())
        }
    }

    /// Record an action without checking the rate limit.
    ///
    /// Useful for tracking actions that have already been validated by
    /// other means.
    pub fn record_action(&self, action_type: &str) {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut windows = self.windows.write().expect("rate limiter lock poisoned");
        let deque = windows.entry(action_type.to_string()).or_default();
        Self::prune(deque, cutoff);
        deque.push_back(now);
    }

    /// Return the number of remaining calls allowed for an action type
    /// within the current window.
    pub fn remaining(&self, action_type: &str) -> u32 {
        let limit = self.effective_limit(action_type);
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut windows = self.windows.write().expect("rate limiter lock poisoned");
        let deque = windows.entry(action_type.to_string()).or_default();
        Self::prune(deque, cutoff);

        limit.saturating_sub(deque.len() as u32)
    }

    /// Reset the sliding window for a specific action type.
    pub fn reset(&self, action_type: &str) {
        let mut windows = self.windows.write().expect("rate limiter lock poisoned");
        windows.remove(action_type);
    }

    /// Return the configured window duration.
    pub fn window_duration(&self) -> Duration {
        self.window
    }

    /// Return the default rate limit.
    pub fn default_limit(&self) -> u32 {
        self.default_limit
    }
}

impl fmt::Debug for ActionRateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActionRateLimiter")
            .field("default_limit", &self.default_limit)
            .field("window", &self.window)
            .field("overrides", &self.limits)
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::{AgentAction, AgentActionType};
    use std::thread;
    use std::time::Duration;

    // ---------------------------------------------------------------
    // ToolCategory
    // ---------------------------------------------------------------

    #[test]
    fn test_tool_category_display() {
        assert_eq!(ToolCategory::DataRetrieval.to_string(), "data_retrieval");
        assert_eq!(ToolCategory::WebAccess.to_string(), "web_access");
        assert_eq!(ToolCategory::FileSystem.to_string(), "file_system");
        assert_eq!(ToolCategory::Database.to_string(), "database");
        assert_eq!(ToolCategory::CodeExecution.to_string(), "code_execution");
        assert_eq!(ToolCategory::Communication.to_string(), "communication");
        assert_eq!(ToolCategory::SystemAdmin.to_string(), "system_admin");
        assert_eq!(
            ToolCategory::Custom("my_cat".to_string()).to_string(),
            "custom:my_cat"
        );
    }

    #[test]
    fn test_tool_category_equality() {
        assert_eq!(ToolCategory::WebAccess, ToolCategory::WebAccess);
        assert_ne!(ToolCategory::WebAccess, ToolCategory::FileSystem);
        assert_eq!(
            ToolCategory::Custom("x".to_string()),
            ToolCategory::Custom("x".to_string())
        );
        assert_ne!(
            ToolCategory::Custom("x".to_string()),
            ToolCategory::Custom("y".to_string())
        );
    }

    // ---------------------------------------------------------------
    // ToolDefinition
    // ---------------------------------------------------------------

    #[test]
    fn test_tool_definition_new_defaults() {
        let tool = ToolDefinition::new("test", "Test", ToolCategory::DataRetrieval);
        assert_eq!(tool.id, "test");
        assert_eq!(tool.name, "Test");
        assert_eq!(tool.category, ToolCategory::DataRetrieval);
        assert!((tool.risk_score - 0.5).abs() < f64::EPSILON);
        assert!(!tool.requires_approval);
        assert!(tool.rate_limit.is_none());
        assert!(tool.required_permissions.is_empty());
        assert!(tool.description.is_empty());
    }

    #[test]
    fn test_tool_definition_builder() {
        let tool = ToolDefinition::new("exec", "Execute", ToolCategory::CodeExecution)
            .with_risk_score(0.95)
            .with_requires_approval(true)
            .with_rate_limit(10)
            .with_permission("exec:shell".to_string())
            .with_permission("exec:code".to_string())
            .with_description("Run shell commands".to_string());

        assert_eq!(tool.id, "exec");
        assert!((tool.risk_score - 0.95).abs() < f64::EPSILON);
        assert!(tool.requires_approval);
        assert_eq!(tool.rate_limit, Some(10));
        assert_eq!(tool.required_permissions.len(), 2);
        assert_eq!(tool.description, "Run shell commands");
    }

    #[test]
    fn test_tool_definition_risk_score_clamped() {
        let tool_high =
            ToolDefinition::new("t", "T", ToolCategory::DataRetrieval).with_risk_score(1.5);
        assert!((tool_high.risk_score - 1.0).abs() < f64::EPSILON);

        let tool_low =
            ToolDefinition::new("t", "T", ToolCategory::DataRetrieval).with_risk_score(-0.5);
        assert!(tool_low.risk_score.abs() < f64::EPSILON);
    }

    // ---------------------------------------------------------------
    // ToolRegistry — basic operations
    // ---------------------------------------------------------------

    #[test]
    fn test_registry_new_is_empty() {
        let reg = ToolRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_registry_default_is_empty() {
        let reg = ToolRegistry::default();
        assert!(reg.is_empty());
    }

    #[test]
    fn test_registry_register_and_get() {
        let reg = ToolRegistry::new();
        let tool =
            ToolDefinition::new("search", "Search", ToolCategory::WebAccess).with_risk_score(0.3);
        reg.register(tool);

        assert!(reg.is_registered("search"));
        assert!(!reg.is_registered("unknown"));
        assert_eq!(reg.len(), 1);

        let got = reg.get("search").unwrap();
        assert_eq!(got.id, "search");
        assert!((got.risk_score - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_registry_get_nonexistent() {
        let reg = ToolRegistry::new();
        assert!(reg.get("nope").is_none());
    }

    #[test]
    fn test_registry_register_overwrites() {
        let reg = ToolRegistry::new();
        let tool_v1 =
            ToolDefinition::new("t", "V1", ToolCategory::DataRetrieval).with_risk_score(0.1);
        reg.register(tool_v1);
        assert_eq!(reg.get("t").unwrap().name, "V1");

        let tool_v2 = ToolDefinition::new("t", "V2", ToolCategory::Database).with_risk_score(0.9);
        reg.register(tool_v2);
        assert_eq!(reg.get("t").unwrap().name, "V2");
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_registry_unregister() {
        let reg = ToolRegistry::new();
        reg.register(ToolDefinition::new("a", "A", ToolCategory::DataRetrieval));
        reg.register(ToolDefinition::new("b", "B", ToolCategory::DataRetrieval));
        assert_eq!(reg.len(), 2);

        assert!(reg.unregister("a"));
        assert!(!reg.is_registered("a"));
        assert!(reg.is_registered("b"));
        assert_eq!(reg.len(), 1);

        assert!(!reg.unregister("nonexistent"));
    }

    #[test]
    fn test_registry_lookup_by_category() {
        let reg = ToolRegistry::new();
        reg.register(
            ToolDefinition::new("web1", "Web 1", ToolCategory::WebAccess).with_risk_score(0.3),
        );
        reg.register(
            ToolDefinition::new("web2", "Web 2", ToolCategory::WebAccess).with_risk_score(0.4),
        );
        reg.register(
            ToolDefinition::new("file1", "File 1", ToolCategory::FileSystem).with_risk_score(0.5),
        );

        let web_tools = reg.lookup_by_category(&ToolCategory::WebAccess);
        assert_eq!(web_tools.len(), 2);
        assert!(web_tools
            .iter()
            .all(|t| t.category == ToolCategory::WebAccess));

        let fs_tools = reg.lookup_by_category(&ToolCategory::FileSystem);
        assert_eq!(fs_tools.len(), 1);

        let db_tools = reg.lookup_by_category(&ToolCategory::Database);
        assert!(db_tools.is_empty());
    }

    // ---------------------------------------------------------------
    // ToolRegistry — with_defaults
    // ---------------------------------------------------------------

    #[test]
    fn test_registry_with_defaults_populated() {
        let reg = ToolRegistry::with_defaults();
        assert!(!reg.is_empty());
        assert!(reg.is_registered("web_search"));
        assert!(reg.is_registered("file_read"));
        assert!(reg.is_registered("file_write"));
        assert!(reg.is_registered("shell_exec"));
        assert!(reg.is_registered("send_email"));
        assert!(reg.is_registered("database_query"));
        assert!(reg.is_registered("system_config"));
    }

    #[test]
    fn test_registry_defaults_risk_scores() {
        let reg = ToolRegistry::with_defaults();
        let search = reg.get("web_search").unwrap();
        assert!(search.risk_score <= 0.5, "web_search should be low risk");

        let shell = reg.get("shell_exec").unwrap();
        assert!(shell.risk_score > 0.8, "shell_exec should be high risk");
        assert!(
            shell.requires_approval,
            "shell_exec should require approval"
        );
    }

    #[test]
    fn test_registry_defaults_categories() {
        let reg = ToolRegistry::with_defaults();
        assert_eq!(
            reg.get("web_search").unwrap().category,
            ToolCategory::WebAccess
        );
        assert_eq!(
            reg.get("file_read").unwrap().category,
            ToolCategory::FileSystem
        );
        assert_eq!(
            reg.get("shell_exec").unwrap().category,
            ToolCategory::CodeExecution
        );
        assert_eq!(
            reg.get("send_email").unwrap().category,
            ToolCategory::Communication
        );
        assert_eq!(
            reg.get("database_query").unwrap().category,
            ToolCategory::Database
        );
        assert_eq!(
            reg.get("data_lookup").unwrap().category,
            ToolCategory::DataRetrieval
        );
        assert_eq!(
            reg.get("system_config").unwrap().category,
            ToolCategory::SystemAdmin
        );
    }

    // ---------------------------------------------------------------
    // ToolRegistry — validate_action
    // ---------------------------------------------------------------

    #[test]
    fn test_validate_unregistered_tool_call() {
        let reg = ToolRegistry::new();
        let action = AgentAction::new(AgentActionType::ToolCall, "unknown_tool".to_string());
        let findings = reg.validate_action(&action);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "unregistered_tool");
        assert_eq!(findings[0].severity, SecuritySeverity::High);
    }

    #[test]
    fn test_validate_unregistered_skill_invocation() {
        let reg = ToolRegistry::new();
        let action = AgentAction::new(
            AgentActionType::SkillInvocation,
            "unknown_skill".to_string(),
        );
        let findings = reg.validate_action(&action);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "unregistered_tool");
    }

    #[test]
    fn test_validate_unregistered_command_not_flagged() {
        let reg = ToolRegistry::new();
        let action = AgentAction::new(AgentActionType::CommandExecution, "ls -la".to_string());
        let findings = reg.validate_action(&action);
        assert!(
            findings.is_empty(),
            "CommandExecution should not trigger unregistered_tool"
        );
    }

    #[test]
    fn test_validate_unregistered_web_access_not_flagged() {
        let reg = ToolRegistry::new();
        let action = AgentAction::new(
            AgentActionType::WebAccess,
            "https://example.com".to_string(),
        );
        let findings = reg.validate_action(&action);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_validate_unregistered_file_access_not_flagged() {
        let reg = ToolRegistry::new();
        let action = AgentAction::new(AgentActionType::FileAccess, "/tmp/file.txt".to_string());
        let findings = reg.validate_action(&action);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_validate_registered_low_risk_tool() {
        let reg = ToolRegistry::new();
        reg.register(
            ToolDefinition::new("safe_tool", "Safe", ToolCategory::DataRetrieval)
                .with_risk_score(0.1),
        );
        let action = AgentAction::new(AgentActionType::ToolCall, "safe_tool".to_string());
        let findings = reg.validate_action(&action);
        assert!(
            findings.is_empty(),
            "Low-risk registered tool should produce no findings"
        );
    }

    #[test]
    fn test_validate_high_risk_tool() {
        let reg = ToolRegistry::new();
        reg.register(
            ToolDefinition::new("danger", "Danger", ToolCategory::CodeExecution)
                .with_risk_score(0.85),
        );
        let action = AgentAction::new(AgentActionType::ToolCall, "danger".to_string());
        let findings = reg.validate_action(&action);
        assert!(findings.iter().any(|f| f.finding_type == "high_risk_tool"));
        assert!(findings
            .iter()
            .any(|f| f.severity == SecuritySeverity::High));
    }

    #[test]
    fn test_validate_tool_at_boundary_risk_score() {
        let reg = ToolRegistry::new();
        reg.register(
            ToolDefinition::new("border", "Border", ToolCategory::FileSystem).with_risk_score(0.8),
        );
        let action = AgentAction::new(AgentActionType::ToolCall, "border".to_string());
        let findings = reg.validate_action(&action);
        assert!(
            !findings.iter().any(|f| f.finding_type == "high_risk_tool"),
            "risk_score == 0.8 is NOT > 0.8, should not trigger"
        );
    }

    #[test]
    fn test_validate_tool_requires_approval() {
        let reg = ToolRegistry::new();
        reg.register(
            ToolDefinition::new("approve_me", "Approve", ToolCategory::Communication)
                .with_risk_score(0.5)
                .with_requires_approval(true),
        );
        let action = AgentAction::new(AgentActionType::ToolCall, "approve_me".to_string());
        let findings = reg.validate_action(&action);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == "tool_requires_approval"));
        let approval_finding = findings
            .iter()
            .find(|f| f.finding_type == "tool_requires_approval")
            .unwrap();
        assert_eq!(approval_finding.severity, SecuritySeverity::Info);
        assert!(!approval_finding.requires_alert);
    }

    #[test]
    fn test_validate_high_risk_and_requires_approval() {
        let reg = ToolRegistry::new();
        reg.register(
            ToolDefinition::new("risky_approval", "Risky", ToolCategory::SystemAdmin)
                .with_risk_score(0.95)
                .with_requires_approval(true),
        );
        let action = AgentAction::new(AgentActionType::ToolCall, "risky_approval".to_string());
        let findings = reg.validate_action(&action);
        assert!(findings.iter().any(|f| f.finding_type == "high_risk_tool"));
        assert!(findings
            .iter()
            .any(|f| f.finding_type == "tool_requires_approval"));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_validate_with_defaults_known_tool() {
        let reg = ToolRegistry::with_defaults();
        let action = AgentAction::new(AgentActionType::ToolCall, "web_search".to_string());
        let findings = reg.validate_action(&action);
        // web_search is low risk, no approval needed
        assert!(
            !findings
                .iter()
                .any(|f| f.finding_type == "unregistered_tool"),
            "web_search is registered in defaults"
        );
        assert!(
            !findings.iter().any(|f| f.finding_type == "high_risk_tool"),
            "web_search is low risk"
        );
    }

    #[test]
    fn test_validate_with_defaults_shell_exec() {
        let reg = ToolRegistry::with_defaults();
        let action = AgentAction::new(AgentActionType::ToolCall, "shell_exec".to_string());
        let findings = reg.validate_action(&action);
        assert!(
            findings.iter().any(|f| f.finding_type == "high_risk_tool"),
            "shell_exec has risk > 0.8"
        );
        assert!(findings
            .iter()
            .any(|f| f.finding_type == "tool_requires_approval"));
    }

    // ---------------------------------------------------------------
    // ToolRegistry — thread safety
    // ---------------------------------------------------------------

    #[test]
    fn test_registry_concurrent_access() {
        let reg = std::sync::Arc::new(ToolRegistry::new());
        let mut handles = Vec::new();

        for i in 0..10 {
            let reg_clone = reg.clone();
            handles.push(thread::spawn(move || {
                let id = format!("tool_{}", i);
                reg_clone.register(ToolDefinition::new(&id, &id, ToolCategory::DataRetrieval));
                assert!(reg_clone.is_registered(&id));
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(reg.len(), 10);
    }

    // ---------------------------------------------------------------
    // RateLimitExceeded
    // ---------------------------------------------------------------

    #[test]
    fn test_rate_limit_exceeded_display() {
        let err = RateLimitExceeded {
            action_type: "tool_call".to_string(),
            limit: 10,
            window: Duration::from_secs(60),
        };
        let msg = err.to_string();
        assert!(msg.contains("tool_call"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn test_rate_limit_exceeded_to_security_finding() {
        let err = RateLimitExceeded {
            action_type: "web_access".to_string(),
            limit: 5,
            window: Duration::from_secs(60),
        };
        let finding = err.to_security_finding();
        assert_eq!(finding.finding_type, "action_rate_limit_exceeded");
        assert_eq!(finding.severity, SecuritySeverity::Medium);
        assert_eq!(
            finding.metadata.get("action_type"),
            Some(&"web_access".to_string())
        );
        assert_eq!(finding.metadata.get("limit"), Some(&"5".to_string()));
    }

    // ---------------------------------------------------------------
    // ActionRateLimiter — basic
    // ---------------------------------------------------------------

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = ActionRateLimiter::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("tool_call").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_denies_over_limit() {
        let limiter = ActionRateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(limiter.check_rate_limit("tool_call").is_ok());
        }
        let result = limiter.check_rate_limit("tool_call");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.action_type, "tool_call");
        assert_eq!(err.limit, 3);
    }

    #[test]
    fn test_rate_limiter_independent_action_types() {
        let limiter = ActionRateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check_rate_limit("type_a").is_ok());
        assert!(limiter.check_rate_limit("type_a").is_ok());
        assert!(limiter.check_rate_limit("type_a").is_err());

        // type_b should be independent
        assert!(limiter.check_rate_limit("type_b").is_ok());
        assert!(limiter.check_rate_limit("type_b").is_ok());
        assert!(limiter.check_rate_limit("type_b").is_err());
    }

    #[test]
    fn test_rate_limiter_remaining() {
        let limiter = ActionRateLimiter::new(5, Duration::from_secs(60));
        assert_eq!(limiter.remaining("test"), 5);

        limiter.check_rate_limit("test").unwrap();
        assert_eq!(limiter.remaining("test"), 4);

        limiter.check_rate_limit("test").unwrap();
        limiter.check_rate_limit("test").unwrap();
        assert_eq!(limiter.remaining("test"), 2);
    }

    #[test]
    fn test_rate_limiter_reset() {
        let limiter = ActionRateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            limiter.check_rate_limit("test").unwrap();
        }
        assert!(limiter.check_rate_limit("test").is_err());
        assert_eq!(limiter.remaining("test"), 0);

        limiter.reset("test");
        assert_eq!(limiter.remaining("test"), 3);
        assert!(limiter.check_rate_limit("test").is_ok());
    }

    #[test]
    fn test_rate_limiter_record_action() {
        let limiter = ActionRateLimiter::new(3, Duration::from_secs(60));
        limiter.record_action("test");
        limiter.record_action("test");
        assert_eq!(limiter.remaining("test"), 1);

        limiter.record_action("test");
        // Now at limit; check should fail
        assert!(limiter.check_rate_limit("test").is_err());
    }

    #[test]
    fn test_rate_limiter_with_overrides() {
        let mut limits = HashMap::new();
        limits.insert("strict".to_string(), 1);
        limits.insert("relaxed".to_string(), 100);

        let limiter = ActionRateLimiter::with_limits(10, Duration::from_secs(60), limits);

        assert!(limiter.check_rate_limit("strict").is_ok());
        assert!(limiter.check_rate_limit("strict").is_err());

        assert_eq!(limiter.remaining("relaxed"), 100);

        // default (no override)
        assert_eq!(limiter.remaining("other"), 10);
    }

    #[test]
    fn test_rate_limiter_sliding_window_expiry() {
        // Use a very short window to test expiry
        let limiter = ActionRateLimiter::new(2, Duration::from_millis(50));
        assert!(limiter.check_rate_limit("test").is_ok());
        assert!(limiter.check_rate_limit("test").is_ok());
        assert!(limiter.check_rate_limit("test").is_err());

        // Wait for the window to expire
        thread::sleep(Duration::from_millis(60));

        // Should be allowed again
        assert!(limiter.check_rate_limit("test").is_ok());
    }

    #[test]
    fn test_rate_limiter_accessors() {
        let limiter = ActionRateLimiter::new(42, Duration::from_secs(120));
        assert_eq!(limiter.default_limit(), 42);
        assert_eq!(limiter.window_duration(), Duration::from_secs(120));
    }

    #[test]
    fn test_rate_limiter_debug() {
        let limiter = ActionRateLimiter::new(10, Duration::from_secs(60));
        let debug_str = format!("{:?}", limiter);
        assert!(debug_str.contains("ActionRateLimiter"));
        assert!(debug_str.contains("10"));
    }

    // ---------------------------------------------------------------
    // ActionRateLimiter — thread safety
    // ---------------------------------------------------------------

    #[test]
    fn test_rate_limiter_concurrent_access() {
        let limiter = std::sync::Arc::new(ActionRateLimiter::new(100, Duration::from_secs(60)));
        let mut handles = Vec::new();

        for _ in 0..10 {
            let limiter_clone = limiter.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..10 {
                    let _ = limiter_clone.check_rate_limit("concurrent");
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All 100 calls should have been recorded
        assert_eq!(limiter.remaining("concurrent"), 0);
    }

    // ---------------------------------------------------------------
    // Integration: registry + rate limiter
    // ---------------------------------------------------------------

    #[test]
    fn test_registry_debug() {
        let reg = ToolRegistry::new();
        reg.register(ToolDefinition::new("a", "A", ToolCategory::DataRetrieval));
        let debug_str = format!("{:?}", reg);
        assert!(debug_str.contains("ToolRegistry"));
        assert!(debug_str.contains("tool_count"));
    }

    #[test]
    fn test_end_to_end_validation_and_rate_limit() {
        let registry = ToolRegistry::with_defaults();
        let limiter = ActionRateLimiter::new(2, Duration::from_secs(60));

        // First call to shell_exec — high risk + requires approval
        let action = AgentAction::new(AgentActionType::ToolCall, "shell_exec".to_string());
        let mut all_findings = registry.validate_action(&action);

        // Check rate limit
        match limiter.check_rate_limit(&action.action_type.to_string()) {
            Ok(()) => {}
            Err(err) => all_findings.push(err.to_security_finding()),
        }

        assert!(all_findings
            .iter()
            .any(|f| f.finding_type == "high_risk_tool"));
        assert!(all_findings
            .iter()
            .any(|f| f.finding_type == "tool_requires_approval"));
        assert!(
            !all_findings
                .iter()
                .any(|f| f.finding_type == "action_rate_limit_exceeded"),
            "First call should not be rate limited"
        );

        // Second call
        let _ = limiter.check_rate_limit(&action.action_type.to_string());

        // Third call — should be rate limited
        let result = limiter.check_rate_limit(&action.action_type.to_string());
        assert!(result.is_err());
        let rate_finding = result.unwrap_err().to_security_finding();
        assert_eq!(rate_finding.finding_type, "action_rate_limit_exceeded");
        assert_eq!(rate_finding.severity, SecuritySeverity::Medium);
    }
}
