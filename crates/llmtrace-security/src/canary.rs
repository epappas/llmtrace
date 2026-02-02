//! Canary token system for detecting system prompt leakage (OWASP LLM07).
//!
//! Canary tokens are unique, cryptographically random strings injected into
//! system prompts. If a canary token appears in an LLM response, it is strong
//! evidence that the system prompt has been extracted — a critical security
//! violation.
//!
//! # Overview
//!
//! 1. **Generate** a [`CanaryToken`] with [`CanaryToken::generate`] or
//!    [`CanaryToken::generate_with_label`].
//! 2. **Inject** it into a system prompt with [`inject_canary`].
//! 3. **Detect** leakage in responses with [`detect_canary`].
//! 4. **Convert** detections into [`SecurityFinding`]s with
//!    [`detect_canary_leakage`] for pipeline integration.
//!
//! The [`CanaryTokenStore`] provides a thread-safe, per-tenant token registry.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use llmtrace_core::{SecurityFinding, SecuritySeverity};
use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A canary token that can be injected into prompts and detected in responses.
///
/// Each token carries a unique string (with a configurable prefix), a creation
/// timestamp, and an optional human-readable label for multi-prompt setups.
#[derive(Debug, Clone)]
pub struct CanaryToken {
    /// The unique token string (e.g. `CANARY-a3F9bQ12xZ7mK0pL`).
    pub token: String,
    /// When this token was created.
    pub created_at: Instant,
    /// Optional label for identifying which prompt this belongs to.
    pub label: Option<String>,
}

/// Configuration for canary token generation and detection.
#[derive(Debug, Clone)]
pub struct CanaryConfig {
    /// Whether canary detection is enabled.
    pub enabled: bool,
    /// Token prefix (default: `"CANARY-"`).
    pub prefix: String,
    /// Length of the random portion of the token in characters (default: 16).
    pub token_length: usize,
    /// Whether to also detect partial token matches (substring).
    pub detect_partial: bool,
    /// Minimum substring length to consider a partial match.
    pub partial_min_length: usize,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefix: "CANARY-".to_string(),
            token_length: 16,
            detect_partial: true,
            partial_min_length: 8,
        }
    }
}

/// Result of canary detection in a response.
#[derive(Debug, Clone)]
pub struct CanaryDetection {
    /// Which token was detected.
    pub token: String,
    /// Whether it was a full or partial match.
    pub match_type: CanaryMatchType,
    /// Confidence (1.0 for full match, lower for partial).
    pub confidence: f64,
    /// Byte position in the response text where the match was found.
    pub position: usize,
}

/// How a canary token was matched in the response text.
#[derive(Debug, Clone, PartialEq)]
pub enum CanaryMatchType {
    /// Exact full token match.
    Full,
    /// Partial substring match.
    Partial {
        /// Number of characters matched.
        matched_length: usize,
    },
    /// Token found but encoded (Base64, hex, reversed, etc.).
    Encoded {
        /// Name of the encoding (e.g. `"base64"`, `"hex"`, `"reversed"`).
        encoding: String,
    },
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

impl CanaryToken {
    /// Generate a cryptographically random canary token.
    ///
    /// The token is formed as `{prefix}{random_alphanumeric_chars}` where the
    /// random portion has length [`CanaryConfig::token_length`].
    ///
    /// # Examples
    ///
    /// ```
    /// use llmtrace_security::canary::{CanaryConfig, CanaryToken};
    ///
    /// let config = CanaryConfig::default();
    /// let token = CanaryToken::generate(&config);
    /// assert!(token.token.starts_with("CANARY-"));
    /// ```
    pub fn generate(config: &CanaryConfig) -> Self {
        let mut rng = rand::thread_rng();
        let random_part: String = (0..config.token_length)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        Self {
            token: format!("{}{}", config.prefix, random_part),
            created_at: Instant::now(),
            label: None,
        }
    }

    /// Generate a canary token with a human-readable label.
    ///
    /// Labels help identify which system prompt a token belongs to when
    /// multiple prompts are in use.
    ///
    /// # Examples
    ///
    /// ```
    /// use llmtrace_security::canary::{CanaryConfig, CanaryToken};
    ///
    /// let config = CanaryConfig::default();
    /// let token = CanaryToken::generate_with_label(&config, "main-system-prompt");
    /// assert_eq!(token.label.as_deref(), Some("main-system-prompt"));
    /// ```
    pub fn generate_with_label(config: &CanaryConfig, label: &str) -> Self {
        let mut token = Self::generate(config);
        token.label = Some(label.to_string());
        token
    }
}

// ---------------------------------------------------------------------------
// Canary injection
// ---------------------------------------------------------------------------

/// Inject a canary token into a prompt.
///
/// Appends a hidden integrity marker that is invisible to users but will
/// appear in the response if the system prompt is leaked.
///
/// # Format
///
/// ```text
/// {original_prompt}
/// [SYSTEM_INTEGRITY_TOKEN: {token}]
/// ```
///
/// # Examples
///
/// ```
/// use llmtrace_security::canary::{CanaryConfig, CanaryToken, inject_canary};
///
/// let config = CanaryConfig::default();
/// let token = CanaryToken::generate(&config);
/// let prompt = inject_canary("You are a helpful assistant.", &token);
/// assert!(prompt.contains(&token.token));
/// assert!(prompt.starts_with("You are a helpful assistant."));
/// ```
pub fn inject_canary(prompt: &str, token: &CanaryToken) -> String {
    format!("{}\n[SYSTEM_INTEGRITY_TOKEN: {}]\n", prompt, token.token)
}

// ---------------------------------------------------------------------------
// Canary detection
// ---------------------------------------------------------------------------

/// Scan response text for any of the registered canary tokens.
///
/// Detection checks (in order):
/// 1. **Exact match** — the full token string appears verbatim.
/// 2. **Case-insensitive match** — the token appears with different casing.
/// 3. **Base64-encoded match** — the token was Base64-encoded in the response.
/// 4. **Hex-encoded match** — the token was hex-encoded in the response.
/// 5. **Reversed match** — the token appears reversed.
/// 6. **Partial match** — a substring of the token appears (if enabled and
///    length ≥ [`CanaryConfig::partial_min_length`]).
///
/// Returns an empty `Vec` when detection is disabled or no tokens match.
///
/// # Examples
///
/// ```
/// use llmtrace_security::canary::{CanaryConfig, CanaryToken, detect_canary};
///
/// let config = CanaryConfig::default();
/// let token = CanaryToken::generate(&config);
/// let response = format!("Here is the system prompt: {}", token.token);
/// let detections = detect_canary(&response, &[token], &config);
/// assert_eq!(detections.len(), 1);
/// ```
pub fn detect_canary(
    response: &str,
    tokens: &[CanaryToken],
    config: &CanaryConfig,
) -> Vec<CanaryDetection> {
    if !config.enabled {
        return Vec::new();
    }

    let mut detections = Vec::new();
    let response_lower = response.to_lowercase();

    for canary in tokens {
        let token_str = &canary.token;

        // 1. Exact match
        if let Some(pos) = response.find(token_str) {
            detections.push(CanaryDetection {
                token: token_str.clone(),
                match_type: CanaryMatchType::Full,
                confidence: 1.0,
                position: pos,
            });
            continue; // Full match found — skip weaker checks for this token
        }

        // 2. Case-insensitive match
        let token_lower = token_str.to_lowercase();
        if let Some(pos) = response_lower.find(&token_lower) {
            detections.push(CanaryDetection {
                token: token_str.clone(),
                match_type: CanaryMatchType::Full,
                confidence: 0.95,
                position: pos,
            });
            continue;
        }

        // 3. Base64-encoded match
        let b64_encoded = BASE64_STANDARD.encode(token_str.as_bytes());
        if let Some(pos) = response.find(&b64_encoded) {
            detections.push(CanaryDetection {
                token: token_str.clone(),
                match_type: CanaryMatchType::Encoded {
                    encoding: "base64".to_string(),
                },
                confidence: 0.9,
                position: pos,
            });
            continue;
        }

        // 4. Hex-encoded match
        let hex_encoded = hex_encode(token_str);
        if let Some(pos) = response.to_lowercase().find(&hex_encoded.to_lowercase()) {
            detections.push(CanaryDetection {
                token: token_str.clone(),
                match_type: CanaryMatchType::Encoded {
                    encoding: "hex".to_string(),
                },
                confidence: 0.85,
                position: pos,
            });
            continue;
        }

        // 5. Reversed match
        let reversed: String = token_str.chars().rev().collect();
        if let Some(pos) = response.find(&reversed) {
            detections.push(CanaryDetection {
                token: token_str.clone(),
                match_type: CanaryMatchType::Encoded {
                    encoding: "reversed".to_string(),
                },
                confidence: 0.85,
                position: pos,
            });
            continue;
        }

        // 6. Partial match (if enabled)
        if config.detect_partial && token_str.len() >= config.partial_min_length {
            if let Some(detection) = detect_partial_match(response, token_str, config) {
                detections.push(detection);
            }
        }
    }

    detections
}

/// Attempt to find the longest partial match of `token` in `response`.
fn detect_partial_match(
    response: &str,
    token: &str,
    config: &CanaryConfig,
) -> Option<CanaryDetection> {
    // Slide a window from the full token length down to the minimum
    let min_len = config.partial_min_length;
    if token.len() < min_len {
        return None;
    }

    for window_size in (min_len..token.len()).rev() {
        for start in 0..=(token.len() - window_size) {
            let substr = &token[start..start + window_size];
            if let Some(pos) = response.find(substr) {
                let confidence = window_size as f64 / token.len() as f64;
                return Some(CanaryDetection {
                    token: token.to_string(),
                    match_type: CanaryMatchType::Partial {
                        matched_length: window_size,
                    },
                    confidence,
                    position: pos,
                });
            }
        }
    }

    None
}

/// Encode a string as lowercase hex.
fn hex_encode(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// SecurityFinding integration
// ---------------------------------------------------------------------------

/// Detect canary token leakage and produce [`SecurityFinding`]s for the
/// existing security pipeline.
///
/// Severity mapping:
/// - **Full match** → `Critical`
/// - **Encoded match** → `High`
/// - **Partial match** → `Medium`
///
/// Each finding has type `"canary_token_leakage"` and includes metadata
/// about the match type, confidence, and position.
///
/// # Examples
///
/// ```
/// use llmtrace_security::canary::{CanaryConfig, CanaryToken, detect_canary_leakage};
///
/// let config = CanaryConfig::default();
/// let token = CanaryToken::generate(&config);
/// let response = format!("Leaked: {}", token.token);
/// let findings = detect_canary_leakage(&response, &[token], &config);
/// assert_eq!(findings.len(), 1);
/// assert_eq!(findings[0].finding_type, "canary_token_leakage");
/// ```
pub fn detect_canary_leakage(
    response: &str,
    tokens: &[CanaryToken],
    config: &CanaryConfig,
) -> Vec<SecurityFinding> {
    detect_canary(response, tokens, config)
        .into_iter()
        .map(|detection| {
            let severity = match &detection.match_type {
                CanaryMatchType::Full => SecuritySeverity::Critical,
                CanaryMatchType::Encoded { .. } => SecuritySeverity::High,
                CanaryMatchType::Partial { .. } => SecuritySeverity::Medium,
            };

            let match_desc = match &detection.match_type {
                CanaryMatchType::Full => "exact match".to_string(),
                CanaryMatchType::Partial { matched_length } => {
                    format!("partial match ({matched_length} chars)")
                }
                CanaryMatchType::Encoded { encoding } => {
                    format!("encoded match ({encoding})")
                }
            };

            SecurityFinding::new(
                severity,
                "canary_token_leakage".to_string(),
                format!(
                    "System prompt leakage detected: canary token '{}' found via {} at position {} (confidence: {:.2})",
                    detection.token,
                    match_desc,
                    detection.position,
                    detection.confidence,
                ),
                detection.confidence,
            )
            .with_metadata("token".to_string(), detection.token)
            .with_metadata("match_type".to_string(), format!("{:?}", detection.match_type))
            .with_metadata("position".to_string(), detection.position.to_string())
            .with_location("response.content".to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Thread-safe token store
// ---------------------------------------------------------------------------

/// A thread-safe, per-tenant canary token store.
///
/// Uses `Arc<RwLock<HashMap<String, Vec<CanaryToken>>>>` internally so it can
/// be shared across async tasks and threads.
///
/// # Examples
///
/// ```
/// use llmtrace_security::canary::{CanaryConfig, CanaryToken, CanaryTokenStore};
///
/// let store = CanaryTokenStore::new();
/// let config = CanaryConfig::default();
/// let token = CanaryToken::generate(&config);
/// let token_string = token.token.clone();
///
/// store.add("tenant-1", token);
/// assert_eq!(store.get("tenant-1").len(), 1);
///
/// store.remove("tenant-1", &token_string);
/// assert!(store.get("tenant-1").is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct CanaryTokenStore {
    /// Internal storage: tenant_id → list of canary tokens.
    inner: Arc<RwLock<HashMap<String, Vec<CanaryToken>>>>,
}

impl Default for CanaryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CanaryTokenStore {
    /// Create a new, empty token store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a canary token for the given tenant.
    pub fn add(&self, tenant_id: &str, token: CanaryToken) {
        let mut map = self.inner.write().expect("canary store lock poisoned");
        map.entry(tenant_id.to_string()).or_default().push(token);
    }

    /// Remove a canary token (by token string) for the given tenant.
    ///
    /// Returns `true` if a token was removed, `false` otherwise.
    pub fn remove(&self, tenant_id: &str, token_str: &str) -> bool {
        let mut map = self.inner.write().expect("canary store lock poisoned");
        if let Some(tokens) = map.get_mut(tenant_id) {
            let before = tokens.len();
            tokens.retain(|t| t.token != token_str);
            let removed = tokens.len() < before;
            // Clean up empty entries
            if tokens.is_empty() {
                map.remove(tenant_id);
            }
            removed
        } else {
            false
        }
    }

    /// Get all canary tokens for a tenant (cloned).
    ///
    /// Returns an empty `Vec` if the tenant has no tokens.
    pub fn get(&self, tenant_id: &str) -> Vec<CanaryToken> {
        let map = self.inner.read().expect("canary store lock poisoned");
        map.get(tenant_id).cloned().unwrap_or_default()
    }

    /// Return the number of tenants with registered tokens.
    pub fn tenant_count(&self) -> usize {
        let map = self.inner.read().expect("canary store lock poisoned");
        map.len()
    }

    /// Return the total number of tokens across all tenants.
    pub fn token_count(&self) -> usize {
        let map = self.inner.read().expect("canary store lock poisoned");
        map.values().map(|v| v.len()).sum()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CanaryConfig {
        CanaryConfig::default()
    }

    // -- Token generation ---------------------------------------------------

    #[test]
    fn test_generate_has_correct_prefix() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        assert!(
            token.token.starts_with("CANARY-"),
            "token should start with default prefix"
        );
    }

    #[test]
    fn test_generate_has_correct_length() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        // prefix length + random length
        let expected_len = config.prefix.len() + config.token_length;
        assert_eq!(token.token.len(), expected_len);
    }

    #[test]
    fn test_generate_tokens_are_unique() {
        let config = default_config();
        let t1 = CanaryToken::generate(&config);
        let t2 = CanaryToken::generate(&config);
        assert_ne!(t1.token, t2.token, "two generated tokens should differ");
    }

    #[test]
    fn test_generate_with_label() {
        let config = default_config();
        let token = CanaryToken::generate_with_label(&config, "my-prompt");
        assert_eq!(token.label.as_deref(), Some("my-prompt"));
        assert!(token.token.starts_with("CANARY-"));
    }

    #[test]
    fn test_generate_no_label_by_default() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        assert!(token.label.is_none());
    }

    #[test]
    fn test_custom_prefix_and_length() {
        let config = CanaryConfig {
            prefix: "TOK_".to_string(),
            token_length: 32,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        assert!(token.token.starts_with("TOK_"));
        assert_eq!(token.token.len(), 4 + 32);
    }

    // -- Exact match detection ----------------------------------------------

    #[test]
    fn test_detect_exact_match() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let response = format!("The system prompt is: {}", token.token);
        let detections = detect_canary(&response, &[token], &config);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].match_type, CanaryMatchType::Full);
        assert!((detections[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_detect_exact_match_position() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let prefix = "Leaked: ";
        let response = format!("{}{}", prefix, token.token);
        let detections = detect_canary(&response, &[token], &config);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].position, prefix.len());
    }

    // -- Case-insensitive detection -----------------------------------------

    #[test]
    fn test_detect_case_insensitive() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let response = token.token.to_lowercase();
        // Only counts if the casing actually differs
        let detections = detect_canary(&response, &[token], &config);

        assert_eq!(detections.len(), 1);
        // Either Full (exact) or Full with 0.95 confidence (case-insensitive)
        assert!(detections[0].confidence >= 0.95);
    }

    #[test]
    fn test_detect_case_insensitive_upper() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let response = token.token.to_uppercase();
        let detections = detect_canary(&response, &[token], &config);

        assert_eq!(detections.len(), 1);
        assert!(detections[0].confidence >= 0.95);
    }

    // -- Partial match detection --------------------------------------------

    #[test]
    fn test_detect_partial_match() {
        let config = CanaryConfig {
            detect_partial: true,
            partial_min_length: 8,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        // Take first 10 chars of the token (includes part of "CANARY-" + random)
        let partial = &token.token[..10];
        let response = format!("Some text with {partial} inside");
        let detections = detect_canary(&response, &[token], &config);

        assert_eq!(detections.len(), 1);
        match &detections[0].match_type {
            CanaryMatchType::Partial { matched_length } => {
                assert!(*matched_length >= 10);
            }
            other => panic!("expected Partial, got {:?}", other),
        }
    }

    #[test]
    fn test_partial_match_respects_min_length() {
        let config = CanaryConfig {
            detect_partial: true,
            partial_min_length: 20,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        // Substring shorter than partial_min_length
        let partial = &token.token[..8];
        let response = format!("Some text with {partial} inside");
        let detections = detect_canary(&response, &[token], &config);

        assert!(
            detections.is_empty(),
            "short substring should not trigger partial match"
        );
    }

    #[test]
    fn test_partial_match_disabled() {
        let config = CanaryConfig {
            detect_partial: false,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        let partial = &token.token[..10];
        let response = format!("Some text with {partial} inside");
        let detections = detect_canary(&response, &[token], &config);

        assert!(
            detections.is_empty(),
            "partial detection should be disabled"
        );
    }

    // -- Base64-encoded detection -------------------------------------------

    #[test]
    fn test_detect_base64_encoded() {
        let config = CanaryConfig {
            detect_partial: false,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        let encoded = BASE64_STANDARD.encode(token.token.as_bytes());
        let response = format!("Here is some data: {encoded}");
        let detections = detect_canary(&response, &[token], &config);

        assert_eq!(detections.len(), 1);
        assert_eq!(
            detections[0].match_type,
            CanaryMatchType::Encoded {
                encoding: "base64".to_string()
            }
        );
        assert!((detections[0].confidence - 0.9).abs() < f64::EPSILON);
    }

    // -- Hex-encoded detection ----------------------------------------------

    #[test]
    fn test_detect_hex_encoded() {
        let config = CanaryConfig {
            detect_partial: false,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        let hex = hex_encode(&token.token);
        let response = format!("Hex dump: {hex}");
        let detections = detect_canary(&response, &[token], &config);

        assert_eq!(detections.len(), 1);
        assert_eq!(
            detections[0].match_type,
            CanaryMatchType::Encoded {
                encoding: "hex".to_string()
            }
        );
        assert!((detections[0].confidence - 0.85).abs() < f64::EPSILON);
    }

    // -- Reversed token detection -------------------------------------------

    #[test]
    fn test_detect_reversed_token() {
        let config = CanaryConfig {
            detect_partial: false,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        let reversed: String = token.token.chars().rev().collect();
        let response = format!("Reversed: {reversed}");
        let detections = detect_canary(&response, &[token], &config);

        assert_eq!(detections.len(), 1);
        assert_eq!(
            detections[0].match_type,
            CanaryMatchType::Encoded {
                encoding: "reversed".to_string()
            }
        );
    }

    // -- No canary present (zero false positives) ---------------------------

    #[test]
    fn test_no_canary_no_detection() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let response = "This is a perfectly normal response with no tokens.";
        let detections = detect_canary(response, &[token], &config);

        assert!(detections.is_empty(), "should not produce false positives");
    }

    #[test]
    fn test_no_canary_detection_disabled() {
        let config = CanaryConfig {
            enabled: false,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        let response = format!("Leaked: {}", token.token);
        let detections = detect_canary(&response, &[token], &config);

        assert!(
            detections.is_empty(),
            "should return empty when disabled even if token present"
        );
    }

    #[test]
    fn test_no_false_positives_on_similar_text() {
        let config = CanaryConfig {
            detect_partial: false,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        let response = "CANARY-something-else-entirely and more text";
        let detections = detect_canary(response, &[token], &config);

        assert!(
            detections.is_empty(),
            "different canary prefix text should not match"
        );
    }

    // -- SecurityFinding generation -----------------------------------------

    #[test]
    fn test_security_finding_full_match() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let response = format!("Leaked: {}", token.token);
        let findings = detect_canary_leakage(&response, &[token], &config);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "canary_token_leakage");
        assert_eq!(findings[0].severity, SecuritySeverity::Critical);
        assert!(findings[0].description.contains("exact match"));
    }

    #[test]
    fn test_security_finding_encoded_match() {
        let config = CanaryConfig {
            detect_partial: false,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        let hex = hex_encode(&token.token);
        let response = format!("Hex: {hex}");
        let findings = detect_canary_leakage(&response, &[token], &config);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, SecuritySeverity::High);
        assert!(findings[0].description.contains("encoded match"));
    }

    #[test]
    fn test_security_finding_partial_match() {
        let config = CanaryConfig {
            detect_partial: true,
            partial_min_length: 8,
            ..default_config()
        };
        let token = CanaryToken::generate(&config);
        let partial = &token.token[..10];
        let response = format!("Fragment: {partial}");
        let findings = detect_canary_leakage(&response, &[token], &config);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, SecuritySeverity::Medium);
        assert!(findings[0].description.contains("partial match"));
    }

    #[test]
    fn test_security_finding_metadata() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let token_str = token.token.clone();
        let response = format!("Leak: {token_str}");
        let findings = detect_canary_leakage(&response, &[token], &config);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].metadata.get("token").map(String::as_str),
            Some(token_str.as_str())
        );
        assert!(findings[0].metadata.contains_key("match_type"));
        assert!(findings[0].metadata.contains_key("position"));
        assert_eq!(findings[0].location.as_deref(), Some("response.content"));
    }

    // -- CanaryTokenStore ---------------------------------------------------

    #[test]
    fn test_store_add_and_get() {
        let store = CanaryTokenStore::new();
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let token_str = token.token.clone();

        store.add("tenant-1", token);
        let tokens = store.get("tenant-1");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, token_str);
    }

    #[test]
    fn test_store_get_empty_tenant() {
        let store = CanaryTokenStore::new();
        let tokens = store.get("nonexistent");
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_store_remove() {
        let store = CanaryTokenStore::new();
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let token_str = token.token.clone();

        store.add("tenant-1", token);
        assert!(store.remove("tenant-1", &token_str));
        assert!(store.get("tenant-1").is_empty());
    }

    #[test]
    fn test_store_remove_nonexistent() {
        let store = CanaryTokenStore::new();
        assert!(!store.remove("tenant-1", "no-such-token"));
    }

    #[test]
    fn test_store_multiple_tenants() {
        let store = CanaryTokenStore::new();
        let config = default_config();

        store.add("tenant-a", CanaryToken::generate(&config));
        store.add("tenant-a", CanaryToken::generate(&config));
        store.add("tenant-b", CanaryToken::generate(&config));

        assert_eq!(store.get("tenant-a").len(), 2);
        assert_eq!(store.get("tenant-b").len(), 1);
        assert_eq!(store.tenant_count(), 2);
        assert_eq!(store.token_count(), 3);
    }

    #[test]
    fn test_store_remove_cleans_up_empty_tenant() {
        let store = CanaryTokenStore::new();
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let token_str = token.token.clone();

        store.add("tenant-1", token);
        store.remove("tenant-1", &token_str);
        assert_eq!(store.tenant_count(), 0);
    }

    #[test]
    fn test_store_thread_safety() {
        use std::thread;

        let store = CanaryTokenStore::new();
        let config = default_config();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let store = store.clone();
                let config = config.clone();
                thread::spawn(move || {
                    let tenant = format!("tenant-{i}");
                    let token = CanaryToken::generate(&config);
                    store.add(&tenant, token);
                    store.get(&tenant)
                })
            })
            .collect();

        for handle in handles {
            let tokens = handle.join().expect("thread panicked");
            assert!(!tokens.is_empty());
        }

        assert_eq!(store.tenant_count(), 10);
    }

    // -- inject_canary ------------------------------------------------------

    #[test]
    fn test_inject_canary_format() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let prompt = "You are a helpful assistant.";
        let result = inject_canary(prompt, &token);

        assert!(result.starts_with(prompt));
        assert!(result.contains(&format!("[SYSTEM_INTEGRITY_TOKEN: {}]", token.token)));
    }

    #[test]
    fn test_inject_canary_preserves_original() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let prompt = "Original prompt text\nWith multiple lines.";
        let result = inject_canary(prompt, &token);

        assert!(result.starts_with(prompt));
    }

    #[test]
    fn test_inject_and_detect_roundtrip() {
        let config = default_config();
        let token = CanaryToken::generate(&config);
        let prompt = inject_canary("System prompt", &token);

        // Simulate the LLM leaking the entire system prompt
        let response = format!("My system prompt is: {prompt}");
        let detections = detect_canary(&response, &[token], &config);

        assert!(
            !detections.is_empty(),
            "should detect the canary in leaked prompt"
        );
        assert_eq!(detections[0].match_type, CanaryMatchType::Full);
    }

    // -- Multiple tokens detection ------------------------------------------

    #[test]
    fn test_detect_multiple_tokens() {
        let config = default_config();
        let t1 = CanaryToken::generate(&config);
        let t2 = CanaryToken::generate(&config);
        let response = format!("First: {} Second: {}", t1.token, t2.token);
        let detections = detect_canary(&response, &[t1, t2], &config);

        assert_eq!(detections.len(), 2);
    }
}
