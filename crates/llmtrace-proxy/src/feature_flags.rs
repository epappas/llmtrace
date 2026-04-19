//! Wire shape and validation for the runtime feature-flag admin API.
//!
//! Implements the field mapping, validation rules, and HTTP error
//! categories for `/api/v1/config/features` (issue #42). The actual
//! handlers and routing live in [`crate::feature_flags_api`].
//!
//! ## Surface
//!
//! Eleven flags are exposed on [`FeatureFlags`]. `analyzer_regex_enabled`
//! is intentionally absent: regex detection is always-on. PUT requests
//! that name `analyzer_regex_enabled` return 400 `Immutable`. The
//! `enforcement_enabled` field is also absent: operators wanting no-op
//! enforcement should set `enforcement_mode = "log"` instead.
//!
//! ## Hot-swap contract
//!
//! Each field on [`FeatureFlags`] either reads its target on the
//! request hot path (HOT) or has a runtime gate plumbed via
//! [`llmtrace_security::EnsembleRuntimeHandle`] in the proxy infrastructure
//! (PLUMB-CHEAP). The `llm_judge_enabled` wire field mirrors
//! `config.judge.enabled` (issue #43); the judge worker reads the
//! nested config on the hot path.

use std::path::Path;

use axum::http::StatusCode;
use llmtrace_core::{EnforcementMode, OperatingPoint, ProxyConfig};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// Wire shape returned by `GET /api/v1/config/features` and accepted
/// by the bulk `PUT /api/v1/config/features` endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct FeatureFlags {
    /// Runtime gate for the DeBERTa ML analyzer's contribution to voting.
    pub analyzer_ml_enabled: bool,
    /// Runtime gate for the InjecGuard ML analyzer.
    pub analyzer_injecguard_enabled: bool,
    /// Runtime gate for the PIGuard ML analyzer.
    pub analyzer_piguard_enabled: bool,
    /// Runtime gate for the dedicated jailbreak detector inside the
    /// regex analyzer.
    pub analyzer_jailbreak_enabled: bool,
    /// Enforcement mode: `"log"`, `"block"`, or `"flag"`.
    pub enforcement_mode: String,
    /// Whether boundary-token injection defense wraps user content.
    pub boundary_defense_enabled: bool,
    /// Whether boundary defense runs in shadow (observe-only) mode.
    pub boundary_defense_shadow_mode: bool,
    /// Whether per-tenant rate limiting is enforced.
    pub rate_limiting_enabled: bool,
    /// Whether cost-cap enforcement is active.
    pub cost_caps_enabled: bool,
    /// Active operating point: `"balanced"`, `"high_recall"`, or
    /// `"high_precision"`.
    pub operating_point: String,
    /// Whether over-defence suppression is applied to ML-only single-
    /// detector injection findings.
    pub over_defence: bool,
    /// Runtime gate for the LLM-as-a-Judge analysis tier (issue #43).
    /// Mirrors `config.judge.enabled` on the wire for backwards
    /// compatibility with external admin-API clients; the nested
    /// `JudgeConfig` struct carries backend selection and tuning
    /// knobs.
    pub llm_judge_enabled: bool,
}

/// Canonical identifier for every flag exposed on [`FeatureFlags`].
///
/// Drives a single-source-of-truth table: `apply_single`, the audit
/// log diff in [`crate::feature_flags_api`], and the feature metadata
/// helpers (`name`, `read`, `kind`) all go through this enum so adding
/// a flag is a single-site change inside `impl FeatureId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureId {
    AnalyzerMlEnabled,
    AnalyzerInjecguardEnabled,
    AnalyzerPiguardEnabled,
    AnalyzerJailbreakEnabled,
    EnforcementMode,
    BoundaryDefenseEnabled,
    BoundaryDefenseShadowMode,
    RateLimitingEnabled,
    CostCapsEnabled,
    OperatingPoint,
    OverDefence,
    LlmJudgeEnabled,
}

/// Kind of value a feature flag accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureKind {
    Bool,
    String,
}

impl FeatureId {
    /// Every flag in declaration order. The audit differ, metrics
    /// recorder, and GET projection all iterate this slice.
    pub const ALL: &'static [FeatureId] = &[
        FeatureId::AnalyzerMlEnabled,
        FeatureId::AnalyzerInjecguardEnabled,
        FeatureId::AnalyzerPiguardEnabled,
        FeatureId::AnalyzerJailbreakEnabled,
        FeatureId::EnforcementMode,
        FeatureId::BoundaryDefenseEnabled,
        FeatureId::BoundaryDefenseShadowMode,
        FeatureId::RateLimitingEnabled,
        FeatureId::CostCapsEnabled,
        FeatureId::OperatingPoint,
        FeatureId::OverDefence,
        FeatureId::LlmJudgeEnabled,
    ];

    /// Wire name as it appears in URLs, JSON, and Prometheus labels.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::AnalyzerMlEnabled => "analyzer_ml_enabled",
            Self::AnalyzerInjecguardEnabled => "analyzer_injecguard_enabled",
            Self::AnalyzerPiguardEnabled => "analyzer_piguard_enabled",
            Self::AnalyzerJailbreakEnabled => "analyzer_jailbreak_enabled",
            Self::EnforcementMode => "enforcement_mode",
            Self::BoundaryDefenseEnabled => "boundary_defense_enabled",
            Self::BoundaryDefenseShadowMode => "boundary_defense_shadow_mode",
            Self::RateLimitingEnabled => "rate_limiting_enabled",
            Self::CostCapsEnabled => "cost_caps_enabled",
            Self::OperatingPoint => "operating_point",
            Self::OverDefence => "over_defence",
            Self::LlmJudgeEnabled => "llm_judge_enabled",
        }
    }

    /// Kind of value this flag accepts over the wire.
    #[must_use]
    pub fn kind(&self) -> FeatureKind {
        match self {
            Self::EnforcementMode | Self::OperatingPoint => FeatureKind::String,
            _ => FeatureKind::Bool,
        }
    }

    /// Resolve a flag by wire name. Returns `None` for unknown names
    /// and for the always-on `analyzer_regex_enabled` (the API handler
    /// handles immutable names separately so it can return a distinct
    /// error category).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|id| id.name() == name)
    }

    /// Project the current value of this flag from a [`FeatureFlags`]
    /// snapshot.
    #[must_use]
    pub fn read(&self, flags: &FeatureFlags) -> FeatureValue {
        match self {
            Self::AnalyzerMlEnabled => FeatureValue::Bool(flags.analyzer_ml_enabled),
            Self::AnalyzerInjecguardEnabled => {
                FeatureValue::Bool(flags.analyzer_injecguard_enabled)
            }
            Self::AnalyzerPiguardEnabled => FeatureValue::Bool(flags.analyzer_piguard_enabled),
            Self::AnalyzerJailbreakEnabled => FeatureValue::Bool(flags.analyzer_jailbreak_enabled),
            Self::EnforcementMode => FeatureValue::String(flags.enforcement_mode.clone()),
            Self::BoundaryDefenseEnabled => FeatureValue::Bool(flags.boundary_defense_enabled),
            Self::BoundaryDefenseShadowMode => {
                FeatureValue::Bool(flags.boundary_defense_shadow_mode)
            }
            Self::RateLimitingEnabled => FeatureValue::Bool(flags.rate_limiting_enabled),
            Self::CostCapsEnabled => FeatureValue::Bool(flags.cost_caps_enabled),
            Self::OperatingPoint => FeatureValue::String(flags.operating_point.clone()),
            Self::OverDefence => FeatureValue::Bool(flags.over_defence),
            Self::LlmJudgeEnabled => FeatureValue::Bool(flags.llm_judge_enabled),
        }
    }
}

/// Untagged value accepted by `PUT /api/v1/config/features/:feature`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, PartialEq)]
#[serde(untagged)]
pub enum FeatureValue {
    Bool(bool),
    String(String),
}

impl FeatureValue {
    fn as_bool(&self) -> Option<bool> {
        match self {
            FeatureValue::Bool(b) => Some(*b),
            FeatureValue::String(_) => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            FeatureValue::String(s) => Some(s.as_str()),
            FeatureValue::Bool(_) => None,
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            FeatureValue::Bool(_) => "bool",
            FeatureValue::String(_) => "string",
        }
    }
}

/// Errors that can occur when validating or applying a feature mutation.
///
/// Map to HTTP status codes via [`ValidationError::http_status`]:
/// `UnknownFeature`, `WrongType`, `Immutable`, and `InvalidEnum` return
/// 400; `RuleViolation` returns 422.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("unknown feature: {0}")]
    UnknownFeature(String),
    #[error("feature '{feature}' expects {expected}, got {got}")]
    WrongType {
        feature: String,
        expected: &'static str,
        got: &'static str,
    },
    #[error("feature '{0}' is immutable")]
    Immutable(&'static str),
    #[error("invalid value '{value}' for '{feature}'; allowed: {allowed}")]
    InvalidEnum {
        feature: String,
        value: String,
        allowed: &'static str,
    },
    #[error("{0}")]
    RuleViolation(String),
}

impl ValidationError {
    /// HTTP status for the wire response.
    #[must_use]
    pub fn http_status(&self) -> StatusCode {
        match self {
            ValidationError::UnknownFeature(_)
            | ValidationError::WrongType { .. }
            | ValidationError::Immutable(_)
            | ValidationError::InvalidEnum { .. } => StatusCode::BAD_REQUEST,
            ValidationError::RuleViolation(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    /// Stable error category for the wire payload.
    #[must_use]
    pub fn error_type(&self) -> &'static str {
        match self {
            ValidationError::UnknownFeature(_) => "unknown_feature",
            ValidationError::WrongType { .. } => "wrong_type",
            ValidationError::Immutable(_) => "immutable",
            ValidationError::InvalidEnum { .. } => "invalid_value",
            ValidationError::RuleViolation(_) => "validation_error",
        }
    }
}

/// Convert an [`EnforcementMode`] to its lowercase wire string.
fn enforcement_mode_to_str(mode: &EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::Log => "log",
        EnforcementMode::Block => "block",
        EnforcementMode::Flag => "flag",
    }
}

/// Parse an enforcement mode wire string. Returns `InvalidEnum` for
/// values outside the contract.
fn parse_enforcement_mode(value: &str) -> Result<EnforcementMode, ValidationError> {
    match value {
        "log" => Ok(EnforcementMode::Log),
        "block" => Ok(EnforcementMode::Block),
        "flag" => Ok(EnforcementMode::Flag),
        other => Err(ValidationError::InvalidEnum {
            feature: "enforcement_mode".to_string(),
            value: other.to_string(),
            allowed: "log | block | flag",
        }),
    }
}

/// Convert an [`OperatingPoint`] to its lowercase wire string.
fn operating_point_to_str(point: &OperatingPoint) -> &'static str {
    match point {
        OperatingPoint::Balanced => "balanced",
        OperatingPoint::HighRecall => "high_recall",
        OperatingPoint::HighPrecision => "high_precision",
    }
}

/// Parse an operating point wire string. Returns `InvalidEnum` for
/// values outside the contract.
fn parse_operating_point(value: &str) -> Result<OperatingPoint, ValidationError> {
    match value {
        "balanced" => Ok(OperatingPoint::Balanced),
        "high_recall" => Ok(OperatingPoint::HighRecall),
        "high_precision" => Ok(OperatingPoint::HighPrecision),
        other => Err(ValidationError::InvalidEnum {
            feature: "operating_point".to_string(),
            value: other.to_string(),
            allowed: "balanced | high_recall | high_precision",
        }),
    }
}

impl FeatureFlags {
    /// Project the runtime feature-flag wire shape from a [`ProxyConfig`].
    #[must_use]
    pub fn from_config(config: &ProxyConfig) -> Self {
        Self {
            analyzer_ml_enabled: config.security_analysis.ml_enabled,
            analyzer_injecguard_enabled: config.security_analysis.injecguard_enabled,
            analyzer_piguard_enabled: config.security_analysis.piguard_enabled,
            analyzer_jailbreak_enabled: config.security_analysis.jailbreak_enabled,
            enforcement_mode: enforcement_mode_to_str(&config.enforcement.mode).to_string(),
            boundary_defense_enabled: config.boundary_defense.enabled,
            boundary_defense_shadow_mode: config.boundary_defense.shadow_mode,
            rate_limiting_enabled: config.rate_limiting.enabled,
            cost_caps_enabled: config.cost_caps.enabled,
            operating_point: operating_point_to_str(&config.security_analysis.operating_point)
                .to_string(),
            over_defence: config.security_analysis.over_defence,
            llm_judge_enabled: config.judge.enabled,
        }
    }

    /// Apply this flag set to the given config. Validates string enums
    /// and transition rules before mutating any field, so a single
    /// validation failure leaves the input config untouched.
    pub fn apply_to_config(&self, config: &mut ProxyConfig) -> Result<(), ValidationError> {
        // Validate the proposed snapshot first.
        validate_transition(self)?;
        let mode = parse_enforcement_mode(&self.enforcement_mode)?;
        let point = parse_operating_point(&self.operating_point)?;

        config.security_analysis.ml_enabled = self.analyzer_ml_enabled;
        config.security_analysis.injecguard_enabled = self.analyzer_injecguard_enabled;
        config.security_analysis.piguard_enabled = self.analyzer_piguard_enabled;
        config.security_analysis.jailbreak_enabled = self.analyzer_jailbreak_enabled;
        config.enforcement.mode = mode;
        config.boundary_defense.enabled = self.boundary_defense_enabled;
        config.boundary_defense.shadow_mode = self.boundary_defense_shadow_mode;
        config.rate_limiting.enabled = self.rate_limiting_enabled;
        config.cost_caps.enabled = self.cost_caps_enabled;
        config.security_analysis.operating_point = point;
        config.security_analysis.over_defence = self.over_defence;
        config.judge.enabled = self.llm_judge_enabled;
        Ok(())
    }
}

/// Apply a single named feature mutation to the config in place.
///
/// Returns the typed [`ValidationError`] so the API handler can map to
/// the correct HTTP status. Non-mutating: the caller passes a clone of
/// the live config (typically inside `ConfigHandle::update`'s mutator
/// closure) so failures leave the live state untouched.
pub fn apply_single(
    config: &mut ProxyConfig,
    feature: &str,
    value: FeatureValue,
) -> Result<(), ValidationError> {
    // The always-on regex analyzer is not in the `FeatureId` surface
    // (it is omitted from `FeatureFlags` entirely), so we catch
    // attempts to mutate it here for a clearer error category than
    // `UnknownFeature`.
    if feature == "analyzer_regex_enabled" {
        return Err(ValidationError::Immutable("analyzer_regex_enabled"));
    }
    let id = FeatureId::from_name(feature)
        .ok_or_else(|| ValidationError::UnknownFeature(feature.to_string()))?;
    apply_feature_id(config, id, value)
}

fn apply_feature_id(
    config: &mut ProxyConfig,
    id: FeatureId,
    value: FeatureValue,
) -> Result<(), ValidationError> {
    let name = id.name();
    match id {
        FeatureId::AnalyzerMlEnabled => {
            config.security_analysis.ml_enabled = require_bool(name, &value)?;
        }
        FeatureId::AnalyzerInjecguardEnabled => {
            config.security_analysis.injecguard_enabled = require_bool(name, &value)?;
        }
        FeatureId::AnalyzerPiguardEnabled => {
            config.security_analysis.piguard_enabled = require_bool(name, &value)?;
        }
        FeatureId::AnalyzerJailbreakEnabled => {
            config.security_analysis.jailbreak_enabled = require_bool(name, &value)?;
        }
        FeatureId::EnforcementMode => {
            config.enforcement.mode = parse_enforcement_mode(require_string(name, &value)?)?;
        }
        FeatureId::BoundaryDefenseEnabled => {
            config.boundary_defense.enabled = require_bool(name, &value)?;
            validate_transition_for_config(config)?;
        }
        FeatureId::BoundaryDefenseShadowMode => {
            config.boundary_defense.shadow_mode = require_bool(name, &value)?;
            validate_transition_for_config(config)?;
        }
        FeatureId::RateLimitingEnabled => {
            config.rate_limiting.enabled = require_bool(name, &value)?;
        }
        FeatureId::CostCapsEnabled => {
            config.cost_caps.enabled = require_bool(name, &value)?;
        }
        FeatureId::OperatingPoint => {
            config.security_analysis.operating_point =
                parse_operating_point(require_string(name, &value)?)?;
        }
        FeatureId::OverDefence => {
            config.security_analysis.over_defence = require_bool(name, &value)?;
        }
        FeatureId::LlmJudgeEnabled => {
            config.judge.enabled = require_bool(name, &value)?;
        }
    }
    Ok(())
}

fn require_bool(feature: &str, value: &FeatureValue) -> Result<bool, ValidationError> {
    value.as_bool().ok_or_else(|| ValidationError::WrongType {
        feature: feature.to_string(),
        expected: "bool",
        got: value.type_name(),
    })
}

fn require_string<'a>(feature: &str, value: &'a FeatureValue) -> Result<&'a str, ValidationError> {
    value.as_str().ok_or_else(|| ValidationError::WrongType {
        feature: feature.to_string(),
        expected: "string",
        got: value.type_name(),
    })
}

/// Cross-field invariant: `boundary_defense_shadow_mode` requires the
/// boundary defense to be enabled. Returns 422 when violated.
pub fn validate_transition(flags: &FeatureFlags) -> Result<(), ValidationError> {
    if flags.boundary_defense_shadow_mode && !flags.boundary_defense_enabled {
        return Err(ValidationError::RuleViolation(
            "boundary_defense_shadow_mode requires boundary_defense_enabled = true".to_string(),
        ));
    }
    Ok(())
}

fn validate_transition_for_config(config: &ProxyConfig) -> Result<(), ValidationError> {
    if config.boundary_defense.shadow_mode && !config.boundary_defense.enabled {
        return Err(ValidationError::RuleViolation(
            "boundary_defense_shadow_mode requires boundary_defense_enabled = true".to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sidecar overlay persistence (phase 3 of issue #42)
// ---------------------------------------------------------------------------

/// Errors emitted by the sidecar overlay load/write helpers.
#[derive(Debug, Error)]
pub enum OverlayError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error: {0}")]
    Parse(#[from] serde_yaml::Error),
}

/// Load the runtime feature-flag overlay from `path`.
///
/// Returns `Ok(None)` when the file does not exist (this is the
/// common "fresh install" case — the operator hasn't toggled anything
/// Hard ceiling on the sidecar overlay file size in bytes. The
/// `FeatureFlags` struct serializes to well under 2 KiB; a 64 KiB
/// cap leaves generous headroom for future fields while refusing to
/// process files whose size suggests corruption, pathological
/// symlinks (e.g. into `/dev/zero`), or an attempt to exhaust memory
/// at startup via a large YAML document. Issue #42 M3.
const OVERLAY_MAX_BYTES: u64 = 64 * 1024;

/// yet). Returns `Err` for other I/O or parse failures so the startup
/// path can surface a descriptive warning instead of silently ignoring
/// corrupted state.
pub fn load_runtime_overlay(path: &Path) -> Result<Option<FeatureFlags>, OverlayError> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(OverlayError::Io(e)),
    };
    if meta.len() > OVERLAY_MAX_BYTES {
        return Err(OverlayError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "runtime overlay file {} exceeds {OVERLAY_MAX_BYTES} byte cap (got {} bytes); \
                 refusing to parse as defence against billion-laughs-style resource exhaustion",
                path.display(),
                meta.len()
            ),
        )));
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let flags: FeatureFlags = serde_yaml::from_str(&contents)?;
            Ok(Some(flags))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(OverlayError::Io(e)),
    }
}

/// Write the runtime feature-flag overlay to `path` atomically via
/// `tempfile::NamedTempFile`.
///
/// `NamedTempFile::new_in` opens with `O_CREAT | O_EXCL` and a random
/// suffix, refusing to follow a pre-planted symlink at a deterministic
/// staging path (issue #42 H1). `persist` then does an atomic
/// `rename(2)` into place so a crash mid-flush cannot leave a torn
/// file for the next startup.
pub fn write_runtime_overlay(path: &Path, flags: &FeatureFlags) -> Result<(), OverlayError> {
    use std::io::Write;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    if !parent.exists() {
        std::fs::create_dir_all(&parent)?;
    }
    let yaml = serde_yaml::to_string(flags)?;
    let mut tmp = tempfile::NamedTempFile::new_in(&parent)?;
    tmp.write_all(yaml.as_bytes())?;
    tmp.as_file().sync_all()?;
    // `persist` consumes the NamedTempFile and performs an atomic
    // rename. On success the caller observes a fully-written file at
    // `path`; on failure the tempfile is preserved for manual recovery
    // but the target path is untouched.
    tmp.persist(path).map_err(|e| OverlayError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> ProxyConfig {
        ProxyConfig::default()
    }

    #[test]
    fn from_config_then_apply_roundtrips() {
        let mut original = defaults();
        original.security_analysis.ml_enabled = false;
        original.security_analysis.over_defence = true;
        original.boundary_defense.enabled = true;
        original.boundary_defense.shadow_mode = true;
        original.enforcement.mode = EnforcementMode::Block;
        original.security_analysis.operating_point = OperatingPoint::HighPrecision;
        original.cost_caps.enabled = true;
        original.rate_limiting.enabled = true;
        original.judge.enabled = true;

        let flags = FeatureFlags::from_config(&original);

        let mut clone = defaults();
        flags.apply_to_config(&mut clone).unwrap();
        let roundtrip = FeatureFlags::from_config(&clone);
        assert_eq!(flags, roundtrip);
    }

    #[test]
    fn apply_single_bool_success_per_field() {
        let mut cfg = defaults();
        apply_single(&mut cfg, "analyzer_ml_enabled", FeatureValue::Bool(false)).unwrap();
        assert!(!cfg.security_analysis.ml_enabled);
        apply_single(&mut cfg, "rate_limiting_enabled", FeatureValue::Bool(true)).unwrap();
        assert!(cfg.rate_limiting.enabled);
        apply_single(&mut cfg, "cost_caps_enabled", FeatureValue::Bool(true)).unwrap();
        assert!(cfg.cost_caps.enabled);
        apply_single(&mut cfg, "over_defence", FeatureValue::Bool(true)).unwrap();
        assert!(cfg.security_analysis.over_defence);
        apply_single(&mut cfg, "llm_judge_enabled", FeatureValue::Bool(true)).unwrap();
        assert!(cfg.judge.enabled);
    }

    #[test]
    fn apply_single_enforcement_mode_string_success() {
        let mut cfg = defaults();
        apply_single(
            &mut cfg,
            "enforcement_mode",
            FeatureValue::String("block".to_string()),
        )
        .unwrap();
        assert_eq!(cfg.enforcement.mode, EnforcementMode::Block);
    }

    #[test]
    fn apply_single_operating_point_string_success() {
        let mut cfg = defaults();
        apply_single(
            &mut cfg,
            "operating_point",
            FeatureValue::String("high_precision".to_string()),
        )
        .unwrap();
        assert_eq!(
            cfg.security_analysis.operating_point,
            OperatingPoint::HighPrecision
        );
    }

    #[test]
    fn apply_single_unknown_feature_returns_400() {
        let mut cfg = defaults();
        let err = apply_single(&mut cfg, "ghost_feature", FeatureValue::Bool(true)).unwrap_err();
        assert!(matches!(err, ValidationError::UnknownFeature(_)));
        assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn apply_single_immutable_regex_returns_400() {
        let mut cfg = defaults();
        let err = apply_single(
            &mut cfg,
            "analyzer_regex_enabled",
            FeatureValue::Bool(false),
        )
        .unwrap_err();
        assert!(matches!(err, ValidationError::Immutable(_)));
        assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn apply_single_wrong_type_returns_400() {
        let mut cfg = defaults();
        let err = apply_single(&mut cfg, "enforcement_mode", FeatureValue::Bool(true)).unwrap_err();
        assert!(matches!(err, ValidationError::WrongType { .. }));
        assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);

        let err = apply_single(
            &mut cfg,
            "analyzer_ml_enabled",
            FeatureValue::String("yes".to_string()),
        )
        .unwrap_err();
        assert!(matches!(err, ValidationError::WrongType { .. }));
    }

    #[test]
    fn apply_single_invalid_enum_returns_400() {
        let mut cfg = defaults();
        let err = apply_single(
            &mut cfg,
            "enforcement_mode",
            FeatureValue::String("monitor".to_string()),
        )
        .unwrap_err();
        assert!(matches!(err, ValidationError::InvalidEnum { .. }));
        assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);

        let err = apply_single(
            &mut cfg,
            "operating_point",
            FeatureValue::String("paranoid".to_string()),
        )
        .unwrap_err();
        assert!(matches!(err, ValidationError::InvalidEnum { .. }));
    }

    #[test]
    fn apply_single_shadow_without_enabled_returns_422() {
        let mut cfg = defaults();
        cfg.boundary_defense.enabled = false;
        let err = apply_single(
            &mut cfg,
            "boundary_defense_shadow_mode",
            FeatureValue::Bool(true),
        )
        .unwrap_err();
        assert!(matches!(err, ValidationError::RuleViolation(_)));
        assert_eq!(err.http_status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn apply_single_shadow_with_enabled_ok() {
        let mut cfg = defaults();
        cfg.boundary_defense.enabled = true;
        apply_single(
            &mut cfg,
            "boundary_defense_shadow_mode",
            FeatureValue::Bool(true),
        )
        .unwrap();
        assert!(cfg.boundary_defense.shadow_mode);
    }

    #[test]
    fn validate_transition_rejects_shadow_without_enabled() {
        let mut flags = FeatureFlags::from_config(&defaults());
        flags.boundary_defense_enabled = false;
        flags.boundary_defense_shadow_mode = true;
        let err = validate_transition(&flags).unwrap_err();
        assert!(matches!(err, ValidationError::RuleViolation(_)));
    }

    #[test]
    fn enforcement_mode_string_roundtrips_lowercase() {
        let mut cfg = defaults();
        cfg.enforcement.mode = EnforcementMode::Flag;
        let flags = FeatureFlags::from_config(&cfg);
        assert_eq!(flags.enforcement_mode, "flag");
        let mut next = defaults();
        flags.apply_to_config(&mut next).unwrap();
        assert_eq!(next.enforcement.mode, EnforcementMode::Flag);
    }

    #[test]
    fn operating_point_string_roundtrips_snake_case() {
        let mut cfg = defaults();
        cfg.security_analysis.operating_point = OperatingPoint::HighRecall;
        let flags = FeatureFlags::from_config(&cfg);
        assert_eq!(flags.operating_point, "high_recall");
    }

    // -- Sidecar overlay persistence --------------------------------------

    #[test]
    fn runtime_overlay_load_missing_file_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("no_such.yaml");
        let result = load_runtime_overlay(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn runtime_overlay_write_then_load_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.runtime.yaml");
        let mut cfg = defaults();
        cfg.enforcement.mode = EnforcementMode::Block;
        cfg.boundary_defense.enabled = true;
        cfg.boundary_defense.shadow_mode = true;
        let flags = FeatureFlags::from_config(&cfg);

        write_runtime_overlay(&path, &flags).unwrap();
        assert!(path.exists());

        let loaded = load_runtime_overlay(&path).unwrap().unwrap();
        assert_eq!(loaded, flags);
    }

    #[test]
    fn runtime_overlay_write_is_atomic_rename() {
        // Writing over an existing file must replace it atomically.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.runtime.yaml");
        let flags_a = FeatureFlags::from_config(&defaults());
        write_runtime_overlay(&path, &flags_a).unwrap();

        let mut cfg_b = defaults();
        cfg_b.cost_caps.enabled = true;
        let flags_b = FeatureFlags::from_config(&cfg_b);
        write_runtime_overlay(&path, &flags_b).unwrap();

        let loaded = load_runtime_overlay(&path).unwrap().unwrap();
        assert_eq!(loaded, flags_b);
        // NamedTempFile uses a randomised suffix; after persist the
        // only file in the parent should be the target itself, not a
        // left-over staging file. Enforce that explicitly.
        let parent = path.parent().unwrap();
        let lingering: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| *p != path)
            .collect();
        assert!(
            lingering.is_empty(),
            "unexpected lingering files after overlay persist: {:?}",
            lingering
        );
    }

    #[test]
    fn runtime_overlay_load_invalid_yaml_returns_err() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.runtime.yaml");
        std::fs::write(&path, "this: is: not: valid: yaml: [unclosed").unwrap();
        let err = load_runtime_overlay(&path).unwrap_err();
        assert!(matches!(err, OverlayError::Parse(_)));
    }

    #[test]
    fn runtime_overlay_load_oversize_file_returns_err() {
        // A 96 KiB file exceeds the OVERLAY_MAX_BYTES 64 KiB ceiling
        // and must be rejected without being parsed. Guards against
        // billion-laughs-style YAML resource exhaustion at startup.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.runtime.yaml");
        // Valid YAML mapping but padded with a comment that balloons
        // file size well past the cap.
        let payload = format!("analyzer_ml_enabled: false\n# {}\n", "x".repeat(96 * 1024));
        std::fs::write(&path, payload).unwrap();
        let err = load_runtime_overlay(&path).unwrap_err();
        match err {
            OverlayError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                assert!(e.to_string().contains("64 KiB") || e.to_string().contains("65536"));
            }
            other => panic!("expected Io(InvalidData), got {other:?}"),
        }
    }
}
