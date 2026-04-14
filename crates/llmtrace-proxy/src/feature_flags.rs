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
//! (PLUMB-CHEAP). The store-only `llm_judge_enabled` flag round-trips
//! through the config but no subsystem consumes it; issue #43 will wire
//! it through.

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
    /// Store-only placeholder for the future LLM Judge analysis tier
    /// (issue #43). PUTs to this flag round-trip through the runtime
    /// config but no subsystem consumes the value yet.
    pub llm_judge_enabled: bool,
}

/// Untagged value accepted by `PUT /api/v1/config/features/:feature`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
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
            llm_judge_enabled: config.llm_judge_enabled,
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
        config.llm_judge_enabled = self.llm_judge_enabled;
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
    match feature {
        "analyzer_regex_enabled" => Err(ValidationError::Immutable("analyzer_regex_enabled")),
        "analyzer_ml_enabled" => {
            let v = require_bool(feature, &value)?;
            config.security_analysis.ml_enabled = v;
            Ok(())
        }
        "analyzer_injecguard_enabled" => {
            let v = require_bool(feature, &value)?;
            config.security_analysis.injecguard_enabled = v;
            Ok(())
        }
        "analyzer_piguard_enabled" => {
            let v = require_bool(feature, &value)?;
            config.security_analysis.piguard_enabled = v;
            Ok(())
        }
        "analyzer_jailbreak_enabled" => {
            let v = require_bool(feature, &value)?;
            config.security_analysis.jailbreak_enabled = v;
            Ok(())
        }
        "enforcement_mode" => {
            let s = require_string(feature, &value)?;
            config.enforcement.mode = parse_enforcement_mode(s)?;
            Ok(())
        }
        "boundary_defense_enabled" => {
            let v = require_bool(feature, &value)?;
            config.boundary_defense.enabled = v;
            // Re-validate transition: shadow_mode without enabled is invalid.
            validate_transition_for_config(config)?;
            Ok(())
        }
        "boundary_defense_shadow_mode" => {
            let v = require_bool(feature, &value)?;
            config.boundary_defense.shadow_mode = v;
            validate_transition_for_config(config)?;
            Ok(())
        }
        "rate_limiting_enabled" => {
            let v = require_bool(feature, &value)?;
            config.rate_limiting.enabled = v;
            Ok(())
        }
        "cost_caps_enabled" => {
            let v = require_bool(feature, &value)?;
            config.cost_caps.enabled = v;
            Ok(())
        }
        "operating_point" => {
            let s = require_string(feature, &value)?;
            config.security_analysis.operating_point = parse_operating_point(s)?;
            Ok(())
        }
        "over_defence" => {
            let v = require_bool(feature, &value)?;
            config.security_analysis.over_defence = v;
            Ok(())
        }
        "llm_judge_enabled" => {
            let v = require_bool(feature, &value)?;
            config.llm_judge_enabled = v;
            Ok(())
        }
        unknown => Err(ValidationError::UnknownFeature(unknown.to_string())),
    }
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
/// yet). Returns `Err` for other I/O or parse failures so the startup
/// path can surface a descriptive warning instead of silently ignoring
/// corrupted state.
pub fn load_runtime_overlay(path: &Path) -> Result<Option<FeatureFlags>, OverlayError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let flags: FeatureFlags = serde_yaml::from_str(&contents)?;
            Ok(Some(flags))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(OverlayError::Io(e)),
    }
}

/// Write the runtime feature-flag overlay to `path` atomically.
///
/// The serialized YAML is first staged to `<path>.tmp` and then
/// renamed into place so a crash mid-flush cannot leave a torn file
/// for the next startup.
pub fn write_runtime_overlay(path: &Path, flags: &FeatureFlags) -> Result<(), OverlayError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("yaml.tmp");
    let yaml = serde_yaml::to_string(flags)?;
    std::fs::write(&tmp, yaml)?;
    std::fs::rename(&tmp, path)?;
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
        original.llm_judge_enabled = true;

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
        assert!(cfg.llm_judge_enabled);
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
        // No stray tmp file left behind.
        let tmp_path = path.with_extension("yaml.tmp");
        assert!(!tmp_path.exists());
    }

    #[test]
    fn runtime_overlay_load_invalid_yaml_returns_err() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.runtime.yaml");
        std::fs::write(&path, "this: is: not: valid: yaml: [unclosed").unwrap();
        let err = load_runtime_overlay(&path).unwrap_err();
        assert!(matches!(err, OverlayError::Parse(_)));
    }
}
