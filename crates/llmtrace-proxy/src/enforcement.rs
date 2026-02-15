//! Pre-request security enforcement.
//!
//! Runs security analysis on the request before it is forwarded upstream.
//! Based on the enforcement config, the proxy can log (default), block (403),
//! or flag (forward + response headers).

use axum::body::Body;
use axum::http::{Response, StatusCode};
use llmtrace_core::{
    AnalysisContext, AnalysisDepth, EnforcementConfig, EnforcementMode, SecurityAnalyzer,
    SecurityFinding,
};
use std::sync::Arc;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// Outcome of enforcement evaluation.
pub enum EnforcementDecision {
    /// Allow the request through.
    Allow,
    /// Block the request — return 403.
    Block {
        reason: String,
        findings: Vec<SecurityFinding>,
    },
    /// Forward to upstream but attach metadata headers to the response.
    Flag { findings: Vec<SecurityFinding> },
}

// ---------------------------------------------------------------------------
// Decision logic (pure function, no IO)
// ---------------------------------------------------------------------------

/// Evaluate enforcement rules against a set of findings.
///
/// Filters by min_severity and min_confidence, then resolves per-category
/// overrides before falling back to the default mode.
/// Block wins over Flag; Flag wins over Log.
pub fn evaluate_enforcement(
    findings: &[SecurityFinding],
    config: &EnforcementConfig,
) -> EnforcementDecision {
    let mut block_findings: Vec<SecurityFinding> = Vec::new();
    let mut flag_findings: Vec<SecurityFinding> = Vec::new();

    for finding in findings {
        if finding.severity < config.min_severity {
            continue;
        }
        if finding.confidence_score < config.min_confidence {
            continue;
        }

        let mode = resolve_mode(finding, config);
        match mode {
            EnforcementMode::Block => block_findings.push(finding.clone()),
            EnforcementMode::Flag => flag_findings.push(finding.clone()),
            EnforcementMode::Log => {}
        }
    }

    if !block_findings.is_empty() {
        let reason = block_findings
            .iter()
            .map(|f| format!("{}: {}", f.finding_type, f.description))
            .collect::<Vec<_>>()
            .join("; ");
        return EnforcementDecision::Block {
            reason,
            findings: block_findings,
        };
    }

    if !flag_findings.is_empty() {
        return EnforcementDecision::Flag {
            findings: flag_findings,
        };
    }

    EnforcementDecision::Allow
}

/// Resolve the enforcement mode for a single finding.
/// Category override takes precedence over default mode.
fn resolve_mode(finding: &SecurityFinding, config: &EnforcementConfig) -> EnforcementMode {
    for cat in &config.categories {
        if cat.finding_type == finding.finding_type {
            return cat.action.clone();
        }
    }
    config.mode.clone()
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

/// Build a 403 Forbidden response for blocked requests.
pub fn blocked_response(reason: &str, findings: &[SecurityFinding]) -> Response<Body> {
    let finding_summaries: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "type": f.finding_type,
                "severity": format!("{}", f.severity),
                "confidence": f.confidence_score,
                "description": f.description,
            })
        })
        .collect();

    let body = serde_json::json!({
        "error": {
            "message": format!("Request blocked by security enforcement: {reason}"),
            "type": "security_enforcement_blocked",
            "findings": finding_summaries,
        }
    });

    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Format findings for the `X-LLMTrace-Findings` response header.
pub fn findings_header_value(findings: &[SecurityFinding]) -> String {
    findings
        .iter()
        .map(|f| format!("{}:{:.2}", f.finding_type, f.confidence_score))
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/// Run pre-request enforcement analysis.
///
/// Fail-open: returns `Allow` on any error or timeout.
pub async fn run_enforcement(
    analysis_text: &str,
    context: &AnalysisContext,
    config: &EnforcementConfig,
    full_analyzer: &Arc<dyn SecurityAnalyzer>,
    fast_analyzer: &Arc<dyn SecurityAnalyzer>,
) -> EnforcementDecision {
    // Log mode with no per-category overrides = skip analysis entirely
    if config.mode == EnforcementMode::Log && config.categories.is_empty() {
        return EnforcementDecision::Allow;
    }

    if analysis_text.is_empty() {
        return EnforcementDecision::Allow;
    }

    let analyzer: &Arc<dyn SecurityAnalyzer> = match config.analysis_depth {
        AnalysisDepth::Fast => fast_analyzer,
        AnalysisDepth::Full => full_analyzer,
    };

    let timeout = std::time::Duration::from_millis(config.timeout_ms);
    let result =
        tokio::time::timeout(timeout, analyzer.analyze_request(analysis_text, context)).await;

    let findings = match result {
        Ok(Ok(findings)) => findings,
        Ok(Err(e)) => {
            warn!("Enforcement analysis failed (fail-open): {e}");
            return EnforcementDecision::Allow;
        }
        Err(_) => {
            warn!(
                timeout_ms = config.timeout_ms,
                "Enforcement analysis timed out (fail-open)"
            );
            return EnforcementDecision::Allow;
        }
    };

    if findings.is_empty() {
        return EnforcementDecision::Allow;
    }

    info!(
        finding_count = findings.len(),
        "Enforcement pre-analysis detected findings"
    );

    evaluate_enforcement(&findings, config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::{CategoryEnforcement, SecuritySeverity};

    fn make_finding(
        finding_type: &str,
        severity: SecuritySeverity,
        confidence: f64,
    ) -> SecurityFinding {
        SecurityFinding::new(
            severity,
            finding_type.to_string(),
            format!("Test {finding_type}"),
            confidence,
        )
    }

    fn default_config(mode: EnforcementMode) -> EnforcementConfig {
        EnforcementConfig {
            mode,
            min_severity: SecuritySeverity::High,
            min_confidence: 0.8,
            ..EnforcementConfig::default()
        }
    }

    #[test]
    fn test_allow_when_no_findings() {
        let config = default_config(EnforcementMode::Block);
        let decision = evaluate_enforcement(&[], &config);
        assert!(matches!(decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_allow_when_below_min_severity() {
        let config = default_config(EnforcementMode::Block);
        let findings = vec![make_finding("prompt_injection", SecuritySeverity::Low, 0.9)];
        let decision = evaluate_enforcement(&findings, &config);
        assert!(matches!(decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_allow_when_below_min_confidence() {
        let config = default_config(EnforcementMode::Block);
        let findings = vec![make_finding(
            "prompt_injection",
            SecuritySeverity::High,
            0.5,
        )];
        let decision = evaluate_enforcement(&findings, &config);
        assert!(matches!(decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_block_when_finding_matches() {
        let config = default_config(EnforcementMode::Block);
        let findings = vec![make_finding(
            "prompt_injection",
            SecuritySeverity::High,
            0.9,
        )];
        let decision = evaluate_enforcement(&findings, &config);
        assert!(matches!(decision, EnforcementDecision::Block { .. }));
    }

    #[test]
    fn test_flag_when_finding_matches() {
        let config = default_config(EnforcementMode::Flag);
        let findings = vec![make_finding(
            "prompt_injection",
            SecuritySeverity::High,
            0.9,
        )];
        let decision = evaluate_enforcement(&findings, &config);
        assert!(matches!(decision, EnforcementDecision::Flag { .. }));
    }

    #[test]
    fn test_log_mode_allows_everything() {
        let config = default_config(EnforcementMode::Log);
        let findings = vec![make_finding(
            "prompt_injection",
            SecuritySeverity::Critical,
            1.0,
        )];
        let decision = evaluate_enforcement(&findings, &config);
        assert!(matches!(decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_block_wins_over_flag() {
        let config = EnforcementConfig {
            mode: EnforcementMode::Flag,
            categories: vec![CategoryEnforcement {
                finding_type: "shell_injection".to_string(),
                action: EnforcementMode::Block,
            }],
            min_severity: SecuritySeverity::High,
            min_confidence: 0.8,
            ..EnforcementConfig::default()
        };
        let findings = vec![
            make_finding("prompt_injection", SecuritySeverity::High, 0.9),
            make_finding("shell_injection", SecuritySeverity::High, 0.9),
        ];
        let decision = evaluate_enforcement(&findings, &config);
        assert!(matches!(decision, EnforcementDecision::Block { .. }));
    }

    #[test]
    fn test_category_override_takes_precedence() {
        let config = EnforcementConfig {
            mode: EnforcementMode::Block,
            categories: vec![CategoryEnforcement {
                finding_type: "data_leakage".to_string(),
                action: EnforcementMode::Log,
            }],
            min_severity: SecuritySeverity::High,
            min_confidence: 0.8,
            ..EnforcementConfig::default()
        };
        // data_leakage has category override to Log, so should be allowed
        let findings = vec![make_finding("data_leakage", SecuritySeverity::High, 0.9)];
        let decision = evaluate_enforcement(&findings, &config);
        assert!(matches!(decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_blocked_response_format() {
        let findings = vec![make_finding(
            "prompt_injection",
            SecuritySeverity::High,
            0.9,
        )];
        let resp = blocked_response("test reason", &findings);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_findings_header_value() {
        let findings = vec![
            make_finding("prompt_injection", SecuritySeverity::High, 0.95),
            make_finding("jailbreak", SecuritySeverity::Medium, 0.80),
        ];
        let value = findings_header_value(&findings);
        assert_eq!(value, "prompt_injection:0.95,jailbreak:0.80");
    }
}
