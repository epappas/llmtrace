//! Convert a [`JudgeVerdict`] to a [`SecurityFinding`] so the judge
//! participates in the existing ensemble voting logic.
//!
//! The chosen `finding_type` is a stable wire key:
//! `"llm_judge_verdict"`. Operators can hook this key into the
//! enforcement config's `categories` block to opt into
//! block/flag/log behaviour on judge findings.

use llmtrace_core::{JudgeVerdict, SecurityFinding, SecuritySeverity};

/// Stable finding type produced by the judge. Referenced in
/// ensemble voting, enforcement category overrides, and the
/// operator-facing docs.
pub const JUDGE_FINDING_TYPE: &str = "llm_judge_verdict";

/// Map a 0..=100 security score onto a [`SecuritySeverity`] using the
/// bands documented in `docs/architecture/LLM_JUDGE.md` section 6.
#[must_use]
pub fn severity_from_score(score: u8) -> SecuritySeverity {
    // Scores above 100 are out of spec but may appear if a backend
    // disregards the schema; clamp to Critical so we don't silently
    // drop a loud signal.
    match score {
        0..=29 => SecuritySeverity::Low,
        30..=59 => SecuritySeverity::Medium,
        60..=79 => SecuritySeverity::High,
        _ => SecuritySeverity::Critical,
    }
}

/// Convert a judge verdict into a security finding carrying the
/// judge's voting metadata.
#[must_use]
pub fn verdict_to_finding(verdict: &JudgeVerdict) -> SecurityFinding {
    let severity = severity_from_score(verdict.security_score);
    let description = if verdict.reasoning.is_empty() {
        format!("LLM Judge verdict: {}", verdict.category)
    } else {
        verdict.reasoning.clone()
    };
    SecurityFinding::new(
        severity,
        JUDGE_FINDING_TYPE.to_string(),
        description,
        verdict.confidence,
    )
    .with_metadata("voting_result".to_string(), "llm_judge".to_string())
    .with_metadata("category".to_string(), verdict.category.clone())
    .with_metadata("model_used".to_string(), verdict.model_used.clone())
    .with_metadata(
        "recommended_action".to_string(),
        verdict.recommended_action.clone(),
    )
    .with_metadata("mode".to_string(), verdict.mode.as_str().to_string())
    .with_metadata(
        "security_score".to_string(),
        verdict.security_score.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use llmtrace_core::{JudgeMode, JudgeVerdict, TenantId};
    use uuid::Uuid;

    fn verdict_with_score(score: u8) -> JudgeVerdict {
        JudgeVerdict {
            id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            is_threat: score >= 50,
            category: "prompt_injection".to_string(),
            confidence: 0.9,
            security_score: score,
            recommended_action: "block".to_string(),
            reasoning: "test reasoning".to_string(),
            mode: JudgeMode::Inline,
            model_used: "security-judge-v1".to_string(),
            latency_ms: 123,
            prompt_tokens: Some(100),
            completion_tokens: Some(50),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn severity_bands_match_design_doc() {
        assert_eq!(severity_from_score(0), SecuritySeverity::Low);
        assert_eq!(severity_from_score(29), SecuritySeverity::Low);
        assert_eq!(severity_from_score(30), SecuritySeverity::Medium);
        assert_eq!(severity_from_score(59), SecuritySeverity::Medium);
        assert_eq!(severity_from_score(60), SecuritySeverity::High);
        assert_eq!(severity_from_score(79), SecuritySeverity::High);
        assert_eq!(severity_from_score(80), SecuritySeverity::Critical);
        assert_eq!(severity_from_score(100), SecuritySeverity::Critical);
    }

    #[test]
    fn verdict_to_finding_sets_type_and_metadata() {
        let v = verdict_with_score(85);
        let f = verdict_to_finding(&v);

        assert_eq!(f.finding_type, JUDGE_FINDING_TYPE);
        assert_eq!(f.severity, SecuritySeverity::Critical);
        assert!((f.confidence_score - 0.9).abs() < f64::EPSILON);
        assert_eq!(
            f.metadata.get("voting_result").map(String::as_str),
            Some("llm_judge")
        );
        assert_eq!(
            f.metadata.get("category").map(String::as_str),
            Some("prompt_injection")
        );
        assert_eq!(
            f.metadata.get("model_used").map(String::as_str),
            Some("security-judge-v1")
        );
        assert_eq!(
            f.metadata.get("recommended_action").map(String::as_str),
            Some("block")
        );
        assert_eq!(f.metadata.get("mode").map(String::as_str), Some("inline"));
        assert_eq!(
            f.metadata.get("security_score").map(String::as_str),
            Some("85")
        );
    }

    #[test]
    fn verdict_to_finding_uses_reasoning_as_description() {
        let v = verdict_with_score(65);
        let f = verdict_to_finding(&v);
        assert_eq!(f.description, "test reasoning");
    }

    #[test]
    fn verdict_to_finding_fallback_description_when_reasoning_empty() {
        let mut v = verdict_with_score(40);
        v.reasoning.clear();
        let f = verdict_to_finding(&v);
        assert_eq!(f.description, "LLM Judge verdict: prompt_injection");
    }

    #[test]
    fn verdict_to_finding_high_severity_requires_alert() {
        let v = verdict_with_score(80);
        let f = verdict_to_finding(&v);
        // SecurityFinding::new flags High+Critical for alerts.
        assert!(f.requires_alert);
    }

    #[test]
    fn verdict_to_finding_low_severity_does_not_require_alert() {
        let v = verdict_with_score(10);
        let f = verdict_to_finding(&v);
        assert!(!f.requires_alert);
    }
}
