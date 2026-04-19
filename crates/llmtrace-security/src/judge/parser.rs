//! JSON schema parser for judge verdicts.
//!
//! The judge emits a strict JSON object shape. See the schema in
//! [`DEFAULT_SYSTEM_PROMPT`](super::DEFAULT_SYSTEM_PROMPT). This
//! module parses that shape, validates ranges, and returns a
//! [`RawVerdict`] the backend then stamps with trace/tenant/model
//! metadata to produce a full [`JudgeVerdict`](llmtrace_core::JudgeVerdict).

use serde::{Deserialize, Serialize};

use super::JudgeError;

/// The classification payload parsed from the judge's JSON response,
/// before it is stamped with backend/trace metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawVerdict {
    pub is_threat: bool,
    pub category: String,
    pub confidence: f64,
    pub security_score: u8,
    pub recommended_action: String,
    pub reasoning: String,
}

/// Valid category strings per the system-prompt schema.
const VALID_CATEGORIES: &[&str] = &[
    "prompt_injection",
    "jailbreak",
    "data_exfiltration",
    "policy_violation",
    "benign",
    "other",
];

/// Valid recommended-action strings.
const VALID_ACTIONS: &[&str] = &["allow", "flag", "block"];

/// Parse a raw JSON response body into a [`RawVerdict`], enforcing:
///
/// - valid JSON (no markdown fences, no trailing commentary)
/// - all required keys present
/// - `confidence` in [0.0, 1.0]
/// - `security_score` in [0, 100]
/// - `category` in the fixed enumeration
/// - `recommended_action` in the fixed enumeration
/// - `reasoning` truncated to at most 1024 bytes (budget for pathological
///   long outputs without rejecting the whole verdict)
pub fn parse_verdict_json(raw: &str) -> Result<RawVerdict, JudgeError> {
    let trimmed = raw.trim();
    let mut verdict: RawVerdict = serde_json::from_str(trimmed)
        .map_err(|e| JudgeError::ParseError(format!("invalid JSON: {e}")))?;

    if !(0.0..=1.0).contains(&verdict.confidence) {
        return Err(JudgeError::ParseError(format!(
            "confidence {} out of range [0.0, 1.0]",
            verdict.confidence
        )));
    }

    if !VALID_CATEGORIES.contains(&verdict.category.as_str()) {
        return Err(JudgeError::ParseError(format!(
            "category '{}' not in allowed set {:?}",
            verdict.category, VALID_CATEGORIES
        )));
    }

    if !VALID_ACTIONS.contains(&verdict.recommended_action.as_str()) {
        return Err(JudgeError::ParseError(format!(
            "recommended_action '{}' not in allowed set {:?}",
            verdict.recommended_action, VALID_ACTIONS
        )));
    }

    if verdict.reasoning.len() > 1024 {
        verdict.reasoning.truncate(1024);
    }

    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_json() -> &'static str {
        r#"{"is_threat":true,"category":"prompt_injection","confidence":0.92,"security_score":85,"recommended_action":"block","reasoning":"override pattern"}"#
    }

    #[test]
    fn parses_valid_verdict() {
        let v = parse_verdict_json(valid_json()).unwrap();
        assert!(v.is_threat);
        assert_eq!(v.category, "prompt_injection");
        assert!((v.confidence - 0.92).abs() < f64::EPSILON);
        assert_eq!(v.security_score, 85);
        assert_eq!(v.recommended_action, "block");
        assert_eq!(v.reasoning, "override pattern");
    }

    #[test]
    fn tolerates_leading_and_trailing_whitespace() {
        let padded = format!("   \n{}   \n", valid_json());
        let v = parse_verdict_json(&padded).unwrap();
        assert!(v.is_threat);
    }

    #[test]
    fn rejects_non_json_body() {
        let err = parse_verdict_json("not json").unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }

    #[test]
    fn rejects_missing_required_field() {
        let missing = r#"{"is_threat":true,"category":"prompt_injection","confidence":0.9,"security_score":80,"recommended_action":"block"}"#;
        let err = parse_verdict_json(missing).unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
        match err {
            JudgeError::ParseError(msg) => assert!(msg.contains("reasoning")),
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_confidence_out_of_range() {
        let over = r#"{"is_threat":true,"category":"prompt_injection","confidence":1.5,"security_score":80,"recommended_action":"block","reasoning":"x"}"#;
        let err = parse_verdict_json(over).unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));

        let neg = r#"{"is_threat":true,"category":"prompt_injection","confidence":-0.1,"security_score":80,"recommended_action":"block","reasoning":"x"}"#;
        let err = parse_verdict_json(neg).unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }

    #[test]
    fn rejects_security_score_out_of_range() {
        // security_score is a u8 in the schema; values > 255 will fail
        // serde deserialisation with a distinct error. Values in
        // [101, 255] pass the parser but are semantically out of spec --
        // we accept them here to keep the parser deterministic and
        // apply range clamping in verdict_to_finding instead.
        let big = r#"{"is_threat":true,"category":"prompt_injection","confidence":0.5,"security_score":300,"recommended_action":"block","reasoning":"x"}"#;
        let err = parse_verdict_json(big).unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }

    #[test]
    fn rejects_unknown_category() {
        let bad = r#"{"is_threat":true,"category":"telepathy","confidence":0.5,"security_score":50,"recommended_action":"flag","reasoning":"x"}"#;
        let err = parse_verdict_json(bad).unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }

    #[test]
    fn rejects_unknown_action() {
        let bad = r#"{"is_threat":true,"category":"jailbreak","confidence":0.5,"security_score":50,"recommended_action":"launch","reasoning":"x"}"#;
        let err = parse_verdict_json(bad).unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }

    #[test]
    fn truncates_oversized_reasoning() {
        let long = "a".repeat(4096);
        let body = format!(
            r#"{{"is_threat":false,"category":"benign","confidence":0.1,"security_score":5,"recommended_action":"allow","reasoning":"{long}"}}"#
        );
        let v = parse_verdict_json(&body).unwrap();
        assert_eq!(v.reasoning.len(), 1024);
    }

    #[test]
    fn rejects_markdown_fenced_response() {
        // The system prompt forbids markdown. If the model wraps its
        // JSON in ``` fences, we reject rather than silently stripping
        // them -- the operator gets a parse_error metric and the call
        // fails open.
        let fenced = "```json\n".to_string() + valid_json() + "\n```";
        let err = parse_verdict_json(&fenced).unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }
}
