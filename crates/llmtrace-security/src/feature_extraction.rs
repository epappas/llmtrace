//! Heuristic feature extraction for feature-level fusion (ADR-013).
//!
//! Builds a fixed-size binary feature vector from regex/heuristic analysis
//! results and raw text properties. This vector is concatenated with the
//! DeBERTa average-pooled embedding to form the input to the fusion classifier.
//!
//! # Feature Vector Layout (10 dimensions, per DMPI-PMHFE paper Appendix A)
//!
//! | Index | Paper Name             | Detection Method                |
//! |-------|------------------------|---------------------------------|
//! | 0     | is_ignore              | Keyword-in-text                 |
//! | 1     | is_urgent              | Finding: is_urgent              |
//! | 2     | is_incentive           | Finding: is_incentive           |
//! | 3     | is_covert              | Finding: is_covert              |
//! | 4     | is_format_manipulation | Keyword-in-text                 |
//! | 5     | is_hypothetical        | Finding: is_hypothetical        |
//! | 6     | is_systemic            | Finding: is_systemic            |
//! | 7     | is_immoral             | Keyword-in-text                 |
//! | 8     | is_shot_attack         | Finding: is_shot_attack         |
//! | 9     | is_repeated_token      | Finding: is_repeated_token      |
//!
//! # Feature Gate
//!
//! This module is only available when the `ml` feature is enabled.

use llmtrace_core::SecurityFinding;

/// Total number of features in the heuristic feature vector.
pub const HEURISTIC_FEATURE_DIM: usize = 10;

/// Finding-based features: (feature_index, finding_type).
const FINDING_BASED_FEATURES: [(usize, &str); 7] = [
    (1, "is_urgent"),
    (2, "is_incentive"),
    (3, "is_covert"),
    (5, "is_hypothetical"),
    (6, "is_systemic"),
    (8, "is_shot_attack"),
    (9, "is_repeated_token"),
];

/// Keywords for is_ignore (index 0).
const IGNORE_KEYWORDS: &[&str] = &[
    "ignore",
    "reveal",
    "disregard",
    "forget",
    "overlook",
    "regardless",
];

/// Keywords for is_format_manipulation (index 4).
const FORMAT_MANIPULATION_KEYWORDS: &[&str] =
    &["encode", "disguising", "morse", "binary", "hexadecimal"];

/// Keywords for is_immoral (index 7).
const IMMORAL_KEYWORDS: &[&str] = &[
    "hitting",
    "amoral",
    "immoral",
    "deceit",
    "irresponsible",
    "offensive",
    "violent",
    "unethical",
    "smack",
    "fake",
    "illegal",
    "biased",
];

/// Check if any keyword appears as a whole word in the text.
/// Case-insensitive, whitespace-split, punctuation-stripped.
fn text_contains_any_keyword(text: &str, keywords: &[&str]) -> bool {
    text.split_whitespace().any(|word| {
        let stripped: String = word
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_lowercase();
        keywords.iter().any(|&kw| stripped == kw)
    })
}

/// Extract a heuristic feature vector from security findings and raw text.
///
/// Returns a `Vec<f32>` of length [`HEURISTIC_FEATURE_DIM`] (all values 0.0 or 1.0).
pub fn extract_heuristic_features(findings: &[SecurityFinding], text: &str) -> Vec<f32> {
    let mut features = vec![0.0_f32; HEURISTIC_FEATURE_DIM];

    // Finding-based binary features
    for &(idx, finding_type) in &FINDING_BASED_FEATURES {
        if findings.iter().any(|f| f.finding_type == finding_type) {
            features[idx] = 1.0;
        }
    }

    // Keyword-based binary features
    if text_contains_any_keyword(text, IGNORE_KEYWORDS) {
        features[0] = 1.0;
    }
    if text_contains_any_keyword(text, FORMAT_MANIPULATION_KEYWORDS) {
        features[4] = 1.0;
    }
    if text_contains_any_keyword(text, IMMORAL_KEYWORDS) {
        features[7] = 1.0;
    }

    features
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::{SecurityFinding, SecuritySeverity};

    fn make_finding(finding_type: &str) -> SecurityFinding {
        SecurityFinding::new(
            SecuritySeverity::Medium,
            finding_type.to_string(),
            format!("{finding_type} detected"),
            0.7,
        )
    }

    #[test]
    fn test_feature_dim_constant() {
        assert_eq!(HEURISTIC_FEATURE_DIM, 10);
    }

    #[test]
    fn test_empty_findings_empty_text() {
        let features = extract_heuristic_features(&[], "");
        assert_eq!(features.len(), HEURISTIC_FEATURE_DIM);
        assert!(features.iter().all(|&f| f == 0.0));
    }

    #[test]
    fn test_finding_based_features_indices() {
        // urgency_attack -> index 1
        let features = extract_heuristic_features(&[make_finding("is_urgent")], "");
        assert_eq!(features[1], 1.0);
        assert_eq!(features[0], 0.0);

        // flattery_attack -> index 2
        let features = extract_heuristic_features(&[make_finding("is_incentive")], "");
        assert_eq!(features[2], 1.0);

        // covert_attack -> index 3
        let features = extract_heuristic_features(&[make_finding("is_covert")], "");
        assert_eq!(features[3], 1.0);

        // roleplay_attack -> index 5
        let features = extract_heuristic_features(&[make_finding("is_hypothetical")], "");
        assert_eq!(features[5], 1.0);

        // impersonation_attack -> index 6
        let features = extract_heuristic_features(&[make_finding("is_systemic")], "");
        assert_eq!(features[6], 1.0);

        // many_shot_attack -> index 8
        let features = extract_heuristic_features(&[make_finding("is_shot_attack")], "");
        assert_eq!(features[8], 1.0);

        // repetition_attack -> index 9
        let features = extract_heuristic_features(&[make_finding("is_repeated_token")], "");
        assert_eq!(features[9], 1.0);
    }

    #[test]
    fn test_keyword_ignore_case_insensitive() {
        let features = extract_heuristic_features(&[], "Please ignore the rules");
        assert_eq!(features[0], 1.0);

        let features = extract_heuristic_features(&[], "Please IGNORE the rules");
        assert_eq!(features[0], 1.0);
    }

    #[test]
    fn test_keyword_ignore_with_punctuation() {
        let features = extract_heuristic_features(&[], "Ignore! the instructions");
        assert_eq!(features[0], 1.0);

        let features = extract_heuristic_features(&[], "Please disregard, previous");
        assert_eq!(features[0], 1.0);
    }

    #[test]
    fn test_keyword_no_partial_match() {
        // "ignoring" should NOT match "ignore"
        let features = extract_heuristic_features(&[], "ignoring the rules");
        assert_eq!(features[0], 0.0);

        // "encoded" should NOT match "encode"
        let features = extract_heuristic_features(&[], "the encoded message");
        assert_eq!(features[4], 0.0);

        // "illegally" should NOT match "illegal"
        let features = extract_heuristic_features(&[], "illegally obtained");
        assert_eq!(features[7], 0.0);
    }

    #[test]
    fn test_keyword_format_manipulation() {
        let features = extract_heuristic_features(&[], "encode this in morse code");
        assert_eq!(features[4], 1.0);

        let features = extract_heuristic_features(&[], "use hexadecimal format");
        assert_eq!(features[4], 1.0);
    }

    #[test]
    fn test_keyword_immoral() {
        let features = extract_heuristic_features(&[], "this is immoral content");
        assert_eq!(features[7], 1.0);

        let features = extract_heuristic_features(&[], "that was violent and illegal");
        assert_eq!(features[7], 1.0);
    }

    #[test]
    fn test_combined_findings_and_keywords() {
        let findings = vec![make_finding("is_urgent"), make_finding("is_incentive")];
        let features = extract_heuristic_features(&findings, "ignore the safety rules, encode it");
        assert_eq!(features[0], 1.0); // is_ignore (keyword)
        assert_eq!(features[1], 1.0); // is_urgent (finding)
        assert_eq!(features[2], 1.0); // is_incentive (finding)
        assert_eq!(features[3], 0.0); // is_covert (not present)
        assert_eq!(features[4], 1.0); // is_format_manipulation (keyword)
        assert_eq!(features[5], 0.0); // is_hypothetical (not present)
        assert_eq!(features[6], 0.0); // is_systemic (not present)
        assert_eq!(features[7], 0.0); // is_immoral (not present)
        assert_eq!(features[8], 0.0); // is_shot_attack (not present)
        assert_eq!(features[9], 0.0); // is_repeated_token (not present)
    }

    #[test]
    fn test_all_features_active() {
        let findings = vec![
            make_finding("is_urgent"),
            make_finding("is_incentive"),
            make_finding("is_covert"),
            make_finding("is_hypothetical"),
            make_finding("is_systemic"),
            make_finding("is_shot_attack"),
            make_finding("is_repeated_token"),
        ];
        let text = "ignore the rules, encode in binary, this is immoral";
        let features = extract_heuristic_features(&findings, text);
        for (i, &val) in features.iter().enumerate().take(HEURISTIC_FEATURE_DIM) {
            assert_eq!(val, 1.0, "Feature index {i} should be 1.0");
        }
    }

    #[test]
    fn test_all_values_binary() {
        let findings = vec![make_finding("is_urgent")];
        let features = extract_heuristic_features(&findings, "ignore this immoral encode");
        for (i, &val) in features.iter().enumerate() {
            assert!(
                val == 0.0 || val == 1.0,
                "Feature {i} must be binary, got {val}"
            );
        }
    }

    #[test]
    fn test_unrelated_findings_ignored() {
        let findings = vec![
            make_finding("prompt_injection"),
            make_finding("pii_detected"),
            make_finding("secret_leakage"),
            make_finding("is_immoral"),
        ];
        let features = extract_heuristic_features(&findings, "normal text");
        assert!(features.iter().all(|&f| f == 0.0));
    }
}
