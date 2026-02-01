//! Heuristic feature extraction for feature-level fusion (ADR-013).
//!
//! Builds a fixed-size numeric feature vector from regex/heuristic analysis
//! results and raw text properties. This vector is concatenated with the
//! DeBERTa CLS embedding to form the input to the fusion classifier.
//!
//! # Feature Vector Layout (15 dimensions)
//!
//! | Index | Feature                          | Type    |
//! |-------|----------------------------------|---------|
//! | 0     | Flattery attack present          | Binary  |
//! | 1     | Urgency attack present           | Binary  |
//! | 2     | Roleplay attack present          | Binary  |
//! | 3     | Impersonation attack present     | Binary  |
//! | 4     | Covert attack present            | Binary  |
//! | 5     | Excuse attack present            | Binary  |
//! | 6     | Many-shot attack present         | Binary  |
//! | 7     | Repetition attack present        | Binary  |
//! | 8     | Number of injection patterns     | Numeric |
//! | 9     | Max injection confidence score   | Numeric |
//! | 10    | PII pattern count                | Numeric |
//! | 11    | Secret leakage count             | Numeric |
//! | 12    | Text length (normalised)         | Numeric |
//! | 13    | Special character ratio          | Numeric |
//! | 14    | Average word length              | Numeric |
//!
//! # Feature Gate
//!
//! This module is only available when the `ml` feature is enabled.

use llmtrace_core::SecurityFinding;

/// Total number of features in the heuristic feature vector.
pub const HEURISTIC_FEATURE_DIM: usize = 15;

/// Maximum text length used for normalisation (characters).
/// Texts longer than this are clamped to 1.0.
const MAX_TEXT_LENGTH: f32 = 10_000.0;

/// Attack category finding types mapped to feature vector indices 0–7.
const ATTACK_CATEGORIES: [&str; 8] = [
    "flattery_attack",
    "urgency_attack",
    "roleplay_attack",
    "impersonation_attack",
    "covert_attack",
    "excuse_attack",
    "many_shot_attack",
    "repetition_attack",
];

/// Injection-related finding types used for counting and max-confidence.
const INJECTION_TYPES: [&str; 5] = [
    "prompt_injection",
    "role_injection",
    "jailbreak",
    "encoding_attack",
    "ml_prompt_injection",
];

/// Extract a heuristic feature vector from security findings and raw text.
///
/// Returns a `Vec<f32>` of length [`HEURISTIC_FEATURE_DIM`].
pub fn extract_heuristic_features(findings: &[SecurityFinding], text: &str) -> Vec<f32> {
    let mut features = vec![0.0_f32; HEURISTIC_FEATURE_DIM];

    // --- Binary attack category features (indices 0–7) ---
    for (idx, category) in ATTACK_CATEGORIES.iter().enumerate() {
        if findings.iter().any(|f| f.finding_type == *category) {
            features[idx] = 1.0;
        }
    }

    // --- Number of injection patterns matched (index 8) ---
    let injection_count = findings
        .iter()
        .filter(|f| INJECTION_TYPES.contains(&f.finding_type.as_str()))
        .count();
    features[8] = injection_count as f32;

    // --- Max injection confidence score (index 9) ---
    let max_injection_confidence = findings
        .iter()
        .filter(|f| INJECTION_TYPES.contains(&f.finding_type.as_str()))
        .map(|f| f.confidence_score)
        .fold(0.0_f64, f64::max);
    features[9] = max_injection_confidence as f32;

    // --- PII pattern count (index 10) ---
    let pii_count = findings
        .iter()
        .filter(|f| f.finding_type == "pii_detected")
        .count();
    features[10] = pii_count as f32;

    // --- Secret leakage count (index 11) ---
    let secret_count = findings
        .iter()
        .filter(|f| f.finding_type == "secret_leakage" || f.finding_type == "data_leakage")
        .count();
    features[11] = secret_count as f32;

    // --- Text length normalised (index 12) ---
    features[12] = (text.len() as f32 / MAX_TEXT_LENGTH).min(1.0);

    // --- Special character ratio (index 13) ---
    if !text.is_empty() {
        let special_count = text
            .chars()
            .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
            .count();
        features[13] = special_count as f32 / text.len() as f32;
    }

    // --- Average word length (index 14) ---
    let words: Vec<&str> = text.split_whitespace().collect();
    if !words.is_empty() {
        let total_word_len: usize = words.iter().map(|w| w.len()).sum();
        // Normalise average word length to roughly [0, 1] range (assume max ~20 chars/word)
        features[14] = (total_word_len as f32 / words.len() as f32) / 20.0;
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

    #[test]
    fn test_feature_dim_constant() {
        assert_eq!(HEURISTIC_FEATURE_DIM, 15);
    }

    #[test]
    fn test_empty_findings_empty_text() {
        let features = extract_heuristic_features(&[], "");
        assert_eq!(features.len(), HEURISTIC_FEATURE_DIM);
        assert!(features.iter().all(|&f| f == 0.0));
    }

    #[test]
    fn test_attack_category_binary_features() {
        let findings = vec![
            SecurityFinding::new(
                SecuritySeverity::Medium,
                "flattery_attack".to_string(),
                "Flattery detected".to_string(),
                0.7,
            ),
            SecurityFinding::new(
                SecuritySeverity::Medium,
                "urgency_attack".to_string(),
                "Urgency detected".to_string(),
                0.8,
            ),
        ];
        let features = extract_heuristic_features(&findings, "test text");
        assert_eq!(features[0], 1.0); // flattery
        assert_eq!(features[1], 1.0); // urgency
        assert_eq!(features[2], 0.0); // roleplay (not present)
        assert_eq!(features[3], 0.0); // impersonation (not present)
    }

    #[test]
    fn test_injection_count_and_max_confidence() {
        let findings = vec![
            SecurityFinding::new(
                SecuritySeverity::High,
                "prompt_injection".to_string(),
                "Injection 1".to_string(),
                0.85,
            ),
            SecurityFinding::new(
                SecuritySeverity::High,
                "role_injection".to_string(),
                "Injection 2".to_string(),
                0.9,
            ),
            SecurityFinding::new(
                SecuritySeverity::Medium,
                "pii_detected".to_string(),
                "PII found".to_string(),
                0.7,
            ),
        ];
        let features = extract_heuristic_features(&findings, "test");
        assert_eq!(features[8], 2.0); // 2 injection patterns
        assert!((features[9] - 0.9).abs() < 0.001); // max confidence
        assert_eq!(features[10], 1.0); // 1 PII pattern
    }

    #[test]
    fn test_text_length_normalisation() {
        let short = extract_heuristic_features(&[], "hello");
        assert!(short[12] < 0.01); // 5 / 10000

        let long_text = "a".repeat(10_000);
        let long = extract_heuristic_features(&[], &long_text);
        assert!((long[12] - 1.0).abs() < 0.001);

        let very_long = "b".repeat(20_000);
        let capped = extract_heuristic_features(&[], &very_long);
        assert!((capped[12] - 1.0).abs() < 0.001); // clamped at 1.0
    }

    #[test]
    fn test_special_character_ratio() {
        let features = extract_heuristic_features(&[], "hello!!!");
        // 3 special chars out of 8 total chars
        assert!((features[13] - 3.0 / 8.0).abs() < 0.001);
    }

    #[test]
    fn test_average_word_length() {
        let features = extract_heuristic_features(&[], "hi there world");
        // words: "hi"(2) + "there"(5) + "world"(5) = 12 / 3 = 4.0 / 20.0 = 0.2
        assert!((features[14] - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_secret_leakage_count() {
        let findings = vec![
            SecurityFinding::new(
                SecuritySeverity::Critical,
                "secret_leakage".to_string(),
                "JWT token found".to_string(),
                0.95,
            ),
            SecurityFinding::new(
                SecuritySeverity::Critical,
                "data_leakage".to_string(),
                "Credential leak".to_string(),
                0.9,
            ),
        ];
        let features = extract_heuristic_features(&findings, "token here");
        assert_eq!(features[11], 2.0);
    }

    #[test]
    fn test_all_attack_categories_present() {
        let findings: Vec<SecurityFinding> = ATTACK_CATEGORIES
            .iter()
            .map(|cat| {
                SecurityFinding::new(
                    SecuritySeverity::Medium,
                    cat.to_string(),
                    format!("{cat} detected"),
                    0.7,
                )
            })
            .collect();
        let features = extract_heuristic_features(&findings, "text");
        // All 8 binary features should be 1.0
        for i in 0..8 {
            assert_eq!(features[i], 1.0, "Feature index {i} should be 1.0");
        }
    }
}
