//! Output analysis module for LLM response content.
//!
//! Provides [`OutputAnalyzer`] which runs multiple safety checks on LLM response
//! content including:
//! - Toxicity detection (via [`ToxicityDetector`])
//! - Hallucination detection (via [`HallucinationDetector`])
//! - PII leakage detection (via [`RegexSecurityAnalyzer`])
//! - Secret scanning (via [`RegexSecurityAnalyzer`])
//!
//! All findings are tagged with `"output_safety"` metadata for easy filtering.
//!
//! # Feature Gate
//!
//! This module is only available when the `ml` feature is enabled (for toxicity
//! and hallucination detection). The PII and secret scanning components use the
//! regex analyzer which is always available.

use llmtrace_core::{OutputSafetyConfig, Result, SecurityFinding};

use crate::hallucination_detector::HallucinationDetector;
use crate::toxicity_detector::ToxicityDetector;
use crate::RegexSecurityAnalyzer;

// ---------------------------------------------------------------------------
// OutputAnalysisResult
// ---------------------------------------------------------------------------

/// Result of analysing LLM output content for safety issues.
#[derive(Debug, Clone)]
pub struct OutputAnalysisResult {
    /// All security findings from output analysis.
    pub findings: Vec<SecurityFinding>,
    /// Whether any critical toxicity was detected (triggers blocking if configured).
    pub has_critical_toxicity: bool,
    /// Overall safety score (0.0 = safe, 1.0 = most dangerous).
    pub max_toxicity_score: f32,
    /// Overall hallucination score (0.0 = hallucinated, 1.0 = consistent).
    /// `None` if hallucination detection was disabled or skipped.
    pub hallucination_score: Option<f32>,
}

// ---------------------------------------------------------------------------
// OutputAnalyzer
// ---------------------------------------------------------------------------

/// Composite output safety analyzer that runs toxicity detection, PII scanning,
/// and secret scanning on LLM response content.
///
/// # Example
///
/// ```no_run
/// use llmtrace_security::output_analyzer::OutputAnalyzer;
/// use llmtrace_core::OutputSafetyConfig;
///
/// # async fn example() {
/// let config = OutputSafetyConfig::default();
/// let analyzer = OutputAnalyzer::new(&config).await.unwrap();
/// let result = analyzer.analyze_output("Some LLM response text");
/// # }
/// ```
pub struct OutputAnalyzer {
    /// Toxicity detector (ML or keyword fallback).
    toxicity_detector: Option<ToxicityDetector>,
    /// Hallucination detector (ML or heuristic fallback).
    hallucination_detector: Option<HallucinationDetector>,
    /// Regex-based analyzer for PII and secret scanning.
    regex_analyzer: RegexSecurityAnalyzer,
    /// Configuration.
    config: OutputSafetyConfig,
}

impl OutputAnalyzer {
    /// Create a new output analyzer from configuration.
    ///
    /// Loads the toxicity and hallucination models if enabled, and initialises
    /// the regex analyzer for PII and secret scanning.
    pub async fn new(config: &OutputSafetyConfig) -> Result<Self> {
        let toxicity_detector = if config.toxicity_enabled {
            Some(ToxicityDetector::new(config).await?)
        } else {
            None
        };

        let hallucination_detector = if config.hallucination_enabled {
            Some(HallucinationDetector::new(config).await?)
        } else {
            None
        };

        let regex_analyzer = RegexSecurityAnalyzer::new()?;

        Ok(Self {
            toxicity_detector,
            hallucination_detector,
            regex_analyzer,
            config: config.clone(),
        })
    }

    /// Create an analyzer with keyword/heuristic-based fallbacks (no ML model download).
    ///
    /// Useful for testing or environments without network access.
    #[must_use]
    pub fn new_with_fallback(config: &OutputSafetyConfig) -> Self {
        let toxicity_detector = if config.toxicity_enabled {
            Some(ToxicityDetector::new_fallback(config.toxicity_threshold))
        } else {
            None
        };

        let hallucination_detector = if config.hallucination_enabled {
            Some(HallucinationDetector::new_fallback(
                config.hallucination_threshold,
                config.hallucination_min_response_length,
            ))
        } else {
            None
        };

        Self {
            toxicity_detector,
            hallucination_detector,
            regex_analyzer: RegexSecurityAnalyzer::default(),
            config: config.clone(),
        }
    }

    /// Analyse LLM response text for safety issues.
    ///
    /// Runs:
    /// 1. Toxicity detection (if enabled)
    /// 2. PII leakage detection
    /// 3. Secret scanning / data leakage detection
    ///
    /// Note: This method does not run hallucination detection because it
    /// requires the original prompt. Use [`analyze_output_with_prompt`] to
    /// include hallucination checking.
    ///
    /// Returns an [`OutputAnalysisResult`] with all findings tagged as output safety.
    pub fn analyze_output(&self, response_text: &str) -> OutputAnalysisResult {
        self.analyze_output_with_prompt(None, response_text)
    }

    /// Analyse LLM response text for safety issues with the original prompt.
    ///
    /// Runs:
    /// 1. Toxicity detection (if enabled)
    /// 2. Hallucination detection (if enabled and prompt is provided)
    /// 3. PII leakage detection
    /// 4. Secret scanning / data leakage detection
    ///
    /// Returns an [`OutputAnalysisResult`] with all findings tagged as output safety.
    pub fn analyze_output_with_prompt(
        &self,
        prompt: Option<&str>,
        response_text: &str,
    ) -> OutputAnalysisResult {
        if !self.config.enabled || response_text.is_empty() {
            return OutputAnalysisResult {
                findings: Vec::new(),
                has_critical_toxicity: false,
                max_toxicity_score: 0.0,
                hallucination_score: None,
            };
        }

        let mut all_findings: Vec<SecurityFinding> = Vec::new();
        let mut has_critical_toxicity = false;
        let mut max_toxicity_score: f32 = 0.0;
        let mut hallucination_score: Option<f32> = None;

        // 1. Toxicity detection
        if let Some(ref detector) = self.toxicity_detector {
            let toxicity_findings =
                detector.detect_toxicity(response_text, self.config.toxicity_threshold);

            for tf in &toxicity_findings {
                if tf.score > max_toxicity_score {
                    max_toxicity_score = tf.score;
                }
                if tf.exceeds_threshold
                    && (tf.category == "severe_toxic" || tf.category == "threat" || tf.score >= 0.9)
                {
                    has_critical_toxicity = true;
                }
            }

            let security_findings =
                ToxicityDetector::findings_to_security_findings(&toxicity_findings);
            all_findings.extend(security_findings);
        }

        // 2. Hallucination detection (after toxicity, only when prompt is available)
        if let (Some(ref detector), Some(prompt_text)) = (&self.hallucination_detector, prompt) {
            let result = detector.detect(prompt_text, response_text);
            if !result.skipped {
                hallucination_score = Some(result.overall_score);
            }
            let hallucination_findings =
                HallucinationDetector::result_to_security_findings(&result);
            all_findings.extend(hallucination_findings);
        }

        // 3. PII leakage detection on response content
        let pii_findings = self.regex_analyzer.detect_pii_patterns(response_text);
        all_findings.extend(pii_findings);

        // 4. Secret scanning / data leakage on response content
        let leakage_findings = self.regex_analyzer.detect_leakage_patterns(response_text);
        all_findings.extend(leakage_findings);

        // Tag all findings as output_safety
        for finding in &mut all_findings {
            finding
                .metadata
                .insert("analysis_type".to_string(), "output_safety".to_string());
            if finding.location.is_none() {
                finding.location = Some("response.content".to_string());
            }
        }

        OutputAnalysisResult {
            findings: all_findings,
            has_critical_toxicity,
            max_toxicity_score,
            hallucination_score,
        }
    }

    /// Check whether a response should be blocked based on analysis results.
    ///
    /// Returns `true` if `block_on_critical` is enabled and critical toxicity
    /// was detected.
    pub fn should_block(&self, result: &OutputAnalysisResult) -> bool {
        self.config.block_on_critical && result.has_critical_toxicity
    }

    /// Generate a blocked response message for when output is censored.
    pub fn blocked_response_text() -> &'static str {
        "[Content blocked by LLMTrace output safety: critical toxicity detected in response]"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> OutputSafetyConfig {
        OutputSafetyConfig {
            enabled: true,
            toxicity_enabled: true,
            toxicity_threshold: 0.5,
            block_on_critical: false,
            ..Default::default()
        }
    }

    fn enabled_no_toxicity_config() -> OutputSafetyConfig {
        OutputSafetyConfig {
            enabled: true,
            toxicity_enabled: false,
            toxicity_threshold: 0.7,
            block_on_critical: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_analyzer_disabled_returns_empty() {
        let config = OutputSafetyConfig::default(); // enabled: false
        let analyzer = OutputAnalyzer::new_with_fallback(&config);
        let result = analyzer.analyze_output("I will kill you, you worthless idiot");
        assert!(result.findings.is_empty());
        assert!(!result.has_critical_toxicity);
    }

    #[test]
    fn test_analyzer_empty_text_returns_empty() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_config());
        let result = analyzer.analyze_output("");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyzer_detects_pii_in_output() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_no_toxicity_config());
        let result = analyzer.analyze_output("The user's email is alice@example.com");
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.finding_type == "pii_detected"),
            "Should detect PII in output; findings: {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.finding_type)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_analyzer_detects_secrets_in_output() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_no_toxicity_config());
        let result = analyzer.analyze_output("Your API key is AKIAIOSFODNN7EXAMPLE");
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.finding_type == "secret_leakage"),
            "Should detect secret in output"
        );
    }

    #[test]
    fn test_analyzer_detects_toxicity_with_fallback() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_config());
        let result = analyzer.analyze_output("You are a worthless moron and I will kill you");
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.finding_type == "output_toxicity"),
            "Should detect toxicity in output; findings: {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.finding_type)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_analyzer_critical_toxicity_flag() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_config());
        // "I will kill" is a threat keyword with high score
        let result = analyzer.analyze_output("I will kill you");
        assert!(result.has_critical_toxicity, "Threat should be critical");
    }

    #[test]
    fn test_analyzer_findings_tagged_as_output_safety() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_config());
        let result = analyzer.analyze_output("You are a worthless moron");
        for finding in &result.findings {
            assert_eq!(
                finding.metadata.get("analysis_type"),
                Some(&"output_safety".to_string()),
                "All findings should be tagged as output_safety"
            );
        }
    }

    #[test]
    fn test_should_block_when_configured() {
        let config = OutputSafetyConfig {
            enabled: true,
            toxicity_enabled: true,
            toxicity_threshold: 0.5,
            block_on_critical: true,
            ..Default::default()
        };
        let analyzer = OutputAnalyzer::new_with_fallback(&config);
        let result = analyzer.analyze_output("I will kill you");
        assert!(analyzer.should_block(&result));
    }

    #[test]
    fn test_should_not_block_when_not_configured() {
        let config = OutputSafetyConfig {
            enabled: true,
            toxicity_enabled: true,
            toxicity_threshold: 0.5,
            block_on_critical: false,
            ..Default::default()
        };
        let analyzer = OutputAnalyzer::new_with_fallback(&config);
        let result = analyzer.analyze_output("I will kill you");
        assert!(!analyzer.should_block(&result));
    }

    #[test]
    fn test_benign_output_no_findings() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_config());
        let result = analyzer.analyze_output(
            "The capital of France is Paris. It has a population of about 2 million people.",
        );
        assert!(
            result.findings.is_empty(),
            "Benign text should produce no findings"
        );
        assert!(!result.has_critical_toxicity);
        assert!(result.max_toxicity_score < f32::EPSILON);
    }

    #[test]
    fn test_blocked_response_text() {
        let text = OutputAnalyzer::blocked_response_text();
        assert!(text.contains("blocked"));
        assert!(text.contains("toxicity"));
    }

    #[test]
    fn test_combined_toxicity_and_pii() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_config());
        let result =
            analyzer.analyze_output("You worthless moron, here is the email: alice@example.com");
        let has_toxicity = result
            .findings
            .iter()
            .any(|f| f.finding_type == "output_toxicity");
        let has_pii = result
            .findings
            .iter()
            .any(|f| f.finding_type == "pii_detected");
        assert!(has_toxicity, "Should detect toxicity");
        assert!(has_pii, "Should detect PII");
    }

    // ---------------------------------------------------------------
    // Hallucination detection integration tests
    // ---------------------------------------------------------------

    fn hallucination_enabled_config() -> OutputSafetyConfig {
        OutputSafetyConfig {
            enabled: true,
            toxicity_enabled: false,
            hallucination_enabled: true,
            hallucination_threshold: 0.5,
            hallucination_min_response_length: 10,
            ..Default::default()
        }
    }

    #[test]
    fn test_hallucination_disabled_by_default() {
        let analyzer = OutputAnalyzer::new_with_fallback(&enabled_config());
        let result = analyzer.analyze_output_with_prompt(
            Some("What is Rust?"),
            "Rust is a programming language. It focuses on safety and performance.",
        );
        assert!(
            result.hallucination_score.is_none(),
            "Hallucination score should be None when detector is disabled"
        );
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.finding_type == "output_hallucination"),
            "No hallucination findings when disabled"
        );
    }

    #[test]
    fn test_hallucination_runs_when_enabled() {
        let analyzer = OutputAnalyzer::new_with_fallback(&hallucination_enabled_config());
        let result = analyzer.analyze_output_with_prompt(
            Some("What is the capital of France?"),
            "The capital of France is Paris. It is a beautiful city in Europe. Paris has many famous landmarks.",
        );
        // Should have run hallucination detection (response > min length)
        assert!(
            result.hallucination_score.is_some(),
            "Hallucination score should be present when enabled"
        );
    }

    #[test]
    fn test_hallucination_skips_short_response() {
        let config = OutputSafetyConfig {
            enabled: true,
            hallucination_enabled: true,
            hallucination_min_response_length: 200,
            ..Default::default()
        };
        let analyzer = OutputAnalyzer::new_with_fallback(&config);
        let result =
            analyzer.analyze_output_with_prompt(Some("What is Rust?"), "A programming language.");
        assert!(
            result.hallucination_score.is_none(),
            "Should skip hallucination for short responses"
        );
    }

    #[test]
    fn test_hallucination_skips_without_prompt() {
        let analyzer = OutputAnalyzer::new_with_fallback(&hallucination_enabled_config());
        let result = analyzer
            .analyze_output("The capital of France is Paris. It is located in northern France.");
        assert!(
            result.hallucination_score.is_none(),
            "Hallucination should be skipped without a prompt"
        );
    }

    #[test]
    fn test_hallucination_findings_tagged_as_output_safety() {
        let config = OutputSafetyConfig {
            enabled: true,
            hallucination_enabled: true,
            hallucination_threshold: 0.99, // Very high to force flagging
            hallucination_min_response_length: 10,
            ..Default::default()
        };
        let analyzer = OutputAnalyzer::new_with_fallback(&config);
        let result = analyzer.analyze_output_with_prompt(
            Some("Tell me about cats"),
            "The Battle of Waterloo was fought in 1815. Napoleon was defeated. This ended the Napoleonic Wars.",
        );
        for finding in &result.findings {
            assert_eq!(
                finding.metadata.get("analysis_type"),
                Some(&"output_safety".to_string()),
                "All hallucination findings should be tagged as output_safety"
            );
        }
    }

    #[test]
    fn test_hallucination_with_high_threshold_flags_sentences() {
        let config = OutputSafetyConfig {
            enabled: true,
            hallucination_enabled: true,
            hallucination_threshold: 0.99,
            hallucination_min_response_length: 10,
            ..Default::default()
        };
        let analyzer = OutputAnalyzer::new_with_fallback(&config);
        let result = analyzer.analyze_output_with_prompt(
            Some("What is the speed of light?"),
            "The speed of light is approximately 300000 km per second. \
             Einstein discovered this through special relativity. \
             The theory was published in 1905.",
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.finding_type == "output_hallucination"),
            "High threshold should flag hallucination; findings: {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.finding_type)
                .collect::<Vec<_>>()
        );
    }
}
