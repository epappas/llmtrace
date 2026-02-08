//! Standardized tool result parsing (R-AS-01).
//!
//! Diverse security detectors (classifiers, heuristics, LLM judges, etc.)
//! produce wildly different output formats. This module normalises those
//! outputs into a unified [`DetectorResult`] schema, then aggregates multiple
//! detector results into a single [`ScanResult`] using pluggable
//! [`AggregationStrategy`] policies.
//!
//! # Quick start
//!
//! ```
//! use llmtrace_security::result_parser::*;
//! use llmtrace_core::SecuritySeverity;
//!
//! let r1 = DetectorResult::new("injecguard", DetectorType::Classifier)
//!     .with_threat(ThreatCategory::InjectionDirect)
//!     .with_confidence(0.92)
//!     .with_severity(SecuritySeverity::High);
//!
//! let r2 = DetectorResult::new("heuristic-v1", DetectorType::Heuristic)
//!     .with_threat(ThreatCategory::Benign)
//!     .with_confidence(0.85)
//!     .with_severity(SecuritySeverity::Info);
//!
//! let aggregator = ResultAggregator::new(AggregationStrategy::MajorityVote);
//! let agg = aggregator.aggregate(&[r1, r2]);
//! ```

use chrono::{DateTime, Utc};
use llmtrace_core::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Threat classification for a scanned input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    InjectionDirect,
    InjectionIndirect,
    Jailbreak,
    PiiLeak,
    ToxicContent,
    DataExfiltration,
    PromptExtraction,
    CodeExecution,
    Benign,
}

impl ThreatCategory {
    /// Map the category to a human-readable finding_type string for
    /// `SecurityFinding`.
    #[must_use]
    pub fn as_finding_type(&self) -> &'static str {
        match self {
            Self::InjectionDirect => "prompt_injection_direct",
            Self::InjectionIndirect => "prompt_injection_indirect",
            Self::Jailbreak => "jailbreak",
            Self::PiiLeak => "pii_leak",
            Self::ToxicContent => "toxic_content",
            Self::DataExfiltration => "data_exfiltration",
            Self::PromptExtraction => "prompt_extraction",
            Self::CodeExecution => "code_execution",
            Self::Benign => "benign",
        }
    }

    /// True when the category represents an actual threat (not benign).
    #[must_use]
    pub fn is_threat(&self) -> bool {
        *self != Self::Benign
    }
}

/// Kind of security detector that produced a result.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectorType {
    Classifier,
    Heuristic,
    Semantic,
    LlmJudge,
    Ensemble,
    Canary,
}

/// Strategy for combining multiple detector results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationStrategy {
    /// Simple majority of detectors determines outcome.
    MajorityVote,
    /// Detectors contribute according to per-detector weights.
    WeightedVote,
    /// Any single detector flagging a threat causes a threat verdict.
    Conservative,
    /// All detectors must agree on the same threat to flag it.
    Permissive,
    /// First result above the confidence threshold wins.
    Cascade,
}

// ---------------------------------------------------------------------------
// DetectorResult
// ---------------------------------------------------------------------------

/// Normalised output from a single security detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorResult {
    pub detector_name: String,
    pub detector_type: DetectorType,
    pub threat_category: ThreatCategory,
    pub severity: SecuritySeverity,
    pub confidence: f64,
    pub raw_output: Option<String>,
    pub metadata: HashMap<String, String>,
    pub latency_ms: Option<u64>,
}

impl DetectorResult {
    /// Start building a result for the given detector.
    #[must_use]
    pub fn new(name: &str, detector_type: DetectorType) -> Self {
        Self {
            detector_name: name.to_string(),
            detector_type,
            threat_category: ThreatCategory::Benign,
            severity: SecuritySeverity::Info,
            confidence: 0.0,
            raw_output: None,
            metadata: HashMap::new(),
            latency_ms: None,
        }
    }

    #[must_use]
    pub fn with_threat(mut self, cat: ThreatCategory) -> Self {
        self.threat_category = cat;
        self
    }

    #[must_use]
    pub fn with_confidence(mut self, c: f64) -> Self {
        self.confidence = c;
        self
    }

    #[must_use]
    pub fn with_severity(mut self, s: SecuritySeverity) -> Self {
        self.severity = s;
        self
    }

    #[must_use]
    pub fn with_raw_output(mut self, raw: String) -> Self {
        self.raw_output = Some(raw);
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    #[must_use]
    pub fn with_latency_ms(mut self, ms: u64) -> Self {
        self.latency_ms = Some(ms);
        self
    }
}

impl From<&DetectorResult> for SecurityFinding {
    fn from(dr: &DetectorResult) -> Self {
        let desc = format!(
            "[{}] detected {} (confidence {:.2})",
            dr.detector_name,
            dr.threat_category.as_finding_type(),
            dr.confidence,
        );
        let mut finding = SecurityFinding::new(
            dr.severity.clone(),
            dr.threat_category.as_finding_type().to_string(),
            desc,
            dr.confidence,
        );
        for (k, v) in &dr.metadata {
            finding = finding.with_metadata(k.clone(), v.clone());
        }
        finding = finding.with_metadata("detector_name".to_string(), dr.detector_name.clone());
        finding
    }
}

// ---------------------------------------------------------------------------
// AggregatedResult
// ---------------------------------------------------------------------------

/// The outcome of combining multiple detector results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedResult {
    pub threat_category: ThreatCategory,
    pub confidence: f64,
    pub severity: SecuritySeverity,
    pub contributing_detectors: Vec<String>,
    pub strategy_used: AggregationStrategy,
}

// ---------------------------------------------------------------------------
// ResultAggregator
// ---------------------------------------------------------------------------

/// Combines multiple [`DetectorResult`]s into a single verdict.
#[derive(Debug, Clone)]
pub struct ResultAggregator {
    pub strategy: AggregationStrategy,
    pub confidence_threshold: f64,
    pub detector_weights: HashMap<String, f64>,
}

impl ResultAggregator {
    #[must_use]
    pub fn new(strategy: AggregationStrategy) -> Self {
        Self {
            strategy,
            confidence_threshold: 0.5,
            detector_weights: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_weights(strategy: AggregationStrategy, weights: HashMap<String, f64>) -> Self {
        Self {
            strategy,
            confidence_threshold: 0.5,
            detector_weights: weights,
        }
    }

    #[must_use]
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    /// Dispatch to the appropriate strategy implementation.
    #[must_use]
    pub fn aggregate(&self, results: &[DetectorResult]) -> AggregatedResult {
        match self.strategy {
            AggregationStrategy::MajorityVote => self.aggregate_majority_vote(results),
            AggregationStrategy::WeightedVote => self.aggregate_weighted_vote(results),
            AggregationStrategy::Conservative => self.aggregate_conservative(results),
            AggregationStrategy::Permissive => self.aggregate_permissive(results),
            AggregationStrategy::Cascade => self.aggregate_cascade(results),
        }
    }

    /// Majority vote: the most commonly reported threat category wins.
    /// Only categories above `confidence_threshold` participate.
    #[must_use]
    pub fn aggregate_majority_vote(&self, results: &[DetectorResult]) -> AggregatedResult {
        if results.is_empty() {
            return benign_aggregated(AggregationStrategy::MajorityVote);
        }

        let eligible: Vec<&DetectorResult> = results
            .iter()
            .filter(|r| r.confidence >= self.confidence_threshold)
            .collect();

        if eligible.is_empty() {
            return benign_aggregated(AggregationStrategy::MajorityVote);
        }

        let mut votes: HashMap<&ThreatCategory, (usize, f64, &SecuritySeverity, Vec<&str>)> =
            HashMap::new();
        for r in &eligible {
            let entry = votes.entry(&r.threat_category).or_insert((
                0,
                0.0,
                &SecuritySeverity::Info,
                Vec::new(),
            ));
            entry.0 += 1;
            entry.1 += r.confidence;
            if r.severity > *entry.2 {
                entry.2 = &r.severity;
            }
            entry.3.push(&r.detector_name);
        }

        let winner = votes
            .iter()
            .max_by_key(|(_, (count, _, _, _))| *count)
            .unwrap();

        let (cat, (count, conf_sum, sev, names)) = winner;
        AggregatedResult {
            threat_category: (*cat).clone(),
            confidence: conf_sum / *count as f64,
            severity: (*sev).clone(),
            contributing_detectors: names.iter().map(|s| (*s).to_string()).collect(),
            strategy_used: AggregationStrategy::MajorityVote,
        }
    }

    /// Weighted vote: each detector's confidence is scaled by its weight.
    /// The threat category with the highest total weighted score wins.
    #[must_use]
    pub fn aggregate_weighted_vote(&self, results: &[DetectorResult]) -> AggregatedResult {
        if results.is_empty() {
            return benign_aggregated(AggregationStrategy::WeightedVote);
        }

        let mut scores: HashMap<&ThreatCategory, (f64, &SecuritySeverity, Vec<&str>)> =
            HashMap::new();
        for r in results {
            let w = self
                .detector_weights
                .get(&r.detector_name)
                .copied()
                .unwrap_or(1.0);
            let entry = scores.entry(&r.threat_category).or_insert((
                0.0,
                &SecuritySeverity::Info,
                Vec::new(),
            ));
            entry.0 += r.confidence * w;
            if r.severity > *entry.1 {
                entry.1 = &r.severity;
            }
            entry.2.push(&r.detector_name);
        }

        let winner = scores
            .iter()
            .max_by(|a, b| a.1 .0.partial_cmp(&b.1 .0).unwrap())
            .unwrap();

        let (cat, (score, sev, names)) = winner;
        let total_weight: f64 = names
            .iter()
            .map(|n| self.detector_weights.get(*n).copied().unwrap_or(1.0))
            .sum();
        let avg_conf = if total_weight > 0.0 {
            score / total_weight
        } else {
            0.0
        };

        AggregatedResult {
            threat_category: (*cat).clone(),
            confidence: avg_conf,
            severity: (*sev).clone(),
            contributing_detectors: names.iter().map(|s| (*s).to_string()).collect(),
            strategy_used: AggregationStrategy::WeightedVote,
        }
    }

    /// Conservative: any detector flagging a threat above threshold -> threat.
    /// Picks the highest-severity threat found.
    #[must_use]
    pub fn aggregate_conservative(&self, results: &[DetectorResult]) -> AggregatedResult {
        if results.is_empty() {
            return benign_aggregated(AggregationStrategy::Conservative);
        }

        let threats: Vec<&DetectorResult> = results
            .iter()
            .filter(|r| r.threat_category.is_threat() && r.confidence >= self.confidence_threshold)
            .collect();

        if threats.is_empty() {
            return AggregatedResult {
                threat_category: ThreatCategory::Benign,
                confidence: results.iter().map(|r| 1.0 - r.confidence).product(),
                severity: SecuritySeverity::Info,
                contributing_detectors: Vec::new(),
                strategy_used: AggregationStrategy::Conservative,
            };
        }

        let worst = threats
            .iter()
            .max_by(|a, b| a.severity.cmp(&b.severity))
            .unwrap();

        AggregatedResult {
            threat_category: worst.threat_category.clone(),
            confidence: threats.iter().map(|r| r.confidence).fold(0.0_f64, f64::max),
            severity: worst.severity.clone(),
            contributing_detectors: threats.iter().map(|r| r.detector_name.clone()).collect(),
            strategy_used: AggregationStrategy::Conservative,
        }
    }

    /// Permissive: all detectors above threshold must agree on the same
    /// threat category for it to be flagged.
    #[must_use]
    pub fn aggregate_permissive(&self, results: &[DetectorResult]) -> AggregatedResult {
        if results.is_empty() {
            return benign_aggregated(AggregationStrategy::Permissive);
        }

        let eligible: Vec<&DetectorResult> = results
            .iter()
            .filter(|r| r.confidence >= self.confidence_threshold)
            .collect();

        if eligible.is_empty() {
            return benign_aggregated(AggregationStrategy::Permissive);
        }

        let first_cat = &eligible[0].threat_category;
        let all_agree = eligible.iter().all(|r| r.threat_category == *first_cat);

        if !all_agree || !first_cat.is_threat() {
            return AggregatedResult {
                threat_category: ThreatCategory::Benign,
                confidence: eligible.iter().map(|r| r.confidence).sum::<f64>()
                    / eligible.len() as f64,
                severity: SecuritySeverity::Info,
                contributing_detectors: Vec::new(),
                strategy_used: AggregationStrategy::Permissive,
            };
        }

        let max_sev = eligible.iter().map(|r| &r.severity).max().unwrap();

        AggregatedResult {
            threat_category: first_cat.clone(),
            confidence: eligible.iter().map(|r| r.confidence).sum::<f64>() / eligible.len() as f64,
            severity: max_sev.clone(),
            contributing_detectors: eligible.iter().map(|r| r.detector_name.clone()).collect(),
            strategy_used: AggregationStrategy::Permissive,
        }
    }

    /// Cascade: the first result whose confidence exceeds the threshold wins.
    /// Order is determined by input slice order.
    #[must_use]
    pub fn aggregate_cascade(&self, results: &[DetectorResult]) -> AggregatedResult {
        for r in results {
            if r.confidence >= self.confidence_threshold {
                return AggregatedResult {
                    threat_category: r.threat_category.clone(),
                    confidence: r.confidence,
                    severity: r.severity.clone(),
                    contributing_detectors: vec![r.detector_name.clone()],
                    strategy_used: AggregationStrategy::Cascade,
                };
            }
        }
        benign_aggregated(AggregationStrategy::Cascade)
    }
}

/// Helper: returns a Benign aggregated result for the given strategy.
#[must_use]
fn benign_aggregated(strategy: AggregationStrategy) -> AggregatedResult {
    AggregatedResult {
        threat_category: ThreatCategory::Benign,
        confidence: 0.0,
        severity: SecuritySeverity::Info,
        contributing_detectors: Vec::new(),
        strategy_used: strategy,
    }
}

// ---------------------------------------------------------------------------
// ScanResult + builder
// ---------------------------------------------------------------------------

/// Final scan output combining all detector results and their aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub input_hash: String,
    pub detector_results: Vec<DetectorResult>,
    pub aggregate_threat: ThreatCategory,
    pub aggregate_confidence: f64,
    pub aggregate_severity: SecuritySeverity,
    pub scan_duration_ms: u64,
    pub timestamp: DateTime<Utc>,
}

impl ScanResult {
    /// Convert every detector result into a `SecurityFinding`.
    /// Only non-benign results are included.
    #[must_use]
    pub fn to_security_findings(&self) -> Vec<SecurityFinding> {
        self.detector_results
            .iter()
            .filter(|r| r.threat_category.is_threat())
            .map(SecurityFinding::from)
            .collect()
    }
}

/// Incrementally builds a [`ScanResult`] from individual detector results.
pub struct ScanResultBuilder {
    input_hash: String,
    results: Vec<DetectorResult>,
    start: std::time::Instant,
}

impl ScanResultBuilder {
    /// Create a new builder, computing the input hash immediately.
    #[must_use]
    pub fn new(input_text: &str) -> Self {
        Self {
            input_hash: compute_input_hash(input_text),
            results: Vec::new(),
            start: std::time::Instant::now(),
        }
    }

    /// Append a detector result.
    pub fn add_result(&mut self, result: DetectorResult) -> &mut Self {
        self.results.push(result);
        self
    }

    /// Finalise the scan using the provided aggregator.
    #[must_use]
    pub fn build(self, aggregator: &ResultAggregator) -> ScanResult {
        let agg = aggregator.aggregate(&self.results);
        let duration = self.start.elapsed().as_millis() as u64;
        ScanResult {
            input_hash: self.input_hash,
            detector_results: self.results,
            aggregate_threat: agg.threat_category,
            aggregate_confidence: agg.confidence,
            aggregate_severity: agg.severity,
            scan_duration_ms: duration,
            timestamp: Utc::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic hash of input text.
/// Uses a simple multiplicative hash folded to 16 hex characters.
#[must_use]
pub fn compute_input_hash(input: &str) -> String {
    let h = input.bytes().fold(0u64, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u64::from(b))
    });
    format!("{h:016x}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ThreatCategory --

    #[test]
    fn threat_category_serde_roundtrip() {
        let cats = vec![
            ThreatCategory::InjectionDirect,
            ThreatCategory::InjectionIndirect,
            ThreatCategory::Jailbreak,
            ThreatCategory::PiiLeak,
            ThreatCategory::ToxicContent,
            ThreatCategory::DataExfiltration,
            ThreatCategory::PromptExtraction,
            ThreatCategory::CodeExecution,
            ThreatCategory::Benign,
        ];
        for cat in cats {
            let json = serde_json::to_string(&cat).unwrap();
            let back: ThreatCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn threat_category_is_threat() {
        assert!(ThreatCategory::InjectionDirect.is_threat());
        assert!(ThreatCategory::Jailbreak.is_threat());
        assert!(!ThreatCategory::Benign.is_threat());
    }

    #[test]
    fn threat_category_finding_type_mapping() {
        assert_eq!(
            ThreatCategory::InjectionDirect.as_finding_type(),
            "prompt_injection_direct"
        );
        assert_eq!(ThreatCategory::Benign.as_finding_type(), "benign");
    }

    // -- DetectorResult --

    #[test]
    fn detector_result_construction_and_metadata() {
        let r = DetectorResult::new("test-det", DetectorType::Classifier)
            .with_threat(ThreatCategory::Jailbreak)
            .with_confidence(0.95)
            .with_severity(SecuritySeverity::High)
            .with_raw_output("raw output".to_string())
            .with_metadata("model", "v2")
            .with_latency_ms(42);

        assert_eq!(r.detector_name, "test-det");
        assert_eq!(r.detector_type, DetectorType::Classifier);
        assert_eq!(r.threat_category, ThreatCategory::Jailbreak);
        assert_eq!(r.severity, SecuritySeverity::High);
        assert!((r.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(r.raw_output.as_deref(), Some("raw output"));
        assert_eq!(r.metadata.get("model").unwrap(), "v2");
        assert_eq!(r.latency_ms, Some(42));
    }

    #[test]
    fn detector_result_serde_roundtrip() {
        let r = DetectorResult::new("d1", DetectorType::Semantic)
            .with_threat(ThreatCategory::PiiLeak)
            .with_confidence(0.77)
            .with_severity(SecuritySeverity::Medium);

        let json = serde_json::to_string(&r).unwrap();
        let back: DetectorResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.detector_name, "d1");
        assert_eq!(back.threat_category, ThreatCategory::PiiLeak);
        assert!((back.confidence - 0.77).abs() < f64::EPSILON);
    }

    // -- SecurityFinding conversion --

    #[test]
    fn detector_result_to_security_finding() {
        let r = DetectorResult::new("ig", DetectorType::Classifier)
            .with_threat(ThreatCategory::InjectionDirect)
            .with_confidence(0.88)
            .with_severity(SecuritySeverity::Critical)
            .with_metadata("source", "unit-test");

        let finding: SecurityFinding = SecurityFinding::from(&r);
        assert_eq!(finding.severity, SecuritySeverity::Critical);
        assert_eq!(finding.finding_type, "prompt_injection_direct");
        assert!((finding.confidence_score - 0.88).abs() < f64::EPSILON);
        assert_eq!(finding.metadata.get("detector_name").unwrap(), "ig");
        assert_eq!(finding.metadata.get("source").unwrap(), "unit-test");
        assert!(finding.requires_alert);
    }

    // -- Input hashing --

    #[test]
    fn input_hash_deterministic() {
        let h1 = compute_input_hash("hello world");
        let h2 = compute_input_hash("hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn input_hash_differs_for_different_inputs() {
        let h1 = compute_input_hash("input A");
        let h2 = compute_input_hash("input B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn input_hash_empty_string() {
        let h = compute_input_hash("");
        assert_eq!(h.len(), 16);
        assert_eq!(h, "0000000000000000");
    }

    // -- MajorityVote aggregation --

    #[test]
    fn majority_vote_single_threat_wins() {
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.9)
                .with_severity(SecuritySeverity::High),
            DetectorResult::new("b", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.8)
                .with_severity(SecuritySeverity::Medium),
            DetectorResult::new("c", DetectorType::Semantic)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.7)
                .with_severity(SecuritySeverity::Info),
        ];

        let agg = ResultAggregator::new(AggregationStrategy::MajorityVote);
        let out = agg.aggregate(&results);

        assert_eq!(out.threat_category, ThreatCategory::Jailbreak);
        assert_eq!(out.strategy_used, AggregationStrategy::MajorityVote);
        assert_eq!(out.contributing_detectors.len(), 2);
        assert_eq!(out.severity, SecuritySeverity::High);
    }

    #[test]
    fn majority_vote_all_benign() {
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.9)
                .with_severity(SecuritySeverity::Info),
            DetectorResult::new("b", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.85)
                .with_severity(SecuritySeverity::Info),
        ];

        let out = ResultAggregator::new(AggregationStrategy::MajorityVote).aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    #[test]
    fn majority_vote_below_threshold_ignored() {
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.3)
                .with_severity(SecuritySeverity::High),
            DetectorResult::new("b", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.8)
                .with_severity(SecuritySeverity::Info),
        ];

        let agg = ResultAggregator::new(AggregationStrategy::MajorityVote).with_threshold(0.5);
        let out = agg.aggregate(&results);
        // Only the benign result is above threshold -> benign wins
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    #[test]
    fn majority_vote_mixed_threats() {
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::InjectionDirect)
                .with_confidence(0.9)
                .with_severity(SecuritySeverity::High),
            DetectorResult::new("b", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.8)
                .with_severity(SecuritySeverity::Medium),
            DetectorResult::new("c", DetectorType::LlmJudge)
                .with_threat(ThreatCategory::InjectionDirect)
                .with_confidence(0.85)
                .with_severity(SecuritySeverity::Critical),
        ];

        let out = ResultAggregator::new(AggregationStrategy::MajorityVote).aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::InjectionDirect);
        assert_eq!(out.severity, SecuritySeverity::Critical);
        assert_eq!(out.contributing_detectors.len(), 2);
    }

    // -- WeightedVote aggregation --

    #[test]
    fn weighted_vote_respects_weights() {
        let mut weights = HashMap::new();
        weights.insert("trusted".to_string(), 5.0);
        weights.insert("weak".to_string(), 1.0);

        let results = vec![
            DetectorResult::new("trusted", DetectorType::Ensemble)
                .with_threat(ThreatCategory::InjectionDirect)
                .with_confidence(0.7)
                .with_severity(SecuritySeverity::High),
            DetectorResult::new("weak", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.9)
                .with_severity(SecuritySeverity::Info),
        ];

        let agg = ResultAggregator::with_weights(AggregationStrategy::WeightedVote, weights);
        let out = agg.aggregate(&results);

        // trusted: 0.7 * 5.0 = 3.5  vs  weak: 0.9 * 1.0 = 0.9
        assert_eq!(out.threat_category, ThreatCategory::InjectionDirect);
    }

    #[test]
    fn weighted_vote_default_weight_is_one() {
        // No explicit weights -> all detectors get weight 1.0
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.8)
                .with_severity(SecuritySeverity::High),
            DetectorResult::new("b", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.7)
                .with_severity(SecuritySeverity::Medium),
        ];

        let agg = ResultAggregator::new(AggregationStrategy::WeightedVote);
        let out = agg.aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::Jailbreak);
        // avg confidence = (0.8 + 0.7) / 2.0 = 0.75
        assert!((out.confidence - 0.75).abs() < f64::EPSILON);
    }

    // -- Conservative aggregation --

    #[test]
    fn conservative_any_threat_flags() {
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.95)
                .with_severity(SecuritySeverity::Info),
            DetectorResult::new("b", DetectorType::Canary)
                .with_threat(ThreatCategory::PromptExtraction)
                .with_confidence(0.6)
                .with_severity(SecuritySeverity::Critical),
        ];

        let out = ResultAggregator::new(AggregationStrategy::Conservative).aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::PromptExtraction);
        assert_eq!(out.severity, SecuritySeverity::Critical);
        assert_eq!(out.contributing_detectors, vec!["b"]);
    }

    #[test]
    fn conservative_all_benign_returns_benign() {
        let results = vec![DetectorResult::new("a", DetectorType::Classifier)
            .with_threat(ThreatCategory::Benign)
            .with_confidence(0.99)
            .with_severity(SecuritySeverity::Info)];

        let out = ResultAggregator::new(AggregationStrategy::Conservative).aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    #[test]
    fn conservative_below_threshold_ignored() {
        let results = vec![DetectorResult::new("a", DetectorType::Classifier)
            .with_threat(ThreatCategory::Jailbreak)
            .with_confidence(0.3)
            .with_severity(SecuritySeverity::High)];

        let agg = ResultAggregator::new(AggregationStrategy::Conservative).with_threshold(0.5);
        let out = agg.aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    // -- Permissive aggregation --

    #[test]
    fn permissive_all_agree_on_threat() {
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::DataExfiltration)
                .with_confidence(0.8)
                .with_severity(SecuritySeverity::High),
            DetectorResult::new("b", DetectorType::Semantic)
                .with_threat(ThreatCategory::DataExfiltration)
                .with_confidence(0.75)
                .with_severity(SecuritySeverity::Medium),
        ];

        let out = ResultAggregator::new(AggregationStrategy::Permissive).aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::DataExfiltration);
        assert_eq!(out.contributing_detectors.len(), 2);
    }

    #[test]
    fn permissive_disagreement_returns_benign() {
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.9)
                .with_severity(SecuritySeverity::High),
            DetectorResult::new("b", DetectorType::Heuristic)
                .with_threat(ThreatCategory::InjectionDirect)
                .with_confidence(0.85)
                .with_severity(SecuritySeverity::High),
        ];

        let out = ResultAggregator::new(AggregationStrategy::Permissive).aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
        assert!(out.contributing_detectors.is_empty());
    }

    #[test]
    fn permissive_all_agree_benign() {
        let results = vec![
            DetectorResult::new("a", DetectorType::Classifier)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.9)
                .with_severity(SecuritySeverity::Info),
            DetectorResult::new("b", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.85)
                .with_severity(SecuritySeverity::Info),
        ];

        let out = ResultAggregator::new(AggregationStrategy::Permissive).aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    // -- Cascade aggregation --

    #[test]
    fn cascade_first_high_confidence_wins() {
        let results = vec![
            DetectorResult::new("fast", DetectorType::Heuristic)
                .with_threat(ThreatCategory::ToxicContent)
                .with_confidence(0.3)
                .with_severity(SecuritySeverity::Low),
            DetectorResult::new("accurate", DetectorType::Classifier)
                .with_threat(ThreatCategory::InjectionDirect)
                .with_confidence(0.85)
                .with_severity(SecuritySeverity::High),
            DetectorResult::new("slow", DetectorType::LlmJudge)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.99)
                .with_severity(SecuritySeverity::Critical),
        ];

        let agg = ResultAggregator::new(AggregationStrategy::Cascade).with_threshold(0.5);
        let out = agg.aggregate(&results);
        // First result above 0.5 is "accurate"
        assert_eq!(out.threat_category, ThreatCategory::InjectionDirect);
        assert_eq!(out.contributing_detectors, vec!["accurate"]);
    }

    #[test]
    fn cascade_none_above_threshold_returns_benign() {
        let results = vec![DetectorResult::new("a", DetectorType::Heuristic)
            .with_threat(ThreatCategory::Jailbreak)
            .with_confidence(0.2)
            .with_severity(SecuritySeverity::High)];

        let agg = ResultAggregator::new(AggregationStrategy::Cascade).with_threshold(0.5);
        let out = agg.aggregate(&results);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    // -- Empty results --

    #[test]
    fn empty_results_majority_vote() {
        let out = ResultAggregator::new(AggregationStrategy::MajorityVote).aggregate(&[]);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
        assert!((out.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_results_conservative() {
        let out = ResultAggregator::new(AggregationStrategy::Conservative).aggregate(&[]);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    #[test]
    fn empty_results_permissive() {
        let out = ResultAggregator::new(AggregationStrategy::Permissive).aggregate(&[]);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    #[test]
    fn empty_results_cascade() {
        let out = ResultAggregator::new(AggregationStrategy::Cascade).aggregate(&[]);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    #[test]
    fn empty_results_weighted_vote() {
        let out = ResultAggregator::new(AggregationStrategy::WeightedVote).aggregate(&[]);
        assert_eq!(out.threat_category, ThreatCategory::Benign);
    }

    // -- ScanResultBuilder --

    #[test]
    fn scan_result_builder_basic() {
        let mut builder = ScanResultBuilder::new("test input");
        builder.add_result(
            DetectorResult::new("d1", DetectorType::Classifier)
                .with_threat(ThreatCategory::Jailbreak)
                .with_confidence(0.9)
                .with_severity(SecuritySeverity::High),
        );
        builder.add_result(
            DetectorResult::new("d2", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.7)
                .with_severity(SecuritySeverity::Info),
        );

        let aggregator = ResultAggregator::new(AggregationStrategy::MajorityVote);
        let scan = builder.build(&aggregator);

        assert_eq!(scan.input_hash, compute_input_hash("test input"));
        assert_eq!(scan.detector_results.len(), 2);
        assert!(scan.timestamp <= Utc::now());
    }

    #[test]
    fn scan_result_to_security_findings_excludes_benign() {
        let mut builder = ScanResultBuilder::new("probe");
        builder.add_result(
            DetectorResult::new("d1", DetectorType::Classifier)
                .with_threat(ThreatCategory::InjectionDirect)
                .with_confidence(0.88)
                .with_severity(SecuritySeverity::High),
        );
        builder.add_result(
            DetectorResult::new("d2", DetectorType::Heuristic)
                .with_threat(ThreatCategory::Benign)
                .with_confidence(0.7)
                .with_severity(SecuritySeverity::Info),
        );

        let aggregator = ResultAggregator::new(AggregationStrategy::Conservative);
        let scan = builder.build(&aggregator);
        let findings = scan.to_security_findings();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "prompt_injection_direct");
    }

    // -- Single detector --

    #[test]
    fn single_detector_all_strategies() {
        let result = DetectorResult::new("sole", DetectorType::Classifier)
            .with_threat(ThreatCategory::CodeExecution)
            .with_confidence(0.91)
            .with_severity(SecuritySeverity::Critical);

        let strategies = vec![
            AggregationStrategy::MajorityVote,
            AggregationStrategy::WeightedVote,
            AggregationStrategy::Conservative,
            AggregationStrategy::Permissive,
            AggregationStrategy::Cascade,
        ];

        for s in strategies {
            let agg = ResultAggregator::new(s.clone());
            let out = agg.aggregate(std::slice::from_ref(&result));
            assert_eq!(out.threat_category, ThreatCategory::CodeExecution);
            assert_eq!(out.severity, SecuritySeverity::Critical);
        }
    }

    // -- Confidence threshold enforcement --

    #[test]
    fn custom_threshold_enforcement() {
        let result = DetectorResult::new("d", DetectorType::Classifier)
            .with_threat(ThreatCategory::Jailbreak)
            .with_confidence(0.6)
            .with_severity(SecuritySeverity::High);

        // threshold 0.7 -> should be ignored as benign
        let agg_high = ResultAggregator::new(AggregationStrategy::Cascade).with_threshold(0.7);
        let out_high = agg_high.aggregate(std::slice::from_ref(&result));
        assert_eq!(out_high.threat_category, ThreatCategory::Benign);

        // threshold 0.5 -> should be detected
        let agg_low = ResultAggregator::new(AggregationStrategy::Cascade).with_threshold(0.5);
        let out_low = agg_low.aggregate(&[result]);
        assert_eq!(out_low.threat_category, ThreatCategory::Jailbreak);
    }

    // -- ScanResult serialization --

    #[test]
    fn scan_result_serde_roundtrip() {
        let mut builder = ScanResultBuilder::new("serialize me");
        builder.add_result(
            DetectorResult::new("d1", DetectorType::Canary)
                .with_threat(ThreatCategory::PromptExtraction)
                .with_confidence(0.99)
                .with_severity(SecuritySeverity::Critical),
        );
        let aggregator = ResultAggregator::new(AggregationStrategy::Conservative);
        let scan = builder.build(&aggregator);

        let json = serde_json::to_string(&scan).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();

        assert_eq!(back.input_hash, scan.input_hash);
        assert_eq!(back.detector_results.len(), 1);
        assert_eq!(back.aggregate_threat, ThreatCategory::PromptExtraction);
    }

    // -- AggregatedResult fields --

    #[test]
    fn aggregated_result_has_correct_strategy() {
        let result = DetectorResult::new("d", DetectorType::Classifier)
            .with_threat(ThreatCategory::Benign)
            .with_confidence(0.9)
            .with_severity(SecuritySeverity::Info);

        let strategies_and_expected = vec![
            AggregationStrategy::MajorityVote,
            AggregationStrategy::WeightedVote,
            AggregationStrategy::Conservative,
            AggregationStrategy::Permissive,
            AggregationStrategy::Cascade,
        ];

        for strategy in strategies_and_expected {
            let agg = ResultAggregator::new(strategy.clone());
            let out = agg.aggregate(std::slice::from_ref(&result));
            assert_eq!(out.strategy_used, strategy);
        }
    }
}
