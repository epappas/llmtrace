//! Adversarial ML robustness module (R-IS-08).
//!
//! Implements multi-pass normalization, perturbation detection, and confidence
//! calibration to defend against adversarial evasion techniques.
//!
//! Research context: TextFooler achieves 46% ASR on DeBERTa.  This module
//! applies layered defenses -- unicode normalization, homoglyph detection,
//! invisible character detection, and temperature-scaled confidence calibration
//! -- to reduce the attack surface before downstream classification.
//!
//! # Architecture
//!
//! 1. **Multi-pass normalization** -- canonicalize text through NFKC, zero-width
//!    removal, homoglyph mapping, whitespace normalization, invisible char
//!    removal, accent stripping, and case normalization.
//! 2. **Perturbation detection** -- identify suspicious characters (homoglyphs,
//!    invisible chars, unicode tricks) and compute an overall suspicion score.
//! 3. **Confidence calibration** -- temperature scaling with perturbation-aware
//!    adjustment to flag adversarial inputs for human review.

use llmtrace_core::{SecurityFinding, SecuritySeverity};
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// NormalizationPass
// ---------------------------------------------------------------------------

/// A single normalization pass in the multi-pass pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizationPass {
    /// NFKC canonical decomposition + compatibility composition.
    UnicodeNfkc,
    /// Remove zero-width chars: U+200B, U+200C, U+200D, U+FEFF.
    ZeroWidthRemoval,
    /// Map common homoglyphs (Cyrillic, Greek, fullwidth) to ASCII.
    HomoglyphNormalization,
    /// Collapse multiple whitespace, normalize exotic spaces.
    WhitespaceNormalization,
    /// Remove control chars except \n and \t.
    InvisibleCharRemoval,
    /// Remove combining diacritical marks after NFD decomposition.
    AccentStripping,
    /// Lowercase for comparison (preserves original elsewhere).
    CaseNormalization,
}

// ---------------------------------------------------------------------------
// NormalizationResult
// ---------------------------------------------------------------------------

/// Result of running the multi-pass normalization pipeline.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    /// The original input text.
    pub original: String,
    /// The fully normalized text.
    pub normalized: String,
    /// Which passes were applied, in order.
    pub passes_applied: Vec<NormalizationPass>,
    /// How many characters changed per pass.
    pub changes_per_pass: Vec<(NormalizationPass, usize)>,
    /// Total character-level edit distance (original vs normalized).
    pub edit_distance: usize,
    /// Suspicion score: high edit distance relative to length = likely evasion.
    pub suspicion_score: f64,
}

// ---------------------------------------------------------------------------
// MultiPassNormalizer
// ---------------------------------------------------------------------------

/// Applies an ordered sequence of normalization passes to text.
#[derive(Debug, Clone)]
pub struct MultiPassNormalizer {
    passes: Vec<NormalizationPass>,
}

impl MultiPassNormalizer {
    /// Create a normalizer with the given passes applied in order.
    #[must_use]
    pub fn new(passes: Vec<NormalizationPass>) -> Self {
        Self { passes }
    }

    /// Create a normalizer with all passes in recommended order.
    #[must_use]
    pub fn with_all_passes() -> Self {
        Self {
            passes: vec![
                NormalizationPass::UnicodeNfkc,
                NormalizationPass::ZeroWidthRemoval,
                NormalizationPass::InvisibleCharRemoval,
                NormalizationPass::HomoglyphNormalization,
                NormalizationPass::WhitespaceNormalization,
                NormalizationPass::AccentStripping,
                NormalizationPass::CaseNormalization,
            ],
        }
    }

    /// Run all configured passes and produce a result with per-pass metrics.
    #[must_use]
    pub fn normalize(&self, text: &str) -> NormalizationResult {
        let original = text.to_string();
        let mut current = text.to_string();
        let mut changes_per_pass = Vec::with_capacity(self.passes.len());

        for pass in &self.passes {
            let before = current.clone();
            current = self.apply_pass(&current, pass);
            let changed = count_char_differences(&before, &current);
            changes_per_pass.push((pass.clone(), changed));
        }

        let edit_distance = count_char_differences(&original, &current);
        // Use char count, not byte length, for accurate suspicion scoring with unicode
        let suspicion_score = compute_suspicion_score(original.chars().count(), edit_distance);

        NormalizationResult {
            original,
            normalized: current,
            passes_applied: self.passes.clone(),
            changes_per_pass,
            edit_distance,
            suspicion_score,
        }
    }

    /// Apply a single normalization pass to the input text.
    #[must_use]
    pub fn apply_pass(&self, text: &str, pass: &NormalizationPass) -> String {
        match pass {
            NormalizationPass::UnicodeNfkc => text.nfkc().collect(),
            NormalizationPass::ZeroWidthRemoval => remove_zero_width(text),
            NormalizationPass::HomoglyphNormalization => normalize_homoglyphs(text),
            NormalizationPass::WhitespaceNormalization => normalize_whitespace(text),
            NormalizationPass::InvisibleCharRemoval => remove_invisible_chars(text),
            NormalizationPass::AccentStripping => strip_accents(text),
            NormalizationPass::CaseNormalization => text.to_lowercase(),
        }
    }
}

// ---------------------------------------------------------------------------
// Pass implementations
// ---------------------------------------------------------------------------

const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', // Zero-width space
    '\u{200C}', // Zero-width non-joiner
    '\u{200D}', // Zero-width joiner
    '\u{FEFF}', // BOM / zero-width no-break space
];

fn remove_zero_width(text: &str) -> String {
    text.chars()
        .filter(|c| !ZERO_WIDTH_CHARS.contains(c))
        .collect()
}

fn remove_invisible_chars(text: &str) -> String {
    text.chars()
        .filter(|&c| {
            // Keep newline and tab
            if c == '\n' || c == '\t' {
                return true;
            }
            // Remove C0 and C1 control characters
            if c.is_control() {
                return false;
            }
            // Remove soft hyphen
            if c == '\u{00AD}' {
                return false;
            }
            // Remove bidirectional controls
            let cp = c as u32;
            if (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
                return false;
            }
            // Remove word joiner, line/paragraph separators
            if matches!(cp, 0x2060 | 0x2028 | 0x2029) {
                return false;
            }
            // Remove tag characters
            if (0xE0001..=0xE007F).contains(&cp) {
                return false;
            }
            true
        })
        .collect()
}

fn normalize_whitespace(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut prev_was_space = false;

    for c in text.chars() {
        let is_exotic_space = matches!(
            c as u32,
            0x00A0   // No-break space
            | 0x1680 // Ogham space mark
            | 0x2000
                ..=0x200A // En quad through hair space
            | 0x202F // Narrow no-break space
            | 0x205F // Medium mathematical space
            | 0x3000 // Ideographic space
        );

        if c == ' ' || is_exotic_space {
            if !prev_was_space {
                result.push(' ');
                prev_was_space = true;
            }
        } else {
            result.push(c);
            prev_was_space = false;
        }
    }
    result
}

fn strip_accents(text: &str) -> String {
    text.nfd()
        .filter(|c| {
            let cp = *c as u32;
            // Remove combining diacritical marks
            !matches!(
                cp,
                0x0300..=0x036F
                | 0x1AB0..=0x1AFF
                | 0x1DC0..=0x1DFF
                | 0x20D0..=0x20FF
                | 0xFE20..=0xFE2F
            )
        })
        .collect()
}

fn normalize_homoglyphs(text: &str) -> String {
    text.chars().map(map_homoglyph).collect()
}

/// Map a single character to its ASCII equivalent if it is a known homoglyph.
fn map_homoglyph(c: char) -> char {
    match c {
        // -- Cyrillic lowercase --
        '\u{0430}' => 'a',
        '\u{0435}' => 'e',
        '\u{043E}' => 'o',
        '\u{0440}' => 'p',
        '\u{0441}' => 'c',
        '\u{0445}' => 'x',
        '\u{0443}' => 'y',
        '\u{0456}' => 'i',
        '\u{0458}' => 'j',
        '\u{04BB}' => 'h',

        // -- Cyrillic uppercase --
        '\u{0410}' => 'A',
        '\u{0412}' => 'B',
        '\u{0415}' => 'E',
        '\u{041A}' => 'K',
        '\u{041C}' => 'M',
        '\u{041D}' => 'H',
        '\u{041E}' => 'O',
        '\u{0420}' => 'P',
        '\u{0421}' => 'C',
        '\u{0422}' => 'T',
        '\u{0425}' => 'X',

        // -- Greek --
        '\u{03BF}' => 'o', // omicron
        '\u{03B1}' => 'a', // alpha
        '\u{0391}' => 'A', // Alpha
        '\u{0392}' => 'B', // Beta
        '\u{0395}' => 'E', // Epsilon
        '\u{039F}' => 'O', // Omicron
        '\u{03A1}' => 'P', // Rho
        '\u{03A4}' => 'T', // Tau
        '\u{03A7}' => 'X', // Chi
        '\u{03A5}' => 'Y', // Upsilon

        // -- Mathematical bold/italic (sample: bold A-Z, a-z) --
        c if ('\u{1D400}'..='\u{1D419}').contains(&c) => {
            // Mathematical bold A-Z -> A-Z
            (b'A' + (c as u32 - 0x1D400) as u8) as char
        }
        c if ('\u{1D41A}'..='\u{1D433}').contains(&c) => {
            // Mathematical bold a-z -> a-z
            (b'a' + (c as u32 - 0x1D41A) as u8) as char
        }
        c if ('\u{1D434}'..='\u{1D44D}').contains(&c) => {
            // Mathematical italic A-Z -> A-Z
            (b'A' + (c as u32 - 0x1D434) as u8) as char
        }
        c if ('\u{1D44E}'..='\u{1D467}').contains(&c) => {
            // Mathematical italic a-z -> a-z
            (b'a' + (c as u32 - 0x1D44E) as u8) as char
        }

        // -- Fullwidth A-Z --
        c if ('\u{FF21}'..='\u{FF3A}').contains(&c) => (b'A' + (c as u32 - 0xFF21) as u8) as char,
        // -- Fullwidth a-z --
        c if ('\u{FF41}'..='\u{FF5A}').contains(&c) => (b'a' + (c as u32 - 0xFF41) as u8) as char,
        // -- Fullwidth 0-9 --
        c if ('\u{FF10}'..='\u{FF19}').contains(&c) => (b'0' + (c as u32 - 0xFF10) as u8) as char,

        _ => c,
    }
}

/// Count character-level differences between two strings.
#[must_use]
fn count_char_differences(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    let len_diff = a_chars.len().abs_diff(b_chars.len());
    let common_len = a_chars.len().min(b_chars.len());

    let char_diffs = a_chars
        .iter()
        .zip(b_chars.iter())
        .take(common_len)
        .filter(|(x, y)| x != y)
        .count();

    char_diffs + len_diff
}

/// Compute suspicion score based on edit distance relative to original length.
#[must_use]
fn compute_suspicion_score(original_len: usize, edit_distance: usize) -> f64 {
    if original_len == 0 {
        return 0.0;
    }
    let ratio = edit_distance as f64 / original_len as f64;
    // Clamp to [0.0, 1.0]
    ratio.min(1.0)
}

// ---------------------------------------------------------------------------
// PerturbationDetector
// ---------------------------------------------------------------------------

/// Detected homoglyph at a specific position.
#[derive(Debug, Clone, PartialEq)]
pub struct HomoglyphDetection {
    pub position: usize,
    pub original_char: char,
    pub likely_intended: char,
}

/// Detected invisible character at a specific position.
#[derive(Debug, Clone, PartialEq)]
pub struct InvisibleCharDetection {
    pub position: usize,
    pub char_code: u32,
    pub char_name: String,
}

/// Detected unicode trick at a specific position.
#[derive(Debug, Clone, PartialEq)]
pub struct UnicodeTrickDetection {
    pub position: usize,
    pub trick_type: String,
    pub description: String,
}

/// Full perturbation analysis report.
#[derive(Debug, Clone)]
pub struct PerturbationReport {
    pub homoglyphs: Vec<HomoglyphDetection>,
    pub invisible_chars: Vec<InvisibleCharDetection>,
    pub unicode_tricks: Vec<UnicodeTrickDetection>,
    pub overall_suspicion: f64,
    pub is_likely_adversarial: bool,
}

/// Detects adversarial perturbations in text.
#[derive(Debug, Clone)]
pub struct PerturbationDetector {
    homoglyph_map: HashMap<char, char>,
    suspicious_char_ranges: Vec<(u32, u32)>,
}

impl PerturbationDetector {
    /// Create a detector with the default homoglyph map and suspicious ranges.
    #[must_use]
    pub fn new() -> Self {
        Self {
            homoglyph_map: build_homoglyph_map(),
            suspicious_char_ranges: default_suspicious_ranges(),
        }
    }

    /// Run all perturbation detections and produce a combined report.
    #[must_use]
    pub fn detect_perturbations(&self, text: &str) -> PerturbationReport {
        let homoglyphs = self.detect_homoglyphs(text);
        let invisible_chars = self.detect_invisible_chars(text);
        let unicode_tricks = self.detect_unicode_tricks(text);

        let total_issues = homoglyphs.len() + invisible_chars.len() + unicode_tricks.len();
        let text_len = text.chars().count().max(1);
        let overall_suspicion = (total_issues as f64 / text_len as f64).min(1.0);
        let is_likely_adversarial = overall_suspicion > 0.05 || total_issues >= 3;

        PerturbationReport {
            homoglyphs,
            invisible_chars,
            unicode_tricks,
            overall_suspicion,
            is_likely_adversarial,
        }
    }

    /// Detect homoglyph characters in the text.
    #[must_use]
    pub fn detect_homoglyphs(&self, text: &str) -> Vec<HomoglyphDetection> {
        text.chars()
            .enumerate()
            .filter_map(|(pos, c)| {
                self.homoglyph_map
                    .get(&c)
                    .map(|&intended| HomoglyphDetection {
                        position: pos,
                        original_char: c,
                        likely_intended: intended,
                    })
            })
            .collect()
    }

    /// Detect invisible characters in the text.
    #[must_use]
    pub fn detect_invisible_chars(&self, text: &str) -> Vec<InvisibleCharDetection> {
        text.chars()
            .enumerate()
            .filter_map(|(pos, c)| {
                let name = invisible_char_name(c)?;
                Some(InvisibleCharDetection {
                    position: pos,
                    char_code: c as u32,
                    char_name: name,
                })
            })
            .collect()
    }

    /// Detect unicode tricks (bidi overrides, tag chars, etc.).
    #[must_use]
    pub fn detect_unicode_tricks(&self, text: &str) -> Vec<UnicodeTrickDetection> {
        let mut tricks = Vec::new();

        for (pos, c) in text.chars().enumerate() {
            let cp = c as u32;

            if let Some(trick) = detect_bidi_trick(pos, cp) {
                tricks.push(trick);
                continue;
            }

            if (0xE0001..=0xE007F).contains(&cp) {
                tricks.push(UnicodeTrickDetection {
                    position: pos,
                    trick_type: "tag_character".to_string(),
                    description: format!("Tag character U+{cp:04X} can hide text"),
                });
                continue;
            }

            // Check suspicious ranges for non-Latin script mixed into Latin context
            for &(start, end) in &self.suspicious_char_ranges {
                if (start..=end).contains(&cp) {
                    tricks.push(UnicodeTrickDetection {
                        position: pos,
                        trick_type: "suspicious_script".to_string(),
                        description: format!(
                            "Character U+{cp:04X} from suspicious range [{start:04X}-{end:04X}]"
                        ),
                    });
                    break;
                }
            }
        }
        tricks
    }

    /// Compute statistical anomaly in character distribution.
    ///
    /// Returns a score in [0.0, 1.0] where higher means more anomalous.
    /// A text mixing multiple scripts or containing many non-ASCII chars
    /// in otherwise ASCII text scores higher.
    #[must_use]
    pub fn compute_char_distribution_anomaly(&self, text: &str) -> f64 {
        let total = text.chars().count();
        if total == 0 {
            return 0.0;
        }

        let ascii_count = text.chars().filter(|c| c.is_ascii_alphanumeric()).count();
        let non_ascii_alpha = text
            .chars()
            .filter(|c| !c.is_ascii() && c.is_alphabetic())
            .count();

        // If text is mostly ASCII but has some non-ASCII alphabetic chars,
        // that is suspicious (potential homoglyph attack).
        if ascii_count == 0 {
            return 0.0; // Entirely non-ASCII text is not necessarily suspicious
        }

        let non_ascii_ratio = non_ascii_alpha as f64 / total as f64;
        let ascii_ratio = ascii_count as f64 / total as f64;

        // Mixed script: high ASCII ratio + some non-ASCII alphabetic = suspicious
        if ascii_ratio > 0.5 && non_ascii_ratio > 0.0 {
            return (non_ascii_ratio * 5.0).min(1.0);
        }

        0.0
    }
}

impl Default for PerturbationDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PerturbationDetector helpers
// ---------------------------------------------------------------------------

fn build_homoglyph_map() -> HashMap<char, char> {
    let mut m = HashMap::new();
    // Cyrillic lowercase
    m.insert('\u{0430}', 'a');
    m.insert('\u{0435}', 'e');
    m.insert('\u{043E}', 'o');
    m.insert('\u{0440}', 'p');
    m.insert('\u{0441}', 'c');
    m.insert('\u{0445}', 'x');
    m.insert('\u{0443}', 'y');
    m.insert('\u{0456}', 'i');
    m.insert('\u{0458}', 'j');
    m.insert('\u{04BB}', 'h');
    // Cyrillic uppercase
    m.insert('\u{0410}', 'A');
    m.insert('\u{0412}', 'B');
    m.insert('\u{0415}', 'E');
    m.insert('\u{041A}', 'K');
    m.insert('\u{041C}', 'M');
    m.insert('\u{041D}', 'H');
    m.insert('\u{041E}', 'O');
    m.insert('\u{0420}', 'P');
    m.insert('\u{0421}', 'C');
    m.insert('\u{0422}', 'T');
    m.insert('\u{0425}', 'X');
    // Greek
    m.insert('\u{03BF}', 'o');
    m.insert('\u{03B1}', 'a');
    m.insert('\u{0391}', 'A');
    m.insert('\u{0392}', 'B');
    m.insert('\u{0395}', 'E');
    m.insert('\u{039F}', 'O');
    m.insert('\u{03A1}', 'P');
    m.insert('\u{03A4}', 'T');
    m.insert('\u{03A7}', 'X');
    m.insert('\u{03A5}', 'Y');
    m
}

fn default_suspicious_ranges() -> Vec<(u32, u32)> {
    vec![
        (0x0400, 0x04FF), // Cyrillic
        (0x0500, 0x052F), // Cyrillic Supplement
        (0x2DE0, 0x2DFF), // Cyrillic Extended-A
        (0xA640, 0xA69F), // Cyrillic Extended-B
        (0x0370, 0x03FF), // Greek and Coptic
        (0x1F00, 0x1FFF), // Greek Extended
    ]
}

/// Return a human-readable name for an invisible character, or None if visible.
fn invisible_char_name(c: char) -> Option<String> {
    match c {
        '\u{200B}' => Some("zero-width space".to_string()),
        '\u{200C}' => Some("zero-width non-joiner".to_string()),
        '\u{200D}' => Some("zero-width joiner".to_string()),
        '\u{FEFF}' => Some("byte order mark".to_string()),
        '\u{00AD}' => Some("soft hyphen".to_string()),
        '\u{2060}' => Some("word joiner".to_string()),
        '\u{2028}' => Some("line separator".to_string()),
        '\u{2029}' => Some("paragraph separator".to_string()),
        c if c.is_control() && c != '\n' && c != '\t' && c != '\r' => {
            Some(format!("control character U+{:04X}", c as u32))
        }
        _ => None,
    }
}

fn detect_bidi_trick(pos: usize, cp: u32) -> Option<UnicodeTrickDetection> {
    let (trick_type, description) = match cp {
        0x202A => ("bidi_override", "left-to-right embedding"),
        0x202B => ("bidi_override", "right-to-left embedding"),
        0x202C => ("bidi_override", "pop directional formatting"),
        0x202D => ("bidi_override", "left-to-right override"),
        0x202E => ("bidi_override", "right-to-left override"),
        0x2066 => ("bidi_isolate", "left-to-right isolate"),
        0x2067 => ("bidi_isolate", "right-to-left isolate"),
        0x2068 => ("bidi_isolate", "first strong isolate"),
        0x2069 => ("bidi_isolate", "pop directional isolate"),
        _ => return None,
    };
    Some(UnicodeTrickDetection {
        position: pos,
        trick_type: trick_type.to_string(),
        description: description.to_string(),
    })
}

// ---------------------------------------------------------------------------
// ConfidenceCalibrator
// ---------------------------------------------------------------------------

/// Temperature-scaled confidence calibration.
///
/// Applies Platt-style temperature scaling to raw confidence scores.
/// Higher temperature -> softer (less extreme) probabilities, reducing
/// overconfidence on adversarial inputs.
#[derive(Debug, Clone)]
pub struct ConfidenceCalibrator {
    temperature: f64,
}

impl ConfidenceCalibrator {
    /// Create a calibrator with the given temperature.
    ///
    /// Temperature must be > 0. Default recommended: 1.5.
    #[must_use]
    pub fn new(temperature: f64) -> Self {
        assert!(temperature > 0.0, "temperature must be positive");
        Self { temperature }
    }

    /// Apply temperature scaling to a raw confidence score in [0.0, 1.0].
    ///
    /// Converts confidence to logit, divides by temperature, then applies
    /// sigmoid to get the calibrated confidence.
    #[must_use]
    pub fn calibrate(&self, raw_confidence: f64) -> f64 {
        let clamped = raw_confidence.clamp(1e-7, 1.0 - 1e-7);
        let logit = (clamped / (1.0 - clamped)).ln();
        let scaled_logit = logit / self.temperature;
        sigmoid(scaled_logit)
    }

    /// Calibrate confidence with perturbation context.
    ///
    /// If the perturbation score is high, the confidence is further reduced
    /// to flag the input for human review.
    #[must_use]
    pub fn calibrate_with_perturbation_context(
        &self,
        raw_confidence: f64,
        perturbation_score: f64,
    ) -> f64 {
        let base = self.calibrate(raw_confidence);
        // Reduce confidence proportionally to perturbation suspicion
        let penalty = perturbation_score.clamp(0.0, 1.0);
        // At max perturbation, reduce confidence by up to 40%
        base * (1.0 - 0.4 * penalty)
    }
}

/// Standard sigmoid function.
#[must_use]
fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

// ---------------------------------------------------------------------------
// AdversarialDefenseConfig
// ---------------------------------------------------------------------------

/// Configuration for the adversarial defense orchestrator.
#[derive(Debug, Clone)]
pub struct AdversarialDefenseConfig {
    /// Which normalization passes to apply, in order.
    pub normalization_passes: Vec<NormalizationPass>,
    /// Temperature for confidence calibration.
    pub calibration_temperature: f64,
    /// Perturbation score above this threshold flags input as adversarial.
    pub perturbation_threshold: f64,
    /// Whether to detect homoglyph characters.
    pub enable_homoglyph_detection: bool,
    /// Whether to detect invisible characters.
    pub enable_invisible_char_detection: bool,
}

impl Default for AdversarialDefenseConfig {
    fn default() -> Self {
        Self {
            normalization_passes: vec![
                NormalizationPass::UnicodeNfkc,
                NormalizationPass::ZeroWidthRemoval,
                NormalizationPass::InvisibleCharRemoval,
                NormalizationPass::HomoglyphNormalization,
                NormalizationPass::WhitespaceNormalization,
                NormalizationPass::AccentStripping,
                NormalizationPass::CaseNormalization,
            ],
            calibration_temperature: 1.5,
            perturbation_threshold: 0.3,
            enable_homoglyph_detection: true,
            enable_invisible_char_detection: true,
        }
    }
}

// ---------------------------------------------------------------------------
// AdversarialAnalysis
// ---------------------------------------------------------------------------

/// Complete adversarial analysis result.
#[derive(Debug, Clone)]
pub struct AdversarialAnalysis {
    /// The original input text.
    pub original_text: String,
    /// The normalized text after all passes.
    pub normalized_text: String,
    /// Detailed normalization result with per-pass metrics.
    pub normalization_result: NormalizationResult,
    /// Perturbation detection report.
    pub perturbation_report: PerturbationReport,
    /// Whether the input is classified as adversarial.
    pub is_adversarial: bool,
    /// How much to adjust downstream model confidence (multiplicative factor).
    pub confidence_adjustment: f64,
}

// ---------------------------------------------------------------------------
// AdversarialDefense (orchestrator)
// ---------------------------------------------------------------------------

/// Orchestrates multi-pass normalization, perturbation detection, and
/// confidence calibration for adversarial ML robustness.
#[derive(Debug, Clone)]
pub struct AdversarialDefense {
    normalizer: MultiPassNormalizer,
    perturbation_detector: PerturbationDetector,
    confidence_calibrator: ConfidenceCalibrator,
    config: AdversarialDefenseConfig,
}

impl AdversarialDefense {
    /// Create with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(AdversarialDefenseConfig::default())
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: AdversarialDefenseConfig) -> Self {
        let normalizer = MultiPassNormalizer::new(config.normalization_passes.clone());
        let perturbation_detector = PerturbationDetector::new();
        let confidence_calibrator = ConfidenceCalibrator::new(config.calibration_temperature);

        Self {
            normalizer,
            perturbation_detector,
            confidence_calibrator,
            config,
        }
    }

    /// Run the full adversarial analysis pipeline on the input text.
    #[must_use]
    pub fn analyze(&self, text: &str) -> AdversarialAnalysis {
        let normalization_result = self.normalizer.normalize(text);

        let perturbation_report = self.perturbation_detector.detect_perturbations(text);

        let is_adversarial = perturbation_report.overall_suspicion
            > self.config.perturbation_threshold
            || normalization_result.suspicion_score > self.config.perturbation_threshold;

        // Compute confidence adjustment: calibrate a baseline 0.9 confidence
        // with perturbation context to get a multiplicative factor.
        let baseline = 0.9;
        let adjusted = self
            .confidence_calibrator
            .calibrate_with_perturbation_context(baseline, perturbation_report.overall_suspicion);
        let confidence_adjustment = adjusted / baseline;

        AdversarialAnalysis {
            original_text: text.to_string(),
            normalized_text: normalization_result.normalized.clone(),
            normalization_result,
            perturbation_report,
            is_adversarial,
            confidence_adjustment,
        }
    }

    /// Convert an adversarial analysis into security findings.
    #[must_use]
    pub fn to_security_findings(analysis: &AdversarialAnalysis) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if !analysis.perturbation_report.homoglyphs.is_empty() {
            let count = analysis.perturbation_report.homoglyphs.len();
            let severity = if count >= 5 {
                SecuritySeverity::High
            } else if count >= 2 {
                SecuritySeverity::Medium
            } else {
                SecuritySeverity::Low
            };
            findings.push(SecurityFinding::new(
                severity,
                "adversarial_homoglyph".to_string(),
                format!(
                    "Detected {count} homoglyph character(s) that may indicate adversarial evasion"
                ),
                analysis.perturbation_report.overall_suspicion,
            ));
        }

        if !analysis.perturbation_report.invisible_chars.is_empty() {
            let count = analysis.perturbation_report.invisible_chars.len();
            findings.push(SecurityFinding::new(
                SecuritySeverity::Medium,
                "adversarial_invisible_chars".to_string(),
                format!(
                    "Detected {count} invisible character(s) that may be used to bypass detection"
                ),
                analysis.perturbation_report.overall_suspicion,
            ));
        }

        if !analysis.perturbation_report.unicode_tricks.is_empty() {
            let count = analysis.perturbation_report.unicode_tricks.len();
            findings.push(SecurityFinding::new(
                SecuritySeverity::High,
                "adversarial_unicode_tricks".to_string(),
                format!("Detected {count} unicode trick(s) (bidi overrides, tag characters, etc.)"),
                analysis.perturbation_report.overall_suspicion,
            ));
        }

        if analysis.is_adversarial {
            findings.push(SecurityFinding::new(
                SecuritySeverity::High,
                "adversarial_input".to_string(),
                format!(
                    "Input classified as adversarial (suspicion: {:.2}, edit distance: {})",
                    analysis.normalization_result.suspicion_score,
                    analysis.normalization_result.edit_distance
                ),
                analysis.perturbation_report.overall_suspicion,
            ));
        }

        findings
    }
}

impl Default for AdversarialDefense {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Unicode NFKC normalization -----------------------------------------

    #[test]
    fn nfkc_normalizes_fullwidth_chars() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::UnicodeNfkc]);
        let result = normalizer.normalize("\u{FF28}\u{FF25}\u{FF2C}\u{FF2C}\u{FF2F}");
        assert_eq!(result.normalized, "HELLO");
    }

    #[test]
    fn nfkc_normalizes_superscript() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::UnicodeNfkc]);
        let result = normalizer.normalize("\u{00B2}");
        assert_eq!(result.normalized, "2");
    }

    // -- Zero-width character removal ---------------------------------------

    #[test]
    fn zero_width_removal_strips_zwsp() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::ZeroWidthRemoval]);
        let result = normalizer.normalize("he\u{200B}llo");
        assert_eq!(result.normalized, "hello");
    }

    #[test]
    fn zero_width_removal_strips_all_types() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::ZeroWidthRemoval]);
        let input = "a\u{200B}b\u{200C}c\u{200D}d\u{FEFF}e";
        let result = normalizer.normalize(input);
        assert_eq!(result.normalized, "abcde");
    }

    // -- Homoglyph detection and normalization ------------------------------

    #[test]
    fn homoglyph_normalization_cyrillic_a() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::HomoglyphNormalization]);
        let result = normalizer.normalize("\u{0430}ttack");
        assert_eq!(result.normalized, "attack");
    }

    #[test]
    fn homoglyph_normalization_mixed_cyrillic_word() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::HomoglyphNormalization]);
        // "ignоre" with Cyrillic o
        let result = normalizer.normalize("ign\u{043E}re");
        assert_eq!(result.normalized, "ignore");
    }

    #[test]
    fn homoglyph_normalization_fullwidth_digits() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::HomoglyphNormalization]);
        let result = normalizer.normalize("\u{FF11}\u{FF12}\u{FF13}");
        assert_eq!(result.normalized, "123");
    }

    #[test]
    fn homoglyph_normalization_math_bold() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::HomoglyphNormalization]);
        // Mathematical bold A, B, C
        let result = normalizer.normalize("\u{1D400}\u{1D401}\u{1D402}");
        assert_eq!(result.normalized, "ABC");
    }

    #[test]
    fn homoglyph_normalization_math_italic() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::HomoglyphNormalization]);
        // Mathematical italic a, b, c
        let result = normalizer.normalize("\u{1D44E}\u{1D44F}\u{1D450}");
        assert_eq!(result.normalized, "abc");
    }

    // -- Whitespace normalization -------------------------------------------

    #[test]
    fn whitespace_normalization_collapses_multiple() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::WhitespaceNormalization]);
        let result = normalizer.normalize("hello   world");
        assert_eq!(result.normalized, "hello world");
    }

    #[test]
    fn whitespace_normalization_converts_exotic_spaces() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::WhitespaceNormalization]);
        // En space (U+2002) and em space (U+2003)
        let result = normalizer.normalize("hello\u{2002}\u{2003}world");
        assert_eq!(result.normalized, "hello world");
    }

    // -- Invisible character detection --------------------------------------

    #[test]
    fn invisible_char_removal_strips_control_chars() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::InvisibleCharRemoval]);
        // Keep \n and \t, remove other control chars
        let result = normalizer.normalize("hello\n\tworld\u{0001}!");
        assert_eq!(result.normalized, "hello\n\tworld!");
    }

    #[test]
    fn invisible_char_removal_strips_soft_hyphen() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::InvisibleCharRemoval]);
        let result = normalizer.normalize("ig\u{00AD}nore");
        assert_eq!(result.normalized, "ignore");
    }

    // -- Accent stripping ---------------------------------------------------

    #[test]
    fn accent_stripping_removes_diacritics() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::AccentStripping]);
        let result = normalizer.normalize("caf\u{00E9}");
        assert_eq!(result.normalized, "cafe");
    }

    #[test]
    fn accent_stripping_handles_multiple_accents() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::AccentStripping]);
        let result = normalizer.normalize("r\u{00E9}sum\u{00E9}");
        assert_eq!(result.normalized, "resume");
    }

    // -- Multi-pass normalization (all passes together) ---------------------

    #[test]
    fn all_passes_normalize_complex_evasion() {
        let normalizer = MultiPassNormalizer::with_all_passes();
        // Cyrillic 'a' + zero-width space + accented e + fullwidth H
        let input = "\u{0430}\u{200B}\u{00E9}\u{FF28}";
        let result = normalizer.normalize(input);
        // After all passes: a + (removed) + e + h -> "aeh"
        assert_eq!(result.normalized, "aeh");
    }

    #[test]
    fn all_passes_record_changes_per_pass() {
        let normalizer = MultiPassNormalizer::with_all_passes();
        let result = normalizer.normalize("he\u{200B}llo");
        assert_eq!(result.passes_applied.len(), 7);
        // At least the ZeroWidthRemoval pass should have 1 change
        let zw_changes = result
            .changes_per_pass
            .iter()
            .find(|(p, _)| *p == NormalizationPass::ZeroWidthRemoval);
        assert!(zw_changes.is_some());
        assert!(zw_changes.unwrap().1 > 0);
    }

    // -- Edit distance computation ------------------------------------------

    #[test]
    fn edit_distance_identical_strings() {
        assert_eq!(count_char_differences("hello", "hello"), 0);
    }

    #[test]
    fn edit_distance_different_chars() {
        assert_eq!(count_char_differences("abc", "axc"), 1);
    }

    #[test]
    fn edit_distance_different_lengths() {
        assert_eq!(count_char_differences("abcde", "abc"), 2);
    }

    // -- Suspicion score calculation ----------------------------------------

    #[test]
    fn suspicion_score_zero_for_clean_text() {
        let normalizer = MultiPassNormalizer::with_all_passes();
        let result = normalizer.normalize("hello world");
        // Clean text should have suspicion near 0 (only case normalization changes)
        assert!(result.suspicion_score < 0.5);
    }

    #[test]
    fn suspicion_score_high_for_adversarial_text() {
        let normalizer = MultiPassNormalizer::with_all_passes();
        // Text made entirely of Cyrillic homoglyphs + zero-width chars
        let input = "\u{0430}\u{200B}\u{0435}\u{200C}\u{043E}\u{200D}\u{0441}";
        let result = normalizer.normalize(input);
        assert!(
            result.suspicion_score > 0.3,
            "suspicion_score={}, expected > 0.3",
            result.suspicion_score
        );
    }

    #[test]
    fn suspicion_score_zero_for_empty() {
        assert_eq!(compute_suspicion_score(0, 0), 0.0);
    }

    // -- Perturbation detection on clean text (no false positives) ----------

    #[test]
    fn perturbation_clean_ascii_text() {
        let detector = PerturbationDetector::new();
        let report = detector.detect_perturbations("Hello world, this is clean text.");
        assert!(report.homoglyphs.is_empty());
        assert!(report.invisible_chars.is_empty());
        assert!(!report.is_likely_adversarial);
        assert_eq!(report.overall_suspicion, 0.0);
    }

    #[test]
    fn perturbation_clean_text_with_newlines() {
        let detector = PerturbationDetector::new();
        let report = detector.detect_perturbations("Line one\nLine two\n");
        assert!(report.invisible_chars.is_empty());
        assert!(!report.is_likely_adversarial);
    }

    // -- Perturbation detection on adversarial text -------------------------

    #[test]
    fn perturbation_detects_cyrillic_homoglyphs() {
        let detector = PerturbationDetector::new();
        // "аttack" with Cyrillic a
        let report = detector.detect_perturbations("\u{0430}ttack");
        assert_eq!(report.homoglyphs.len(), 1);
        assert_eq!(report.homoglyphs[0].original_char, '\u{0430}');
        assert_eq!(report.homoglyphs[0].likely_intended, 'a');
        assert_eq!(report.homoglyphs[0].position, 0);
    }

    #[test]
    fn perturbation_detects_invisible_chars() {
        let detector = PerturbationDetector::new();
        let report = detector.detect_perturbations("he\u{200B}llo");
        assert_eq!(report.invisible_chars.len(), 1);
        assert_eq!(report.invisible_chars[0].char_code, 0x200B);
        assert_eq!(report.invisible_chars[0].char_name, "zero-width space");
    }

    #[test]
    fn perturbation_detects_bidi_overrides() {
        let detector = PerturbationDetector::new();
        let report = detector.detect_perturbations("hello\u{202E}world");
        assert!(!report.unicode_tricks.is_empty());
        assert_eq!(report.unicode_tricks[0].trick_type, "bidi_override");
    }

    #[test]
    fn perturbation_detects_tag_characters() {
        let detector = PerturbationDetector::new();
        let report = detector.detect_perturbations("safe\u{E0041}text");
        let tag_tricks: Vec<_> = report
            .unicode_tricks
            .iter()
            .filter(|t| t.trick_type == "tag_character")
            .collect();
        assert_eq!(tag_tricks.len(), 1);
    }

    #[test]
    fn perturbation_adversarial_flagged() {
        let detector = PerturbationDetector::new();
        // Multiple homoglyphs + invisible char
        let report = detector.detect_perturbations("\u{0430}\u{200B}\u{0435}\u{200C}\u{043E}");
        assert!(report.is_likely_adversarial);
        assert!(report.overall_suspicion > 0.0);
    }

    // -- Confidence calibration with temperature ----------------------------

    #[test]
    fn calibration_temperature_1_is_identity() {
        let calibrator = ConfidenceCalibrator::new(1.0);
        let result = calibrator.calibrate(0.8);
        // Temperature 1.0 should return approximately the same value
        assert!((result - 0.8).abs() < 1e-6, "result={result}");
    }

    #[test]
    fn calibration_high_temperature_reduces_confidence() {
        let calibrator = ConfidenceCalibrator::new(2.0);
        let result = calibrator.calibrate(0.9);
        // Higher temperature should pull confidence toward 0.5
        assert!(result < 0.9, "expected < 0.9, got {result}");
        assert!(result > 0.5, "expected > 0.5, got {result}");
    }

    #[test]
    fn calibration_symmetric_around_half() {
        let calibrator = ConfidenceCalibrator::new(1.5);
        let result = calibrator.calibrate(0.5);
        assert!((result - 0.5).abs() < 1e-6, "result={result}");
    }

    #[test]
    fn calibration_clamps_extreme_values() {
        let calibrator = ConfidenceCalibrator::new(1.5);
        let high = calibrator.calibrate(0.999);
        let low = calibrator.calibrate(0.001);
        assert!(high < 1.0);
        assert!(low > 0.0);
    }

    // -- Confidence adjustment based on perturbation context ----------------

    #[test]
    fn perturbation_context_reduces_confidence() {
        let calibrator = ConfidenceCalibrator::new(1.5);
        let base = calibrator.calibrate(0.8);
        let reduced = calibrator.calibrate_with_perturbation_context(0.8, 0.5);
        assert!(reduced < base, "expected {reduced} < {base}");
    }

    #[test]
    fn perturbation_context_zero_perturbation_no_change() {
        let calibrator = ConfidenceCalibrator::new(1.5);
        let base = calibrator.calibrate(0.8);
        let same = calibrator.calibrate_with_perturbation_context(0.8, 0.0);
        assert!((same - base).abs() < 1e-10);
    }

    #[test]
    fn perturbation_context_max_perturbation_reduces_by_40_percent() {
        let calibrator = ConfidenceCalibrator::new(1.5);
        let base = calibrator.calibrate(0.8);
        let max_penalty = calibrator.calibrate_with_perturbation_context(0.8, 1.0);
        let expected = base * 0.6;
        assert!(
            (max_penalty - expected).abs() < 1e-10,
            "expected {expected}, got {max_penalty}"
        );
    }

    // -- Full adversarial analysis pipeline ---------------------------------

    #[test]
    fn full_pipeline_clean_text() {
        let defense = AdversarialDefense::new();
        let analysis = defense.analyze("Hello world, this is a normal sentence.");
        assert!(!analysis.is_adversarial);
        assert!(analysis.confidence_adjustment > 0.9);
    }

    #[test]
    fn full_pipeline_adversarial_text() {
        let defense = AdversarialDefense::new();
        // Cyrillic homoglyphs + zero-width chars
        let input = "\u{0430}\u{200B}tt\u{0430}\u{200C}ck \u{0441}ommand";
        let analysis = defense.analyze(input);
        assert!(analysis.is_adversarial);
        assert!(analysis.confidence_adjustment < 1.0);
    }

    // -- Real-world evasion examples ----------------------------------------

    #[test]
    fn real_world_cyrillic_a_in_english() {
        let defense = AdversarialDefense::new();
        // "ignore previous instructions" with Cyrillic a and o
        let input = "ign\u{043E}re previous instructi\u{043E}ns";
        let analysis = defense.analyze(input);
        // Normalized text should have Latin chars
        assert!(analysis.normalized_text.contains("ignore"));
        assert!(!analysis.perturbation_report.homoglyphs.is_empty());
    }

    #[test]
    fn real_world_zero_width_between_letters() {
        let defense = AdversarialDefense::new();
        let input = "i\u{200B}g\u{200C}n\u{200D}o\u{FEFF}re";
        let analysis = defense.analyze(input);
        assert!(analysis.normalized_text.contains("ignore"));
        assert!(!analysis.perturbation_report.invisible_chars.is_empty());
    }

    // -- SecurityFinding generation -----------------------------------------

    #[test]
    fn security_findings_empty_for_clean_text() {
        let defense = AdversarialDefense::new();
        let analysis = defense.analyze("This is clean English text.");
        let findings = AdversarialDefense::to_security_findings(&analysis);
        // Clean text should produce no findings
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    #[test]
    fn security_findings_generated_for_homoglyphs() {
        let defense = AdversarialDefense::new();
        let input = "\u{0430}\u{0435}\u{043E}\u{0441}\u{0445} hello";
        let analysis = defense.analyze(input);
        let findings = AdversarialDefense::to_security_findings(&analysis);
        let homoglyph_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "adversarial_homoglyph")
            .collect();
        assert!(!homoglyph_findings.is_empty());
    }

    #[test]
    fn security_findings_generated_for_invisible_chars() {
        let defense = AdversarialDefense::new();
        let input = "test\u{200B}\u{200C}\u{200D}input";
        let analysis = defense.analyze(input);
        let findings = AdversarialDefense::to_security_findings(&analysis);
        let invis_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "adversarial_invisible_chars")
            .collect();
        assert!(!invis_findings.is_empty());
    }

    #[test]
    fn security_findings_include_adversarial_flag() {
        let defense = AdversarialDefense::new();
        let input = "\u{0430}\u{200B}\u{0435}\u{200C}\u{043E}\u{200D}\u{0441}";
        let analysis = defense.analyze(input);
        assert!(analysis.is_adversarial);
        let findings = AdversarialDefense::to_security_findings(&analysis);
        let adv_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "adversarial_input")
            .collect();
        assert!(!adv_findings.is_empty());
    }

    // -- Config defaults ----------------------------------------------------

    #[test]
    fn config_defaults_correct() {
        let config = AdversarialDefenseConfig::default();
        assert_eq!(config.calibration_temperature, 1.5);
        assert_eq!(config.perturbation_threshold, 0.3);
        assert!(config.enable_homoglyph_detection);
        assert!(config.enable_invisible_char_detection);
        assert_eq!(config.normalization_passes.len(), 7);
    }

    #[test]
    fn config_custom_temperature() {
        let config = AdversarialDefenseConfig {
            calibration_temperature: 2.0,
            ..AdversarialDefenseConfig::default()
        };
        let defense = AdversarialDefense::with_config(config);
        let analysis = defense.analyze("test");
        // Should not panic, defense should work with custom config
        assert!(!analysis.original_text.is_empty());
    }

    // -- Edge cases ---------------------------------------------------------

    #[test]
    fn edge_case_empty_string() {
        let defense = AdversarialDefense::new();
        let analysis = defense.analyze("");
        assert!(!analysis.is_adversarial);
        assert_eq!(analysis.normalized_text, "");
        assert_eq!(analysis.normalization_result.edit_distance, 0);
        assert_eq!(analysis.normalization_result.suspicion_score, 0.0);
    }

    #[test]
    fn edge_case_ascii_only_text() {
        let defense = AdversarialDefense::new();
        let analysis = defense.analyze("Hello World 123!@#");
        assert!(!analysis.is_adversarial);
        // Suspicion should be very low for ASCII-only text
        // (only case normalization changes, which is expected)
        assert!(
            analysis.normalization_result.suspicion_score < 0.5,
            "score={}",
            analysis.normalization_result.suspicion_score
        );
    }

    #[test]
    fn edge_case_all_unicode_text() {
        let defense = AdversarialDefense::new();
        // Entirely Cyrillic homoglyphs
        let input = "\u{0430}\u{0435}\u{043E}\u{0440}\u{0441}\u{0445}\u{0443}";
        let analysis = defense.analyze(input);
        assert!(analysis.is_adversarial);
        assert!(analysis.normalization_result.suspicion_score > 0.5);
    }

    // -- char_distribution_anomaly ------------------------------------------

    #[test]
    fn char_distribution_anomaly_clean_ascii() {
        let detector = PerturbationDetector::new();
        let score = detector.compute_char_distribution_anomaly("Hello world");
        assert_eq!(score, 0.0);
    }

    #[test]
    fn char_distribution_anomaly_mixed_script() {
        let detector = PerturbationDetector::new();
        // Mostly ASCII with some Cyrillic
        let score = detector.compute_char_distribution_anomaly("hell\u{043E} w\u{043E}rld");
        assert!(score > 0.0, "expected > 0.0, got {score}");
    }

    #[test]
    fn char_distribution_anomaly_empty() {
        let detector = PerturbationDetector::new();
        assert_eq!(detector.compute_char_distribution_anomaly(""), 0.0);
    }

    // -- Homoglyph map completeness -----------------------------------------

    #[test]
    fn homoglyph_map_contains_cyrillic_entries() {
        let map = build_homoglyph_map();
        assert_eq!(map[&'\u{0430}'], 'a');
        assert_eq!(map[&'\u{0435}'], 'e');
        assert_eq!(map[&'\u{043E}'], 'o');
        assert_eq!(map[&'\u{0440}'], 'p');
        assert_eq!(map[&'\u{0441}'], 'c');
        assert_eq!(map[&'\u{0445}'], 'x');
        assert_eq!(map[&'\u{0443}'], 'y');
    }

    #[test]
    fn homoglyph_map_contains_greek_entries() {
        let map = build_homoglyph_map();
        assert_eq!(map[&'\u{03BF}'], 'o');
        assert_eq!(map[&'\u{03B1}'], 'a');
        assert_eq!(map[&'\u{0391}'], 'A');
        assert_eq!(map[&'\u{0392}'], 'B');
    }

    // -- Normalizer with subset of passes -----------------------------------

    #[test]
    fn normalizer_with_single_pass() {
        let normalizer = MultiPassNormalizer::new(vec![NormalizationPass::CaseNormalization]);
        let result = normalizer.normalize("HELLO");
        assert_eq!(result.normalized, "hello");
        assert_eq!(result.passes_applied.len(), 1);
    }

    #[test]
    fn normalizer_with_empty_passes() {
        let normalizer = MultiPassNormalizer::new(vec![]);
        let result = normalizer.normalize("Hello");
        assert_eq!(result.normalized, "Hello");
        assert_eq!(result.edit_distance, 0);
    }
}
