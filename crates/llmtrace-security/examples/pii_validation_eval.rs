//! Corpus-level correctness eval for the non-ML PII checksum validators in
//! `llmtrace_security::pii_validation`.
//!
//! SCOPE / HONESTY:
//! - The dataset here is SYNTHETIC and DETERMINISTICALLY constructed. "Valid"
//!   inputs are built so the real checksum genuinely passes: Luhn check digits
//!   are computed with the correct algorithm, IBAN check digits are computed via
//!   real MOD-97, SSN components are drawn from the legal ranges. "Invalid"
//!   inputs are constructed to genuinely fail (wrong check digit / check digits,
//!   malformed length, illegal area). NO detector output is faked or hardcoded —
//!   the validators under test are invoked for real on every sample.
//! - This measures VALIDATOR CORRECTNESS on well-formed valid/invalid inputs
//!   (does the checksum/structural rule classify a clean string correctly?). It
//!   is NOT free-text PII detection: locating PII inside arbitrary prose is the
//!   job of the ML `ner_detector`, which is gated behind the `ml` feature and
//!   blocked offline. That path is out of scope for this eval.
//! - Metric convention: a sample is POSITIVE if it is genuinely valid (the
//!   validator is expected to return `true`). TP = valid input accepted,
//!   FP = invalid input wrongly accepted, FN = valid input wrongly rejected,
//!   TN = invalid input correctly rejected.
//!
//! Run:
//!   cargo run -q -p llmtrace-security --example pii_validation_eval

use llmtrace_security::pii_validation::{validate_credit_card, validate_iban, validate_ssn};

/// One labeled sample: the input string and whether it is genuinely valid.
struct Sample {
    input: String,
    expected_valid: bool,
}

/// Confusion-matrix counts plus derived metrics for one validator.
#[derive(Default)]
struct Metrics {
    tp: usize,
    fp: usize,
    tn: usize,
    fn_: usize,
}

impl Metrics {
    fn record(&mut self, expected_valid: bool, predicted_valid: bool) {
        match (expected_valid, predicted_valid) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
    }
    fn total(&self) -> usize {
        self.tp + self.fp + self.tn + self.fn_
    }
    fn accuracy(&self) -> f64 {
        ratio(self.tp + self.tn, self.total())
    }
    fn precision(&self) -> f64 {
        ratio(self.tp, self.tp + self.fp)
    }
    fn recall(&self) -> f64 {
        ratio(self.tp, self.tp + self.fn_)
    }
    fn fpr(&self) -> f64 {
        ratio(self.fp, self.fp + self.tn)
    }
}

fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

/// Tiny deterministic LCG (numerical-recipes constants) so the dataset is fixed
/// across runs without pulling in `rand`. Seeded explicitly per validator.
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 33) as u32
    }
    fn digit(&mut self) -> u8 {
        (self.next_u32() % 10) as u8
    }
    fn range(&mut self, lo: u32, hi_inclusive: u32) -> u32 {
        lo + self.next_u32() % (hi_inclusive - lo + 1)
    }
}

/// Compute the Luhn check digit for a body of digits (the body is everything
/// except the final check digit). Mirrors the standard algorithm.
fn luhn_check_digit(body: &[u8]) -> u8 {
    let mut sum = 0u32;
    // The check digit will sit at the rightmost position; positions are counted
    // from the right of the FULL number, so the body's rightmost digit is at
    // index 1 (a "doubled" position).
    for (i, &d) in body.iter().rev().enumerate() {
        let mut v = d as u32;
        if i % 2 == 0 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    ((10 - (sum % 10)) % 10) as u8
}

/// Build the credit-card sample set: valid Luhn numbers across the common
/// lengths, plus invalid (wrong check digit, malformed length, non-digit).
fn credit_card_samples() -> Vec<Sample> {
    let mut rng = Lcg::new(0xC0FFEE);
    let mut out = Vec::new();
    let lengths = [13usize, 15, 16, 16, 19];

    // Valid: build a body, append the correct Luhn check digit.
    for n in 0..50 {
        let len = lengths[n % lengths.len()];
        let mut body: Vec<u8> = (0..len - 1).map(|_| rng.digit()).collect();
        body[0] = (rng.range(1, 9)) as u8; // avoid leading zero / all-zero
        let check = luhn_check_digit(&body);
        let mut digits = body.clone();
        digits.push(check);
        out.push(Sample {
            input: digits.iter().map(|d| (b'0' + d) as char).collect(),
            expected_valid: true,
        });
    }

    // Invalid: same construction but flip the check digit to a wrong value.
    for n in 0..30 {
        let len = lengths[n % lengths.len()];
        let mut body: Vec<u8> = (0..len - 1).map(|_| rng.digit()).collect();
        body[0] = (rng.range(1, 9)) as u8;
        let good = luhn_check_digit(&body);
        let bad = (good + 1) % 10; // guaranteed to fail Luhn
        let mut digits = body.clone();
        digits.push(bad);
        out.push(Sample {
            input: digits.iter().map(|d| (b'0' + d) as char).collect(),
            expected_valid: false,
        });
    }

    // Invalid: malformed length (too short / too long) but otherwise Luhn-valid
    // body, so only the length rule should reject them.
    for &len in &[10usize, 11, 12, 20, 21] {
        let mut body: Vec<u8> = (0..len - 1).map(|_| rng.digit()).collect();
        body[0] = (rng.range(1, 9)) as u8;
        let check = luhn_check_digit(&body);
        let mut digits = body.clone();
        digits.push(check);
        out.push(Sample {
            input: digits.iter().map(|d| (b'0' + d) as char).collect(),
            expected_valid: false,
        });
    }

    // Invalid: contains a non-digit character (letter) inside a 16-char string.
    for _ in 0..15 {
        let mut body: Vec<u8> = (0..15).map(|_| rng.digit()).collect();
        body[0] = (rng.range(1, 9)) as u8;
        let mut s: String = body.iter().map(|d| (b'0' + d) as char).collect();
        s.replace_range(5..6, "X");
        out.push(Sample {
            input: s,
            expected_valid: false,
        });
    }

    out
}

/// (country code, total IBAN length) for a handful of real IBAN specs.
const IBAN_SPECS: &[(&str, usize)] = &[
    ("DE", 22),
    ("GB", 22),
    ("FR", 27),
    ("ES", 24),
    ("IT", 27),
    ("NL", 18),
    ("BE", 16),
];

/// Map an uppercase ASCII char to its IBAN numeric value (A=10..Z=35, 0..9 as-is).
fn iban_char_value(c: char) -> String {
    if c.is_ascii_alphabetic() {
        ((c as u32) - ('A' as u32) + 10).to_string()
    } else {
        c.to_string()
    }
}

/// MOD-97 over a (possibly huge) numeric string, iteratively. Matches the
/// reference algorithm used by the validator.
fn mod97_str(numeric: &str) -> u64 {
    let mut rem: u64 = 0;
    for b in numeric.bytes() {
        rem = (rem * 10 + (b - b'0') as u64) % 97;
    }
    rem
}

/// Compute the two ISO 13616 check digits for a country + BBAN so the resulting
/// IBAN genuinely passes MOD-97 (remainder == 1).
fn iban_check_digits(country: &str, bban: &str) -> String {
    // Rearranged form with check digits = "00", then numeric-encode.
    let rearranged = format!("{}{}00", bban, country);
    let numeric: String = rearranged.chars().map(iban_char_value).collect();
    let check = 98 - mod97_str(&numeric);
    format!("{:02}", check)
}

/// Build the IBAN sample set: valid IBANs with correct check digits across
/// several country specs, plus invalid (wrong check digits, too short, no
/// letter prefix).
fn iban_samples() -> Vec<Sample> {
    let mut rng = Lcg::new(0x1BA4);
    let mut out = Vec::new();

    // Valid: random alphanumeric BBAN, then real check digits.
    for n in 0..50 {
        let (country, total_len) = IBAN_SPECS[n % IBAN_SPECS.len()];
        let bban_len = total_len - 4; // country(2) + check(2)
        let bban = random_bban(&mut rng, bban_len);
        let check = iban_check_digits(country, &bban);
        out.push(Sample {
            input: format!("{}{}{}", country, check, bban),
            expected_valid: true,
        });
    }

    // Invalid: correct structure but wrong check digits (good+1 mod 100).
    for n in 0..30 {
        let (country, total_len) = IBAN_SPECS[n % IBAN_SPECS.len()];
        let bban_len = total_len - 4;
        let bban = random_bban(&mut rng, bban_len);
        let good: u32 = iban_check_digits(country, &bban).parse().unwrap();
        let bad = (good + 1) % 100;
        out.push(Sample {
            input: format!("{}{:02}{}", country, bad, bban),
            expected_valid: false,
        });
    }

    // Invalid: too short (< 15 chars) — structurally rejected.
    for n in 0..10 {
        let (country, _) = IBAN_SPECS[n % IBAN_SPECS.len()];
        let bban = random_bban(&mut rng, 6);
        let check = iban_check_digits(country, &bban);
        out.push(Sample {
            input: format!("{}{}{}", country, check, bban),
            expected_valid: false,
        });
    }

    // Invalid: no two-letter prefix (digits where letters belong).
    for _ in 0..10 {
        let bban = random_bban(&mut rng, 18);
        out.push(Sample {
            input: format!("12{}", bban),
            expected_valid: false,
        });
    }

    out
}

/// Generate a BBAN of `len` uppercase-alphanumeric characters deterministically.
fn random_bban(rng: &mut Lcg, len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    (0..len)
        .map(|_| ALPHABET[(rng.next_u32() as usize) % ALPHABET.len()] as char)
        .collect()
}

/// Build the SSN sample set: valid SSNs (legal area/group/serial), plus invalid
/// (area 000/666/900+, group 00, serial 0000, wrong length).
fn ssn_samples() -> Vec<Sample> {
    let mut rng = Lcg::new(0x55_11);
    let mut out = Vec::new();

    // Valid: area in {1..665, 667..899}, group 01..99, serial 0001..9999.
    for _ in 0..50 {
        let area = legal_ssn_area(&mut rng);
        let group = rng.range(1, 99);
        let serial = rng.range(1, 9999);
        out.push(Sample {
            input: format!("{:03}-{:02}-{:04}", area, group, serial),
            expected_valid: true,
        });
    }

    // Invalid: illegal area (000, 666, 900..999).
    let bad_areas = [0u32, 666, 900, 901, 950, 999];
    for n in 0..18 {
        let area = bad_areas[n % bad_areas.len()];
        let group = rng.range(1, 99);
        let serial = rng.range(1, 9999);
        out.push(Sample {
            input: format!("{:03}-{:02}-{:04}", area, group, serial),
            expected_valid: false,
        });
    }

    // Invalid: group 00.
    for _ in 0..12 {
        let area = legal_ssn_area(&mut rng);
        let serial = rng.range(1, 9999);
        out.push(Sample {
            input: format!("{:03}-00-{:04}", area, serial),
            expected_valid: false,
        });
    }

    // Invalid: serial 0000.
    for _ in 0..12 {
        let area = legal_ssn_area(&mut rng);
        let group = rng.range(1, 99);
        out.push(Sample {
            input: format!("{:03}-{:02}-0000", area, group),
            expected_valid: false,
        });
    }

    // Invalid: wrong length (8 digits).
    for _ in 0..8 {
        let group = rng.range(1, 99);
        let serial = rng.range(1, 9999);
        out.push(Sample {
            input: format!("{:02}-{:02}-{:04}", rng.range(1, 99), group, serial),
            expected_valid: false,
        });
    }

    out
}

/// Draw a legal SSN area number: 1..=665 or 667..=899 (excludes 000, 666, 900+).
fn legal_ssn_area(rng: &mut Lcg) -> u32 {
    loop {
        let a = rng.range(1, 899);
        if a != 666 {
            return a;
        }
    }
}

/// Run one validator over its labeled set, returning the metrics.
fn run_validator(samples: &[Sample], validator: fn(&str) -> bool) -> Metrics {
    let mut m = Metrics::default();
    for s in samples {
        m.record(s.expected_valid, validator(&s.input));
    }
    m
}

fn print_table(rows: &[(&str, &Metrics)]) {
    println!(
        "\n| {:<14} | {:>3} | {:>3} | {:>3} | {:>3} | {:>3} | {:>8} | {:>9} | {:>6} | {:>6} |",
        "validator", "N", "TP", "FP", "TN", "FN", "accuracy", "precision", "recall", "FPR"
    );
    println!(
        "|{:-<16}|{:-<5}|{:-<5}|{:-<5}|{:-<5}|{:-<5}|{:-<10}|{:-<11}|{:-<8}|{:-<8}|",
        "", "", "", "", "", "", "", "", "", ""
    );
    for (name, m) in rows {
        println!(
            "| {:<14} | {:>3} | {:>3} | {:>3} | {:>3} | {:>3} | {:>7.3} | {:>8.3} | {:>5.3} | {:>5.3} |",
            name,
            m.total(),
            m.tp,
            m.fp,
            m.tn,
            m.fn_,
            m.accuracy(),
            m.precision(),
            m.recall(),
            m.fpr(),
        );
    }
}

fn metrics_json(m: &Metrics) -> serde_json::Value {
    serde_json::json!({
        "n": m.total(),
        "tp": m.tp,
        "fp": m.fp,
        "tn": m.tn,
        "fn": m.fn_,
        "accuracy": m.accuracy(),
        "precision": m.precision(),
        "recall": m.recall(),
        "false_positive_rate": m.fpr(),
    })
}

fn main() {
    let cc = credit_card_samples();
    let iban = iban_samples();
    let ssn = ssn_samples();

    let cc_m = run_validator(&cc, validate_credit_card);
    let iban_m = run_validator(&iban, validate_iban);
    let ssn_m = run_validator(&ssn, validate_ssn);

    println!(
        "PII checksum-validator correctness eval (SYNTHETIC, deterministic)\n\
         positive class = genuinely valid input (validator should return true).\n\
         Scope: validator correctness on well-formed valid/invalid strings,\n\
         NOT free-text PII detection (that uses the ML ner_detector, blocked offline)."
    );
    print_table(&[("credit_card", &cc_m), ("iban", &iban_m), ("ssn", &ssn_m)]);

    let report = serde_json::json!({
        "scope": "Validator correctness on synthetic, deterministically constructed \
                  valid/invalid inputs. Positive class = genuinely valid. Valid inputs \
                  carry real Luhn / MOD-97 / SSN-range-correct values; invalid inputs \
                  genuinely fail. NOT free-text PII detection (ML ner_detector path).",
        "validators": {
            "validate_credit_card": metrics_json(&cc_m),
            "validate_iban": metrics_json(&iban_m),
            "validate_ssn": metrics_json(&ssn_m),
        },
    });

    let out_path = "benchmarks/results/pii_validation_eval.json";
    if let Some(parent) = std::path::Path::new(out_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(out_path, serde_json::to_string_pretty(&report).unwrap()) {
        Ok(()) => println!("\nwrote {out_path}"),
        Err(e) => eprintln!("\nfailed to write {out_path}: {e}"),
    }
}
