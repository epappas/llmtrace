//! Code security analysis for LLM-generated code outputs.
//!
//! Scans LLM response text for code blocks (Markdown fenced, indented, or inline)
//! and analyses them for common security vulnerabilities:
//!
//! - **SQL Injection** — string concatenation in SQL queries
//! - **Command Injection** — `os.system()`, `eval()`, `child_process.exec()`
//! - **Path Traversal** — `../` in file operations without sanitisation
//! - **Hardcoded Credentials** — `password = "..."`, AWS keys in code
//! - **Insecure Deserialization** — `pickle.loads()`, `yaml.load()` without SafeLoader
//! - **XSS Patterns** — `innerHTML`, `document.write()`, `dangerouslySetInnerHTML`
//! - **Insecure Crypto** — MD5/SHA1 for passwords, `Math.random()` for security

use llmtrace_core::{SecurityFinding, SecuritySeverity};
use regex::Regex;

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

/// Programming language detected in a code block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeLanguage {
    Python,
    JavaScript,
    TypeScript,
    Sql,
    Bash,
    Rust,
    Go,
    Java,
    C,
    Cpp,
    Ruby,
    Unknown,
}

impl std::fmt::Display for CodeLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Python => write!(f, "Python"),
            Self::JavaScript => write!(f, "JavaScript"),
            Self::TypeScript => write!(f, "TypeScript"),
            Self::Sql => write!(f, "SQL"),
            Self::Bash => write!(f, "Shell/Bash"),
            Self::Rust => write!(f, "Rust"),
            Self::Go => write!(f, "Go"),
            Self::Java => write!(f, "Java"),
            Self::C => write!(f, "C"),
            Self::Cpp => write!(f, "C++"),
            Self::Ruby => write!(f, "Ruby"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detect the programming language from a fenced code block's info string,
/// falling back to content heuristics.
fn detect_language(info_string: Option<&str>, code: &str) -> CodeLanguage {
    // 1. Check the info string (e.g. ```python)
    if let Some(info) = info_string {
        let lower = info.trim().to_lowercase();
        if lower.starts_with("python") || lower == "py" {
            return CodeLanguage::Python;
        }
        if lower.starts_with("javascript") || lower == "js" || lower == "node" {
            return CodeLanguage::JavaScript;
        }
        if lower.starts_with("typescript") || lower == "ts" {
            return CodeLanguage::TypeScript;
        }
        if lower == "sql" || lower == "mysql" || lower == "postgresql" || lower == "sqlite" {
            return CodeLanguage::Sql;
        }
        if lower == "bash" || lower == "sh" || lower == "shell" || lower == "zsh" {
            return CodeLanguage::Bash;
        }
        if lower == "rust" || lower == "rs" {
            return CodeLanguage::Rust;
        }
        if lower == "go" || lower == "golang" {
            return CodeLanguage::Go;
        }
        if lower == "java" {
            return CodeLanguage::Java;
        }
        if lower == "c++" || lower == "cpp" || lower == "cxx" {
            return CodeLanguage::Cpp;
        }
        if lower == "c" {
            return CodeLanguage::C;
        }
        if lower == "ruby" || lower == "rb" {
            return CodeLanguage::Ruby;
        }
    }

    // 2. Heuristic detection from content
    detect_language_from_content(code)
}

/// Heuristic language detection based on code content patterns.
fn detect_language_from_content(code: &str) -> CodeLanguage {
    let lower = code.to_lowercase();

    // Python indicators
    if lower.contains("import ") && (lower.contains("def ") || lower.contains("from "))
        || lower.contains("print(")
        || lower.contains("pickle.")
        || lower.contains("subprocess.")
    {
        return CodeLanguage::Python;
    }

    // JavaScript/TypeScript indicators
    if lower.contains("const ") || lower.contains("let ") || lower.contains("var ") {
        if lower.contains(": string") || lower.contains(": number") || lower.contains("interface ")
        {
            return CodeLanguage::TypeScript;
        }
        return CodeLanguage::JavaScript;
    }
    if lower.contains("require(") || lower.contains("module.exports") {
        return CodeLanguage::JavaScript;
    }
    if lower.contains("document.") || lower.contains("console.log") {
        return CodeLanguage::JavaScript;
    }

    // SQL indicators
    if lower.contains("select ") && lower.contains(" from ")
        || lower.contains("insert into ")
        || lower.contains("create table ")
        || lower.contains("update ") && lower.contains(" set ")
    {
        return CodeLanguage::Sql;
    }

    // Bash indicators
    if lower.starts_with("#!/bin/")
        || lower.contains("echo ")
        || (lower.contains("if [") && lower.contains("then"))
    {
        return CodeLanguage::Bash;
    }

    // Go indicators
    if lower.contains("func main()") || lower.contains("package main") {
        return CodeLanguage::Go;
    }

    // Java indicators
    if lower.contains("public class ") || lower.contains("system.out.println") {
        return CodeLanguage::Java;
    }

    // Rust indicators
    if lower.contains("fn main()") || lower.contains("let mut ") {
        return CodeLanguage::Rust;
    }

    // Ruby indicators
    if lower.contains("puts ") || lower.contains("def ") && lower.contains("end") {
        return CodeLanguage::Ruby;
    }

    CodeLanguage::Unknown
}

// ---------------------------------------------------------------------------
// Code block extraction
// ---------------------------------------------------------------------------

/// A code block extracted from text.
#[derive(Debug, Clone)]
struct CodeBlock {
    /// The code content.
    code: String,
    /// Detected language.
    language: CodeLanguage,
}

/// Extract code blocks from Markdown text.
///
/// Detects:
/// 1. Fenced code blocks (``` ... ```)
/// 2. Indented code blocks (4+ spaces or tab)
fn extract_code_blocks(text: &str) -> Vec<CodeBlock> {
    let mut blocks = Vec::new();

    // 1. Fenced code blocks
    let fence_re = Regex::new(r"```(\w*)\s*\n([\s\S]*?)```").expect("valid regex");
    for cap in fence_re.captures_iter(text) {
        let info_string = cap.get(1).map(|m| m.as_str()).filter(|s| !s.is_empty());
        let code = cap.get(2).map_or("", |m| m.as_str());
        if !code.trim().is_empty() {
            let language = detect_language(info_string, code);
            blocks.push(CodeBlock {
                code: code.to_string(),
                language,
            });
        }
    }

    // 2. Indented code blocks (4+ spaces at line start, consecutive lines)
    // Only if no fenced blocks were found (to avoid double-counting)
    if blocks.is_empty() {
        let mut current_block = String::new();
        for line in text.lines() {
            if let Some(stripped) = line
                .strip_prefix("    ")
                .or_else(|| line.strip_prefix('\t'))
            {
                current_block.push_str(stripped);
                current_block.push('\n');
            } else if !current_block.is_empty() {
                let code = current_block.trim().to_string();
                if !code.is_empty() {
                    let language = detect_language(None, &code);
                    blocks.push(CodeBlock { code, language });
                }
                current_block.clear();
            }
        }
        if !current_block.is_empty() {
            let code = current_block.trim().to_string();
            if !code.is_empty() {
                let language = detect_language(None, &code);
                blocks.push(CodeBlock { code, language });
            }
        }
    }

    blocks
}

// ---------------------------------------------------------------------------
// Vulnerability patterns
// ---------------------------------------------------------------------------

/// Type of code vulnerability detected.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VulnerabilityType {
    SqlInjection,
    CommandInjection,
    PathTraversal,
    HardcodedCredentials,
    InsecureDeserialization,
    Xss,
    InsecureCrypto,
}

impl std::fmt::Display for VulnerabilityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SqlInjection => write!(f, "SQL Injection"),
            Self::CommandInjection => write!(f, "Command Injection"),
            Self::PathTraversal => write!(f, "Path Traversal"),
            Self::HardcodedCredentials => write!(f, "Hardcoded Credentials"),
            Self::InsecureDeserialization => write!(f, "Insecure Deserialization"),
            Self::Xss => write!(f, "Cross-Site Scripting (XSS)"),
            Self::InsecureCrypto => write!(f, "Insecure Cryptography"),
        }
    }
}

/// A detected code vulnerability.
struct CodeVulnerability {
    vuln_type: VulnerabilityType,
    severity: SecuritySeverity,
    description: String,
    snippet: String,
    suggested_fix: String,
    confidence: f64,
}

// ---------------------------------------------------------------------------
// Vulnerability detection patterns
// ---------------------------------------------------------------------------

/// Compiled vulnerability detection pattern.
struct VulnPattern {
    regex: Regex,
    vuln_type: VulnerabilityType,
    severity: SecuritySeverity,
    description: &'static str,
    suggested_fix: &'static str,
    confidence: f64,
}

/// Build all vulnerability detection patterns.
fn build_vuln_patterns() -> Vec<VulnPattern> {
    let definitions: Vec<(
        &str,
        VulnerabilityType,
        SecuritySeverity,
        &'static str,
        &'static str,
        f64,
    )> = vec![
        // ---------------------------------------------------------------
        // SQL Injection (High)
        // ---------------------------------------------------------------
        (
            // String concatenation in SQL: "SELECT ... " + variable
            r#"(?i)(?:"|')(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s[^"']*(?:"|')\s*(?:\+|\.format\(|%\s)"#,
            VulnerabilityType::SqlInjection,
            SecuritySeverity::High,
            "SQL query built with string concatenation — vulnerable to SQL injection",
            "Use parameterised queries (e.g., cursor.execute(\"SELECT * FROM t WHERE id = ?\", (user_id,)))",
            0.85,
        ),
        (
            // f-string SQL: f"SELECT ... {variable}"
            r#"(?i)f\s*(?:"|')(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{[^}]+\}"#,
            VulnerabilityType::SqlInjection,
            SecuritySeverity::High,
            "SQL query built with f-string interpolation — vulnerable to SQL injection",
            "Use parameterised queries instead of f-strings for SQL",
            0.9,
        ),
        (
            // execute() with string formatting: .execute("..." % ...) or .execute("..." + ...)
            r#"(?i)\.execute\(\s*(?:f\s*)?["'][^"']*["']\s*(?:%|\+|\.format\()"#,
            VulnerabilityType::SqlInjection,
            SecuritySeverity::High,
            "SQL execute() called with string formatting — vulnerable to SQL injection",
            "Use parameterised queries: cursor.execute(\"SELECT ... WHERE id = %s\", (param,))",
            0.9,
        ),
        // ---------------------------------------------------------------
        // Command Injection (Critical)
        // ---------------------------------------------------------------
        (
            // os.system() with string formatting (f-string)
            r#"(?i)os\.system\s*\(\s*f\s*["'][^"']*\{[^}]*\}"#,
            VulnerabilityType::CommandInjection,
            SecuritySeverity::Critical,
            "os.system() called with dynamic input — vulnerable to command injection",
            "Use subprocess.run() with a list of arguments instead of os.system()",
            0.9,
        ),
        (
            // os.system() with concatenation
            r#"(?i)os\.system\s*\(\s*["'][^"']*["']\s*\+"#,
            VulnerabilityType::CommandInjection,
            SecuritySeverity::Critical,
            "os.system() called with string concatenation — vulnerable to command injection",
            "Use subprocess.run() with a list of arguments instead of os.system()",
            0.9,
        ),
        (
            // subprocess with shell=True and string formatting
            r"(?i)subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
            VulnerabilityType::CommandInjection,
            SecuritySeverity::Critical,
            "subprocess called with shell=True — vulnerable to command injection",
            "Use subprocess.run([\"cmd\", \"arg1\", \"arg2\"]) without shell=True",
            0.85,
        ),
        (
            // eval() with non-literal argument
            r"(?i)\beval\s*\(\s*[a-zA-Z_]",
            VulnerabilityType::CommandInjection,
            SecuritySeverity::Critical,
            "eval() called with potentially dynamic input — code injection risk",
            "Avoid eval(); use ast.literal_eval() for Python or JSON.parse() for JavaScript",
            0.8,
        ),
        (
            // child_process.exec() in Node.js with template literal or concatenation
            r"(?i)child_process\.exec\s*\(\s*`[^`]*\$\{",
            VulnerabilityType::CommandInjection,
            SecuritySeverity::Critical,
            "child_process.exec() called with template literal — vulnerable to command injection",
            "Use child_process.execFile() or spawn() with argument arrays instead",
            0.9,
        ),
        (
            // child_process.exec() with concatenation
            r#"(?i)(?:child_process\.exec|exec)\s*\(\s*["'][^"']*["']\s*\+"#,
            VulnerabilityType::CommandInjection,
            SecuritySeverity::Critical,
            "child_process.exec() called with string concatenation — command injection risk",
            "Use child_process.execFile() or spawn() with argument arrays instead",
            0.85,
        ),
        // ---------------------------------------------------------------
        // Path Traversal (High)
        // ---------------------------------------------------------------
        (
            // open() or readFile with ../ path
            r#"(?i)(?:open|readFile|readFileSync|read_file|fs\.read)\s*\([^)]*\.\.\/"#,
            VulnerabilityType::PathTraversal,
            SecuritySeverity::High,
            "File operation with '../' path — vulnerable to path traversal",
            "Validate and canonicalise file paths using os.path.realpath() or path.resolve()",
            0.85,
        ),
        (
            // Path concatenation with user input (Python-style)
            r"(?i)open\s*\(\s*(?:(?:request|user_input|filename|path|file_path|params)\b[^)]*|[^)]*\+\s*(?:request|user_input|filename|path|file_path|params)\b)",
            VulnerabilityType::PathTraversal,
            SecuritySeverity::High,
            "File open() with potentially user-controlled path — path traversal risk",
            "Validate paths against an allowlist and use os.path.realpath() to resolve symlinks",
            0.75,
        ),
        // ---------------------------------------------------------------
        // Hardcoded Credentials (High)
        // ---------------------------------------------------------------
        (
            // password = "..." or password = '...'
            r#"(?i)(?:password|passwd|pwd)\s*=\s*(?:"|')[^"']{3,}(?:"|')"#,
            VulnerabilityType::HardcodedCredentials,
            SecuritySeverity::High,
            "Hardcoded password detected in code",
            "Use environment variables or a secrets manager instead of hardcoding passwords",
            0.85,
        ),
        (
            // api_key = "..." or secret = "..." or token = "..."
            r#"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|secret)\s*=\s*(?:"|')[A-Za-z0-9+/=_\-]{8,}(?:"|')"#,
            VulnerabilityType::HardcodedCredentials,
            SecuritySeverity::High,
            "Hardcoded API key, secret, or token detected in code",
            "Use environment variables or a secrets manager instead of hardcoding secrets",
            0.85,
        ),
        (
            // Connection string with password
            r"(?i)(?:mysql|postgres|postgresql|mongodb|redis)://[^:]+:[^@]+@",
            VulnerabilityType::HardcodedCredentials,
            SecuritySeverity::High,
            "Connection string with embedded password detected",
            "Use environment variables for connection strings containing credentials",
            0.85,
        ),
        (
            // AWS key patterns in code assignment
            r#"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*=\s*["'][A-Za-z0-9/+=]{16,}["']"#,
            VulnerabilityType::HardcodedCredentials,
            SecuritySeverity::High,
            "Hardcoded AWS credentials detected in code",
            "Use IAM roles, environment variables, or AWS Secrets Manager instead",
            0.9,
        ),
        // ---------------------------------------------------------------
        // Insecure Deserialization (High)
        // ---------------------------------------------------------------
        (
            // pickle.loads() or pickle.load()
            r"(?i)pickle\.loads?\s*\(",
            VulnerabilityType::InsecureDeserialization,
            SecuritySeverity::High,
            "pickle.loads() used — insecure deserialization can lead to remote code execution",
            "Avoid pickle for untrusted data; use JSON or a safe serialisation format instead",
            0.9,
        ),
        (
            // yaml.load() without SafeLoader
            r"(?i)yaml\.load\s*\([^)]*\)",
            VulnerabilityType::InsecureDeserialization,
            SecuritySeverity::High,
            "yaml.load() without SafeLoader — can execute arbitrary code",
            "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
            0.85,
        ),
        (
            // eval(JSON.parse(...)) pattern
            r"(?i)eval\s*\(\s*JSON\.parse",
            VulnerabilityType::InsecureDeserialization,
            SecuritySeverity::High,
            "eval(JSON.parse(...)) — combining eval with parsed JSON is dangerous",
            "Use JSON.parse() alone; never pass its result to eval()",
            0.9,
        ),
        // ---------------------------------------------------------------
        // XSS Patterns (Medium)
        // ---------------------------------------------------------------
        (
            // innerHTML assignment
            r"(?i)\.innerHTML\s*=",
            VulnerabilityType::Xss,
            SecuritySeverity::Medium,
            "innerHTML assignment — potential XSS if user input is not sanitised",
            "Use textContent or a DOM sanitisation library (e.g., DOMPurify) instead",
            0.8,
        ),
        (
            // document.write()
            r"(?i)document\.write\s*\(",
            VulnerabilityType::Xss,
            SecuritySeverity::Medium,
            "document.write() — potential XSS vector",
            "Use DOM manipulation methods (createElement, appendChild) instead of document.write()",
            0.8,
        ),
        (
            // dangerouslySetInnerHTML
            r"(?i)dangerouslySetInnerHTML",
            VulnerabilityType::Xss,
            SecuritySeverity::Medium,
            "dangerouslySetInnerHTML in React — potential XSS if content is not sanitised",
            "Sanitise HTML with DOMPurify before passing to dangerouslySetInnerHTML",
            0.8,
        ),
        // ---------------------------------------------------------------
        // Insecure Crypto (Medium)
        // ---------------------------------------------------------------
        (
            // MD5 for passwords
            r"(?i)(?:md5|MD5)\s*\(.*(?:password|passwd|pwd)",
            VulnerabilityType::InsecureCrypto,
            SecuritySeverity::Medium,
            "MD5 used for password hashing — cryptographically broken",
            "Use bcrypt, scrypt, or Argon2 for password hashing",
            0.85,
        ),
        (
            // hashlib.md5 or hashlib.sha1 for passwords
            r"(?i)hashlib\.(?:md5|sha1)\s*\(.*(?:password|passwd|pwd)",
            VulnerabilityType::InsecureCrypto,
            SecuritySeverity::Medium,
            "MD5/SHA1 used for password hashing — cryptographically weak",
            "Use bcrypt, scrypt, or Argon2 for password hashing",
            0.85,
        ),
        (
            // Math.random() for security
            r"(?i)(?:(?:token|key|secret|password|nonce|salt|iv).*Math\.random|Math\.random\s*\(\s*\).*(?:token|key|secret|password|nonce|salt|iv))",
            VulnerabilityType::InsecureCrypto,
            SecuritySeverity::Medium,
            "Math.random() used for security-sensitive value — not cryptographically secure",
            "Use crypto.getRandomValues() or crypto.randomBytes() instead",
            0.8,
        ),
        (
            // ECB mode
            r"(?i)(?:AES|DES|Blowfish).*(?:ECB|mode_ecb|MODE_ECB)",
            VulnerabilityType::InsecureCrypto,
            SecuritySeverity::Medium,
            "ECB mode encryption — does not provide semantic security",
            "Use CBC, GCM, or another authenticated encryption mode instead of ECB",
            0.85,
        ),
    ];

    definitions
        .into_iter()
        .filter_map(
            |(pattern, vuln_type, severity, description, suggested_fix, confidence)| {
                Regex::new(pattern).ok().map(|regex| VulnPattern {
                    regex,
                    vuln_type,
                    severity,
                    description,
                    suggested_fix,
                    confidence,
                })
            },
        )
        .collect()
}

// ---------------------------------------------------------------------------
// CodeSecurityAnalyzer
// ---------------------------------------------------------------------------

/// Analyser that scans text for code blocks and checks them for security
/// vulnerabilities.
pub struct CodeSecurityAnalyzer {
    patterns: Vec<VulnPattern>,
    /// Minimum severity to report (findings below this are skipped).
    severity_threshold: SecuritySeverity,
}

impl CodeSecurityAnalyzer {
    /// Create a new `CodeSecurityAnalyzer` with the default severity threshold
    /// (`Medium`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: build_vuln_patterns(),
            severity_threshold: SecuritySeverity::Medium,
        }
    }

    /// Create a new `CodeSecurityAnalyzer` with a custom severity threshold.
    ///
    /// Findings with severity below `threshold` are silently dropped.
    #[must_use]
    pub fn with_severity_threshold(threshold: SecuritySeverity) -> Self {
        Self {
            patterns: build_vuln_patterns(),
            severity_threshold: threshold,
        }
    }

    /// Analyse text (typically an LLM response) for code security vulnerabilities.
    ///
    /// Extracts code blocks, detects languages, and scans for vulnerability
    /// patterns. Returns a list of `SecurityFinding`s tagged as
    /// `"insecure_code"`.
    pub fn analyze(&self, text: &str) -> Vec<SecurityFinding> {
        let blocks = extract_code_blocks(text);
        if blocks.is_empty() {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for block in &blocks {
            let vulns = self.scan_code(&block.code, &block.language);
            for vuln in vulns {
                if vuln.severity < self.severity_threshold {
                    continue;
                }
                let description = format!(
                    "[{}] {}: {}\n\nVulnerable code:\n  {}\n\nSuggested fix: {}",
                    vuln.severity,
                    vuln.vuln_type,
                    vuln.description,
                    vuln.snippet.trim(),
                    vuln.suggested_fix,
                );
                let mut finding = SecurityFinding::new(
                    vuln.severity,
                    "insecure_code".to_string(),
                    description,
                    vuln.confidence,
                );
                finding
                    .metadata
                    .insert("vulnerability_type".to_string(), vuln.vuln_type.to_string());
                finding
                    .metadata
                    .insert("language".to_string(), block.language.to_string());
                finding
                    .metadata
                    .insert("code_snippet".to_string(), vuln.snippet);
                finding
                    .metadata
                    .insert("suggested_fix".to_string(), vuln.suggested_fix);
                findings.push(finding);
            }
        }

        findings
    }

    /// Scan a single code block for vulnerability patterns.
    fn scan_code(&self, code: &str, _language: &CodeLanguage) -> Vec<CodeVulnerability> {
        let mut vulns = Vec::new();

        for pattern in &self.patterns {
            if let Some(mat) = pattern.regex.find(code) {
                // Extract the line containing the match for context
                let snippet = extract_snippet(code, mat.start());
                vulns.push(CodeVulnerability {
                    vuln_type: pattern.vuln_type.clone(),
                    severity: pattern.severity.clone(),
                    description: pattern.description.to_string(),
                    snippet,
                    suggested_fix: pattern.suggested_fix.to_string(),
                    confidence: pattern.confidence,
                });
            }
        }

        vulns
    }
}

impl Default for CodeSecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the line containing the byte offset `pos` from `code`.
fn extract_snippet(code: &str, pos: usize) -> String {
    let before = &code[..pos];
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let after = &code[pos..];
    let line_end = after.find('\n').map_or(code.len(), |i| pos + i);
    code[line_start..line_end].to_string()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Helper
    // ---------------------------------------------------------------

    fn analyzer() -> CodeSecurityAnalyzer {
        CodeSecurityAnalyzer::new()
    }

    fn has_vuln_type(findings: &[SecurityFinding], vuln_type: &str) -> bool {
        findings
            .iter()
            .any(|f| f.metadata.get("vulnerability_type") == Some(&vuln_type.to_string()))
    }

    // ---------------------------------------------------------------
    // Language detection
    // ---------------------------------------------------------------

    #[test]
    fn test_detect_language_from_info_string() {
        assert_eq!(detect_language(Some("python"), ""), CodeLanguage::Python);
        assert_eq!(detect_language(Some("js"), ""), CodeLanguage::JavaScript);
        assert_eq!(detect_language(Some("ts"), ""), CodeLanguage::TypeScript);
        assert_eq!(detect_language(Some("sql"), ""), CodeLanguage::Sql);
        assert_eq!(detect_language(Some("bash"), ""), CodeLanguage::Bash);
        assert_eq!(detect_language(Some("rust"), ""), CodeLanguage::Rust);
        assert_eq!(detect_language(Some("go"), ""), CodeLanguage::Go);
        assert_eq!(detect_language(Some("java"), ""), CodeLanguage::Java);
        assert_eq!(detect_language(Some("cpp"), ""), CodeLanguage::Cpp);
        assert_eq!(detect_language(Some("c"), ""), CodeLanguage::C);
        assert_eq!(detect_language(Some("ruby"), ""), CodeLanguage::Ruby);
    }

    #[test]
    fn test_detect_language_from_content() {
        assert_eq!(
            detect_language_from_content("import os\ndef foo():\n    pass"),
            CodeLanguage::Python
        );
        assert_eq!(
            detect_language_from_content("const x = 5; console.log(x);"),
            CodeLanguage::JavaScript
        );
        assert_eq!(
            detect_language_from_content("SELECT * FROM users WHERE id = 1"),
            CodeLanguage::Sql
        );
    }

    // ---------------------------------------------------------------
    // Code block extraction
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_fenced_code_block() {
        let text = "Here is code:\n```python\nimport os\nprint('hello')\n```\nDone.";
        let blocks = extract_code_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].language, CodeLanguage::Python);
        assert!(blocks[0].code.contains("import os"));
    }

    #[test]
    fn test_extract_indented_code_block() {
        let text = "Example:\n    import os\n    os.system('ls')\nDone.";
        let blocks = extract_code_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].code.contains("import os"));
    }

    #[test]
    fn test_extract_multiple_fenced_blocks() {
        let text = "```python\nprint('a')\n```\nText\n```js\nconsole.log('b');\n```";
        let blocks = extract_code_blocks(text);
        assert_eq!(blocks.len(), 2);
    }

    // ---------------------------------------------------------------
    // SQL Injection
    // ---------------------------------------------------------------

    #[test]
    fn test_sql_injection_string_concat() {
        let text = r#"```python
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "SQL Injection"),
            "Should detect SQL injection via concatenation; findings: {:?}",
            findings
                .iter()
                .map(|f| f.metadata.get("vulnerability_type"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_sql_injection_fstring() {
        let text = r#"```python
query = f"SELECT * FROM users WHERE name = '{username}'"
cursor.execute(query)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "SQL Injection"),
            "Should detect SQL injection via f-string"
        );
    }

    #[test]
    fn test_sql_injection_execute_format() {
        let text = r#"```python
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "SQL Injection"),
            "Should detect SQL injection via execute with format"
        );
    }

    #[test]
    fn test_sql_parameterised_query_safe() {
        let text = r#"```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            !has_vuln_type(&findings, "SQL Injection"),
            "Parameterised query should NOT trigger SQL injection; findings: {:?}",
            findings
                .iter()
                .map(|f| f.metadata.get("vulnerability_type"))
                .collect::<Vec<_>>()
        );
    }

    // ---------------------------------------------------------------
    // Command Injection
    // ---------------------------------------------------------------

    #[test]
    fn test_command_injection_os_system_fstring() {
        let text = r#"```python
import os
os.system(f"rm -rf {user_input}")
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Command Injection"),
            "Should detect command injection via os.system with f-string"
        );
    }

    #[test]
    fn test_command_injection_os_system_concat() {
        let text = r#"```python
import os
os.system("ping " + host)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Command Injection"),
            "Should detect command injection via os.system with concatenation"
        );
    }

    #[test]
    fn test_command_injection_subprocess_shell_true() {
        let text = r#"```python
import subprocess
subprocess.call("ls " + path, shell=True)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Command Injection"),
            "Should detect command injection via subprocess with shell=True"
        );
    }

    #[test]
    fn test_command_injection_child_process_exec_template() {
        let text = r#"```javascript
const { exec } = require('child_process');
child_process.exec(`ls ${userInput}`, callback);
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Command Injection"),
            "Should detect command injection via child_process.exec with template literal"
        );
    }

    #[test]
    fn test_subprocess_list_args_safe() {
        let text = r#"```python
import subprocess
subprocess.run(["ls", "-la", path])
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            !has_vuln_type(&findings, "Command Injection"),
            "subprocess with list args should NOT trigger command injection"
        );
    }

    // ---------------------------------------------------------------
    // Path Traversal
    // ---------------------------------------------------------------

    #[test]
    fn test_path_traversal_open_dotdot() {
        let text = r#"```python
with open("../../etc/passwd") as f:
    data = f.read()
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Path Traversal"),
            "Should detect path traversal with ../"
        );
    }

    #[test]
    fn test_path_traversal_user_input() {
        let text = r#"```python
f = open(user_input)
data = f.read()
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Path Traversal"),
            "Should detect open() with user-controlled path"
        );
    }

    // ---------------------------------------------------------------
    // Hardcoded Credentials
    // ---------------------------------------------------------------

    #[test]
    fn test_hardcoded_password() {
        let text = r#"```python
password = "super_secret_123"
db.connect(password=password)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Hardcoded Credentials"),
            "Should detect hardcoded password"
        );
    }

    #[test]
    fn test_hardcoded_api_key() {
        let text = r#"```javascript
const api_key = "sk_live_abcdef1234567890";
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Hardcoded Credentials"),
            "Should detect hardcoded API key"
        );
    }

    #[test]
    fn test_hardcoded_connection_string() {
        let text = r#"```python
db_url = "postgresql://admin:password123@localhost:5432/mydb"
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Hardcoded Credentials"),
            "Should detect connection string with embedded password"
        );
    }

    #[test]
    fn test_env_var_password_safe() {
        let text = r#"```python
import os
password = os.environ.get("DB_PASSWORD")
db.connect(password=password)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            !has_vuln_type(&findings, "Hardcoded Credentials"),
            "Password from env var should NOT trigger hardcoded credentials"
        );
    }

    // ---------------------------------------------------------------
    // Insecure Deserialization
    // ---------------------------------------------------------------

    #[test]
    fn test_pickle_loads() {
        let text = r#"```python
import pickle
data = pickle.loads(user_data)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Insecure Deserialization"),
            "Should detect pickle.loads()"
        );
    }

    #[test]
    fn test_yaml_load_unsafe() {
        let text = r#"```python
import yaml
data = yaml.load(content)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Insecure Deserialization"),
            "Should detect yaml.load() without SafeLoader"
        );
    }

    #[test]
    fn test_eval_json_parse() {
        let text = r#"```javascript
const result = eval(JSON.parse(data));
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Insecure Deserialization"),
            "Should detect eval(JSON.parse(...))"
        );
    }

    // ---------------------------------------------------------------
    // XSS Patterns
    // ---------------------------------------------------------------

    #[test]
    fn test_xss_innerhtml() {
        let text = r#"```javascript
element.innerHTML = userInput;
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Cross-Site Scripting (XSS)"),
            "Should detect innerHTML assignment"
        );
    }

    #[test]
    fn test_xss_document_write() {
        let text = r#"```javascript
document.write(userContent);
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Cross-Site Scripting (XSS)"),
            "Should detect document.write()"
        );
    }

    #[test]
    fn test_xss_dangerously_set_inner_html() {
        let text = r#"```javascript
<div dangerouslySetInnerHTML={{__html: content}} />
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Cross-Site Scripting (XSS)"),
            "Should detect dangerouslySetInnerHTML"
        );
    }

    // ---------------------------------------------------------------
    // Insecure Crypto
    // ---------------------------------------------------------------

    #[test]
    fn test_md5_password() {
        let text = r#"```python
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Insecure Cryptography"),
            "Should detect MD5 for password hashing"
        );
    }

    #[test]
    fn test_math_random_token() {
        let text = r#"```javascript
const token = Math.random().toString(36);
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Insecure Cryptography"),
            "Should detect Math.random() for token generation"
        );
    }

    #[test]
    fn test_ecb_mode() {
        let text = r#"```python
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Insecure Cryptography"),
            "Should detect ECB mode encryption"
        );
    }

    // ---------------------------------------------------------------
    // Finding metadata
    // ---------------------------------------------------------------

    #[test]
    fn test_findings_have_correct_type() {
        let text = r#"```python
password = "secret123"
```"#;
        let findings = analyzer().analyze(text);
        assert!(!findings.is_empty());
        for f in &findings {
            assert_eq!(f.finding_type, "insecure_code");
            assert!(f.metadata.contains_key("vulnerability_type"));
            assert!(f.metadata.contains_key("language"));
            assert!(f.metadata.contains_key("code_snippet"));
            assert!(f.metadata.contains_key("suggested_fix"));
        }
    }

    #[test]
    fn test_findings_severity_high_or_above() {
        let text = r#"```python
os.system(f"rm {user_input}")
```"#;
        let findings = analyzer().analyze(text);
        assert!(!findings.is_empty());
        for f in &findings {
            assert!(f.severity >= SecuritySeverity::Medium);
        }
    }

    // ---------------------------------------------------------------
    // Severity threshold filtering
    // ---------------------------------------------------------------

    #[test]
    fn test_severity_threshold_filters_low() {
        // XSS is Medium severity — should be included with Medium threshold
        let text = r#"```javascript
element.innerHTML = data;
```"#;
        let analyzer = CodeSecurityAnalyzer::with_severity_threshold(SecuritySeverity::Medium);
        let findings = analyzer.analyze(text);
        assert!(
            !findings.is_empty(),
            "Medium findings should pass Medium threshold"
        );

        // High threshold should filter out Medium findings
        let analyzer_high = CodeSecurityAnalyzer::with_severity_threshold(SecuritySeverity::High);
        let findings_high = analyzer_high.analyze(text);
        assert!(
            !has_vuln_type(&findings_high, "Cross-Site Scripting (XSS)"),
            "Medium XSS findings should be filtered by High threshold"
        );
    }

    // ---------------------------------------------------------------
    // Safe code (no false positives)
    // ---------------------------------------------------------------

    #[test]
    fn test_safe_python_code_no_findings() {
        let text = r#"```python
import json

def get_user(user_id: int):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()

data = json.loads(response.text)
print(data)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            findings.is_empty(),
            "Safe Python code should not trigger findings; got: {:?}",
            findings
                .iter()
                .map(|f| f.metadata.get("vulnerability_type"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_safe_node_code_no_findings() {
        let text = r#"```javascript
const { execFile } = require('child_process');
execFile('ls', ['-la', dir], (error, stdout) => {
    console.log(stdout);
});
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            findings.is_empty(),
            "Safe Node.js code should not trigger findings"
        );
    }

    // ---------------------------------------------------------------
    // Plain text without code blocks
    // ---------------------------------------------------------------

    #[test]
    fn test_no_code_blocks_returns_empty() {
        let text = "This is just plain text without any code blocks. SELECT * FROM users.";
        let findings = analyzer().analyze(text);
        assert!(
            findings.is_empty(),
            "Plain text without code blocks should not trigger findings"
        );
    }

    // ---------------------------------------------------------------
    // Multiple vulnerabilities in one block
    // ---------------------------------------------------------------

    #[test]
    fn test_multiple_vulns_in_one_block() {
        let text = r#"```python
password = "hardcoded_secret"
query = f"SELECT * FROM users WHERE name = '{name}'"
data = pickle.loads(user_data)
```"#;
        let findings = analyzer().analyze(text);
        assert!(
            findings.len() >= 2,
            "Should detect multiple vulnerabilities; got {}",
            findings.len()
        );
    }

    // ---------------------------------------------------------------
    // Markdown code blocks vs indented
    // ---------------------------------------------------------------

    #[test]
    fn test_indented_code_block_detection() {
        let text = "Here is some code:\n    password = \"secret123\"\n    db.connect()\nEnd.";
        let findings = analyzer().analyze(text);
        assert!(
            has_vuln_type(&findings, "Hardcoded Credentials"),
            "Should detect vulnerabilities in indented code blocks"
        );
    }
}
