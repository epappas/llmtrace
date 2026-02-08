//! LLMTrace Benchmark Suite
//!
//! Comprehensive evaluation framework for LLMTrace security analysis capabilities.
//! Implements benchmarks derived from the following research papers:
//!
//! - **InjecGuard** (Li & Liu, ACL 2025) — Over-defense evaluation using NotInject methodology
//! - **DMPI-PMHFE** (Zhengzhou University, 2025) — Feature-level fusion effectiveness
//! - **Bypassing Guardrails** (Mindgard/ACL LLMSEC 2025) — Unicode and AML evasion resistance
//! - **PromptShield** (UC Berkeley, CODASPY 2025) — Deployment-realistic FPR evaluation
//! - **Multi-Agent Defense** (Hossain et al., 2024) — HPI_ATTACK_DATASET attack categories
//! - **Tool Result Parsing** (HIT, 2025) — Indirect injection defense effectiveness
//! - **Protocol Exploits** (Ferrag et al., 2025) — Comprehensive threat taxonomy
//! - **Design Patterns** (IBM/EPFL/ETH, 2025) — Agent security pattern validation
//! - **Benchmarks & Tools Landscape** (2026) — Competitive baseline metrics
//!
//! # Modules
//!
//! - [`datasets`] — Dataset loaders for benchmark test cases
//! - [`metrics`] — Precision, recall, F1, FPR, ASR, over-defense rate calculators
//! - [`runners`] — Benchmark runner framework with paper-table output

pub mod datasets;
pub mod metrics;
pub mod regression;
pub mod runners;
pub mod training;

/// Re-export commonly used types for benchmark implementations.
pub mod prelude {
    pub use crate::datasets::{BenchmarkSample, DatasetLoader, Label};
    pub use crate::metrics::{BenchmarkMetrics, ConfusionMatrix, ThreeDimensionalMetrics};
    pub use crate::regression::{self, RegressionResult, RegressionThresholds};
    pub use crate::runners::cyberseceval2;
    pub use crate::runners::notinject;
    pub use crate::runners::{BenchmarkResult, BenchmarkRunner};
}
