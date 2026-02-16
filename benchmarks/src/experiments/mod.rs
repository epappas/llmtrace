//! Streaming partial-text ML experiments.
//!
//! Implements the experiments described in the truncation degradation study:
//!
//! - **Experiment A (Truncation)**: Character-level truncation at 20/40/60/80/100%
//!   across all ML detectors. Measures accuracy/TPR/FPR degradation.
//! - **Experiment B (Boundary)**: Binary-search detection of the earliest character
//!   position where model confidence crosses threshold levels.
//! - **Experiment C (Checkpoint)**: Simulation of streaming checkpoint strategies
//!   to find the Pareto frontier of inference cost vs detection latency.

pub mod boundary;
pub mod checkpoint;
pub mod recalibration;
pub mod truncation;
pub mod types;

pub use boundary::{print_boundary_summary, run_boundary_experiment, DEFAULT_BOUNDARY_THRESHOLDS};
pub use checkpoint::{print_checkpoint_summary, run_checkpoint_experiment};
pub use recalibration::{print_recalibration_summary, run_recalibration_experiment};
pub use truncation::{
    print_truncation_summary, run_truncation_experiment, truncate_text, RawScoreDetector,
    DEFAULT_TRUNCATION_LEVELS,
};
pub use types::*;
