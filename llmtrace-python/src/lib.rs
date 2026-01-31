//! Python bindings for LLMTrace
//!
//! This crate provides Python bindings using PyO3 to make LLMTrace accessible from Python applications.
//! Full implementation in Loop 7.

use pyo3::prelude::*;

/// Python module initialization
#[pymodule]
fn llmtrace_python(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
