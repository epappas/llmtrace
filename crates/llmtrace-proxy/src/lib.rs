//! LLMTrace Transparent Proxy — library interface.
//!
//! Re-exports the core proxy types and handlers so that integration tests
//! and other crates can programmatically construct a proxy router.

pub mod api;
pub mod circuit_breaker;
pub mod config;
pub mod cost;
pub mod provider;
pub mod proxy;
pub mod streaming;

// Re-export key types for convenience
pub use circuit_breaker::CircuitBreaker;
pub use cost::CostEstimator;
pub use proxy::{health_handler, proxy_handler, AppState};
