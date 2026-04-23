//! LLMTrace Transparent Proxy — library interface.
//!
//! Re-exports the core proxy types and handlers so that integration tests
//! and other crates can programmatically construct a proxy router.

pub mod action_router;
pub mod alerts;
pub mod anomaly;
pub mod api;
pub mod auth;
pub mod boundary;
pub mod circuit_breaker;
pub mod compliance;
pub mod config;
pub mod config_handle;
pub mod cost;
pub mod cost_caps;
pub mod debug;
pub mod enforcement;
pub mod feature_flags;
pub mod feature_flags_api;
pub mod grpc;
#[cfg(feature = "judge")]
pub mod judge;
pub mod metrics;
pub mod openapi;
pub mod otel;
pub mod provider;
pub mod proxy;
pub mod rate_limit;
pub mod shutdown;
pub mod streaming;
pub mod tenant_api;

// Re-export key types for convenience
pub use action_router::ActionRouter;
pub use alerts::AlertEngine;
pub use anomaly::AnomalyDetector;
pub use circuit_breaker::CircuitBreaker;
pub use cost::CostEstimator;
pub use cost_caps::CostTracker;
pub use grpc::run_grpc_server;
pub use metrics::Metrics;
pub use proxy::{health_handler, proxy_handler, AppState};
pub use rate_limit::RateLimiter;
pub use shutdown::ShutdownCoordinator;
pub use streaming::StreamingSecurityMonitor;
