//! Simple circuit breaker for storage and security subsystems.
//!
//! When failures exceed a threshold the circuit opens and calls are skipped
//! (degrading to pure pass-through). After a recovery timeout the circuit
//! enters half-open state and allows a limited number of probe calls.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — calls are allowed.
    Closed,
    /// Too many failures — calls are blocked.
    Open,
    /// Recovery probe — a limited number of calls are allowed.
    HalfOpen,
}

/// A thread-safe circuit breaker.
///
/// Call [`CircuitBreaker::allow`] before performing an operation. If it returns
/// `true` you may proceed; afterwards call [`CircuitBreaker::record_success`] or
/// [`CircuitBreaker::record_failure`] to update the breaker.
pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_timeout: Duration,
    half_open_max_calls: u32,

    failure_count: AtomicU32,
    half_open_calls: AtomicU32,
    /// Timestamp (as nanos since an arbitrary epoch) when the circuit opened.
    opened_at_nanos: AtomicU64,
    /// Protects state transitions so they are linearizable.
    state: Mutex<CircuitState>,
    /// The reference instant for our monotonic clock.
    epoch: Instant,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given thresholds.
    pub fn new(
        failure_threshold: u32,
        recovery_timeout: Duration,
        half_open_max_calls: u32,
    ) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            half_open_max_calls,
            failure_count: AtomicU32::new(0),
            half_open_calls: AtomicU32::new(0),
            opened_at_nanos: AtomicU64::new(0),
            state: Mutex::new(CircuitState::Closed),
            epoch: Instant::now(),
        }
    }

    /// Create a circuit breaker from a [`llmtrace_core::CircuitBreakerConfig`].
    pub fn from_config(cfg: &llmtrace_core::CircuitBreakerConfig) -> Self {
        Self::new(
            cfg.failure_threshold,
            Duration::from_millis(cfg.recovery_timeout_ms),
            cfg.half_open_max_calls,
        )
    }

    /// Returns `true` if the caller may proceed with an operation.
    pub async fn allow(&self) -> bool {
        let mut state = self.state.lock().await;
        match *state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let opened_at = self.opened_at_nanos.load(Ordering::Acquire);
                let elapsed = self.epoch.elapsed().as_nanos() as u64 - opened_at;
                if elapsed >= self.recovery_timeout.as_nanos() as u64 {
                    // Transition to half-open — this call counts as the first probe
                    *state = CircuitState::HalfOpen;
                    self.half_open_calls.store(1, Ordering::Release);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                let calls = self.half_open_calls.fetch_add(1, Ordering::AcqRel);
                calls < self.half_open_max_calls
            }
        }
    }

    /// Record a successful operation — may close the circuit.
    pub async fn record_success(&self) {
        let mut state = self.state.lock().await;
        match *state {
            CircuitState::HalfOpen => {
                // Probe succeeded — close the circuit
                *state = CircuitState::Closed;
                self.failure_count.store(0, Ordering::Release);
            }
            CircuitState::Closed => {
                // Reset consecutive failures
                self.failure_count.store(0, Ordering::Release);
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failed operation — may open the circuit.
    pub async fn record_failure(&self) {
        let mut state = self.state.lock().await;
        match *state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
                if count >= self.failure_threshold {
                    *state = CircuitState::Open;
                    let now_nanos = self.epoch.elapsed().as_nanos() as u64;
                    self.opened_at_nanos.store(now_nanos, Ordering::Release);
                }
            }
            CircuitState::HalfOpen => {
                // Probe failed — re-open
                *state = CircuitState::Open;
                let now_nanos = self.epoch.elapsed().as_nanos() as u64;
                self.opened_at_nanos.store(now_nanos, Ordering::Release);
            }
            CircuitState::Open => {}
        }
    }

    /// Return the current circuit state (for health reporting).
    pub async fn state(&self) -> CircuitState {
        *self.state.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_closed_allows_calls() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(5), 1);
        assert!(cb.allow().await);
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_opens_after_threshold() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60), 1);
        for _ in 0..3 {
            assert!(cb.allow().await);
            cb.record_failure().await;
        }
        assert_eq!(cb.state().await, CircuitState::Open);
        assert!(!cb.allow().await);
    }

    #[tokio::test]
    async fn test_success_resets_failure_count() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60), 1);
        cb.record_failure().await;
        cb.record_failure().await;
        cb.record_success().await;
        // After success, counter resets — need 3 more failures to open
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_half_open_after_recovery_timeout() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(10), 1);
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Wait for recovery
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(cb.allow().await);
        assert_eq!(cb.state().await, CircuitState::HalfOpen);
    }

    #[tokio::test]
    async fn test_half_open_success_closes() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(10), 1);
        cb.record_failure().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(cb.allow().await);
        cb.record_success().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_half_open_failure_reopens() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(10), 1);
        cb.record_failure().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(cb.allow().await);
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_half_open_limited_calls() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(10), 2);
        cb.record_failure().await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(cb.allow().await);
        assert!(cb.allow().await);
        // Third call should be rejected
        assert!(!cb.allow().await);
    }
}
