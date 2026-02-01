//! Graceful shutdown coordination.
//!
//! Provides a [`ShutdownCoordinator`] that listens for OS signals (SIGTERM,
//! SIGINT) and propagates a cancellation to all subsystems: the axum HTTP
//! server, the optional gRPC server, and any in-flight background tasks
//! (trace capture, security analysis).
//!
//! ## Design
//!
//! * A single [`tokio_util::sync::CancellationToken`] acts as the shutdown
//!   broadcast channel.  Cloning the token is cheap and can be handed to
//!   every subsystem.
//! * A [`tokio::task::JoinSet`] (wrapped behind an `Arc<Mutex<…>>`) tracks
//!   background tasks so we can wait for them to complete before exiting.
//! * After the shutdown signal fires we wait up to
//!   `shutdown.timeout_seconds` (default 30 s) for pending tasks, then
//!   force-exit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Shutdown coordinator
// ---------------------------------------------------------------------------

/// Coordinates graceful shutdown across all proxy subsystems.
#[derive(Clone)]
pub struct ShutdownCoordinator {
    /// The cancellation token that signals shutdown to all subsystems.
    token: CancellationToken,
    /// Atomic counter of in-flight background tasks.
    in_flight: Arc<AtomicUsize>,
    /// Maximum seconds to wait for in-flight tasks after signal.
    timeout_seconds: u64,
}

impl ShutdownCoordinator {
    /// Create a new coordinator with the given shutdown timeout.
    pub fn new(timeout_seconds: u64) -> Self {
        Self {
            token: CancellationToken::new(),
            in_flight: Arc::new(AtomicUsize::new(0)),
            timeout_seconds,
        }
    }

    /// Get a clone of the cancellation token (cheap).
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Returns `true` if a shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Register a new in-flight background task.
    ///
    /// Returns a [`TaskGuard`] that decrements the counter on drop.
    pub fn track_task(&self) -> TaskGuard {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        TaskGuard {
            in_flight: Arc::clone(&self.in_flight),
        }
    }

    /// Current number of in-flight background tasks.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Trigger the shutdown signal (used by signal handler).
    pub fn trigger(&self) {
        self.token.cancel();
    }

    /// Wait for in-flight tasks to complete, up to the configured timeout.
    ///
    /// Returns `true` if all tasks drained within the timeout, `false` if
    /// the timeout expired with tasks still pending.
    pub async fn wait_for_tasks(&self) -> bool {
        let timeout = std::time::Duration::from_secs(self.timeout_seconds);
        let poll_interval = std::time::Duration::from_millis(250);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let count = self.in_flight_count();
            if count == 0 {
                info!("All in-flight tasks completed");
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    remaining_tasks = count,
                    timeout_seconds = self.timeout_seconds,
                    "Shutdown timeout expired with in-flight tasks still pending"
                );
                return false;
            }
            info!(
                remaining_tasks = count,
                "Waiting for in-flight tasks to complete"
            );
            tokio::time::sleep(poll_interval).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Task guard (RAII counter)
// ---------------------------------------------------------------------------

/// RAII guard that decrements the in-flight task counter on drop.
pub struct TaskGuard {
    in_flight: Arc<AtomicUsize>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

/// Returns a future that resolves when a shutdown signal is received.
///
/// On Unix this listens for both SIGTERM and SIGINT.
/// On other platforms (Windows) it listens for Ctrl-C only.
pub async fn shutdown_signal(coordinator: ShutdownCoordinator) {
    let token = coordinator.token();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Shutdown signal received (SIGTERM)");
            }
            _ = sigint.recv() => {
                info!("Shutdown signal received (SIGINT)");
            }
            _ = token.cancelled() => {
                // Token was cancelled externally (e.g., programmatic shutdown).
                info!("Shutdown signal received (token cancelled)");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received (Ctrl-C)");
            }
            _ = token.cancelled() => {
                info!("Shutdown signal received (token cancelled)");
            }
        }
    }

    // Propagate the cancellation to all subsystems.
    coordinator.trigger();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_initial_state() {
        let coord = ShutdownCoordinator::new(30);
        assert!(!coord.is_shutting_down());
        assert_eq!(coord.in_flight_count(), 0);
    }

    #[test]
    fn test_coordinator_trigger() {
        let coord = ShutdownCoordinator::new(30);
        assert!(!coord.is_shutting_down());
        coord.trigger();
        assert!(coord.is_shutting_down());
    }

    #[test]
    fn test_task_guard_increments_and_decrements() {
        let coord = ShutdownCoordinator::new(30);
        assert_eq!(coord.in_flight_count(), 0);

        let guard1 = coord.track_task();
        assert_eq!(coord.in_flight_count(), 1);

        let guard2 = coord.track_task();
        assert_eq!(coord.in_flight_count(), 2);

        drop(guard1);
        assert_eq!(coord.in_flight_count(), 1);

        drop(guard2);
        assert_eq!(coord.in_flight_count(), 0);
    }

    #[test]
    fn test_coordinator_clone_shares_state() {
        let coord = ShutdownCoordinator::new(30);
        let coord2 = coord.clone();

        let _guard = coord.track_task();
        assert_eq!(coord2.in_flight_count(), 1);

        coord.trigger();
        assert!(coord2.is_shutting_down());
    }

    #[tokio::test]
    async fn test_wait_for_tasks_immediate_when_empty() {
        let coord = ShutdownCoordinator::new(1);
        assert!(coord.wait_for_tasks().await);
    }

    #[tokio::test]
    async fn test_wait_for_tasks_completes_when_guard_dropped() {
        let coord = ShutdownCoordinator::new(5);
        let coord2 = coord.clone();

        // Spawn a task that holds a guard for 100ms
        tokio::spawn(async move {
            let _guard = coord2.track_task();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        // Give the spawn a moment to register
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(coord.in_flight_count() > 0);

        // Should complete well within 5s
        assert!(coord.wait_for_tasks().await);
    }

    #[tokio::test]
    async fn test_wait_for_tasks_timeout() {
        let coord = ShutdownCoordinator::new(1); // 1 second timeout
        let _guard = coord.track_task(); // never dropped

        // Should return false after ~1s
        let start = tokio::time::Instant::now();
        assert!(!coord.wait_for_tasks().await);
        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() >= 1);
    }

    #[tokio::test]
    async fn test_shutdown_signal_via_token_cancellation() {
        let coord = ShutdownCoordinator::new(30);
        let coord2 = coord.clone();

        // Cancel the token after a short delay
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            coord2.trigger();
        });

        // shutdown_signal should return quickly
        let start = tokio::time::Instant::now();
        shutdown_signal(coord.clone()).await;
        assert!(start.elapsed().as_millis() < 1000);
        assert!(coord.is_shutting_down());
    }
}
