//! ML inference latency tracking with percentile statistics.
//!
//! Provides [`InferenceStatsTracker`], a thread-safe tracker that records
//! inference durations and computes P50/P95/P99 percentile statistics over
//! a sliding window of recent samples.
//!
//! # Feature Gate
//!
//! This module is only available when the `ml` feature is enabled.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

/// Default number of samples to retain in the sliding window.
pub const DEFAULT_MAX_SAMPLES: usize = 1000;

/// Summary statistics for ML inference latency.
#[derive(Debug, Clone)]
pub struct InferenceStats {
    /// Number of inference calls recorded.
    pub count: usize,
    /// Median latency (50th percentile).
    pub p50: Duration,
    /// 95th percentile latency.
    pub p95: Duration,
    /// 99th percentile latency.
    pub p99: Duration,
    /// Minimum observed latency.
    pub min: Duration,
    /// Maximum observed latency.
    pub max: Duration,
    /// Arithmetic mean latency.
    pub mean: Duration,
}

/// Thread-safe tracker for ML inference latency.
///
/// Maintains a sliding window of the most recent `max_samples` inference
/// durations. Statistics are computed on demand by sorting a snapshot of
/// the window — no ongoing overhead for each recorded sample beyond a
/// mutex-protected `VecDeque::push_back`.
///
/// # Example
///
/// ```
/// use llmtrace_security::inference_stats::InferenceStatsTracker;
/// use std::time::Duration;
///
/// let tracker = InferenceStatsTracker::new(100);
/// tracker.record(Duration::from_millis(10));
/// tracker.record(Duration::from_millis(20));
///
/// let stats = tracker.stats().unwrap();
/// assert_eq!(stats.count, 2);
/// assert!(stats.min <= stats.max);
/// ```
pub struct InferenceStatsTracker {
    inner: Mutex<TrackerInner>,
}

struct TrackerInner {
    /// Ring buffer of recent durations (insertion order).
    durations: VecDeque<Duration>,
    /// Maximum number of samples to retain.
    max_samples: usize,
}

impl InferenceStatsTracker {
    /// Create a new tracker with the specified sliding window size.
    #[must_use]
    pub fn new(max_samples: usize) -> Self {
        Self {
            inner: Mutex::new(TrackerInner {
                durations: VecDeque::with_capacity(max_samples),
                max_samples,
            }),
        }
    }

    /// Record an inference duration.
    ///
    /// If the window is full, the oldest sample is evicted.
    pub fn record(&self, duration: Duration) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.durations.len() >= inner.max_samples {
            inner.durations.pop_front();
        }
        inner.durations.push_back(duration);
    }

    /// Compute percentile statistics over the current window.
    ///
    /// Returns `None` if no samples have been recorded.
    #[must_use]
    pub fn stats(&self) -> Option<InferenceStats> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.durations.is_empty() {
            return None;
        }

        let mut sorted: Vec<Duration> = inner.durations.iter().copied().collect();
        sorted.sort();

        let count = sorted.len();
        let min = sorted[0];
        let max = sorted[count - 1];
        let total: Duration = sorted.iter().sum();
        let mean = total / count as u32;

        let p50 = percentile(&sorted, 50.0);
        let p95 = percentile(&sorted, 95.0);
        let p99 = percentile(&sorted, 99.0);

        Some(InferenceStats {
            count,
            p50,
            p95,
            p99,
            min,
            max,
            mean,
        })
    }

    /// Number of recorded samples currently in the window.
    #[must_use]
    pub fn count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .durations
            .len()
    }

    /// Reset the tracker, clearing all recorded samples.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.durations.clear();
    }
}

impl Default for InferenceStatsTracker {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SAMPLES)
    }
}

/// Compute the value at the given percentile from a sorted slice.
///
/// Uses nearest-rank interpolation.
fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_creation() {
        let tracker = InferenceStatsTracker::new(100);
        assert_eq!(tracker.count(), 0);
        assert!(tracker.stats().is_none());
    }

    #[test]
    fn test_tracker_default() {
        let tracker = InferenceStatsTracker::default();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn test_record_single_sample() {
        let tracker = InferenceStatsTracker::new(100);
        tracker.record(Duration::from_millis(42));
        assert_eq!(tracker.count(), 1);

        let stats = tracker.stats().unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.p50, Duration::from_millis(42));
        assert_eq!(stats.p95, Duration::from_millis(42));
        assert_eq!(stats.p99, Duration::from_millis(42));
        assert_eq!(stats.min, Duration::from_millis(42));
        assert_eq!(stats.max, Duration::from_millis(42));
        assert_eq!(stats.mean, Duration::from_millis(42));
    }

    #[test]
    fn test_record_multiple_samples() {
        let tracker = InferenceStatsTracker::new(100);
        for ms in [10, 20, 30, 40, 50] {
            tracker.record(Duration::from_millis(ms));
        }

        let stats = tracker.stats().unwrap();
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min, Duration::from_millis(10));
        assert_eq!(stats.max, Duration::from_millis(50));
        assert_eq!(stats.p50, Duration::from_millis(30));
        assert_eq!(stats.mean, Duration::from_millis(30));
    }

    #[test]
    fn test_sliding_window_eviction() {
        let tracker = InferenceStatsTracker::new(3);
        tracker.record(Duration::from_millis(100));
        tracker.record(Duration::from_millis(200));
        tracker.record(Duration::from_millis(300));
        assert_eq!(tracker.count(), 3);

        // Add a fourth — should evict the oldest (100ms)
        tracker.record(Duration::from_millis(400));
        assert_eq!(tracker.count(), 3);

        let stats = tracker.stats().unwrap();
        assert_eq!(stats.min, Duration::from_millis(200));
        assert_eq!(stats.max, Duration::from_millis(400));
    }

    #[test]
    fn test_percentiles_with_10_samples() {
        let tracker = InferenceStatsTracker::new(100);
        for ms in 1..=10 {
            tracker.record(Duration::from_millis(ms));
        }

        let stats = tracker.stats().unwrap();
        assert_eq!(stats.count, 10);
        assert_eq!(stats.min, Duration::from_millis(1));
        assert_eq!(stats.max, Duration::from_millis(10));
        // P50 with 10 items: index = round(0.5 * 9) = round(4.5) = 5 → value at index 5 = 6ms
        assert_eq!(stats.p50, Duration::from_millis(6));
        // P95: index = round(0.95 * 9) = round(8.55) = 9 → value at index 9 = 10ms
        assert_eq!(stats.p95, Duration::from_millis(10));
        // P99: index = round(0.99 * 9) = round(8.91) = 9 → value at index 9 = 10ms
        assert_eq!(stats.p99, Duration::from_millis(10));
    }

    #[test]
    fn test_percentiles_with_100_samples() {
        let tracker = InferenceStatsTracker::new(1000);
        for ms in 1..=100 {
            tracker.record(Duration::from_millis(ms));
        }

        let stats = tracker.stats().unwrap();
        assert_eq!(stats.count, 100);
        // P50: index = round(0.5 * 99) = round(49.5) = 50 → sorted[50] = 51ms
        assert_eq!(stats.p50, Duration::from_millis(51));
        // P95: index = round(0.95 * 99) = round(94.05) = 94 → sorted[94] = 95ms
        assert_eq!(stats.p95, Duration::from_millis(95));
        // P99: index = round(0.99 * 99) = round(98.01) = 98 → sorted[98] = 99ms
        assert_eq!(stats.p99, Duration::from_millis(99));
    }

    #[test]
    fn test_reset() {
        let tracker = InferenceStatsTracker::new(100);
        tracker.record(Duration::from_millis(10));
        tracker.record(Duration::from_millis(20));
        assert_eq!(tracker.count(), 2);

        tracker.reset();
        assert_eq!(tracker.count(), 0);
        assert!(tracker.stats().is_none());
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(InferenceStatsTracker::new(1000));
        let mut handles = Vec::new();

        for i in 0..10 {
            let t = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    t.record(Duration::from_millis(i * 100 + j));
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(tracker.count(), 1000);
        let stats = tracker.stats().unwrap();
        assert_eq!(stats.count, 1000);
        assert!(stats.min <= stats.p50);
        assert!(stats.p50 <= stats.p95);
        assert!(stats.p95 <= stats.p99);
        assert!(stats.p99 <= stats.max);
    }

    #[test]
    fn test_percentile_empty_slice() {
        assert_eq!(percentile(&[], 50.0), Duration::ZERO);
    }

    #[test]
    fn test_percentile_single_element() {
        let sorted = [Duration::from_millis(42)];
        assert_eq!(percentile(&sorted, 50.0), Duration::from_millis(42));
        assert_eq!(percentile(&sorted, 99.0), Duration::from_millis(42));
    }

    #[test]
    fn test_all_same_values() {
        let tracker = InferenceStatsTracker::new(100);
        for _ in 0..50 {
            tracker.record(Duration::from_millis(100));
        }

        let stats = tracker.stats().unwrap();
        assert_eq!(stats.p50, Duration::from_millis(100));
        assert_eq!(stats.p95, Duration::from_millis(100));
        assert_eq!(stats.p99, Duration::from_millis(100));
        assert_eq!(stats.min, Duration::from_millis(100));
        assert_eq!(stats.max, Duration::from_millis(100));
    }
}
