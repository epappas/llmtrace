//! Bounded exponential-backoff retry wrapper for judge backend calls.
//!
//! Retries are applied to transient transport-level failures (timeout,
//! network reset) and to the retriable HTTP status codes defined by
//! [`is_retriable_status`]: 408 Request Timeout, 429 Too Many
//! Requests, and the entire 5xx range. 4xx otherwise is treated as a
//! permanent client error and returned immediately so misconfigured
//! API keys fail fast rather than exhausting the retry budget.
//!
//! Issues #73 / #74 / #75 harden this wrapper:
//! - A configurable `total_deadline` caps the worst-case end-to-end
//!   latency regardless of how many retries happen (#73).
//! - Full-jitter randomisation on the exponential backoff avoids a
//!   thundering-herd when many clients hit the same upstream outage
//!   simultaneously (#74).
//! - Server-supplied `Retry-After` hints (parsed in the backend layer
//!   into [`super::JudgeError::retry_after_ms`]) override the
//!   jittered backoff, clamped to the remaining deadline (#75).

use std::future::Future;
use std::time::{Duration, Instant};

use rand::Rng;

use super::JudgeError;

/// Run `op` with bounded exponential backoff + full jitter, retrying
/// only on transient failures.
///
/// # Arguments
///
/// * `max_retries` — how many *additional* attempts after the initial
///   call. `0` disables retries.
/// * `backoff_base_ms` — initial backoff in milliseconds. Grows as
///   `base * 2^attempt` before jittering; capped at `attempt = 8`.
/// * `total_deadline` — optional end-to-end ceiling. The loop exits
///   early with the last error when the next sleep would push past
///   this budget. `None` disables the deadline (retries are only
///   bounded by `max_retries`).
/// * `op` — the operation to run. Called at least once; may be called
///   up to `max_retries + 1` times total.
pub async fn with_retry<T, F, Fut>(
    max_retries: u32,
    backoff_base_ms: u64,
    total_deadline: Option<Duration>,
    mut op: F,
) -> Result<T, JudgeError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, JudgeError>>,
{
    let started = Instant::now();
    let mut attempt: u32 = 0;
    loop {
        let result = op().await;
        match result {
            Ok(v) => return Ok(v),
            Err(ref e) if !is_retriable(e) => return result,
            Err(_) if attempt >= max_retries => return result,
            Err(ref e) => {
                // Deadline check first: if the operator-configured
                // deadline has already elapsed, return without a
                // further retry regardless of how we'd compute sleep.
                if let Some(deadline) = total_deadline {
                    if started.elapsed() >= deadline {
                        return result;
                    }
                }
                let computed = compute_backoff(backoff_base_ms, attempt);
                let hint = e
                    .retry_after_ms()
                    .map(Duration::from_millis)
                    .unwrap_or(computed);
                // Clamp the sleep to whatever budget remains so a
                // hostile server cannot hold the worker past the
                // operator deadline via a large `Retry-After`.
                let sleep = match total_deadline {
                    None => hint,
                    Some(deadline) => {
                        let remaining = deadline.saturating_sub(started.elapsed());
                        hint.min(remaining)
                    }
                };
                tokio::time::sleep(sleep).await;
                attempt += 1;
            }
        }
    }
}

/// Compute the full-jittered exponential backoff for a given attempt
/// number. Pure function for testability.
///
/// Jitter strategy: "full jitter" from AWS Architecture Blog — sleep
/// is uniformly sampled from `[0, base * 2^attempt]`. Compared to
/// deterministic exponential backoff this flattens synchronised
/// retries across many clients without raising the expected latency.
#[must_use]
pub fn compute_backoff(backoff_base_ms: u64, attempt: u32) -> Duration {
    let ceiling = backoff_base_ms.saturating_mul(1u64 << attempt.min(8));
    if ceiling == 0 {
        return Duration::ZERO;
    }
    let jittered = rand::thread_rng().gen_range(0..=ceiling);
    Duration::from_millis(jittered)
}

/// Classify a judge error as transient (retriable) or permanent.
///
/// Retriable:
/// - [`JudgeError::Timeout`]: the peer may recover before the caller's
///   outer deadline.
/// - [`JudgeError::Transport`]: socket-level failure (DNS, reset, TLS).
/// - [`JudgeError::BackendError`] where `is_retriable_status` returns
///   true (5xx + 408 + 429).
///
/// Non-retriable:
/// - [`JudgeError::BackendError`] with any other 4xx status: client
///   misconfig (bad API key, bad request) — retrying burns budget.
/// - [`JudgeError::ParseError`]: malformed output — retry with the
///   same prompt will produce the same malformed output with high
///   probability.
/// - [`JudgeError::Misconfigured`]: not recoverable by retry.
fn is_retriable(err: &JudgeError) -> bool {
    match err {
        JudgeError::Timeout { .. } | JudgeError::Transport(_) => true,
        JudgeError::BackendError { status, .. } => is_retriable_status(*status),
        JudgeError::ParseError(_) | JudgeError::Misconfigured(_) => false,
    }
}

/// HTTP status codes treated as transient by the judge retry policy.
///
/// - `408 Request Timeout`: upstream signalled it gave up waiting; a
///   fresh connection may succeed.
/// - `429 Too Many Requests`: rate-limit window; provider guidance is
///   to retry with `Retry-After` honored.
/// - `500..600`: server-side transient failures.
#[must_use]
pub fn is_retriable_status(status: u16) -> bool {
    status == 408 || status == 429 || (500..600).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn with_retry_succeeds_first_try_no_sleep() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let out: Result<i32, JudgeError> = with_retry(3, 1, None, move || {
            let calls = Arc::clone(&calls_c);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<i32, JudgeError>(7)
            }
        })
        .await;
        assert_eq!(out.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn with_retry_retries_on_transport_then_succeeds() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let out: Result<&'static str, JudgeError> = with_retry(3, 1, None, move || {
            let calls = Arc::clone(&calls_c);
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(JudgeError::Transport("reset".to_string()))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn with_retry_stops_after_max_retries() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let out: Result<(), JudgeError> = with_retry(2, 1, None, move || {
            let calls = Arc::clone(&calls_c);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), JudgeError>(JudgeError::Timeout { elapsed_ms: 100 })
            }
        })
        .await;
        assert!(matches!(out, Err(JudgeError::Timeout { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 3); // initial + 2 retries
    }

    #[tokio::test]
    async fn with_retry_does_not_retry_parse_errors() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let out: Result<(), JudgeError> = with_retry(5, 1, None, move || {
            let calls = Arc::clone(&calls_c);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), JudgeError>(JudgeError::ParseError("bad".to_string()))
            }
        })
        .await;
        assert!(matches!(out, Err(JudgeError::ParseError(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn with_retry_retries_on_429_then_succeeds() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let out: Result<&'static str, JudgeError> = with_retry(2, 1, None, move || {
            let calls = Arc::clone(&calls_c);
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(JudgeError::BackendError {
                        status: 429,
                        message: "rate limited".to_string(),
                        retry_after_ms: None,
                    })
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn with_retry_retries_on_408_then_succeeds() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let out: Result<&'static str, JudgeError> = with_retry(2, 1, None, move || {
            let calls = Arc::clone(&calls_c);
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(JudgeError::BackendError {
                        status: 408,
                        message: "request timeout".to_string(),
                        retry_after_ms: None,
                    })
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn with_retry_does_not_retry_400() {
        // 400 Bad Request is not in the retriable set.
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let out: Result<(), JudgeError> = with_retry(5, 1, None, move || {
            let calls = Arc::clone(&calls_c);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), JudgeError>(JudgeError::BackendError {
                    status: 400,
                    message: "bad request".to_string(),
                    retry_after_ms: None,
                })
            }
        })
        .await;
        assert!(matches!(
            out,
            Err(JudgeError::BackendError { status: 400, .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn with_retry_total_deadline_short_circuits_before_retrying() {
        // Deadline of 10ms but the computed/jittered backoff for
        // attempt 0 at base=50ms can land above 10ms. Even if it
        // lands below, after the first retry elapsed time exceeds
        // the 10ms deadline. Assert <= 2 calls rather than the 3
        // the max_retries would otherwise produce.
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let out: Result<(), JudgeError> =
            with_retry(10, 50, Some(Duration::from_millis(10)), move || {
                let calls = Arc::clone(&calls_c);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err::<(), JudgeError>(JudgeError::Timeout { elapsed_ms: 5 })
                }
            })
            .await;
        assert!(matches!(out, Err(JudgeError::Timeout { .. })));
        let n = calls.load(Ordering::SeqCst);
        assert!(
            n < 10,
            "deadline should have short-circuited the 10 configured retries; got {n} calls"
        );
    }

    #[tokio::test]
    async fn with_retry_honors_retry_after_hint() {
        // Assert the wrapper sleeps for the hint rather than the
        // default backoff. Use a large hint + small max_retries so the
        // observable effect is a minimum elapsed time near the hint.
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let started = Instant::now();
        let out: Result<&'static str, JudgeError> = with_retry(1, 1, None, move || {
            let calls = Arc::clone(&calls_c);
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(JudgeError::BackendError {
                        status: 429,
                        message: "rate limited".to_string(),
                        retry_after_ms: Some(100), // hint: wait 100ms
                    })
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        let elapsed = started.elapsed();
        assert_eq!(out.unwrap(), "ok");
        // 100ms hint should dominate the 1ms base; we should have
        // slept approximately 100ms before retrying.
        assert!(
            elapsed >= Duration::from_millis(90),
            "retry_after hint ignored: elapsed={elapsed:?}"
        );
    }

    #[test]
    fn compute_backoff_respects_attempt_cap_and_jitters() {
        // Full jitter samples in [0, ceiling] where ceiling is
        // `base * 2^min(attempt, 8)`. Any single sample can be 0; the
        // contract is that the upper bound matches the computed ceiling.
        let ceiling_b0 = Duration::from_millis(10);
        let ceiling_b8 = Duration::from_millis(10 * 256);
        for _ in 0..32 {
            assert!(compute_backoff(10, 0) <= ceiling_b0);
            assert!(compute_backoff(10, 8) <= ceiling_b8);
            // Attempts past 8 reuse the capped ceiling.
            assert!(compute_backoff(10, 20) <= ceiling_b8);
        }
    }

    #[test]
    fn is_retriable_status_matches_contract() {
        assert!(is_retriable_status(408));
        assert!(is_retriable_status(429));
        assert!(is_retriable_status(500));
        assert!(is_retriable_status(503));
        assert!(is_retriable_status(599));
        assert!(!is_retriable_status(400));
        assert!(!is_retriable_status(401));
        assert!(!is_retriable_status(404));
        assert!(!is_retriable_status(600));
        assert!(!is_retriable_status(200));
    }
}
