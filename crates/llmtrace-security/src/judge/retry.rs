//! Bounded exponential-backoff retry wrapper for judge backend calls.
//!
//! Retries are applied only to transient transport-level failures
//! (timeout, network reset) and to HTTP 5xx responses. 4xx responses
//! are treated as permanent client errors and returned immediately so
//! misconfigured API keys fail fast rather than exhausting the retry
//! budget.

use std::future::Future;
use std::time::Duration;

use super::JudgeError;

/// Run `op` with bounded exponential backoff, retrying only on
/// transient failures.
///
/// `max_retries = 0` disables retries and returns the first result
/// unchanged. Backoff grows as `backoff_base_ms * 2^attempt`, capped
/// implicitly by the caller's own timeout.
pub async fn with_retry<T, F, Fut>(
    max_retries: u32,
    backoff_base_ms: u64,
    mut op: F,
) -> Result<T, JudgeError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, JudgeError>>,
{
    let mut attempt: u32 = 0;
    loop {
        let result = op().await;
        match result {
            Ok(v) => return Ok(v),
            Err(ref e) if !is_retriable(e) => return result,
            Err(_) if attempt >= max_retries => return result,
            Err(_) => {
                let backoff = backoff_base_ms.saturating_mul(1u64 << attempt.min(8));
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                attempt += 1;
            }
        }
    }
}

/// Classify a judge error as transient (retriable) or permanent.
///
/// Retriable:
/// - [`JudgeError::Timeout`]: the peer may recover before the caller's
///   outer deadline.
/// - [`JudgeError::Transport`]: socket-level failure (DNS, reset, TLS).
/// - [`JudgeError::BackendError`] with status in 500-599: upstream
///   overload or transient 5xx.
///
/// Non-retriable:
/// - [`JudgeError::BackendError`] 4xx: client misconfig (bad API key,
///   bad request) -- retrying just burns the retry budget.
/// - [`JudgeError::ParseError`]: malformed output -- retry with the
///   same prompt will produce the same malformed output with high
///   probability.
/// - [`JudgeError::Misconfigured`]: not recoverable by retry.
fn is_retriable(err: &JudgeError) -> bool {
    match err {
        JudgeError::Timeout { .. } | JudgeError::Transport(_) => true,
        JudgeError::BackendError { status, .. } => (500..600).contains(status),
        JudgeError::ParseError(_) | JudgeError::Misconfigured(_) => false,
    }
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
        let out: Result<i32, JudgeError> = with_retry(3, 1, move || {
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
        let out: Result<&'static str, JudgeError> = with_retry(3, 1, move || {
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
        let out: Result<(), JudgeError> = with_retry(2, 1, move || {
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
        let out: Result<(), JudgeError> = with_retry(5, 1, move || {
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
}
