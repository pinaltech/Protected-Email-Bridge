//! Application-level back-off (§4.6).

use std::future::Future;
use std::time::Duration;

use crate::config::limits;
use crate::error::Result;
use crate::util::jitter;

/// Back-off sequence state. Resets at the start of each logical operation.
#[derive(Debug, Default, Clone)]
pub struct Backoff {
    step: usize,
}

impl Backoff {
    pub fn new() -> Self {
        Self::default()
    }

    /// Next wait: 20, 40, 80, 160, 300, 600 s (then 600 s), plus U[0, 10 s).
    pub fn next_delay(&mut self) -> Duration {
        let seq = &limits::APP_BACKOFF_SEQUENCE;
        let base = seq[self.step.min(seq.len() - 1)];
        self.step = (self.step + 1).min(seq.len() - 1);
        Duration::from_secs(base) + jitter(Duration::from_secs(limits::BACKOFF_JITTER_SECS))
    }

    pub fn reset(&mut self) {
        self.step = 0;
    }
}

/// Run `op`, retrying indefinitely on errors with HTTP status 429 or ≥ 500.
/// Any other error is returned immediately. Drop the future to cancel.
pub async fn with_backoff<T, F, Fut>(mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut backoff = Backoff::new();
    loop {
        match op().await {
            Err(e) if e.is_backoff_retryable() => {
                let d = backoff.next_delay();
                tracing::debug!("back-off {:?} after error: {e}", d);
                tokio::time::sleep(d).await;
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence() {
        let mut b = Backoff::new();
        let secs: Vec<u64> = (0..8).map(|_| b.next_delay().as_secs()).collect();
        let bases = [20, 40, 80, 160, 300, 600, 600, 600];
        for (s, base) in secs.iter().zip(bases) {
            assert!(*s >= base && *s < base + 10);
        }
    }
}
