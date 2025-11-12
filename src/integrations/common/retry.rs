use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

use super::errors::{IntegrationError, IntegrationResult};

/// Retry policy configuration
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay before first retry
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
    /// Enable jitter to prevent thundering herd
    pub enable_jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            enable_jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            ..Default::default()
        }
    }

    /// Set initial delay
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Set max delay
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set backoff multiplier
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Disable jitter
    pub fn without_jitter(mut self) -> Self {
        self.enable_jitter = false;
        self
    }

    /// Calculate delay for a specific attempt
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(0);
        }

        // Calculate exponential backoff
        let base_delay_ms = self.initial_delay.as_millis() as f64;
        let exponential_delay = base_delay_ms * self.backoff_multiplier.powi((attempt - 1) as i32);

        // Cap at max delay
        let delay_ms = exponential_delay.min(self.max_delay.as_millis() as f64);

        Duration::from_millis(delay_ms as u64)
    }
}

/// Retry a fallible async operation with exponential backoff
pub async fn retry_with_backoff<F, Fut, T>(
    operation_name: &str,
    policy: &RetryPolicy,
    mut operation: F,
) -> IntegrationResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = IntegrationResult<T>>,
{
    let mut attempts = 0;

    while attempts < policy.max_attempts {
        attempts += 1;

        debug!(
            operation = operation_name,
            attempt = attempts,
            max_attempts = policy.max_attempts,
            "Attempting operation"
        );

        match operation().await {
            Ok(result) => {
                if attempts > 1 {
                    debug!(
                        operation = operation_name,
                        attempts = attempts,
                        "Operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(err) => {
                // Check if error is retryable
                if !err.is_retryable() {
                    warn!(
                        operation = operation_name,
                        error = %err,
                        "Non-retryable error encountered"
                    );
                    return Err(err);
                }

                warn!(
                    operation = operation_name,
                    attempt = attempts,
                    error = %err,
                    "Operation failed, will retry if attempts remaining"
                );

                // If we have more attempts, wait before retrying
                if attempts < policy.max_attempts {
                    let delay = policy.calculate_delay(attempts);
                    debug!(
                        operation = operation_name,
                        delay_ms = delay.as_millis(),
                        next_attempt = attempts + 1,
                        "Waiting before retry"
                    );
                    sleep(delay).await;
                }
            }
        }
    }

    // All retries exhausted
    Err(IntegrationError::RetryExhausted {
        operation: operation_name.to_string(),
        attempts,
    })
}
