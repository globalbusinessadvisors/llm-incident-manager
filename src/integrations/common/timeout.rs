use std::time::Duration;
use tokio::time::timeout;
use tracing::warn;

use crate::error::{AppError, Result};

/// Timeout configuration for LLM operations
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    pub request_timeout: Duration,
    pub connection_timeout: Duration,
    pub stream_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(10),
            stream_timeout: Duration::from_secs(300), // 5 minutes for streaming
        }
    }
}

/// Execute an operation with a timeout
pub async fn with_timeout<F, T>(
    operation_name: &str,
    duration: Duration,
    future: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match timeout(duration, future).await {
        Ok(result) => result,
        Err(_) => {
            warn!(
                operation = operation_name,
                timeout_secs = duration.as_secs(),
                "Operation timed out"
            );
            Err(AppError::Timeout(format!(
                "{} timed out after {:?}",
                operation_name, duration
            )))
        }
    }
}

/// Execute a request with the configured request timeout
pub async fn with_request_timeout<F, T>(
    config: &TimeoutConfig,
    operation_name: &str,
    future: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    with_timeout(operation_name, config.request_timeout, future).await
}

/// Execute a connection operation with the configured connection timeout
pub async fn with_connection_timeout<F, T>(
    config: &TimeoutConfig,
    operation_name: &str,
    future: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    with_timeout(operation_name, config.connection_timeout, future).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_timeout_success() {
        let result = with_timeout(
            "test_op",
            Duration::from_secs(1),
            async {
                sleep(Duration::from_millis(100)).await;
                Ok(42)
            },
        )
        .await;

        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_timeout_exceeded() {
        let result = with_timeout(
            "test_op",
            Duration::from_millis(100),
            async {
                sleep(Duration::from_secs(1)).await;
                Ok::<i32, AppError>(42)
            },
        )
        .await;

        assert!(matches!(result, Err(AppError::Timeout(_))));
    }

    #[tokio::test]
    async fn test_request_timeout() {
        let config = TimeoutConfig::default();
        let result = with_request_timeout(
            &config,
            "test_request",
            async {
                sleep(Duration::from_millis(100)).await;
                Ok(42)
            },
        )
        .await;

        assert_eq!(result.unwrap(), 42);
    }
}
