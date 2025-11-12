pub mod auth;
pub mod client;
pub mod errors;
pub mod metrics;
pub mod retry;
pub mod timeout;

pub use auth::Credentials;
pub use client::{ConnectionConfig, ConnectionState, HealthCheck, HealthStatus, LLMClient};
pub use errors::{IntegrationError, IntegrationResult};
pub use metrics::IntegrationMetrics;
pub use retry::{retry_with_backoff, RetryPolicy};
pub use timeout::TimeoutConfig;
