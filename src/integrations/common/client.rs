use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::errors::IntegrationResult;

/// Health check status for an LLM integration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    /// Service is healthy and operational
    Healthy,
    /// Service is degraded but operational
    Degraded,
    /// Service is unhealthy or unreachable
    Unhealthy,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Overall health status
    pub status: HealthStatus,
    /// Service name
    pub service: String,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Additional details
    pub details: Option<String>,
    /// Timestamp of the check
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

impl HealthCheck {
    /// Create a new health check result
    pub fn new(service: String, status: HealthStatus, response_time_ms: u64) -> Self {
        Self {
            status,
            service,
            response_time_ms,
            details: None,
            checked_at: chrono::Utc::now(),
        }
    }

    /// Add details to the health check
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Check if the service is healthy
    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }

    /// Check if the service is operational (healthy or degraded)
    pub fn is_operational(&self) -> bool {
        matches!(self.status, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

/// Connection configuration for LLM clients
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Base URL of the service
    pub base_url: String,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Enable TLS verification
    pub verify_tls: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_connections: 100,
            verify_tls: true,
        }
    }
}

impl ConnectionConfig {
    /// Create a new connection configuration
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            ..Default::default()
        }
    }

    /// Set connection timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set request timeout
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set max connections
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Disable TLS verification (for testing only)
    pub fn without_tls_verification(mut self) -> Self {
        self.verify_tls = false;
        self
    }
}

/// Trait for LLM service clients
#[async_trait]
pub trait LLMClient: Send + Sync {
    /// Connect to the LLM service
    async fn connect(&mut self) -> IntegrationResult<()>;

    /// Disconnect from the LLM service
    async fn disconnect(&mut self) -> IntegrationResult<()>;

    /// Perform a health check
    async fn health_check(&self) -> IntegrationResult<HealthCheck>;

    /// Check if the client is connected
    fn is_connected(&self) -> bool;

    /// Get the service name
    fn service_name(&self) -> &str;

    /// Get connection configuration
    fn config(&self) -> &ConnectionConfig;
}

/// Connection state for client implementations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Currently connecting
    Connecting,
    /// Successfully connected
    Connected,
    /// Connection failed
    Failed,
}

impl ConnectionState {
    /// Check if connected
    pub fn is_connected(&self) -> bool {
        *self == ConnectionState::Connected
    }

    /// Check if in a transitional state
    pub fn is_transitioning(&self) -> bool {
        *self == ConnectionState::Connecting
    }

    /// Check if failed
    pub fn is_failed(&self) -> bool {
        *self == ConnectionState::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check_creation() {
        let check = HealthCheck::new("sentinel".to_string(), HealthStatus::Healthy, 100);
        assert_eq!(check.service, "sentinel");
        assert_eq!(check.status, HealthStatus::Healthy);
        assert_eq!(check.response_time_ms, 100);
        assert!(check.is_healthy());
        assert!(check.is_operational());
    }

    #[test]
    fn test_health_check_with_details() {
        let check = HealthCheck::new("sentinel".to_string(), HealthStatus::Degraded, 200)
            .with_details("High latency detected".to_string());

        assert_eq!(check.status, HealthStatus::Degraded);
        assert_eq!(check.details, Some("High latency detected".to_string()));
        assert!(!check.is_healthy());
        assert!(check.is_operational());
    }

    #[test]
    fn test_health_check_unhealthy() {
        let check = HealthCheck::new("sentinel".to_string(), HealthStatus::Unhealthy, 0);
        assert!(!check.is_healthy());
        assert!(!check.is_operational());
    }

    #[test]
    fn test_connection_config_builder() {
        let config = ConnectionConfig::new("https://api.example.com".to_string())
            .with_connect_timeout(Duration::from_secs(5))
            .with_request_timeout(Duration::from_secs(60))
            .with_max_connections(50);

        assert_eq!(config.base_url, "https://api.example.com");
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.request_timeout, Duration::from_secs(60));
        assert_eq!(config.max_connections, 50);
        assert!(config.verify_tls);
    }

    #[test]
    fn test_connection_state() {
        assert!(ConnectionState::Connected.is_connected());
        assert!(!ConnectionState::Disconnected.is_connected());
        assert!(!ConnectionState::Failed.is_connected());

        assert!(ConnectionState::Connecting.is_transitioning());
        assert!(!ConnectionState::Connected.is_transitioning());

        assert!(ConnectionState::Failed.is_failed());
        assert!(!ConnectionState::Connected.is_failed());
    }
}
