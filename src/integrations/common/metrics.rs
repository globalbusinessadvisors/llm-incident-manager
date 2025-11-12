use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metrics for tracking LLM integration performance
#[derive(Debug, Clone)]
pub struct IntegrationMetrics {
    pub name: String,
    pub total_requests: Arc<AtomicU64>,
    pub successful_requests: Arc<AtomicU64>,
    pub failed_requests: Arc<AtomicU64>,
    pub total_latency_ms: Arc<AtomicU64>,
    pub last_request_time: Arc<parking_lot::RwLock<Option<DateTime<Utc>>>>,
}

impl IntegrationMetrics {
    /// Create a new metrics tracker for an integration
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            total_requests: Arc::new(AtomicU64::new(0)),
            successful_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            total_latency_ms: Arc::new(AtomicU64::new(0)),
            last_request_time: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Record a successful request
    pub fn record_success(&self, latency_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        *self.last_request_time.write() = Some(Utc::now());

        tracing::debug!(
            integration = %self.name,
            latency_ms = latency_ms,
            "Request succeeded"
        );
    }

    /// Record a failed request
    pub fn record_failure(&self, latency_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        *self.last_request_time.write() = Some(Utc::now());

        tracing::warn!(
            integration = %self.name,
            latency_ms = latency_ms,
            "Request failed"
        );
    }

    /// Get a snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        let total = self.total_requests.load(Ordering::Relaxed);
        let successful = self.successful_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        let total_latency = self.total_latency_ms.load(Ordering::Relaxed);

        MetricsSnapshot {
            integration_name: self.name.clone(),
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            success_rate: if total > 0 {
                (successful as f64 / total as f64) * 100.0
            } else {
                0.0
            },
            average_latency_ms: if total > 0 {
                total_latency / total
            } else {
                0
            },
            last_request_time: *self.last_request_time.read(),
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.successful_requests.store(0, Ordering::Relaxed);
        self.failed_requests.store(0, Ordering::Relaxed);
        self.total_latency_ms.store(0, Ordering::Relaxed);
        *self.last_request_time.write() = None;
    }
}

/// Snapshot of integration metrics at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub integration_name: String,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub success_rate: f64,
    pub average_latency_ms: u64,
    pub last_request_time: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_tracking() {
        let metrics = IntegrationMetrics::new("test-integration");

        metrics.record_success(100);
        metrics.record_success(200);
        metrics.record_failure(150);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.total_requests, 3);
        assert_eq!(snapshot.successful_requests, 2);
        assert_eq!(snapshot.failed_requests, 1);
        assert!((snapshot.success_rate - 66.67).abs() < 0.1);
        assert_eq!(snapshot.average_latency_ms, 150);
        assert!(snapshot.last_request_time.is_some());
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = IntegrationMetrics::new("test-integration");

        metrics.record_success(100);
        metrics.record_failure(200);

        let before_reset = metrics.snapshot();
        assert_eq!(before_reset.total_requests, 2);

        metrics.reset();

        let after_reset = metrics.snapshot();
        assert_eq!(after_reset.total_requests, 0);
        assert_eq!(after_reset.successful_requests, 0);
        assert_eq!(after_reset.failed_requests, 0);
    }
}
