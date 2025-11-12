use tokio::sync::mpsc;
use tracing::{debug, error, info};

use super::models::{InferenceRequest, InferenceResult};

/// Bidirectional stream manager for edge inference
pub struct StreamManager {
    request_tx: mpsc::Sender<InferenceRequest>,
    response_rx: mpsc::Receiver<InferenceResult>,
}

impl StreamManager {
    /// Create a new stream manager
    pub fn new(
        request_tx: mpsc::Sender<InferenceRequest>,
        response_rx: mpsc::Receiver<InferenceResult>,
    ) -> Self {
        Self {
            request_tx,
            response_rx,
        }
    }

    /// Send a request through the stream
    pub async fn send_request(&self, request: InferenceRequest) -> Result<(), String> {
        debug!(request_id = %request.request_id, "Sending inference request");
        self.request_tx
            .send(request)
            .await
            .map_err(|e| format!("Failed to send request: {}", e))
    }

    /// Receive the next response from the stream
    pub async fn recv_response(&mut self) -> Option<InferenceResult> {
        match self.response_rx.recv().await {
            Some(result) => {
                debug!(request_id = %result.request_id, status = %result.status, "Received inference result");
                Some(result)
            }
            None => {
                info!("Response stream closed");
                None
            }
        }
    }

    /// Get a reference to the request sender
    pub fn request_sender(&self) -> mpsc::Sender<InferenceRequest> {
        self.request_tx.clone()
    }
}

/// Stream coordinator for managing multiple concurrent streams
pub struct StreamCoordinator {
    active_streams: std::sync::Arc<parking_lot::RwLock<Vec<String>>>,
}

impl StreamCoordinator {
    /// Create a new stream coordinator
    pub fn new() -> Self {
        Self {
            active_streams: std::sync::Arc::new(parking_lot::RwLock::new(Vec::new())),
        }
    }

    /// Register a new active stream
    pub fn register_stream(&self, stream_id: String) {
        let mut streams = self.active_streams.write();
        streams.push(stream_id.clone());
        info!(stream_id = %stream_id, "Registered new stream");
    }

    /// Unregister a stream
    pub fn unregister_stream(&self, stream_id: &str) {
        let mut streams = self.active_streams.write();
        streams.retain(|id| id != stream_id);
        info!(stream_id = %stream_id, "Unregistered stream");
    }

    /// Get count of active streams
    pub fn active_count(&self) -> usize {
        self.active_streams.read().len()
    }

    /// Get list of active stream IDs
    pub fn active_stream_ids(&self) -> Vec<String> {
        self.active_streams.read().clone()
    }
}

impl Default for StreamCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Health checker for stream connectivity
pub struct StreamHealthChecker {
    last_heartbeat: std::sync::Arc<parking_lot::RwLock<chrono::DateTime<chrono::Utc>>>,
}

impl StreamHealthChecker {
    /// Create a new health checker
    pub fn new() -> Self {
        Self {
            last_heartbeat: std::sync::Arc::new(parking_lot::RwLock::new(chrono::Utc::now())),
        }
    }

    /// Update the last heartbeat timestamp
    pub fn heartbeat(&self) {
        let mut last = self.last_heartbeat.write();
        *last = chrono::Utc::now();
        debug!("Stream heartbeat updated");
    }

    /// Check if the stream is healthy (heartbeat within threshold)
    pub fn is_healthy(&self, threshold_secs: i64) -> bool {
        let last = self.last_heartbeat.read();
        let now = chrono::Utc::now();
        let duration = now.signed_duration_since(*last);
        let is_healthy = duration.num_seconds() < threshold_secs;

        if !is_healthy {
            error!(
                seconds_since_heartbeat = duration.num_seconds(),
                threshold = threshold_secs,
                "Stream health check failed"
            );
        }

        is_healthy
    }

    /// Get seconds since last heartbeat
    pub fn seconds_since_heartbeat(&self) -> i64 {
        let last = self.last_heartbeat.read();
        let now = chrono::Utc::now();
        now.signed_duration_since(*last).num_seconds()
    }
}

impl Default for StreamHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_stream_manager() {
        let (request_tx, mut request_rx) = mpsc::channel(10);
        let (response_tx, response_rx) = mpsc::channel(10);

        let manager = StreamManager::new(request_tx, response_rx);

        // Spawn a task to echo requests as responses
        tokio::spawn(async move {
            while let Some(req) = request_rx.recv().await {
                let result = InferenceResult {
                    request_id: req.request_id,
                    result: "test result".to_string(),
                    confidence: 0.95,
                    status: super::super::models::InferenceStatus::Completed,
                    metadata: HashMap::new(),
                    resource_usage: super::super::models::ResourceSnapshot {
                        cpu_percent: 50.0,
                        memory_mb: 1024.0,
                        gpu_percent: 30.0,
                        disk_io_mb_per_sec: 10.0,
                        active_requests: 1,
                        queued_requests: 0,
                        timestamp: Utc::now(),
                    },
                    processed_at: Utc::now(),
                };
                response_tx.send(result).await.unwrap();
            }
        });

        let request = InferenceRequest {
            request_id: "test-1".to_string(),
            model_id: "model-1".to_string(),
            input_data: "test input".to_string(),
            parameters: HashMap::new(),
            priority: super::super::models::InferencePriority::Medium,
            allow_offline_queue: false,
            timestamp: Utc::now(),
        };

        manager.send_request(request).await.unwrap();
        let mut manager_mut = manager;
        let result = manager_mut.recv_response().await.unwrap();
        assert_eq!(result.request_id, "test-1");
    }

    #[test]
    fn test_stream_coordinator() {
        let coordinator = StreamCoordinator::new();

        assert_eq!(coordinator.active_count(), 0);

        coordinator.register_stream("stream-1".to_string());
        coordinator.register_stream("stream-2".to_string());

        assert_eq!(coordinator.active_count(), 2);

        coordinator.unregister_stream("stream-1");
        assert_eq!(coordinator.active_count(), 1);

        let ids = coordinator.active_stream_ids();
        assert_eq!(ids, vec!["stream-2"]);
    }

    #[tokio::test]
    async fn test_health_checker() {
        let checker = StreamHealthChecker::new();

        // Should be healthy immediately
        assert!(checker.is_healthy(60));

        // Update heartbeat
        checker.heartbeat();
        assert!(checker.is_healthy(60));
        assert_eq!(checker.seconds_since_heartbeat(), 0);

        // Wait a bit and check again
        sleep(Duration::from_millis(100)).await;
        assert!(checker.is_healthy(60));
        assert!(checker.seconds_since_heartbeat() < 2);
    }
}
