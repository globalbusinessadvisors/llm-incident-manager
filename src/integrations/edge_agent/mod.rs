/// Edge-Agent LLM integration for local inference with bidirectional streaming
pub mod client;
pub mod handlers;
pub mod models;
pub mod stream;

pub use client::EdgeAgentClient;
pub use handlers::{EdgeInferenceHandler, ResourceAwarePrioritizer};
pub use models::*;
pub use stream::{StreamCoordinator, StreamHealthChecker, StreamManager};
