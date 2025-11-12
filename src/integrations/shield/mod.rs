/// Shield LLM integration for security threat analysis
pub mod client;
pub mod handlers;
pub mod models;

pub use client::ShieldClient;
pub use handlers::{SecurityEventHandler, SecurityIncidentResponse};
pub use models::*;
