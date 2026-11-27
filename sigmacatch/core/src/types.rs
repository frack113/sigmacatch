// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Input/runner contract and re-exports of the exchange data model.
//!
//! The data models that cross autonomous boundaries live in [`crate::exchange`]
//! so that inputs, the detection engine, and outputs depend on a narrow,
//! stable waist. This module keeps the async [`EventProducer`] trait and
//! [`ProducerError`], which are part of the input↔runner contract.
//!
//! # Example
//!
//! ```rust
//! use sigmacatch::types::{Event, Alert, Product, EventProducer};
//! use serde_json::json;
//! use uuid::Uuid;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let event = Event::new(json!({"event_id": 4624}), json!({"event_id": 4624}), b"raw".to_vec());
//! let alert = Alert {
//!     rule_id: Uuid::new_v4(),
//!     rule_title: "Test Rule".into(),
//!     description: None,
//!     rule_path: None,
//!     severity: "medium".into(),
//!     event_json_raw: std::sync::Arc::new(json!({"event_id": 4624})),
//!     event_json: std::sync::Arc::new(json!({"event_id": 4624})),
//!     event_raw: std::sync::Arc::new(b"raw".to_vec()),
//!     event_json_raw_all: None,
//! };
//! assert_eq!(Product::Windows.as_str(), "windows");
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};

// Data models that cross autonomous boundaries are defined in `exchange`.
pub use crate::exchange::{
    Alert, CATEGORY_CHANNELS, CHANNEL_TO_SERVICE, Event, PROVIDER_TO_CHANNEL, ParseError, Product,
    RegressionHeader, SERVICE_CHANNELS,
};

/// Errors raised by an [`EventProducer`] while collecting events.
#[derive(Debug, thiserror::Error)]
pub enum ProducerError {
    /// A collection failure wrapping the underlying source error.
    #[error(transparent)]
    Collector(Box<dyn std::error::Error + Send + Sync>),
    /// A collection failure described only by a message.
    #[error("{0}")]
    Message(String),
}

/// Trait for async event producers that send events into a channel.
///
/// Implementors collect events from a source and send them into the provided
/// `mpsc::Sender<Event>`. When collection is complete, the sender is dropped
/// automatically. The producer must exit promptly when `stop` is set.
#[async_trait]
pub trait EventProducer: Send {
    /// Run the producer, sending collected events into `tx`.
    /// Stops when `stop` is set to `true` or when the receiver is dropped.
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError>;
}
