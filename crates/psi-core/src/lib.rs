mod event;
mod inbound;
mod outbound;
mod target;

pub use event::{ConnState, Event, EventBus};
pub use inbound::{Handler, Meta, MixedInbound};
pub use outbound::{BoxFuture, DirectOutbound, Health, Outbound};
pub use target::{AsyncStream, BoxStream, Target};

use thiserror::Error;

/// Общие ошибки сетевого слоя.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("протокол: {0}")]
    Protocol(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
