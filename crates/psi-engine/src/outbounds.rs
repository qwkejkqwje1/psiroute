use std::sync::Arc;

use async_trait::async_trait;

use psi_core::{BoxStream, CoreError, Health, Outbound, Result, Target};
use psi_router::Action;

/// Исходящее, которое всегда отвечает ошибкой (не настроено / заблокировано).
pub struct ErrorOutbound {
    tag: String,
    message: String,
}

impl ErrorOutbound {
    pub fn new(tag: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            message: message.into(),
        }
    }
}

#[async_trait]
impl Outbound for ErrorOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_tcp(&self, dst: &Target) -> Result<BoxStream> {
        Err(CoreError::Other(format!("{}: {}", self.message, dst)))
    }

    async fn health(&self) -> Health {
        Health::down()
    }
}

/// Набор исходящих по действиям роутера.
pub struct OutboundSet {
    pub direct: Arc<dyn Outbound>,
    pub dpi: Arc<dyn Outbound>,
    pub psiphon: Arc<dyn Outbound>,
    pub vless: Arc<dyn Outbound>,
    pub warp: Arc<dyn Outbound>,
    pub block: Arc<dyn Outbound>,
}

impl OutboundSet {
    pub fn disconnected() -> Self {
        let stub = |tag: &str| -> Arc<dyn Outbound> {
            Arc::new(ErrorOutbound::new(tag, "движок не подключён"))
        };
        Self {
            direct: Arc::new(psi_core::DirectOutbound::new()),
            dpi: stub("dpi"),
            psiphon: stub("psiphon"),
            vless: stub("vless"),
            warp: stub("warp"),
            block: Arc::new(ErrorOutbound::new("block", "заблокировано правилом")),
        }
    }

    pub fn get(&self, action: Action) -> Arc<dyn Outbound> {
        match action {
            Action::Direct => Arc::clone(&self.direct),
            Action::Dpi => Arc::clone(&self.dpi),
            Action::Psiphon => Arc::clone(&self.psiphon),
            Action::Vless => Arc::clone(&self.vless),
            Action::Warp => Arc::clone(&self.warp),
            Action::Block => Arc::clone(&self.block),
        }
    }
}
