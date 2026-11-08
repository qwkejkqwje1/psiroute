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

/// Цепочка запасных выходов: пробует по очереди, пока один не соединится.
/// Так действие «proxy» остаётся рабочим, даже если главный выход не настроен:
/// Psiphon → VLESS → WARP → DPI-фрагментация.
pub struct FallbackOutbound {
    chain: Vec<Arc<dyn Outbound>>,
}

impl FallbackOutbound {
    pub fn new(chain: Vec<Arc<dyn Outbound>>) -> Self {
        Self { chain }
    }

}

#[async_trait]
impl Outbound for FallbackOutbound {
    fn tag(&self) -> &str {
        "proxy"
    }

    async fn connect_tcp(&self, dst: &Target) -> Result<BoxStream> {
        let mut last_error = CoreError::Other("пустая цепочка выходов".into());
        for outbound in &self.chain {
            match outbound.connect_tcp(dst).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn health(&self) -> Health {
        for outbound in &self.chain {
            let health = outbound.health().await;
            if health.ok {
                return health;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    struct OkOutbound;

    #[async_trait]
    impl Outbound for OkOutbound {
        fn tag(&self) -> &str {
            "ok"
        }

        async fn connect_tcp(&self, _dst: &Target) -> Result<BoxStream> {
            let (stream, _peer) = tokio::io::duplex(1024);
            Ok(Box::new(stream) as BoxStream)
        }

        async fn health(&self) -> Health {
            Health::up(Some(5))
        }
    }

    #[tokio::test]
    async fn fallback_skips_failing_and_uses_next() {
        let chain = FallbackOutbound::new(vec![
            Arc::new(ErrorOutbound::new("a", "первый мёртв")),
            Arc::new(OkOutbound),
        ]);
        let target = Target::Domain("example.com".to_string(), 443);
        assert!(chain.connect_tcp(&target).await.is_ok());
        assert!(chain.health().await.ok);
    }

    #[tokio::test]
    async fn fallback_returns_last_error() {
        let chain = FallbackOutbound::new(vec![
            Arc::new(ErrorOutbound::new("a", "первый мёртв")),
            Arc::new(ErrorOutbound::new("b", "второй мёртв")),
        ]);
        let target = Target::Domain("example.com".to_string(), 443);
        let error = chain
            .connect_tcp(&target)
            .await
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(error.contains("второй мёртв"), "got: {error}");
    }
}
