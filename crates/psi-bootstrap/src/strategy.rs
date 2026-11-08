use std::sync::Arc;

use async_trait::async_trait;

use psi_core::EventBus;

use crate::bridge::Bridge;

/// Стратегия подъёма пути к Psiphon.
#[async_trait]
pub trait Strategy: Send + Sync {
    fn tag(&self) -> &str;

    /// Поднимает локальный мост. `None` — стратегия недоступна/не настроена.
    async fn prepare(&self) -> Option<Bridge>;
}

/// Прямой режим: Psiphon сам обходит блокировки.
pub struct DirectStrategy;

#[async_trait]
impl Strategy for DirectStrategy {
    fn tag(&self) -> &str {
        "direct"
    }

    async fn prepare(&self) -> Option<Bridge> {
        Some(Bridge::direct())
    }
}

/// SOCKS-мост поверх psi-dpi.
pub struct DpiStrategy {
    config: psi_config::Dpi,
    bus: EventBus,
}

impl DpiStrategy {
    pub fn new(config: psi_config::Dpi, bus: EventBus) -> Self {
        Self { config, bus }
    }
}

#[async_trait]
impl Strategy for DpiStrategy {
    fn tag(&self) -> &str {
        "dpi"
    }

    async fn prepare(&self) -> Option<Bridge> {
        let outbound = psi_dpi::DpiOutbound::from(&self.config);
        Bridge::socks(self.bus.clone(), move |addr, bus| {
            psi_dpi::serve_socks(addr, outbound, bus)
        })
        .ok()
    }
}

/// SOCKS-мост поверх VLESS-WS-TLS.
pub struct VlessStrategy {
    config: psi_config::Vless,
    bus: EventBus,
}

impl VlessStrategy {
    pub fn new(config: psi_config::Vless, bus: EventBus) -> Self {
        Self { config, bus }
    }
}

#[async_trait]
impl Strategy for VlessStrategy {
    fn tag(&self) -> &str {
        "vless"
    }

    async fn prepare(&self) -> Option<Bridge> {
        let outbound = psi_vless::VlessOutbound::from_config(&self.config).ok()?;
        Bridge::socks(self.bus.clone(), move |addr, bus| {
            psi_vless::serve_socks(addr, outbound, bus)
        })
        .ok()
    }
}

/// SOCKS-мост поверх WARP.
pub struct WarpStrategy {
    config: psi_config::Warp,
    bus: EventBus,
}

impl WarpStrategy {
    pub fn new(config: psi_config::Warp, bus: EventBus) -> Self {
        Self { config, bus }
    }
}

#[async_trait]
impl Strategy for WarpStrategy {
    fn tag(&self) -> &str {
        "warp"
    }

    async fn prepare(&self) -> Option<Bridge> {
        let outbound = psi_warp::WarpOutbound::from_settings(&self.config)
            .await
            .ok()?;
        Bridge::socks(self.bus.clone(), move |addr, bus| {
            psi_warp::serve_socks(addr, outbound, bus)
        })
        .ok()
    }
}

/// Стратегии, для которых есть конфигурация.
pub fn builtin_strategies(config: &psi_config::Config, bus: EventBus) -> Vec<Arc<dyn Strategy>> {
    let mut strategies: Vec<Arc<dyn Strategy>> = vec![
        Arc::new(DirectStrategy),
        Arc::new(DpiStrategy::new(config.dpi.clone(), bus.clone())),
    ];

    if let Some(vless) = &config.vless {
        strategies.push(Arc::new(VlessStrategy::new(vless.clone(), bus.clone())));
    }

    if let Some(warp) = &config.warp {
        strategies.push(Arc::new(WarpStrategy::new(warp.clone(), bus.clone())));
    }

    strategies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_strategy_has_no_upstream() {
        let bridge = DirectStrategy.prepare().await.expect("direct");
        assert_eq!(DirectStrategy.tag(), "direct");
        assert!(bridge.is_direct());
        assert!(bridge.upstream().is_none());
    }

    #[test]
    fn strategies_without_config_are_skipped() {
        let config = psi_config::Config::default();
        let strategies = builtin_strategies(&config, EventBus::new());
        let tags: Vec<&str> = strategies.iter().map(|strategy| strategy.tag()).collect();

        assert_eq!(tags, vec!["direct", "dpi"]);
    }

    #[tokio::test]
    async fn dpi_strategy_starts_socks_bridge() {
        let strategy = DpiStrategy::new(psi_config::Dpi::default(), EventBus::new());
        let bridge = strategy.prepare().await.expect("dpi");

        let upstream = bridge.upstream().expect("socks url");
        assert!(upstream.starts_with("socks5://127.0.0.1:"));
    }
}
