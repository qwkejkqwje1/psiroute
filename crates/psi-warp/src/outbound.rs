use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use smoltcp::wire::{IpAddress, IpEndpoint};
use tokio::io::DuplexStream;

use psi_core::{BoxStream, Health, Outbound, Result as CoreResult, Target};

use crate::junk::JunkConfig;
use crate::net::WarpStack;
use crate::register::WarpRegistration;
use crate::{Result, WarpError};

/// Исходящее через WARP: smoltcp TCP поверх WireGuard-туннеля.
pub struct WarpOutbound {
    stack: Arc<WarpStack>,
    tag: String,
}

impl WarpOutbound {
    pub async fn new(registration: &WarpRegistration, junk: JunkConfig) -> Result<Self> {
        let stack = WarpStack::start(registration, junk).await?;
        Ok(Self {
            stack: Arc::new(stack),
            tag: "warp".to_string(),
        })
    }

    pub async fn from_settings(config: &psi_config::Warp) -> Result<Self> {
        let registration = WarpRegistration {
            private_key: config.private_key.clone(),
            peer_public_key: config.peer_public_key.clone(),
            address_v4: config.address_v4.clone(),
            address_v6: config.address_v6.clone(),
            reserved: config.reserved,
            endpoint: config.endpoint.clone(),
            client_id: String::new(),
        };
        let junk = JunkConfig::from_awg(&config.awg)?;
        Self::new(&registration, junk).await
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = tag.into();
        self
    }

    pub async fn connect_stream(&self, dst: &Target) -> Result<DuplexStream> {
        let remote = match dst {
            Target::Ip(address) => IpEndpoint::new(to_smoltcp(address.ip()), address.port()),
            Target::Domain(host, port) => {
                let address = self
                    .stack
                    .resolve(host)
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| WarpError::Net(format!("DNS не вернул адрес для {host}")))?;
                IpEndpoint::new(to_smoltcp(address), *port)
            }
        };

        self.stack.connect(remote).await
    }
}

#[async_trait]
impl Outbound for WarpOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_tcp(&self, dst: &Target) -> CoreResult<BoxStream> {
        let stream = self.connect_stream(dst).await?;
        Ok(Box::new(stream))
    }

    async fn health(&self) -> Health {
        Health::up(None)
    }
}

fn to_smoltcp(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => IpAddress::Ipv4(address),
        IpAddr::V6(address) => IpAddress::Ipv6(address),
    }
}
