use std::net::SocketAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use psi_core::{socks5_connect, BoxStream, Health, Outbound, Result, Target};

/// Исходящее через локальный SOCKS5-порт Psiphon.
#[derive(Debug, Clone)]
pub struct PsiphonOutbound {
    tag: String,
    socks_addr: SocketAddr,
}

impl PsiphonOutbound {
    pub fn new(tag: impl Into<String>, socks_addr: SocketAddr) -> Self {
        Self {
            tag: tag.into(),
            socks_addr,
        }
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }
}

#[async_trait]
impl Outbound for PsiphonOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_tcp(&self, dst: &Target) -> Result<BoxStream> {
        socks5_connect(self.socks_addr, dst).await
    }

    async fn health(&self) -> Health {
        let started = Instant::now();
        match tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(self.socks_addr),
        )
        .await
        {
            Ok(Ok(_)) => Health::up(Some(started.elapsed().as_millis() as u64)),
            _ => Health::down(),
        }
    }
}
