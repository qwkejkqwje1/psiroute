use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::{BoxStream, CoreError, Result, Target};

/// Боксованный `Send`-фьючер.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Результат проверки здоровья исходящего.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Health {
    pub ok: bool,
    pub latency_ms: Option<u64>,
}

impl Health {
    pub fn up(latency_ms: Option<u64>) -> Self {
        Self {
            ok: true,
            latency_ms,
        }
    }

    pub fn down() -> Self {
        Self {
            ok: false,
            latency_ms: None,
        }
    }
}

/// Исходящее подключение (DIRECT, Psiphon, VLESS, WARP, ...).
#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;

    async fn connect_tcp(&self, dst: &Target) -> Result<BoxStream>;

    async fn health(&self) -> Health;
}

/// Прямое TCP-подключение.
#[derive(Debug, Clone)]
pub struct DirectOutbound {
    tag: String,
    bind_iface: Option<u32>,
    connect_timeout: Duration,
}

impl DirectOutbound {
    pub fn new() -> Self {
        Self {
            tag: "direct".to_string(),
            bind_iface: None,
            connect_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = tag.into();
        self
    }

    /// Привязка исходящих сокетов к физическому интерфейсу (пока no-op).
    pub fn with_bind_iface(mut self, iface: u32) -> Self {
        self.bind_iface = Some(iface);
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    async fn resolve(&self, dst: &Target) -> Result<SocketAddr> {
        match dst {
            Target::Ip(addr) => Ok(*addr),
            Target::Domain(host, port) => {
                let mut addrs = tokio::net::lookup_host((host.as_str(), *port)).await?;
                addrs.next().ok_or_else(|| {
                    CoreError::Other(format!("DNS не вернул адрес для {host}:{port}"))
                })
            }
        }
    }
}

impl Default for DirectOutbound {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_tcp(&self, dst: &Target) -> Result<BoxStream> {
        // Привязка к интерфейсу появится на шаге TUN/петель.
        let _ = self.bind_iface;

        let addr = self.resolve(dst).await?;
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                CoreError::Other(format!(
                    "таймаут подключения к {addr} ({} с)",
                    self.connect_timeout.as_secs()
                ))
            })??;

        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }

    async fn health(&self) -> Health {
        Health::up(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_connects_to_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let outbound = DirectOutbound::new();
        let stream = outbound
            .connect_tcp(&Target::Ip(addr))
            .await
            .expect("connect");
        drop(stream);

        accept.await.expect("accept");
        assert_eq!(outbound.tag(), "direct");
        assert!(outbound.health().await.ok);
    }
}
