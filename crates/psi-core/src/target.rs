use std::fmt;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

/// Объект, пригодный для двунаправленного проксирования.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Стрим произвольного типа (TLS, WebSocket, TCP, ...).
pub type BoxStream = Box<dyn AsyncStream>;

/// Цель подключения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Домен и порт.
    Domain(String, u16),
    /// IP-адрес и порт.
    Ip(SocketAddr),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, port) => *port,
            Self::Ip(addr) => addr.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Domain(host, _) => host.clone(),
            Self::Ip(addr) => addr.ip().to_string(),
        }
    }

    /// Строка вида `host:port` (для логов и заголовков).
    pub fn authority(&self) -> String {
        match self {
            Self::Domain(host, port) => format!("{host}:{port}"),
            Self::Ip(addr) => addr.to_string(),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.authority())
    }
}
