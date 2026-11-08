use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use psi_core::{EventBus, Result as CoreResult};

use crate::error::Result;

/// Локальный SOCKS5-мост, который отдаётся Psiphon как `UpstreamProxyUrl`.
///
/// При уничтожении отменяет фоновую задачу через `CancellationToken`.
pub struct Bridge {
    upstream: Option<String>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Bridge {
    /// Прямой режим: внешнего прокси нет.
    pub fn direct() -> Self {
        Self {
            upstream: None,
            cancel: CancellationToken::new(),
            task: None,
        }
    }

    /// Запускает SOCKS5/HTTP-мост на свободном локальном порту.
    pub fn socks<F, Fut>(bus: EventBus, serve: F) -> Result<Self>
    where
        F: FnOnce(SocketAddr, EventBus) -> Fut + Send + 'static,
        Fut: Future<Output = CoreResult<()>> + Send + 'static,
    {
        let addr = free_local_addr()?;
        let cancel = CancellationToken::new();
        let task = tokio::spawn(async move {
            if let Err(error) = serve(addr, bus).await {
                tracing::debug!(target: "psi_bootstrap", %addr, "мост остановлен: {error}");
            }
        });

        Ok(Self {
            upstream: Some(format!("socks5://{addr}")),
            cancel,
            task: Some(task),
        })
    }

    /// URL для `PsiphonConfig.upstream_proxy_url`.
    pub fn upstream(&self) -> Option<&str> {
        self.upstream.as_deref()
    }

    pub fn is_direct(&self) -> bool {
        self.upstream.is_none()
    }

    /// Останавливает мост.
    pub async fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop();
    }
}

fn free_local_addr() -> Result<SocketAddr> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}
