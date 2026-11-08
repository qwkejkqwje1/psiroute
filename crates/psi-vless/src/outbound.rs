use std::time::Duration;

use async_trait::async_trait;
use tokio::io::DuplexStream;
use tokio_rustls::TlsConnector;

use psi_core::{BoxStream, CoreError, Health, Outbound, Result as CoreResult, Target};

use crate::error::{Result, VlessError};
use crate::tls::{build_connector, connect_tls as connect_tls_stream, TlsClientStream};
use crate::tunnel::run_tunnel;
use crate::uri::VlessSettings;

/// VLESS-WS-TLS outbound с early-data и опциональными clean IP.
#[derive(Clone)]
pub struct VlessOutbound {
    settings: VlessSettings,
    connector: TlsConnector,
    tag: String,
}

impl VlessOutbound {
    pub fn new(settings: VlessSettings) -> Result<Self> {
        Ok(Self {
            settings,
            connector: build_connector()?,
            tag: "vless".to_string(),
        })
    }

    pub fn from_config(config: &psi_config::Vless) -> Result<Self> {
        Self::new(VlessSettings::from_config(config)?)
    }

    pub fn from_uri(uri: &str) -> Result<Self> {
        Self::new(VlessSettings::from_uri(uri)?)
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = tag.into();
        self
    }

    pub fn settings(&self) -> &VlessSettings {
        &self.settings
    }

    /// Открывает TCP-поток через туннель.
    pub(crate) async fn connect_stream(&self, target: &Target) -> Result<DuplexStream> {
        let tls = self.open_tls().await?;

        let (client, server) = tokio::io::duplex(64 * 1024);
        let settings = self.settings.clone();
        let target = target.clone();

        tokio::spawn(async move {
            if let Err(error) = run_tunnel(server, tls, settings, target).await {
                tracing::debug!(target: "psi_vless", "VLESS-туннель закрыт: {error}");
            }
        });

        Ok(client)
    }

    async fn open_tls(&self) -> Result<TlsClientStream> {
        if self.settings.fragment {
            tracing::debug!(
                target: "psi_vless",
                "хук DPI-фрагментации ClientHello активируется на шаге 04"
            );
        }

        let mut last_error = None;

        for (host, port) in self.settings.candidates() {
            match connect_tls_stream(
                &self.connector,
                &host,
                port,
                &self.settings.sni,
                Duration::from_secs(8),
            )
            .await
            {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    tracing::debug!(target: "psi_vless", "{host}:{port} не подошёл: {error}");
                    last_error = Some(error);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| VlessError::NoCandidate(self.settings.server.clone())))
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_tcp(&self, dst: &Target) -> CoreResult<BoxStream> {
        self.connect_stream(dst)
            .await
            .map(|stream| Box::new(stream) as BoxStream)
            .map_err(CoreError::from)
    }

    async fn health(&self) -> Health {
        Health::up(None)
    }
}
