use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{Result, VlessError};

pub type TlsClientStream = TlsStream<TcpStream>;

/// Клиентский TLS-конфиг: системные корни Mozilla (webpki-roots), ALPN `http/1.1`.
pub fn build_connector() -> Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsConnector::from(Arc::new(config)))
}

pub async fn connect_tls(
    connector: &TlsConnector,
    host: &str,
    port: u16,
    sni: &str,
    timeout: Duration,
) -> Result<TlsClientStream> {
    let attempt = async {
        let tcp = TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;

        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|error| VlessError::Tls(format!("некорректный SNI {sni}: {error}")))?;

        connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| VlessError::Tls(format!("{host}:{port}: {error}")))
    };

    tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_| VlessError::Tls(format!("таймаут TLS {host}:{port}")))?
}
