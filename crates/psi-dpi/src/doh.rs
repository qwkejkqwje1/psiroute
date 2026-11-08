use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use url::Url;

use psi_core::Target;

use crate::outbound::DpiOutbound;
use crate::{DpiError, Result};

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_CACHE_TTL: Duration = Duration::from_secs(300);
const DOH_TIMEOUT: Duration = Duration::from_secs(10);

pub fn default_doh_servers() -> Vec<String> {
    vec![
        "https://cloudflare-dns.com/dns-query".to_string(),
        "https://dns.google/dns-query".to_string(),
        "https://dns.quad9.net/dns-query".to_string(),
    ]
}

#[derive(Debug, Clone)]
struct DohServer {
    host: String,
    port: u16,
    path: String,
    bootstrap: Vec<SocketAddr>,
}

impl DohServer {
    fn parse(raw: &str) -> Result<Self> {
        let url = Url::parse(raw).map_err(|error| DpiError::Url(error.to_string()))?;
        if url.scheme() != "https" {
            return Err(DpiError::Url(format!("DoH должен быть https: {raw}")));
        }

        let host = url
            .host_str()
            .ok_or_else(|| DpiError::Url(format!("нет хоста в {raw}")))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let path = if url.path().is_empty() {
            "/dns-query".to_string()
        } else {
            match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().to_string(),
            }
        };

        let bootstrap = bootstrap_addrs(&host, port)
            .ok_or_else(|| DpiError::Url(format!("нет bootstrap-IP для DoH-хоста {host}")))?;

        Ok(Self {
            host,
            port,
            path,
            bootstrap,
        })
    }
}

fn bootstrap_addrs(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let addresses: Vec<IpAddr> = match host {
        "cloudflare-dns.com" | "1dot1dot1dot1.cloudflare-dns.com" => {
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))]
        }
        "dns.google" => vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        ],
        "dns.quad9.net" => vec![
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
        ],
        other => vec![other.parse::<IpAddr>().ok()?],
    };

    Some(
        addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect(),
    )
}

/// DoH-резолвер с кэшем и гонкой серверов; запросы идут через `DpiOutbound`.
pub struct DohResolver {
    servers: Vec<DohServer>,
    outbound: DpiOutbound,
    cache: Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>,
}

impl DohResolver {
    pub fn new(urls: &[String]) -> Result<Self> {
        Self::with_outbound(urls, DpiOutbound::default())
    }

    pub fn with_outbound(urls: &[String], outbound: DpiOutbound) -> Result<Self> {
        let mut servers = Vec::new();
        for raw in urls {
            match DohServer::parse(raw) {
                Ok(server) => servers.push(server),
                Err(error) => tracing::warn!(%error, url = %raw, "DoH-сервер пропущен"),
            }
        }

        if servers.is_empty() {
            return Err(DpiError::NoDohServers);
        }

        Ok(Self {
            servers,
            outbound,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn from_config(config: &psi_config::Dpi) -> Result<Self> {
        let urls = if config.doh.is_empty() {
            default_doh_servers()
        } else {
            config.doh.clone()
        };
        Self::new(&urls)
    }

    pub async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();

        if let Ok(address) = name.parse::<IpAddr>() {
            return Ok(vec![address]);
        }

        {
            let cache = self.cache.lock().await;
            if let Some((expires, addresses)) = cache.get(&name) {
                if *expires > Instant::now() {
                    return Ok(addresses.clone());
                }
            }
        }

        let message = self.query_all(&name).await?;
        let mut addresses = Vec::new();
        let mut ttl = DEFAULT_CACHE_TTL;

        for answer in message.answers() {
            match answer.data() {
                Some(RData::A(address)) => addresses.push(IpAddr::V4(address.0)),
                Some(RData::AAAA(address)) => addresses.push(IpAddr::V6(address.0)),
                _ => {}
            }
            ttl = ttl.min(Duration::from_secs(u64::from(answer.ttl())).min(MAX_CACHE_TTL));
        }

        if addresses.is_empty() {
            return Err(DpiError::Resolve {
                name,
                reason: "нет записей A/AAAA".to_string(),
            });
        }

        let mut cache = self.cache.lock().await;
        cache.insert(name, (Instant::now() + ttl, addresses.clone()));

        Ok(addresses)
    }

    pub async fn resolve_socket(&self, name: &str, port: u16) -> Result<SocketAddr> {
        let address = self
            .resolve(name)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| DpiError::Resolve {
                name: name.to_string(),
                reason: "пустой список адресов".to_string(),
            })?;
        Ok(SocketAddr::new(address, port))
    }

    async fn query_all(&self, name: &str) -> Result<Message> {
        let mut pending: Vec<Pin<Box<dyn Future<Output = Result<Message>> + Send>>> = self
            .servers
            .iter()
            .cloned()
            .map(|server| {
                let outbound = self.outbound.clone();
                let name = name.to_string();
                Box::pin(async move { query_server(&server, &outbound, &name).await })
                    as Pin<Box<dyn Future<Output = Result<Message>> + Send>>
            })
            .collect();

        let mut last_error = None;

        while !pending.is_empty() {
            let (result, _index, rest) = futures::future::select_all(pending).await;
            pending = rest;

            match result {
                Ok(message) => return Ok(message),
                Err(error) => {
                    tracing::debug!(%error, "DoH-сервер не ответил");
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or(DpiError::NoDohServers))
    }
}

async fn query_server(server: &DohServer, outbound: &DpiOutbound, name: &str) -> Result<Message> {
    let mut merged = Message::new();
    merged.set_message_type(MessageType::Response);
    merged.set_op_code(OpCode::Query);
    merged.set_recursion_desired(true);

    let mut answered = false;

    for record_type in [RecordType::A, RecordType::AAAA] {
        let request = build_request(name, record_type)?;
        let body = request
            .to_vec()
            .map_err(|error| DpiError::Doh(error.to_string()))?;
        let bytes = doh_post(server, outbound, body).await?;
        let response =
            Message::from_vec(&bytes).map_err(|error| DpiError::Doh(error.to_string()))?;

        if response.response_code() != ResponseCode::NoError {
            continue;
        }

        for answer in response.answers() {
            merged.add_answer(answer.clone());
            answered = true;
        }
    }

    if !answered {
        return Err(DpiError::Resolve {
            name: name.to_string(),
            reason: "пустой ответ DoH".to_string(),
        });
    }

    Ok(merged)
}

fn build_request(name: &str, record_type: RecordType) -> Result<Message> {
    let fqdn = Name::from_ascii(name).map_err(|error| DpiError::Doh(error.to_string()))?;

    let mut message = Message::new();
    message.set_id(pseudo_random_id());
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(fqdn);
    query.set_query_type(record_type);
    query.set_query_class(DNSClass::IN);
    message.add_query(query);

    Ok(message)
}

fn pseudo_random_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    (nanos & 0xffff) as u16
}

async fn doh_post(server: &DohServer, outbound: &DpiOutbound, body: Vec<u8>) -> Result<Vec<u8>> {
    let connector = h2_connector()?;
    let mut last_error = None;

    for address in &server.bootstrap {
        let stream = match outbound.connect_stream(&Target::Ip(*address)).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };

        let server_name = ServerName::try_from(server.host.clone())
            .map_err(|error| DpiError::Tls(error.to_string()))?;

        let tls = match tokio::time::timeout(
            DOH_TIMEOUT,
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(tls)) => tls,
            Ok(Err(error)) => {
                last_error = Some(DpiError::Io(error));
                continue;
            }
            Err(_) => {
                last_error = Some(DpiError::Tls(format!(
                    "таймаут TLS к {}:{}",
                    server.host, server.port
                )));
                continue;
            }
        };

        match doh_h2_request(tls, server, body.clone()).await {
            Ok(bytes) => return Ok(bytes),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or(DpiError::NoDohServers))
}

async fn doh_h2_request<S>(tls: S, server: &DohServer, body: Vec<u8>) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, connection) = h2::client::handshake(tls)
        .await
        .map_err(|error| DpiError::Http2(error.to_string()))?;

    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "h2-соединение DoH завершено");
        }
    });

    let authority = if server.port == 443 {
        server.host.clone()
    } else {
        format!("{}:{}", server.host, server.port)
    };
    let uri = format!("https://{authority}{}", server.path);

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(|error| DpiError::Http2(error.to_string()))?;

    let (response, mut send) = client
        .send_request(request, false)
        .map_err(|error| DpiError::Http2(error.to_string()))?;

    send.send_data(bytes::Bytes::from(body), true)
        .map_err(|error| DpiError::Http2(error.to_string()))?;

    let response = tokio::time::timeout(DOH_TIMEOUT, response)
        .await
        .map_err(|_| DpiError::Doh("таймаут ответа DoH".to_string()))?
        .map_err(|error| DpiError::Http2(error.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(DpiError::Doh(format!("DoH вернул HTTP {status}")));
    }

    let mut receive = response.into_body();
    let mut output = Vec::new();

    while let Some(chunk) = receive.data().await {
        let chunk = chunk.map_err(|error| DpiError::Http2(error.to_string()))?;
        let _ = receive.flow_control().release_capacity(chunk.len());
        output.extend_from_slice(&chunk);
    }

    Ok(output)
}

fn h2_connector() -> Result<TlsConnector> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

    if let Some(config) = CONFIG.get() {
        return Ok(TlsConnector::from(config.clone()));
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let config = Arc::new(config);
    let _ = CONFIG.set(config.clone());

    Ok(TlsConnector::from(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_servers_with_bootstrap() {
        let server = DohServer::parse("https://cloudflare-dns.com/dns-query").expect("server");
        assert_eq!(server.host, "cloudflare-dns.com");
        assert_eq!(server.port, 443);
        assert_eq!(server.path, "/dns-query");
        assert_eq!(server.bootstrap.len(), 2);
    }

    #[test]
    fn rejects_plain_http() {
        assert!(DohServer::parse("http://dns.google/dns-query").is_err());
    }

    #[test]
    fn builds_dns_query() {
        let message = build_request("example.com", RecordType::A).expect("query");
        assert_eq!(message.queries().len(), 1);
        assert_eq!(message.queries()[0].query_type(), RecordType::A);
    }
}
