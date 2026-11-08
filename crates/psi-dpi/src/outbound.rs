use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use psi_core::{BoxStream, Health, Outbound, Result as CoreResult, Target};

use crate::parse::{analyze, PayloadKind};
use crate::strategy::{build_first_flight, FirstFlight, Segment, StrategyPlan};
use crate::{oob, DpiError, Result};

const FIRST_WRITE_TIMEOUT: Duration = Duration::from_millis(200);
const READ_GAP_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_INITIAL_BUFFER: usize = 16 * 1024;
const RELAY_BUFFER: usize = 64 * 1024;

/// TCP-исходящее, которое переписывает первый клиентский пакет для обхода DPI.
#[derive(Debug, Clone)]
pub struct DpiOutbound {
    plan: StrategyPlan,
    tag: String,
    connect_timeout: Duration,
}

impl DpiOutbound {
    pub fn new(plan: StrategyPlan) -> Self {
        Self {
            plan,
            tag: "dpi".to_string(),
            connect_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = tag.into();
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn plan(&self) -> &StrategyPlan {
        &self.plan
    }

    /// TCP-соединение с перехватом первой записи. Возвращает клиентскую половину duplex.
    pub async fn connect_stream(&self, dst: &Target) -> Result<tokio::io::DuplexStream> {
        let addr = self.resolve(dst).await?;

        let tcp = tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                DpiError::Other(format!(
                    "таймаут подключения к {addr} ({} с)",
                    self.connect_timeout.as_secs()
                ))
            })??;
        tcp.set_nodelay(true)?;

        let (client, server) = tokio::io::duplex(RELAY_BUFFER);
        let plan = self.plan.clone();

        tokio::spawn(async move {
            if let Err(error) = run_dpi(server, tcp, plan).await {
                tracing::debug!(%error, "DPI-туннель завершён с ошибкой");
            }
        });

        Ok(client)
    }

    async fn resolve(&self, dst: &Target) -> Result<SocketAddr> {
        match dst {
            Target::Ip(addr) => Ok(*addr),
            Target::Domain(host, port) => {
                let mut addrs = tokio::net::lookup_host((host.as_str(), *port)).await?;
                addrs.next().ok_or_else(|| DpiError::Resolve {
                    name: host.clone(),
                    reason: "DNS вернул пустой список".to_string(),
                })
            }
        }
    }
}

impl Default for DpiOutbound {
    fn default() -> Self {
        Self::new(StrategyPlan::default_plan())
    }
}

impl From<&psi_config::Dpi> for DpiOutbound {
    fn from(config: &psi_config::Dpi) -> Self {
        Self::new(StrategyPlan::from_config(config))
    }
}

#[async_trait]
impl Outbound for DpiOutbound {
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

async fn run_dpi(
    mut client: tokio::io::DuplexStream,
    mut tcp: TcpStream,
    plan: StrategyPlan,
) -> Result<()> {
    match read_first_write(&mut client).await? {
        Some(buffer) => {
            let flight = build_first_flight(&buffer, &plan)?;
            send_flight(&mut tcp, &flight).await?;
        }
        None => {
            return Ok(());
        }
    }

    tokio::io::copy_bidirectional(&mut client, &mut tcp).await?;
    Ok(())
}

async fn read_first_write(client: &mut tokio::io::DuplexStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut buffer = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    let first_deadline = tokio::time::Instant::now() + FIRST_WRITE_TIMEOUT;

    loop {
        let wait = if buffer.is_empty() {
            first_deadline.saturating_duration_since(tokio::time::Instant::now())
        } else {
            READ_GAP_TIMEOUT
        };

        if buffer.is_empty() && wait.is_zero() {
            return Ok(None);
        }

        match tokio::time::timeout(wait, client.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(buffer));
            }
            Ok(Ok(read)) => {
                buffer.extend_from_slice(&chunk[..read]);
                if ready_to_split(&buffer) || buffer.len() >= MAX_INITIAL_BUFFER {
                    return Ok(Some(buffer));
                }
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(buffer));
            }
        }
    }
}

fn ready_to_split(buffer: &[u8]) -> bool {
    match analyze(buffer) {
        PayloadKind::Tls { record_len, .. } => buffer.len() >= record_len + 5,
        PayloadKind::Http { .. } => buffer
            .windows(4)
            .any(|window| window == b"\r\n\r\n"),
        PayloadKind::Other => false,
    }
}

async fn send_flight(tcp: &mut TcpStream, flight: &FirstFlight) -> std::io::Result<()> {
    let original_ttl = socket2::SockRef::from(&*tcp).ttl().ok();

    for (index, segment) in flight.segments.iter().enumerate() {
        write_segment(tcp, segment, original_ttl).await?;

        if segment.delay_ms > 0 && index + 1 < flight.segments.len() {
            tokio::time::sleep(Duration::from_millis(segment.delay_ms)).await;
        }
    }

    Ok(())
}

async fn write_segment(
    tcp: &mut TcpStream,
    segment: &Segment,
    original_ttl: Option<u32>,
) -> std::io::Result<()> {
    if let Some(ttl) = segment.ttl {
        let _ = socket2::SockRef::from(&*tcp).set_ttl(u32::from(ttl));
    }

    tcp.write_all(&segment.data).await?;
    tcp.flush().await?;

    if segment.ttl.is_some() {
        if let Some(ttl) = original_ttl {
            let _ = socket2::SockRef::from(&*tcp).set_ttl(ttl);
        }
    }

    if segment.oob {
        if let Err(error) = oob::send_oob(tcp, b'*') {
            tracing::debug!(%error, "не удалось отправить OOB-байт");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::{SplitAt, Strategy};

    #[tokio::test]
    async fn connects_through_dpi_outbound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.expect("read");
            buffer
        });

        let outbound = DpiOutbound::new(StrategyPlan::new(vec![Strategy::Split(
            SplitAt::Fixed(2),
        )]));
        let mut stream = outbound
            .connect_stream(&Target::Ip(addr))
            .await
            .expect("connect");
        stream.write_all(b"ping").await.expect("write");
        stream.flush().await.expect("flush");

        let received = server.await.expect("server");
        assert_eq!(&received, b"ping");
        assert_eq!(outbound.tag(), "dpi");
    }
}
