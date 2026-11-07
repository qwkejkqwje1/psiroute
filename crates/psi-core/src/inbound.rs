use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{
    copy_bidirectional_with_sizes, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf,
};
use tokio::net::{TcpListener, TcpStream};

use crate::{BoxFuture, BoxStream, CoreError, Event, EventBus, Result, Target};

/// Дополнительная информация о входящем соединении.
#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub peer: SocketAddr,
}

/// Обработчик подключений: выбирает исходящее и возвращает стрим.
pub type Handler = Arc<dyn Fn(Target, Meta) -> BoxFuture<Result<BoxStream>> + Send + Sync>;

/// Смешанный inbound: SOCKS5 и HTTP на одном порту.
pub struct MixedInbound {
    bus: EventBus,
}

impl MixedInbound {
    pub fn new(bus: EventBus) -> Self {
        Self { bus }
    }

    /// Запускает приём соединений. Работает до первой фатальной ошибки accept.
    pub async fn serve(self: Arc<Self>, addr: SocketAddr, handler: Handler) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;

        loop {
            let (stream, peer) = listener.accept().await?;
            let handler = Arc::clone(&handler);
            let bus = self.bus.clone();

            tokio::spawn(async move {
                let meta = Meta { peer };
                if let Err(error) = handle_conn(stream, meta, handler, bus).await {
                    tracing::debug!(%peer, "соединение закрыто: {error}");
                }
            });
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    meta: Meta,
    handler: Handler,
    bus: EventBus,
) -> Result<()> {
    let mut first = [0u8; 1];
    let peeked = stream.peek(&mut first).await?;
    if peeked == 0 {
        return Ok(());
    }

    if first[0] == 0x05 {
        let target = read_socks5_target(&mut stream).await?;
        let remote = handler(target, meta).await?;
        write_socks5_ok(&mut stream).await?;
        relay(stream, remote, bus).await
    } else {
        match read_http_handshake(&mut stream).await? {
            HttpHandshake::Connect(target) => {
                let remote = handler(target, meta).await?;
                stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await?;
                stream.flush().await?;
                relay(stream, remote, bus).await
            }
            HttpHandshake::Plain { target, head } => {
                let mut remote = handler(target, meta).await?;
                remote.write_all(&head).await?;
                remote.flush().await?;
                relay(stream, remote, bus).await
            }
        }
    }
}

async fn relay(client: TcpStream, remote: BoxStream, bus: EventBus) -> Result<()> {
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));

    let mut client = CountingStream::new(client, Arc::clone(&up));
    let mut remote = CountingStream::new(remote, Arc::clone(&down));

    let stats = {
        let bus = bus.clone();
        let up = Arc::clone(&up);
        let down = Arc::clone(&down);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                bus.publish(Event::Stats {
                    up: up.load(Ordering::Relaxed),
                    down: down.load(Ordering::Relaxed),
                });
            }
        })
    };

    let result =
        copy_bidirectional_with_sizes(&mut client, &mut remote, 64 * 1024, 64 * 1024).await;

    stats.abort();
    bus.publish(Event::Stats {
        up: up.load(Ordering::Relaxed),
        down: down.load(Ordering::Relaxed),
    });

    result?;
    Ok(())
}

async fn read_socks5_target(stream: &mut TcpStream) -> Result<Target> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(CoreError::Protocol(format!(
            "SOCKS5: неверная версия {:#x}",
            greeting[0]
        )));
    }

    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        return Err(CoreError::Protocol(
            "SOCKS5: клиент не поддерживает no-auth".to_string(),
        ));
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 0x05 {
        return Err(CoreError::Protocol("SOCKS5: неверная версия запроса".to_string()));
    }
    if request[1] != 0x01 {
        let _ = stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err(CoreError::Protocol(format!(
            "SOCKS5: команда {:#x} не поддерживается",
            request[1]
        )));
    }

    let atyp = request[3];
    let mut data = Vec::new();
    match atyp {
        0x01 => {
            data.resize(4, 0);
            stream.read_exact(&mut data).await?;
        }
        0x04 => {
            data.resize(16, 0);
            stream.read_exact(&mut data).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            data.push(len[0]);
            let mut host = vec![0u8; len[0] as usize];
            stream.read_exact(&mut host).await?;
            data.extend_from_slice(&host);
        }
        _ => {
            let _ = stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(CoreError::Protocol(format!(
                "SOCKS5: неизвестный ATYP {atyp:#x}"
            )));
        }
    }

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    data.extend_from_slice(&port);

    let (target, _) = parse_socks5_address(atyp, &data)?;
    Ok(target)
}

/// Разбирает адрес SOCKS5. `data` начинается сразу после ATYP и включает порт.
fn parse_socks5_address(atyp: u8, data: &[u8]) -> Result<(Target, usize)> {
    match atyp {
        0x01 => {
            if data.len() < 6 {
                return Err(CoreError::Protocol(
                    "SOCKS5: короткий IPv4-адрес".to_string(),
                ));
            }
            let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            let port = u16::from_be_bytes([data[4], data[5]]);
            Ok((Target::Ip(SocketAddr::new(ip.into(), port)), 6))
        }
        0x04 => {
            if data.len() < 18 {
                return Err(CoreError::Protocol(
                    "SOCKS5: короткий IPv6-адрес".to_string(),
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[16], data[17]]);
            Ok((Target::Ip(SocketAddr::new(ip.into(), port)), 18))
        }
        0x03 => {
            if data.is_empty() {
                return Err(CoreError::Protocol(
                    "SOCKS5: пустой домен".to_string(),
                ));
            }
            let len = data[0] as usize;
            if data.len() < 1 + len + 2 {
                return Err(CoreError::Protocol(
                    "SOCKS5: короткий доменный адрес".to_string(),
                ));
            }
            let host = std::str::from_utf8(&data[1..1 + len])
                .map_err(|_| CoreError::Protocol("SOCKS5: домен не в UTF-8".to_string()))?;
            let port = u16::from_be_bytes([data[1 + len], data[2 + len]]);
            Ok((Target::Domain(host.to_string(), port), 1 + len + 2))
        }
        _ => Err(CoreError::Protocol(format!(
            "SOCKS5: неизвестный ATYP {atyp:#x}"
        ))),
    }
}

async fn write_socks5_ok(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await?;
    Ok(())
}

enum HttpHandshake {
    Connect(Target),
    Plain { target: Target, head: Vec<u8> },
}

async fn read_http_handshake(stream: &mut TcpStream) -> Result<HttpHandshake> {
    let head = read_until_headers_end(stream).await?;
    let text = std::str::from_utf8(&head)
        .map_err(|_| CoreError::Protocol("HTTP: заголовки не в UTF-8".to_string()))?;

    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| CoreError::Protocol("HTTP: пустой запрос".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| CoreError::Protocol("HTTP: нет метода".to_string()))?;
    let uri = parts
        .next()
        .ok_or_else(|| CoreError::Protocol("HTTP: нет URI".to_string()))?;
    let version = parts.next().unwrap_or("HTTP/1.1");
    let headers: Vec<String> = lines
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_authority(uri)?;
        return Ok(HttpHandshake::Connect(host_port_target(host, port)));
    }

    let (target, path) = if let Some(rest) = uri.strip_prefix("http://") {
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let (host, port) = parse_authority_or_default(authority, 80)?;
        (host_port_target(host, port), path.to_string())
    } else if uri.starts_with('/') {
        let host_header = headers
            .iter()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.trim().eq_ignore_ascii_case("host") {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| CoreError::Protocol("HTTP: нет заголовка Host".to_string()))?;
        let (host, port) = parse_authority_or_default(&host_header, 80)?;
        (host_port_target(host, port), uri.to_string())
    } else {
        return Err(CoreError::Protocol(format!(
            "HTTP: неподдерживаемый URI {uri}"
        )));
    };

    let mut rebuilt = String::new();
    rebuilt.push_str(method);
    rebuilt.push(' ');
    rebuilt.push_str(&path);
    rebuilt.push(' ');
    rebuilt.push_str(version);
    rebuilt.push_str("\r\n");
    for line in &headers {
        let name = line
            .split_once(':')
            .map(|(name, _)| name.trim())
            .unwrap_or("");
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    rebuilt.push_str("Connection: close\r\n\r\n");

    Ok(HttpHandshake::Plain {
        target,
        head: rebuilt.into_bytes(),
    })
}

async fn read_until_headers_end(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];

    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(CoreError::Protocol(
                "HTTP: соединение закрыто до конца заголовков".to_string(),
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > 64 * 1024 {
            return Err(CoreError::Protocol(
                "HTTP: заголовки слишком большие".to_string(),
            ));
        }
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| CoreError::Protocol(format!("HTTP: неверный адрес {authority}")))?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| CoreError::Protocol(format!("HTTP: нет порта в {authority}")))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| CoreError::Protocol(format!("HTTP: неверный порт в {authority}")))?;
        Ok((host.to_string(), port))
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| CoreError::Protocol(format!("HTTP: нет порта в {authority}")))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| CoreError::Protocol(format!("HTTP: неверный порт в {authority}")))?;
        Ok((host.to_string(), port))
    }
}

fn parse_authority_or_default(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if authority.starts_with('[') {
        return parse_authority(authority);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => {
            let port = port
                .parse::<u16>()
                .map_err(|_| CoreError::Protocol(format!("HTTP: неверный порт в {authority}")))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((authority.to_string(), default_port)),
    }
}

fn host_port_target(host: String, port: u16) -> Target {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Target::Ip(SocketAddr::new(ip, port)),
        Err(_) => Target::Domain(host, port),
    }
}

/// Стрим с подсчётом прочитанных байт.
struct CountingStream<S> {
    inner: S,
    counter: Arc<AtomicU64>,
}

impl<S> CountingStream<S> {
    fn new(inner: S, counter: Arc<AtomicU64>) -> Self {
        Self { inner, counter }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();

        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len().saturating_sub(before);
                this.counter.fetch_add(read as u64, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socks5_ipv4_request() {
        let data = [93, 184, 216, 34, 0x01, 0xbb];
        let (target, used) = parse_socks5_address(0x01, &data).expect("IPv4");

        assert_eq!(
            target,
            Target::Ip("93.184.216.34:443".parse().expect("адрес"))
        );
        assert_eq!(used, 6);
    }

    #[test]
    fn parses_socks5_domain_request() {
        let mut data = vec![11u8];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x00, 0x50]);

        let (target, used) = parse_socks5_address(0x03, &data).expect("домен");

        assert_eq!(target, Target::Domain("example.com".to_string(), 80));
        assert_eq!(used, data.len());
    }
}
