use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;

use psi_core::Target;

use crate::error::{Result, VlessError};
use crate::outbound::VlessOutbound;
use crate::tls::{build_connector, connect_tls};
use crate::uri::VlessSettings;
use crate::ws::handshake;

pub const DEFAULT_SCAN_PORTS: &[u16] = &[443, 8443, 2053, 2083, 2087, 2096];

/// Найденный рабочий clean IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedIp {
    pub ip: IpAddr,
    pub port: u16,
    pub latency: Duration,
}

/// Перебирает IP из диапазонов, проверяет TCP+TLS+WS и возвращает топ-5 по задержке.
///
/// `n` — максимум проверяемых адресов, параллельность — 32.
pub async fn scan_clean_ips(
    ranges: &[String],
    ports: &[u16],
    n: usize,
    settings: &VlessSettings,
) -> Result<Vec<ScannedIp>> {
    let ips = expand_ranges(ranges, n.max(1))?;
    let ports = if ports.is_empty() {
        DEFAULT_SCAN_PORTS
    } else {
        ports
    };

    let connector = Arc::new(build_connector()?);
    let semaphore = Arc::new(Semaphore::new(32));
    let mut tasks = Vec::new();

    for ip in ips {
        for &port in ports {
            let connector = Arc::clone(&connector);
            let semaphore = Arc::clone(&semaphore);
            let settings = settings.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.ok()?;
                probe(&connector, &settings, ip, port).await
            }));
        }
    }

    let mut results: Vec<ScannedIp> = Vec::new();
    for task in tasks {
        if let Ok(Some(result)) = task.await {
            results.push(result);
        }
    }

    results.sort_by_key(|result| result.latency);
    results.truncate(5);
    Ok(results)
}

fn expand_ranges(ranges: &[String], limit: usize) -> Result<Vec<IpAddr>> {
    let mut ips: Vec<IpAddr> = Vec::new();

    for range in ranges {
        let range = range.trim();
        if range.is_empty() {
            continue;
        }

        if let Ok(ip) = range.parse::<IpAddr>() {
            if ips.len() < limit {
                ips.push(ip);
            }
            continue;
        }

        let network: ipnet::IpNet = range
            .parse()
            .map_err(|_| VlessError::Range(range.to_string()))?;

        for ip in network.hosts() {
            if ips.len() >= limit {
                break;
            }
            ips.push(ip);
        }

        if ips.len() >= limit {
            break;
        }
    }

    Ok(ips)
}

async fn probe(
    connector: &TlsConnector,
    settings: &VlessSettings,
    ip: IpAddr,
    port: u16,
) -> Option<ScannedIp> {
    let started = Instant::now();

    let tls = connect_tls(
        connector,
        &ip.to_string(),
        port,
        &settings.sni,
        Duration::from_secs(5),
    )
    .await
    .ok()?;

    let _websocket = handshake(tls, settings, None).await.ok()?;

    Some(ScannedIp {
        ip,
        port,
        latency: started.elapsed(),
    })
}

/// Тест «16КБ-заморозки» ТСПУ: качает Range 0-131071 с НЕ-Cloudflare хоста.
/// `true` — соединение зависло на малом объёме (IP/канал плохой).
pub async fn detect_tspu_freeze(
    outbound: &VlessOutbound,
    host: &str,
    path: &str,
) -> Result<bool> {
    let target = Target::Domain(host.to_string(), 443);
    let mut stream = outbound.connect_stream(&target).await?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nRange: bytes=0-131071\r\n\
         User-Agent: curl/8.0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut total = 0usize;
    let mut buffer = [0u8; 8192];

    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total += n;
                if total >= 100 * 1024 {
                    return Ok(false);
                }
            }
            Ok(Err(error)) => return Err(VlessError::Io(error)),
            Err(_) => return Ok((16 * 1024..100 * 1024).contains(&total)),
        }
    }

    Ok((16 * 1024..100 * 1024).contains(&total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_cidr_up_to_limit() {
        let ips = expand_ranges(&["192.0.2.0/24".to_string()], 4).expect("ranges");
        assert_eq!(ips.len(), 4);
        assert_eq!(ips[0], "192.0.2.1".parse::<IpAddr>().expect("ip"));
    }

    #[test]
    fn accepts_single_ip() {
        let ips = expand_ranges(&["203.0.113.5".to_string()], 64).expect("ranges");
        assert_eq!(ips, vec!["203.0.113.5".parse::<IpAddr>().expect("ip")]);
    }

    #[test]
    fn rejects_invalid_range() {
        assert!(expand_ranges(&["not-an-ip".to_string()], 64).is_err());
    }
}
