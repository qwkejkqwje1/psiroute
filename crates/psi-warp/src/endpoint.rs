use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::Tunn;
use futures::StreamExt;
use rand::seq::SliceRandom;
use rand::Rng;
use tokio::net::UdpSocket;

use crate::junk::JunkConfig;
use crate::keys::{public_from_base64, KeyPair};
use crate::register::WarpRegistration;
use crate::transport::inject_reserved;
use crate::{Result, WarpError};

pub const ENDPOINT_NETWORKS: &[&str] = &[
    "162.159.192.0",
    "162.159.193.0",
    "162.159.195.0",
    "188.114.96.0",
    "188.114.97.0",
    "188.114.98.0",
    "188.114.99.0",
];

pub const ENDPOINT_PORTS: &[u16] = &[
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955,
    968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506,
    3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
    8742, 8854, 8886,
];

#[derive(Debug, Clone)]
pub struct EndpointResult {
    pub endpoint: SocketAddr,
    pub rtt: Duration,
}

pub fn expand_networks() -> Vec<Ipv4Addr> {
    let mut addresses = Vec::with_capacity(ENDPOINT_NETWORKS.len() * 256);
    for network in ENDPOINT_NETWORKS {
        let base: Ipv4Addr = match network.parse() {
            Ok(address) => address,
            Err(_) => continue,
        };
        let octets = base.octets();
        for last in 0..=255u8 {
            addresses.push(Ipv4Addr::new(octets[0], octets[1], octets[2], last));
        }
    }
    addresses
}

/// Стандартный скан: 200 случайных пар, 50 параллельно, топ-3.
pub async fn scan(
    registration: &WarpRegistration,
    junk: &JunkConfig,
) -> Result<Vec<EndpointResult>> {
    scan_endpoints(registration, junk, 200, 50).await
}

/// Перебирает случайные пары IP:порт и возвращает топ-3 по RTT.
pub async fn scan_endpoints(
    registration: &WarpRegistration,
    junk: &JunkConfig,
    count: usize,
    concurrency: usize,
) -> Result<Vec<EndpointResult>> {
    let addresses = expand_networks();
    if addresses.is_empty() {
        return Err(WarpError::Endpoint("нет подсетей WARP".to_string()));
    }

    let registration = Arc::new(registration.clone());
    let junk = Arc::new(junk.clone());
    let mut rng = rand::thread_rng();
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        let address = *addresses
            .choose(&mut rng)
            .ok_or_else(|| WarpError::Endpoint("пустой список адресов".to_string()))?;
        let port = *ENDPOINT_PORTS
            .choose(&mut rng)
            .ok_or_else(|| WarpError::Endpoint("пустой список портов".to_string()))?;
        pairs.push(SocketAddr::from((address, port)));
    }

    let parallel = concurrency.max(1);
    let probes = futures::stream::iter(pairs.into_iter().map(|endpoint| {
        let registration = registration.clone();
        let junk = junk.clone();
        async move {
            probe(&registration, &junk, endpoint)
                .await
                .map(|rtt| EndpointResult { endpoint, rtt })
        }
    }))
    .buffer_unordered(parallel)
    .filter_map(|result| async move { result })
    .collect::<Vec<_>>()
    .await;

    let mut results = probes;
    results.sort_by_key(|result| result.rtt);
    results.truncate(3);

    if results.is_empty() {
        return Err(WarpError::Endpoint(
            "ни один WARP-эндпоинт не ответил".to_string(),
        ));
    }

    Ok(results)
}

/// Проба: junk + handshake initiation, ждём HandshakeResponse ≤ 1 с.
pub async fn probe(
    registration: &WarpRegistration,
    junk: &JunkConfig,
    endpoint: SocketAddr,
) -> Option<Duration> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    socket.connect(endpoint).await.ok()?;

    let mut rng = rand::thread_rng();
    for packet in junk.packets(&mut rng) {
        socket.send(&packet).await.ok()?;
    }

    let keypair = KeyPair::from_private_base64(&registration.private_key).ok()?;
    let peer = public_from_base64(&registration.peer_public_key).ok()?;
    let mut tunn = Tunn::new(
        keypair.private,
        peer,
        None,
        None,
        rng.gen(),
        None,
    );

    let mut destination = vec![0u8; 2048];
    let initiation = match tunn.format_handshake_initiation(&mut destination, false) {
        boringtun::noise::TunnResult::WriteToNetwork(data) => data.to_vec(),
        _ => return None,
    };
    let mut initiation = initiation;
    inject_reserved(&mut initiation, registration.reserved);

    let started = std::time::Instant::now();
    socket.send(&initiation).await.ok()?;

    let mut buffer = vec![0u8; 2048];
    let read = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;

    match Tunn::parse_incoming_packet(&buffer[..read]) {
        Ok(boringtun::noise::Packet::HandshakeResponse(_)) => Some(started.elapsed()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_all_networks() {
        let addresses = expand_networks();
        assert_eq!(addresses.len(), ENDPOINT_NETWORKS.len() * 256);
        assert!(addresses.contains(&Ipv4Addr::new(162, 159, 192, 1)));
        assert!(addresses.contains(&Ipv4Addr::new(188, 114, 99, 255)));
    }

    #[test]
    fn ports_are_in_expected_range() {
        assert!(ENDPOINT_PORTS.iter().all(|port| *port >= 500));
        assert!(ENDPOINT_PORTS.contains(&2408));
    }
}
