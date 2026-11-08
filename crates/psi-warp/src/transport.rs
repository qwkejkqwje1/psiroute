use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use rand::RngCore;
use tokio::net::UdpSocket;

use crate::junk::JunkConfig;
use crate::keys::{public_from_base64, KeyPair};
use crate::register::WarpRegistration;
use crate::{Result, WarpError};

const MAX_DATAGRAM: usize = 65_535;
const HANDSHAKE_BUFFER: usize = 2048;

/// UDP-транспорт WireGuard с WARP reserved и AmneziaWG-junk.
pub struct WarpTransport {
    socket: Arc<UdpSocket>,
    tunn: Mutex<Tunn>,
    junk: JunkConfig,
    reserved: [u8; 3],
    endpoint: SocketAddr,
    pending: Mutex<VecDeque<Vec<u8>>>,
}

impl WarpTransport {
    pub async fn new(registration: &WarpRegistration, junk: JunkConfig) -> Result<Self> {
        let (host, port) = split_endpoint(&registration.endpoint)?;
        let mut addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
        let endpoint = addrs
            .next()
            .ok_or_else(|| WarpError::Net(format!("нет адреса для {host}:{port}")))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(endpoint).await?;

        let keypair = KeyPair::from_private_base64(&registration.private_key)?;
        let peer = public_from_base64(&registration.peer_public_key)?;
        let index = rand::random::<u32>();

        let tunn = Tunn::new(keypair.private, peer, None, Some(25), index, None);

        Ok(Self {
            socket: Arc::new(socket),
            tunn: Mutex::new(tunn),
            junk,
            reserved: registration.reserved,
            endpoint,
            pending: Mutex::new(VecDeque::new()),
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub async fn send_junk(&self) -> Result<()> {
        let packets = {
            let mut rng = rand::thread_rng();
            self.junk.packets(&mut rng)
        };

        for packet in packets {
            self.socket.send(&packet).await?;
        }
        Ok(())
    }

    /// Отправляет handshake init, предварительно отправив junk-пакеты.
    pub async fn send_handshake(&self, force: bool) -> Result<()> {
        let packet = {
            let mut tunn = self
                .tunn
                .lock()
                .map_err(|_| WarpError::Tunnel("мьютекс tunn".to_string()))?;
            let mut dst = vec![0u8; HANDSHAKE_BUFFER];
            match tunn.format_handshake_initiation(&mut dst, force) {
                TunnResult::WriteToNetwork(data) => data.to_vec(),
                TunnResult::Done => return Ok(()),
                TunnResult::Err(error) => {
                    return Err(WarpError::Tunnel(format!("handshake: {error:?}")))
                }
                _ => return Ok(()),
            }
        };

        self.send_junk().await?;
        self.send_datagram(&packet).await
    }

    /// Шифрует один IP-пакет и отправляет его в UDP.
    pub async fn send_ip(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }

        let output = {
            let mut tunn = self
                .tunn
                .lock()
                .map_err(|_| WarpError::Tunnel("мьютекс tunn".to_string()))?;
            let mut dst = vec![0u8; packet.len() + 148];
            match tunn.encapsulate(packet, &mut dst) {
                TunnResult::WriteToNetwork(data) => Some(data.to_vec()),
                TunnResult::Done => None,
                TunnResult::Err(error) => {
                    return Err(WarpError::Tunnel(format!("encapsulate: {error:?}")))
                }
                _ => None,
            }
        };

        match output {
            Some(packet) => self.send_datagram(&packet).await,
            None => Ok(()),
        }
    }

    pub async fn update_timers(&self) -> Result<()> {
        loop {
            let output = {
                let mut tunn = self
                    .tunn
                    .lock()
                    .map_err(|_| WarpError::Tunnel("мьютекс tunn".to_string()))?;
                let mut dst = vec![0u8; HANDSHAKE_BUFFER];
                match tunn.update_timers(&mut dst) {
                    TunnResult::WriteToNetwork(data) => data.to_vec(),
                    TunnResult::Done => break,
                    TunnResult::Err(error) => {
                        return Err(WarpError::Tunnel(format!("timers: {error:?}")))
                    }
                    _ => break,
                }
            };
            self.send_datagram(&output).await?;
        }

        Ok(())
    }

    /// Принимает датаграмму, расшифровывает и возвращает IP-пакет (если он есть).
    pub async fn recv_ip(&self) -> Result<Option<Vec<u8>>> {
        if let Some(packet) = self
            .pending
            .lock()
            .map_err(|_| WarpError::Tunnel("мьютекс pending".to_string()))?
            .pop_front()
        {
            return Ok(Some(packet));
        }

        let mut buffer = vec![0u8; MAX_DATAGRAM];
        let read = self.socket.recv(&mut buffer).await?;
        buffer.truncate(read);
        self.handle_datagram(&buffer).await?;

        Ok(self
            .pending
            .lock()
            .map_err(|_| WarpError::Tunnel("мьютекс pending".to_string()))?
            .pop_front())
    }

    async fn handle_datagram(&self, datagram: &[u8]) -> Result<()> {
        let mut network_packets = Vec::new();

        {
            let mut tunn = self
                .tunn
                .lock()
                .map_err(|_| WarpError::Tunnel("мьютекс tunn".to_string()))?;
            let mut dst = vec![0u8; MAX_DATAGRAM];

            match tunn.decapsulate(None, datagram, &mut dst) {
                TunnResult::WriteToNetwork(data) => network_packets.push(data.to_vec()),
                TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                    self.push_pending(data);
                }
                TunnResult::Err(error) => {
                    tracing::debug!(?error, "WireGuard decapsulate");
                }
                TunnResult::Done => {}
            }

            for _ in 0..8 {
                match tunn.decapsulate(None, &[], &mut dst) {
                    TunnResult::WriteToNetwork(data) => network_packets.push(data.to_vec()),
                    TunnResult::WriteToTunnelV4(data, _)
                    | TunnResult::WriteToTunnelV6(data, _) => {
                        self.push_pending(data);
                    }
                    _ => break,
                }
            }
        }

        for packet in network_packets {
            self.send_datagram(&packet).await?;
        }

        Ok(())
    }

    fn push_pending(&self, packet: &[u8]) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.push_back(packet.to_vec());
        }
    }

    async fn send_datagram(&self, packet: &[u8]) -> Result<()> {
        let mut packet = packet.to_vec();
        inject_reserved(&mut packet, self.reserved);
        self.socket.send(&packet).await?;
        Ok(())
    }

    pub async fn handshake_with_timeout(&self, timeout: Duration) -> Result<()> {
        self.send_handshake(false).await?;
        tokio::time::sleep(timeout).await;
        Ok(())
    }
}

/// WARP кладёт reserved в байты 1..4 каждого исходящего WG-пакета.
pub fn inject_reserved(packet: &mut [u8], reserved: [u8; 3]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    packet[1] = reserved[0];
    packet[2] = reserved[1];
    packet[3] = reserved[2];
    true
}

pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn split_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| WarpError::Profile(format!("endpoint без порта: {endpoint}")))?;
    let port = port
        .parse()
        .map_err(|error| WarpError::Profile(format!("порт endpoint: {error}")))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_reserved_into_packet() {
        let mut packet = [0u8; 8];
        assert!(inject_reserved(&mut packet, [1, 2, 3]));
        assert_eq!(&packet[1..4], &[1, 2, 3]);
        assert_eq!(packet[0], 0);
    }

    #[test]
    fn rejects_short_packet() {
        let mut packet = [0u8; 3];
        assert!(!inject_reserved(&mut packet, [1, 2, 3]));
    }
}
