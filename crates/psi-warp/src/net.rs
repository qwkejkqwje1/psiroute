use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};

use crate::junk::JunkConfig;
use crate::register::WarpRegistration;
use crate::transport::WarpTransport;
use crate::{Result, WarpError};

const MTU: usize = 1280;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const TCP_BUFFER: usize = 64 * 1024;

enum Command {
    Connect {
        remote: IpEndpoint,
        stack: DuplexStream,
    },
    Resolve {
        name: String,
        reply: oneshot::Sender<Result<Vec<IpAddr>>>,
    },
}

/// Userspace-стек поверх WARP: smoltcp + UDP-транспорт WireGuard.
pub struct WarpStack {
    commands: mpsc::UnboundedSender<Command>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WarpStack {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl WarpStack {
    pub async fn start(registration: &WarpRegistration, junk: JunkConfig) -> Result<Self> {
        let transport = WarpTransport::new(registration, junk).await?;

        let address_v4 = registration
            .address_v4
            .parse::<Ipv4Addr>()
            .unwrap_or_else(|_| Ipv4Addr::new(172, 16, 0, 2));
        let address_v6 = registration
            .address_v6
            .parse::<Ipv6Addr>()
            .unwrap_or(Ipv6Addr::UNSPECIFIED);

        let (commands, command_rx) = mpsc::unbounded_channel();
        let transport = Arc::new(transport);
        let task = tokio::spawn(run_stack(transport, address_v4, address_v6, command_rx));

        Ok(Self { commands, task })
    }

    pub async fn connect(&self, remote: IpEndpoint) -> Result<DuplexStream> {
        let (application, stack) = tokio::io::duplex(TCP_BUFFER);
        self.commands
            .send(Command::Connect { remote, stack })
            .map_err(|_| WarpError::Net("стек WARP остановлен".to_string()))?;
        Ok(application)
    }

    pub async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>> {
        if let Ok(address) = name.parse::<IpAddr>() {
            return Ok(vec![address]);
        }

        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Resolve {
                name: name.to_string(),
                reply,
            })
            .map_err(|_| WarpError::Net("стек WARP остановлен".to_string()))?;

        tokio::time::timeout(Duration::from_secs(8), response)
            .await
            .map_err(|_| WarpError::Timeout(format!("DNS через WARP для {name}")))?
            .map_err(|_| WarpError::Net("стек WARP остановлен".to_string()))?
    }
}

struct TcpConnection {
    handle: smoltcp::iface::SocketHandle,
    upstream: mpsc::UnboundedReceiver<Vec<u8>>,
    downstream: mpsc::UnboundedSender<Vec<u8>>,
    pending: VecDeque<u8>,
    upstream_open: bool,
}

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

impl QueueDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu,
        }
    }

    fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx)
    }
}

struct QueueRx<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl RxToken for QueueRx<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        match self.queue.pop_front() {
            Some(packet) => f(&packet),
            None => f(&[]),
        }
    }
}

struct QueueTx<'a> {
    queue: &'a mut Vec<Vec<u8>>,
}

impl TxToken for QueueTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.push(buffer);
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx<'a>;
    type TxToken<'a> = QueueTx<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx.is_empty() {
            return None;
        }
        Some((
            QueueRx { queue: &mut self.rx },
            QueueTx { queue: &mut self.tx },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx { queue: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

async fn run_stack(
    transport: Arc<WarpTransport>,
    address_v4: Ipv4Addr,
    address_v6: Ipv6Addr,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let started = std::time::Instant::now();
    let mut device = QueueDevice::new(MTU);

    let mut config = IfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut interface = Interface::new(config, &mut device, now(started));

    interface.update_ip_addrs(|addresses| {
        if !address_v4.is_unspecified() {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(address_v4), 32));
        }
        if !address_v6.is_unspecified() {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv6(address_v6), 128));
        }
    });

    let _ = interface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(172, 16, 0, 1));
    if !address_v6.is_unspecified() {
        let _ = interface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    }

    let mut sockets = SocketSet::new(Vec::new());
    let mut connections: Vec<TcpConnection> = Vec::new();
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let _ = transport.send_handshake(false).await;

    loop {
        tokio::select! {
            received = transport.recv_ip() => {
                match received {
                    Ok(Some(packet)) => device.push_rx(packet),
                    Ok(None) => {}
                    Err(error) => tracing::debug!(%error, "WARP: приём датаграммы"),
                }
            }
            command = commands.recv() => {
                match command {
                    Some(Command::Connect { remote, stack }) => {
                        add_connection(&mut interface, &mut sockets, &mut connections, remote, stack);
                    }
                    Some(Command::Resolve { name, reply }) => {
                        let result = resolve_via(
                            &mut interface,
                            &mut device,
                            &mut sockets,
                            &transport,
                            started,
                            &name,
                        )
                        .await;
                        let _ = reply.send(result);
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                let _ = transport.update_timers().await;

                interface.poll(now(started), &mut device, &mut sockets);

                for packet in device.drain_tx() {
                    if let Err(error) = transport.send_ip(&packet).await {
                        tracing::debug!(%error, "WARP: отправка пакета");
                    }
                }

                service_connections(&mut sockets, &mut connections);
            }
        }
    }
}

fn add_connection(
    interface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    connections: &mut Vec<TcpConnection>,
    remote: IpEndpoint,
    stack: DuplexStream,
) {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
    );

    if let Err(error) = socket.connect(
        interface.context(),
        remote,
        IpListenEndpoint { addr: None, port: 0 },
    ) {
        tracing::debug!(?error, "WARP: не удалось начать TCP connect");
        return;
    }

    let handle = sockets.add(socket);
    let (upstream_tx, upstream_rx) = mpsc::unbounded_channel();
    let (downstream_tx, downstream_rx) = mpsc::unbounded_channel();

    connections.push(TcpConnection {
        handle,
        upstream: upstream_rx,
        downstream: downstream_tx,
        pending: VecDeque::new(),
        upstream_open: true,
    });

    tokio::spawn(pump(stack, upstream_tx, downstream_rx));
}

async fn pump(
    application: DuplexStream,
    upstream: mpsc::UnboundedSender<Vec<u8>>,
    mut downstream: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (mut reader, mut writer) = tokio::io::split(application);
    let mut buffer = vec![0u8; 16 * 1024];

    loop {
        tokio::select! {
            result = reader.read(&mut buffer) => {
                match result {
                    Ok(0) => break,
                    Ok(read) => {
                        if upstream.send(buffer[..read].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            data = downstream.recv() => {
                match data {
                    Some(data) => {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    let _ = writer.shutdown().await;
}

fn service_connections(sockets: &mut SocketSet<'_>, connections: &mut Vec<TcpConnection>) {
    for connection in connections.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(connection.handle);

        loop {
            match connection.upstream.try_recv() {
                Ok(data) => connection.pending.extend(data),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    connection.upstream_open = false;
                    break;
                }
            }
        }

        while socket.can_send() && !connection.pending.is_empty() {
            let (slice, _) = connection.pending.as_slices();
            match socket.send_slice(slice) {
                Ok(0) | Err(_) => break,
                Ok(sent) => {
                    connection.pending.drain(..sent);
                }
            }
        }

        while socket.can_recv() {
            match socket.recv(|data| {
                let chunk = data.to_vec();
                (data.len(), chunk)
            }) {
                Ok(chunk) => {
                    if connection.downstream.send(chunk).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        if !connection.upstream_open && connection.pending.is_empty() && socket.may_send() {
            socket.close();
        }
    }

    let mut open = Vec::with_capacity(connections.len());
    for connection in connections.drain(..) {
        let state = sockets.get::<tcp::Socket>(connection.handle).state();
        if matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
            sockets.remove(connection.handle);
        } else {
            open.push(connection);
        }
    }
    *connections = open;
}

async fn resolve_via(
    interface: &mut Interface,
    device: &mut QueueDevice,
    sockets: &mut SocketSet<'_>,
    transport: &WarpTransport,
    started: std::time::Instant,
    name: &str,
) -> Result<Vec<IpAddr>> {
    if let Ok(address) = name.parse::<IpAddr>() {
        return Ok(vec![address]);
    }

    for query_type in [1u16, 28u16] {
        let query = build_dns_query(name, query_type)?;
        let handle = match add_dns_socket(sockets) {
            Ok(handle) => handle,
            Err(error) => return Err(error),
        };

        let remote = IpEndpoint::new(IpAddress::v4(1, 1, 1, 1), 53);
        if let Err(error) = sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(&query, remote)
        {
            sockets.remove(handle);
            return Err(WarpError::Net(format!("DNS send: {error:?}")));
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let mut buffer = vec![0u8; 4096];
        let mut answers = Vec::new();

        while std::time::Instant::now() < deadline {
            if let Ok(Ok(Some(packet))) =
                tokio::time::timeout(Duration::from_millis(10), transport.recv_ip()).await
            {
                device.push_rx(packet);
            }

            interface.poll(now(started), device, sockets);

            for packet in device.drain_tx() {
                transport.send_ip(&packet).await?;
            }

            let socket = sockets.get_mut::<udp::Socket>(handle);
            if socket.can_recv() {
                if let Ok((read, _)) = socket.recv_slice(&mut buffer) {
                    answers = parse_dns_answers(&buffer[..read], query_type);
                }
                break;
            }

            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        sockets.remove(handle);

        if !answers.is_empty() {
            return Ok(answers);
        }
    }

    Err(WarpError::Net(format!(
        "DNS через туннель не ответил для {name}"
    )))
}

fn add_dns_socket(sockets: &mut SocketSet<'_>) -> Result<smoltcp::iface::SocketHandle> {
    let mut socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]),
    );

    let mut bound = false;
    for _ in 0..16 {
        let port = rand::random::<u16>() | 0x8000;
        if socket
            .bind(IpListenEndpoint {
                addr: None,
                port,
            })
            .is_ok()
        {
            bound = true;
            break;
        }
    }

    if !bound {
        return Err(WarpError::Net("не удалось занять UDP-порт".to_string()));
    }

    Ok(sockets.add(socket))
}

fn build_dns_query(name: &str, query_type: u16) -> Result<Vec<u8>> {
    let mut query = Vec::with_capacity(64);
    let id = rand::random::<u16>();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(WarpError::Net(format!("некорректное DNS-имя: {name}")));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&query_type.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());

    Ok(query)
}

fn parse_dns_answers(data: &[u8], query_type: u16) -> Vec<IpAddr> {
    if data.len() < 12 {
        return Vec::new();
    }

    let questions = u16::from_be_bytes([data[4], data[5]]) as usize;
    let answers = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut position = 12;
    for _ in 0..questions {
        position = match skip_dns_name(data, position) {
            Some(position) => position,
            None => return Vec::new(),
        };
        position += 4;
    }

    let mut addresses = Vec::new();
    for _ in 0..answers {
        position = match skip_dns_name(data, position) {
            Some(position) => position,
            None => break,
        };

        if position + 10 > data.len() {
            break;
        }

        let record_type = u16::from_be_bytes([data[position], data[position + 1]]);
        let length = u16::from_be_bytes([data[position + 8], data[position + 9]]) as usize;
        position += 10;

        if position + length > data.len() {
            break;
        }

        if record_type == query_type {
            let record = &data[position..position + length];
            match (query_type, record.len()) {
                (1, 4) => addresses.push(IpAddr::V4(Ipv4Addr::new(
                    record[0], record[1], record[2], record[3],
                ))),
                (28, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(record);
                    addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }

        position += length;
    }

    addresses
}

fn skip_dns_name(data: &[u8], mut position: usize) -> Option<usize> {
    loop {
        let length = *data.get(position)?;
        if length == 0 {
            return Some(position + 1);
        }
        if length & 0xC0 == 0xC0 {
            return Some(position + 2);
        }
        position += 1 + length as usize;
        if position > data.len() {
            return None;
        }
    }
}

fn now(started: std::time::Instant) -> SmolInstant {
    SmolInstant::from_millis(started.elapsed().as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_dns_query() {
        let query = build_dns_query("example.com", 1).expect("query");
        assert_eq!(query[12], 7);
        assert_eq!(&query[13..20], b"example");
        assert_eq!(&query[query.len() - 4..], &[0, 1, 0, 1]);
    }

    #[test]
    fn parses_dns_answer() {
        let mut data = vec![0u8; 12];
        data[4] = 0;
        data[5] = 1;
        data[6] = 0;
        data[7] = 1;
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // question
        data.extend_from_slice(&[0xC0, 0x0C]); // pointer
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
        data.extend_from_slice(&[0x00, 0x04, 1, 2, 3, 4]);

        let answers = parse_dns_answers(&data, 1);
        assert_eq!(answers, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }
}
