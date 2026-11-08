use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use psi_core::{ConnState, Event, EventBus};

use crate::config::PsiphonConfig;
use crate::error::{PsiphonError, Result};
use crate::notice::Notice;
use crate::outbound::PsiphonOutbound;

/// Текущее состояние сайдкара Psiphon.
#[derive(Debug, Clone, Default)]
pub struct PsiphonState {
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub tunnels: u32,
    pub protocol: Option<String>,
    pub region: Option<String>,
    pub sent: u64,
    pub received: u64,
    pub regions: Vec<String>,
    pub last_error: Option<String>,
}

impl PsiphonState {
    pub fn socks_addr(&self) -> Option<SocketAddr> {
        self.socks_port
            .map(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    }

    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_port
            .map(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    }
}

/// Запущенный экземпляр `psiphon-tunnel-core`.
pub struct PsiphonInstance {
    child: Child,
    config: PsiphonConfig,
    strategy_tag: String,
    data_dir: PathBuf,
    bus: EventBus,
    state_rx: watch::Receiver<PsiphonState>,
    reader: JoinHandle<()>,
}

impl PsiphonInstance {
    /// Запускает сайдкар.
    ///
    /// Если `cfg.upstream_proxy_url == None`, Psiphon работает напрямую через
    /// собственные обфусцированные протоколы (OSSH/TLS-OSSH/meek/QUIC).
    pub async fn spawn(
        cfg: PsiphonConfig,
        strategy_tag: impl Into<String>,
        data_dir: PathBuf,
        bus: EventBus,
    ) -> Result<Self> {
        cfg.validate()?;

        let strategy_tag = strategy_tag.into();
        let mut cfg = cfg;
        cfg.data_root_directory = data_dir.to_string_lossy().into_owned();

        std::fs::create_dir_all(&data_dir).map_err(|source| PsiphonError::ConfigWrite {
            path: data_dir.clone(),
            source,
        })?;

        let config_path = data_dir.join("config.json");
        let json = serde_json::to_string_pretty(&cfg)?;
        std::fs::write(&config_path, json).map_err(|source| PsiphonError::ConfigWrite {
            path: config_path.clone(),
            source,
        })?;

        let mut command = Command::new(&cfg.binary);
        command
            .arg("-config")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        #[cfg(windows)]
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW

        tracing::info!(
            target: "psi_psiphon",
            strategy = %strategy_tag,
            region = %cfg.egress_region,
            direct = cfg.upstream_proxy_url.is_none(),
            "запуск psiphon-tunnel-core"
        );

        let mut child = command.spawn().map_err(PsiphonError::Spawn)?;
        let stderr = child.stderr.take().ok_or(PsiphonError::NoStderr)?;

        let (state_tx, state_rx) = watch::channel(PsiphonState::default());
        bus.publish(Event::State(ConnState::Bootstrapping {
            strategy: strategy_tag.clone(),
        }));

        let reader = tokio::spawn(read_notices(
            stderr,
            state_tx,
            bus.clone(),
            strategy_tag.clone(),
            cfg.egress_region.clone(),
        ));

        Ok(Self {
            child,
            config: cfg,
            strategy_tag,
            data_dir,
            bus,
            state_rx,
            reader,
        })
    }

    pub fn strategy_tag(&self) -> &str {
        &self.strategy_tag
    }

    pub fn config(&self) -> &PsiphonConfig {
        &self.config
    }

    pub fn state(&self) -> PsiphonState {
        self.state_rx.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<PsiphonState> {
        self.state_rx.clone()
    }

    pub fn socks_addr(&self) -> Option<SocketAddr> {
        self.state_rx.borrow().socks_addr()
    }

    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.state_rx.borrow().http_addr()
    }

    /// Outbound поверх локального SOCKS5-порта Psiphon.
    pub fn outbound(&self) -> Option<PsiphonOutbound> {
        self.socks_addr()
            .map(|addr| PsiphonOutbound::new(self.strategy_tag.clone(), addr))
    }

    /// Ждёт, пока Psiphon поднимет SOCKS5 и будет хотя бы один туннель.
    pub async fn wait_connected(&mut self, timeout: Duration) -> Result<SocketAddr> {
        let wait = async {
            loop {
                {
                    let state = self.state_rx.borrow().clone();
                    if state.tunnels >= 1 {
                        if let Some(addr) = state.socks_addr() {
                            return Ok(addr);
                        }
                    }
                }

                if self.state_rx.changed().await.is_err() {
                    return Err(PsiphonError::Stopped);
                }
            }
        };

        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| PsiphonError::Timeout(timeout))?
    }

    /// Перезапуск со сменой страны (кэш серверов сохраняется в `data_dir`).
    pub async fn restart_with_region(self, region: impl Into<String>) -> Result<Self> {
        let mut config = self.config.clone();
        let strategy_tag = self.strategy_tag.clone();
        let data_dir = self.data_dir.clone();
        let bus = self.bus.clone();

        self.stop().await?;

        config.egress_region = region.into();
        Self::spawn(config, strategy_tag, data_dir, bus).await
    }

    /// Останавливает процесс и фоновый читатель stderr.
    pub async fn stop(mut self) -> Result<()> {
        self.reader.abort();
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        Ok(())
    }
}

async fn read_notices(
    stderr: tokio::process::ChildStderr,
    state_tx: watch::Sender<PsiphonState>,
    bus: EventBus,
    strategy_tag: String,
    fallback_region: String,
) {
    let mut lines = BufReader::new(stderr).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => match Notice::parse(&line) {
                Some(notice) => {
                    apply_notice(notice, &state_tx, &bus, &strategy_tag, &fallback_region);
                }
                None => {
                    if !line.trim().is_empty() {
                        tracing::debug!(target: "psi_psiphon", "stderr: {line}");
                    }
                }
            },
            Ok(None) => break,
            Err(error) => {
                tracing::debug!(target: "psi_psiphon", "ошибка чтения stderr: {error}");
                break;
            }
        }
    }
}

fn apply_notice(
    notice: Notice,
    state_tx: &watch::Sender<PsiphonState>,
    bus: &EventBus,
    strategy_tag: &str,
    fallback_region: &str,
) {
    match notice {
        Notice::ListeningSocksProxyPort { port } => {
            state_tx.send_modify(|state| state.socks_port = Some(port));
            bus.publish(Event::Log(format!(
                "Psiphon: SOCKS5 слушает 127.0.0.1:{port}"
            )));
        }
        Notice::ListeningHttpProxyPort { port } => {
            state_tx.send_modify(|state| state.http_port = Some(port));
            bus.publish(Event::Log(format!(
                "Psiphon: HTTP слушает 127.0.0.1:{port}"
            )));
        }
        Notice::Tunnels { count } => {
            let was_connected = state_tx.borrow().tunnels >= 1;
            state_tx.send_modify(|state| state.tunnels = count);

            if count >= 1 && !was_connected {
                let state = state_tx.borrow().clone();
                bus.publish(Event::State(ConnState::Connected {
                    region: region_of(&state, fallback_region),
                    via: via_of(&state, strategy_tag),
                }));
            } else if count == 0 && was_connected {
                bus.publish(Event::State(ConnState::Connecting {
                    region: fallback_region.to_string(),
                }));
            }
        }
        Notice::AvailableEgressRegions { regions } => {
            state_tx.send_modify(|state| state.regions = regions.clone());
            bus.publish(Event::Regions(regions));
        }
        Notice::ActiveTunnel { protocol, region } => {
            let connected = state_tx.borrow().tunnels >= 1;
            state_tx.send_modify(|state| {
                if !protocol.is_empty() {
                    state.protocol = Some(protocol);
                }
                if !region.is_empty() {
                    state.region = Some(region);
                }
            });

            if connected {
                let state = state_tx.borrow().clone();
                bus.publish(Event::State(ConnState::Connected {
                    region: region_of(&state, fallback_region),
                    via: via_of(&state, strategy_tag),
                }));
            }
        }
        Notice::BytesTransferred { sent, received } => {
            state_tx.send_modify(|state| {
                state.sent = sent;
                state.received = received;
            });
            bus.publish(Event::Stats {
                up: sent,
                down: received,
            });
        }
        Notice::Alert { message } => {
            state_tx.send_modify(|state| state.last_error = Some(message.clone()));
            bus.publish(Event::Log(format!("Psiphon alert: {message}")));
        }
        Notice::Error { message } => {
            state_tx.send_modify(|state| state.last_error = Some(message.clone()));
            bus.publish(Event::Log(format!("Psiphon error: {message}")));
        }
        Notice::Unknown { notice_type } => {
            tracing::trace!(target: "psi_psiphon", "неизвестный notice: {notice_type}");
        }
    }
}

fn region_of(state: &PsiphonState, fallback: &str) -> String {
    state
        .region
        .clone()
        .filter(|region| !region.is_empty())
        .unwrap_or_else(|| {
            if fallback.is_empty() {
                "auto".to_string()
            } else {
                fallback.to_string()
            }
        })
}

fn via_of(state: &PsiphonState, strategy_tag: &str) -> String {
    state
        .protocol
        .clone()
        .filter(|protocol| !protocol.is_empty())
        .unwrap_or_else(|| strategy_tag.to_string())
}
