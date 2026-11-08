use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use psi_config::Config;
use psi_core::{Event, EventBus};
use psi_psiphon::{PsiphonConfig, PsiphonInstance, PsiphonState};

use crate::bridge::Bridge;
use crate::cache::BootstrapCache;
use crate::error::{BootstrapError, Result};
use crate::fingerprint::NetworkFingerprint;
use crate::race::{order_tags, race_entries, start_delays, RaceEntry};
use crate::strategy::{builtin_strategies, Strategy};

/// Настройки гонки и фоновых проверок.
#[derive(Debug, Clone)]
pub struct BootstrapSettings {
    pub cache_path: PathBuf,
    pub data_root: PathBuf,
    pub order: Vec<String>,
    pub stagger: Duration,
    pub timeout: Duration,
    pub head_start: Duration,
    pub auto_promote: bool,
    pub direct_probe_interval: Duration,
    pub reconnect_after: Duration,
}

impl BootstrapSettings {
    pub fn new(data_root: PathBuf, order: Vec<String>) -> Self {
        Self {
            cache_path: data_root.join("bootstrap_cache.json"),
            data_root,
            order,
            stagger: Duration::from_millis(300),
            timeout: Duration::from_secs(25),
            head_start: Duration::from_millis(1500),
            auto_promote: true,
            direct_probe_interval: Duration::from_secs(15 * 60),
            reconnect_after: Duration::from_secs(20),
        }
    }
}

/// Победившая стратегия: живой Psiphon и удерживаемый мост.
pub struct Winner {
    tag: String,
    instance: PsiphonInstance,
    bridge: Bridge,
    elapsed: Duration,
    from_cache: bool,
}

impl Winner {
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn upstream(&self) -> Option<&str> {
        self.bridge.upstream()
    }

    pub fn instance(&self) -> &PsiphonInstance {
        &self.instance
    }

    pub fn instance_mut(&mut self) -> &mut PsiphonInstance {
        &mut self.instance
    }

    pub fn subscribe(&self) -> watch::Receiver<PsiphonState> {
        self.instance.subscribe()
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn from_cache(&self) -> bool {
        self.from_cache
    }

    /// Останавливает Psiphon и мост.
    pub async fn stop(self) {
        let _ = self.instance.stop().await;
        self.bridge.shutdown().await;
    }
}

/// Гонка путей к Psiphon с кэшем победителя и фоновым мониторингом.
pub struct Bootstrap {
    config: Config,
    bus: EventBus,
    cache: Mutex<BootstrapCache>,
    fingerprint: NetworkFingerprint,
    settings: BootstrapSettings,
}

impl Bootstrap {
    pub fn new(config: Config, bus: EventBus) -> Result<Self> {
        let data_root = Config::data_dir()?;
        let settings = BootstrapSettings::new(data_root, config.bootstrap.order.clone());
        let settings = BootstrapSettings {
            stagger: Duration::from_millis(config.bootstrap.stagger_ms),
            timeout: Duration::from_secs(config.bootstrap.timeout_s.max(1)),
            auto_promote: config.bootstrap.auto_promote,
            ..settings
        };

        Ok(Self::with_settings(
            config,
            bus,
            settings,
            NetworkFingerprint::current(),
        ))
    }

    pub fn with_settings(
        config: Config,
        bus: EventBus,
        settings: BootstrapSettings,
        fingerprint: NetworkFingerprint,
    ) -> Self {
        let cache = BootstrapCache::load(&settings.cache_path);
        Self {
            config,
            bus,
            cache: Mutex::new(cache),
            fingerprint,
            settings,
        }
    }

    pub fn fingerprint(&self) -> &NetworkFingerprint {
        &self.fingerprint
    }

    pub fn settings(&self) -> &BootstrapSettings {
        &self.settings
    }

    /// Полная гонка стратегий; кэшированный победитель стартует первым.
    pub async fn race(&self) -> Result<Winner> {
        self.race_forced(None).await
    }

    async fn race_forced(&self, forced: Option<&str>) -> Result<Winner> {
        if PsiphonConfig::from_settings(&self.config.psiphon, "", None, "").is_err() {
            return Err(BootstrapError::MissingCredentials);
        }

        let strategies = builtin_strategies(&self.config, self.bus.clone());
        if strategies.is_empty() {
            return Err(BootstrapError::NoStrategies);
        }

        let available: Vec<String> = strategies
            .iter()
            .map(|strategy| strategy.tag().to_string())
            .collect();

        let cached = {
            let cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
            cache
                .winner_tag(&self.fingerprint.id)
                .map(ToOwned::to_owned)
        };

        let mut ordered = Vec::with_capacity(available.len());
        if let Some(tag) = forced {
            if available.iter().any(|item| item == tag) {
                ordered.push(tag.to_string());
            }
        }
        for tag in order_tags(&self.settings.order, cached.as_deref(), &available) {
            if !ordered.iter().any(|item| item == &tag) {
                ordered.push(tag);
            }
        }

        let cached_head_start = forced.is_none() && cached.is_some();
        let delays = start_delays(
            ordered.len(),
            cached_head_start,
            self.settings.stagger,
            self.settings.head_start,
        );

        let context = RaceContext {
            config: self.config.clone(),
            data_root: self.settings.data_root.clone(),
            network_id: self.fingerprint.id.clone(),
            bus: self.bus.clone(),
            timeout: self.settings.timeout,
        };

        let entries: Vec<RaceEntry<Winner>> = ordered
            .into_iter()
            .zip(delays)
            .filter_map(|(tag, delay)| {
                let strategy = strategies
                    .iter()
                    .find(|strategy| strategy.tag() == tag)
                    .cloned()?;
                let context = context.clone();
                let from_cache = cached.as_deref() == Some(tag.as_str());

                let entry_tag = tag.clone();
                let future: BoxFuture<'static, Option<Winner>> = Box::pin(async move {
                    run_strategy(context, strategy, tag, from_cache).await
                });

                Some(RaceEntry {
                    tag: entry_tag,
                    delay,
                    future,
                })
            })
            .collect();

        let winner = race_entries(entries, self.settings.timeout).await?;

        {
            let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
            cache.remember(&self.fingerprint.id, winner.tag())?;
        }

        self.bus.publish(Event::Log(format!(
            "Psiphon подключён через {} за {:?}{}",
            winner.tag(),
            winner.elapsed(),
            if winner.from_cache() {
                " (из кэша сети)"
            } else {
                ""
            }
        )));

        Ok(winner)
    }

    /// Раз в 15 минут тихо проверяет прямой путь; при успехе предлагает переключение.
    pub fn spawn_direct_monitor(&self, current_tag: &str) -> DirectMonitor {
        let (tx, rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();

        if current_tag == "direct" {
            return DirectMonitor {
                rx,
                cancel,
                task: None,
            };
        }

        let config = self.config.clone();
        let data_root = self.settings.data_root.clone();
        let network_id = self.fingerprint.id.clone();
        let bus = self.bus.clone();
        let auto_promote = self.settings.auto_promote;
        let interval = self.settings.direct_probe_interval;
        let task_cancel = cancel.clone();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {}
                }

                if probe_direct(config.clone(), data_root.clone(), network_id.clone(), bus.clone())
                    .await
                {
                    bus.publish(Event::Log(
                        "прямой путь Psiphon доступен — можно переключиться".to_string(),
                    ));

                    if auto_promote && tx.send(()).await.is_err() {
                        break;
                    }
                }
            }
        });

        DirectMonitor {
            rx,
            cancel,
            task: Some(task),
        }
    }

    /// Гонка с восстановлением: потеря туннелей и авто-повышение прямого пути.
    pub async fn run_forever(self: Arc<Self>) -> Result<()> {
        let mut winner = self.race().await?;

        loop {
            let mut monitor = self.spawn_direct_monitor(winner.tag());
            let mut lost = Box::pin(wait_lost(
                winner.subscribe(),
                self.settings.reconnect_after,
            ));

            loop {
                tokio::select! {
                    _ = &mut lost => {
                        self.bus.publish(Event::Log(
                            "Psiphon потерял туннели — повторная гонка".to_string(),
                        ));
                        winner.stop().await;
                        winner = self.race().await?;
                        break;
                    }
                    signal = monitor.recv() => {
                        if signal.is_none() {
                            continue;
                        }

                        self.bus.publish(Event::Log(
                            "переключение на прямой путь Psiphon".to_string(),
                        ));
                        winner.stop().await;
                        winner = match self.race_forced(Some("direct")).await {
                            Ok(winner) => winner,
                            Err(error) => {
                                self.bus.publish(Event::Log(format!(
                                    "прямой путь не поднялся: {error}"
                                )));
                                self.race().await?
                            }
                        };
                        break;
                    }
                }
            }
        }
    }
}

/// Фоновая проверка прямого пути; при уничтожении отменяет задачу.
pub struct DirectMonitor {
    rx: mpsc::Receiver<()>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl DirectMonitor {
    pub async fn recv(&mut self) -> Option<()> {
        self.rx.recv().await
    }
}

impl Drop for DirectMonitor {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Clone)]
struct RaceContext {
    config: Config,
    data_root: PathBuf,
    network_id: String,
    bus: EventBus,
    timeout: Duration,
}

async fn run_strategy(
    context: RaceContext,
    strategy: Arc<dyn Strategy>,
    tag: String,
    from_cache: bool,
) -> Option<Winner> {
    let bridge = strategy.prepare().await?;
    let upstream = bridge.upstream().map(ToOwned::to_owned);
    let data_dir = context.data_root.join("psiphon").join(sanitize(&tag));

    let psiphon = PsiphonConfig::from_settings(
        &context.config.psiphon,
        data_dir.to_string_lossy().into_owned(),
        upstream,
        context.network_id,
    )
    .ok()?;

    let started = Instant::now();
    let mut instance = PsiphonInstance::spawn(psiphon, tag.clone(), data_dir, context.bus)
        .await
        .ok()?;
    instance.wait_connected(context.timeout).await.ok()?;

    Some(Winner {
        tag,
        instance,
        bridge,
        elapsed: started.elapsed(),
        from_cache,
    })
}

async fn probe_direct(
    config: Config,
    data_root: PathBuf,
    network_id: String,
    bus: EventBus,
) -> bool {
    let data_dir = data_root.join("psiphon").join(".direct-probe");
    let Ok(psiphon) = PsiphonConfig::from_settings(
        &config.psiphon,
        data_dir.to_string_lossy().into_owned(),
        None,
        network_id,
    ) else {
        return false;
    };

    let Ok(mut instance) = PsiphonInstance::spawn(psiphon, "direct-probe", data_dir, bus).await
    else {
        return false;
    };

    let connected = instance.wait_connected(Duration::from_secs(20)).await.is_ok();
    let _ = instance.stop().await;
    connected
}

/// Ждёт падения туннелей; если они не восстановились за `lost_after` — `true`.
pub async fn wait_lost(mut state: watch::Receiver<PsiphonState>, lost_after: Duration) -> bool {
    let mut was_connected = state.borrow().tunnels >= 1;

    loop {
        if state.changed().await.is_err() {
            return true;
        }

        if state.borrow().tunnels >= 1 {
            was_connected = true;
            continue;
        }

        if !was_connected {
            continue;
        }

        let deadline = tokio::time::sleep(lost_after);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => return true,
                changed = state.changed() => {
                    if changed.is_err() {
                        return true;
                    }
                    if state.borrow().tunnels >= 1 {
                        was_connected = true;
                        break;
                    }
                }
            }
        }
    }
}

fn sanitize(tag: &str) -> String {
    tag.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    #[tokio::test(start_paused = true)]
    async fn reports_lost_tunnels_after_grace_period() {
        let (tx, rx) = watch::channel(PsiphonState {
            tunnels: 1,
            ..PsiphonState::default()
        });
        let lost = tokio::spawn(wait_lost(rx, Duration::from_secs(20)));

        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send_modify(|state| state.tunnels = 0);

        assert!(lost.await.expect("задача"));
    }

    #[tokio::test(start_paused = true)]
    async fn ignores_short_dropout() {
        let (tx, rx) = watch::channel(PsiphonState {
            tunnels: 1,
            ..PsiphonState::default()
        });
        let mut lost = Box::pin(wait_lost(rx, Duration::from_secs(20)));

        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send_modify(|state| state.tunnels = 0);
        tokio::time::sleep(Duration::from_secs(5)).await;
        tx.send_modify(|state| state.tunnels = 1);

        let result = tokio::time::timeout(Duration::from_secs(60), &mut lost).await;
        assert!(result.is_err(), "восстановление не должно считаться потерей");
    }

    #[test]
    fn sanitizes_data_directory() {
        assert_eq!(sanitize("vless/us"), "vless_us");
        assert_eq!(sanitize("warp"), "warp");
    }
}
