mod outbounds;
mod sysproxy;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use psi_bootstrap::Bootstrap;
use psi_config::{Config, RuleCfg};
use psi_core::{ConnState, DirectOutbound, Event, EventBus, Handler, MixedInbound, Outbound, Target};
use psi_dpi::DpiOutbound;
use psi_psiphon::PsiphonState;
use psi_router::{CompiledRouter, HotRouter, Meta as RouteMeta, Network, ProcessLookup, RouterAssets};
use psi_vless::{VlessOutbound, VlessSettings};
use psi_warp::{JunkConfig, WarpOutbound, WarpRegistration};

use outbounds::{ErrorOutbound, OutboundSet};

/// Снимок состояния движка для UI.
#[derive(Debug, Clone, Default)]
pub struct Status {
    pub connected: bool,
    pub connecting: bool,
    pub region: String,
    pub strategy: String,
    pub ping_ms: Option<u64>,
    pub up_bps: u64,
    pub down_bps: u64,
    pub error: Option<String>,
}

/// Конфиг + статус + регионы одним ответом (для первичного заполнения UI).
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub config: Config,
    pub status: Status,
    pub regions: Vec<String>,
}

/// Команды движку (шаг 09; TUN — шаг 08, пока честный отказ).
#[allow(clippy::large_enum_variant)]
pub enum Cmd {
    Connect,
    Disconnect,
    SetRegion(String),
    SetPreset(String),
    UpsertRule(RuleCfg),
    DeleteRule(usize),
    ReloadConfig,
    TestRoute(String, oneshot::Sender<String>),
    Snapshot(oneshot::Sender<Snapshot>),
    ImportVless(String),
    SetPsiphonParams {
        propagation_channel_id: String,
        sponsor_id: String,
        remote_server_list_url: String,
        remote_server_list_signature_public_key: String,
    },
    RegisterWarp,
    ScanCleanIps,
    ScanWarp,
    AutotuneDpi,
    ToggleTun(bool),
    ToggleSystemProxy(bool),
}

/// Ручка управления движком.
#[derive(Clone)]
pub struct Handle {
    cmd: mpsc::Sender<Cmd>,
    bus: EventBus,
    status: Arc<Mutex<Status>>,
}

impl Handle {
    pub async fn send(&self, cmd: Cmd) {
        let _ = self.cmd.send(cmd).await;
    }

    pub fn bus(&self) -> EventBus {
        self.bus.clone()
    }

    pub fn status(&self) -> Status {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub async fn test_route(&self, input: &str) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::TestRoute(input.to_string(), tx)).await;
        rx.await.ok()
    }

    pub async fn snapshot(&self) -> Option<Snapshot> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::Snapshot(tx)).await;
        rx.await.ok()
    }
}

/// Точка входа: `Engine::start(cfg, dir) -> Handle`.
pub struct Engine;

impl Engine {
    pub fn start(config: Config, config_dir: PathBuf) -> Handle {
        let bus = EventBus::new();
        let status = Arc::new(Mutex::new(Status::default()));
        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        let actor = Actor::new(config, config_dir, bus.clone(), Arc::clone(&status));
        tokio::spawn(actor.run(cmd_rx));

        Handle {
            cmd: cmd_tx,
            bus,
            status,
        }
    }
}

struct Actor {
    cfg: Config,
    dir: PathBuf,
    bus: EventBus,
    status: Arc<Mutex<Status>>,
    winner: Option<psi_bootstrap::Winner>,
    inbound_task: Option<JoinHandle<()>>,
    aux_tasks: Vec<JoinHandle<()>>,
    proxy_on: bool,
    dpi_plan: Option<psi_dpi::StrategyPlan>,
    outbounds: Arc<ArcSwap<OutboundSet>>,
    router: Arc<HotRouter>,
    lookup: Arc<ProcessLookup>,
    regions: Vec<String>,
}

impl Actor {
    fn new(cfg: Config, dir: PathBuf, bus: EventBus, status: Arc<Mutex<Status>>) -> Self {
        let router = Arc::new(HotRouter::new(build_router(&cfg, &bus)));
        Self {
            cfg,
            dir,
            bus,
            status,
            winner: None,
            inbound_task: None,
            aux_tasks: Vec::new(),
            proxy_on: false,
            dpi_plan: None,
            outbounds: Arc::new(ArcSwap::from_pointee(OutboundSet::disconnected())),
            router,
            lookup: Arc::new(ProcessLookup::new()),
            regions: psi_psiphon::default_regions(),
        }
    }

    fn set_status(&self, update: impl FnOnce(&mut Status)) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        update(&mut status);
    }

    fn log(&self, text: impl Into<String>) {
        self.bus.publish(Event::Log(text.into()));
    }

    async fn run(mut self, mut rx: mpsc::Receiver<Cmd>) {
        self.bus.publish(Event::Regions(self.regions.clone()));
        while let Some(cmd) = rx.recv().await {
            match cmd {
                Cmd::Connect => self.connect().await,
                Cmd::Disconnect => self.disconnect().await,
                Cmd::SetRegion(region) => {
                    self.cfg.psiphon.egress_region = region.clone();
                    self.save();
                    self.set_status(|s| s.region = region.clone());
                    self.log(format!("страна выхода: {}", if region.is_empty() { "авто".into() } else { region }));
                    if self.winner.is_some() {
                        self.disconnect().await;
                        self.connect().await;
                    }
                }
                Cmd::SetPreset(preset) => {
                    self.cfg.routing.preset = preset.clone();
                    self.save();
                    self.rebuild_router();
                    self.log(format!("пресет маршрутов: {preset}"));
                }
                Cmd::UpsertRule(rule) => {
                    self.cfg.routing.rules.push(rule);
                    self.save();
                    self.rebuild_router();
                    self.log("правило добавлено");
                }
                Cmd::DeleteRule(idx) => {
                    if idx < self.cfg.routing.rules.len() {
                        self.cfg.routing.rules.remove(idx);
                        self.save();
                        self.rebuild_router();
                        self.log("правило удалено");
                    }
                }
                Cmd::ReloadConfig => match Config::load_from_dir(&self.dir) {
                    Ok(cfg) => {
                        self.cfg = cfg;
                        self.rebuild_router();
                        self.log("конфиг перечитан с диска");
                    }
                    Err(error) => self.log(format!("ошибка чтения конфига: {error}")),
                },
                Cmd::TestRoute(input, reply) => {
                    let _ = reply.send(self.test_route(&input));
                }
                Cmd::Snapshot(reply) => {
                    let _ = reply.send(Snapshot {
                        config: self.cfg.clone(),
                        status: self.status(),
                        regions: self.regions.clone(),
                    });
                }
                Cmd::ImportVless(uri) => self.import_vless(&uri),
                Cmd::SetPsiphonParams {
                    propagation_channel_id,
                    sponsor_id,
                    remote_server_list_url,
                    remote_server_list_signature_public_key,
                } => {
                    self.cfg.psiphon.propagation_channel_id = propagation_channel_id;
                    self.cfg.psiphon.sponsor_id = sponsor_id;
                    self.cfg.psiphon.remote_server_list_url = remote_server_list_url;
                    self.cfg.psiphon.remote_server_list_signature_public_key =
                        remote_server_list_signature_public_key;
                    self.save();
                    self.log("параметры сети Psiphon сохранены (в config.local.toml)");
                }
                Cmd::RegisterWarp => self.register_warp().await,
                Cmd::ScanCleanIps => self.scan_clean_ips().await,
                Cmd::ScanWarp => self.scan_warp().await,
                Cmd::AutotuneDpi => self.autotune_dpi().await,
                Cmd::ToggleTun(on) => {
                    self.log(format!(
                        "TUN-режим запрошен ({on}), но он делается шагом 08 и в этой сборке недоступен"
                    ));
                }
                Cmd::ToggleSystemProxy(on) => {
                    self.cfg.inbound.system_proxy = on;
                    self.save();
                    if self.winner.is_some() || self.proxy_on {
                        if on {
                            self.apply_proxy();
                        } else {
                            self.remove_proxy();
                        }
                    }
                    self.log(format!("системный прокси: {}", if on { "вкл" } else { "выкл" }));
                }
            }
        }
    }

    fn status(&self) -> Status {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn save(&self) {
        if let Err(error) = self.cfg.save_to_dir(&self.dir) {
            self.log(format!("не удалось сохранить конфиг: {error}"));
        }
    }

    fn rebuild_router(&self) {
        self.router.replace(Arc::new(build_router(&self.cfg, &self.bus)));
    }

    fn test_route(&self, input: &str) -> String {
        let input = input.trim();
        let (host, port) = match input.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !host.is_empty() => {
                (host.to_string(), port.parse::<u16>().unwrap_or(443))
            }
            _ => (input.to_string(), 443),
        };
        if host.is_empty() {
            return "введите домен".to_string();
        }
        let mut meta = RouteMeta::new(port).with_network(Network::Tcp);
        if let Ok(ip) = host.parse() {
            meta = meta.with_ip(ip);
        } else {
            meta = meta.with_domain(host);
        }
        self.router.explain(&meta)
    }

    fn import_vless(&mut self, uri: &str) {
        match VlessSettings::from_uri(uri.trim()) {
            Ok(settings) => {
                self.cfg.vless = Some(psi_config::Vless {
                    server: settings.server.clone(),
                    port: settings.port,
                    uuid: settings.uuid.to_string(),
                    path: settings.path.clone(),
                    sni: settings.sni.clone(),
                    host: settings.host.clone(),
                    early_data: settings.early_data,
                    clean_ips: settings.clean_ips.clone(),
                });
                self.save();
                self.log(format!("VLESS импортирован: {}:{}", settings.server, settings.port));
                if self.winner.is_some() {
                    self.log("переподключитесь, чтобы применить VLESS");
                }
            }
            Err(error) => self.log(format!("ошибка импорта vless://: {error}")),
        }
    }

    async fn register_warp(&mut self) {
        self.log("регистрация WARP…");
        match WarpRegistration::register().await {
            Ok(reg) => {
                let old_awg = self.cfg.warp.as_ref().map(|w| w.awg.clone()).unwrap_or_default();
                self.cfg.warp = Some(psi_config::Warp {
                    private_key: reg.private_key.clone(),
                    peer_public_key: reg.peer_public_key.clone(),
                    endpoint: reg.endpoint.clone(),
                    address_v4: reg.address_v4.clone(),
                    address_v6: reg.address_v6.clone(),
                    reserved: reg.reserved,
                    awg: old_awg,
                });
                self.save();
                self.log(format!("WARP зарегистрирован: {}", reg.endpoint));
            }
            Err(error) => self.log(format!("регистрация WARP не удалась: {error}")),
        }
    }

    async fn scan_clean_ips(&self) {
        let Some(vless_cfg) = self.cfg.vless.clone() else {
            self.log("сканирование чистых IP: сначала импортируйте vless://");
            return;
        };
        let Ok(settings) = VlessSettings::from_config(&vless_cfg) else {
            self.log("сканирование чистых IP: битый конфиг VLESS");
            return;
        };
        self.log("сканирование чистых IP Cloudflare…");
        let ranges = vec![
            "104.16.0.0/13".to_string(),
            "172.64.0.0/13".to_string(),
            "162.159.0.0/16".to_string(),
        ];
        match psi_vless::scan_clean_ips(&ranges, &[443], 256, &settings).await {
            Ok(found) => {
                for ip in &found {
                    self.log(format!("чистый IP: {}:{} — {:?}", ip.ip, ip.port, ip.latency));
                }
                if found.is_empty() {
                    self.log("чистые IP не нашлись");
                } else if let Some(vless) = self.cfg.vless.clone() {
                    let mut updated = vless;
                    updated.clean_ips = found.iter().map(|ip| ip.ip.to_string()).collect();
                    self.log("топ IP сохранён в конфиг (clean_ips), переподключитесь для применения");
                    let cfg = {
                        let mut cfg = self.cfg.clone();
                        cfg.vless = Some(updated);
                        cfg
                    };
                    if let Err(error) = cfg.save_to_dir(&self.dir) {
                        self.log(format!("не удалось сохранить clean_ips: {error}"));
                    }
                }
            }
            Err(error) => self.log(format!("сканирование IP не удалось: {error}")),
        }
    }

    async fn scan_warp(&self) {
        let Some(warp_cfg) = self.cfg.warp.clone() else {
            self.log("сканирование WARP: сначала зарегистрируйте WARP");
            return;
        };
        if warp_cfg.private_key.trim().is_empty() {
            self.log("сканирование WARP: нет ключа WARP");
            return;
        }
        let registration = WarpRegistration {
            private_key: warp_cfg.private_key.clone(),
            peer_public_key: warp_cfg.peer_public_key.clone(),
            address_v4: warp_cfg.address_v4.clone(),
            address_v6: warp_cfg.address_v6.clone(),
            reserved: warp_cfg.reserved,
            endpoint: warp_cfg.endpoint.clone(),
            client_id: String::new(),
        };
        let junk = match JunkConfig::from_awg(&warp_cfg.awg) {
            Ok(junk) => junk,
            Err(error) => {
                self.log(format!("сканирование WARP: битый AWG-профиль: {error}"));
                return;
            }
        };
        self.log("сканирование эндпоинтов WARP…");
        // psi-warp::scan держит ThreadRng через await и потому не Send:
        // гоняем его в отдельном потоке со своей current-thread рантайм.
        let (tx, rx) = oneshot::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(runtime) = runtime {
                let result = runtime.block_on(async move {
                    psi_warp::scan(&registration, &junk)
                        .await
                        .map_err(|error| error.to_string())
                });
                let _ = tx.send(result);
            } else {
                let _ = tx.send(Err("не удалось создать runtime для скана".to_string()));
            }
        });
        let scanned = match rx.await {
            Ok(result) => result,
            Err(_) => Err("поток сканирования завершился без ответа".to_string()),
        };
        match scanned {
            Ok(found) => {
                for ep in &found {
                    self.log(format!("WARP эндпоинт: {} — RTT {:?}", ep.endpoint, ep.rtt));
                }
                if found.is_empty() {
                    self.log("живые эндпоинты WARP не нашлись");
                }
            }
            Err(error) => self.log(format!("сканирование WARP не удалось: {error}")),
        }
    }

    async fn autotune_dpi(&mut self) {
        self.log("автоподбор DPI-стратегии…");
        match psi_dpi::autotune(psi_dpi::DEFAULT_TEST_HOSTS).await {
            Some(plan) => {
                self.log(format!("DPI: подобрана стратегия {plan:?}"));
                self.dpi_plan = Some(plan);
                if self.winner.is_some() {
                    self.log("переподключитесь, чтобы применить DPI-стратегию");
                }
            }
            None => self.log("DPI: ни одна стратегия не прошла проверку"),
        }
    }

    fn apply_proxy(&mut self) {
        match sysproxy::enable(self.cfg.inbound.mixed_port) {
            Ok(()) => self.proxy_on = true,
            Err(error) => self.log(format!("системный прокси не выставлен: {error}")),
        }
    }

    fn remove_proxy(&mut self) {
        if self.proxy_on {
            if let Err(error) = sysproxy::disable() {
                self.log(format!("системный прокси не снят: {error}"));
            }
            self.proxy_on = false;
        }
    }

    async fn connect(&mut self) {
        if self.winner.is_some() || self.status().connecting {
            return;
        }
        self.set_status(|s| {
            s.connecting = true;
            s.error = None;
        });
        self.bus.publish(Event::State(ConnState::Connecting {
            region: self.cfg.psiphon.egress_region.clone(),
        }));

        // --- Psiphon через гонку bootstrap (если есть параметры сети) ---
        let mut psiphon_outbound: Arc<dyn Outbound> = Arc::new(ErrorOutbound::new(
            "psiphon",
            "Psiphon не настроен: нужны параметры сети (Настройки → Psiphon)",
        ));
        let mut strategy_name = "без Psiphon (direct/dpi/vless/warp)".to_string();
        let mut state_rx: Option<watch::Receiver<PsiphonState>> = None;

        let creds_ok = !self.cfg.psiphon.propagation_channel_id.trim().is_empty()
            && !self.cfg.psiphon.sponsor_id.trim().is_empty();

        if creds_ok {
            match Bootstrap::new(self.cfg.clone(), self.bus.clone()) {
                Ok(bootstrap) => match bootstrap.race().await {
                    Ok(mut winner) => {
                        match winner.instance_mut().wait_connected(Duration::from_secs(30)).await {
                            Ok(socks_addr) => {
                                strategy_name = format!("Psiphon · {}", winner.tag());
                                psiphon_outbound = Arc::new(psi_psiphon::PsiphonOutbound::new(
                                    "psiphon",
                                    socks_addr,
                                ));
                                state_rx = Some(winner.subscribe());
                                self.winner = Some(winner);
                            }
                            Err(error) => {
                                self.log(format!("Psiphon не поднялся: {error}"));
                                winner.stop().await;
                            }
                        }
                    }
                    Err(error) => self.log(format!("гонка bootstrap: {error}")),
                },
                Err(error) => self.log(format!("bootstrap: {error}")),
            }
        } else {
            self.log("параметры сети Psiphon не заданы — Psiphon пропущен, остальные выходы работают");
        }

        // --- Остальные выходы ---
        let dpi_outbound: Arc<dyn Outbound> = match &self.dpi_plan {
            Some(plan) => Arc::new(DpiOutbound::new(plan.clone())),
            None => Arc::new(DpiOutbound::from(&self.cfg.dpi)),
        };

        let vless_outbound: Arc<dyn Outbound> = match &self.cfg.vless {
            Some(vless_cfg) => match VlessSettings::from_config(vless_cfg)
                .and_then(VlessOutbound::new)
            {
                Ok(outbound) => Arc::new(outbound),
                Err(error) => Arc::new(ErrorOutbound::new("vless", format!("VLESS: {error}"))),
            },
            None => Arc::new(ErrorOutbound::new("vless", "VLESS не импортирован")),
        };

        let warp_outbound: Arc<dyn Outbound> = match &self.cfg.warp {
            Some(warp_cfg) if !warp_cfg.private_key.trim().is_empty() => {
                match WarpOutbound::from_settings(warp_cfg).await {
                    Ok(outbound) => Arc::new(outbound),
                    Err(error) => Arc::new(ErrorOutbound::new("warp", format!("WARP: {error}"))),
                }
            }
            _ => Arc::new(ErrorOutbound::new("warp", "WARP не зарегистрирован")),
        };

        self.outbounds.store(Arc::new(OutboundSet {
            direct: Arc::new(DirectOutbound::new()),
            dpi: dpi_outbound,
            psiphon: psiphon_outbound.clone(),
            vless: vless_outbound,
            warp: warp_outbound,
            block: Arc::new(ErrorOutbound::new("block", "заблокировано правилом")),
        }));
        self.rebuild_router();

        // --- Inbound ---
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.cfg.inbound.mixed_port));
        let inbound = Arc::new(MixedInbound::new(self.bus.clone()));
        let handler = self.make_handler();
        let bus = self.bus.clone();
        self.inbound_task = Some(tokio::spawn(async move {
            if let Err(error) = inbound.serve(addr, handler).await {
                bus.publish(Event::Log(format!("inbound остановлен: {error}")));
            }
        }));

        if self.cfg.inbound.system_proxy {
            self.apply_proxy();
        }

        // --- Статистика и пинг ---
        if let Some(rx) = state_rx {
            self.aux_tasks.push(spawn_sampler(rx, Arc::clone(&self.status), self.bus.clone()));
        }
        self.aux_tasks.push(spawn_ping(psiphon_outbound, Arc::clone(&self.status)));

        let region = if self.cfg.psiphon.egress_region.is_empty() {
            "авто".to_string()
        } else {
            self.cfg.psiphon.egress_region.clone()
        };
        self.set_status(|s| {
            s.connecting = false;
            s.connected = true;
            s.region = region.clone();
            s.strategy = strategy_name.clone();
        });
        self.bus.publish(Event::State(ConnState::Connected {
            region,
            via: strategy_name,
        }));
    }

    async fn disconnect(&mut self) {
        if let Some(task) = self.inbound_task.take() {
            task.abort();
        }
        for task in self.aux_tasks.drain(..) {
            task.abort();
        }
        self.remove_proxy();
        if let Some(winner) = self.winner.take() {
            winner.stop().await;
        }
        self.outbounds.store(Arc::new(OutboundSet::disconnected()));
        self.set_status(|s| {
            *s = Status::default();
        });
        self.bus.publish(Event::State(ConnState::Idle));
        self.log("отключено");
    }

    fn make_handler(&self) -> Handler {
        let outbounds = Arc::clone(&self.outbounds);
        let router = Arc::clone(&self.router);
        let lookup = Arc::clone(&self.lookup);
        let bus = self.bus.clone();

        Arc::new(move |target: Target, meta: psi_core::Meta| {
            let outbounds = Arc::clone(&outbounds);
            let router = Arc::clone(&router);
            let lookup = Arc::clone(&lookup);
            let bus = bus.clone();
            Box::pin(async move {
                let (domain, ip) = match &target {
                    Target::Domain(host, _) => (Some(host.clone()), None),
                    Target::Ip(addr) => (None, Some(addr.ip())),
                };
                let mut route_meta = RouteMeta::new(target.port()).with_network(Network::Tcp);
                if let Some(domain) = domain {
                    route_meta = route_meta.with_domain(domain);
                }
                if let Some(ip) = ip {
                    route_meta = route_meta.with_ip(ip);
                }
                if let Some(process) = lookup.process_for_port(meta.peer.port()) {
                    route_meta = route_meta.with_process(process);
                }

                let decision = router.route(&route_meta);
                bus.publish(Event::Route {
                    dst: target.authority(),
                    outbound: decision.action.to_string(),
                });

                let outbound = outbounds.load().get(decision.action);
                outbound.connect_tcp(&target).await
            })
        })
    }
}

fn build_router(cfg: &Config, bus: &EventBus) -> CompiledRouter {
    let assets = match Config::data_dir() {
        Ok(dir) => RouterAssets::load(&dir.join("lists")),
        Err(_) => RouterAssets::default(),
    };
    match CompiledRouter::from_settings(&cfg.routing, Arc::new(assets)) {
        Ok(router) => router,
        Err(error) => {
            bus.publish(Event::Log(format!(
                "ошибка компиляции правил ({error}) — беру первый рабочий пресет"
            )));
            // Встроенные пресеты покрыты тестами psi-router и компилируются всегда;
            // сюда можно попасть только из-за битых пользовательских правил.
            ["smart_ru", "blocked_only", "all_vpn"]
                .into_iter()
                .find_map(|name| CompiledRouter::from_preset(name).ok())
                .expect("хотя бы один встроенный пресет обязан компилироваться")
        }
    }
}

fn spawn_sampler(
    mut rx: watch::Receiver<PsiphonState>,
    status: Arc<Mutex<Status>>,
    bus: EventBus,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut prev: Option<(u64, u64, Instant)> = None;
        let mut last_regions: Vec<String> = Vec::new();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let state = rx.borrow_and_update().clone();

            if !state.regions.is_empty() && state.regions != last_regions {
                last_regions = state.regions.clone();
                bus.publish(Event::Regions(state.regions.clone()));
            }

            let now = Instant::now();
            if let Some((up0, down0, at)) = prev {
                let dt = now.duration_since(at).as_secs_f64().max(0.001);
                let up_bps = ((state.sent.saturating_sub(up0)) as f64 / dt) as u64;
                let down_bps = ((state.received.saturating_sub(down0)) as f64 / dt) as u64;
                let mut status = status.lock().unwrap_or_else(|e| e.into_inner());
                status.up_bps = up_bps;
                status.down_bps = down_bps;
            }
            prev = Some((state.sent, state.received, now));
        }
    })
}

fn spawn_ping(outbound: Arc<dyn Outbound>, status: Arc<Mutex<Status>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let started = Instant::now();
            let target = Target::Ip(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)));
            let ping = match tokio::time::timeout(Duration::from_secs(5), outbound.connect_tcp(&target)).await {
                Ok(Ok(_stream)) => Some(started.elapsed().as_millis() as u64),
                _ => None,
            };
            {
                let mut status = status.lock().unwrap_or_else(|e| e.into_inner());
                status.ping_ms = ping;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn engine_answers_test_route_and_snapshot() {
        let dir = std::env::temp_dir().join(format!("psiroute-engine-test-{}", std::process::id()));
        let handle = Engine::start(Config::default(), dir);

        let explain = handle
            .test_route("example.ru")
            .await
            .expect("ответ тестера маршрутов");
        assert!(explain.contains("direct"), "неожиданное объяснение: {explain}");

        let snapshot = handle.snapshot().await.expect("снимок состояния");
        assert_eq!(snapshot.config.routing.preset, "smart_ru");
        assert!(!snapshot.status.connected);
        assert!(snapshot.regions.iter().any(|code| code == "DE"));
    }
}
