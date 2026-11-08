// PsiRoute — Slint-версия GUI (шаг 10, вариант A для сравнения с Tauri).
//! Движок (psi-engine) работает in-process; события идут через EventBus,
//! команды — через Handle::send(Cmd).

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use psi_config::{Config, MatchCfg, RuleCfg};
use psi_core::{ConnState, Event};
use psi_engine::{Cmd, Engine};

slint::include_modules!();

fn rgba(bytes: &[u8], size: u32) -> slint::Image {
    slint::Image::from_rgba8(slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
        bytes, size, size,
    ))
}

fn flag(code: &str) -> String {
    if code.len() != 2 {
        return "🌐".to_string();
    }
    let mut out = String::new();
    for ch in code.chars() {
        let v = ch as u32;
        if (0x41..=0x5A).contains(&v) {
            if let Some(flag_ch) = char::from_u32(0x1F1E6 + (v - 0x41)) {
                out.push(flag_ch);
            }
        }
    }
    if out.is_empty() {
        "🌐".to_string()
    } else {
        out
    }
}

fn country_name(code: &str) -> String {
    let name = match code {
        "AT" => "Австрия",
        "BE" => "Бельгия",
        "BG" => "Болгария",
        "CA" => "Канада",
        "CH" => "Швейцария",
        "CZ" => "Чехия",
        "DE" => "Германия",
        "DK" => "Дания",
        "EE" => "Эстония",
        "ES" => "Испания",
        "FI" => "Финляндия",
        "FR" => "Франция",
        "GB" => "Великобритания",
        "HU" => "Венгрия",
        "IE" => "Ирландия",
        "IN" => "Индия",
        "IT" => "Италия",
        "JP" => "Япония",
        "LV" => "Латвия",
        "NL" => "Нидерланды",
        "NO" => "Норвегия",
        "PL" => "Польша",
        "RO" => "Румыния",
        "RS" => "Сербия",
        "SE" => "Швеция",
        "SG" => "Сингапур",
        "SK" => "Словакия",
        "US" => "США",
        _ => return code.to_string(),
    };
    name.to_string()
}

fn fmt_speed(bps: u64) -> String {
    if bps >= 1_000_000 {
        format!("{:.1} МБ/с", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.0} КБ/с", bps as f64 / 1_000.0)
    } else {
        format!("{bps} Б/с")
    }
}

fn rule_target(rule: &RuleCfg) -> String {
    let m = &rule.matcher;
    let mut parts: Vec<String> = Vec::new();
    for (label, values) in [
        ("домен", &m.domain),
        ("суффикс", &m.domain_suffix),
        ("ключ", &m.domain_keyword),
        ("regex", &m.domain_regex),
        ("geosite", &m.geosite),
        ("cidr", &m.ip_cidr),
        ("geoip", &m.geoip),
        ("процесс", &m.process),
    ] {
        for value in values {
            parts.push(format!("{label}:{value}"));
        }
    }
    if !m.port.is_empty() {
        parts.push(format!("порт:{}", m.port));
    }
    if !m.network.is_empty() {
        parts.push(m.network.clone());
    }
    if parts.is_empty() {
        if rule.name.is_empty() {
            "—".to_string()
        } else {
            rule.name.clone()
        }
    } else {
        parts.join(", ")
    }
}

#[derive(Debug)]
enum UiEvent {
    Log(String),
    Regions(Vec<String>),
    Rules(Vec<(String, String, String)>),
    TestResult(String),
    SnapshotData {
        rules: Vec<(String, String, String)>,
        preset: String,
        system_proxy: bool,
        psi_channel: String,
        psi_sponsor: String,
        psi_url: String,
        psi_key: String,
    },
}

fn rules_plain(config: &Config) -> Vec<(String, String, String)> {
    config
        .routing
        .rules
        .iter()
        .map(|rule| (rule.name.clone(), rule_target(rule), rule.action.clone()))
        .collect()
}

fn rules_rows(plain: &[(String, String, String)]) -> Vec<RuleRow> {
    plain
        .iter()
        .map(|(name, target, action)| RuleRow {
            name: SharedString::from(name.as_str()),
            target: SharedString::from(target.as_str()),
            action: SharedString::from(action.as_str()),
        })
        .collect()
}

struct Ui {
    regions_all: Vec<String>,
    favorites: HashSet<String>,
    fav_path: std::path::PathBuf,
}

impl Ui {
    fn regions_model(&self, search: &str) -> Vec<RegionRow> {
        let search = search.to_lowercase();
        let mut rows: Vec<RegionRow> = self
            .regions_all
            .iter()
            .filter(|code| {
                search.is_empty()
                    || code.to_lowercase().contains(&search)
                    || country_name(code).to_lowercase().contains(&search)
            })
            .map(|code| RegionRow {
                code: SharedString::from(code.as_str()),
                label: SharedString::from(
                    format!("{} {} ({})", flag(code), country_name(code), code).as_str(),
                ),
                fav: self.favorites.contains(code),
            })
            .collect();
        rows.sort_by_key(|row| !row.fav);
        rows
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _runtime_guard = runtime.enter();

    let config_dir = Config::config_dir()?;
    std::fs::create_dir_all(&config_dir)?;
    let config = Config::load_from_dir(&config_dir).unwrap_or_default();
    let handle = Engine::start(config, config_dir.clone());

    let fav_path = config_dir.join("favorites.txt");
    let favorites: HashSet<String> = std::fs::read_to_string(&fav_path)
        .map(|text| text.lines().map(|line| line.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default();

    let ui_state = Rc::new(RefCell::new(Ui {
        regions_all: psi_psiphon::default_regions(),
        favorites,
        fav_path,
    }));

    let window = MainWindow::new()?;
    window.set_app_icon(rgba(include_bytes!("../assets/app-64.rgba"), 64));

    let tray = Tray::new()?;
    tray.set_icon_off(rgba(include_bytes!("../assets/tray-off.rgba"), 32));
    tray.set_icon_on(rgba(include_bytes!("../assets/tray-on.rgba"), 32));
    tray.set_icon_busy(rgba(include_bytes!("../assets/tray-busy.rgba"), 32));

    let regions_model = Rc::new(VecModel::<RegionRow>::default());
    let rules_model = Rc::new(VecModel::<RuleRow>::default());
    let log_model = Rc::new(VecModel::<SharedString>::default());
    window
        .global::<Logic>()
        .set_regions(ModelRc::from(regions_model.clone()));
    window
        .global::<Logic>()
        .set_rules(ModelRc::from(rules_model.clone()));
    window
        .global::<Logic>()
        .set_log_lines(ModelRc::from(log_model.clone()));
    regions_model.set_vec(ui_state.borrow().regions_model(""));

    // --- очередь событий движка -> UI ---
    let queue: Arc<Mutex<Vec<UiEvent>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let queue = Arc::clone(&queue);
        let bus = handle.bus();
        runtime.spawn(async move {
            let mut rx = bus.subscribe();
            loop {
                match rx.recv().await {
                    Ok(Event::Log(text)) => queue.lock().unwrap_or_else(|e| e.into_inner()).push(UiEvent::Log(text)),
                    Ok(Event::Route { dst, outbound }) => queue
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(UiEvent::Log(format!("{dst} → {outbound}"))),
                    Ok(Event::Regions(regions)) => queue
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(UiEvent::Regions(regions)),
                    Ok(Event::State(state)) => {
                        let text = match state {
                            ConnState::Idle => "отключено".to_string(),
                            ConnState::Bootstrapping { strategy } => format!("гонка стратегий: {strategy}"),
                            ConnState::Connecting { .. } => "подключение…".to_string(),
                            ConnState::Connected { region, via } => format!("подключено: {region} через {via}"),
                            ConnState::Error(error) => format!("ошибка: {error}"),
                        };
                        queue.lock().unwrap_or_else(|e| e.into_inner()).push(UiEvent::Log(text));
                    }
                    Ok(Event::Stats { .. }) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    let send = {
        let handle = handle.clone();
        move |cmd: Cmd| {
            let handle = handle.clone();
            tokio::spawn(async move { handle.send(cmd).await });
        }
    };

    // --- первичный снимок конфига ---
    {
        let handle = handle.clone();
        let queue = Arc::clone(&queue);
        runtime.spawn(async move {
            if let Some(snapshot) = handle.snapshot().await {
                let psi = snapshot.config.psiphon.clone();
                queue.lock().unwrap_or_else(|e| e.into_inner()).push(UiEvent::SnapshotData {
                    rules: rules_plain(&snapshot.config),
                    preset: snapshot.config.routing.preset.clone(),
                    system_proxy: snapshot.config.inbound.system_proxy,
                    psi_channel: psi.propagation_channel_id.clone(),
                    psi_sponsor: psi.sponsor_id.clone(),
                    psi_url: psi.remote_server_list_url.clone(),
                    psi_key: psi.remote_server_list_signature_public_key.clone(),
                });
            }
        });
    }

    // --- обработчики Logic ---
    {
        let logic = window.global::<Logic>();
        let status_handle = handle.clone();
        let send = send.clone();
        logic.on_toggle_connect(move || {
            let status = status_handle.status();
            if status.connected || status.connecting {
                send(Cmd::Disconnect);
            } else {
                send(Cmd::Connect);
            }
        });
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        let weak = window.as_weak();
        logic.on_pick_region(move |code| {
            send(Cmd::SetRegion(code.to_string()));
            if let Some(window) = weak.upgrade() {
                let label = if code.is_empty() {
                    "Страна: авто".to_string()
                } else {
                    format!("{} {} ({})", flag(&code), country_name(&code), code)
                };
                window.global::<Logic>().set_region_label(SharedString::from(label.as_str()));
                window.global::<Logic>().set_page(0);
            }
        });
    }
    {
        let logic = window.global::<Logic>();
        let ui_state = ui_state.clone();
        let regions_model = regions_model.clone();
        let weak = window.as_weak();
        logic.on_toggle_fav(move |code| {
            let code = code.to_string();
            let search = weak
                .upgrade()
                .map(|w| w.global::<Logic>().get_search_text().to_string())
                .unwrap_or_default();
            {
                let mut state = ui_state.borrow_mut();
                if !state.favorites.remove(&code) {
                    state.favorites.insert(code.clone());
                }
                let text: Vec<&String> = state.favorites.iter().collect();
                let joined = text.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n");
                let _ = std::fs::write(&state.fav_path, joined);
            }
            regions_model.set_vec(ui_state.borrow().regions_model(&search));
        });
    }
    {
        let logic = window.global::<Logic>();
        let ui_state = ui_state.clone();
        let regions_model = regions_model.clone();
        let weak = window.as_weak();
        logic.on_search_edited(move || {
            let search = weak
                .upgrade()
                .map(|w| w.global::<Logic>().get_search_text().to_string())
                .unwrap_or_default();
            regions_model.set_vec(ui_state.borrow().regions_model(&search));
        });
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        logic.on_set_preset(move |preset| send(Cmd::SetPreset(preset.to_string())));
    }
    {
        let logic = window.global::<Logic>();
        let handle = handle.clone();
        let weak = window.as_weak();
        let queue = Arc::clone(&queue);
        logic.on_run_test(move || {
            let input = weak
                .upgrade()
                .map(|w| w.global::<Logic>().get_test_text().to_string())
                .unwrap_or_default();
            let handle = handle.clone();
            let queue = Arc::clone(&queue);
            tokio::spawn(async move {
                if let Some(answer) = handle.test_route(&input).await {
                    queue
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(UiEvent::TestResult(answer));
                }
            });
        });
    }

    // обновить модели правил после изменения
    let refresh_rules = {
        let handle = handle.clone();
        let queue = Arc::clone(&queue);
        move || {
            let handle = handle.clone();
            let queue = Arc::clone(&queue);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(350)).await;
                if let Some(snapshot) = handle.snapshot().await {
                    queue
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(UiEvent::Rules(rules_plain(&snapshot.config)));
                }
            });
        }
    };
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        let weak = window.as_weak();
        let refresh_rules = refresh_rules.clone();
        logic.on_add_rule(move || {
            if let Some(window) = weak.upgrade() {
                let logic = window.global::<Logic>();
                let domain = logic.get_add_domain().to_string();
                let domain = domain.trim().trim_start_matches('.').to_string();
                if domain.is_empty() {
                    return;
                }
                let actions = ["direct", "dpi", "vless", "psiphon", "warp", "block"];
                let action = actions
                    .get(logic.get_add_action_index() as usize)
                    .copied()
                    .unwrap_or("psiphon");
                send(Cmd::UpsertRule(RuleCfg {
                    name: format!("{domain} → {action}"),
                    matcher: MatchCfg {
                        domain_suffix: vec![domain],
                        ..MatchCfg::default()
                    },
                    action: action.to_string(),
                    ..RuleCfg::default()
                }));
                logic.set_add_domain(SharedString::from(""));
                refresh_rules();
            }
        });
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        let refresh_rules = refresh_rules.clone();
        logic.on_delete_rule(move |idx| {
            if idx >= 0 {
                send(Cmd::DeleteRule(idx as usize));
                refresh_rules();
            }
        });
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        let weak = window.as_weak();
        logic.on_import_vless(move || {
            if let Some(window) = weak.upgrade() {
                let uri = window.global::<Logic>().get_vless_uri().to_string();
                if !uri.trim().is_empty() {
                    send(Cmd::ImportVless(uri));
                    window.global::<Logic>().set_vless_uri(SharedString::from(""));
                }
            }
        });
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        let weak = window.as_weak();
        logic.on_save_psiphon(move || {
            if let Some(window) = weak.upgrade() {
                let logic = window.global::<Logic>();
                send(Cmd::SetPsiphonParams {
                    propagation_channel_id: logic.get_psi_channel().to_string(),
                    sponsor_id: logic.get_psi_sponsor().to_string(),
                    remote_server_list_url: logic.get_psi_url().to_string(),
                    remote_server_list_signature_public_key: logic.get_psi_key().to_string(),
                });
            }
        });
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        logic.on_register_warp(move || send(Cmd::RegisterWarp));
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        logic.on_scan_ips(move || send(Cmd::ScanCleanIps));
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        logic.on_scan_warp(move || send(Cmd::ScanWarp));
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        logic.on_autotune(move || send(Cmd::AutotuneDpi));
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        logic.on_sysproxy_changed(move |on| send(Cmd::ToggleSystemProxy(on)));
    }
    {
        let logic = window.global::<Logic>();
        let send = send.clone();
        logic.on_quit_app(move || {
            send(Cmd::Disconnect);
            let _ = slint::quit_event_loop();
        });
    }

    // --- трей ---
    {
        let weak = window.as_weak();
        tray.on_show_window(move || {
            if let Some(window) = weak.upgrade() {
                let _ = window.show();
                window.window().set_minimized(false);
            }
        });
    }
    {
        let status_handle = handle.clone();
        let send = send.clone();
        tray.on_toggle(move || {
            let status = status_handle.status();
            if status.connected || status.connecting {
                send(Cmd::Disconnect);
            } else {
                send(Cmd::Connect);
            }
        });
    }
    {
        let send = send.clone();
        tray.on_quit(move || {
            send(Cmd::Disconnect);
            let _ = slint::quit_event_loop();
        });
    }

    // закрытие окна = свернуть в трей (выход — через меню трея или Настройки)
    window
        .window()
        .on_close_requested(|| slint::CloseRequestResponse::HideWindow);

    // --- таймер: события + статус ---
    let timer = slint::Timer::default();
    {
        let weak = window.as_weak();
        let tray_weak = tray.as_weak();
        let queue = Arc::clone(&queue);
        let ui_state = ui_state.clone();
        let regions_model = regions_model.clone();
        let log_model = log_model.clone();
        let status_handle = handle.clone();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(500),
            move || {
                let Some(window) = weak.upgrade() else { return };
                let logic = window.global::<Logic>();

                let events: Vec<UiEvent> = {
                    let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
                    std::mem::take(&mut *queue)
                };
                for event in events {
                    match event {
                        UiEvent::Log(text) => {
                            log_model.push(SharedString::from(text.as_str()));
                            while log_model.row_count() > 200 {
                                log_model.remove(0);
                            }
                        }
                        UiEvent::Regions(regions) => {
                            let search = logic.get_search_text().to_string();
                            ui_state.borrow_mut().regions_all = regions;
                            regions_model.set_vec(ui_state.borrow().regions_model(&search));
                        }
                        UiEvent::Rules(plain) => {
                            rules_model.set_vec(rules_rows(&plain));
                        }
                        UiEvent::TestResult(answer) => {
                            logic.set_test_result(SharedString::from(answer.as_str()));
                        }
                        UiEvent::SnapshotData {
                            rules,
                            preset,
                            system_proxy,
                            psi_channel,
                            psi_sponsor,
                            psi_url,
                            psi_key,
                        } => {
                            rules_model.set_vec(rules_rows(&rules));
                            logic.set_preset_name(SharedString::from(preset.as_str()));
                            logic.set_system_proxy(system_proxy);
                            logic.set_psi_channel(SharedString::from(psi_channel.as_str()));
                            logic.set_psi_sponsor(SharedString::from(psi_sponsor.as_str()));
                            logic.set_psi_url(SharedString::from(psi_url.as_str()));
                            logic.set_psi_key(SharedString::from(psi_key.as_str()));
                        }
                    }
                }

                let status = status_handle.status();
                logic.set_connected(status.connected);
                logic.set_connecting(status.connecting);
                logic.set_status_text(SharedString::from(
                    if status.connecting {
                        "Подключение…".to_string()
                    } else if status.connected {
                        format!("Подключено · {}", status.region)
                    } else if let Some(error) = &status.error {
                        format!("Ошибка: {error}")
                    } else {
                        "Отключено".to_string()
                    }
                    .as_str(),
                ));
                logic.set_strategy_text(SharedString::from(
                    if status.connected { status.strategy.as_str() } else { "—" },
                ));
                logic.set_ping_text(SharedString::from(
                    status
                        .ping_ms
                        .map(|ms| format!("{ms} мс"))
                        .unwrap_or_else(|| "—".to_string())
                        .as_str(),
                ));
                logic.set_up_text(SharedString::from(fmt_speed(status.up_bps).as_str()));
                logic.set_down_text(SharedString::from(fmt_speed(status.down_bps).as_str()));

                if let Some(tray) = tray_weak.upgrade() {
                    tray.set_connected(status.connected);
                    tray.set_busy(status.connecting);
                }
            },
        );
    }

    window.run()?;
    drop(timer);
    Ok(())
}
