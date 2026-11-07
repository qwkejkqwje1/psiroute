# Шаг 01 — Workspace, psi-config, psi-core

## Сделать
1. Корневой `Cargo.toml` (workspace, resolver = "2"), members: `crates/*`, `app/src-tauri` (добавить позже — пока закомментировать). `[workspace.dependencies]`: tokio (full), anyhow, thiserror, tracing, tracing-subscriber, serde (derive), serde_json, toml, bytes, async-trait, futures, socket2, uuid, base64. `[profile.release]`: lto="fat", codegen-units=1, opt-level=3, strip=true, panic="abort".
2. `crates/psi-config`: структуры из ARCHITECTURE (General, Inbound{mixed_port=7890, tun=false, system_proxy=true}, Psiphon{binary, propagation_channel_id, sponsor_id, remote_server_list_url, remote_server_list_signature_public_key, egress_region, limit_tunnel_protocols:Vec<String>, tunnel_pool_size=1}, Vless:Option{server, port=443, uuid, path="/api/v1/stream", sni, host, early_data=2048, clean_ips:Vec<String>}, Warp:Option{private_key, peer_public_key, endpoint, address_v4, address_v6, reserved:[u8;3], awg:Awg{jc=4,jmin=40,jmax=70,i1:Option<String>}}, Dpi{strategy="tlsrec", split_pos="sni", doh:Vec<String>}, Routing{preset="smart_ru", rules:Vec<RuleCfg>}, Bootstrap{order=["direct","dpi","vless","warp"], stagger_ms=300, timeout_s=25}). Всё `#[serde(default)]`.
   - `Config::load()` = `config.toml` + поверх `config.local.toml` (глубокий merge `toml::Value`). Пути — crate `directories` (`ProjectDirs::from("dev","psiroute","PsiRoute")`).
   - `Config::save()` пишет НЕсекретное в config.toml, секреты (uuid, ключи, ID psiphon) — в config.local.toml.
3. `crates/psi-core`:
   - `Target`, `Outbound` трейт, `BoxStream` (type alias на `Box<dyn AsyncStream>`; `trait AsyncStream: AsyncRead+AsyncWrite+Unpin+Send {}` + blanket impl), `Event`, `ConnState` — как в ARCHITECTURE.
   - `EventBus` = обёртка над `tokio::sync::broadcast` (cap 1024).
   - `DirectOutbound` (TcpStream, nodelay, `connect` с таймаутом 10 с; хук `bind_iface: Option<u32>` пока no-op).
   - `MixedInbound::serve(addr, handler)` — один порт: определить по первому байту SOCKS5 (0x05) / HTTP. SOCKS5: no-auth, CONNECT (ATYP 1/3/4), ответ с BND 0.0.0.0:0. HTTP: `CONNECT host:port` → `200 Connection established`; обычный `GET http://...` → переписать на origin-form и проксировать (Keep-Alive не нужен: `Connection: close`).
   - `handler: Arc<dyn Fn(Target, Meta) -> BoxFuture<Result<BoxStream>>>`; relay через `tokio::io::copy_bidirectional_with_sizes(64KiB,64KiB)`, счётчики байт → Event::Stats раз в 1 с.
## Проверка
`cargo check --workspace`; 1 юнит-тест на парсинг SOCKS5-запроса и 1 на merge конфигов.
