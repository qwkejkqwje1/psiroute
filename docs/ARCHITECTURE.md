# Архитектура PsiRoute

## Идея
Psiphon-ядро (Go, `psiphon-tunnel-core`) **не переписываем** — это годы работы над обфускацией (OSSH, TLS-OSSH, meek/CDN-fronting, QUIC, Conduit/inproxy). Rust-приложение — это **оркестратор + сетевой стек + роутер + UI**:

```
 Приложения ──► [TUN (wintun/utun/tun)] ─┐
 Браузер ────► [Mixed inbound SOCKS5/HTTP :7890] ─┤
                                           ▼
                                  ┌─── ROUTER (правила) ───┐
                                  ▼        ▼        ▼      ▼
                              DIRECT  DIRECT+DPI  PSIPHON  BLOCK
                                         (frag)      │
                                                     ▼
                     psiphon-tunnel-core (сайдкар, SOCKS :1080 локально)
                                 │ UpstreamProxyURL (только если прямой путь заблокирован)
                                 ▼
                 ┌──────── BOOTSTRAP RACER (гонка путей) ────────┐
                 ▼                ▼                 ▼             ▼
              напрямую      DPI-frag SOCKS    VLESS-WS-TLS     WARP (boringtun
                                              (CF Worker)      + AWG-junk) SOCKS
```

## Крейты (cargo workspace)
| Крейт | Назначение | Ключевые зависимости |
|---|---|---|
| `psi-config` | TOML-конфиг, профили, пресеты, пути (`directories`) | serde, toml |
| `psi-core` | Общие трейты: `Outbound`, `Inbound`, `Event`-шина (tokio broadcast), SOCKS5/HTTP inbound | tokio, bytes |
| `psi-psiphon` | Управление сайдкаром: генерация config.json, запуск, парсинг JSON-notices, страны | tokio::process, serde_json |
| `psi-vless` | VLESS поверх WS+TLS, early-data (0-RTT) | tokio-tungstenite, rustls, uuid |
| `psi-dpi` | Обход DPI в userspace: split/фрагментация TLS ClientHello, DoH | rustls (работаем с байтами), hickory-proto + h2 (DoH через DpiOutbound) |
| `psi-warp` | Регистрация WARP, WireGuard (boringtun) + AmneziaWG-junk, перебор эндпоинтов, SOCKS-выход через smoltcp | boringtun, smoltcp |
| `psi-bootstrap` | Гонка стратегий, кэш победителя на сеть | — |
| `psi-router` | Движок правил: domain/suffix/keyword/regex, CIDR, geoip(mmdb), geosite(списки), process, port | maxminddb, ipnet, regex, aho-corasick |
| `psi-tun` | TUN + userspace TCP/IP (ipstack), fake-ip DNS, защита от петель | tun-rs, ipstack |
| `psi-engine` | Движок-библиотека: `Engine::start(cfg) -> Handle{events, cmd}`; используется Tauri in-process + бинарь `psiroute-cli` | всё выше |
| `app` | Tauri 2 GUI + трей | tauri 2, svelte/solid (лёгкий фронт) |

## Контракты (не ломать)
```rust
// psi-core
#[async_trait] pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect_tcp(&self, dst: &Target) -> Result<BoxStream>; // BoxStream: AsyncRead+AsyncWrite+Unpin+Send
    async fn health(&self) -> Health; // латентность/ок
}
pub enum Target { Domain(String, u16), Ip(SocketAddr) }
pub enum Event { State(ConnState), Log(String), Stats{up:u64, down:u64}, Regions(Vec<String>), Route{dst:String, outbound:String} }
```
`ConnState`: `Idle | Bootstrapping{strategy} | Connecting{region} | Connected{region, via} | Error(String)`.

```rust
// psi-dpi
pub enum SplitAt { Fixed(usize), Sni, SniPlusOne }
pub enum Strategy { Split(SplitAt), TlsRec(SplitAt), Disorder{at: SplitAt, ttl: u8}, Oob(SplitAt), HttpHost }
pub struct StrategyPlan { pub actions: Vec<Strategy> } // presets(): tlsrec+split(sni), disorder(1), split(1)+oob, tlsrec(sni)+disorder(sni)
pub struct DpiOutbound; // impl Outbound; перехватывает первую запись и применяет StrategyPlan
pub struct DohResolver;  // resolve(name) -> Vec<IpAddr>; DoH-трафик идёт через DpiOutbound
```

## Psiphon: как подключаем
- Бинарь `psiphon-tunnel-core` ConsoleClient (собираем в CI из github.com/Psiphon-Labs/psiphon-tunnel-core, `go build ./ConsoleClient`).
- config.json генерирует Rust: `PropagationChannelId`, `SponsorId`, `RemoteServerListUrl`, `RemoteServerListSignaturePublicKey`, `EgressRegion` (страна, "" = лучшая), `LocalSocksProxyPort`, `LocalHttpProxyPort`, `UpstreamProxyURL` (socks5://127.0.0.1:PORT от VLESS/WARP/DPI-моста), `LimitTunnelProtocols` (опционально), `DataRootDirectory`, `EmitBytesTransferred: true`, `EmitDiagnosticNotices`.
- ID и ключи — из публичных клиентов/документации, хранятся в `config.local.toml`, в git не попадают.
- Notices (JSON-строки в stderr): `Tunnels{count}` → Connected; `AvailableEgressRegions{regions}` → список стран в UI; `ActiveTunnel`; `BytesTransferred` → скорость; `ListeningSocksProxyPort`.
- Смена страны = перезапуск сайдкара с новым `EgressRegion` (быстро: data dir сохраняет серверный список).

## Bootstrap racer (главное для РФ)
Стратегии запускаются **параллельно со сдвигом 300 мс** (happy-eyeballs), побеждает первая, давшая `Tunnels{count>=1}`; остальные гасятся:
1. `direct` — Psiphon как есть.
2. `dpi` — Psiphon через локальный DPI-мост (фрагментация ClientHello для TLS/meek-протоколов).
3. `vless` — Psiphon через свой CF Worker (TCP-протоколы Psiphon проходят через `cloudflare:sockets`).
4. `warp` — Psiphon через WARP (WireGuard+AWG-junk).
5. (опц.) `psiphon-inproxy` — Conduit/in-proxy режим самого Psiphon.
Победитель кэшируется по «отпечатку сети» (hash шлюза+SSID) → следующий запуск начинает с него, остальные через 1.5 с. **Скорость**: после подключения цепочка не меняется; если победил `direct`, лишних хопов нет. Фоновая проверка раз в N минут может «повысить» на более короткий путь.

## Маршрутизация (просто для пользователя, мощно внутри)
Режимы-пресеты (1 клик): 
- **«Умный (РФ)»** — российские домены/IP напрямую, заблокированное → Psiphon, реклама → block.
- **«Только заблокированное»** — списки runetfreedom/antifilter → Psiphon, остальное напрямую.
- **«Всё через VPN»**.
- **«Свои правила»** — редактор: правило = условие + действие (`direct | dpi | psiphon | vless | warp | block`), drag-n-drop порядок, тест «куда пойдёт домен X».
Источники списков (автообновление): `runetfreedom/russia-v2ray-rules-dat` (geosite/geoip RU, ru-blocked), `itdoginfo/allow-domains`, MaxMind/DB-IP mmdb.

## Важные ограничения
- CF Worker не может `connect()` к IP Cloudflare и не делает UDP → используем только для TCP-протоколов Psiphon/правил. Для Psiphon QUIC — не через Worker.
- TUN требует прав администратора (Windows: wintun.dll рядом с exe; сервис-помощник).
- Петли: исходящие сокеты сайдкаров/движка привязываются к физическому интерфейсу (`IP_UNICAST_IF` на Windows, `SO_BINDTODEVICE` на Linux), процесс psiphon исключён из TUN.

## Готовые решения (референсы, не копировать слепо)
- `Psiphon-Labs/psiphon-tunnel-core` — ядро (сайдкар).
- `bepass-org/warp-plus` (Go) — WARP + сканер + режим Psiphon-over-WARP с выбором страны: ближайший аналог идеи.
- `aramperes/onetun` (Rust) — boringtun + smoltcp → TCP-форвардинг (основа psi-warp).
- `tun2proxy/tun2proxy`, `narrowlink/ipstack` (Rust) — TUN → SOCKS (основа psi-tun).
- `hufrea/byedpi`, `bol-van/zapret`, `xvzc/SpoofDPI`, `ValdikSS/GoodbyeDPI` — техники обхода DPI (psi-dpi).
- `amnezia-vpn/amneziawg-go` — junk/I1-пакеты (обфускация WG).
- `runetfreedom/russia-v2ray-rules-dat`, `itdoginfo/allow-domains` — списки РФ.
- `zizifn/edgetunnel`, `cmliu/edgetunnel` — VLESS на CF Workers (PROXYIP, early-data).
- `SagerNet/sing-box` — эталон правил/TUN/fake-ip (подсматривать логику).
