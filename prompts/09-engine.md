# Шаг 09 — psi-engine + psiroute-cli

## Сделать
1. `Engine::start(cfg) -> Handle`; `Handle { events: broadcast::Receiver<Event>, cmd: mpsc::Sender<Cmd> }`.
   `Cmd`: `Connect, Disconnect, SetRegion(String), SetPreset(String), UpsertRule(RuleCfg), DeleteRule(idx), ReloadConfig, TestRoute(String) -> oneshot<Explain>, ScanCleanIps, ScanWarp, AutotuneDpi, ToggleTun(bool), ToggleSystemProxy(bool)`.
2. Сборка: bootstrap → Psiphon-выход; карта outbounds `{direct, dpi, psiphon, vless, warp, block}`; MixedInbound(7890) → router → outbound; TUN по флагу.
3. Системный прокси: Windows — реестр `Internet Settings` (ProxyEnable, ProxyServer=127.0.0.1:7890, ProxyOverride=<local>;localhost;127.*) + `InternetSetOption` refresh; macOS `networksetup`; Linux gsettings. Откат при выходе.
4. Состояние/статистика: скорость up/down (скользящее 1 с), текущая страна, стратегия, пинг (TCP-handshake через выход до `1.1.1.1:443` раз в 30 с).
5. `crates/psiroute-cli` (clap): `psiroute connect [--region DE] [--tun]`, `psiroute regions`, `psiroute route <domain>`, `psiroute scan warp|ips`, `psiroute dpi autotune`. Лог в консоль.
## Проверка
`cargo build -p psiroute-cli --release` (только сборка).
