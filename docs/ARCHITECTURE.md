# Архитектура PsiRoute Go (v2.3.0)

## Каноничный стек
- **Ядро**: единый бинарь на Go (`package main`), встроенный `psiphon-tunnel-core`, userspace `wireguard-go` + `gvisor/netstack`, Wintun (`wintun.dll`) для режима TUN.
- **Каноничный UI**: нативный аппаратно-ускоренный **Go/Gio GUI** (Obsidian Pro / тактический интерфейс «пульт управления», 5 экранов + закреплённый Status Bar).
- **Web UI**: облегчённая веб-панель мониторинга и управления на `http://127.0.0.1:9090` поверх единого HTTP API с CSRF-токеном `X-Psiroute`.
- **Портативность**: все кэши, конфиги, списки, временные файлы и отчёты строго изолированы в `dataDir` рядом с `psiroute.exe`.

## Конечный автомат ядра (`core_fsm.go`)
Единый FSM координирует состояние туннелей и публикует неизменяемые снапшоты состояния (`CoreFSMSnapshot`) в UI:
`Idle → Bootstrapping → Connecting → Connected → Degraded → Reconnecting → Stopping`
Шкала стадий запуска: `Bootstrap → Obfs → Tunnel → Check → Ready`.

## Интерфейс транспортов (`ChainDialer`) и каскад Clean-IP (`clean_chain.go`)
Все выходы (`direct`, `direct-dpi`, `psiphon`, `psiphon:XX`, `warp`, `clean-ip`) реализуют единый контракт `ChainDialer` без создания дополнительных TUN-адаптеров в Windows:
- **Звено 1 (`EntryWarp`)**: userspace WireGuard netstack (MTU `1280`), привязанный к физическому адаптеру Windows (`IP_UNICAST_IF`) с обфускацией AmneziaWG `I1–I5`. В адаптивном режиме `Auto-Chain` подключается автоматически только при блокировке прямого входа.
- **Звено 2 (`Psiphon` / VLESS)**: транзитный туннель в выбранную страну.
- **Звено 3 (`ExitWarp`)**: второй независимый userspace WireGuard netstack (MTU `1200`, собственный `warp-exit-identity.json`), работающий поверх `udpgw` TCP-моста через Звено 2 (`tunnelUDPBind`).
- **MTU & TCP MSS Clamping (`tun.go`, `tun_util.go`)**: при активном `clean-ip` каскаде TCP MSS принудительно зажимается до `<= 1140` (IPv4) / `<= 1120` (IPv6) на входе и выходе единственного Wintun-адаптера.

## Защита от утечек на Windows (`wfp_windows.go`, `tun_windows.go`, `tun.go`, `netwatch_windows.go`)
1. **WFP Kill Switch (`wfp_windows.go`)**: 3 режима (`off`, `auto`, `strict`) через Windows Filtering Platform (`fwpuclnt.dll`) с разрешением loopback, RFC1918 LAN, самого `psiroute.exe` и адаптера Wintun, плюс автоматическая очистка сиротских фильтров при старте после аварийного завершения.
2. **IPv6 Blackhole (`tun_windows.go`, `tun.go`)**: при `tun.ipv6 = false` маршруты `::/1` и `8000::/1` всё равно перехватываются на TUN, а все IPv6-пакеты сбрасываются внутри gVisor, исключая утечку нативного IPv6 провайдера.
3. **Строгий Split-DNS (`tun.go`, `dns.go`)**: перехват TCP/UDP 53, блокировка DoT (853) и публичных DoH IP/доменов, запрет отката DNS-запросов туннелируемых доменов в `obDirect` при включённом Kill Switch или обрыве Psiphon, сброс `DnsFlushResolverCache`.
4. **Событийный мониторинг сети (`netwatch_windows.go`)**: подписка на `NotifyRouteChange2` (`iphlpapi.dll`) для мгновенной реакции на смену шлюза/Wi-Fi и перепривязку `IP_UNICAST_IF` без задержек поллинга.
5. **Умный Watchdog (`psi.go`)**: детектирование «тихой блокировки» ТСПУ (передача контрольного чанка `>= 32 КБ` через туннель и переключение стратегии при 2 сбоях подряд).
