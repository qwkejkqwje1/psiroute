# Шаг 08 — psi-tun (режим TUN: весь трафик системы)

## Сделать
1. `tun-rs` (Windows: wintun.dll рядом с exe; Linux/macOS — нативно), адрес 172.19.0.1/30, MTU 9000 (Win 1500), IPv6 fd00:19::1/126.
2. Userspace-стек `ipstack`: TCP → `IpStackTcpStream` → роутер → Outbound → relay; UDP → DIRECT/псифон-SOCKS UDP нет → для UDP: DNS обрабатываем сами, QUIC (UDP 443) к проксируемым направлениям — **отбрасывать** (браузер откатится на TCP), остальное UDP — direct.
3. DNS: перехват UDP/TCP 53 на любой адрес → fake-ip из `198.18.0.0/15` (мап domain↔ip, LRU 65k, TTL 1 с в ответе). Для `direct`-решений реальный IP резолвит DoH-резолвер psi-dpi.
4. Маршруты: `0.0.0.0/1` и `128.0.0.0/1` (+ `::/1`, `8000::/1`) через TUN; DNS адаптера = 172.19.0.2; Windows — низкая метрика интерфейса, иначе DNS-утечки.
5. Защита от петель: ВСЕ исходящие сокеты движка — bind к физическому интерфейсу: Windows `setsockopt(IP_UNICAST_IF / IPV6_UNICAST_IF)` (windows-sys, индекс в network byte order для v4), Linux `SO_BINDTODEVICE` (socket2 `bind_device`), macOS `IP_BOUND_IF` (socket2 `bind_device_by_index_v4`). Реализовать хук `bind_iface` из psi-core.
6. Трафик сайдкара Psiphon попадает в TUN → правило-встроенное «process == psiphon-tunnel-core → direct» ставится ПЕРВЫМ автоматически (сохраняет все протоколы Psiphon, включая QUIC).
7. Kill-switch (опц.): при обрыве держать маршруты, но блокировать (action block) до переподключения.
8. Корректный откат маршрутов/DNS при выходе и панике (guard + обработчик Ctrl-C/завершения сессии Windows).
## Проверка
`cargo check` на windows и linux target (`--target x86_64-pc-windows-msvc` если доступно). Тест fake-ip пула.
