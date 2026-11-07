# Roadmap (отмечать [x] после шага)

- [x] 00 Промпт-план, архитектура, репозиторий
- [x] 01 Workspace-скелет + psi-config + psi-core (трейты, SOCKS5/HTTP inbound, DIRECT outbound)
  - Сделано: workspace (psi-config, psi-core), загрузка/сохранение TOML с deep-merge и выносом секретов в `config.local.toml`, `Target/Outbound/BoxStream/Event/EventBus`, `DirectOutbound`, `MixedInbound` (SOCKS5 + HTTP CONNECT/proxy) со счётчиками `Event::Stats`.
  - Тесты: парсинг SOCKS5 (IPv4/домен), merge конфигов, разделение секретов, подсчёт событий, DIRECT-connect. `cargo check`, `clippy -D warnings`, `cargo test` зелёные.
  - Осталось: реальный append фактического трафика в UI появится вместе с движком (шаг 09).
- [ ] 02 psi-psiphon: сайдкар, config.json, notices, страны
- [ ] 03 psi-vless: VLESS-WS-TLS клиент + early-data; модернизация Worker
- [ ] 04 psi-dpi: DPI-мост (TLS split/фрагментация), DoH
- [ ] 05 psi-warp: WARP + boringtun + AWG-junk + сканер эндпоинтов
- [ ] 06 psi-bootstrap: гонка стратегий + кэш
- [ ] 07 psi-router: правила, geoip/geosite, пресеты
- [ ] 08 psi-tun: TUN-режим, fake-ip DNS, защита от петель
- [ ] 09 psi-engine: сборка движка, команды, CLI
- [ ] 10 app: Tauri 2 UI + трей + выбор стран
- [ ] 11 CI/релизы: сборка psiphon, wintun, установщики, автообновление списков
