# Шаг 06 — psi-bootstrap (гонка путей к Psiphon)

## Сделать
1. `NetworkFingerprint::current()` — hash(IP шлюза + MAC шлюза/SSID) через crate `netdev` (default gateway). Используется как `NetworkID` Psiphon и ключ кэша.
2. `Strategy { tag, prepare: async -> Option<UpstreamUrl> }`: `direct` → None; `dpi` → поднять psi-dpi SOCKS на 127.0.0.1:0, вернуть `socks5://...`; `vless` → psi-vless мост; `warp` → psi-warp мост. Стратегия без конфига пропускается.
3. `race(strategies, cfg) -> Winner{tag, instance: PsiphonInstance, bridge}`:
   - порядок: сначала победитель из кэша (`bootstrap_cache.json`: fingerprint → tag, last_ok), остальные по `order`;
   - старт каждой следующей через `stagger_ms` (300 мс; если кэш есть — первой даётся фора 1500 мс);
   - у каждой стратегии свой `DataRootDirectory` = `data/psiphon/<tag>` (bolt-БД Psiphon блокируется одним процессом);
   - первый `Tunnels{count>=1}` побеждает: остальные `stop()` + их мосты гасятся (CancellationToken из tokio-util);
   - общий таймаут `timeout_s`; события `ConnState::Bootstrapping{strategy}` в шину.
4. Сохранить победителя в кэш. Фоновая задача раз в 15 мин: если победил не `direct`, тихо проверить `direct` (отдельный инстанс, без трафика) и при успехе предложить/переключить (флаг `auto_promote`).
5. Reconnect: при `Tunnels{count:0}` > 20 с — повторная гонка (с кэшем).
## Проверка
`cargo check`; тест гонки на фейковых стратегиях (tokio::time::pause): побеждает самая быстрая, проигравшие отменены.
