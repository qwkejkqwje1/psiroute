# Шаг 02 — psi-psiphon (сайдкар Psiphon)

Ядро: `psiphon-tunnel-core` ConsoleClient (Go). Запуск: `psiphon-tunnel-core -config <path>/config.json`. Notices — JSON-строки в **stderr**: `{"noticeType":"Tunnels","data":{"count":1},"timestamp":"..."}`.

## Сделать
1. `PsiphonConfig` → serde в config.json (PascalCase-ключи как в psiphon): `PropagationChannelId, SponsorId, RemoteServerListUrl, RemoteServerListSignaturePublicKey, DataRootDirectory, EgressRegion, LocalSocksProxyPort (0=авто), LocalHttpProxyPort, UpstreamProxyURL (опц.), LimitTunnelProtocols (опц.), NetworkID, TunnelPoolSize, EmitBytesTransferred=true, EmitDiagnosticNotices=false, EstablishTunnelTimeoutSeconds`.
2. `PsiphonInstance::spawn(cfg, strategy_tag, data_dir, bus) -> Result<Self>`:
   - `tokio::process::Command`, `kill_on_drop(true)`; Windows: `creation_flags(0x08000000)` (CREATE_NO_WINDOW).
   - Читать stderr построчно, парсить notices → внутренний `watch` состояния + `Event`:
     `ListeningSocksProxyPort{port}`, `ListeningHttpProxyPort{port}`, `Tunnels{count}` (≥1 → Connected), `AvailableEgressRegions{regions}` → `Event::Regions`, `ActiveTunnel{protocol, ...}` → via, `BytesTransferred{sent,received}`, `Alert/Error` → лог.
   - `wait_connected(timeout) -> Result<SocketAddr /*socks*/>`, `stop()`.
3. `PsiphonOutbound`: реализует `Outbound` через SOCKS5-клиент к локальному порту Psiphon (написать мини-клиент SOCKS5 в psi-core, переиспользуется дальше).
4. Смена страны: `restart_with_region(code)` — stop + spawn с тем же data dir (быстро за счёт кэша серверов).
5. Список стран по умолчанию (если notice ещё не пришёл): AT BE BG CA CH CZ DE DK EE ES FI FR GB HU IE IN IT JP LV NL NO PL RO RS SE SG SK US.
## Примечания
- При `UpstreamProxyURL` Psiphon сам использует только TCP-протоколы — это ожидаемо.
- `NetworkID` = отпечаток сети из шага 06 (пока строка "default").
- ID/ключ RSL — из `config.local.toml`; если пусто — понятная ошибка `PsiphonError::MissingCredentials`.
## Проверка
`cargo check`; тест: парсинг 4 примеров notice-строк (зашить как фикстуры).
