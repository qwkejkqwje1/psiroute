# Шаг 07 — psi-router (правила маршрутизации)

## Модель (TOML, понятная пользователю)
```toml
[[routing.rules]]
name = "Российские сайты напрямую"
match = { geosite = ["category-ru"], geoip = ["RU"], domain_suffix = [".ru", ".рф", ".su"] }
action = "direct"         # direct | dpi | psiphon | vless | warp | block
[[routing.rules]]
match = { process = ["Telegram.exe"] }
action = "psiphon"
```
Условия в одном `match` — ИЛИ; `all = [...]`, `not = {...}` — для сложных. Поля: `domain, domain_suffix, domain_keyword, domain_regex, geosite, ip_cidr, geoip, process, port (диапазоны "443,8000-9000"), network ("tcp"/"udp")`. Последнее правило — `final` из пресета.

## Сделать
1. Компиляция правил в `CompiledRouter`: suffix — HashSet + проход по меткам домена справа налево; keyword — `aho-corasick`; regex — `RegexSet`; CIDR — prefix-trie (`ip_network_table`); geoip — `maxminddb` (Country mmdb) либо v2ray `geoip.dat`; geosite — v2ray `geosite.dat` (protobuf, структуры вручную через `prost` derive, без build.rs). Punycode: `idna` для `.рф`.
2. `route(&Meta{domain, ip, port, process, network}) -> (Action, rule_idx)` + LRU-кэш решений (`quick_cache`, 10k) + `explain()` для UI («почему так»).
3. Определение процесса по локальному порту: `netstat2` + `sysinfo` (кэш 2 с).
4. Сниффинг домена, если пришёл только IP: TLS SNI / HTTP Host из первых байт (переиспользовать парсер из psi-dpi).
5. Пресеты (`include_str!` из `crates/psi-router/presets/*.toml`):
   - `smart_ru`: реклама(geosite category-ads-all)→block; geosite `ru-blocked`/`ru-blocked-all`→psiphon; `category-ru`, geoip RU, private→direct; final→psiphon.
   - `blocked_only`: ru-blocked→psiphon; youtube/discord → `dpi` (часто достаточно фрагментации, быстрее); final→direct.
   - `all_vpn`: private→direct; final→psiphon.
6. Списки: скачивание/обновление раз в сутки из `runetfreedom/russia-v2ray-rules-dat` (releases/latest: geosite.dat, geoip.dat) и `itdoginfo/allow-domains`; скачивать через уже работающий выход; хранить в data dir; атомарная подмена роутера (`arc-swap`).
## Проверка
`cargo check`; тесты: suffix/keyword/cidr/порядок правил/`.рф`.
