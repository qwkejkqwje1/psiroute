# Шаг 03 — psi-vless (VLESS-WS-TLS + early-data) и модернизация Worker

## A. Клиент (крейт psi-vless)
1. Протокол VLESS запрос: `[0x00][UUID 16B][0x00 addons_len][0x01 cmd TCP][port u16 BE][atyp: 1=IPv4,2=domain(len+bytes),3=IPv6][addr]` + сразу первые данные приложения. Ответ сервера: `[0x00][addons_len][addons]` — отбросить перед отдачей данных.
2. Транспорт: TCP → TLS (rustls + webpki-roots, ALPN `http/1.1`, SNI=`sni`) → WebSocket upgrade на `wss://{host}{path}`; заголовок `Host: host`, обычный браузерный `User-Agent`.
3. Early-data (0-RTT): дождаться первых байт от приложения (≤ 50 мс, ≤ `early_data` байт), склеить `VLESS-заголовок + данные`, закодировать base64url без паддинга и положить в `Sec-WebSocket-Protocol`. Если данных не было — отправить заголовок первым WS-binary-фреймом.
   - tokio-tungstenite проверяет, что сервер вернул subprotocol → Worker обязан эхо-вернуть этот заголовок (см. B). Альтернатива: `fastwebsockets` (быстрее, без проверки) — можно выбрать её.
4. Адаптер WS↔AsyncRead/AsyncWrite (`VlessStream`), бинарные фреймы, без лишних копий (`Bytes`).
5. Подключение к `clean_ips` (если заданы): TCP к IP, SNI/Host = домен. Функция `scan_clean_ips(ranges, ports=[443,8443,2053,2083,2087,2096], n=64)`: параллельно (32) TCP+TLS+WS-handshake, сортировка по задержке, топ-5 сохранить в конфиг.
   - Тест «16КБ-заморозки» ТСПУ: через туннель скачать ≥100 КБ с НЕ-Cloudflare хоста (напр. `https://proof.ovh.net/files/1Mb.dat`, Range 0-131071). Если зависло на ~16 КБ — пометить IP плохим.
6. Опция: применять DPI-фрагментацию из psi-dpi к TLS ClientHello до Worker (флаг `fragment=true`), интерфейс-хук оставить сейчас.
7. `VlessOutbound: Outbound` + `vless://` URI парсер (`vless://UUID@host:port?type=ws&security=tls&sni=..&host=..&path=%2Fapi%2Fv1%2Fstream%3Fed%3D2048`).
8. Локальный SOCKS-мост `serve_socks(addr)` (MixedInbound → VlessOutbound) — его отдаём Psiphon как `UpstreamProxyURL`.

## B. Worker (папка `worker/`, пользователь вставит свой код ~150 строк)
Модернизировать, сохранив путь `/api/v1/stream`, проверку UUID и страницу-прикрытие:
1. Ответ 101 эхо-возвращает `Sec-WebSocket-Protocol`, если он был (иначе строгие клиенты рвут соединение).
2. UUID и путь — из `env` (`wrangler secret put UUID`, `WS_PATH`), поддержка нескольких UUID через запятую; сравнение UUID в постоянном времени.
3. `PROXYIP` fallback: если `connect()` к цели падает/цель в сети Cloudflare (Workers не коннектятся к IP CF) — повторить через `env.PROXYIP` (host:port). Иначе часть CDN-фронтов Psiphon не откроется.
4. UDP только для DNS: VLESS cmd=0x02 на порт 53 → DNS-over-HTTPS к 1.1.1.1 (`fetch`), остальное UDP — отклонять.
5. `/api/v1/dns` — DoH-релей (для psi-dpi, когда 1.1.1.1 заблокирован).
6. Прикрытие: на чужие пути отдавать правдоподобный сайт (`fetch` к реальной статической странице) с кэшем.
7. `wrangler.toml`, деплой на **свой домен** (не `*.workers.dev`), README по деплою.
## Проверка
`cargo check`; юнит-тест сериализации VLESS-заголовка (domain и IPv4) и парсинга `vless://`.
