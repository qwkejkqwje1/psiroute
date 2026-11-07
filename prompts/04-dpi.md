# Шаг 04 — psi-dpi (обход DPI ТСПУ без драйверов)

Цель: прямые TCP-соединения, которые ТСПУ режет по SNI/Host, должны проходить. Userspace, без WinDivert (как byedpi/ciadpi, SpoofDPI).

## Сделать
1. `DpiOutbound: Outbound` — TCP connect (nodelay), затем перехват ПЕРВОЙ записи клиента:
   - если это TLS ClientHello (`0x16 0x03 ..`, handshake type 0x01) — найти смещение SNI (парсер extensions, тип 0x0000);
   - если HTTP — найти `Host:`.
2. Стратегии (enum, комбинируемые, порядок важен):
   - `split(pos)` — отправить байты [0..pos] отдельным TCP-сегментом (write+flush, пауза 1–5 мс), потом остальное. `pos`: число | `sni` (середина имени) | `sni+1`.
   - `tlsrec(pos)` — разрезать ClientHello на 2+ TLS-записи (новый 5-байтовый заголовок `16 03 01 len` для каждой части). Самая эффективная против ТСПУ.
   - `disorder(pos)` — первый сегмент с `IP_TTL=1..3` (socket2 `set_ttl`), затем вернуть TTL и отправить остальное (сегмент будет перепослан ОС, DPI видит беспорядок).
   - `oob` — вставить 1 байт OOB (`send` с MSG_OOB) между частями (Windows/Linux).
   - HTTP: `Host` → `hOsT`, пробел/таб после двоеточия, split на Host.
3. Пресеты: `tlsrec+split(sni)` (по умолчанию), `disorder(1)`, `split(1)+oob`, `tlsrec(sni)+disorder(sni)`.
4. `autotune(test_hosts)` — перебрать пресеты на хостах `["www.youtube.com","rutracker.org","x.com","discord.com"]` (TLS handshake + HEAD), сохранить лучший в конфиг. Параллельно ≤4.
5. DoH-резолвер (`hickory-resolver` с `dns-over-https-rustls`): список `doh` из конфига (по умолчанию `https://cloudflare-dns.com/dns-query`, `https://dns.google/dns-query`, `https://dns.quad9.net/dns-query`, + свой `https://<worker>/api/v1/dns`), кэш, гонка серверов. Сам DoH-трафик тоже через DpiOutbound.
6. SOCKS-мост `serve_socks(addr)` → для Psiphon `UpstreamProxyURL` в стратегии `dpi`.
7. (опц., флаг) Интеграция внешних движков: если рядом лежит `ciadpi`(byedpi) или `winws`(zapret) — запуск как сайдкар-SOCKS/драйвер. Только конфиг-описание и запуск процесса.
## Проверка
`cargo check`; тест: на фикстуре ClientHello `tlsrec` даёт две валидные TLS-записи, склейка = исходник.
