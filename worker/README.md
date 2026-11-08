# Worker — VLESS-WS-TLS на Cloudflare

Модернизированный Worker для `psi-vless`: VLESS поверх WebSocket, early-data,
DNS-over-HTTPS, PROXYIP fallback и страница-прикрытие.

## Что реализовано

- путь туннеля `/api/v1/stream` (настраивается `WS_PATH`);
- ответ `101` эхо-возвращает `Sec-WebSocket-Protocol` (нужно для early-data);
- UUID и путь из `env`, несколько UUID через запятую, сравнение UUID в постоянном времени;
- `PROXYIP` fallback для целей в сети Cloudflare / при ошибке `connect()`;
- UDP `cmd=0x02` только для DNS (порт 53) → DoH `https://1.1.1.1/dns-query`;
- `/api/v1/dns` — DoH-релей для `psi-dpi`;
- на чужие пути отдаёт закэшированную страницу прикрытия (`DECOY_HOST`).

## Деплой

```powershell
cd worker
npm install -g wrangler
wrangler login

# секреты
wrangler secret put UUID        # "uuid1,uuid2"
wrangler secret put PROXYIP     # опционально: "proxy.example.com:443"

# свой домен в wrangler.toml (routes) — обязательно, не *.workers.dev
wrangler deploy
```

## Проверка

```powershell
# ожидается HTTP 101 и заголовок Sec-WebSocket-Protocol при early-data
wscat -c "wss://vpn.example.com/api/v1/stream" -s "<base64url>"
```

Клиент: `vless://UUID@vpn.example.com:443?type=ws&security=tls&sni=vpn.example.com&host=vpn.example.com&path=%2Fapi%2Fv1%2Fstream%3Fed%3D2048&ed=2048`.
