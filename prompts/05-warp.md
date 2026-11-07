# Шаг 05 — psi-warp (Cloudflare WARP + AmneziaWG-обфускация)

Референсы: `aramperes/onetun` (boringtun+smoltcp → TCP), `bepass-org/warp-plus` (сканер, режим Psiphon-over-WARP), `ViRb3/wgcf` (регистрация), `amnezia-vpn/amneziawg-go` (junk).

## Сделать
1. Регистрация (как wgcf): x25519 ключи (`x25519-dalek`), `POST https://api.cloudflareclient.com/v0a2158/reg` JSON `{key, install_id:"", fcm_token:"", tos:<RFC3339>, type:"Android", locale:"en_US"}`, заголовки `CF-Client-Version: a-6.11-2223`, `User-Agent: okhttp/3.12.1`. Из ответа: `config.peers[0].public_key`, `config.interface.addresses.v4/v6`, `config.client_id` → base64-decode → 3 байта **reserved**. Сохранить в config.local.toml. Импорт готового `wgcf-profile.conf`/AmneziaWG `.conf` — тоже поддержать. Если API недоступен напрямую — регистрировать через уже поднятый VLESS/DPI-выход.
2. Туннель: `boringtun::noise::Tunn`. В КАЖДЫЙ исходящий пакет записывать reserved в байты [1..4]. UDP-сокет к endpoint (bind к физическому интерфейсу — хук).
3. AmneziaWG-совместимая обфускация для WARP: перед каждым handshake-initiation отправить `jc` junk-пакетов случайной длины `jmin..jmax` (случайные байты); опционально `i1..i5` — hex-блоб «сигнатурных» пакетов (имитация QUIC/DNS), отправляются до junk. Заголовки H1–H4/S1–S2 НЕ менять (WARP их не поймёт).
4. Сеть поверх туннеля: `smoltcp` Interface (IP из address_v4/v6, MTU 1280), TCP-сокеты на каждое соединение (как в onetun), DNS через туннель к 1.1.1.1. → `WarpOutbound: Outbound` + `serve_socks(addr)`.
5. Сканер эндпоинтов: подсети `162.159.192.0/24, 162.159.193.0/24, 162.159.195.0/24, 188.114.96.0/24, 188.114.97.0/24, 188.114.98.0/24, 188.114.99.0/24`, порты `500,854,859,864,878,880,890,891,894,903,908,928,934,939,942,943,945,946,955,968,987,988,1002,1010,1014,1018,1070,1074,1180,1387,1701,1843,2371,2408,2506,3138,3476,3581,3854,4177,4198,4233,4500,5279,5956,7103,7152,7156,7281,7559,8319,8742,8854,8886`. Проба = junk + handshake initiation, ждать response ≤ 1 с. 200 случайных пар, параллельно 50, топ-3 по RTT в конфиг.
## Проверка
`cargo check`; тест: запись reserved в пакет и генерация junk в диапазоне длин.
