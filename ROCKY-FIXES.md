# БАЗОВОЕ ДЕРЕВО 2.4.0 = 2.3.9-complete + все правки Rocky (слито Rocky 2026-11-22)

Это дерево — основа для задания «одно действие» (правки по аудиту). Оно уже содержит:
оркестратор из 2.3.9-complete (psi_seed.go, psi_carriers.go, psi_tuning.go, psi_ux.go и др.)
ПЛЮС все 9 правок Rocky. Дальше ветвиться ТОЛЬКО от этого дерева.

## Сборочные правки (без них не компилируется под Windows)
1. clean_chain.go — netip.AddrPortFrom(addr.Unmap(), uint16(rport)).
2. clean_chain.go — warpRegister([]*http.Client{cl}).
3. gui_countries.go — импорт gioui.org/unit.
4. gui_events.go — удалена мёртвая запись в ui.pendingTheme.
5. gui_widgets.go — восстановлена функция maskText.
6. psi.go (~2071) — исправлена искажённая руна ''' -> '\'' в strings.IndexByte (разбор тега тактик).

## Поведенческие правки подключения (НЕ откатывать; проверено вживую на машине пользователя:
## 2.3.0 подключается стабильно и быстро, 2.3.3–2.3.9 — нет, прямой desync-путь мёртв)
7. warptun.go:130 — главный WARP-туннель через newPhysUDPBind() (НЕ conn.NewDefaultBind()).
8. config.go — порядок стратегий по умолчанию: via-warp первая
   (via-warp, auto, conduit, meek, tls, ossh, quic, direct-dpi, desync-meek, desync-ossh).
9. psiorder.go buildRoundZeroPlan — удалено правило «direct/desync всегда первый выстрел раньше WARP».

## Состояние проверок этого дерева ДО правок по аудиту (Rocky, Go 1.26.2)
- go build (Windows GUI): собирается; все 6 полей psiphon.Config из psi_tuning.go существуют
  в закреплённом tunnel-core aabc0b3a6397 (п. A-01 аудита закрыт компиляцией).
- go vet: чистый.
- go test (без правок п.7–9): 237 pass / 1 skip / 3 fail из 241. Падения: TestUDPAssociateDirect
  (песочница Rocky, не баг), TestConfigSetKeyAndValues (таблица 37 при 42 ключах),
  TestPsiOrderUnstableDebounce (ждёт 150 на раунде 3 при новой лестнице 90/150/240).
  После правок п.7–9 добавятся падения тестов, утверждающих старый порядок, — их обновить
  под новое поведение (см. п. 4.1 задания).
