//go:build windows

package main

import (
	"fmt"
	"image/color"
	"net/url"
	"strings"

	"gioui.org/font"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// ============================================================================
// FILE: gui_palette.go — Нативная палитра команд (Ctrl+K)
// ============================================================================
//
// Позволяет мгновенно находить и запускать любые разделы, переключатели,
// режимы DPI, Kill Switch, страны выхода и проверять маршрут домена/IP.

type paletteEntry struct {
	id       string
	title    string
	sub      string
	icon     string
	shortcut string
	keywords string
	run      func()
}

func (ui *gioUI) buildPaletteEntries() []paletteEntry {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()

	psi, _ := st["psiphon"].(map[string]any)
	pState, _ := psi["state"].(string)
	tun, _ := st["tun"].(map[string]any)
	tunOn, _ := tun["on"].(bool)
	sysProxy, _ := st["sysproxy"].(bool)
	warpOn, _ := st["warp_on"].(bool)
	ccMap, _ := st["clean_chain"].(map[string]any)
	ccOn, _ := ccMap["enabled"].(bool)
	dnsOn, _ := st["dns_on"].(bool)
	quicOn, _ := st["block_quic"].(bool)
	stunOn, _ := st["block_stun"].(bool)
	lanOn, _ := st["bypass_lan"].(bool)
	shareOn, _ := st["share_on"].(bool)
	paused, _ := st["paused"].(bool)
	listen, _ := st["listen"].(string)
	host, port := proxyHostPort(listen)
	hp := host + ":" + port

	var items []paletteEntry
	add := func(id, title, sub, icon, shortcut, kw string, fn func()) {
		items = append(items, paletteEntry{
			id:       id,
			title:    title,
			sub:      sub,
			icon:     icon,
			shortcut: shortcut,
			keywords: strings.ToLower(title + " " + sub + " " + kw),
			run:      fn,
		})
	}

	// 1. Все 9 разделов
	for i := 0; i < len(navTitles); i++ {
		idx := i
		add(fmt.Sprintf("nav-%d", idx), navTitles[idx], navHints[idx], navIcons[idx], fmt.Sprintf("Ctrl+%d", idx+1), "раздел страница открыть перейти", func() {
			ui.tab = idx
			ui.pipePopup = 0
			safeGo("palette.nav", func() { ui.fetchAll(true) })
		})
	}

	// 2. Основные действия подключения
	pwrTitle := "Подключить VPN"
	if pState == "connected" || pState == "connecting" || pState == "reconnecting" {
		pwrTitle = "Отключить VPN"
	}
	add("power", pwrTitle, "Включить или выключить защиту Psiphon", "power", "Ctrl+Enter", "connect disconnect старт стоп psiphon", func() {
		ui.togglePower(pState)
	})
	add("newnode", "Новый узел", "Переключиться на другой сервер Psiphon", "refresh", "", "node сервер сменить", func() {
		ui.doAsync("Поиск нового узла Psiphon…", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psiphon/newnode", nil)
		})
	})
	add("repair", "Починить обход DPI", "Автоподбор DPI и сброс DNS", "bolt", "", "repair fix dpi", func() {
		ui.doAsync("Автоподбор DPI и сброс DNS запущены", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/repair", map[string]any{})
		})
	})
	add("restart", "Перезапустить Psiphon", "Полный перезапуск туннеля", "refresh", "", "restart", func() {
		ui.doAsync("Перезапуск Psiphon…", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psiphon/restart", nil)
		})
	})
	add("reset-stack", "Reset Stack", "Сбросить DNS, маршруты и туннель", "bolt", "", "сброс стек", func() {
		ui.doAsync("Стек сброшен", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/stack/reset", map[string]any{})
		})
	})

	// 3. Пауза
	if paused {
		add("resume", "Возобновить защиту", "Снять паузу защиты", "play", "", "pause resume", func() {
			ui.doAsync("Защита возобновлена", func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/pause", map[string]any{"minutes": 0})
			})
		})
	} else {
		for _, mins := range []int{5, 15, 30, 60} {
			m := mins
			add(fmt.Sprintf("pause-%d", m), fmt.Sprintf("Пауза на %d мин", m), "Временно приостановить защиту", "stop", "", "pause пауза", func() {
				ui.doAsync(fmt.Sprintf("Защита на паузе: %d мин", m), func() (map[string]any, error) {
					return ui.apiCall("POST", "/api/pause", map[string]any{"minutes": m})
				})
			})
		}
	}

	// 4. Быстрые переключатели
	tunLabel := "Включить TUN"
	if tunOn {
		tunLabel = "Выключить TUN"
	}
	add("tun", tunLabel, "Весь трафик ПК через Wintun", "shield", "", "tun wintun", func() {
		act := "on"
		if tunOn {
			act = "off"
		}
		ui.doAsync("Режим TUN: "+act, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/tun/"+act, map[string]any{})
		})
	})
	sysLabel := "Включить системный прокси"
	if sysProxy {
		sysLabel = "Выключить системный прокси"
	}
	add("sysproxy", sysLabel, "Системный прокси Windows", "globe", "", "sysproxy", func() {
		ui.doAsync("Системный прокси обновлён", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"general.system_proxy": !sysProxy})
		})
	})
	warpLabel := "Включить WARP"
	if warpOn {
		warpLabel = "Выключить WARP"
	}
	add("warp", warpLabel, "Подложка Cloudflare WARP", "bolt", "", "warp cloudflare", func() {
		act := "on"
		if warpOn {
			act = "off"
		}
		ui.doAsync("WARP: "+act, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/warp/"+act, nil)
		})
	})
	ccLabel := "Включить Clean-IP"
	if ccOn {
		ccLabel = "Выключить Clean-IP"
	}
	add("cleanip", ccLabel, "Каскад WARP → VPN → WARP", "shield", "", "clean чистый ip каскад", func() {
		ui.doAsync("Clean-IP переключён", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/clean-chain/toggle", map[string]any{"enabled": !ccOn})
		})
	})
	add("verify-clean", "Проверить связку WARP → VPN → WARP", "3-звенная проверка каскада Clean-IP", "check", "", "verify clean", func() {
		ui.tab = 4
		ui.subTabs[4] = 1
		ui.doAsync("Проверка связки WARP → VPN → WARP…", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/clean-chain/verify", map[string]any{})
		})
	})
	add("doh", "Переключить DoH + ECH", "Шифрованный DNS ("+onOffRu(dnsOn)+")", "lock", "", "dns doh", func() {
		ui.doAsync("DoH + ECH обновлён", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"dns.enabled": !dnsOn})
		})
	})
	add("quic", "Переключить блокировку QUIC", "UDP 443 / HTTP3 ("+onOffRu(quicOn)+")", "stop", "", "quic http3", func() {
		ui.doAsync("Блокировка QUIC обновлена", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.block_quic": !quicOn})
		})
	})
	add("stun", "Переключить защиту WebRTC / STUN", "Блокировка утечки IP по UDP ("+onOffRu(stunOn)+")", "shield", "", "webrtc stun", func() {
		ui.doAsync("Защита WebRTC обновлена", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.block_stun": !stunOn})
		})
	})
	add("lan", "Переключить локальную сеть напрямую", "RFC1918 мимо VPN ("+onOffRu(lanOn)+")", "lan", "", "lan", func() {
		ui.doAsync("Обход LAN обновлён", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.bypass_lan": !lanOn})
		})
	})
	add("share", "Переключить раздачу в LAN", "Прокси для телефона и ТВ ("+onOffRu(shareOn)+")", "lan", "", "share раздача", func() {
		act := "on"
		if shareOn {
			act = "off"
		}
		ui.doAsync("Раздача в LAN: "+act, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/share/"+act, nil)
		})
	})

	// 5. Режимы маршрутизации
	for _, m := range []struct{ id, title string }{
		{"auto", "Режим: Умный обход"},
		{"rules", "Режим: По моим правилам"},
		{"psiphon", "Режим: Весь трафик в VPN"},
	} {
		m := m
		add("mode-"+m.id, m.title, "Глобальный сценарий маршрутизации", "route", "", "сценарий mode", func() {
			ui.doAsync(m.title, func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/mode/"+m.id, nil)
			})
		})
	}

	// 6. Методы DPI
	for i := 0; i < len(nativeDPIModes); i++ {
		mID, mName := nativeDPIModes[i], nativeDPINames[i]
		add("dpi-"+mID, "Обход DPI: "+mName, "Метод разрезания TLS-рукопожатия", "shield", "", "dpi "+mID, func() {
			ui.doAsync("Обход DPI: "+mName, func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/dpi/mode", map[string]any{"mode": mID})
			})
		})
	}

	// 7. Kill Switch
	for _, ks := range []struct{ id, title string }{
		{"off", "Kill Switch: Выключен"},
		{"auto", "Kill Switch: Авто"},
		{"strict", "Kill Switch: Строгий"},
	} {
		ks := ks
		add("ks-"+ks.id, ks.title, "WFP блокировка трафика при обрыве VPN", "lock", "", "kill switch wfp", func() {
			ui.doAsync(ks.title, func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/settings", map[string]any{"routing.kill_switch_mode": ks.id})
			})
		})
	}

	// 8. Диагностика и утилиты
	add("leak", "Запустить тест утечек", "Проверка IP, DNS, IPv6, WebRTC, Kill Switch", "shield", "", "leak утечки", func() {
		ui.tab = 6
		ui.subTabs[6] = 0
		ui.doAsync("Тест утечек завершён", func() (map[string]any, error) {
			res, err := ui.apiCall("POST", "/api/leaktest", map[string]any{})
			if err == nil && res != nil {
				ui.mu.Lock()
				ui.leakRes = res
				ui.mu.Unlock()
			}
			return res, err
		})
	})
	add("selftest", "Запустить самопроверку", "Полная проверка сети, DNS, ядра и конфигурации", "check", "", "selftest", func() {
		ui.tab = 6
		ui.subTabs[6] = 0
		ui.doAsync("Самопроверка завершена", func() (map[string]any, error) {
			res, err := ui.apiCall("POST", "/api/selftest", nil)
			if err == nil && res != nil {
				ui.mu.Lock()
				ui.selftestRes = res
				ui.mu.Unlock()
			}
			return res, err
		})
	})
	add("speedtest", "Тест скорости туннеля", "Измерить скорость Psiphon", "chart", "", "speed скорость", func() {
		ui.tab = 4
		ui.subTabs[4] = 2
		ui.doAsync("Тест скорости завершён", func() (map[string]any, error) {
			res, err := ui.apiCall("POST", "/api/psi/speedtest", nil)
			if err == nil && res != nil {
				ui.mu.Lock()
				ui.speedTestRes = res
				ui.mu.Unlock()
			}
			return res, err
		})
	})
	add("dns-clear", "Сбросить кэш DNS", "Очистить кэш резолвера", "refresh", "", "dns clear", func() {
		ui.doAsync("Кэш DNS очищен", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/dns/clear", nil)
		})
	})
	add("copy-proxy", "Скопировать адрес прокси", hp, "copy", "", "proxy socks http", func() {
		writeClipboardText(hp)
		ui.setToast("Адрес прокси скопирован: "+hp, false)
	})
	add("privacy", "Переключить «Чистый экран»", "Скрывать или показывать IP и домены", "shield", "", "privacy скрыть", func() {
		ui.privacyMode = !ui.privacyMode
		if ui.privacyMode {
			ui.setToast("Чистый экран: IP и домены скрыты", false)
		} else {
			ui.setToast("IP и домены показаны", false)
		}
	})
	add("reload", "Перечитать настройки", "Загрузить psiroute.json с диска", "refresh", "", "reload config", func() {
		ui.doAsync("Настройки перечитаны", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/reload", nil)
		})
	})
	add("report", "Создать отчёт для поддержки (.zip)", "Диагностический архив без паролей", "download", "", "report отчёт", func() {
		ui.doAsync("Отчёт сохранён", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/report", nil)
		})
	})
	add("quit", "Выйти из PsiRoute", "Остановить туннель и закрыть программу", "power", "", "quit exit выход", func() {
		safeGo("palette.quit", func() {
			_, _ = ui.apiCall("GET", "/api/quit", nil)
		})
	})

	// 9. Страны выхода
	for i := 0; i < len(nativeCountries); i++ {
		cc := nativeCountries[i]
		name := nativeCountryNames[i]
		add("cc-"+orDefault(cc, "AUTO"), "Страна: "+name, "Выбрать страну выхода Psiphon", "globe", "", cc+" country выход", func() {
			ui.doAsync("Страна выхода: "+name, func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/psi/region", map[string]any{"region": cc})
			})
		})
	}

	return items
}

func (ui *gioUI) layoutCommandPalette(gtx layout.Context) layout.Dimensions {
	if ui.paletteCloseBtn.Clicked(gtx) {
		ui.paletteOpen = false
		return layout.Dimensions{}
	}

	// Полупрозрачная подложка поверх всего окна (перехватывает клики вне модального окна)
	backdrop := ui.appBtn("palette|backdrop")
	if backdrop.Clicked(gtx) {
		ui.paletteOpen = false
		return layout.Dimensions{}
	}

	qRaw := strings.TrimSpace(ui.paletteEditor.Text())
	qLow := strings.ToLower(qRaw)
	all := ui.buildPaletteEntries()
	var filtered []paletteEntry
	if qLow == "" {
		filtered = all
	} else {
		words := strings.Fields(qLow)
		for _, it := range all {
			match := true
			for _, w := range words {
				if !strings.Contains(it.keywords, w) {
					match = false
					break
				}
			}
			if match {
				filtered = append(filtered, it)
			}
		}
	}
	if len(filtered) > 35 {
		filtered = filtered[:35]
	}

	// Если введён домен или IP — предлагаем мгновенную проверку маршрута и создание правила
	looksLikeHost := qRaw != "" && strings.Contains(qRaw, ".") && !strings.Contains(qRaw, " ")
	traceBtn := ui.appBtn("palette|trace-run")
	if looksLikeHost && traceBtn.Clicked(gtx) {
		target := qRaw
		safeGo("palette.trace", func() {
			if res, err := ui.apiCall("GET", "/api/route?host="+url.QueryEscape(target)+"&port=443", nil); err == nil && res != nil {
				ui.mu.Lock()
				ui.paletteTraceHost = target
				ui.paletteTraceRes = res
				ui.mu.Unlock()
				if ui.w != nil {
					ui.w.Invalidate()
				}
			}
		})
	}

	ui.mu.Lock()
	traceHost := ui.paletteTraceHost
	traceRes := ui.paletteTraceRes
	ui.mu.Unlock()

	return layout.Stack{Alignment: layout.N}.Layout(gtx,
		// Подложка
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			return backdrop.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				paint.FillShape(gtx.Ops, rgba(0x03050E, 185), clip.Rect{Max: gtx.Constraints.Max}.Op())
				return layout.Dimensions{Size: gtx.Constraints.Max}
			})
		}),
		// Модальное окно палитры команд
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(48), Left: space2, Right: space2, Bottom: space2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				maxW := gtx.Dp(620)
				if gtx.Constraints.Max.X < maxW {
					maxW = gtx.Constraints.Max.X
				}
				maxH := gtx.Dp(520)
				if gtx.Constraints.Max.Y < maxH {
					maxH = gtx.Constraints.Max.Y
				}
				gtx.Constraints.Min.X = maxW
				gtx.Constraints.Max.X = maxW
				gtx.Constraints.Max.Y = maxH

				return ui.subCard(gtx, ui.pal.card, ui.pal.borderHi, space2, func(gtx layout.Context) layout.Dimensions {
					var topChildren []layout.FlexChild
					topChildren = append(topChildren,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return ui.editorBox(gtx, "palette-q", &ui.paletteEditor, "Что сделать? Например: «Германия», «DPI», «youtube.com», «утечки»…")
								}),
								layout.Rigid(layout.Spacer{Width: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.paletteCloseBtn, "Esc", false, "")
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
					)

					if looksLikeHost {
						topChildren = append(topChildren, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Bottom: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return ui.subCard(gtx, ui.pal.accSoft, tint(ui.pal.acc, 140), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
									var tRows []layout.FlexChild
									tRows = append(tRows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, "Куда пойдёт «"+ui.maskSensitive(qRaw)+"»?")
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.iconButton(gtx, traceBtn, "search", "Проверить трассу", false, "primary")
											}),
										)
									}))
									if traceRes != nil && strings.EqualFold(traceHost, qRaw) {
										ob, _ := traceRes["outbound"].(string)
										ruleNm, _ := traceRes["rule"].(string)
										tRows = append(tRows, layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
													layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.routeBadge(gtx, ob) }),
													layout.Rigid(layout.Spacer{Width: space1}.Layout),
													layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
														return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, "Правило: "+orDefault(ruleNm, "по умолчанию"))
													}),
												)
											}))
									}
									// 6 быстрых кнопок создания правила прямо из палитры
									obBtns := []struct{ id, lbl, st string }{
										{obDirect, "Direct", "ok"},
										{obDesync, "DPI", "teal"},
										{obWarp, "WARP", "warn"},
										{obPsiphon, "VPN", "vio"},
										{obCleanIP, "Clean-IP", "teal"},
										{obBlock, "Блок", "danger"},
									}
									var chips []layout.Widget
									for _, o := range obBtns {
										o := o
										b := ui.appBtn("palette|mkrule|" + o.id)
										if b.Clicked(gtx) {
											hostCopy := qRaw
											ui.paletteOpen = false
											ui.doAsync("Правило: "+hostCopy+" → "+o.lbl, func() (map[string]any, error) {
												return ui.apiCall("POST", "/api/rules/add", map[string]any{
													"tokens":   hostCopy,
													"name":     hostCopy,
													"outbound": o.id,
												})
											})
										}
										chips = append(chips, func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, b, "→ "+o.lbl, false, o.st)
										})
									}
									tRows = append(tRows, layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return flowWrap(gtx, unit.Dp(5), unit.Dp(5), chips...)
										}))
									return layout.Flex{Axis: layout.Vertical}.Layout(gtx, tRows...)
								})
							})
						}))
					}

					topChildren = append(topChildren, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						if len(filtered) == 0 {
							return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, "Ничего не найдено")
						}
						return material.List(ui.th, &ui.paletteList).Layout(gtx, len(filtered), func(gtx layout.Context, i int) layout.Dimensions {
							it := filtered[i]
							rowBtn := ui.appBtn("palette|item|" + it.id)
							if rowBtn.Clicked(gtx) {
								ui.paletteOpen = false
								if it.run != nil {
									it.run()
								}
							}
							bg := color.NRGBA{}
							if rowBtn.Hovered() {
								bg = ui.pal.hover
							}
							return layout.Inset{Bottom: unit.Dp(3)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								gtx.Constraints.Min.X = gtx.Constraints.Max.X
								return rowBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									pointer.CursorPointer.Add(gtx.Ops)
									return layout.Background{}.Layout(gtx,
										func(gtx layout.Context) layout.Dimensions {
											if bg.A > 0 {
												fillRect(gtx, gtx.Constraints.Min, gtx.Dp(8), bg)
											}
											return layout.Dimensions{Size: gtx.Constraints.Min}
										},
										func(gtx layout.Context) layout.Dimensions {
											return layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return drawIcon(gtx, it.icon, unit.Dp(15), ui.pal.acc2)
													}),
													layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
													layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
														return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
															layout.Rigid(func(gtx layout.Context) layout.Dimensions {
																return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, it.title)
															}),
															layout.Rigid(func(gtx layout.Context) layout.Dimensions {
																if it.sub == "" {
																	return layout.Dimensions{}
																}
																return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.Normal, it.sub)
															}),
														)
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														if it.shortcut == "" {
															return layout.Dimensions{}
														}
														return ui.monoLabel(gtx, fontMicro, ui.pal.dim, it.shortcut)
													}),
												)
											})
										},
									)
								})
							})
						})
					}))

					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, topChildren...)
				})
			})
		}),
	)
}
