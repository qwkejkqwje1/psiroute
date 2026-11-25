//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// ============================================================================
// FILE: gui_settings.go — Вкладка 7 «Настройки» (4 подвкладки) и Вкладка 8 «Журнал»
// ============================================================================

func (ui *gioUI) layoutSettingsTab(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.layoutSubTabBar(gtx, 7, []string{"Основные", "Сеть и TUN", "Профили и данные", "Система"})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			switch ui.subTabs[7] {
			case 1:
				return ui.layoutSettingsNetworkSub(gtx)
			case 2:
				return ui.layoutSettingsProfilesSub(gtx)
			case 3:
				return ui.layoutSettingsSystemSub(gtx)
			default:
				return ui.layoutSettingsGeneralSub(gtx)
			}
		}),
	)
}

func (ui *gioUI) layoutSettingsGeneralSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	sData := ui.settingsData
	sVals := ui.settingsValues()
	ui.mu.Unlock()

	autostartOn, _ := sData["autostart"].(bool)
	watchCfg, _ := sVals["general.watch_config"].(bool)
	learnOn, _ := sVals["routing.learn"].(bool)
	failoverOn, _ := sVals["routing.failover"].(bool)

	btnAutostart := ui.appBtn("set|autostart")
	btnWatch := ui.appBtn("set|watch_config")
	btnLearn := ui.appBtn("set|learn")
	btnFailover := ui.appBtn("set|failover")
	btnCompact := ui.appBtn("set|compact_side")

	if btnAutostart.Clicked(gtx) {
		act := "on"
		if autostartOn {
			act = "off"
		}
		ui.doAsync("Автозапуск с Windows: "+onOffRu(!autostartOn), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/autostart/"+act, nil)
		})
	}
	if btnWatch.Clicked(gtx) {
		next := !watchCfg
		ui.doAsync("Слежение за psiroute.json: "+onOffRu(next), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"general.watch_config": next})
		})
	}
	if btnLearn.Clicked(gtx) {
		next := !learnOn
		ui.doAsync("Самообучение маршрутов: "+onOffRu(next), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.learn": next})
		})
	}
	if btnFailover.Clicked(gtx) {
		next := !failoverOn
		ui.doAsync("Авто-переключение при сбое: "+onOffRu(next), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.failover": next})
		})
	}
	if btnCompact.Clicked(gtx) {
		ui.sidebarCollapsed = !ui.sidebarCollapsed
	}

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.twoCol(gtx, 0.5, 0.5,
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "power", "Запуск и маршрутизация", "Поведение программы при старте Windows и работе маршрутизатора", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, btnAutostart, "power", "Автозапуск с Windows", onOffRu(autostartOn), autostartOn)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, btnWatch, "refresh", "Следить за файлом настроек", "Применять правки psiroute.json на лету", watchCfg)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, btnLearn, "bolt", "Самообучение маршрутов", "Запоминать, какой способ открывает сайт", learnOn)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, btnFailover, "swap", "Авто-переключение при сбое", "Пробовать другой маршрут, если сайт не открылся", failoverOn)
							}),
						)
					})
				},
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "gear", "Интерфейс и приватность", "Aurora Dark — нативный GPU-интерфейс Gio (только тёмная тема)", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, &ui.privacyBtn, "shield", "Чистый экран (скрывать IP и домены)", "Заменяет IP и домены на ••• для скриншотов", ui.privacyMode)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, btnCompact, "apps", "Компактная боковая панель", "Показывать только иконки в меню слева", ui.sidebarCollapsed)
							}),
						)
					})
				},
			)
		},
	}

	return material.List(ui.th, &ui.setPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutSettingsNetworkSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	sVals := ui.settingsValues()
	ui.mu.Unlock()

	tunMap, _ := st["tun"].(map[string]any)
	needAdm, _ := tunMap["need_admin"].(bool)
	dnsHijack, _ := sVals["tun.dns_hijack"].(bool)
	tunIPv6, _ := sVals["tun.ipv6"].(bool)
	udpMode, _ := sVals["udp.mode"].(string)
	if udpMode == "" {
		udpMode = "route"
	}
	proxyEn, _ := sVals["proxy.enabled"].(bool)

	btnHijack := ui.appBtn("set|tun_dns_hijack")
	btnIPv6 := ui.appBtn("set|tun_ipv6")
	btnSaveMTU := ui.appBtn("set|save_mtu")
	btnSaveEx := ui.appBtn("set|save_exclude")
	btnProxyEn := ui.appBtn("set|proxy_en")
	btnSaveProxy := ui.appBtn("set|save_proxy")

	if btnHijack.Clicked(gtx) {
		next := !dnsHijack
		ui.doAsync("Перехват DNS в TUN: "+onOffRu(next), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"tun.dns_hijack": next})
		})
	}
	if btnIPv6.Clicked(gtx) {
		next := !tunIPv6
		ui.doAsync("IPv6 в TUN: "+onOffRu(next), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"tun.ipv6": next})
		})
	}
	if btnSaveMTU.Clicked(gtx) {
		if v, err := strconv.Atoi(strings.TrimSpace(ui.tunMTUEditor.Text())); err == nil && v >= 1000 && v <= 1500 {
			ui.doAsync(fmt.Sprintf("MTU туннеля: %d", v), func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/settings", map[string]any{"tun.mtu": v})
			})
		} else {
			ui.setToast("Укажите MTU от 1000 до 1500", true)
		}
	}
	if btnSaveEx.Clicked(gtx) {
		val := strings.TrimSpace(ui.tunExcludeEditor.Text())
		ui.doAsync("Исключения TUN сохранены", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"tun.exclude_apps": val})
		})
	}
	if btnProxyEn.Clicked(gtx) {
		next := !proxyEn
		ui.doAsync("Внешний прокси: "+onOffRu(next), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"proxy.enabled": next})
		})
	}
	if btnSaveProxy.Clicked(gtx) {
		val := strings.TrimSpace(ui.proxyUpstreamEditor.Text())
		ui.doAsync("Адрес внешнего прокси сохранён", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"proxy.upstream": val})
		})
	}

	udpOpts := []struct{ id, title string }{
		{"route", "По правилам"},
		{"direct", "Напрямую"},
		{"psiphon", "Через VPN"},
		{"off", "Блок"},
	}
	var udpChips []layout.Widget
	for _, opt := range udpOpts {
		opt := opt
		b := ui.appBtn("set|udp|" + opt.id)
		if b.Clicked(gtx) {
			ui.doAsync("Обработка UDP: "+opt.title, func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/settings", map[string]any{"udp.mode": opt.id})
			})
		}
		udpChips = append(udpChips, func(gtx layout.Context) layout.Dimensions {
			return ui.pillButton(gtx, b, opt.title, udpMode == opt.id, "primary")
		})
	}

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.twoCol(gtx, 0.5, 0.5,
				// Левая: Захват трафика и TUN
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var rows []layout.FlexChild
						rows = append(rows,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "shield", "Захват трафика и TUN", "Wintun, FakeIP, перехват DNS и исключения", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(ui.toggleTile(st, "tun")),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(ui.toggleTile(st, "sysproxy")),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(ui.toggleTile(st, "autostart")),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(ui.toggleTile(st, "fakeip")),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, btnHijack, "lock", "Перехват DNS в TUN", "Весь DNS идёт через PsiRoute", dnsHijack)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, btnIPv6, "globe", "IPv6 в TUN", "Включайте только если IPv6 необходим", tunIPv6)
							}),
						)
						if needAdm {
							rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, &ui.tunAdminBtn, "shield", "Перезапустить от Администратора (Wintun)", false, "danger")
								}))
						}
						rows = append(rows,
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Medium, "MTU (1000–1500):")
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return ui.editorBox(gtx, "tun-mtu", &ui.tunMTUEditor, "1280")
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, btnSaveMTU, "OK", false, "primary")
									}),
								)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return ui.editorBox(gtx, "tun-ex", &ui.tunExcludeEditor, "Исключения TUN: game.exe, bank.exe…")
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, btnSaveEx, "OK", false, "primary")
									}),
								)
							}),
						)
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				},
				// Правая: DNS, защита и UDP
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "lock", "DNS, защита и UDP", "Шифрование DNS, блокировка утечек и политика UDP", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(ui.toggleTile(st, "doh")),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(ui.toggleTile(st, "localdns")),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(ui.toggleTile(st, "quic")),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(ui.toggleTile(st, "stun")),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(ui.toggleTile(st, "lan")),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.caption(gtx, "Обработка UDP:") }),
							layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return flowWrap(gtx, unit.Dp(6), unit.Dp(6), udpChips...) }),
						)
					})
				},
			)
		},
		// Внешний прокси
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "route", "Внешний прокси (Upstream)", "Используется для маршрута «Прокси» (proxy) в правилах", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchButton(gtx, btnProxyEn, proxyEn)
							}),
							layout.Rigid(layout.Spacer{Width: space1}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return ui.editorBox(gtx, "proxy-up", &ui.proxyUpstreamEditor, "socks5://127.0.0.1:9050")
							}),
							layout.Rigid(layout.Spacer{Width: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, btnSaveProxy, "Сохранить", false, "primary")
							}),
						)
					}),
				)
			})
		},
	}

	return material.List(ui.th, &ui.setPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutSettingsProfilesSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	pData := ui.profilesData
	ui.mu.Unlock()

	builtins := toMapSlice(pData["builtin"])
	canUndo, _ := pData["undo"].(bool)

	btnExportProf := ui.appBtn("prof|export")
	btnImpMerge := ui.appBtn("prof|imp-merge")
	btnImpReplace := ui.appBtn("prof|imp-replace")
	btnExportRules := ui.appBtn("prof|rules-export")

	if btnExportProf.Clicked(gtx) {
		safeGo("profile.export", func() {
			if res, err := ui.apiCall("POST", "/api/profiles/export", map[string]any{"name": "Мой профиль"}); err == nil && res != nil {
				if code, _ := res["code"].(string); code != "" {
					writeClipboardText(code)
					ui.setToast("Код профиля скопирован в буфер обмена", false)
					return
				}
			}
			ui.setToast("Не удалось экспортировать профиль", true)
		})
	}
	if btnImpMerge.Clicked(gtx) || btnImpReplace.Clicked(gtx) {
		merge := btnImpMerge.Clicked(gtx)
		code := strings.TrimSpace(ui.profileImportEditor.Text())
		if code == "" {
			ui.setToast("Вставьте код профиля", true)
		} else {
			ui.doAsync("Профиль импортирован", func() (map[string]any, error) {
				res, err := ui.apiCall("POST", "/api/profiles/import", map[string]any{"data": code, "merge": merge})
				if err == nil {
					ui.queueEditorText(&ui.profileImportEditor, "")
				}
				return res, err
			})
		}
	}
	if btnExportRules.Clicked(gtx) {
		safeGo("rules.export", func() {
			if res, err := ui.apiCall("GET", "/api/rules/export", nil); err == nil && res != nil {
				if txt, _ := res["text"].(string); txt != "" {
					writeClipboardText(txt)
					ui.setToast("Текст правил скопирован в буфер обмена", false)
					return
				}
			}
			ui.setToast("Не удалось экспортировать правила", true)
		})
	}

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.twoCol(gtx, 0.55, 0.45,
				// Готовые профили
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var rows []layout.FlexChild
						rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							var undoW layout.Widget
							if canUndo {
								undoW = func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, &ui.undoProfileBtn, "refresh", "Отменить последнее", false, "warn")
								}
							}
							return ui.cardHeader(gtx, "list", "Готовые профили", "Набор правил в 1 клик (можно добавить или заменить)", undoW)
						}))
						for _, p := range builtins {
							pID, _ := p["id"].(string)
							pName, _ := p["name"].(string)
							pAbout, _ := p["about"].(string)
							pRules, _ := p["rules"].(float64)
							bAdd := ui.appBtn("prof|add|" + pID)
							bRep := ui.appBtn("prof|rep|" + pID)
							if bAdd.Clicked(gtx) {
								idCopy := pID
								ui.doAsync("Профиль добавлен: "+pName, func() (map[string]any, error) {
									return ui.apiCall("POST", "/api/profiles/import", map[string]any{"builtin": idCopy, "merge": true})
								})
							}
							if bRep.Clicked(gtx) {
								idCopy := pID
								ui.doAsync("Профиль применён: "+pName, func() (map[string]any, error) {
									return ui.apiCall("POST", "/api/profiles/import", map[string]any{"builtin": idCopy, "merge": false})
								})
							}
							rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, pName)
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.Normal, fmt.Sprintf("%s · %.0f правил", pAbout, pRules))
													}),
												)
											}),
											layout.Rigid(layout.Spacer{Width: space1}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.pillButton(gtx, bAdd, "Добавить", false, "") }),
											layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.pillButton(gtx, bRep, "Заменить", false, "teal") }),
										)
									})
								})
							}))
						}
						if len(builtins) == 0 {
							rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, "Загрузка встроенных профилей…")
								}))
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				},
				// Свой профиль (экспорт / импорт)
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "copy", "Свой профиль и экспорт", "Поделитесь набором правил по коду или сохраните резервную копию", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, space1, space1,
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, btnExportProf, "copy", "Экспортировать код профиля", false, "primary")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, btnExportRules, "download", "Экспорт правил (в буфер)", false, "")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.clearLearnBtn, "swap", "Забыть выученные маршруты", false, "danger")
									},
								)
							}),
							layout.Rigid(layout.Spacer{Height: space2}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.caption(gtx, "Импорт профиля по коду:")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.editorBox(gtx, "prof-imp", &ui.profileImportEditor, "Вставьте код профиля…")
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, space1, space1,
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, btnImpMerge, "plus", "Добавить к текущим", false, "")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, btnImpReplace, "check", "Заменить правила", false, "primary")
									},
								)
							}),
						)
					})
				},
			)
		},
	}

	return material.List(ui.th, &ui.setPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutSettingsSystemSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	sData := ui.settingsData
	ui.mu.Unlock()

	cfgPath, _ := sData["config_path"].(string)
	cfgErr, _ := st["config_error"].(string)
	uiAddr, _ := st["ui"].(string)
	var lifeTot float64
	if stats, ok := st["stats"].(map[string]any); ok {
		if life, ok := stats["lifetime"].(map[string]any); ok {
			lifeTot, _ = life["total"].(float64)
		}
	}

	btnReload := ui.appBtn("sys|reload")
	if btnReload.Clicked(gtx) {
		ui.doAsync("Настройки перечитаны из psiroute.json", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/reload", nil)
		})
	}

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.twoCol(gtx, 0.5, 0.5,
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var rows []layout.FlexChild
						rows = append(rows,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "gear", "Конфигурация", "Хранится строго портативно рядом с программой", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.kvRow(gtx, "Файл настроек", ui.maskSensitive(orDefault(cfgPath, "psiroute.json")))
							}),
						)
						if cfgErr != "" {
							rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.subCard(gtx, ui.pal.errSoft, tint(ui.pal.err, 130), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
										return ui.label(gtx, fontSmall, ui.pal.err, font.SemiBold, "Ошибка конфига: "+cfgErr)
									})
								}))
						}
						rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, btnReload, "refresh", "Перечитать psiroute.json", false, "")
							}))
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				},
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "shield", "Приложение", "Версия, веб-панель и завершение работы", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Версия", "v"+version) }),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Веб-панель", orDefault(uiAddr, "127.0.0.1:9090")) }),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Всего передано", fmtBytes(int64(lifeTot))) }),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, space1, space1,
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.resetStatsBtn, "refresh", "Сбросить счётчики", false, "")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.webBtn, "globe", "Открыть веб-панель", false, "")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.quitBtn, "power", "Выйти из PsiRoute", false, "danger")
									},
								)
							}),
						)
					})
				},
			)
		},
		// Горячие клавиши
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "bolt", "Горячие клавиши", "Быстрое управление с клавиатуры", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Ctrl + K", "Палитра команд и поиск по всем функциям") }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Ctrl + Enter", "Подключить / отключить VPN") }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Ctrl + 1 … 9", "Переход по 9 разделам программы") }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Ctrl + F", "Фокус на поиск текущей вкладки") }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Esc", "Закрыть палитру команд") }),
				)
			})
		},
	}

	return material.List(ui.th, &ui.setPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

// ---------- Вкладка 8: Полноэкранный Живой Журнал Событий ----------

func (ui *gioUI) layoutLiveLogOnlyTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	savedLogs := ui.cachedLogs
	logFilter := ui.logLevelFilter
	ui.mu.Unlock()

	var logs []map[string]any
	if st != nil {
		logs = toMapSlice(st["log"])
	}
	if len(logs) == 0 && len(savedLogs) > 0 {
		logs = savedLogs
	}

	btnAll := ui.appBtn("log|filter-all")
	btnWarn := ui.appBtn("log|filter-warn")
	btnErr := ui.appBtn("log|filter-err")
	btnCopyLog := ui.appBtn("log|copy-all")

	if btnAll.Clicked(gtx) {
		ui.mu.Lock()
		ui.logLevelFilter = 0
		logFilter = 0
		ui.mu.Unlock()
	}
	if btnWarn.Clicked(gtx) {
		ui.mu.Lock()
		ui.logLevelFilter = 1
		logFilter = 1
		ui.mu.Unlock()
	}
	if btnErr.Clicked(gtx) {
		ui.mu.Lock()
		ui.logLevelFilter = 2
		logFilter = 2
		ui.mu.Unlock()
	}

	q := strings.ToLower(strings.TrimSpace(ui.logSearchEditor.Text()))
	var filtered []map[string]any
	warnCount, errCount := 0, 0
	for i := len(logs) - 1; i >= 0; i-- {
		ln := logs[i]
		lv, _ := ln["level"].(string)
		msg, _ := ln["msg"].(string)
		if lv == "warn" {
			warnCount++
		} else if lv == "error" {
			errCount++
		}
		if logFilter == 1 && lv != "warn" && lv != "error" {
			continue
		}
		if logFilter == 2 && lv != "error" {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(lv+" "+msg), q) {
			continue
		}
		filtered = append(filtered, ln)
	}

	if btnCopyLog.Clicked(gtx) && len(filtered) > 0 {
		var sb strings.Builder
		for _, ln := range filtered {
			tm, _ := ln["time"].(string)
			lv, _ := ln["level"].(string)
			msg, _ := ln["msg"].(string)
			sb.WriteString(fmt.Sprintf("%s [%s] %s\n", tm, strings.ToUpper(orDefault(lv, "INFO")), msg))
		}
		ui.copyText(gtx, "all-logs", sb.String())
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "chart",
							fmt.Sprintf("Живой журнал событий (%d / %d)", len(filtered), len(logs)),
							"Новые записи отображаются сверху. Поддерживаются фильтр уровней и текстовый поиск (Ctrl+F).",
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, btnCopyLog, "copy", "Скопировать журнал", false, "primary")
							})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, btnAll, fmt.Sprintf("Все (%d)", len(logs)), logFilter == 0, "primary")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, btnWarn, fmt.Sprintf("⚠ Предупреждения (%d)", warnCount+errCount), logFilter == 1, "warn")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, btnErr, fmt.Sprintf("Ошибки (%d)", errCount), logFilter == 2, "danger")
									},
								)
							}),
							layout.Rigid(layout.Spacer{Width: space1}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return ui.editorBox(gtx, "log-search", &ui.logSearchEditor, "Поиск в журнале (Ctrl+F)…")
							}),
						)
					}),
				)
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
				if len(filtered) == 0 {
					return ui.emptyState(gtx, "chart", "По выбранному фильтру записей в журнале нет",
						"Все события запуска ядра, переключения правил, работы TUN и Psiphon отображаются здесь в реальном времени.", "", nil)
				}
				return material.List(ui.th, &ui.logList).Layout(gtx, len(filtered), func(gtx layout.Context, i int) layout.Dimensions {
					ln := filtered[i]
					tm, _ := ln["time"].(string)
					lv, _ := ln["level"].(string)
					msg, _ := ln["msg"].(string)
					col := ui.pal.text
					badgeCol := ui.pal.teal
					bdrCol := ui.pal.border
					lvTag := "INFO"
					if lv == "warn" {
						col = ui.pal.warn
						badgeCol = ui.pal.warn
						bdrCol = tint(ui.pal.warn, 110)
						lvTag = "WARN"
					} else if lv == "error" {
						col = ui.pal.err
						badgeCol = ui.pal.err
						bdrCol = tint(ui.pal.err, 130)
						lvTag = "ERROR"
					}
					return layout.Inset{Bottom: unit.Dp(5)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.subCard(gtx, ui.pal.card2, bdrCol, unit.Dp(7), func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.monoLabel(gtx, fontSmall, ui.pal.dim, tm+"  ")
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.monoLabel(gtx, fontSmall, badgeCol, "["+lvTag+"]  ")
								}),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return ui.label(gtx, fontBody, col, font.Normal, msg)
								}),
							)
						})
					})
				})
			})
		}),
	)
}

func (ui *gioUI) layoutSettingsLogTab(gtx layout.Context) layout.Dimensions {
	return ui.layoutLiveLogOnlyTab(gtx)
}
