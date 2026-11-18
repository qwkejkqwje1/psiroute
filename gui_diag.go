//go:build windows

package main

import (
	"fmt"
	"strings"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// ============================================================================
// FILE: gui_diag.go (Вкладка «Потоки и подключения» + Диагностика сети)
// ============================================================================
//
// ВАЖНО:
//   - Вкладка «Потоки» (layoutStreamsTab, ui.tab == 2) активна ТОЛЬКО когда пользователь
//     открыл её (в фоновом режиме на других вкладках сбор и отрисовка потоков отключены).
//   - Показывает все живые и недавние TCP/UDP потоки: процесс (.exe), протокол, порт,
//     домен/SNI, текущий выход, сработавшее правило, объём трафика и аномалии ТСПУ.
//   - Позволяет в 1 клик прямо из строки потока назначить правило для сайта или для .exe.

func (ui *gioUI) layoutStreamsTab(gtx layout.Context) layout.Dimensions {
	if ui.tab != 2 {
		return layout.Dimensions{}
	}

	ui.mu.Lock()
	st := ui.state
	recentExtra := ui.recentStreams
	paused := ui.streamsPaused
	ruleForApp := ui.streamRuleForApp
	ui.mu.Unlock()

	pauseBtn := ui.appBtn("streams|pause-toggle")
	if pauseBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.streamsPaused = !ui.streamsPaused
		paused = ui.streamsPaused
		if paused && st != nil {
			if stats, ok := st["stats"].(map[string]any); ok {
				ui.frozenLiveStreams = toMapSlice(stats["live"])
				ui.frozenRecentStreams = toMapSlice(stats["recent"])
			}
		}
		ui.mu.Unlock()
	}

	targetDomBtn := ui.appBtn("streams|target-domain")
	targetAppBtn := ui.appBtn("streams|target-app")
	if targetDomBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.streamRuleForApp = false
		ruleForApp = false
		ui.mu.Unlock()
	}
	if targetAppBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.streamRuleForApp = true
		ruleForApp = true
		ui.mu.Unlock()
	}

	var liveConns []map[string]any
	var recentConns []map[string]any
	if paused {
		ui.mu.Lock()
		liveConns = ui.frozenLiveStreams
		recentConns = ui.frozenRecentStreams
		ui.mu.Unlock()
	} else if st != nil {
		if stats, ok := st["stats"].(map[string]any); ok {
			liveConns = toMapSlice(stats["live"])
			recentConns = toMapSlice(stats["recent"])
		}
	}
	if len(recentExtra) > len(recentConns) && !paused {
		recentConns = recentExtra
	}

	// Объединяем живые и недавние потоки (помечая живые флагом _live=true)
	allStreams := make([]map[string]any, 0, len(liveConns)+len(recentConns))
	for _, lc := range liveConns {
		cp := make(map[string]any, len(lc)+1)
		for k, v := range lc {
			cp[k] = v
		}
		cp["_live"] = true
		allStreams = append(allStreams, cp)
	}
	for _, rc := range recentConns {
		allStreams = append(allStreams, rc)
	}

	searchQ := strings.ToLower(strings.TrimSpace(ui.streamSearchEditor.Text()))
	var filteredConns []map[string]any
	errCount, blockCount, liveCount := 0, 0, len(liveConns)
	for _, c := range allStreams {
		isLive, _ := c["_live"].(bool)
		appNm, _ := c["app"].(string)
		h, _ := c["host"].(string)
		if sni, _ := c["sni"].(string); sni != "" {
			h = sni
		}
		ob, _ := c["outbound"].(string)
		rl, _ := c["rule"].(string)
		errStr, _ := c["error"].(string)
		dnB, _ := c["down"].(float64)
		upB, _ := c["up"].(float64)
		isBlocked := ob == obBlock || strings.Contains(strings.ToLower(rl), "блок") || strings.Contains(strings.ToLower(errStr), "заблокировано")
		isResetOrFail := errStr != "" || (upB > 0 && dnB == 0 && (ob == obDirect || ob == obDesync))
		if isBlocked {
			blockCount++
		}
		if isResetOrFail {
			errCount++
		}
		if searchQ != "" {
			hay := strings.ToLower(appNm + " " + h + " " + ob + " " + rl + " " + errStr)
			if !strings.Contains(hay, searchQ) {
				continue
			}
		}
		switch ui.diagConnFilter {
		case 1:
			if !isResetOrFail {
				continue
			}
		case 2:
			if !isBlocked {
				continue
			}
		case 3:
			if !isLive {
				continue
			}
		}
		filteredConns = append(filteredConns, c)
	}

	for i := range ui.diagFilterBtns {
		if ui.diagFilterBtns[i].Clicked(gtx) {
			ui.diagConnFilter = i
		}
	}
	filterLiveBtn := ui.appBtn("streams|filter-live")
	if filterLiveBtn.Clicked(gtx) {
		ui.diagConnFilter = 3
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Верхняя панель управления потоками
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
				pauseLbl := "⏸ Пауза списка"
				pauseStyle := ""
				if paused {
					pauseLbl = "▶ Продолжить обновление"
					pauseStyle = "warn"
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "lan",
							fmt.Sprintf("Потоки и подключения в реальном времени (активных: %d, всего: %d)", liveCount, len(allStreams)),
							"Эта вкладка активна ТОЛЬКО когда вы открыли её (0% нагрузки в фоне). Назначайте правила для любого домена или программы в 1 клик.",
							func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, pauseBtn, pauseLbl, paused, pauseStyle)
							})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, unit.Dp(5), unit.Dp(5),
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, &ui.diagFilterBtns[0], fmt.Sprintf("Все (%d)", len(allStreams)), ui.diagConnFilter == 0, "primary")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, filterLiveBtn, fmt.Sprintf("🟢 Активные сейчас (%d)", liveCount), ui.diagConnFilter == 3, "ok")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, &ui.diagFilterBtns[1], fmt.Sprintf("⚠ Сбросы ТСПУ / Ошибки (%d)", errCount), ui.diagConnFilter == 1, "warn")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, &ui.diagFilterBtns[2], fmt.Sprintf("🔴 Заблокированные (%d)", blockCount), ui.diagConnFilter == 2, "danger")
									},
								)
							}),
							layout.Flexed(1, layout.Spacer{}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(2), func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.segRouteButton(gtx, targetDomBtn, "Правило для сайта", !ruleForApp, "primary")
										}),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.segRouteButton(gtx, targetAppBtn, "Правило для .exe", ruleForApp, "vio")
										}),
									)
								})
							}),
						)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.editorBox(gtx, "stream-search", &ui.streamSearchEditor, "Фильтр потоков по домену, SNI, IP или программе (например: youtube, chrome.exe, 443)…")
					}),
				)
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		// Единый полноэкранный список потоков (без вложенных material.List!)
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
				if len(filteredConns) == 0 {
					return ui.emptyState(gtx, "lan", "По выбранному фильтру потоков нет",
						"Откройте любой сайт в браузере или программу — все TCP/UDP соединения сразу появятся здесь.", "", nil)
				}
				return material.List(ui.th, &ui.connList).Layout(gtx, len(filteredConns), func(gtx layout.Context, i int) layout.Dimensions {
					c := filteredConns[i]
					isLive, _ := c["_live"].(bool)
					appNm, _ := c["app"].(string)
					rawHost, _ := c["host"].(string)
					h := rawHost
					if sni, _ := c["sni"].(string); sni != "" {
						h = sni
					}
					proto, _ := c["proto"].(string)
					if proto == "" {
						proto = "tcp"
					}
					portF, _ := c["port"].(float64)
					ob, _ := c["outbound"].(string)
					rl, _ := c["rule"].(string)
					errStr, _ := c["error"].(string)
					upB, _ := c["up"].(float64)
					dnB, _ := c["down"].(float64)

					rowKey := fmt.Sprintf("strm|%d|%s|%s", i, appNm, h)
					btnDir := ui.appBtn(rowKey + "|direct")
					btnDPI := ui.appBtn(rowKey + "|dpi")
					btnWarp := ui.appBtn(rowKey + "|warp")
					btnTun := ui.appBtn(rowKey + "|psiphon")
					btnBlk := ui.appBtn(rowKey + "|block")

					applyQuick := func(targetOb string) {
						if ruleForApp && appNm != "" {
							targetApp := appNm
							ui.doAsync(fmt.Sprintf("Правило для программы %s ➔ %s", targetApp, routeShortRu(targetOb)), func() (map[string]any, error) {
								return ui.apiCall("POST", "/api/apps", map[string]any{"app": targetApp, "outbound": targetOb})
							})
							return
						}
						targetH := h
						if targetH == "" {
							targetH = rawHost
						}
						if targetH != "" {
							ui.doAsync(fmt.Sprintf("Правило для сайта %s ➔ %s (Приоритет 2)", targetH, routeShortRu(targetOb)), func() (map[string]any, error) {
								return ui.apiCall("POST", "/api/conns/quick-rule", map[string]any{"host": targetH, "outbound": targetOb})
							})
						}
					}

					if btnDir.Clicked(gtx) {
						applyQuick(obDirect)
					}
					if btnDPI.Clicked(gtx) {
						applyQuick(obDesync)
					}
					if btnWarp.Clicked(gtx) {
						applyQuick(obWarp)
					}
					if btnTun.Clicked(gtx) {
						applyQuick(obPsiphon)
					}
					if btnBlk.Clicked(gtx) {
						applyQuick(obBlock)
					}

					stateTag := "завершён"
					if isLive {
						stateTag = "● активен"
					}
					meta := fmt.Sprintf("%s · %s:%d · правило: %s · ↓%.1f КБ ↑%.1f КБ",
						stateTag, strings.ToUpper(proto), int(portF), orDefault(rl, "по умолчанию"), dnB/1024, upB/1024)
					if rawHost != "" && rawHost != h {
						meta += " · IP: " + ui.maskSensitive(rawHost)
					}
					if errStr != "" {
						meta += " · ⚠ " + errStr
					} else if upB > 0 && dnB == 0 && (ob == obDirect || ob == obDesync) {
						meta += " · ⚠ нет ответа (возможен дроп ТСПУ)"
					}

					bdr := ui.pal.border
					if errStr != "" || (upB > 0 && dnB == 0 && (ob == obDirect || ob == obDesync)) {
						bdr = tint(ui.pal.warn, 150)
					} else if isLive {
						bdr = tint(ui.pal.ok, 90)
					}

					return layout.Inset{Bottom: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.subCard(gtx, ui.pal.card2, bdr, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return ui.monoLabel(gtx, fontBody, ui.pal.text, fmt.Sprintf("%s  ➔  %s", orDefault(appNm, "Система"), ui.maskSensitive(orDefault(h, rawHost))))
												}),
												layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return ui.routeBadge(gtx, ob)
												}),
											)
										}),
										layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.Normal, meta)
										}),
									)
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.subCard(gtx, ui.pal.card, ui.pal.border, unit.Dp(2), func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.segRouteButton(gtx, btnDir, "Direct", ob == obDirect, "ok")
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.segRouteButton(gtx, btnDPI, "DPI", ob == obDesync, "teal")
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.segRouteButton(gtx, btnWarp, "WARP", ob == obWarp, "warn")
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.segRouteButton(gtx, btnTun, "В VPN", ob == obPsiphon || strings.HasPrefix(ob, "psiphon:"), "vio")
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.segRouteButton(gtx, btnBlk, "Блок", ob == obBlock, "danger")
											}),
										)
									})
								}),
							)
						})
					})
				})
			})
		}),
	)
}

// layoutTrafficDiagTab (Вкладка 4, Подвкладка 2): Диагностика доступности сайта, телеметрия Psiphon и самопроверка.
func (ui *gioUI) layoutTrafficDiagTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	diag := ui.diagRes
	psiStats := ui.psiStatsData
	ui.mu.Unlock()

	sections := []layout.Widget{
		// 1. Site Diagnostics Card (DNS, DoH, ECH & all routes)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "search", "Глубокая диагностика доступности сайта",
							"Проверка системного DNS, DoH, Encrypted ClientHello (ECH) и скорости через Direct, DPI, WARP и Psiphon", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return ui.editorBox(gtx, "diag-host", &ui.diagEditor, "например, www.youtube.com или discord.com (Ctrl+F)")
							}),
							layout.Rigid(layout.Spacer{Width: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.diagRunBtn, "Проверить сайт", false, "primary")
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if diag == nil {
							return layout.Dimensions{}
						}
						best, _ := diag["best"].(string)
						dnsMap, _ := diag["dns"].(map[string]any)
						hasECH, _ := dnsMap["ech"].(bool)
						echTxt := "нет записи HTTPS ECH"
						if hasECH {
							echTxt = "поддерживается ECH (Encrypted ClientHello)"
						}
						return layout.Inset{Top: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return ui.label(gtx, fontBody, ui.pal.ok, font.SemiBold, fmt.Sprintf("Лучший маршрут: %s   |   %s", orDefault(best, "не найден"), echTxt))
						})
					}),
				)
			})
		},
		// 2. Per-Network Psiphon Strategy Telemetry & Server Entries Import
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				netKey := "—"
				netID := "—"
				var stratRows []map[string]any
				var imported float64
				if psiStats != nil {
					netKey, _ = psiStats["net_key"].(string)
					netID, _ = psiStats["network_id"].(string)
					imported, _ = psiStats["imported_entries"].(float64)
					stratRows = toMapSlice(psiStats["strategies"])
				}
				var rows []layout.FlexChild
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.cardHeader(gtx, "chart",
						fmt.Sprintf("Статистика способов Psiphon для текущей сети (%s)", orDefault(netKey, "net-default")),
						fmt.Sprintf("NetworkID: %s · импортировано записей серверов: %.0f", orDefault(netID, "psiroute"), imported), nil)
				}))
				rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout))
				for i := range stratRows {
					sr := stratRows[i]
					title, _ := sr["title"].(string)
					att, _ := sr["attempts"].(float64)
					succ, _ := sr["successes"].(float64)
					medMs, _ := sr["median_connect_ms"].(float64)
					medLife, _ := sr["median_lifetime_sec"].(float64)
					score, _ := sr["score"].(float64)
					unstable, _ := sr["unstable"].(bool)
					line := fmt.Sprintf("попыток: %.0f · успехов: %.0f · мед. вход: %.0f мс · мед. жизнь: %.0f с · оценка: %.0f",
						att, succ, medMs, medLife, score)
					if unstable {
						line += " · [временно нестабилен]"
					}
					rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return ui.subCard(gtx, ui.pal.card2, ui.pal.border, space1, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, title)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, line)
									}),
								)
							})
						})
					}))
				}
				rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout))
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return ui.editorBox(gtx, "server-entries", &ui.serverEntriesEditor, "Импорт server entries Psiphon (вставьте hex или base64 строку)…")
						}),
						layout.Rigid(layout.Spacer{Width: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, &ui.importEntriesBtn, "plus", "Импортировать серверы", false, "primary")
						}),
					)
				}))
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
		// 3. Maintenance & Self-Check Card
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "refresh", "Обслуживание и самопроверка",
							"Проверка сети, сброс кэша DNS/маршрутов и сохранение архива диагностики (.zip)", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space2}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.maintenanceButtons(gtx, false)
					}),
				)
			})
		},
	}

	return material.List(ui.th, &ui.diagPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}
