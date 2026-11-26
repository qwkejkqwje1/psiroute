//go:build windows

package main

import (
	"fmt"
	"sort"
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
	sortMode := ui.streamSortMode
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

	// Объединяем живые и недавние потоки (живые сверху с флагом _live=true, без дублей в recent)
	liveKeys := make(map[string]struct{}, len(liveConns))
	allStreams := make([]map[string]any, 0, len(liveConns)+len(recentConns))
	for _, lc := range liveConns {
		cp := make(map[string]any, len(lc)+1)
		for k, v := range lc {
			cp[k] = v
		}
		cp["_live"] = true
		appNm, _ := cp["app"].(string)
		h, _ := cp["host"].(string)
		if sni, _ := cp["sni"].(string); sni != "" {
			h = sni
		}
		liveKeys[appNm+"\x00"+h] = struct{}{}
		allStreams = append(allStreams, cp)
	}
	for _, rc := range recentConns {
		appNm, _ := rc["app"].(string)
		h, _ := rc["host"].(string)
		if _, exists := liveKeys[appNm+"\x00"+h]; exists {
			continue
		}
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

	sortRecentBtn := ui.appBtn("streams|sort-recent")
	sortTrDescBtn := ui.appBtn("streams|sort-traffic-desc")
	sortTrAscBtn := ui.appBtn("streams|sort-traffic-asc")
	sortNameBtn := ui.appBtn("streams|sort-name")
	if sortRecentBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.streamSortMode = 0
		sortMode = 0
		ui.mu.Unlock()
	}
	if sortTrDescBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.streamSortMode = 1
		sortMode = 1
		ui.mu.Unlock()
	}
	if sortTrAscBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.streamSortMode = 2
		sortMode = 2
		ui.mu.Unlock()
	}
	if sortNameBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.streamSortMode = 3
		sortMode = 3
		ui.mu.Unlock()
	}

	streamHost := func(m map[string]any) string {
		if sni, _ := m["sni"].(string); sni != "" {
			return sni
		}
		h, _ := m["host"].(string)
		return h
	}
	streamBytes := func(m map[string]any) float64 {
		dnB, _ := m["down"].(float64)
		upB, _ := m["up"].(float64)
		return dnB + upB
	}
	switch sortMode {
	case 1:
		sort.SliceStable(filteredConns, func(i, j int) bool {
			return streamBytes(filteredConns[i]) > streamBytes(filteredConns[j])
		})
	case 2:
		sort.SliceStable(filteredConns, func(i, j int) bool {
			return streamBytes(filteredConns[i]) < streamBytes(filteredConns[j])
		})
	case 3:
		sort.SliceStable(filteredConns, func(i, j int) bool {
			hi := strings.ToLower(orDefault(streamHost(filteredConns[i]), func() string { s, _ := filteredConns[i]["app"].(string); return s }()))
			hj := strings.ToLower(orDefault(streamHost(filteredConns[j]), func() string { s, _ := filteredConns[j]["app"].(string); return s }()))
			if hi != hj {
				return hi < hj
			}
			ai, _ := filteredConns[i]["app"].(string)
			aj, _ := filteredConns[j]["app"].(string)
			return strings.ToLower(ai) < strings.ToLower(aj)
		})
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
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return ui.editorBox(gtx, "stream-search", &ui.streamSearchEditor, "Фильтр потоков по домену, SNI, IP или программе…")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(2), func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.segRouteButton(gtx, sortRecentBtn, "Время", sortMode == 0, "primary")
										}),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.segRouteButton(gtx, sortTrDescBtn, "↓ Трафик", sortMode == 1, "teal")
										}),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.segRouteButton(gtx, sortTrAscBtn, "↑ Трафик", sortMode == 2, "warn")
										}),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.segRouteButton(gtx, sortNameBtn, "Имя A–Z", sortMode == 3, "vio")
										}),
									)
								})
							}),
						)
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

					rowKey := fmt.Sprintf("strm|%s|%s|%s|%d", appNm, h, proto, int(portF))
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
					meta := fmt.Sprintf("%s · %s:%d · правило: %s · ↓ %s ↑ %s (всего %s)",
						stateTag, strings.ToUpper(proto), int(portF), orDefault(rl, "по умолчанию"),
						fmtBytes(int64(dnB)), fmtBytes(int64(upB)), fmtBytes(int64(dnB+upB)))
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

// layoutDiagTab (Вкладка 6 «Диагностика»): 3 подвкладки — Проверки, Проверка сайта, Инструменты.
func (ui *gioUI) layoutDiagTab(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.layoutSubTabBar(gtx, 6, []string{"Проверки (Утечки и Самопроверка)", "Проверка сайта и трассы", "Инструменты и состояние ядра"})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			switch ui.subTabs[6] {
			case 1:
				return ui.layoutDiagSiteSub(gtx)
			case 2:
				return ui.layoutDiagToolsSub(gtx)
			default:
				return ui.layoutDiagChecksSub(gtx)
			}
		}),
	)
}

func (ui *gioUI) layoutTrafficDiagTab(gtx layout.Context) layout.Dimensions {
	return ui.layoutDiagTab(gtx)
}

func (ui *gioUI) renderCheckRows(gtx layout.Context, checks []any, titleKey string) layout.Dimensions {
	var rows []layout.FlexChild
	for _, raw := range checks {
		cm, _ := raw.(map[string]any)
		title, _ := cm[titleKey].(string)
		if title == "" {
			title, _ = cm["name"].(string)
		}
		if title == "" {
			title, _ = cm["title"].(string)
		}
		detail, _ := cm["detail"].(string)
		status, _ := cm["status"].(string)
		col := ui.pal.ok
		tag := "OK"
		if status == "warn" {
			col = ui.pal.warn
			tag = "ВНИМАНИЕ"
		} else if status == "fail" {
			col = ui.pal.err
			tag = "ОШИБКА"
		} else if status == "info" {
			col = ui.pal.teal
			tag = "ИНФО"
		}
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return ui.subCard(gtx, ui.pal.card2, tint(col, 115), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, title)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if detail == "" {
										return layout.Dimensions{}
									}
									return ui.label(gtx, fontMicro, ui.pal.mut, font.Normal, ui.maskText(detail))
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Width: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.miniTag(gtx, col, tag)
						}),
					)
				})
			})
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
}

func (ui *gioUI) layoutDiagChecksSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	lr := ui.leakRes
	sr := ui.selftestRes
	ui.mu.Unlock()

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.twoCol(gtx, 0.5, 0.5,
				// Тест утечек
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var rows []layout.FlexChild
						rows = append(rows,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "shield", "Тест утечек (1 клик)",
									"Внешний IP, DNS/Split-DNS, IPv6 blackhole, WebRTC/STUN, Kill Switch и чужие VPN-адаптеры",
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.leakTestBtn, "play", "Запустить", false, "primary")
									})
							}),
						)
						if lr != nil {
							verdict, _ := lr["verdict"].(string)
							passed, _ := lr["passed"].(float64)
							total, _ := lr["total"].(float64)
							vCol := ui.pal.ok
							vTxt := fmt.Sprintf("✓ Утечек нет (%.0f/%.0f)", passed, total)
							if verdict == "warn" {
								vCol = ui.pal.warn
								vTxt = fmt.Sprintf("⚠ Есть рекомендации (%.0f/%.0f)", passed, total)
							} else if verdict != "ok" {
								vCol = ui.pal.err
								vTxt = fmt.Sprintf("✕ Найдены проблемы (%.0f/%.0f)", passed, total)
							}
							rows = append(rows,
								layout.Rigid(layout.Spacer{Height: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.miniTag(gtx, vCol, vTxt) }),
							)
							if checks, ok := lr["checks"].([]any); ok {
								rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.renderCheckRows(gtx, checks, "title")
								}))
							}
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				},
				// Самопроверка программы
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var rows []layout.FlexChild
						rows = append(rows,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "check", "Самопроверка программы",
									"Полная проверка сети, DNS, ядра, прав администратора и конфигурации",
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.selftestBtn, "play", "Запустить", false, "primary")
									})
							}),
						)
						if sr != nil {
							if checks, ok := sr["checks"].([]any); ok {
								rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.renderCheckRows(gtx, checks, "name")
								}))
							}
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				},
			)
		},
	}
	return material.List(ui.th, &ui.diagPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutDiagSiteSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	diag := ui.diagRes
	psiStats := ui.psiStatsData
	ui.mu.Unlock()

	sections := []layout.Widget{
		// Диагностика сайта
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				var rows []layout.FlexChild
				rows = append(rows,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "search", "Глубокая диагностика доступности сайта",
							"Проверка системного DNS, DoH, Encrypted ClientHello (ECH) и скорости через Direct, DPI, WARP и Psiphon", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return ui.editorBox(gtx, "diag-host", &ui.diagEditor, "например, www.youtube.com или 2ip.io (Ctrl+F)")
							}),
							layout.Rigid(layout.Spacer{Width: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.diagRunBtn, "search", "Проверить сайт", false, "primary")
							}),
						)
					}),
				)
				if diag != nil {
					best, _ := diag["best"].(string)
					dnsMap, _ := diag["dns"].(map[string]any)
					hasECH, _ := dnsMap["ech"].(bool)
					echTxt := "нет записи HTTPS ECH"
					if hasECH {
						echTxt = "поддерживается ECH (Encrypted ClientHello)"
					}
					rows = append(rows,
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.subCard(gtx, ui.pal.okSoft, tint(ui.pal.ok, 120), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
								return ui.label(gtx, fontBody, ui.pal.ok, font.SemiBold,
									fmt.Sprintf("Лучший маршрут: %s   ·   %s", orDefault(best, "не найден"), echTxt))
							})
						}),
					)
					if routes, ok := diag["routes"].([]any); ok {
						for _, rr := range routes {
							rm, _ := rr.(map[string]any)
							name, _ := rm["route"].(string)
							if name == "" {
								name, _ = rm["outbound"].(string)
							}
							okR, _ := rm["ok"].(bool)
							msR, _ := rm["ms"].(float64)
							errR, _ := rm["error"].(string)
							col := ui.pal.err
							info := orDefault(errR, "недоступно")
							if okR {
								col = ui.pal.ok
								info = fmt.Sprintf("OK · %.0f мс", msR)
							}
							rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: unit.Dp(5)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return ui.kvRow(gtx, routeShortRu(name), info)
								})
							}))
							_ = col
						}
					}
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
		// Статистика способов Psiphon для текущей сети
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
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
					fmt.Sprintf("Телеметрия стратегий Psiphon (%s)", orDefault(netKey, "net-default")),
					fmt.Sprintf("NetworkID: %s · импортировано записей серверов: %.0f", orDefault(netID, "psiroute"), imported), nil)
			}))
			for i := range stratRows {
				sr := stratRows[i]
				title, _ := sr["title"].(string)
				att, _ := sr["attempts"].(float64)
				succ, _ := sr["successes"].(float64)
				medMs, _ := sr["median_connect_ms"].(float64)
				medLife, _ := sr["median_lifetime_sec"].(float64)
				score, _ := sr["score"].(float64)
				unstable, _ := sr["unstable"].(bool)
				line := fmt.Sprintf("попыток: %.0f · успехов: %.0f · вход: %.0f мс · жизнь: %.0f с · оценка: %.0f",
					att, succ, medMs, medLife, score)
				if unstable {
					line += " · [нестабилен]"
				}
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: unit.Dp(5)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, title) }),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, line) }),
							)
						})
					})
				}))
			}
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
	}
	return material.List(ui.th, &ui.diagPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutDiagToolsSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()

	memStr := "—"
	if mem, ok := st["mem"].(map[string]any); ok {
		if t, _ := mem["text"].(string); t != "" {
			memStr = t
		} else if tot, ok := mem["total"].(float64); ok && tot > 0 {
			memStr = fmt.Sprintf("%.0f МБ", tot/1048576)
		}
	}
	fakeIPCnt, _ := st["fakeip_count"].(float64)
	panicsCnt, _ := st["panics"].(float64)
	restartsCnt, _ := st["crash_restarts"].(float64)
	learnedCnt, _ := st["learned_count"].(float64)
	udpMode := "—"
	var udpFlows float64
	if udp, ok := st["udp"].(map[string]any); ok {
		udpMode, _ = udp["mode"].(string)
		udpFlows, _ = udp["flows"].(float64)
	}
	netName := "—"
	if netM, ok := st["net"].(map[string]any); ok {
		if n, _ := netM["name"].(string); n != "" {
			netName = n
		} else if t, _ := netM["text"].(string); t != "" {
			netName = t
		}
	}

	sections := []layout.Widget{
		// Быстрые инструменты обслуживания
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "refresh", "Инструменты обслуживания",
							"Сброс DNS, перезапуск сетевого стека и сохранение диагностического архива (.zip)", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, space1, space1,
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.clearDNSBtn, "refresh", "Сбросить кэш DNS", false, "")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.resetStackBtn, "bolt", "Reset Stack", false, "warn")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.reportBtn, "download", "Создать отчёт (.zip)", false, "primary")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.clearLearnBtn, "swap", "Забыть выученные маршруты", false, "")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.refreshListBtn, "download", "Обновить все списки", false, "")
							},
						)
					}),
				)
			})
		},
		// Состояние ядра (телеметрия служб)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "chart", "Состояние ядра", "Сводка по внутренним службам PsiRoute", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Память процесса", memStr) }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "FakeIP адресов в пуле", fmt.Sprintf("%.0f", fakeIPCnt)) }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Выученных маршрутов", fmt.Sprintf("%.0f", learnedCnt)) }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "UDP-режим / активные потоки", fmt.Sprintf("%s / %.0f", orDefault(udpMode, "—"), udpFlows)) }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Активная сеть", ui.maskSensitive(netName)) }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Перехваченных сбоев / перезапусков", fmt.Sprintf("%.0f / %.0f", panicsCnt, restartsCnt)) }),
				)
			})
		},
	}
	return material.List(ui.th, &ui.diagPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}
