//go:build windows

package main

import (
	"fmt"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// ---------- Tab 5: Диагностика (Проверка сайта, Статистика способов Psiphon, Импорт серверов, Обслуживание, Соединения) ----------

func (ui *gioUI) layoutTrafficDiagTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	diag := ui.diagRes
	psiStats := ui.psiStatsData
	ui.mu.Unlock()

	var liveConns []map[string]any
	if st != nil {
		if stats, ok := st["stats"].(map[string]any); ok {
			liveConns = toMapSlice(stats["live"])
		}
	}

	sections := []layout.Widget{
		// 1. Site Diagnostics Card (DNS, DoH, ECH & all routes)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "search", "Диагностика доступности сайта",
							"Проверка системного DNS, DoH, Encrypted ClientHello (ECH) и скорости через все маршруты", nil)
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
		// 3. Maintenance & Self-Check Card (moved from Home)
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
		// 4. Live Connections Card
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				var rows []layout.FlexChild
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.cardHeader(gtx, "lan", fmt.Sprintf("Активные соединения (%d)", len(liveConns)),
						"Текущие потоки программ и быстрый перевод любого домена в туннель или напрямую", nil)
				}))
				rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout))
				if len(liveConns) == 0 {
					rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.emptyState(gtx, "lan", "Сейчас нет активных соединений",
							"Откройте любой сайт в браузере — соединения появятся здесь в реальном времени.", "", nil)
					}))
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
				}
				limit := min(len(liveConns), 40)
				for i := 0; i < limit; i++ {
					c := liveConns[i]
					appNm, _ := c["app"].(string)
					h, _ := c["host"].(string)
					if sni, _ := c["sni"].(string); sni != "" {
						h = sni
					}
					ob, _ := c["outbound"].(string)
					rl, _ := c["rule"].(string)
					upB, _ := c["up"].(float64)
					dnB, _ := c["down"].(float64)

					btnTun := ui.appBtn("conn|" + h + "|psiphon")
					btnDir := ui.appBtn("conn|" + h + "|direct")
					btnBlk := ui.appBtn("conn|" + h + "|block")
					if btnTun.Clicked(gtx) && h != "" {
						targetH := h
						ui.doAsync("Правило: "+targetH+" → Psiphon VPN", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/conns/quick-rule", map[string]any{"host": targetH, "outbound": obPsiphon})
						})
					}
					if btnDir.Clicked(gtx) && h != "" {
						targetH := h
						ui.doAsync("Правило: "+targetH+" → Напрямую", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/conns/quick-rule", map[string]any{"host": targetH, "outbound": obDirect})
						})
					}
					if btnBlk.Clicked(gtx) && h != "" {
						targetH := h
						ui.doAsync("Правило: "+targetH+" → Блок", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/conns/quick-rule", map[string]any{"host": targetH, "outbound": obBlock})
						})
					}

					rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Bottom: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return ui.subCard(gtx, ui.pal.card2, ui.pal.border, space1, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, fmt.Sprintf("%s  →  %s", orDefault(appNm, "Система"), h))
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.routeBadge(gtx, ob)
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, fmt.Sprintf("%s · ↓%.0f КБ ↑%.0f КБ", rl, dnB/1024, upB/1024))
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.pillButton(gtx, btnTun, "В VPN", false, "vio")
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.pillButton(gtx, btnDir, "Напрямую", false, "ok")
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.pillButton(gtx, btnBlk, "Блок", false, "danger")
											}),
										)
									}),
								)
							})
						})
					}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
	}

	return material.List(ui.th, &ui.diagPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}
