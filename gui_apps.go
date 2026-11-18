//go:build windows

package main

import (
	"fmt"
	"strings"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// ============================================================================
// FILE: gui_apps.go (Split Tunneling & Контроль захвата Wintun)
// ============================================================================

func (ui *gioUI) layoutAppsTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	apps := ui.apps
	presets := ui.presets
	st := ui.state
	ui.mu.Unlock()

	tunMap, _ := st["tun"].(map[string]any)
	tunOn, _ := tunMap["on"].(bool)

	items := apps
	if ui.appTabFilter == 1 {
		items = presets
	}
	q := strings.TrimSpace(ui.appSearch.Text())
	if lq := strings.ToLower(q); lq != "" {
		var f []map[string]any
		for _, it := range items {
			exe, _ := it["app"].(string)
			title, _ := it["title"].(string)
			cat, _ := it["category"].(string)
			if strings.Contains(strings.ToLower(exe+" "+title+" "+cat), lq) {
				f = append(f, it)
			}
		}
		items = f
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Информационный баннер режима Wintun TUN
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
				bdrColor := ui.pal.ok
				statusText := "Режим TUN активен — Wintun перехватывает трафик игр и программ автоматически"
				if !tunOn {
					bdrColor = ui.pal.warn
					statusText = "⚠ ВНИМАНИЕ: Маршрутизация программ ОТКЛЮЧЕНА, так как выключен режим TUN!"
				}
				return ui.subCard(gtx, ui.pal.card2, bdrColor, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontBody, bdrColor, font.Bold, statusText)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.Normal, "Для раздельного туннелирования процессов (.exe) требуется виртуальный адаптер Wintun. Прокси-режим перехватывает только браузеры.")
								}),
							)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if tunOn {
								return layout.Dimensions{}
							}
							return ui.pillButton(gtx, &ui.tunBtn, "Включить режим TUN", false, "warn")
						}),
					)
				})
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.caption(gtx, "Раздельное туннелирование программ (Split Tunneling):")
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.appRefreshBtn, "refresh", "Обновить список", false, "")
							}),
						)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.appTabBtns[0], fmt.Sprintf("Активные в сети (%d)", len(apps)), ui.appTabFilter == 0, "primary")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.appTabBtns[1], fmt.Sprintf("Каталог шаблонов (%d)", len(presets)), ui.appTabFilter == 1, "primary")
							}),
							layout.Flexed(1, layout.Spacer{}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.searchBox(gtx) }),
						)
					}),
				)
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
				if len(items) == 0 {
					return ui.label(gtx, fontBody, ui.pal.mut, font.Normal, emptyAppsMsg(q))
				}
				return material.List(ui.th, &ui.appList).Layout(gtx, len(items), func(gtx layout.Context, i int) layout.Dimensions {
					it := items[i]
					exe, _ := it["app"].(string)
					title, _ := it["title"].(string)
					cat, _ := it["category"].(string)
					route, _ := it["route"].(string)
					running, _ := it["running"].(bool)
					b, _ := it["bytes"].(float64)
					conns, _ := it["conns"].(float64)

					sub := exe + " · " + cat
					if running {
						sub += " · ● процесс запущен"
					}
					if b > 0 || conns > 0 {
						sub += fmt.Sprintf(" · трафик: %.1f МБ (%.0f TCP/UDP)", b/1048576, conns)
					}

					btnVPN := ui.appBtn(exe + "|psiphon")
					btnDir := ui.appBtn(exe + "|direct")
					btnDPI := ui.appBtn(exe + "|direct-dpi")
					btnWarp := ui.appBtn(exe + "|warp")
					btnBlk := ui.appBtn(exe + "|block")
					btnDef := ui.appBtn(exe + "|default")
					btnCty := ui.appBtn(exe + "|country")

					if btnCty.Clicked(gtx) {
						targetApp, targetOb := exe, nextAppCountry(route)
						ui.doAsync(fmt.Sprintf("Программа %s ➔ %s", targetApp, routeShortRu(targetOb)), func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/apps", map[string]any{"app": targetApp, "outbound": targetOb})
						})
					}
					ctyTxt, ctyCC, ctyOn := "Страна", "auto", false
					if cc, ok := strings.CutPrefix(route, obPsiphon+":"); ok {
						ctyTxt, ctyCC, ctyOn = "Страна: "+cc, cc, true
					}

					for _, pair := range []struct {
						b  *widget.Clickable
						ob string
					}{
						{btnVPN, obPsiphon}, {btnDir, obDirect}, {btnDPI, obDesync},
						{btnWarp, obWarp}, {btnBlk, obBlock}, {btnDef, "default"},
					} {
						if pair.b.Clicked(gtx) {
							targetApp, targetOb := exe, pair.ob
							ui.doAsync(fmt.Sprintf("Программа %s ➔ %s", targetApp, routeShortRu(targetOb)), func() (map[string]any, error) {
								return ui.apiCall("POST", "/api/apps", map[string]any{"app": targetApp, "outbound": targetOb})
							})
						}
					}

					return layout.Inset{Bottom: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.label(gtx, fontBody, ui.pal.text, font.Bold, title) }),
												layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.routeBadge(gtx, route) }),
											)
										}),
										layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, sub) }),
									)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.subCard(gtx, ui.pal.card, ui.pal.border, unit.Dp(2), func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.segRouteButton(gtx, btnDir, "Direct", route == obDirect || route == "tun-exclude", "ok")
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.segRouteButton(gtx, btnDPI, "DPI", route == obDesync, "teal")
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.segRouteButton(gtx, btnWarp, "WARP", route == obWarp, "warn")
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.segRouteButton(gtx, btnVPN, "В VPN", route == obPsiphon, "vio")
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.segRouteButton(gtx, btnBlk, "Блок", route == obBlock, "danger")
													}),
												)
											})
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.flagButton(gtx, btnCty, ctyCC, ctyTxt, ctyOn, "vio") }),
										layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.pillButton(gtx, btnDef, "Сброс", route == "", "") }),
									)
								}),
							)
						})
					})
				})
			})
		}),
	)
}
