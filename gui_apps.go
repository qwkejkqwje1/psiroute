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

// ---------- Tab 1: Split Tunneling / Running Apps Manager ----------

func (ui *gioUI) layoutAppsTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	apps := ui.apps
	presets := ui.presets
	ui.mu.Unlock()

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
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(18), func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.label(gtx, unit.Sp(18), ui.pal.text, font.Bold, "Программы")
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.appRefreshBtn, "refresh", "Обновить", false, "")
							}),
						)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.label(gtx, unit.Sp(13), ui.pal.mut, font.Normal,
							"Маршрут для каждой программы в один клик: VPN, VPN через выбранную страну, напрямую, DPI-обход, WARP или блокировка.")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.appTabBtns[0], fmt.Sprintf("Запущенные · %d", len(apps)), ui.appTabFilter == 0, "")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.appTabBtns[1], fmt.Sprintf("Каталог · %d", len(presets)), ui.appTabFilter == 1, "")
							}),
							layout.Flexed(1, layout.Spacer{}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.searchBox(gtx)
							}),
						)
					}),
				)
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return ui.card(gtx, unit.Dp(14), func(gtx layout.Context) layout.Dimensions {
				if len(items) == 0 {
					return ui.label(gtx, unit.Sp(14), ui.pal.mut, font.Normal, emptyAppsMsg(q))
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
						sub += " · ● запущено"
					}
					if b > 0 || conns > 0 {
						sub += fmt.Sprintf(" · трафик: %.1f МБ (%.0f соед.)", b/1048576, conns)
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
						ui.doAsync(fmt.Sprintf("Программа %s → %s", targetApp, targetOb), func() (map[string]any, error) {
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
							ui.doAsync(fmt.Sprintf("Программа %s → %s", targetApp, targetOb), func() (map[string]any, error) {
								return ui.apiCall("POST", "/api/apps", map[string]any{"app": targetApp, "outbound": targetOb})
							})
						}
					}

					return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return ui.label(gtx, unit.Sp(14), ui.pal.text, font.Bold, title)
												}),
												layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return ui.routeBadge(gtx, route)
												}),
											)
										}),
										layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.label(gtx, unit.Sp(11.5), ui.pal.mut, font.Normal, sub)
										}),
									)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, btnVPN, "Через VPN", route == obPsiphon, "vio")
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.flagButton(gtx, btnCty, ctyCC, ctyTxt, ctyOn, "vio")
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, btnDir, "Напрямую", route == obDirect || route == "tun-exclude", "ok")
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, btnDPI, "DPI-обход", route == obDesync, "teal")
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, btnWarp, "WARP", route == obWarp, "")
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, btnBlk, "Блок", route == obBlock, "danger")
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, btnDef, "Сброс", route == "", "")
										}),
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

