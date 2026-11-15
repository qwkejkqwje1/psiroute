//go:build windows

package main

import (
	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// ---------- Tab 6: Настройки и Журнал (Все сгруппированные переключатели + Журнал) ----------

func (ui *gioUI) layoutSettingsLogTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()
	var logs []map[string]any
	if st != nil {
		logs = toMapSlice(st["log"])
	}

	group := func(title string, keys ...string) layout.FlexChild {
		return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: space2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.caption(gtx, title)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.grid(gtx, unit.Dp(240), 3, ui.toggleTiles(st, keys...))
					}),
				)
			})
		})
	}

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "gear", "Все параметры сети, DNS и защиты",
							"Главные 4 переключателя вынесены на главный экран, остальные 8 сгруппированы здесь",
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.quitBtn, "power", "Выйти из Psiroute", false, "danger")
							})
					}),
					group("Подключение и локальная сеть", "sysproxy", "tun", "warp", "share", "lan", "single"),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						tunMap, _ := st["tun"].(map[string]any)
						needAdm, _ := tunMap["need_admin"].(bool)
						if !needAdm {
							return layout.Dimensions{}
						}
						return layout.Inset{Top: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, &ui.tunAdminBtn, "shield", "Перезапустить от администратора (для режима TUN)", false, "primary")
						})
					}),
					group("Шифрованный DNS и FakeIP", "doh", "localdns", "fakeip"),
					group("Защита от утечек и обход блокировок", "kill", "stun", "quic"),
				)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			h := gtx.Dp(340)
			gtx.Constraints.Min.Y = h
			gtx.Constraints.Max.Y = h
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.Y = gtx.Constraints.Max.Y
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "chart", "Журнал событий", "Новые записи сверху", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						if len(logs) == 0 {
							return ui.emptyState(gtx, "chart", "Журнал пока пуст", "События подключения и обновления списков появятся здесь.", "", nil)
						}
						return material.List(ui.th, &ui.logList).Layout(gtx, len(logs), func(gtx layout.Context, i int) layout.Dimensions {
							ln := logs[len(logs)-1-i]
							tm, _ := ln["time"].(string)
							lv, _ := ln["level"].(string)
							msg, _ := ln["msg"].(string)
							col := ui.pal.text
							if lv == "warn" {
								col = ui.pal.warn
							} else if lv == "error" {
								col = ui.pal.err
							}
							return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.monoLabel(gtx, fontSmall, ui.pal.dim, tm+"  ")
									}),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return ui.label(gtx, fontBody, col, font.Normal, msg)
									}),
								)
							})
						})
					}),
				)
			})
		},
	}
	return material.List(ui.th, &ui.setPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}
