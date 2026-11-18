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
// FILE: gui_settings.go (Полноэкранный Живой Журнал Событий + Настройки сети)
// ============================================================================
//
// Исправление отрисовки журнала:
//   - Журнал вынесен в отдельную полноэкранную панель (layoutLiveLogOnlyTab) БЕЗ
//     вложенного material.List внутри setPageList, благодаря чему Gio корректно
//     вычисляет высоту области прокрутки и мгновенно отображает все строки.
//   - Добавлены фильтры уровней (Все / Предупреждения / Ошибки) и кнопка копирования.

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

	var filtered []map[string]any
	warnCount, errCount := 0, 0
	for i := len(logs) - 1; i >= 0; i-- {
		ln := logs[i]
		lv, _ := ln["level"].(string)
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
							fmt.Sprintf("Живой журнал событий PsiRoute v%s (%d записей)", version, len(logs)),
							"Новые записи отображаются сверху. Журнал сохраняется при фоновом опросе и поддерживает быстрый фильтр ошибок.",
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, btnCopyLog, "copy", "Скопировать журнал", false, "primary")
							})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
							func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, btnAll, fmt.Sprintf("Все события (%d)", len(logs)), logFilter == 0, "primary")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, btnWarn, fmt.Sprintf("⚠ Предупреждения и ошибки (%d)", warnCount+errCount), logFilter == 1, "warn")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, btnErr, fmt.Sprintf("🔴 Только ошибки (%d)", errCount), logFilter == 2, "danger")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.clearDNSBtn, "refresh", "Сбросить кэш DNS", false, "")
							},
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

func (ui *gioUI) layoutSettingsOnlyTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()

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
						return ui.cardHeader(gtx, "gear", fmt.Sprintf("Все параметры сети, DNS и защиты (PsiRoute v%s)", version),
							"Главные переключатели вынесены на Командный центр, все системные опции сгруппированы здесь",
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
	}
	return material.List(ui.th, &ui.setPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutSettingsLogTab(gtx layout.Context) layout.Dimensions {
	return ui.layoutLiveLogOnlyTab(gtx)
}
