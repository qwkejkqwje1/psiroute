//go:build windows

package main

import (
	"fmt"
	"image"
	"image/color"
	"strings"
	"time"

	"gioui.org/f32"
	"gioui.org/font"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// ---------- Tab 0: Главная («Командный центр» 1040×680 без вертикального скролла) ----------
//
// Разделён на три визуально чистых блока:
//   - Блок А (Левая колонка, 40% ширины) — Состояние, Питание (Серый/Янтарный с таймером/Изумрудный/Красный),
//     Живой визуальный пайплайн ПК (TUN) -> WARP (MASQUE) -> Psiphon (NL · 64 мс) с кликабельными звеньями,
//     и две быстрые кнопки: «Сменить сервер» и «Починить соединение».
//   - Блок Б (Правая верхняя зона, 60% ширины) — 3 крупные карточки глобального сценария
//     («Умный обход», «По моим правилам», «Весь трафик в VPN») и интерактивный омнибокс «Быстрое правило».
//   - Блок В (Нижняя полоса) — Мини-график скорости (68dp) и лента «Сейчас используют сеть» (3–4 процесса)
//     с переключением маршрута процесса в 1 клик.

func (ui *gioUI) layoutHomeTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	apps := ui.apps
	routePrev := ui.homeRoutePreview
	ui.mu.Unlock()

	psi, _ := st["psiphon"].(map[string]any)
	pState, _ := psi["state"].(string)
	if pState == "" {
		pState = "stopped"
	}
	if pState == "connecting" || pState == "reconnecting" {
		if ui.connectingStart.IsZero() {
			ui.connectingStart = time.Now()
		}
	} else {
		ui.connectingStart = time.Time{}
	}

	strat, _ := psi["strategy_title"].(string)
	reg, _ := psi["egress_region"].(string)
	cfgReg, _ := psi["region"].(string)
	ping, _ := psi["health_ms"].(float64)
	lastErr, _ := psi["last_error"].(string)
	diagReason, _ := psi["diag_reason"].(string)

	tunMap, _ := st["tun"].(map[string]any)
	tunOn, _ := tunMap["on"].(bool)
	needAdm, _ := tunMap["need_admin"].(bool)
	tunErr, _ := tunMap["error"].(string)
	sysProxyOn, _ := st["sysproxy"].(bool)
	warpOn, _ := st["warp_on"].(bool)
	warpMask, _ := st["warp_mask"].(string)
	mode, _ := st["mode"].(string)
	if mode == "" {
		mode = "psiphon"
	}
	paused, _ := st["paused"].(bool)
	pauseRem, _ := st["pause_remaining_sec"].(float64)
	netMap, _ := st["net"].(map[string]any)
	captiveOn, _ := netMap["captive_portal"].(bool)

	// Блок А (Левая колонка, 40% ширины) — Состояние, Питание и Визуальный пайплайн
	blockA := func(gtx layout.Context) layout.Dimensions {
		accent := ui.powerStateColor(pState, needAdm)
		return ui.heroCard(gtx, accent, func(gtx layout.Context) layout.Dimensions {
			stateHead := "Выключено"
			subTxt := "Нажмите кнопку питания для запуска защиты"
			switch {
			case needAdm && tunErr != "":
				stateHead = "Нужны права администратора"
				subTxt = "Для режима TUN перезапустите PsiRoute от имени администратора"
			case pState == "connected":
				stateHead = "Защищено"
				subTxt = "Канал активен · " + orDefault(strat, "Psiphon")
			case pState == "connecting" || pState == "reconnecting":
				sec := int(time.Since(ui.connectingStart).Seconds())
				if sec < 1 {
					sec = 1
				}
				stateHead = fmt.Sprintf("Поиск узла · %d с…", sec)
				subTxt = "Гонка протоколов: " + orDefault(strat, "подбор узла")
			case pState == "error":
				stateHead = "Ошибка соединения"
				if diagReason != "" {
					subTxt = diagReason
				} else if lastErr != "" {
					subTxt = lastErr
				} else {
					subTxt = "Не удалось подключиться к узлу"
				}
			}

			captureLbl := "Ручной прокси"
			if tunOn {
				captureLbl = "ПК (TUN)"
			} else if sysProxyOn {
				captureLbl = "Браузеры (Прокси)"
			}
			warpLbl := "WARP (Выкл)"
			if warpOn {
				m := strings.ToUpper(orDefault(warpMask, "MASQUE"))
				if m == "AUTO" {
					m = "MASQUE"
				}
				warpLbl = "WARP (" + m + ")"
			}
			dispCC := reg
			if dispCC == "" {
				dispCC = cfgReg
			}
			psiLbl := "Psiphon (" + cnameShort(dispCC)
			if ping > 0 {
				psiLbl += fmt.Sprintf(" · %.0f мс)", ping)
			} else {
				psiLbl += ")"
			}

			return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween}.Layout(gtx,
				// 1. Крупная кнопка питания и цветовое состояние
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.drawPowerButton(gtx, pState, needAdm)
						}),
						layout.Rigid(layout.Spacer{Width: space2}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.statusPill(gtx, pState)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontHero, ui.pal.text, font.Bold, stateHead)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, subTxt)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if !needAdm {
										return layout.Dimensions{}
									}
									return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.tunAdminBtn, "shield", "Нужны права администратора для TUN → Перезапустить", false, "danger")
									})
								}),
							)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				// 2. Цепочка активного канала (Визуальный интерактивный пайплайн)
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Bold, "ЦЕПОЧКА АКТИВНОГО КАНАЛА (НАЖМИТЕ НА ЗВЕНО ДЛЯ СМЕНЫ)")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
									func(gtx layout.Context) layout.Dimensions {
										style := ""
										if tunOn {
											style = "ok"
										}
										return ui.pillButton(gtx, &ui.pipeCaptureBtn, captureLbl, ui.pipePopup == 1 || tunOn, style)
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontBody, ui.pal.dim, font.Bold, "→")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, &ui.pipeWarpBtn, warpLbl, warpOn, "vio")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontBody, ui.pal.dim, font.Bold, "→")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.flagButton(gtx, &ui.pipePsiBtn, dispCC, psiLbl, ui.pipePopup == 2 || pState == "connected", "warn")
									},
								)
							}),
							// Выпадающий выбор звена 1: режим перехвата трафика
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if ui.pipePopup != 1 {
									return layout.Dimensions{}
								}
								return layout.Inset{Top: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
										func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, &ui.captureModeBtns[0], "Весь ПК [TUN]", tunOn, "ok")
										},
										func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, &ui.captureModeBtns[1], "Только браузеры [Системный прокси]", !tunOn && sysProxyOn, "primary")
										},
										func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, &ui.captureModeBtns[2], "Ручной прокси", !tunOn && !sysProxyOn, "")
										},
									)
								})
							}),
							// Выпадающий выбор звена 3: быстрая смена страны Psiphon
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if ui.pipePopup != 2 {
									return layout.Dimensions{}
								}
								return layout.Inset{Top: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return ui.compactCountryRow(gtx, cfgReg)
								})
							}),
						)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				// 3. Две быстрые кнопки под статусом + Таймер паузы (5 / 15 минут) и детектор Captive Portal
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, &ui.newNodeBtn, "refresh", "Сменить сервер", false, "primary")
								}),
								layout.Rigid(layout.Spacer{Width: space1}.Layout),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, &ui.repairConnBtn, "bolt", "Починить соединение", false, "teal")
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if paused {
								remSec := int(pauseRem)
								txt := fmt.Sprintf("Пауза активна (%02d:%02d) → Возобновить защиту", remSec/60, remSec%60)
								return ui.pillButton(gtx, &ui.pauseResumeBtn, txt, true, "warn")
							}
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.SemiBold, "Таймер паузы:")
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.pause5Btn, "Пауза 5 мин", false, "")
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.pause15Btn, "Пауза 15 мин", false, "")
								}),
							)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if !captiveOn {
								return layout.Dimensions{}
							}
							return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.captiveOpenBtn, "Требуется вход в сеть Wi-Fi → Открыть страницу авторизации", true, "warn")
							})
						}),
					)
				}),
			)
		})
	}

	// Блок Б (Правая верхняя зона, 60% ширины) — Режим работы (3 карточки) и Омнибокс «Быстрое правило»
	blockB := func(gtx layout.Context) layout.Dimensions {
		scenarios := [3]struct {
			modeKey string
			btnIdx  int // index in ui.modeBtns (0=psiphon, 1=rules, 2=auto)
			title   string
			sub     string
			badge   string
		}{
			{
				modeKey: "auto",
				btnIdx:  2,
				title:   "1. Умный обход",
				badge:   "Рекомендуется",
				sub:     "Российские сайты и игры напрямую (без пинга и капч), заблокированные — автоматически через DPI-обход или VPN.",
			},
			{
				modeKey: "rules",
				btnIdx:  1,
				title:   "2. По моим правилам",
				badge:   "Конвейер 1–7",
				sub:     "Строго по настроенным спискам, личным доменам и программам, без фонового автообучения.",
			},
			{
				modeKey: "psiphon",
				btnIdx:  0,
				title:   "3. Весь трафик в VPN",
				badge:   "Приватность",
				sub:     "Максимальная защита: весь трафик ПК идёт через выбранную страну (кроме локальной сети).",
			},
		}

		homeObs := [3]struct{ id, title, style string }{
			{obPsiphon, "В VPN", "warn"},
			{obDesync, "Обход DPI", "teal"},
			{obDirect, "Напрямую", "ok"},
		}

		return ui.card(gtx, unit.Dp(14), func(gtx layout.Context) layout.Dimensions {
			var cardRows []layout.FlexChild
			cardRows = append(cardRows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.caption(gtx, "Глобальный сценарий работы")
			}))
			cardRows = append(cardRows, layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout))

			for i := range scenarios {
				sc := scenarios[i]
				active := mode == sc.modeKey
				if i > 0 {
					cardRows = append(cardRows, layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout))
				}
				cardRows = append(cardRows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.scenarioCard(gtx, &ui.modeBtns[sc.btnIdx], sc.title, sc.badge, sc.sub, active)
				}))
			}

			cardRows = append(cardRows, layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout))
			// Интерактивная строка «Быстрое правило» (Омнибокс)
			cardRows = append(cardRows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, "Быстрое правило (Омнибокс)")
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if routePrev == "" {
										return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Normal, "Домен попадёт в Приоритет 3, программа .exe — в Приоритет 2")
									}
									return ui.labelLine(gtx, fontMicro, ui.pal.teal, font.Bold, "Маршрут: "+routePrev)
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.editorBox(gtx, "home-rule", &ui.homeRuleEditor, "Не открывается сайт или тормозит игра? Введите домен или программу.exe…")
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							var ws []layout.Widget
							for i := range homeObs {
								idx := i
								it := homeObs[idx]
								ws = append(ws, func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.homeRuleObBtns[idx], it.title, ui.homeRuleOb == it.id, it.style)
								})
							}
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.homeCheckBtn, "Проверить (?)", false, "")
							})
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.homeRuleAddBtn, "plus", "Добавить", false, "primary")
							})
							return flowWrap(gtx, unit.Dp(6), unit.Dp(6), ws...)
						}),
					)
				})
			}))

			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, cardRows...)
		})
	}

	// Блок В (Нижняя полоса) — Компактная телеметрия (68dp) и Лента «Сейчас используют сеть» (3–4 процесса)
	blockC := func(gtx layout.Context) layout.Dimensions {
		return ui.twoCol(gtx, 0.40, 0.60,
			func(gtx layout.Context) layout.Dimensions {
				return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
					return ui.drawCompactSpeedStrip(gtx, st)
				})
			},
			func(gtx layout.Context) layout.Dimensions {
				return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
					return ui.drawLiveAppsStrip(gtx, st, apps)
				})
			},
		)
	}

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.twoCol(gtx, 0.42, 0.58, blockA, blockB)
		},
		blockC,
	}
	return material.List(ui.th, &ui.mainList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: unit.Dp(10)}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) powerStateColor(pState string, needAdm bool) color.NRGBA {
	if needAdm {
		return ui.pal.err
	}
	switch pState {
	case "connected":
		return ui.pal.ok // Изумрудный (Защищено)
	case "connecting", "reconnecting":
		return ui.pal.warn // Янтарный (Поиск узла / Гонка протоколов)
	case "error":
		return ui.pal.err // Красный (Ошибка)
	default:
		return ui.pal.dim // Серый (Выкл)
	}
}

func (ui *gioUI) scenarioCard(gtx layout.Context, btn *widget.Clickable, title, badge, sub string, active bool) layout.Dimensions {
	bg := ui.pal.card2
	bdr := ui.pal.border
	titleCol := ui.pal.text
	if active {
		bg = mix(ui.pal.card2, ui.pal.acc, 0.14)
		bdr = ui.pal.acc
		titleCol = ui.pal.acc
	} else if btn.Hovered() {
		bg = ui.pal.hover
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		return ui.subCard(gtx, bg, bdr, unit.Dp(9), func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									col := ui.pal.dim
									if active {
										col = ui.pal.ok
									}
									return dotWidget(gtx, unit.Dp(8), col)
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontSub, titleCol, font.Bold, title)
								}),
							)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.SemiBold, badge)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, sub)
				}),
			)
		})
	})
}

func (ui *gioUI) drawPowerButton(gtx layout.Context, state string, needAdm bool) layout.Dimensions {
	sz := gtx.Dp(94)
	col := ui.powerStateColor(state, needAdm)
	hov := ui.powerBtn.Hovered()
	return ui.powerBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		gtx.Constraints = layout.Exact(image.Pt(sz, sz))

		haloA := uint8(22)
		if state == "connected" || hov {
			haloA = 46
		}
		paint.FillShape(gtx.Ops, tint(col, haloA), clip.Ellipse{Max: image.Pt(sz, sz)}.Op(gtx.Ops))

		midPad := gtx.Dp(6)
		mid := clip.Ellipse{Min: image.Pt(midPad, midPad), Max: image.Pt(sz-midPad, sz-midPad)}
		paint.FillShape(gtx.Ops, tint(col, 36), clip.Stroke{Path: mid.Path(gtx.Ops), Width: float32(gtx.Dp(1))}.Op())

		pad := gtx.Dp(12)
		inner := clip.Ellipse{Min: image.Pt(pad, pad), Max: image.Pt(sz-pad, sz-pad)}
		bg, fg := ui.pal.card, col
		if state == "connected" {
			bg, fg = col, rgb(0xFFFFFF)
		} else if hov {
			bg = mix(ui.pal.card, col, 0.18)
		}
		paint.FillShape(gtx.Ops, bg, inner.Op(gtx.Ops))
		paint.FillShape(gtx.Ops, col, clip.Stroke{Path: inner.Path(gtx.Ops), Width: float32(gtx.Dp(2.5))}.Op())

		is := gtx.Dp(30)
		t := op.Offset(image.Pt((sz-is)/2, (sz-is)/2)).Push(gtx.Ops)
		drawIcon(gtx, "power", unit.Dp(30), fg)
		t.Pop()
		return layout.Dimensions{Size: image.Pt(sz, sz)}
	})
}

func (ui *gioUI) metricChip(gtx layout.Context, title, val string) layout.Dimensions {
	return ui.subCard(gtx, ui.pal.card2, ui.pal.border, space1, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.label(gtx, fontSmall, ui.pal.dim, font.Normal, title)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.label(gtx, fontBody, ui.pal.text, font.Bold, val)
			}),
		)
	})
}

// drawCompactSpeedStrip рисует компактный мини-график скорости высотой строго 68dp (в пределах 60–80dp по ТЗ).
func (ui *gioUI) drawCompactSpeedStrip(gtx layout.Context, st map[string]any) layout.Dimensions {
	var spDown, spUp, totDown, totUp float64
	var hist [][2]float64
	if st != nil {
		if stats, ok := st["stats"].(map[string]any); ok {
			if tot, ok := stats["total"].(map[string]any); ok {
				totDown, _ = tot["down"].(float64)
				totUp, _ = tot["up"].(float64)
			}
			if spd, ok := stats["speed"].(map[string]any); ok {
				spDown, _ = spd["down"].(float64)
				spUp, _ = spd["up"].(float64)
				if rawH, ok := spd["history"].([]any); ok {
					for _, item := range rawH {
						if pair, ok := item.([]any); ok && len(pair) == 2 {
							u, _ := pair[0].(float64)
							d, _ := pair[1].(float64)
							hist = append(hist, [2]float64{u, d})
						}
					}
				}
			}
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontSmall, ui.pal.ok, font.Bold, "↓ "+fmtSpeed(spDown))
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontSmall, ui.pal.acc, font.Bold, "↑ "+fmtSpeed(spUp))
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.Normal,
						fmt.Sprintf("Сессия: ↓%s / ↑%s", fmtBytes(int64(totDown)), fmtBytes(int64(totUp))))
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			h := gtx.Dp(68)
			w := gtx.Constraints.Max.X
			sz := image.Pt(w, h)
			fillRect(gtx, sz, gtx.Dp(8), ui.pal.card2)
			strokeRect(gtx, sz, gtx.Dp(8), float32(gtx.Dp(1)), ui.pal.border)

			if len(hist) >= 2 && w > 16 {
				maxVal := 16384.0
				for _, pt := range hist {
					if pt[0] > maxVal {
						maxVal = pt[0]
					}
					if pt[1] > maxVal {
						maxVal = pt[1]
					}
				}
				baseY := float32(h - 4)
				var dlLine clip.Path
				dlLine.Begin(gtx.Ops)
				for i, pt := range hist {
					px := float32(i)/float32(len(hist)-1)*float32(w-10) + 5
					py := baseY - float32(pt[1]/maxVal)*float32(h-10)
					if py < 4 {
						py = 4
					}
					if i == 0 {
						dlLine.MoveTo(f32.Pt(px, py))
					} else {
						dlLine.LineTo(f32.Pt(px, py))
					}
				}
				paint.FillShape(gtx.Ops, ui.pal.ok, clip.Stroke{Path: dlLine.End(), Width: float32(gtx.Dp(2))}.Op())

				var upLine clip.Path
				upLine.Begin(gtx.Ops)
				for i, pt := range hist {
					px := float32(i)/float32(len(hist)-1)*float32(w-10) + 5
					py := baseY - float32(pt[0]/maxVal)*float32(h-10)
					if py < 4 {
						py = 4
					}
					if i == 0 {
						upLine.MoveTo(f32.Pt(px, py))
					} else {
						upLine.LineTo(f32.Pt(px, py))
					}
				}
				paint.FillShape(gtx.Ops, ui.pal.acc, clip.Stroke{Path: upLine.End(), Width: float32(gtx.Dp(1.5))}.Op())
			}
			return layout.Dimensions{Size: sz}
		}),
	)
}

// drawLiveAppsStrip рисует ленту «Сейчас используют сеть» (3–4 активных процесса) с переключением маршрута в 1 клик.
func (ui *gioUI) drawLiveAppsStrip(gtx layout.Context, st map[string]any, apps []map[string]any) layout.Dimensions {
	type liveProc struct {
		exe   string
		title string
		route string
	}
	var items []liveProc
	seen := map[string]bool{}

	for _, a := range apps {
		exe, _ := a["exe"].(string)
		if exe == "" {
			exe, _ = a["app"].(string)
		}
		if exe == "" || seen[strings.ToLower(exe)] {
			continue
		}
		running, _ := a["running"].(bool)
		conns, _ := a["conns"].(float64)
		rt, _ := a["route"].(string)
		if !running && conns == 0 && rt == "" {
			continue
		}
		seen[strings.ToLower(exe)] = true
		short := strings.TrimSuffix(exe, ".exe")
		items = append(items, liveProc{exe: exe, title: capFirst(short), route: rt})
		if len(items) >= 4 {
			break
		}
	}

	if len(items) == 0 {
		defaults := []liveProc{
			{exe: "chrome.exe", title: "Chrome", route: obPsiphon},
			{exe: "Discord.exe", title: "Discord", route: obWarp},
			{exe: "cs2.exe", title: "CS2", route: obDirect},
			{exe: "Telegram.exe", title: "Telegram", route: obPsiphon},
		}
		items = defaults
	}

	for i := 0; i < 4; i++ {
		if i < len(items) {
			ui.liveAppNames[i] = items[i].exe
			ui.liveAppRoutes[i] = items[i].route
		} else {
			ui.liveAppNames[i] = ""
			ui.liveAppRoutes[i] = ""
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, "Сейчас используют сеть")
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Normal, "Клик по программе меняет её маршрут (VPN → WARP → DPI → Напрямую)")
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			var chips []layout.Widget
			for i := range items {
				idx := i
				it := items[idx]
				rtTitle := routeShortRu(it.route)
				lbl := fmt.Sprintf("%s (%s)", it.title, rtTitle)
				style := "warn"
				switch it.route {
				case obDirect, "tun-exclude":
					style = "ok"
				case obDesync:
					style = "teal"
				case obWarp:
					style = "vio"
				case "":
					style = ""
				}
				chips = append(chips, func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, &ui.liveAppBtns[idx], lbl, it.route != "", style)
				})
			}
			return flowWrap(gtx, unit.Dp(8), unit.Dp(6), chips...)
		}),
	)
}
