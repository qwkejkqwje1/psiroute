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
)

// ---------- Tab 0: Главная («Командный центр» 1040×680 без вертикального скролла) ----------
//
// Разделён на три визуально чистых блока:
//   - Блок А (Левая колонка, 40% ширины) — Состояние, Питание (Серый/Янтарный с таймером/Изумрудный/Красный),
//     Пайплайн захвата, WARP и выхода Psiphon с кликабельными звеньями,
//     и две быстрые кнопки: «Сменить сервер» и «Починить соединение».
//   - Блок Б (Правая верхняя зона, 60% ширины) — 3 крупные карточки глобального сценария
//     («Умный обход», «По моим правилам», «Весь трафик в VPN») и интерактивный омнибокс «Быстрое правило».
//   - Блок В (Нижняя полоса) — Мини-график скорости (68dp) и лента «Сейчас используют сеть» (3–4 процесса)
//     с переключением маршрута процесса в 1 клик.

func (ui *gioUI) layoutHomeTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st, apps, preview := ui.state, ui.apps, ui.homeRoutePreview
	ui.mu.Unlock()
	psi, _ := st["psiphon"].(map[string]any)
	state, _ := psi["state"].(string)
	if state == "" {
		state = "stopped"
	}
	if state == "connecting" || state == "reconnecting" {
		if ui.connectingStart.IsZero() {
			ui.connectingStart = time.Now()
		}
	} else {
		ui.connectingStart = time.Time{}
	}
	tun, _ := st["tun"].(map[string]any)
	tunOn, _ := tun["on"].(bool)
	admin, _ := tun["need_admin"].(bool)
	proxy, _ := st["sysproxy"].(bool)
	warp, _ := st["warp_on"].(bool)
	mode, _ := st["mode"].(string)
	cc, _ := psi["egress_region"].(string)
	configured, _ := psi["region"].(string)
	if cc == "" {
		cc = configured
	}
	ping, _ := psi["health_ms"].(float64)
	capture := "Ручной прокси"
	if tunOn {
		capture = "Весь ПК · TUN"
	} else if proxy {
		capture = "Браузеры · прокси"
	}
	country := "Psiphon · " + cnameShort(cc)
	if ping > 0 {
		country += fmt.Sprintf(" · %.0f мс", ping)
	}
	button := func(btn *widget.Clickable, title string, active bool, style string) layout.Widget {
		return func(gtx layout.Context) layout.Dimensions { return ui.pillButton(gtx, btn, title, active, style) }
	}
	gap := func(h unit.Dp) layout.FlexChild { return layout.Rigid(layout.Spacer{Height: h}.Layout) }
	left := func(gtx layout.Context) layout.Dimensions {
		return ui.heroCard(gtx, ui.powerStateColor(state, admin), func(gtx layout.Context) layout.Dimensions {
			status := "Защита выключена"
			switch state {
			case "connected":
				status = "Канал подключён"
			case "connecting", "reconnecting":
				status = fmt.Sprintf("Поиск узла · %d с", int(time.Since(ui.connectingStart).Seconds()))
			case "error":
				status = "Ошибка соединения"
			}
			children := []layout.FlexChild{
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx, layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.drawPowerButton(gtx, state, admin) }), layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontSub, ui.pal.text, font.Bold, status)
					}))
				}),
				gap(8), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.caption(gtx, "Захват → подложка → выход")
				}), gap(6),
				layout.Rigid(button(&ui.pipeCaptureBtn, capture, ui.pipePopup == 1, "primary")), gap(6),
				layout.Rigid(button(&ui.pipeWarpBtn, "WARP · "+onOffRu(warp), warp, "vio")), gap(6),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.flagButton(gtx, &ui.pipePsiBtn, cc, country, ui.pipePopup == 2, "warn")
				}), gap(8),
			}
			if ui.pipePopup == 1 {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return flowWrap(gtx, 4, 4, button(&ui.captureModeBtns[0], "TUN", tunOn, ""), button(&ui.captureModeBtns[1], "Прокси", proxy && !tunOn, ""), button(&ui.captureModeBtns[2], "Вручную", !proxy && !tunOn, ""))
				}), gap(6))
			}
			if ui.pipePopup == 2 {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.compactCountryRow(gtx, configured) }), gap(6))
			}
			if admin {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.iconButton(gtx, &ui.tunAdminBtn, "shield", "Права для TUN", false, "danger")
				}), gap(6))
			}
			children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return flowWrap(gtx, 4, 4, button(&ui.newNodeBtn, "Другой сервер", false, "primary"), button(&ui.restartPsiBtn, "Переподключить", false, ""), button(&ui.repairConnBtn, "Починить", false, "teal"))
			}), gap(6))
			paused, _ := st["paused"].(bool)
			if paused {
				remaining, _ := st["pause_remaining_sec"].(float64)
				children = append(children, layout.Rigid(button(&ui.pauseResumeBtn, fmt.Sprintf("Пауза %02d:%02d · Продолжить", int(remaining)/60, int(remaining)%60), true, "warn")))
			} else {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return flowWrap(gtx, 4, 4, button(&ui.pause5Btn, "Пауза 5 мин", false, ""), button(&ui.pause15Btn, "15 мин", false, ""))
				}))
			}
			netState, _ := st["net"].(map[string]any)
			if portal, _ := netState["captive_portal"].(bool); portal {
				children = append(children, gap(6), layout.Rigid(button(&ui.captiveOpenBtn, "Войти в сеть Wi-Fi", true, "warn")))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	}
	right := func(gtx layout.Context) layout.Dimensions {
		return ui.card(gtx, 12, func(gtx layout.Context) layout.Dimensions {
			scenarios := []struct {
				mode, title, badge, sub string
				idx                     int
			}{
				{"auto", "Умный обход", "Автоматически", "Прямое соединение, DPI или VPN по доступности.", 2},
				{"rules", "По моим правилам", "Без обучения", "Личные правила и списки; затем маршрут по умолчанию.", 1},
				{"psiphon", "Весь трафик в VPN", "Psiphon", "VPN по умолчанию; ваши явные исключения сохраняются.", 0},
			}
			children := []layout.FlexChild{layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.caption(gtx, "Сценарий маршрутизации")
			}), gap(6)}
			for _, sc := range scenarios {
				sc := sc
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.scenarioCard(gtx, &ui.modeBtns[sc.idx], sc.title, sc.badge, sc.sub, mode == sc.mode)
				}), gap(5))
			}
			children = append(children, gap(4), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, "Быстрое правило · сайт или программа")
			}), gap(4), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.editorBox(gtx, "home-rule", &ui.homeRuleEditor, "example.com или Discord.exe")
			}), gap(5), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				options := []struct{ id, title, style string }{{obDirect, "Direct", "ok"}, {obDesync, "DPI", "teal"}, {obWarp, "WARP", "vio"}, {obPsiphon, "Psiphon", "warn"}, {obBlock, "Блок", "danger"}}
				var buttons []layout.Widget
				for i, option := range options {
					i, option := i, option
					buttons = append(buttons, button(&ui.homeRuleObBtns[i], option.title, ui.homeRuleOb == option.id, option.style))
				}
				return flowWrap(gtx, 4, 4, buttons...)
			}), gap(5), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return flowWrap(gtx, 6, 4, button(&ui.homeCheckBtn, "Проверить маршрут", false, ""), button(&ui.homeRuleAddBtn, "Добавить правило", false, "primary"))
			}))
			if preview != "" {
				children = append(children, gap(4), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontMicro, ui.pal.teal, font.Normal, preview)
				}))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return ui.twoCol(gtx, .40, .60, left, right) }),
		gap(8),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			h := gtx.Dp(76)
			gtx.Constraints.Min.Y = h
			gtx.Constraints.Max.Y = h
			return ui.twoCol(gtx, .40, .60, func(gtx layout.Context) layout.Dimensions {
				return ui.card(gtx, 6, func(gtx layout.Context) layout.Dimensions { return ui.drawCompactSpeedStrip(gtx, st) })
			}, func(gtx layout.Context) layout.Dimensions {
				return ui.card(gtx, 6, func(gtx layout.Context) layout.Dimensions { return ui.drawLiveAppsStrip(gtx, st, apps) })
			})
		}),
	)
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
					return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, sub)
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
						"Σ "+fmtBytes(int64(totDown+totUp)))
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			h := gtx.Dp(36)
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
		conns, _ := a["conns"].(float64)
		rt, _ := a["route"].(string)
		if conns == 0 {
			continue
		}
		seen[strings.ToLower(exe)] = true
		short := strings.TrimSuffix(exe, ".exe")
		items = append(items, liveProc{exe: exe, title: capFirst(short), route: rt})
		if len(items) >= 4 {
			break
		}
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
					return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, "Активные приложения")
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Normal, "Клик: сменить маршрут")
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
			if len(chips) == 0 {
				return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, "Нет активных соединений")
			}
			var cells []layout.FlexChild
			for _, chip := range chips {
				cells = append(cells, layout.Flexed(1, chip))
			}
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, cells...)
		}),
	)
}
