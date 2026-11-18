//go:build windows

package main

import (
	"fmt"
	"image"
	"image/color"
	"net/url"
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

// ============================================================================
// FILE: gui_home.go (Модернизированный командный центр Tactical Minimal)
// ============================================================================
//
// Ключевые возможности:
//   - На кнопке Пуска (drawPowerButton) при подключении горит большой яркий флаг
//     страны подключения + код региона (например, NL, DE, FI).
//   - Визуально разделены способ перехвата (TUN / Прокси) и глобальный сценарий
//     маршрутизации (Умный обход / По моим правилам / Весь трафик в VPN).
//   - Предупреждающий баннер, если выбран режим «По правилам», а TUN выключен.
//   - Внизу — график скорости с заливкой и живой мини-инспектор (процессы + сбросы ТСПУ)
//     с быстрым переходом во вкладку «Потоки».

func (ui *gioUI) layoutHomeTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st, apps, preview := ui.state, ui.apps, ui.homeRoutePreview
	ui.mu.Unlock()

	// Живая проверка маршрута при вводе текста в омнибокс Главной (с debounce 250 мс)
	curInput := strings.TrimSpace(ui.homeRuleEditor.Text())
	if curInput != ui.lastHomeQuery {
		ui.lastHomeQuery = curInput
		stamp := time.Now()
		ui.mu.Lock()
		ui.lastHomeCheckAt = stamp
		ui.mu.Unlock()
		if curInput == "" {
			ui.mu.Lock()
			ui.homeRoutePreview = ""
			ui.mu.Unlock()
			preview = ""
		} else {
			target := curInput
			go func(raw string, ts time.Time) {
				time.Sleep(250 * time.Millisecond)
				ui.mu.Lock()
				stillCurrent := ui.lastHomeQuery == raw && ui.lastHomeCheckAt.Equal(ts)
				ui.mu.Unlock()
				if !stillCurrent {
					return
				}
				q := "/api/route?host=" + url.QueryEscape(raw) + "&port=443"
				if strings.HasSuffix(strings.ToLower(raw), ".exe") || !strings.Contains(raw, ".") {
					exe := raw
					if !strings.HasSuffix(strings.ToLower(exe), ".exe") {
						exe += ".exe"
					}
					q = "/api/route?host=example.com&port=443&app=" + url.QueryEscape(exe)
				}
				if res, err := ui.apiCall("GET", q, nil); err == nil && res != nil {
					badge, _ := res["badge"].(string)
					conflict, _ := res["conflict"].(string)
					msg := "Текущий маршрут: " + badge
					if conflict != "" {
						msg += "  ⚠ " + conflict
					}
					ui.mu.Lock()
					if strings.TrimSpace(ui.homeRuleEditor.Text()) == raw {
						ui.homeRoutePreview = msg
					}
					ui.mu.Unlock()
					if ui.w != nil {
						ui.w.Invalidate()
					}
				}
			}(target, stamp)
		}
	}

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

	capture := "Ручной прокси (127.0.0.1:1080)"
	if tunOn {
		capture = "Весь ПК перехвачен ➔ Режим TUN"
	} else if proxy {
		capture = "Браузеры перехвачены ➔ Системный прокси"
	}

	country := "Выход: Psiphon VPN ➔ " + cnameShort(cc)
	if ping > 0 {
		country += fmt.Sprintf(" (%.0f мс)", ping)
	}

	button := func(btn *widget.Clickable, title string, active bool, style string) layout.Widget {
		return func(gtx layout.Context) layout.Dimensions { return ui.pillButton(gtx, btn, title, active, style) }
	}
	gap := func(h unit.Dp) layout.FlexChild { return layout.Rigid(layout.Spacer{Height: h}.Layout) }

	left := func(gtx layout.Context) layout.Dimensions {
		return ui.heroCard(gtx, ui.powerStateColor(state, admin), func(gtx layout.Context) layout.Dimensions {
			status := "Защита PsiRoute отключена"
			subStatus := "Нажмите на кнопку Пуска для старта VPN-туннеля"
			switch state {
			case "connected":
				status = "Туннель активен ➔ " + countryLabel(cc)
				subStatus = fmt.Sprintf("Выход %s защищён · FakeIP + DoH активны (v%s)", cnameShort(cc), version)
			case "connecting", "reconnecting":
				status = fmt.Sprintf("Гонка протоколов ТСПУ ➔ %d сек", int(time.Since(ui.connectingStart).Seconds()))
				subStatus = "Автоподбор OSSH / TLS / Conduit / WARP"
			case "error":
				status = "Ошибка подключения к VPN"
				subStatus = "Нажмите «Починить DPI обход» для сброса и смены узла"
			}

			children := []layout.FlexChild{
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.drawPowerButtonWithFlag(gtx, state, admin, cc)
						}),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Left: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontSub, ui.pal.text, font.Bold, status)
									}),
									layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.label(gtx, fontMicro, ui.pal.mut, font.Normal, subStatus)
									}),
								)
							})
						}),
					)
				}),
				gap(10),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.caption(gtx, "Схема перехвата и подложки пакетов:")
				}),
				gap(5),
				layout.Rigid(button(&ui.pipeCaptureBtn, capture, ui.pipePopup == 1, "primary")),
				gap(4),
				layout.Rigid(button(&ui.pipeWarpBtn, "Защитная подложка Cloudflare WARP ➔ "+onOffRu(warp), warp, "warn")),
				gap(4),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.flagButton(gtx, &ui.pipePsiBtn, cc, country, ui.pipePopup == 2, "vio")
				}),
				gap(8),
			}

			if ui.pipePopup == 1 {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, ui.pal.card2, ui.pal.acc, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
							button(&ui.captureModeBtns[0], "Режим TUN (Весь ПК)", tunOn, "ok"),
							button(&ui.captureModeBtns[1], "Системный прокси (Браузеры)", proxy && !tunOn, "primary"),
							button(&ui.captureModeBtns[2], "Ручной прокси", !proxy && !tunOn, ""),
						)
					})
				}), gap(6))
			}

			if ui.pipePopup == 2 {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, ui.pal.card2, ui.pal.vio, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
						return ui.compactCountryRow(gtx, configured)
					})
				}), gap(6))
			}

			// Предупреждение о выключенном TUN, если выбран сценарий «По правилам»
			if mode == "rules" && !tunOn {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, ui.pal.card2, ui.pal.warn, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.label(gtx, fontSmall, ui.pal.warn, font.Bold, "⚠ Нужен TUN для маршрутизации программ (.exe)")
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.label(gtx, fontMicro, ui.pal.mut, font.Normal, "Правила для Discord.exe, Telegram и игр требуют адаптер Wintun (TUN). Прокси перехватывает только браузеры.")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
							layout.Rigid(button(&ui.captureModeBtns[0], "Включить режим TUN прямо сейчас", false, "warn")),
						)
					})
				}), gap(6))
			}

			if admin {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.iconButton(gtx, &ui.tunAdminBtn, "shield", "Запросить права Администратора для Wintun", false, "danger")
				}), gap(6))
			}

			children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
					button(&ui.newNodeBtn, "Сменить сервер", false, "primary"),
					button(&ui.restartPsiBtn, "Переподключить", false, ""),
					button(&ui.repairConnBtn, "Починить DPI обход", false, "teal"),
				)
			}), gap(8))

			paused, _ := st["paused"].(bool)
			if paused {
				remaining, _ := st["pause_remaining_sec"].(float64)
				children = append(children, layout.Rigid(button(&ui.pauseResumeBtn, fmt.Sprintf("Пауза защиты %02d:%02d ➔ Возобновить", int(remaining)/60, int(remaining)%60), true, "warn")))
			} else {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Bold, "ПАУЗА:")
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return flowWrap(gtx, unit.Dp(4), unit.Dp(4),
								button(&ui.pause5Btn, "5 минут", false, ""),
								button(&ui.pause15Btn, "15 минут", false, ""),
							)
						}),
					)
				}))
			}

			netState, _ := st["net"].(map[string]any)
			if portal, _ := netState["captive_portal"].(bool); portal {
				children = append(children, gap(6), layout.Rigid(button(&ui.captiveOpenBtn, "Авторизоваться в Captive Portal Wi-Fi", true, "warn")))
			}

			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	}

	right := func(gtx layout.Context) layout.Dimensions {
		return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
			scenarios := []struct {
				mode, title, badge, sub string
				idx                     int
			}{
				{"auto", "Умный обход ТСПУ (Рекомендуемый)", "Автоподбор", "Прямое подключение для РФ, DPI для блоков, VPN для жёстких блокировок.", 2},
				{"rules", "По моим правилам", "Строгий режим", "В VPN/DPI идут ТОЛЬКО указанные сайты и программы; всё остальное — напрямую.", 1},
				{"psiphon", "Направить весь трафик в VPN", "Глобальный", "Шифрует 100% трафика через Psiphon; правила с Always (банки РФ, игры) идут напрямую.", 0},
			}

			children := []layout.FlexChild{
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.caption(gtx, "Глобальный сценарий маршрутизации:")
				}),
				gap(5),
			}

			for _, sc := range scenarios {
				sc := sc
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.scenarioCard(gtx, &ui.modeBtns[sc.idx], sc.title, sc.badge, sc.sub, mode == sc.mode)
				}), gap(5))
			}

			children = append(children,
				gap(6),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, "Интерактивный омнибокс / Быстрое правило:")
				}),
				gap(4),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.editorBox(gtx, "home-rule", &ui.homeRuleEditor, "Впишите домен (youtube.com) или программу (Discord.exe)")
				}),
				gap(5),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					options := []struct{ id, title, style string }{
						{obDirect, "Direct", "ok"},
						{obDesync, "DPI Обход", "teal"},
						{obWarp, "WARP", "warn"},
						{obPsiphon, "Psiphon VPN", "vio"},
						{obBlock, "Блок", "danger"},
					}
					var buttons []layout.Widget
					for i, option := range options {
						i, option := i, option
						buttons = append(buttons, func(gtx layout.Context) layout.Dimensions {
							return ui.segRouteButton(gtx, &ui.homeRuleObBtns[i], option.title, ui.homeRuleOb == option.id, option.style)
						})
					}
					return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(4), func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, unit.Dp(4), unit.Dp(4), buttons...)
					})
				}),
				gap(5),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, &ui.homeCheckBtn, "search", "Проверить трассу", false, "")
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							gtx.Constraints.Min.X = gtx.Constraints.Max.X
							return ui.iconButton(gtx, &ui.homeRuleAddBtn, "plus", "Сохранить в правила", false, "primary")
						}),
					)
				}),
			)

			if preview != "" {
				col := ui.pal.teal
				if strings.Contains(preview, "⚠") {
					col = ui.pal.warn
				}
				children = append(children, gap(5), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, ui.pal.card2, col, unit.Dp(6), func(gtx layout.Context) layout.Dimensions {
						return ui.monoLabel(gtx, fontMicro, col, preview)
					})
				}))
			}

			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return ui.twoCol(gtx, .44, .56, left, right) }),
		gap(10),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			h := gtx.Dp(82)
			gtx.Constraints.Min.Y, gtx.Constraints.Max.Y = h, h
			return ui.twoCol(gtx, .44, .56, func(gtx layout.Context) layout.Dimensions {
				return ui.card(gtx, unit.Dp(8), func(gtx layout.Context) layout.Dimensions { return ui.drawCompactSpeedStrip(gtx, st) })
			}, func(gtx layout.Context) layout.Dimensions {
				return ui.card(gtx, unit.Dp(8), func(gtx layout.Context) layout.Dimensions { return ui.drawLiveAppsStrip(gtx, st, apps) })
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
		return ui.pal.ok
	case "connecting", "reconnecting":
		return ui.pal.warn
	case "error":
		return ui.pal.err
	default:
		return ui.pal.dim
	}
}

func (ui *gioUI) scenarioCard(gtx layout.Context, btn *widget.Clickable, title, badge, sub string, active bool) layout.Dimensions {
	bg := ui.pal.card2
	bdr := ui.pal.border
	titleCol := ui.pal.text
	if active {
		bg = mix(ui.pal.card2, ui.pal.acc, 0.16)
		bdr = ui.pal.acc
		titleCol = ui.pal.acc
	} else if btn.Hovered() {
		bg = ui.pal.hover
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		return ui.subCard(gtx, bg, bdr, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
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
	return ui.drawPowerButtonWithFlag(gtx, state, needAdm, "")
}

// drawPowerButtonWithFlag рисует главную кнопку Пуска.
// При активном подключении (state == "connected") внутри светящегося кольца Пуска
// загорается БОЛЬШОЙ флаг страны подключения (48×32 dp) и код региона.
func (ui *gioUI) drawPowerButtonWithFlag(gtx layout.Context, state string, needAdm bool, cc string) layout.Dimensions {
	sz := gtx.Dp(94)
	col := ui.powerStateColor(state, needAdm)
	hov := ui.powerBtn.Hovered()
	return ui.powerBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		gtx.Constraints = layout.Exact(image.Pt(sz, sz))

		haloA := uint8(26)
		if state == "connected" || hov {
			haloA = 58
		}
		paint.FillShape(gtx.Ops, tint(col, haloA), clip.Ellipse{Max: image.Pt(sz, sz)}.Op(gtx.Ops))

		midPad := gtx.Dp(5)
		mid := clip.Ellipse{Min: image.Pt(midPad, midPad), Max: image.Pt(sz-midPad, sz-midPad)}
		paint.FillShape(gtx.Ops, tint(col, 65), clip.Stroke{Path: mid.Path(gtx.Ops), Width: float32(gtx.Dp(1.5))}.Op())

		pad := gtx.Dp(10)
		inner := clip.Ellipse{Min: image.Pt(pad, pad), Max: image.Pt(sz-pad, sz-pad)}
		bg, fg := ui.pal.card, col
		if state == "connected" {
			bg = mix(ui.pal.card, col, 0.24)
			fg = rgb(0xFFFFFF)
		} else if hov {
			bg = mix(ui.pal.card, col, 0.18)
		}
		paint.FillShape(gtx.Ops, bg, inner.Op(gtx.Ops))
		paint.FillShape(gtx.Ops, col, clip.Stroke{Path: inner.Path(gtx.Ops), Width: float32(gtx.Dp(3))}.Op())

		if state == "connected" {
			flagCC := strings.ToUpper(strings.TrimSpace(cc))
			if flagCC == "" || flagCC == "AUTO" {
				flagCC = "NL"
			}
			fw, fh := gtx.Dp(46), gtx.Dp(31)
			fx := (sz - fw) / 2
			fy := (sz - fh) / 2 - gtx.Dp(6)
			t := op.Offset(image.Pt(fx, fy)).Push(gtx.Ops)
			drawCountryFlag(gtx, flagCC, unit.Dp(46), unit.Dp(31))
			t.Pop()

			// Подпись кода страны под большим флагом внутри кнопки Пуска
			badgeRect := image.Rect(sz/2-gtx.Dp(18), fy+fh+gtx.Dp(3), sz/2+gtx.Dp(18), fy+fh+gtx.Dp(17))
			paint.FillShape(gtx.Ops, col, clip.UniformRRect(badgeRect, gtx.Dp(4)).Op(gtx.Ops))
			bt := op.Offset(image.Pt(badgeRect.Min.X, badgeRect.Min.Y-gtx.Dp(1))).Push(gtx.Ops)
			cgtx := gtx
			cgtx.Constraints = layout.Exact(image.Pt(badgeRect.Dx(), badgeRect.Dy()))
			layout.Center.Layout(cgtx, func(gtx layout.Context) layout.Dimensions {
				return ui.labelLine(gtx, fontMicro, rgb(0xFFFFFF), font.Bold, cnameShort(cc))
			})
			bt.Pop()
			return layout.Dimensions{Size: image.Pt(sz, sz)}
		}

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
							return ui.monoLabel(gtx, fontSmall, ui.pal.ok, "↓ "+fmtSpeed(spDown))
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.monoLabel(gtx, fontSmall, ui.pal.acc, "↑ "+fmtSpeed(spUp))
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.monoLabel(gtx, fontMicro, ui.pal.mut, "Σ "+fmtBytes(int64(totDown+totUp)))
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			h := gtx.Dp(38)
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

// drawLiveAppsStrip на Главной автоматически выводит радар ТСПУ-сбросов, если они зафиксированы ядром,
// и позволяет в 1 клик переключить маршрут или открыть вкладку «Потоки».
func (ui *gioUI) drawLiveAppsStrip(gtx layout.Context, st map[string]any, apps []map[string]any) layout.Dimensions {
	type liveProc struct {
		exe   string
		title string
		route string
		alert bool
	}
	var items []liveProc
	seen := map[string]bool{}

	// Сначала сканируем live-соединения на предмет скрытых блокировок ТСПУ (отправлено >0 Б, ответа 0 Б на Direct маршрутах)
	if stats, ok := st["stats"].(map[string]any); ok {
		if liveConns, ok := stats["live"].([]any); ok {
			for _, cVal := range liveConns {
				if c, ok := cVal.(map[string]any); ok {
					ob, _ := c["outbound"].(string)
					appNm, _ := c["app"].(string)
					upB, _ := c["up"].(float64)
					dnB, _ := c["down"].(float64)
					host, _ := c["host"].(string)
					if appNm != "" && upB > 0 && dnB == 0 && (ob == obDirect || ob == obDesync) && !seen[strings.ToLower(appNm)] {
						seen[strings.ToLower(appNm)] = true
						short := strings.TrimSuffix(appNm, ".exe")
						items = append(items, liveProc{
							exe:   appNm,
							title: fmt.Sprintf("⚠ %s (Дроп ТСПУ: %s)", capFirst(short), ui.maskSensitive(host)),
							route: ob,
							alert: true,
						})
					}
				}
			}
		}
	}

	// Дополняем обычными активными процессами
	for _, a := range apps {
		if len(items) >= 4 {
			break
		}
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
		items = append(items, liveProc{exe: exe, title: capFirst(short), route: rt, alert: false})
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

	openStreamsBtn := ui.appBtn("home|open-streams")
	if openStreamsBtn.Clicked(gtx) {
		ui.tab = 2
		go ui.fetchAll(true)
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, "Потоки трафика / Триггеры ТСПУ:")
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, openStreamsBtn, "Открыть все потоки ➔", false, "teal")
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			var chips []layout.Widget
			for i := range items {
				idx := i
				it := items[idx]
				rtTitle := routeShortRu(it.route)
				lbl := fmt.Sprintf("%s (%s)", it.title, rtTitle)

				style := "vio"
				if it.alert {
					style = "danger"
				} else {
					switch it.route {
					case obDirect, "tun-exclude":
						style = "ok"
					case obDesync:
						style = "teal"
					case obWarp:
						style = "warn"
					case "":
						style = ""
					}
				}

				chips = append(chips, func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, &ui.liveAppBtns[idx], lbl, it.route != "", style)
				})
			}
			if len(chips) == 0 {
				return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, "Активных сокетов нет — откройте сайт или вкладку «Потоки»")
			}
			var cells []layout.FlexChild
			for _, chip := range chips {
				cells = append(cells, layout.Flexed(1, chip))
			}
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, cells...)
		}),
	)
}
