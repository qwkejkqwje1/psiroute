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
// FILE: gui_home.go — Командный центр PsiRoute v2.2 (Obsidian Pro)
// ============================================================================
//
// Современный одноэкранный командный центр без прокрутки:
//   - Левая колонка: световая кнопка Пуск (104dp) с большим флагом страны и
//     явной индикацией отключения при наведении; пошаговая цепочка перехвата
//     (TUN/Прокси -> WARP -> Psiphon) с инлайн-переключателями; быстрые действия
//     и таймер паузы.
//   - Правая колонка: 3 карточки глобальных сценариев маршрутизации с акцентной
//     индикацией и интерактивный омнибокс с мгновенным превью маршрута.
//   - Нижний телеметрический док: график скорости с полупрозрачной заливкой и
//     живой радар активных процессов / сбросов ТСПУ (клик по ТСПУ-дропу создаёт
//     правило именно для домена, не перехватывая весь браузер .exe).

func (ui *gioUI) layoutHomeTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st, apps, preview := ui.state, ui.apps, ui.homeRoutePreview
	lastQ := ui.lastHomeQuery
	ui.mu.Unlock()

	// Живая проверка маршрута при вводе текста в омнибокс (debounce 250 мс, потокобезопасно)
	curInput := strings.TrimSpace(ui.homeRuleEditor.Text())
	if curInput != lastQ {
		stamp := time.Now()
		ui.mu.Lock()
		ui.lastHomeQuery = curInput
		ui.lastHomeCheckAt = stamp
		if curInput == "" {
			ui.homeRoutePreview = ""
			preview = ""
		}
		ui.mu.Unlock()
		if curInput != "" {
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
					msg := "Маршрут сейчас: " + badge
					if conflict != "" {
						msg += "  ⚠ " + conflict
					}
					ui.mu.Lock()
					if ui.lastHomeQuery == raw {
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
	userStopped, _ := psi["user_stopped"].(bool)
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
	proto, _ := psi["protocol"].(string)

	captureTitle := "Ручной прокси"
	captureBadge := "127.0.0.1:1080"
	captureCol := ui.pal.dim
	if tunOn {
		captureTitle = "Режим TUN (Весь ПК)"
		captureBadge = "Wintun активен"
		captureCol = ui.pal.ok
	} else if proxy {
		captureTitle = "Системный прокси"
		captureBadge = "Браузеры"
		captureCol = ui.pal.acc
	}

	countryTitle := "Выход Psiphon · " + cnameShort(cc)
	countryBadge := "Выбрать"
	if ping > 0 && state == "connected" {
		countryBadge = fmt.Sprintf("%.0f мс", ping)
	} else if configured != "" {
		countryBadge = strings.ToUpper(configured)
	}

	button := func(btn *widget.Clickable, title string, active bool, style string) layout.Widget {
		return func(gtx layout.Context) layout.Dimensions { return ui.pillButton(gtx, btn, title, active, style) }
	}
	gap := func(h unit.Dp) layout.FlexChild { return layout.Rigid(layout.Spacer{Height: h}.Layout) }

	left := func(gtx layout.Context) layout.Dimensions {
		return ui.heroCard(gtx, ui.powerStateColor(state, admin), func(gtx layout.Context) layout.Dimensions {
			status := "VPN отключён"
			subStatus := "Нажмите кнопку Пуск для подключения туннеля"
			if userStopped {
				subStatus = "Отключён вручную · трафик идёт напрямую"
			}
			switch state {
			case "connected":
				status = "Защищено · " + countryLabel(cc)
				extra := "Нажмите Пуск, чтобы отключить VPN"
				if proto != "" {
					extra = fmt.Sprintf("%s · Нажмите Пуск для отключения", proto)
				}
				subStatus = extra
			case "connecting", "reconnecting":
				status = fmt.Sprintf("Подключение · %d сек", int(time.Since(ui.connectingStart).Seconds()))
				subStatus = "Гонка протоколов ТСПУ · нажмите Пуск для отмены"
			case "stopping":
				status = "Отключение VPN…"
				subStatus = "Закрытие туннелей и активных VPN-сессий"
			case "error":
				status = "Ошибка подключения"
				subStatus = "Нажмите «Починить DPI» или попробуйте снова"
			}

			children := []layout.FlexChild{
				// Hero-блок: кнопка Пуск + статус + быстрые метрики
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.drawPowerButtonWithFlag(gtx, state, admin, cc)
						}),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Left: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontTitle, ui.pal.text, font.Bold, status)
									}),
									layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, subStatus)
									}),
									layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return flowWrap(gtx, unit.Dp(5), unit.Dp(5),
											func(gtx layout.Context) layout.Dimensions {
												return ui.miniTag(gtx, ui.powerStateColor(state, admin), stateTitle(state))
											},
											func(gtx layout.Context) layout.Dimensions {
												if ping > 0 && state == "connected" {
													return ui.miniTag(gtx, ui.pal.teal, fmt.Sprintf("RTT %.0f мс", ping))
												}
												return ui.miniTag(gtx, ui.pal.dim, "v"+version)
											},
										)
									}),
								)
							})
						}),
					)
				}),
				gap(12),
				// Компактная полоса управления туннелем
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							gtx.Constraints.Min.X = gtx.Constraints.Max.X
							return ui.iconButton(gtx, &ui.newNodeBtn, "swap", "Узел", false, "")
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							gtx.Constraints.Min.X = gtx.Constraints.Max.X
							return ui.iconButton(gtx, &ui.restartPsiBtn, "refresh", "Рестарт", false, "")
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
						layout.Flexed(1.15, func(gtx layout.Context) layout.Dimensions {
							gtx.Constraints.Min.X = gtx.Constraints.Max.X
							return ui.iconButton(gtx, &ui.repairConnBtn, "bolt", "Починить DPI", false, "teal")
						}),
					)
				}),
				gap(12),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.caption(gtx, "Цепочка трафика:")
				}),
				gap(6),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.pipelineRow(gtx, &ui.pipeCaptureBtn, "shield", "", captureTitle, captureBadge, captureCol, ui.pipePopup == 1)
				}),
				gap(5),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					wCol := ui.pal.dim
					wBadge := "Выкл"
					if warp {
						wCol = ui.pal.warn
						wBadge = "Активен"
					}
					return ui.pipelineRow(gtx, &ui.pipeWarpBtn, "bolt", "", "Подложка Cloudflare WARP", wBadge, wCol, warp)
				}),
				gap(5),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.pipelineRow(gtx, &ui.pipePsiBtn, "", cc, countryTitle, countryBadge, ui.pal.vio, ui.pipePopup == 2)
				}),
				gap(8),
			}

			if ui.pipePopup == 1 {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, ui.pal.card2, tint(ui.pal.acc, 140), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
							button(&ui.captureModeBtns[0], "TUN (Весь ПК)", tunOn, "ok"),
							button(&ui.captureModeBtns[1], "Системный прокси", proxy && !tunOn, "primary"),
							button(&ui.captureModeBtns[2], "Ручной прокси", !proxy && !tunOn, ""),
						)
					})
				}), gap(6))
			}

			if ui.pipePopup == 2 {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, ui.pal.card2, tint(ui.pal.vio, 140), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
						return ui.compactCountryRow(gtx, configured)
					})
				}), gap(6))
			}

			// Предупреждение о выключенном TUN (отдельная кнопка ui.tunBannerBtn без коллизии с captureModeBtns[0])
			if mode == "rules" && !tunOn {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, mix(ui.pal.card2, ui.pal.warn, 0.08), tint(ui.pal.warn, 150), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontSmall, ui.pal.warn, font.Bold, "Для правил программ (.exe) нужен TUN")
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.Normal, "Прокси перехватывает только браузеры")
									}),
								)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(button(&ui.tunBannerBtn, "Включить TUN", false, "warn")),
						)
					})
				}), gap(6))
			}

			if admin {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.iconButton(gtx, &ui.tunAdminBtn, "shield", "Перезапустить от Администратора (Wintun)", false, "danger")
				}), gap(6))
			}

			paused, _ := st["paused"].(bool)
			if paused {
				remaining, _ := st["pause_remaining_sec"].(float64)
				children = append(children, layout.Rigid(button(&ui.pauseResumeBtn, fmt.Sprintf("Пауза %02d:%02d · Возобновить защиту", int(remaining)/60, int(remaining)%60), true, "warn")))
			} else {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Bold, "ПАУЗА ЗАЩИТЫ:")
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return flowWrap(gtx, unit.Dp(5), unit.Dp(5),
								button(&ui.pause5Btn, "5 мин", false, ""),
								button(&ui.pause15Btn, "15 мин", false, ""),
							)
						}),
					)
				}))
			}

			netState, _ := st["net"].(map[string]any)
			if portal, _ := netState["captive_portal"].(bool); portal {
				children = append(children, gap(6), layout.Rigid(button(&ui.captiveOpenBtn, "Авторизоваться в Wi-Fi (Captive Portal)", true, "warn")))
			}

			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	}

	right := func(gtx layout.Context) layout.Dimensions {
		return ui.card(gtx, unit.Dp(14), func(gtx layout.Context) layout.Dimensions {
			scenarios := []struct {
				mode, title, badge, sub string
				idx                     int
				col                     color.NRGBA
			}{
				{"auto", "Умный обход ТСПУ", "Рекомендуемый", "РФ напрямую, DPI для блоков, VPN для жёстких блокировок", 2, ui.pal.teal},
				{"rules", "По моим правилам", "Строгий", "В VPN/DPI идут только указанные сайты и программы; остальное — напрямую", 1, ui.pal.acc},
				{"psiphon", "Весь трафик через VPN", "Глобальный", "100% трафика в Psiphon; исключения Always (банки РФ, игры) — напрямую", 0, ui.pal.vio},
			}

			children := []layout.FlexChild{
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.caption(gtx, "Сценарий маршрутизации:")
				}),
				gap(6),
			}

			for _, sc := range scenarios {
				sc := sc
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.scenarioCard(gtx, &ui.modeBtns[sc.idx], sc.title, sc.badge, sc.sub, mode == sc.mode, sc.col)
				}), gap(6))
			}

			children = append(children,
				gap(4),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.caption(gtx, "Быстрое правило / Проверка трассы:")
				}),
				gap(5),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.editorBox(gtx, "home-rule", &ui.homeRuleEditor, "Домен (youtube.com) или программа (Discord.exe)…")
				}),
				gap(6),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					options := []struct{ id, title, style string }{
						{obDirect, "Direct", "ok"},
						{obDesync, "DPI", "teal"},
						{obWarp, "WARP", "warn"},
						{obPsiphon, "VPN", "vio"},
						{obBlock, "Блок", "danger"},
					}
					return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(3), func(gtx layout.Context) layout.Dimensions {
						var segs []layout.FlexChild
						for i, option := range options {
							i, option := i, option
							if i > 0 {
								segs = append(segs, layout.Rigid(layout.Spacer{Width: unit.Dp(3)}.Layout))
							}
							segs = append(segs, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								gtx.Constraints.Min.X = gtx.Constraints.Max.X
								return ui.segRouteButton(gtx, &ui.homeRuleObBtns[i], option.title, ui.homeRuleOb == option.id, option.style)
							}))
						}
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, segs...)
					})
				}),
				gap(6),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, &ui.homeCheckBtn, "search", "Проверить", false, "")
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
				children = append(children, gap(6), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.subCard(gtx, mix(ui.pal.card2, col, 0.08), tint(col, 140), unit.Dp(7), func(gtx layout.Context) layout.Dimensions {
						return ui.monoLabel(gtx, fontMicro, col, preview)
					})
				}))
			}

			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return ui.twoCol(gtx, .45, .55, left, right) }),
		gap(10),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			h := gtx.Dp(88)
			gtx.Constraints.Min.Y, gtx.Constraints.Max.Y = h, h
			return ui.twoCol(gtx, .45, .55, func(gtx layout.Context) layout.Dimensions {
				return ui.card(gtx, unit.Dp(10), func(gtx layout.Context) layout.Dimensions { return ui.drawCompactSpeedStrip(gtx, st) })
			}, func(gtx layout.Context) layout.Dimensions {
				return ui.card(gtx, unit.Dp(10), func(gtx layout.Context) layout.Dimensions { return ui.drawLiveAppsStrip(gtx, st, apps) })
			})
		}),
	)
}

func (ui *gioUI) miniTag(gtx layout.Context, col color.NRGBA, txt string) layout.Dimensions {
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fillRect(gtx, gtx.Constraints.Min, gtx.Dp(6), tint(col, 32))
			strokeRect(gtx, gtx.Constraints.Min, gtx.Dp(6), float32(gtx.Dp(1)), tint(col, 85))
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(2), Bottom: unit.Dp(2), Left: unit.Dp(7), Right: unit.Dp(7)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return ui.labelLine(gtx, fontMicro, col, font.SemiBold, txt)
			})
		},
	)
}

func (ui *gioUI) pipelineRow(gtx layout.Context, btn *widget.Clickable, icon, flagCC, title, badge string, col color.NRGBA, active bool) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	bg := ui.pal.card2
	bdr := ui.pal.border
	if active {
		bg = mix(ui.pal.card2, col, 0.14)
		bdr = tint(col, 170)
	} else if btn.Hovered() {
		bg = ui.pal.hover
		bdr = tint(col, 120)
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				rad := gtx.Dp(10)
				fillRect(gtx, gtx.Constraints.Min, rad, bg)
				strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), bdr)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if flagCC != "" {
								return drawCountryFlag(gtx, flagCC, unit.Dp(18), unit.Dp(12))
							}
							return ui.iconBadge(gtx, icon, col, tint(col, 36), unit.Dp(24))
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, title)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.miniTag(gtx, col, badge)
						}),
					)
				})
			},
		)
	})
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
	case "stopping":
		return ui.pal.err
	case "error":
		return ui.pal.err
	default:
		return ui.pal.dim
	}
}

func (ui *gioUI) scenarioCard(gtx layout.Context, btn *widget.Clickable, title, badge, sub string, active bool, accent color.NRGBA) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	bg := ui.pal.card2
	bdr := ui.pal.border
	titleCol := ui.pal.text
	if active {
		bg = mix(ui.pal.card2, accent, 0.14)
		bdr = tint(accent, 185)
		titleCol = ui.pal.text
	} else if btn.Hovered() {
		bg = ui.pal.hover
		bdr = tint(ui.pal.dim, 130)
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				rad := gtx.Dp(10)
				fillRect(gtx, gtx.Constraints.Min, rad, bg)
				strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), bdr)
				if active && gtx.Constraints.Min.Y > gtx.Dp(16) {
					bar := image.Rect(0, gtx.Dp(8), gtx.Dp(3), gtx.Constraints.Min.Y-gtx.Dp(8))
					paint.FillShape(gtx.Ops, accent, clip.UniformRRect(bar, gtx.Dp(2)).Op(gtx.Ops))
				}
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											col := ui.pal.dim
											if active {
												col = accent
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
									bCol := ui.pal.mut
									if active {
										bCol = accent
									}
									return ui.miniTag(gtx, bCol, badge)
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, sub)
						}),
					)
				})
			},
		)
	})
}

func (ui *gioUI) drawPowerButton(gtx layout.Context, state string, needAdm bool) layout.Dimensions {
	return ui.drawPowerButtonWithFlag(gtx, state, needAdm, "")
}

// drawPowerButtonWithFlag рисует главную кнопку Пуска (104×104 dp):
//   - При подключении: светящееся изумрудное кольцо + флаг страны + код региона;
//     при наведении кольцо мягко смещается к коралловому цвету, показывая, что клик отключит VPN.
//   - При отключении (stopping): коралловый индикатор.
//   - В остановленном состоянии: минималистичная иконка питания с подсветкой при наведении.
func (ui *gioUI) drawPowerButtonWithFlag(gtx layout.Context, state string, needAdm bool, cc string) layout.Dimensions {
	sz := gtx.Dp(104)
	col := ui.powerStateColor(state, needAdm)
	hov := ui.powerBtn.Hovered()
	ringCol := col
	if state == "connected" && hov {
		ringCol = mix(col, ui.pal.err, 0.72)
	}
	return ui.powerBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		gtx.Constraints = layout.Exact(image.Pt(sz, sz))

		haloA := uint8(24)
		if state == "connected" {
			haloA = 54
		}
		if hov {
			haloA = 72
		}
		paint.FillShape(gtx.Ops, tint(ringCol, haloA), clip.Ellipse{Max: image.Pt(sz, sz)}.Op(gtx.Ops))

		midPad := gtx.Dp(6)
		mid := clip.Ellipse{Min: image.Pt(midPad, midPad), Max: image.Pt(sz-midPad, sz-midPad)}
		paint.FillShape(gtx.Ops, tint(ringCol, 85), clip.Stroke{Path: mid.Path(gtx.Ops), Width: float32(gtx.Dp(1.5))}.Op())

		pad := gtx.Dp(12)
		inner := clip.Ellipse{Min: image.Pt(pad, pad), Max: image.Pt(sz-pad, sz-pad)}
		bg, fg := ui.pal.card, ringCol
		if state == "connected" {
			bg = mix(ui.pal.card, ringCol, 0.22)
			fg = rgb(0xFFFFFF)
		} else if hov {
			bg = mix(ui.pal.card, ui.pal.acc, 0.20)
			fg = ui.pal.acc
			ringCol = ui.pal.acc
		}
		paint.FillShape(gtx.Ops, bg, inner.Op(gtx.Ops))
		paint.FillShape(gtx.Ops, ringCol, clip.Stroke{Path: inner.Path(gtx.Ops), Width: float32(gtx.Dp(3))}.Op())

		if state == "connected" && !hov {
			flagCC := strings.ToUpper(strings.TrimSpace(cc))
			if flagCC == "" || flagCC == "AUTO" {
				flagCC = "NL"
			}
			fw, fh := gtx.Dp(46), gtx.Dp(31)
			fx := (sz - fw) / 2
			fy := (sz - fh) / 2 - gtx.Dp(7)
			t := op.Offset(image.Pt(fx, fy)).Push(gtx.Ops)
			drawCountryFlag(gtx, flagCC, unit.Dp(46), unit.Dp(31))
			t.Pop()

			badgeRect := image.Rect(sz/2-gtx.Dp(20), fy+fh+gtx.Dp(4), sz/2+gtx.Dp(20), fy+fh+gtx.Dp(19))
			paint.FillShape(gtx.Ops, col, clip.UniformRRect(badgeRect, gtx.Dp(5)).Op(gtx.Ops))
			bt := op.Offset(image.Pt(badgeRect.Min.X, badgeRect.Min.Y-gtx.Dp(1))).Push(gtx.Ops)
			cgtx := gtx
			cgtx.Constraints = layout.Exact(image.Pt(badgeRect.Dx(), badgeRect.Dy()))
			layout.Center.Layout(cgtx, func(gtx layout.Context) layout.Dimensions {
				return ui.labelLine(gtx, fontMicro, rgb(0xFFFFFF), font.Bold, cnameShort(cc))
			})
			bt.Pop()
			return layout.Dimensions{Size: image.Pt(sz, sz)}
		}

		// Иконка питания + микроподпись действия при наведении на активное соединение
		is := gtx.Dp(30)
		offY := (sz - is) / 2
		if state == "connected" && hov {
			offY -= gtx.Dp(7)
		}
		t := op.Offset(image.Pt((sz-is)/2, offY)).Push(gtx.Ops)
		drawIcon(gtx, "power", unit.Dp(30), fg)
		t.Pop()

		if state == "connected" && hov {
			bt := op.Offset(image.Pt(0, offY+is+gtx.Dp(2))).Push(gtx.Ops)
			cgtx := gtx
			cgtx.Constraints = layout.Exact(image.Pt(sz, gtx.Dp(16)))
			layout.Center.Layout(cgtx, func(gtx layout.Context) layout.Dimensions {
				return ui.labelLine(gtx, fontMicro, rgb(0xFFFFFF), font.Bold, "ВЫКЛ")
			})
			bt.Pop()
		}
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
			h := gtx.Dp(42)
			w := gtx.Constraints.Max.X
			sz := image.Pt(w, h)
			fillRect(gtx, sz, gtx.Dp(8), ui.pal.card2)
			strokeRect(gtx, sz, gtx.Dp(8), float32(gtx.Dp(1)), ui.pal.border)

			// Тонкая горизонтальная направляющая сетка
			if w > 20 {
				midY := h / 2
				paint.FillShape(gtx.Ops, tint(ui.pal.border, 120), clip.Rect{Min: image.Pt(6, midY), Max: image.Pt(w-6, midY+1)}.Op())
			}

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

				// Полупрозрачная заливка под кривой скачивания
				var dlArea clip.Path
				dlArea.Begin(gtx.Ops)
				for i, pt := range hist {
					px := float32(i)/float32(len(hist)-1)*float32(w-10) + 5
					py := baseY - float32(pt[1]/maxVal)*float32(h-10)
					if py < 4 {
						py = 4
					}
					if i == 0 {
						dlArea.MoveTo(f32.Pt(px, baseY))
						dlArea.LineTo(f32.Pt(px, py))
					} else {
						dlArea.LineTo(f32.Pt(px, py))
					}
				}
				dlArea.LineTo(f32.Pt(float32(w-5), baseY))
				dlArea.Close()
				paint.FillShape(gtx.Ops, tint(ui.pal.ok, 34), clip.Outline{Path: dlArea.End()}.Op())

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

// drawLiveAppsStrip на Главной выводит активные процессы и радар ТСПУ-сбросов:
// клик по ТСПУ-дропу создаёт точечное правило для домена (host -> psiphon),
// а клик по обычному процессу переключает его маршрут.
func (ui *gioUI) drawLiveAppsStrip(gtx layout.Context, st map[string]any, apps []map[string]any) layout.Dimensions {
	type liveProc struct {
		exe   string
		host  string
		title string
		route string
		alert bool
	}
	var items []liveProc
	seen := map[string]bool{}

	// 1. Сканируем live-соединения на сбросы ТСПУ (отправлено >0 Б, ответа 0 Б на Direct/DPI)
	if stats, ok := st["stats"].(map[string]any); ok {
		if liveConns, ok := stats["live"].([]any); ok {
			for _, cVal := range liveConns {
				if len(items) >= 4 {
					break
				}
				if c, ok := cVal.(map[string]any); ok {
					ob, _ := c["outbound"].(string)
					appNm, _ := c["app"].(string)
					upB, _ := c["up"].(float64)
					dnB, _ := c["down"].(float64)
					host, _ := c["host"].(string)
					if sni, _ := c["sni"].(string); sni != "" {
						host = sni
					}
					key := strings.ToLower(orDefault(host, appNm))
					if key != "" && upB > 0 && dnB == 0 && (ob == obDirect || ob == obDesync) && !seen[key] {
						seen[key] = true
						items = append(items, liveProc{
							exe:   appNm,
							host:  host,
							title: fmt.Sprintf("⚠ %s", ui.maskSensitive(orDefault(host, appNm))),
							route: ob,
							alert: true,
						})
					}
				}
			}
		}
	}

	// 2. Дополняем активными процессами
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
			ui.liveAppHosts[i] = items[i].host
			ui.liveAppAlerts[i] = items[i].alert
		} else {
			ui.liveAppNames[i] = ""
			ui.liveAppRoutes[i] = ""
			ui.liveAppHosts[i] = ""
			ui.liveAppAlerts[i] = false
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
					return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, "Активные потоки и радар ТСПУ")
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, openStreamsBtn, "Все потоки ➔", false, "teal")
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			var chips []layout.Widget
			for i := range items {
				idx := i
				it := items[idx]
				lbl := fmt.Sprintf("%s · %s", it.title, routeShortRu(it.route))
				if it.alert {
					lbl = it.title + " → VPN"
				}

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
					return ui.pillButton(gtx, &ui.liveAppBtns[idx], lbl, it.route != "" && !it.alert, style)
				})
			}
			if len(chips) == 0 {
				return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, "Нет активных сокетов — откройте сайт или вкладку «Потоки»")
			}
			var cells []layout.FlexChild
			for idx, chip := range chips {
				if idx > 0 {
					cells = append(cells, layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout))
				}
				cells = append(cells, layout.Flexed(1, chip))
			}
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, cells...)
		}),
	)
}
