//go:build windows

package main

import (
	"fmt"
	"net/url"
	"strings"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// ============================================================================
// FILE: gui_bypass.go — Вкладка 4 «Обход и ядро» (DPI, WARP/Clean-IP, Psiphon)
// ============================================================================

func (ui *gioUI) layoutBypassTab(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.layoutSubTabBar(gtx, 4, []string{"Обход DPI", "WARP и Clean-IP", "Psiphon и стратегии"})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			switch ui.subTabs[4] {
			case 1:
				return ui.layoutBypassWarpSub(gtx)
			case 2:
				return ui.layoutBypassPsiSub(gtx)
			default:
				return ui.layoutBypassDPISub(gtx)
			}
		}),
	)
}

func (ui *gioUI) layoutBypassDPISub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	dpiT := ui.dpiTestData
	probe := ui.probeData
	ui.mu.Unlock()

	obfsMap, _ := st["obfs"].(map[string]any)
	dpiMode, _ := obfsMap["mode"].(string)
	psiDPI, _ := obfsMap["psi_dpi"].(string)

	dpiRunning, _ := dpiT["running"].(bool)
	dpiDone, _ := dpiT["done"].(float64)
	dpiTotal, _ := dpiT["total"].(float64)
	dpiBest, _ := dpiT["best"].(string)
	dpiAutoTuned, _ := dpiT["auto_tuned"].(string)
	dpiMethods := toMapSlice(dpiT["methods"])

	probeRunning, _ := probe["running"].(bool)
	if !probeRunning {
		probeRunning, _ = st["probe_running"].(bool)
	}
	probeTotal, _ := probe["total"].(float64)
	probeBest, _ := probe["best"].(string)
	probeResults := toMapSlice(probe["results"])

	// Обработка кликов динамических кнопок подвкладки DPI
	btnObfsReset := ui.appBtn("bypass|obfs-reset")
	if btnObfsReset.Clicked(gtx) {
		ui.doAsync("Выученные методы DPI сброшены", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/obfs/reset", nil)
		})
	}
	btnDPIStop := ui.appBtn("bypass|dpi-stop")
	if btnDPIStop.Clicked(gtx) {
		ui.doAsync("Тест DPI остановлен", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/dpi/test/stop", nil)
		})
	}
	btnDPIApplyBest := ui.appBtn("bypass|dpi-apply-best")
	if btnDPIApplyBest.Clicked(gtx) && dpiBest != "" {
		best := dpiBest
		ui.doAsync("Применён лучший метод DPI: "+best, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/dpi/mode", map[string]any{"mode": best})
		})
	}
	btnProbeApplyBest := ui.appBtn("bypass|probe-apply-best")
	if btnProbeApplyBest.Clicked(gtx) && probeBest != "" {
		best := probeBest
		ui.doAsync("Применён лучший способ Psiphon: "+best, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psi/probe/apply?id="+url.QueryEscape(best), nil)
		})
	}

	sections := []layout.Widget{
		// 1. Метод обхода DPI
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				info := "Сейчас: " + orDefault(dpiMode, "auto")
				if dpiAutoTuned != "" {
					info += " · выучено: " + dpiAutoTuned
				}
				if psiDPI != "" {
					info += " · Psiphon DPI: " + psiDPI
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "shield", "Метод обхода DPI",
							"Как разрезать TLS-рукопожатие, чтобы провайдер не опознал сайт. «Авто» сам подбирает и запоминает лучший способ.", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space2}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.dpiChips(gtx, dpiMode)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.subCard(gtx, ui.pal.card2, ui.pal.border, space1, func(gtx layout.Context) layout.Dimensions {
							return ui.monoLabel(gtx, fontSmall, ui.pal.teal, info)
						})
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, space1, space1,
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.repairConnBtn, "bolt", "Починить обход", false, "teal")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, btnObfsReset, "refresh", "Забыть выученное DPI", false, "")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.clearLearnBtn, "swap", "Забыть выученные маршруты", false, "")
							},
						)
					}),
				)
			})
		},
		// 2. Тест методов DPI с прогресс-баром и результатами
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				var rows []layout.FlexChild
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.cardHeader(gtx, "play", "Тест методов DPI",
						"Проверяет, какой метод лучше открывает заблокированные сайты у вашего провайдера",
						func(gtx layout.Context) layout.Dimensions {
							if dpiRunning {
								return ui.iconButton(gtx, btnDPIStop, "stop", "Остановить тест", false, "danger")
							}
							return ui.iconButton(gtx, &ui.dpiTestBtn, "play", "Запустить тест", false, "primary")
						})
				}))
				if dpiRunning {
					frac := float32(0)
					if dpiTotal > 0 {
						frac = float32(dpiDone / dpiTotal)
					}
					rows = append(rows,
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.progressBar(gtx, frac, ui.pal.teal)
						}),
						layout.Rigid(layout.Spacer{Height: space0}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, fmt.Sprintf("Проверено %.0f из %.0f…", dpiDone, dpiTotal))
						}),
					)
				}
				if len(dpiMethods) > 0 {
					rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout))
					for _, m := range dpiMethods {
						mID, _ := m["id"].(string)
						mTitle, _ := m["title"].(string)
						if mTitle == "" {
							mTitle = mID
						}
						okC, _ := m["ok"].(float64)
						failC, _ := m["fail"].(float64)
						msVal, _ := m["ms"].(float64)
						tot := okC + failC
						frac := float32(0)
						if tot > 0 {
							frac = float32(okC / tot)
						}
						isBest := dpiBest != "" && dpiBest == mID
						pickBtn := ui.appBtn("bypass|dpi-pick|" + mID)
						if pickBtn.Clicked(gtx) {
							idCopy := mID
							ui.doAsync("Метод DPI: "+mTitle, func() (map[string]any, error) {
								return ui.apiCall("POST", "/api/dpi/mode", map[string]any{"mode": idCopy})
							})
						}
						rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Bottom: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								bdr := ui.pal.border
								if isBest {
									bdr = tint(ui.pal.ok, 140)
								}
								return ui.subCard(gtx, ui.pal.card2, bdr, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
											return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													lbl := mTitle
													if isBest {
														lbl += "  ★ ЛУЧШИЙ"
													}
													col := ui.pal.text
													if isBest {
														col = ui.pal.ok
													}
													return ui.labelLine(gtx, fontBody, col, font.SemiBold, lbl)
												}),
												layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return ui.progressBar(gtx, frac, ui.pal.ok)
												}),
											)
										}),
										layout.Rigid(layout.Spacer{Width: space2}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											statTxt := fmt.Sprintf("%.0f/%.0f", okC, tot)
											if msVal > 0 {
												statTxt += fmt.Sprintf(" · %.0f мс", msVal)
											}
											return ui.monoLabel(gtx, fontSmall, ui.pal.mut, statTxt)
										}),
										layout.Rigid(layout.Spacer{Width: space1}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, pickBtn, "Выбрать", dpiMode == mID, "teal")
										}),
									)
								})
							})
						}))
					}
					if dpiBest != "" {
						rows = append(rows, layout.Rigid(layout.Spacer{Height: space0}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, btnDPIApplyBest, "check", "Применить лучший ("+dpiBest+")", false, "ok")
							}))
					}
				} else if !dpiRunning {
					rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, "Тест ещё не запускался. Нажмите «Запустить тест», чтобы проверить все методы на вашей сети.")
						}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
		// 3. Автоподбор обхода Psiphon (Probe)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				var rows []layout.FlexChild
				probeBtnTxt := "Запустить подбор"
				probeStyle := "primary"
				if probeRunning {
					probeBtnTxt = "Остановить подбор"
					probeStyle = "danger"
				}
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.cardHeader(gtx, "search", "Автоподбор обхода Psiphon",
						"Перебирает протоколы и транспортные связки (до 8 минут) и находит оптимальную для вашего провайдера",
						func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, &ui.probeBtn, "play", probeBtnTxt, probeRunning, probeStyle)
						})
				}))
				if probeRunning {
					okCnt := 0
					for _, r := range probeResults {
						if ok, _ := r["ok"].(bool); ok {
							okCnt++
						}
					}
					rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.subCard(gtx, ui.pal.tealSoft, tint(ui.pal.teal, 120), space1, func(gtx layout.Context) layout.Dimensions {
								return ui.label(gtx, fontSmall, ui.pal.teal, font.SemiBold,
									fmt.Sprintf("Идёт подбор… найдено рабочих: %d (проверено %d из %.0f)", okCnt, len(probeResults), probeTotal))
							})
						}))
				}
				for _, r := range probeResults {
					rID, _ := r["id"].(string)
					rName, _ := r["name"].(string)
					if rName == "" {
						rName = rID
					}
					rOK, _ := r["ok"].(bool)
					rProtos, _ := r["protos"].(string)
					if rProtos == "" {
						rProtos, _ = r["proto"].(string)
					}
					rMs, _ := r["connect_ms"].(float64)
					rKbps, _ := r["kbps"].(float64)
					isBest := probeBest != "" && probeBest == rID
					applyBtn := ui.appBtn("bypass|probe-apply|" + rID)
					if applyBtn.Clicked(gtx) {
						idCopy := rID
						ui.doAsync("Применён вариант: "+rName, func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/psi/probe/apply?id="+url.QueryEscape(idCopy), nil)
						})
					}
					rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
								dotCol := ui.pal.err
								if rOK {
									dotCol = ui.pal.ok
								}
								detail := rProtos
								if rOK {
									detail += fmt.Sprintf(" · %.0f мс · %.0f КБ/с", rMs, rKbps)
								}
								title := rName
								if isBest {
									title += "  ★ ЛУЧШИЙ"
								}
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions { return dotWidget(gtx, unit.Dp(8), dotCol) }),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, title)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.monoLabel(gtx, fontMicro, ui.pal.mut, detail)
											}),
										)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if !rOK {
											return layout.Dimensions{}
										}
										return ui.pillButton(gtx, applyBtn, "Применить", isBest, "ok")
									}),
								)
							})
						})
					}))
				}
				if probeBest != "" {
					rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, btnProbeApplyBest, "check", "Применить лучший ("+probeBest+")", false, "ok")
						}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
	}

	return material.List(ui.th, &ui.bypassPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutBypassWarpSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	sVals := ui.settingsValues()
	ui.mu.Unlock()

	warpOn, _ := st["warp_on"].(bool)
	warpMap, _ := st["warp"].(map[string]any)
	warpText, _ := warpMap["text"].(string)
	warpMask, _ := sVals["warp.mask"].(string)
	if warpMask == "" {
		warpMask, _ = st["warp_mask"].(string)
	}
	if warpMask == "" {
		warpMask = "quic"
	}
	warpEngine, _ := sVals["warp.engine"].(string)
	if warpEngine == "" {
		warpEngine = "builtin"
	}

	ccMap, _ := st["clean_chain"].(map[string]any)
	ccEnabled, _ := ccMap["enabled"].(bool)
	ccAuto, _ := ccMap["auto_chain"].(bool)
	ccHops, _ := ccMap["hops"].(string)
	if ccHops == "" {
		ccHops = "WARP → PSI → WARP"
	}
	ccText, _ := ccMap["text"].(string)
	ccExitIP, _ := ccMap["exit_ip"].(string)
	ccExitLoc, _ := ccMap["exit_loc"].(string)
	ccExitColo, _ := ccMap["exit_colo"].(string)
	ccErr, _ := ccMap["error"].(string)
	lastVer, _ := ccMap["last_verify"].(map[string]any)

	ksMode, _ := st["kill_switch_mode"].(string)
	if ksMode == "" {
		ksMode = "off"
	}
	wfpMap, _ := st["wfp"].(map[string]any)
	wfpText, _ := wfpMap["text"].(string)
	if wfpText == "" {
		wfpText, _ = wfpMap["state"].(string)
	}

	// Кнопки движка WARP и сохранения endpoint/socks
	engBuiltin := ui.appBtn("warp|eng-builtin")
	engSocks := ui.appBtn("warp|eng-socks")
	saveEP := ui.appBtn("warp|save-ep")
	saveSocks := ui.appBtn("warp|save-socks")

	if engBuiltin.Clicked(gtx) {
		ui.doAsync("Движок WARP: встроенный WireGuard", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"warp.engine": "builtin"})
		})
	}
	if engSocks.Clicked(gtx) {
		ui.doAsync("Движок WARP: внешний SOCKS5", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"warp.engine": "socks"})
		})
	}
	if saveEP.Clicked(gtx) {
		val := strings.TrimSpace(ui.warpEndpointEditor.Text())
		ui.doAsync("Endpoint WARP сохранён", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"warp.endpoint": val})
		})
	}
	if saveSocks.Clicked(gtx) {
		val := strings.TrimSpace(ui.warpSocksEditor.Text())
		ui.doAsync("Адрес SOCKS5 WARP сохранён", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"warp.socks": val})
		})
	}

	masks := [5]struct{ id, title string }{
		{"quic", "QUIC+ECH"},
		{"masque", "MASQUE"},
		{"bwg", "BWG"},
		{"dns", "DNS"},
		{"off", "Выкл"},
	}

	renderHopCard := func(gtx layout.Context, h map[string]any) layout.Dimensions {
		if h == nil {
			return layout.Dimensions{}
		}
		name, _ := h["name"].(string)
		ok, _ := h["ok"].(bool)
		bypassed, _ := h["bypassed"].(bool)
		msVal, _ := h["ms"].(float64)
		ip, _ := h["ip"].(string)
		loc, _ := h["loc"].(string)
		colo, _ := h["colo"].(string)
		warpSt, _ := h["warp"].(string)
		note, _ := h["note"].(string)
		errS, _ := h["error"].(string)

		col := ui.pal.err
		badge := "ошибка"
		if ok {
			col = ui.pal.ok
			badge = fmt.Sprintf("%.0f мс", msVal)
		} else if bypassed {
			col = ui.pal.warn
			badge = "обход"
		}
		return ui.subCard(gtx, ui.pal.card2, tint(col, 130), unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, name)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.miniTag(gtx, col, badge)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if ok {
						return ui.monoLabel(gtx, fontMicro, ui.pal.mut,
							fmt.Sprintf("IP: %s · %s/%s · warp=%s", ui.maskSensitive(ip), orDefault(loc, "?"), orDefault(colo, "?"), orDefault(warpSt, "off")))
					}
					return ui.label(gtx, fontMicro, ui.pal.mut, font.Normal, orDefault(note, orDefault(errS, "Недоступно")))
				}),
			)
		})
	}

	sections := []layout.Widget{
		// 1. Cloudflare WARP + Каскад Clean-IP в две колонки
		func(gtx layout.Context) layout.Dimensions {
			return ui.twoCol(gtx, 0.5, 0.5,
				// Левая: Cloudflare WARP
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var maskChips []layout.Widget
						for i := range masks {
							idx := i
							m := masks[idx]
							maskChips = append(maskChips, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.warpMaskBtns[idx], m.title, warpMask == m.id, "warn")
							})
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "bolt", "Cloudflare WARP", "Встроенная подложка WireGuard с маскировкой рукопожатия", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, &ui.warpBtn, "bolt", "Подложка WARP", orDefault(warpText, onOffRu(warpOn)), warpOn)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.caption(gtx, "Маскировка рукопожатия:")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, unit.Dp(6), unit.Dp(6), maskChips...)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.caption(gtx, "Движок WARP:")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, engBuiltin, "Встроенный", warpEngine != "socks", "primary")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, engSocks, "Внешний SOCKS5", warpEngine == "socks", "primary")
									},
								)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if warpEngine == "socks" {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
											return ui.editorBox(gtx, "warp-socks", &ui.warpSocksEditor, "Внешний SOCKS5 (127.0.0.1:40000)")
										}),
										layout.Rigid(layout.Spacer{Width: space1}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.pillButton(gtx, saveSocks, "OK", false, "primary")
										}),
									)
								}
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return ui.editorBox(gtx, "warp-ep", &ui.warpEndpointEditor, "Свой endpoint (162.159.192.1:2408)")
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.pillButton(gtx, saveEP, "OK", false, "primary")
									}),
								)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.warpReconnBtn, "refresh", "Переподключить WARP", false, "")
							}),
						)
					})
				},
				// Правая: Каскад Clean-IP
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var rows []layout.FlexChild
						rows = append(rows,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "shield", "Каскад «Чистый IP»",
									fmt.Sprintf("%s · MTU 1280 → 1200 · MSS ≤ 1140", ccHops), nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, &ui.cleanChainToggleBtn, "shield", "Clean-IP (WARP → VPN → WARP)",
									orDefault(ccText, "Выходной IP заменяется на чистый адрес Cloudflare"), ccEnabled)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, &ui.cleanAutoChainBtn, "bolt", "Auto-Chain",
									"Автоматически строить цепочку при необходимости", ccAuto)
							}),
						)
						if ccExitIP != "" {
							rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.subCard(gtx, ui.pal.cleanSoft, tint(ui.pal.clean, 120), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
										return ui.monoLabel(gtx, fontSmall, ui.pal.clean,
											fmt.Sprintf("Выход Clean-IP: %s · %s %s", ui.maskSensitive(ccExitIP), ccExitLoc, ccExitColo))
									})
								}))
						}
						if ccErr != "" {
							rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.subCard(gtx, ui.pal.warnSoft, tint(ui.pal.warn, 130), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
										return ui.label(gtx, fontSmall, ui.pal.warn, font.Normal, "⚠ "+ccErr)
									})
								}))
						}
						rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.verifyCleanBtn, "check", "Проверить связку WARP → VPN → WARP", false, "teal")
							}))
						if lastVer != nil {
							verOK, _ := lastVer["verified"].(bool)
							ipChanged, _ := lastVer["ip_changed"].(bool)
							h1, _ := lastVer["hop1"].(map[string]any)
							h2, _ := lastVer["hop2"].(map[string]any)
							h3, _ := lastVer["hop3"].(map[string]any)
							vCol := ui.pal.warn
							vTxt := "⚠ Связка подтверждена не полностью"
							if verOK {
								vCol = ui.pal.ok
								vTxt = "✓ Связка WARP → VPN → WARP подтверждена"
								if ipChanged {
									vTxt += " · IP заменён"
								}
							}
							rows = append(rows,
								layout.Rigid(layout.Spacer{Height: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.miniTag(gtx, vCol, vTxt)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions { return renderHopCard(gtx, h1) }),
								layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions { return renderHopCard(gtx, h2) }),
								layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions { return renderHopCard(gtx, h3) }),
							)
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				},
			)
		},
		// 2. Kill Switch (WFP)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			ksDesc := "Трафик не блокируется."
			if ksMode == "auto" {
				ksDesc = "Включается вместе с VPN и снимается при остановке."
			} else if ksMode == "strict" {
				ksDesc = "Интернет только через туннель — максимальная защита (нужны права Администратора)."
			}
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				var rows []layout.FlexChild
				rows = append(rows,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "lock", "Kill Switch (Windows Filtering Platform)",
							"Блокирует весь трафик мимо VPN, если туннель оборвался", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, space1, space1,
							func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.ksModeBtns[0], "Выключен", ksMode == "off", "")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.ksModeBtns[1], "Авто", ksMode == "auto", "warn")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.ksModeBtns[2], "Строгий", ksMode == "strict", "danger")
							},
						)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, ksDesc)
					}),
				)
				if wfpText != "" {
					rows = append(rows, layout.Rigid(layout.Spacer{Height: space0}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
								return ui.monoLabel(gtx, fontSmall, ui.pal.mut, wfpText)
							})
						}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
	}

	return material.List(ui.th, &ui.bypassPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutBypassPsiSub(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	sVals := ui.settingsValues()
	pInfo := ui.psiInfoData
	speedRes := ui.speedTestRes
	ui.mu.Unlock()

	psi, _ := st["psiphon"].(map[string]any)
	preset, _ := sVals["psiphon.preset"].(string)
	if preset == "" {
		preset = "balanced"
	}
	psiDPI, _ := sVals["psiphon.dpi"].(string)
	standby, _ := sVals["psiphon.standby"].(bool)
	parallel, _ := sVals["psiphon.parallel"].(float64)
	if parallel <= 0 {
		parallel = 2
	}
	healthSec, _ := sVals["psiphon.health_interval_secs"].(float64)
	if healthSec <= 0 {
		healthSec = 30
	}

	imported, _ := psi["imported_entries"].(float64)
	server, _ := psi["server"].(string)
	proto, _ := psi["protocol"].(string)
	netKey, _ := psi["net_key"].(string)
	if netKey == "" {
		netKey, _ = psi["network_id"].(string)
	}
	strategies := toMapSlice(pInfo["strategies"])

	// Обработчики кнопок Psiphon
	standbyBtn := ui.appBtn("psi|standby")
	if standbyBtn.Clicked(gtx) {
		next := !standby
		ui.doAsync("Резервный туннель: "+onOffRu(next), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"psiphon.standby": next})
		})
	}
	resetOrderBtn := ui.appBtn("psi|reset-order")
	if resetOrderBtn.Clicked(gtx) {
		ui.doAsync("Порядок стратегий Psiphon сброшен", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psi/reset-order", nil)
		})
	}
	psiDiagBtn := ui.appBtn("psi|preflight")
	if psiDiagBtn.Clicked(gtx) {
		ui.doAsync("Предварительная диагностика Psiphon…", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psiphon/action", map[string]any{"action": "run_diagnostics"})
		})
	}

	presets := []struct{ id, title string }{
		{"fast", "Быстрый"},
		{"balanced", "Сбалансированный"},
		{"patient", "Терпеливый"},
	}
	psiDPIOpts := []struct{ id, title string }{
		{"", "Стандартный"},
		{"off", "Без обхода"},
		{"hello", "Hello-разрез"},
		{"light", "Лёгкое"},
		{"strong", "Сильное"},
		{"auto", "Авто"},
	}

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.twoCol(gtx, 0.5, 0.5,
				// Левая: Профиль подключения
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var presetChips []layout.Widget
						for _, pr := range presets {
							pr := pr
							btn := ui.appBtn("psi|preset|" + pr.id)
							if btn.Clicked(gtx) {
								ui.doAsync("Профиль Psiphon: "+pr.title, func() (map[string]any, error) {
									return ui.apiCall("POST", "/api/settings", map[string]any{"psiphon.preset": pr.id})
								})
							}
							presetChips = append(presetChips, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, btn, pr.title, preset == pr.id, "primary")
							})
						}
						var dpiChips []layout.Widget
						for _, opt := range psiDPIOpts {
							opt := opt
							btn := ui.appBtn("psi|dpi|" + orDefault(opt.id, "default"))
							if btn.Clicked(gtx) {
								ui.doAsync("DPI внутри Psiphon: "+opt.title, func() (map[string]any, error) {
									return ui.apiCall("POST", "/api/settings", map[string]any{"psiphon.dpi": opt.id})
								})
							}
							dpiChips = append(dpiChips, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, btn, opt.title, psiDPI == opt.id, "teal")
							})
						}
						var parChips []layout.Widget
						for _, n := range []int{1, 2, 3, 4} {
							n := n
							btn := ui.appBtn(fmt.Sprintf("psi|par|%d", n))
							if btn.Clicked(gtx) {
								ui.doAsync(fmt.Sprintf("Параллельных попыток: %d", n), func() (map[string]any, error) {
									return ui.apiCall("POST", "/api/settings", map[string]any{"psiphon.parallel": n})
								})
							}
							parChips = append(parChips, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, btn, fmt.Sprintf("%d", n), int(parallel) == n, "primary")
							})
						}
						var hlChips []layout.Widget
						for _, sec := range []int{15, 30, 60, 120} {
							sec := sec
							btn := ui.appBtn(fmt.Sprintf("psi|hl|%d", sec))
							if btn.Clicked(gtx) {
								ui.doAsync(fmt.Sprintf("Интервал проверки: %d сек", sec), func() (map[string]any, error) {
									return ui.apiCall("POST", "/api/settings", map[string]any{"psiphon.health_interval_secs": sec})
								})
							}
							hlChips = append(hlChips, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, btn, fmt.Sprintf("%dс", sec), int(healthSec) == sec, "primary")
							})
						}

						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "gear", "Профиль подключения", "Баланс между скоростью подбора сервера и надёжностью", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return flowWrap(gtx, unit.Dp(6), unit.Dp(6), presetChips...) }),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.caption(gtx, "DPI внутри Psiphon:") }),
							layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return flowWrap(gtx, unit.Dp(6), unit.Dp(6), dpiChips...) }),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.switchTile(gtx, standbyBtn, "shield", "Резервный туннель (Standby)", "Запасное соединение для мгновенного переключения", standby)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Medium, "Попыток:")
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions { return flowWrap(gtx, unit.Dp(4), unit.Dp(4), parChips...) }),
									layout.Rigid(layout.Spacer{Width: space2}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Medium, "Проверка:")
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return flowWrap(gtx, unit.Dp(4), unit.Dp(4), hlChips...) }),
								)
							}),
						)
					})
				},
				// Правая: Скорость и серверы
				func(gtx layout.Context) layout.Dimensions {
					return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
						var rows []layout.FlexChild
						rows = append(rows,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.cardHeader(gtx, "chart", "Скорость и серверы", "Проверка текущего туннеля и импорт server entries", nil)
							}),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return flowWrap(gtx, unit.Dp(6), unit.Dp(6),
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.speedTestBtn, "play", "Тест скорости", false, "teal")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, psiDiagBtn, "search", "Диагностика", false, "")
									},
									func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.nextStratBtn, "swap", "Следующий способ", false, "")
									},
								)
							}),
						)
						if speedRes != nil {
							kbps, _ := speedRes["kbps"].(float64)
							msVal, _ := speedRes["ms"].(float64)
							errS, _ := speedRes["error"].(string)
							txt := fmt.Sprintf("Скорость: %.0f КБ/с · Задержка: %.0f мс", kbps, msVal)
							col := ui.pal.ok
							if errS != "" {
								txt = "Ошибка теста: " + errS
								col = ui.pal.err
							}
							rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.subCard(gtx, ui.pal.card2, tint(col, 120), unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
										return ui.monoLabel(gtx, fontSmall, col, txt)
									})
								}))
						}
						rows = append(rows,
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Импортировано записей", fmt.Sprintf("%.0f", imported)) }),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Текущий сервер", ui.maskSensitive(orDefault(server, "—"))) }),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Протокол", orDefault(proto, "—")) }),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.kvRow(gtx, "Идентификатор сети", orDefault(netKey, "—")) }),
							layout.Rigid(layout.Spacer{Height: space1}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return ui.editorBox(gtx, "server-entries-psi", &ui.serverEntriesEditor, "Импорт server entries (hex/base64)…")
									}),
									layout.Rigid(layout.Spacer{Width: space1}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.importEntriesBtn, "plus", "Импорт", false, "primary")
									}),
								)
							}),
						)
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
					})
				},
			)
		},
		// 2. Способы подключения (стратегии Psiphon)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				var tiles []layout.Widget
				for _, s := range strategies {
					sID, _ := s["id"].(string)
					sTitle, _ := s["title"].(string)
					if sTitle == "" {
						sTitle = sID
					}
					sEn, _ := s["enabled"].(bool)
					sProtos := strings.Join(toStringSlice(s["protocols"]), ", ")
					if ups, _ := s["upstream"].(string); ups != "" {
						if sProtos != "" {
							sProtos += " · "
						}
						sProtos += ups
					}
					btn := ui.appBtn("psi|strat|" + sID)
					if btn.Clicked(gtx) {
						var nextIDs []string
						for _, stItem := range strategies {
							id, _ := stItem["id"].(string)
							en, _ := stItem["enabled"].(bool)
							if id == sID {
								en = !en
							}
							if en {
								nextIDs = append(nextIDs, id)
							}
						}
						ui.doAsync("Способы подключения обновлены", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/psi/strategies", map[string]any{"strategies": nextIDs})
						})
					}
					tiles = append(tiles, func(gtx layout.Context) layout.Dimensions {
						return ui.switchTile(gtx, btn, "route", sTitle, orDefault(sProtos, sID), sEn)
					})
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "route", "Способы подключения Psiphon",
							"Программа пробует включённые способы по очереди, начиная с самых успешных в вашей сети",
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, resetOrderBtn, "refresh", "Сбросить порядок", false, "")
							})
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if len(tiles) == 0 {
							return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, "Загрузка списка способов подключения…")
						}
						return ui.grid(gtx, unit.Dp(260), 2, tiles)
					}),
				)
			})
		},
	}

	return material.List(ui.th, &ui.bypassPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}
