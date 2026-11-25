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
// FILE: gui_countries.go — Вкладка 3 «Страны» и Вкладка 5 «Устройства»
// ============================================================================

func (ui *gioUI) layoutCountriesTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()

	psi, _ := st["psiphon"].(map[string]any)
	pState, _ := psi["state"].(string)
	cfgReg, _ := psi["region"].(string)
	egressReg, _ := psi["egress_region"].(string)
	curReg := strings.ToUpper(orDefault(egressReg, cfgReg))
	if curReg == "" {
		curReg = "AUTO"
	}
	ping, _ := psi["health_ms"].(float64)
	singleProc, _ := st["single_process_countries"].(bool)

	blkSet := map[string]bool{}
	var blkList []string
	if arr, ok := st["blocked_countries"].([]any); ok {
		for _, it := range arr {
			if s, ok := it.(string); ok && s != "" {
				cc := strings.ToUpper(s)
				blkSet[cc] = true
				blkList = append(blkList, cc)
			}
		}
	}
	bgCountries := toMapSlice(st["countries"])
	q := strings.ToLower(strings.TrimSpace(ui.countrySearchEditor.Text()))

	resetAutoBtn := ui.appBtn("countries|auto")
	if resetAutoBtn.Clicked(gtx) {
		ui.doAsync("Страна выхода: Авто (лучшая)", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psi/region", map[string]any{"region": ""})
		})
	}

	sections := []layout.Widget{
		// 1. Текущая страна выхода (Hero-полоса)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			statusSub := "Применится при подключении"
			if pState == "connected" {
				statusSub = "Подключено"
				if ping > 0 {
					statusSub += fmt.Sprintf(" · %.0f мс", ping)
				}
			}
			curTitle := "Авто — самая быстрая"
			if curReg != "AUTO" {
				curTitle = countryLabel(curReg)
			}
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return drawCountryFlag(gtx, curReg, unit.Dp(44), unit.Dp(29))
					}),
					layout.Rigid(layout.Spacer{Width: space2}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Bold, "СЕЙЧАС ВЫБРАНО")
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.labelLine(gtx, fontTitle, ui.pal.text, font.Bold, curTitle)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, statusSub)
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if curReg == "AUTO" {
							return layout.Dimensions{}
						}
						return layout.Inset{Right: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, resetAutoBtn, "refresh", "Вернуть Авто", false, "")
						})
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						w := gtx.Dp(260)
						if w < gtx.Constraints.Max.X {
							gtx.Constraints.Max.X = w
						}
						return ui.switchTile(gtx, &ui.singleProcBtn, "chart", "Один процесс на страны", "экономия ~25 МБ ОЗУ", singleProc)
					}),
				)
			})
		},
	}

	// 2. Чёрный список стран (если не пуст)
	if len(blkList) > 0 {
		sections = append(sections, func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			var chips []layout.Widget
			for _, cc := range blkList {
				code := cc
				b := ui.appBtn("countries|unblk|" + code)
				if b.Clicked(gtx) {
					ui.doAsync("Убрано из чёрного списка: "+countryLabel(code), func() (map[string]any, error) {
						return ui.apiCall("POST", "/api/psi/blocked-countries", map[string]any{"country": code})
					})
				}
				chips = append(chips, func(gtx layout.Context) layout.Dimensions {
					return ui.flagButton(gtx, b, code, countryLabel(code)+" ✕", false, "danger")
				})
			}
			return ui.subCard(gtx, ui.pal.errSoft, tint(ui.pal.err, 130), space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontBody, ui.pal.err, font.Bold, fmt.Sprintf("⊘ Чёрный список (%d) — нажмите, чтобы вернуть в Авто-выбор:", len(blkList)))
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6), chips...)
					}),
				)
			})
		})
	}

	// 3. Все 28 стран с поиском, ★ избранным и ⊘ чёрным списком
	sections = append(sections, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		var cards []layout.Widget
		for i := 0; i < len(nativeCountries) && i < len(ui.countryBtns); i++ {
			idx := i
			cc := nativeCountries[idx]
			name := nativeCountryNames[idx]
			if q != "" && !strings.Contains(strings.ToLower(cc+" "+name), q) {
				continue
			}
			active := strings.EqualFold(cfgReg, cc) || (cfgReg == "" && cc == "")
			isFav := ui.isFavoriteCountry(cc)
			isBlk := blkSet[strings.ToUpper(cc)]

			cards = append(cards, func(gtx layout.Context) layout.Dimensions {
				bdr := ui.pal.border
				bg := ui.pal.card2
				if active {
					bg = mix(ui.pal.card2, ui.pal.acc, 0.18)
					bdr = ui.pal.acc
				} else if isBlk {
					bg = mix(ui.pal.card2, ui.pal.err, 0.10)
					bdr = tint(ui.pal.err, 120)
				}
				return ui.subCard(gtx, bg, bdr, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return ui.flagButton(gtx, &ui.countryBtns[idx], cc, name, active, "")
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if cc == "" {
								return layout.Dimensions{}
							}
							starTxt := "☆"
							starStyle := ""
							if isFav {
								starTxt = "★"
								starStyle = "warn"
							}
							return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.favStarBtns[idx], starTxt, isFav, starStyle)
							})
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if cc == "" {
								return layout.Dimensions{}
							}
							blkStyle := ""
							if isBlk {
								blkStyle = "danger"
							}
							return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.blockCountryBtns[idx], "⊘", isBlk, blkStyle)
							})
						}),
					)
				})
			})
		}

		return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.cardHeader(gtx, "globe", "Страны выхода Psiphon",
						"★ — в избранное (быстрый выбор на Главной) · ⊘ — в чёрный список (исключить из Авто)",
						func(gtx layout.Context) layout.Dimensions {
							w := gtx.Dp(240)
							if w > gtx.Constraints.Max.X {
								w = gtx.Constraints.Max.X
							}
							gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
							return ui.editorBox(gtx, "country-search", &ui.countrySearchEditor, "Найти страну…")
						})
				}),
				layout.Rigid(layout.Spacer{Height: space1}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.caption(gtx, "★ Избранные страны:")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.favoriteCountryChips(gtx, cfgReg)
				}),
				layout.Rigid(layout.Spacer{Height: space2}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if len(cards) == 0 {
						return ui.emptyState(gtx, "search", "Страна не найдена", "Измените поисковый запрос", "", nil)
					}
					return ui.grid(gtx, unit.Dp(265), 3, cards)
				}),
			)
		})
	})

	// 4. Фоновые процессы стран (если запущены)
	if len(bgCountries) > 0 {
		sections = append(sections, func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			var rows []layout.FlexChild
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.cardHeader(gtx, "apps", fmt.Sprintf("Фоновые процессы стран (%d)", len(bgCountries)),
					"Для маршрутов «VPN · страна» поднимаются отдельные процессы",
					func(gtx layout.Context) layout.Dimensions {
						return ui.iconButton(gtx, &ui.stopCountryBtn, "stop", "Остановить все", false, "danger")
					})
			}))
			for _, item := range bgCountries {
				cc, _ := item["country"].(string)
				if cc == "" {
					cc, _ = item["code"].(string)
				}
				if cc == "" {
					cc, _ = item["cc"].(string)
				}
				stStr, _ := item["state"].(string)
				if stStr == "" {
					stStr, _ = item["status"].(string)
				}
				stopBtn := ui.appBtn("countries|stop|" + cc)
				if stopBtn.Clicked(gtx) {
					code := cc
					ui.doAsync("Процесс страны остановлен: "+code, func() (map[string]any, error) {
						return ui.apiCall("POST", "/api/countries/stop?country="+url.QueryEscape(code), nil)
					})
				}
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return drawCountryFlag(gtx, cc, unit.Dp(20), unit.Dp(13))
								}),
								layout.Rigid(layout.Spacer{Width: space1}.Layout),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, countryLabel(cc)+" · "+stStr)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, stopBtn, "Остановить", false, "danger")
								}),
							)
						})
					})
				}))
			}
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		})
	}

	return material.List(ui.th, &ui.countriesPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

// ---------- Вкладка 5: Устройства (Прокси, PAC, Раздача в LAN, Браузеры) ----------

func (ui *gioUI) layoutDevicesTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	share := ui.shareInfo
	browsers := ui.browsersData
	ui.mu.Unlock()

	listen, _ := st["listen"].(string)
	host, port := proxyHostPort(listen)
	hp := host + ":" + port
	shareOn, _ := st["share_on"].(bool)
	sysProxy, _ := st["sysproxy"].(bool)

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.layoutAddressCard(gtx, host, port, hp, shareOn, share)
		},
		// Открыть браузер через PsiRoute (отдельный профиль с прокси)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				var btns []layout.Widget
				for _, b := range browsers {
					bID, _ := b["id"].(string)
					if bID == "" {
						bID, _ = b["name"].(string)
					}
					bTitle, _ := b["title"].(string)
					if bTitle == "" {
						bTitle = bID
					}
					btn := ui.appBtn("devices|browser|" + bID)
					if btn.Clicked(gtx) {
						idCopy := bID
						ui.doAsync("Запуск браузера "+bTitle+"…", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/browser/open", map[string]any{"browser": idCopy})
						})
					}
					btns = append(btns, func(gtx layout.Context) layout.Dimensions {
						return ui.iconButton(gtx, btn, "globe", bTitle, false, "primary")
					})
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "globe", "Открыть браузер через PsiRoute",
							"Запускает отдельный изолированный профиль браузера, уже настроенный на локальный прокси", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if len(btns) == 0 {
							return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, "Подходящие установленные браузеры не найдены.")
						}
						return flowWrap(gtx, space1, space1, btns...)
					}),
				)
			})
		},
		// Системный прокси Windows
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return ui.switchTile(gtx, &ui.sysProxyBtn, "globe", "Системный прокси Windows",
					"Автоматически направляет Chrome, Edge и системные приложения Windows в PsiRoute", sysProxy)
			})
		},
	}
	return material.List(ui.th, &ui.devicesPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

func (ui *gioUI) layoutAddressCard(gtx layout.Context, host, port, hp string, shareOn bool, share map[string]any) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	sIP, _ := share["ip"].(string)
	sPortF, _ := share["port"].(float64)
	sUser, _ := share["user"].(string)
	sPass, _ := share["password"].(string)
	sSocks, _ := share["socks"].(string)
	sHTTP, _ := share["http"].(string)
	sPort := port
	if sPortF > 0 {
		sPort = fmt.Sprintf("%.0f", sPortF)
	}
	return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
		var rows []layout.FlexChild
		add := func(w layout.Widget) {
			if len(rows) > 0 {
				rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout))
			}
			rows = append(rows, layout.Rigid(w))
		}
		add(func(gtx layout.Context) layout.Dimensions {
			return ui.cardHeader(gtx, "copy", "Локальный прокси и автонастройка PAC",
				"Всегда запущен — работает даже при включённом TUN. Нажмите на любую строку для копирования.",
				func(gtx layout.Context) layout.Dimensions {
					return ui.miniTag(gtx, ui.pal.ok, "всегда включён")
				})
		})
		add(func(gtx layout.Context) layout.Dimensions {
			return ui.copyRow(gtx, "hp", "Хост и порт", hp)
		})
		add(func(gtx layout.Context) layout.Dimensions {
			return ui.copyRow(gtx, "socks", "SOCKS5", "socks5://"+hp)
		})
		add(func(gtx layout.Context) layout.Dimensions {
			return ui.copyRow(gtx, "http", "HTTP / HTTPS", "http://"+hp)
		})
		add(func(gtx layout.Context) layout.Dimensions {
			return ui.copyRow(gtx, "pac", "Автонастройка (PAC)", ui.apiBase+"/proxy.pac")
		})
		add(func(gtx layout.Context) layout.Dimensions {
			return flowWrap(gtx, space1, space1,
				func(gtx layout.Context) layout.Dimensions { return ui.copyChip(gtx, "host", "IP", host) },
				func(gtx layout.Context) layout.Dimensions { return ui.copyChip(gtx, "port", "Порт", port) },
				func(gtx layout.Context) layout.Dimensions { return ui.copyChip(gtx, "web", "Веб-панель", ui.apiBase+"/") },
			)
		})
		rows = append(rows, layout.Rigid(ui.divider))
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, "Раздача в локальную сеть (телефон, Smart TV, второй ПК)")
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, "позволяет другим устройствам в домашней сети подключаться через этот компьютер")
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.switchButton(gtx, &ui.shareQuickBtn, shareOn)
				}),
			)
		}))
		if shareOn && sIP != "" {
			lanHP := sIP + ":" + sPort
			add(func(gtx layout.Context) layout.Dimensions { return ui.copyRow(gtx, "lan-hp", "Адрес в сети", lanHP) })
			if sSocks != "" {
				add(func(gtx layout.Context) layout.Dimensions { return ui.copyRow(gtx, "lan-socks", "SOCKS5 (LAN)", sSocks) })
			}
			if sHTTP != "" {
				add(func(gtx layout.Context) layout.Dimensions { return ui.copyRow(gtx, "lan-http", "HTTP (LAN)", sHTTP) })
			}
			if sUser != "" || sPass != "" {
				passDisplay := sPass
				if ui.privacyMode && passDisplay != "" {
					passDisplay = "••••••"
				}
				add(func(gtx layout.Context) layout.Dimensions {
					return flowWrap(gtx, space1, space1,
						func(gtx layout.Context) layout.Dimensions { return ui.copyChip(gtx, "lan-ip", "IP", sIP) },
						func(gtx layout.Context) layout.Dimensions { return ui.copyChip(gtx, "lan-user", "Логин", sUser) },
						func(gtx layout.Context) layout.Dimensions { return ui.copyChip(gtx, "lan-pass", "Пароль", passDisplay) },
					)
				})
			}
		} else if shareOn {
			add(func(gtx layout.Context) layout.Dimensions {
				return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, "Определяю адрес в локальной сети…")
			})
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	})
}
