//go:build windows

package main

import (
	"fmt"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/widget/material"
)

// ---------- Tab 3: Страны и обход DPI ----------

func (ui *gioUI) layoutCountriesDPITab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()
	psi, _ := st["psiphon"].(map[string]any)
	cfgReg, _ := psi["region"].(string)
	obfsMap, _ := st["obfs"].(map[string]any)
	dpiMode, _ := obfsMap["mode"].(string)
	singleProc, _ := st["single_process_countries"].(bool)
	probeRun, _ := st["probe_running"].(bool)

	masks := [5]struct{ id, title string }{
		{"auto", "Авто (перебор)"},
		{"quic", "QUIC-приманка"},
		{"masque", "HTTP/3-приманка"},
		{"bwg", "bash-warp-generator"},
		{"dns", "DNS-запрос (EDNS0)"},
	}

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "globe", "Страна выхода Psiphon", "Сейчас: "+countryLabel(cfgReg)+". Нажмите ★ рядом со страной, чтобы закрепить её в избранном и на Главной", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space2}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.caption(gtx, "★ Избранные страны (быстрый доступ на Главной и в Правилах):")
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.favoriteCountryChips(gtx, cfgReg)
					}),
					layout.Rigid(layout.Spacer{Height: space2}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.caption(gtx, "Все доступные страны (28):")
					}),
					layout.Rigid(layout.Spacer{Height: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.countryChips(gtx, cfgReg)
					}),
					layout.Rigid(layout.Spacer{Height: space2}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						w := gtx.Dp(420)
						if w < gtx.Constraints.Max.X {
							gtx.Constraints.Max.X = w
						}
						return ui.switchTile(gtx, &ui.singleProcBtn, "chart", "Страны в одном процессе", "экономит около 25 МБ памяти", singleProc)
					}),
				)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				probeTxt := "Подобрать лучший способ Psiphon"
				if probeRun {
					probeTxt = "Остановить подбор"
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "shield", "Обход DPI", "Метод для прямых подключений (маршрут «DPI»), сохраняется на диск", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space2}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.dpiChips(gtx, dpiMode)
					}),
					layout.Rigid(layout.Spacer{Height: space2}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, space1, space1,
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.dpiTestBtn, "play", "Проверить все методы", false, "primary")
							},
							func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.probeBtn, "search", probeTxt, probeRun, "")
							},
						)
					}),
				)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "bolt", "Маскировка WARP", "Как скрывать рукопожатие Cloudflare WARP от блокировок", nil)
					}),
					layout.Rigid(layout.Spacer{Height: space2}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						var ws []layout.Widget
						for i := range masks {
							idx := i
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.warpMaskBtns[idx], masks[idx].title, false, "")
							})
						}
						return flowWrap(gtx, space1, space1, ws...)
					}),
				)
			})
		},
	}
	return material.List(ui.th, &ui.dpiPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: space2, Right: space1}.Layout(gtx, sections[i])
	})
}

// ---------- Tab 4: Подключение устройств (Адреса для браузеров, PAC, Раздача в LAN) ----------

func (ui *gioUI) layoutDevicesTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	share := ui.shareInfo
	ui.mu.Unlock()

	listen, _ := st["listen"].(string)
	host, port := proxyHostPort(listen)
	hp := host + ":" + port
	shareOn, _ := st["share_on"].(bool)

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.layoutAddressCard(gtx, host, port, hp, shareOn, share)
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
			return ui.cardHeader(gtx, "copy", "Адреса для браузеров и программ", "Нажмите на любую строку — адрес скопируется в буфер обмена", nil)
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
				func(gtx layout.Context) layout.Dimensions {
					return ui.copyChip(gtx, "host", "IP", host)
				},
				func(gtx layout.Context) layout.Dimensions {
					return ui.copyChip(gtx, "port", "Порт", port)
				},
				func(gtx layout.Context) layout.Dimensions {
					return ui.copyChip(gtx, "web", "Веб-панель", ui.apiBase+"/")
				},
			)
		})
		add(func(gtx layout.Context) layout.Dimensions {
			return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal,
				"Firefox / Telegram / торрент: SOCKS5, узел "+host+", порт "+port+". Chrome и Edge используют системный прокси (переключатель на главной).")
		})
		rows = append(rows, layout.Rigid(ui.divider))
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, "Раздача в локальную сеть (телефон, ТВ, приставка, второй ПК)")
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
			add(func(gtx layout.Context) layout.Dimensions {
				return ui.copyRow(gtx, "lan-hp", "Адрес в сети", lanHP)
			})
			if sSocks != "" {
				add(func(gtx layout.Context) layout.Dimensions {
					return ui.copyRow(gtx, "lan-socks", "SOCKS5 (LAN)", sSocks)
				})
			}
			if sHTTP != "" {
				add(func(gtx layout.Context) layout.Dimensions {
					return ui.copyRow(gtx, "lan-http", "HTTP (LAN)", sHTTP)
				})
			}
			if sUser != "" || sPass != "" {
				add(func(gtx layout.Context) layout.Dimensions {
					return flowWrap(gtx, space1, space1,
						func(gtx layout.Context) layout.Dimensions {
							return ui.copyChip(gtx, "lan-ip", "IP", sIP)
						},
						func(gtx layout.Context) layout.Dimensions {
							return ui.copyChip(gtx, "lan-user", "Логин", sUser)
						},
						func(gtx layout.Context) layout.Dimensions {
							return ui.copyChip(gtx, "lan-pass", "Пароль", sPass)
						},
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
