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

// ---------- Tab 2: Routing Rules & Ready Profiles ----------

type ruleObOption struct {
	id, title, flag string
}

var ruleObChoices = [10]ruleObOption{
	{obPsiphon, "Psiphon VPN", ""},
	{obDirect, "Напрямую", ""},
	{obDesync, "DPI-обход", ""},
	{obWarp, "WARP", ""},
	{obBlock, "Блок", ""},
	{obAuto, "Авто", ""},
	{"psiphon:DE", "Psiphon DE", "DE"},
	{"psiphon:NL", "Psiphon NL", "NL"},
	{"psiphon:US", "Psiphon US", "US"},
	{"psiphon:FI", "Psiphon FI", "FI"},
}

// dynamicRuleObChoices формирует список маршрутов конструктора правил, подставляя
// в кнопки psiphon:<CC> избранные страны пользователя (Раздел 4.1 ТЗ).
func (ui *gioUI) dynamicRuleObChoices() [10]ruleObOption {
	out := ruleObChoices
	favs := ui.favoriteCountriesList()
	defaults := []string{"DE", "NL", "US", "FI"}
	seen := map[string]bool{}
	var codes []string
	for _, cc := range append(favs, defaults...) {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if len(cc) == 2 && !seen[cc] {
			seen[cc] = true
			codes = append(codes, cc)
		}
		if len(codes) >= 4 {
			break
		}
	}
	for i := 0; i < 4 && i < len(codes); i++ {
		cc := codes[i]
		out[6+i] = ruleObOption{id: "psiphon:" + cc, title: "Psiphon " + cc, flag: cc}
	}
	return out
}

var rulePresetChoices = [8]struct{ id, title string }{
	{"youtube", "+ YouTube + Google Video"},
	{"discord", "+ Discord (Голос + Чат)"},
	{"ai", "+ AI (ChatGPT / Claude)"},
	{"telegram", "+ Telegram"},
	{"steam", "+ Steam / Игры"},
	{"blocked", "+ Заблокированные (РФ)"},
	{"ru-direct", "+ РФ (.ru) напрямую"},
	{"ads-block", "+ Блок рекламы/телеметрии"},
}

var ruleQuickListIDs = [12]struct{ id, title string }{
	{"youtube", "list:youtube"},
	{"discord", "list:discord"},
	{"ai", "list:ai"},
	{"telegram", "list:telegram"},
	{"meta", "list:meta"},
	{"google", "list:google"},
	{"steam", "list:steam"},
	{"twitch", "list:twitch"},
	{"spotify", "list:spotify"},
	{"github", "list:github"},
	{"blocked", "list:blocked"},
	{"!ru", "list:!ru (кроме РФ)"},
}

func ruleEditableTokens(r map[string]any) string {
	var parts []string
	addStrs := func(key, prefix string) {
		if arr, ok := r[key].([]any); ok {
			for _, it := range arr {
				if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
					if prefix != "" && !strings.HasPrefix(s, prefix) {
						parts = append(parts, prefix+s)
					} else {
						parts = append(parts, s)
					}
				}
			}
		}
	}
	addStrs("lists", "list:")
	addStrs("domains", "")
	addStrs("ips", "")
	addStrs("apps", "")
	if p, ok := r["ports"].(string); ok && strings.TrimSpace(p) != "" {
		parts = append(parts, "port:"+strings.TrimSpace(p))
	}
	return strings.Join(parts, ", ")
}

func (ui *gioUI) listUseBtn(id string) *widget.Clickable {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	b := ui.listUseBtns[id]
	if b == nil {
		b = new(widget.Clickable)
		ui.listUseBtns[id] = b
	}
	return b
}

func (ui *gioUI) layoutRulesTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	rlData := ui.rulesData
	ui.mu.Unlock()
	var rules []map[string]any
	if rlData != nil {
		rules = toMapSlice(rlData["rules"])
	}

	protoChoices := [3]struct{ id, title string }{
		{"", "TCP + UDP"},
		{"tcp", "Только TCP"},
		{"udp", "Только UDP"},
	}

	sections := []layout.Widget{
		// 0. Чёткий конвейер приоритетов (Top-to-Bottom Pipeline 1–7)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, unit.Dp(14), func(gtx layout.Context) layout.Dimensions {
				var stageWidgets []layout.Widget
				for _, stg := range routingPipelineStages {
					s := stg
					stageWidgets = append(stageWidgets, func(gtx layout.Context) layout.Dimensions {
						return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontSmall, ui.pal.acc, font.Bold, fmt.Sprintf("%d. %s", s.Stage, s.Title))
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontMicro, ui.pal.text, font.Medium, s.Example)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.Normal, s.Summary)
								}),
							)
						})
					})
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "shield", "Конвейер приоритетов маршрутизации (Top-to-Bottom Pipeline 1–7)",
							"Пакеты проверяются строго сверху вниз до первого совпадения. Кнопка «Проверить» ниже покажет точный уровень и причину маршрута.", nil)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6), stageWidgets...)
					}),
				)
			})
		},
		// 1. Visual Rule Constructor & 1-Click Templates
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, unit.Dp(18), func(gtx layout.Context) layout.Dimensions {
				hdrTitle := "Умный конструктор правил маршрутизации"
				hdrSub := "Введите через запятую домены (youtube.com, *.googlevideo.com), списки (list:youtube, !ru), IP/CIDR (1.1.1.1/32), порты (port:443) или программы (Discord.exe)"
				if ui.editingRuleIdx >= 0 {
					hdrTitle = fmt.Sprintf("Редактирование правила #%d", ui.editingRuleIdx+1)
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "route", hdrTitle, hdrSub, nil)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
					// Row 1: Rule Name (optional) + Target Input + Action Buttons
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								w := gtx.Dp(230)
								if w > gtx.Constraints.Max.X/3 {
									w = gtx.Constraints.Max.X / 3
								}
								gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
								return ui.editorBox(gtx, "rule-name", &ui.ruleNameEditor, "Имя правила (необяз.)")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return ui.editorBox(gtx, "rule-host", &ui.hostEditor, "youtube.com, list:discord, !ru, 1.1.1.1, Discord.exe, port:443")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.checkRouteBtn, "search", "Проверить", false, "")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btnTxt := "Добавить правило"
								if ui.editingRuleIdx >= 0 {
									btnTxt = "Сохранить правило"
								}
								return ui.iconButton(gtx, &ui.addRuleBtn, "plus", btnTxt, false, "primary")
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if ui.editingRuleIdx < 0 {
									return layout.Dimensions{}
								}
								return layout.Inset{Left: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.ruleCancelBtn, "Отмена", false, "danger")
								})
							}),
						)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
					// Row 2: Route Outbound Pills (with country flags)
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.caption(gtx, "Куда направлять трафик (Outbound):")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						obChoices := ui.dynamicRuleObChoices()
						var ws []layout.Widget
						for i := range obChoices {
							idx := i
							ch := obChoices[idx]
							active := ui.selectedRuleOb == ch.id
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								if ch.flag != "" {
									return ui.flagButton(gtx, &ui.ruleObBtns[idx], ch.flag, ch.title, active, "vio")
								}
								return ui.pillButton(gtx, &ui.ruleObBtns[idx], ch.title, active, "")
							})
						}
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6), ws...)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
					// Row 3: Quick List Picker Chips + Protocol & Always toggles
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.caption(gtx, "Вставить готовый список в поле правила (кликните по чипу):")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						curTxt := strings.ToLower(ui.hostEditor.Text())
						var ws []layout.Widget
						for i := range ruleQuickListIDs {
							idx := i
							item := ruleQuickListIDs[idx]
							tok := "list:" + item.id
							active := strings.Contains(curTxt, tok)
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.listPickBtns[idx], "list", item.title, active, "teal")
							})
						}
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6), ws...)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
					// Row 4: Protocol filter + Always mode
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						var ws []layout.Widget
						for i := range protoChoices {
							idx := i
							p := protoChoices[idx]
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.ruleProtoBtns[idx], p.title, ui.selectedProto == p.id, "")
							})
						}
						ws = append(ws, func(gtx layout.Context) layout.Dimensions {
							return ui.pillButton(gtx, &ui.ruleAlwaysBtn, "Работать во всех режимах (Always)", ui.ruleAlways, "ok")
						})
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6), ws...)
					}),
					layout.Rigid(ui.divider),
					// Row 5: 1-Click Service Templates & Ready Profiles
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.caption(gtx, "Готовые шаблоны сервисов в 1 клик (сразу добавляют настроенное правило):")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						var ws []layout.Widget
						for i := range rulePresetChoices {
							idx := i
							pr := rulePresetChoices[idx]
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.presetRuleBtns[idx], pr.title, false, "vio")
							})
						}
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6), ws...)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.caption(gtx, "Комплексные профили маршрутизации:")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						var ws []layout.Widget
						for i, p := range builtinProfiles {
							if i >= 5 {
								break
							}
							idx := i
							profName := p.Name
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.profileBtns[idx], profName, false, "")
							})
						}
						ws = append(ws, func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, &ui.undoProfileBtn, "refresh", "↶ Отменить импорт профиля", false, "teal")
						})
						return flowWrap(gtx, unit.Dp(6), unit.Dp(6), ws...)
					}),
					layout.Rigid(ui.divider),
					// Row 6: Batch Rule Import (Баг №4: многострочный импорт доменов/IP/процессов)
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.caption(gtx, "Пакетный импорт правил (по одному домену, подсети, списку или .exe на строку):")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								h := gtx.Dp(68)
								gtx.Constraints.Min.Y, gtx.Constraints.Max.Y = h, h
								return ui.editorBox(gtx, "batch-rule", &ui.batchRuleEditor, "youtube.com\ndiscord.gg\n91.108.4.0/22\nTelegram.exe")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.iconButton(gtx, &ui.batchImportBtn, "plus", "Импортировать пакетно", false, "primary")
							}),
						)
					}),
				)
			})
		},
		// 2. Active Rules List with Edit / Move / Toggle / Delete
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, unit.Dp(18), func(gtx layout.Context) layout.Dimensions {
				var rows []layout.FlexChild
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.cardHeader(gtx, "check", fmt.Sprintf("Активные правила маршрутизации (%d)", len(rules)),
						"Правила проверяются сверху вниз. Используйте стрелки ↑↓ для изменения приоритета, «Изм.» для редактирования", nil)
				}))
				rows = append(rows, layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout))
				if len(rules) == 0 {
					rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.label(gtx, unit.Sp(13.5), ui.pal.mut, font.Normal, "Список правил пуст. Нажмите на любой шаблон сервиса выше или создайте своё правило.")
					}))
				}
				for i := range rules {
					idx := i
					r := rules[idx]
					nm, _ := r["name"].(string)
					ob, _ := r["outbound"].(string)
					dis, _ := r["disabled"].(bool)
					alw, _ := r["always"].(bool)
					proto, _ := r["proto"].(string)

					ui.mu.Lock()
					tBtn := ui.ruleToggleBtns[idx]
					if tBtn == nil {
						tBtn = new(widget.Clickable)
						ui.ruleToggleBtns[idx] = tBtn
					}
					dBtn := ui.ruleDeleteBtns[idx]
					if dBtn == nil {
						dBtn = new(widget.Clickable)
						ui.ruleDeleteBtns[idx] = dBtn
					}
					eBtn := ui.ruleEditBtns[idx]
					if eBtn == nil {
						eBtn = new(widget.Clickable)
						ui.ruleEditBtns[idx] = eBtn
					}
					uBtn := ui.ruleUpBtns[idx]
					if uBtn == nil {
						uBtn = new(widget.Clickable)
						ui.ruleUpBtns[idx] = uBtn
					}
					dnBtn := ui.ruleDownBtns[idx]
					if dnBtn == nil {
						dnBtn = new(widget.Clickable)
						ui.ruleDownBtns[idx] = dnBtn
					}
					ui.mu.Unlock()

					if tBtn.Clicked(gtx) {
						ruleIdx := idx
						ui.doAsync("Статус правила изменён", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/rules/toggle", map[string]any{"index": ruleIdx})
						})
					}
					if dBtn.Clicked(gtx) {
						ruleIdx := idx
						if ui.editingRuleIdx == ruleIdx {
							ui.editingRuleIdx = -1
						}
						ui.doAsync("Правило удалено", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/rules/delete", map[string]any{"index": ruleIdx})
						})
					}
					if uBtn.Clicked(gtx) && idx > 0 {
						ruleIdx := idx
						ui.doAsync("Приоритет правила повышен", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/rules/move", map[string]any{"index": ruleIdx, "dir": -1})
						})
					}
					if dnBtn.Clicked(gtx) && idx < len(rules)-1 {
						ruleIdx := idx
						ui.doAsync("Приоритет правила понижен", func() (map[string]any, error) {
							return ui.apiCall("POST", "/api/rules/move", map[string]any{"index": ruleIdx, "dir": 1})
						})
					}
					if eBtn.Clicked(gtx) {
						ui.editingRuleIdx = idx
						ui.ruleNameEditor.SetText(nm)
						ui.hostEditor.SetText(ruleEditableTokens(r))
						if ob != "" {
							ui.selectedRuleOb = ob
						}
						ui.selectedProto = strings.ToLower(proto)
						ui.ruleAlways = alw
						ui.setToast("Правило «"+nm+"» загружено в конструктор сверху", false)
					}

					summary := ruleEditableTokens(r)
					if len(summary) > 110 {
						summary = summary[:107] + "..."
					}
					var metaTags []string
					if proto != "" {
						metaTags = append(metaTags, strings.ToUpper(proto))
					}
					if alw {
						metaTags = append(metaTags, "все режимы")
					}
					if len(metaTags) > 0 {
						summary = "[" + strings.Join(metaTags, " · ") + "]  " + summary
					}

					rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							bdr := ui.pal.border
							if ui.editingRuleIdx == idx {
								bdr = ui.pal.acc
							}
							return ui.subCard(gtx, ui.pal.card2, bdr, unit.Dp(11), func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.monoLabel(gtx, unit.Sp(11.5), ui.pal.dim, fmt.Sprintf("#%d  ", idx+1))
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.label(gtx, unit.Sp(13.5), ui.pal.text, font.Bold, orDefault(nm, "Правило"))
													}),
													layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return ui.routeBadge(gtx, ob)
													}),
												)
											}),
											layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.labelLine(gtx, unit.Sp(11.5), ui.pal.mut, font.Normal, orDefault(summary, "все направления"))
											}),
										)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										txt := "Вкл"
										if dis {
											txt = "Выкл"
										}
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.iconButton(gtx, uBtn, "up", "", false, "")
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.iconButton(gtx, dnBtn, "down", "", false, "")
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.iconButton(gtx, eBtn, "edit", "Изм.", ui.editingRuleIdx == idx, "")
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.pillButton(gtx, tBtn, txt, !dis, "")
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.iconButton(gtx, dBtn, "trash", "", false, "danger")
											}),
										)
									}),
								)
							})
						})
					}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
		// 3. Modernized Lists Catalog Card
		ui.layoutListsCatalogCard,
	}

	return material.List(ui.th, &ui.rulesPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: unit.Dp(14), Right: unit.Dp(6)}.Layout(gtx, sections[i])
	})
}
