//go:build windows

package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// ============================================================================
// FILE: gui_rules.go (Умные сгруппированные карточки и Живой Инспектор)
// ============================================================================

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
	{"telegram", "+ Telegram (Звонки + Чат)"},
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

func toStringSlice(v any) []string {
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, it := range arr {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func toIntSlice(v any) []int {
	switch arr := v.(type) {
	case []int:
		return arr
	case []any:
		out := make([]int, 0, len(arr))
		for _, it := range arr {
			switch n := it.(type) {
			case int:
				out = append(out, n)
			case float64:
				out = append(out, int(n))
			}
		}
		return out
	}
	return nil
}

func isRUWhitelistRuleMap(r map[string]any) bool {
	ob, _ := r["outbound"].(string)
	if ob != obDirect {
		return false
	}
	for _, l := range toStringSlice(r["lists"]) {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "ru" || l == "ru-gov-banks" {
			return true
		}
	}
	doms := toStringSlice(r["domains"])
	if len(doms) > 0 && len(toStringSlice(r["apps"])) == 0 && len(toStringSlice(r["cidr"])) == 0 && len(toIntSlice(r["ports"])) == 0 && len(toStringSlice(r["port_ranges"])) == 0 {
		for _, d := range doms {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "ru" || d == ".ru" || d == "*.ru" || d == "xn--p1ai" || d == "su" || d == "рф" || d == "country:ru" {
				return true
			}
		}
	}
	return false
}

func classifyRuleMapGroup(r map[string]any) int {
	hasPosApp := false
	for _, a := range toStringSlice(r["apps"]) {
		a = strings.TrimSpace(a)
		if a != "" && !strings.HasPrefix(a, "!") {
			hasPosApp = true
			break
		}
	}
	hasTarget := len(toStringSlice(r["domains"])) > 0 ||
		len(toStringSlice(r["keywords"])) > 0 ||
		len(toStringSlice(r["cidr"])) > 0 ||
		len(toStringSlice(r["ips"])) > 0 ||
		len(toIntSlice(r["ports"])) > 0 ||
		len(toStringSlice(r["port_ranges"])) > 0
	hasLists := len(toStringSlice(r["lists"])) > 0
	proto, _ := r["proto"].(string)

	// Приоритет 1 — Точечные комбинированные правила (Программа + Домен/Порт)
	if hasPosApp && (hasTarget || hasLists || strings.TrimSpace(proto) != "") {
		return 1
	}
	// Приоритет 4 (Белый список РФ) проверяется до Приоритета 2, как и в router.go (Tier 5)
	if !hasPosApp && isRUWhitelistRuleMap(r) {
		return 4
	}
	// Приоритет 2 — Личные точные сайты, ключевые слова и IP-подсети
	if !hasPosApp && (hasTarget || !hasLists) {
		return 2
	}
	// Приоритет 3 — Общие правила для программ целиком (.exe)
	if hasPosApp {
		return 3
	}
	// Приоритет 4 — Массовые списки доменов и внешние реестры
	return 4
}

func ruleGroupHeaderInfo(group int) (title, sub string) {
	switch group {
	case 1:
		return "УРОВЕНЬ 1 (TIER 2) · ТОЧЕЧНЫЕ ПРАВИЛА (КОНКРЕТНАЯ ПРОГРАММА + САЙТ / ПОРТ)",
			"Высший приоритет маршрутизации: срабатывает только для указанной программы при запросе к конкретному сайту или порту."
	case 2:
		return "УРОВЕНЬ 2 (TIER 3) · ЛИЧНЫЕ САЙТЫ, ДОМЕНЫ И IP (ДЛЯ ВСЕХ БРАУЗЕРОВ)",
			"Срабатывают во всех браузерах (Chrome, Edge, Яндекс) одновременно, перекрывая общие правила программ и списки."
	case 3:
		return "УРОВЕНЬ 3 (TIER 4) · ОБЩИЕ ПРАВИЛА ДЛЯ ПРОГРАММ ЦЕЛИКОМ (.EXE)",
			"Задают базовый выход для всего трафика процесса (например, Discord.exe ➔ WARP или cs2.exe ➔ Direct)."
	default:
		return "УРОВЕНЬ 4 (TIER 5–6) · ПОДКЛЮЧЁННЫЕ СПИСКИ И МАССОВЫЕ РЕЕСТРЫ",
			"Массовая маршрутизация на базе списков доменов и подсетей (ru-gov-banks, antifilter, youtube, ai-services)."
	}
}

func (ui *gioUI) layoutRulesTab(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	rlData := ui.rulesData
	inspectorPreview := ui.ruleInspectorPreview
	inspectorConflict := ui.ruleInspectorConflict
	ui.mu.Unlock()

	var rules []map[string]any
	if rlData != nil {
		rules = toMapSlice(rlData["rules"])
	}

	// Автоматический Debounce инспектора трассы пакета (250 мс)
	rawInput := strings.TrimSpace(ui.hostEditor.Text())
	firstTok := rawInput
	if idx := strings.IndexAny(firstTok, ",;"); idx >= 0 {
		firstTok = strings.TrimSpace(firstTok[:idx])
	}
	firstTok = strings.TrimPrefix(firstTok, "list:")
	firstTok = strings.TrimPrefix(firstTok, "app:")
	firstTok = strings.TrimPrefix(firstTok, "domain:")
	firstTok = strings.TrimPrefix(firstTok, "keyword:")
	firstTok = strings.TrimPrefix(firstTok, "port:")
	firstTok = strings.TrimPrefix(firstTok, "cidr:")
	firstTok = strings.TrimSpace(firstTok)

	if firstTok != ui.lastRuleCheckQuery {
		ui.lastRuleCheckQuery = firstTok
		stamp := time.Now()
		ui.mu.Lock()
		ui.lastRuleCheckAt = stamp
		ui.mu.Unlock()
		if firstTok == "" || strings.Contains(firstTok, " ") {
			ui.mu.Lock()
			ui.ruleInspectorPreview = ""
			ui.ruleInspectorConflict = ""
			ui.mu.Unlock()
			inspectorPreview, inspectorConflict = "", ""
		} else {
			func(target string, ts time.Time) { safeGo("gioUI.layoutRulesTab", func() {
				time.Sleep(250 * time.Millisecond)
				ui.mu.Lock()
				stillCurrent := ui.lastRuleCheckQuery == target && ui.lastRuleCheckAt.Equal(ts)
				ui.mu.Unlock()
				if !stillCurrent {
					return
				}
				q := "/api/route?host=" + url.QueryEscape(target) + "&port=443"
				if strings.HasSuffix(strings.ToLower(target), ".exe") {
					q = "/api/route?host=example.com&port=443&app=" + url.QueryEscape(target)
				}
				if res, err := ui.apiCall("GET", q, nil); err == nil && res != nil {
					badge, _ := res["badge"].(string)
					stageTitle, _ := res["stage_title"].(string)
					ruleNm, _ := res["rule"].(string)
					conflict, _ := res["conflict"].(string)
					trace := fmt.Sprintf("[Вход: %s] ➔ [%s · %s] ➔ [%s]", target, orDefault(stageTitle, "Ядро конвейера"), orDefault(ruleNm, "Выход по умолчанию"), badge)
					ui.mu.Lock()
					if ui.lastRuleCheckQuery == target {
						ui.ruleInspectorPreview = trace
						ui.ruleInspectorConflict = conflict
					}
					ui.mu.Unlock()
					if ui.w != nil {
						ui.w.Invalidate()
					}
				}
			}) }(firstTok, stamp)
		}
	}

	protoChoices := [3]struct{ id, title string }{
		{"", "TCP + UDP"},
		{"tcp", "Только TCP"},
		{"udp", "Только UDP"},
	}

	toggleTemplatesBtn := ui.appBtn("rules|toggle-templates")
	if toggleTemplatesBtn.Clicked(gtx) {
		ui.rulesTemplatesOpen = !ui.rulesTemplatesOpen
	}

	sections := []layout.Widget{
		// 0. Компактный Конструктор + Живой Симулятор (Tactical Minimal — фокус на правилах!)
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
				hdrTitle := "Умный конструктор правил и Живой симулятор"
				if ui.editingRuleIdx >= 0 {
					hdrTitle = fmt.Sprintf("Редактирование правила #%d", ui.editingRuleIdx+1)
				}
				tplBtnLabel := "+ Шаблоны, списки и импорт"
				if ui.rulesTemplatesOpen {
					tplBtnLabel = "▲ Скрыть шаблоны и импорт"
				}

				children := []layout.FlexChild{
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.cardHeader(gtx, "route", hdrTitle,
							"Ссылки (https://...) автоматически очищаются до чистого домена. Новые правила получают высший приоритет.",
							func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, toggleTemplatesBtn, tplBtnLabel, ui.rulesTemplatesOpen, "teal")
							})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				}

				if inspectorPreview != "" {
					children = append(children,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							bdrColor := ui.pal.teal
							if inspectorConflict != "" {
								bdrColor = ui.pal.warn
							}
							return ui.subCard(gtx, ui.pal.card2, bdrColor, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.monoLabel(gtx, fontBody, ui.pal.teal, "Инспектор: "+inspectorPreview)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if inspectorConflict == "" {
											return layout.Dimensions{}
										}
										return layout.Inset{Top: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return ui.labelLine(gtx, fontSmall, ui.pal.warn, font.SemiBold, "⚠ КОНФЛИКТ ПРАВИЛ: "+inspectorConflict)
										})
									}),
								)
							})
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					)
				}

				children = append(children,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								w := gtx.Dp(190)
								if w > gtx.Constraints.Max.X/4 {
									w = gtx.Constraints.Max.X / 4
								}
								gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
								return ui.editorBox(gtx, "rule-name", &ui.ruleNameEditor, "Имя (необяз.)")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return ui.editorBox(gtx, "rule-host", &ui.hostEditor, "youtube.com, list:discord, !ru, Discord.exe, port:443")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btnTxt := "Добавить правило"
								if ui.editingRuleIdx >= 0 {
									btnTxt = "Сохранить"
								}
								return ui.iconButton(gtx, &ui.addRuleBtn, "plus", btnTxt, false, "primary")
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if ui.editingRuleIdx < 0 {
									return layout.Dimensions{}
								}
								return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.ruleCancelBtn, "Отмена", false, "danger")
								})
							}),
						)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						obChoices := ui.dynamicRuleObChoices()
						var ws []layout.Widget
						for i := range obChoices {
							idx := i
							ch := obChoices[idx]
							active := ui.selectedRuleOb == ch.id
							style := "vio"
							switch ch.id {
							case obDirect:
								style = "ok"
							case obDesync:
								style = "teal"
							case obWarp:
								style = "warn"
							case obBlock:
								style = "danger"
							case obAuto:
								style = "primary"
							}
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								if ch.flag != "" {
									return ui.flagButton(gtx, &ui.ruleObBtns[idx], ch.flag, ch.title, active, "vio")
								}
								return ui.segRouteButton(gtx, &ui.ruleObBtns[idx], ch.title, active, style)
							})
						}
						for i := range protoChoices {
							idx := i
							p := protoChoices[idx]
							ws = append(ws, func(gtx layout.Context) layout.Dimensions {
								return ui.pillButton(gtx, &ui.ruleProtoBtns[idx], p.title, ui.selectedProto == p.id, "")
							})
						}
						ws = append(ws, func(gtx layout.Context) layout.Dimensions {
							return ui.pillButton(gtx, &ui.ruleAlwaysBtn, "✓ Все режимы (Always)", ui.ruleAlways, "ok")
						})
						return flowWrap(gtx, unit.Dp(4), unit.Dp(4), ws...)
					}),
				)

				// Раскрывающийся аккордеон с шаблонами, чипами списков и пакетным импортом
				if ui.rulesTemplatesOpen {
					children = append(children,
						layout.Rigid(ui.divider),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.caption(gtx, "Шаблоны популярных сервисов в 1 клик:")
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							var ws []layout.Widget
							for i := range rulePresetChoices {
								idx := i
								pr := rulePresetChoices[idx]
								ws = append(ws, func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.presetRuleBtns[idx], pr.title, false, "vio")
								})
							}
							return flowWrap(gtx, unit.Dp(4), unit.Dp(4), ws...)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.caption(gtx, "Быстрые чипы списков и пакетный импорт:")
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
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
							return flowWrap(gtx, unit.Dp(4), unit.Dp(4), ws...)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									h := gtx.Dp(58)
									gtx.Constraints.Min.Y, gtx.Constraints.Max.Y = h, h
									return ui.editorBox(gtx, "batch-rule", &ui.batchRuleEditor, "Пакетный импорт (по одному домену, подсети или .exe на строку)")
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, &ui.batchImportBtn, "plus", "Импортировать", false, "primary")
								}),
							)
						}),
					)
				}

				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
			})
		},
		// 1. Группированные карточки активных правил (Tier 1..4) с компактным Segmented Route Switcher
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return ui.card(gtx, unit.Dp(12), func(gtx layout.Context) layout.Dimensions {
				var rows []layout.FlexChild
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.cardHeader(gtx, "check", fmt.Sprintf("Активные правила по уровням приоритета ядра (%d)", len(rules)),
						"Переключайте выход (Direct / DPI / WARP / VPN / Блок) в 1 клик прямо на сегментной плашке карточки.", nil)
				}))
				rows = append(rows, layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout))

				if len(rules) == 0 {
					rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.label(gtx, unit.Sp(13), ui.pal.mut, font.Normal, "Список правил пуст. Впишите сайт выше или откройте «+ Шаблоны, списки и импорт».")
					}))
				}

				for group := 1; group <= 4; group++ {
					var groupIndices []int
					for i, r := range rules {
						if classifyRuleMapGroup(r) == group {
							groupIndices = append(groupIndices, i)
						}
					}
					if len(groupIndices) == 0 {
						continue
					}

					gTitle, gSub := ruleGroupHeaderInfo(group)
					rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontSmall, ui.pal.acc, font.Bold, fmt.Sprintf("%s (%d)", gTitle, len(groupIndices)))
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Normal, gSub)
								}),
							)
						})
					}))

					for pos, idxVal := range groupIndices {
						idx := idxVal
						prevInGroupIdx := -1
						if pos > 0 {
							prevInGroupIdx = groupIndices[pos-1]
						}
						nextInGroupIdx := -1
						if pos < len(groupIndices)-1 {
							nextInGroupIdx = groupIndices[pos+1]
						}

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

						inlineObs := []struct{ id, title, style string }{
							{obDirect, "Direct", "ok"},
							{obDesync, "DPI", "teal"},
							{obWarp, "WARP", "warn"},
							{obPsiphon, "VPN", "vio"},
							{obBlock, "Блок", "danger"},
						}

						for _, io := range inlineObs {
							btnInline := ui.appBtn(fmt.Sprintf("ruleob|%d|%s", idx, io.id))
							if btnInline.Clicked(gtx) && ob != io.id {
								ruleIdx := idx
								ruleCopy := r
								targetOb := io.id
								toks := ruleEditableTokens(ruleCopy)
								ui.doAsync(fmt.Sprintf("Правило «%s» ➔ %s", orDefault(nm, "Правило"), routeShortRu(targetOb)), func() (map[string]any, error) {
									body := ruleEditRequest(ruleCopy, toks, nm, targetOb, proto, alw)
									body["index"] = ruleIdx
									return ui.apiCall("POST", "/api/rules/add", body)
								})
							}
						}

						if uBtn.Clicked(gtx) && prevInGroupIdx >= 0 {
							ruleIdx := idx
							swapIdx := prevInGroupIdx
							dir := swapIdx - ruleIdx
							if ui.editingRuleIdx == ruleIdx {
								ui.editingRuleIdx = swapIdx
							} else if ui.editingRuleIdx == swapIdx {
								ui.editingRuleIdx = ruleIdx
							}
							ui.doAsync("Приоритет правила повышен", func() (map[string]any, error) {
								return ui.apiCall("POST", "/api/rules/move", map[string]any{"index": ruleIdx, "dir": dir})
							})
						}
						if dnBtn.Clicked(gtx) && nextInGroupIdx >= 0 {
							ruleIdx := idx
							swapIdx := nextInGroupIdx
							dir := swapIdx - ruleIdx
							if ui.editingRuleIdx == ruleIdx {
								ui.editingRuleIdx = swapIdx
							} else if ui.editingRuleIdx == swapIdx {
								ui.editingRuleIdx = ruleIdx
							}
							ui.doAsync("Приоритет правила понижен", func() (map[string]any, error) {
								return ui.apiCall("POST", "/api/rules/move", map[string]any{"index": ruleIdx, "dir": dir})
							})
						}

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
						if eBtn.Clicked(gtx) {
							ui.editingRuleIdx = idx
							ui.ruleNameEditor.SetText(nm)
							ui.editingRuleOriginal = r
							ui.hostEditor.SetText(ruleEditableTokens(r))
							if ob != "" {
								ui.selectedRuleOb = ob
							}
							ui.selectedProto = strings.ToLower(proto)
							ui.ruleAlways = alw
							ui.setToast("Правило загружено в конструктор сверху", false)
						}

						summary := ruleEditableTokens(r)
						if len(summary) > 90 {
							summary = summary[:87] + "..."
						}

						var tags []string
						if proto != "" {
							tags = append(tags, strings.ToUpper(proto))
						}
						if alw {
							tags = append(tags, "все режимы")
						}
						for _, d := range toStringSlice(r["domains"]) {
							cleanD := strings.TrimPrefix(cleanHostKey(cleanHost(d)), "www.")
							if extras, ok := serviceCompanionDomains[cleanD]; ok && len(extras) > 0 {
								tags = append(tags, fmt.Sprintf("+%d связанных CDN", len(extras)))
								break
							}
						}
						if len(tags) > 0 {
							summary = "[" + strings.Join(tags, " · ") + "]  " + summary
						}

						rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Bottom: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								bdr := ui.pal.border
								if ui.editingRuleIdx == idx {
									bdr = ui.pal.acc
								}
								return ui.subCard(gtx, ui.pal.card2, bdr, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
										layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
											return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
														layout.Rigid(func(gtx layout.Context) layout.Dimensions {
															return ui.monoLabel(gtx, unit.Sp(11), ui.pal.dim, fmt.Sprintf("#%d ", idx+1))
														}),
														layout.Rigid(func(gtx layout.Context) layout.Dimensions {
															return ui.label(gtx, unit.Sp(13), ui.pal.text, font.Bold, orDefault(nm, "Без имени"))
														}),
														layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
														layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.routeBadge(gtx, ob) }),
													)
												}),
												layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return ui.monoLabel(gtx, unit.Sp(11), ui.pal.mut, summary)
												}),
											)
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											txt := "Вкл"
											if dis {
												txt = "Выкл"
											}
											var segCells []layout.FlexChild
											for _, io := range inlineObs {
												io := io
												btnInline := ui.appBtn(fmt.Sprintf("ruleob|%d|%s", idx, io.id))
												segCells = append(segCells, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return ui.segRouteButton(gtx, btnInline, io.title, ob == io.id, io.style)
												}))
											}
											segPill := ui.subCard(gtx, ui.pal.card, ui.pal.border, unit.Dp(2), func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, segCells...)
											})
											_ = segPill
											return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return ui.subCard(gtx, ui.pal.card, ui.pal.border, unit.Dp(2), func(gtx layout.Context) layout.Dimensions {
														return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, segCells...)
													})
												}),
												layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.iconButton(gtx, uBtn, "up", "", false, "") }),
												layout.Rigid(layout.Spacer{Width: unit.Dp(2)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.iconButton(gtx, dnBtn, "down", "", false, "") }),
												layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.iconButton(gtx, eBtn, "edit", "Ред.", ui.editingRuleIdx == idx, "") }),
												layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.pillButton(gtx, tBtn, txt, !dis, "") }),
												layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions { return ui.iconButton(gtx, dBtn, "trash", "", false, "danger") }),
											)
										}),
									)
								})
							})
						}))
					}
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			})
		},
	}

	return material.List(ui.th, &ui.rulesPageList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: unit.Dp(10), Right: unit.Dp(4)}.Layout(gtx, sections[i])
	})
}
