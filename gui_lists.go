//go:build windows

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
)

// ---------- Lists Manager Card (Gio UI, Tab 1 «Правила и списки») ----------
//
// Supports:
//  - Search filter across list ID, title, category, and URL
//  - Groups: «Все», «Мои», «Встроенные», «Скрытые» + «Вернуть встроенные»
//  - Creating & editing lists: by URL, pasted text (multiline editor), or file path
//  - Live preview before saving (domains, subnets, skipped lines, regexp warnings)
//  - Explicit confirmation dialog when adding an untrusted HTTPS host
//  - Safe deletion dialog when a list is used in rules («Убрать из правил и удалить» / «Отмена»)
//  - Per-list actions: «В правило…», «Изменить», «Обновить», «Удалить» / «Скрыть»

func (ui *gioUI) listActBtn(key string) *widget.Clickable {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	b := ui.listActionBtns[key]
	if b == nil {
		b = new(widget.Clickable)
		ui.listActionBtns[key] = b
	}
	return b
}

func (ui *gioUI) layoutListsCatalogCard(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	rlData := ui.rulesData
	preview := ui.listPreviewData
	delID := ui.listDeleteConfirmID
	delTitle := ui.listDeleteConfirmTitle
	delRules := append([]string(nil), ui.listDeleteUsedRules...)
	trustHost := ui.listTrustConfirmHost
	ui.mu.Unlock()

	var allItems []map[string]any
	var hiddenList []string
	if rlData != nil {
		allItems = toMapSlice(rlData["lists"])
		if hArr, ok := rlData["hidden_lists"].([]any); ok {
			for _, x := range hArr {
				if s, ok := x.(string); ok && s != "" {
					hiddenList = append(hiddenList, s)
				}
			}
		}
	}

	// Count custom vs built-in vs hidden
	var myCount, builtinCount, hiddenCount int
	for _, it := range allItems {
		custom, _ := it["custom"].(bool)
		local, _ := it["local"].(bool)
		hid, _ := it["hidden"].(bool)
		if hid {
			hiddenCount++
		} else if custom || local {
			myCount++
		} else {
			builtinCount++
		}
	}
	if len(hiddenList) > hiddenCount {
		hiddenCount = len(hiddenList)
	}

	q := strings.ToLower(strings.TrimSpace(ui.listSearchEditor.Text()))
	var filtered []map[string]any
	for _, it := range allItems {
		custom, _ := it["custom"].(bool)
		local, _ := it["local"].(bool)
		hid, _ := it["hidden"].(bool)
		switch ui.listGroupFilter {
		case 1: // Мои
			if (!custom && !local) || hid {
				continue
			}
		case 2: // Встроенные
			if custom || local || hid {
				continue
			}
		case 3: // Скрытые
			if !hid {
				continue
			}
		default: // Все (кроме скрытых)
			if hid {
				continue
			}
		}
		if q != "" {
			id, _ := it["id"].(string)
			title, _ := it["title"].(string)
			cat, _ := it["category"].(string)
			u, _ := it["url"].(string)
			if !strings.Contains(strings.ToLower(id+" "+title+" "+cat+" "+u), q) {
				continue
			}
		}
		filtered = append(filtered, it)
	}

	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return ui.card(gtx, space2, func(gtx layout.Context) layout.Dimensions {
		var rows []layout.FlexChild

		// 1. Header with "+ Добавить список" and "Обновить все"
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.cardHeader(gtx, "list",
				fmt.Sprintf("Списки доменов и подсетей (моих: %d · встроенных: %d)", myCount, builtinCount),
				"Свои списки (по ссылке, тексту или из файла) и встроенный каталог с бинарным поиском O(log N)",
				func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := "+ Добавить список"
							if ui.listFormOpen && ui.listEditID == "" {
								lbl = "Закрыть форму"
							}
							return ui.iconButton(gtx, &ui.listNewBtn, "plus", lbl, ui.listFormOpen, "primary")
						}),
						layout.Rigid(layout.Spacer{Width: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.iconButton(gtx, &ui.refreshListBtn, "refresh", "Обновить все", false, "")
						}),
					)
				})
		}))

		// 2. Delete Confirmation Banner when list is used in rules
		if delID != "" {
			rows = append(rows, layout.Rigid(layout.Spacer{Height: space2}.Layout))
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.subCard(gtx, ui.pal.errSoft, ui.pal.err, space2, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.label(gtx, fontBody, ui.pal.err, font.Bold,
								fmt.Sprintf("Список «%s» используется в правилах: %s", orDefault(delTitle, delID), strings.Join(delRules, ", ")))
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.label(gtx, fontSmall, ui.pal.text, font.Normal,
								"Чтобы не оставлять правила с битой ссылкой, выберите «Убрать из правил и удалить» или отмените удаление.")
						}),
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, &ui.listDeleteForceBtn, "trash", "Убрать из правил и удалить", false, "danger")
								}),
								layout.Rigid(layout.Spacer{Width: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.listDeleteCancelBtn, "Отмена", false, "")
								}),
							)
						}),
					)
				})
			}))
		}

		// 3. Untrusted Host Confirmation Banner
		if trustHost != "" {
			rows = append(rows, layout.Rigid(layout.Spacer{Height: space2}.Layout))
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.subCard(gtx, ui.pal.warnSoft, ui.pal.warn, space2, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.label(gtx, fontBody, ui.pal.warn, font.Bold,
								fmt.Sprintf("Подтвердите доверие к внешнему HTTPS-хосту «%s»", trustHost))
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.label(gtx, fontSmall, ui.pal.text, font.Normal,
								"Этот хост не входит в стандартный белый список. Разрешить загрузку и запомнить его в lists.trusted_hosts?")
						}),
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, &ui.listTrustApproveBtn, "check", "Доверять хосту и сохранить", false, "primary")
								}),
								layout.Rigid(layout.Spacer{Width: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.listTrustCancelBtn, "Отмена", false, "")
								}),
							)
						}),
					)
				})
			}))
		}

		// 4. Add / Edit List Form (URL / Text / File + Multiline Editor + Live Preview)
		if ui.listFormOpen {
			rows = append(rows, layout.Rigid(layout.Spacer{Height: space2}.Layout))
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				formTitle := "Новый пользовательский список"
				if ui.listEditID != "" {
					formTitle = "Редактирование списка «" + ui.listEditID + "»"
				}
				modeBtns := []*widget.Clickable{&ui.listSourceModeBtns[0], &ui.listSourceModeBtns[1], &ui.listSourceModeBtns[2]}
				modeLabels := []string{"Вставить текст (локальный)", "По ссылке (HTTPS URL)", "Импорт из файла"}
				return ui.subCard(gtx, ui.pal.card2, ui.pal.acc, space2, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.label(gtx, fontBody, ui.pal.text, font.Bold, formTitle)
						}),
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.segmented(gtx, modeBtns, modeLabels, ui.listSourceMode)
						}),
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						// ID + Title + Interval row
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									w := gtx.Dp(220)
									gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
									return ui.editorBox(gtx, "list-id", &ui.listIDEditor, "ID (напр. my-work)")
								}),
								layout.Rigid(layout.Spacer{Width: space1}.Layout),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return ui.editorBox(gtx, "list-title", &ui.listTitleEditor, "Название списка (например, Рабочие сервисы)")
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						// Mode-specific input: multiline editor, URL input, or file path loader
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if ui.listSourceMode == 1 {
								return ui.editorBox(gtx, "list-url", &ui.listURLEditor, "https://raw.githubusercontent.com/... или любой доверенный https:// адрес")
							}
							var fileRow layout.FlexChild
							if ui.listSourceMode == 2 {
								fileRow = layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Bottom: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												return ui.editorBox(gtx, "list-file", &ui.listFilePathEditor, `Путь к файлу (.lst, .txt, .json, .yaml), напр. D:\lists\my.txt`)
											}),
											layout.Rigid(layout.Spacer{Width: space1}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return ui.iconButton(gtx, &ui.listLoadFileBtn, "download", "Прочитать файл", false, "")
											}),
										)
									})
								})
							} else {
								fileRow = layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} })
							}
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								fileRow,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									h := gtx.Dp(136)
									gtx.Constraints.Min.Y, gtx.Constraints.Max.Y = h, h
									return ui.editorBox(gtx, "list-content", &ui.listContentEditor,
										"По одному домену, подсети или правилу на строку:\nexample.com\nfull:exact.example.org\n10.20.0.0/16\ninclude:yandex")
								}),
							)
						}),
						// Preview stats line
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if preview == nil {
								return layout.Dimensions{}
							}
							doms, _ := preview["domains"].(float64)
							subs, _ := preview["subnets"].(float64)
							skipped, _ := preview["skipped_lines"].(float64)
							rxSkip, _ := preview["regexp_skipped"].(float64)
							msg := fmt.Sprintf("Предпросмотр: распознано доменов: %.0f · подсетей: %.0f · отброшено строк: %.0f", doms, subs, skipped)
							if rxSkip > 0 {
								msg += fmt.Sprintf(" · пропущено regexp: %.0f (не поддерживаются)", rxSkip)
							}
							return layout.Inset{Top: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return ui.label(gtx, fontSmall, ui.pal.teal, font.SemiBold, msg)
							})
						}),
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if ui.listSourceMode == 1 {
										return layout.Dimensions{}
									}
									return layout.Inset{Right: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, &ui.listPreviewBtn, "search", "Предпросмотр", false, "")
									})
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, &ui.listSaveBtn, "check", "Сохранить список", false, "primary")
								}),
								layout.Rigid(layout.Spacer{Width: space1}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.pillButton(gtx, &ui.listCancelBtn, "Отмена", false, "")
								}),
							)
						}),
					)
				})
			}))
		}

		// 5. Filter tabs («Все», «Мои», «Встроенные», «Скрытые») + «Вернуть встроенные» + Search Box
		rows = append(rows, layout.Rigid(layout.Spacer{Height: space2}.Layout))
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, &ui.listGroupBtns[0], fmt.Sprintf("Все · %d", myCount+builtinCount), ui.listGroupFilter == 0, "")
				}),
				layout.Rigid(layout.Spacer{Width: space1}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, &ui.listGroupBtns[1], fmt.Sprintf("Мои · %d", myCount), ui.listGroupFilter == 1, "")
				}),
				layout.Rigid(layout.Spacer{Width: space1}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, &ui.listGroupBtns[2], fmt.Sprintf("Встроенные · %d", builtinCount), ui.listGroupFilter == 2, "")
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if hiddenCount == 0 {
						return layout.Dimensions{}
					}
					return layout.Inset{Left: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.pillButton(gtx, &ui.listGroupBtns[3], fmt.Sprintf("Скрытые · %d", hiddenCount), ui.listGroupFilter == 3, "")
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if hiddenCount == 0 {
						return layout.Dimensions{}
					}
					return layout.Inset{Left: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.iconButton(gtx, &ui.listRestoreBuiltinBtn, "refresh", "Вернуть встроенные", false, "teal")
					})
				}),
				layout.Flexed(1, layout.Spacer{}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					w := gtx.Dp(280)
					if w > gtx.Constraints.Max.X {
						w = gtx.Constraints.Max.X
					}
					gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
					return ui.editorBox(gtx, "list-search", &ui.listSearchEditor, "Поиск списков…")
				}),
			)
		}))

		rows = append(rows, layout.Rigid(layout.Spacer{Height: space2}.Layout))

		if len(filtered) == 0 {
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.emptyState(gtx, "list",
					"В этой группе пока нет списков",
					"Добавьте свой список по ссылке, вставьте домены/подсети текстом или загрузите из файла.",
					"+ Добавить список", &ui.listNewBtn)
			}))
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		}

		// 6. Grid of List Cards with «В правило…», «Изменить», «Обновить», «Удалить» / «Скрыть»
		var tiles []layout.Widget
		for i := range filtered {
			it := filtered[i]
			id, _ := it["id"].(string)
			title, _ := it["title"].(string)
			cat, _ := it["category"].(string)
			typ, _ := it["type"].(string)
			u, _ := it["url"].(string)
			custom, _ := it["custom"].(bool)
			local, _ := it["local"].(bool)
			errMsg, _ := it["error"].(string)
			doms, _ := it["domains"].(float64)
			cidrs, _ := it["subnets"].(float64)
			if cidrs == 0 {
				cidrs, _ = it["cidrs"].(float64)
			}
			updUnix, _ := it["updated"].(float64)

			useBtn := ui.listUseBtn(id)
			editBtn := ui.listActBtn("edit|" + id)
			refBtn := ui.listActBtn("ref|" + id)
			delBtn := ui.listActBtn("del|" + id)

			if useBtn.Clicked(gtx) {
				listID := id
				listTitle := title
				ob := ui.selectedRuleOb
				if listID == "ru" || listID == "ru-gov-banks" {
					ob = obDirect
				}
				ui.doAsync(fmt.Sprintf("Добавлено правило со списком «%s» → %s", listTitle, ob), func() (map[string]any, error) {
					return ui.apiCall("POST", "/api/rules/add", map[string]any{
						"name":     listTitle,
						"lists":    []string{listID},
						"outbound": ob,
					})
				})
			}
			if editBtn.Clicked(gtx) {
				listID := id
				listTitle := title
				listURL := u
				isLoc := local || typ == "local"
				ui.listFormOpen = true
				ui.listEditID = listID
				ui.listIDEditor.SetText(listID)
				ui.listTitleEditor.SetText(listTitle)
				if isLoc {
					ui.listSourceMode = 0
					go func() {
						res, err := ui.apiCall("GET", "/api/lists/"+url.PathEscape(listID)+"/content", nil)
						if err == nil && res != nil {
							if txt, ok := res["content"].(string); ok {
								ui.queueEditorText(&ui.listContentEditor, txt)
							}
						}
					}()
				} else {
					ui.listSourceMode = 1
					ui.listURLEditor.SetText(listURL)
				}
			}
			if refBtn.Clicked(gtx) {
				listID := id
				ui.doAsync("Обновляю список «"+title+"»…", func() (map[string]any, error) {
					return ui.apiCall("POST", "/api/lists/"+url.PathEscape(listID)+"/refresh", map[string]any{})
				})
			}
			if delBtn.Clicked(gtx) {
				listID := id
				listTitle := title
				go func() {
					res, err := ui.apiCall("DELETE", "/api/lists/"+url.PathEscape(listID), map[string]any{})
					if res != nil && res["in_use"] == true {
						var used []string
						if arr, ok := res["used_in_rules"].([]any); ok {
							for _, x := range arr {
								if s, ok := x.(string); ok {
									used = append(used, s)
								}
							}
						}
						ui.mu.Lock()
						ui.listDeleteConfirmID = listID
						ui.listDeleteConfirmTitle = listTitle
						ui.listDeleteUsedRules = used
						ui.mu.Unlock()
						if ui.w != nil {
							ui.w.Invalidate()
						}
						return
					}
					if err != nil {
						ui.setToast("Ошибка: "+err.Error(), true)
						return
					}
					ui.setToast("Список «"+listTitle+"» удалён", false)
					ui.fetchAll(true)
				}()
			}

			metaLine := fmt.Sprintf("%s · доменов: %.0f · подсетей: %.0f", orDefault(cat, "Список"), doms, cidrs)
			if updUnix > 0 {
				metaLine += " · обновлён"
			}
			delLbl := "Скрыть"
			if custom || local {
				delLbl = "Удалить"
			}

			tiles = append(tiles, func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				return ui.subCard(gtx, ui.pal.card2, ui.pal.border, space1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontBody, ui.pal.text, font.Bold, fmt.Sprintf("%s  (list:%s)", title, id))
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, useBtn, "plus", "В правило…", false, "teal")
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, metaLine)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if errMsg == "" {
								return layout.Dimensions{}
							}
							return layout.Inset{Top: unit.Dp(2)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return ui.labelLine(gtx, fontSmall, ui.pal.warn, font.Normal, errMsg)
							})
						}),
						layout.Rigid(layout.Spacer{Height: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							var acts []layout.FlexChild
							if custom || local {
								acts = append(acts, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Right: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, editBtn, "edit", "Изменить", false, "")
									})
								}))
							}
							acts = append(acts,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Right: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return ui.iconButton(gtx, refBtn, "refresh", "Обновить", false, "")
									})
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.iconButton(gtx, delBtn, "trash", delLbl, false, "danger")
								}),
							)
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, acts...)
						}),
					)
				})
			})
		}

		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.grid(gtx, unit.Dp(320), 2, tiles)
		}))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	})
}

// loadFileIntoListEditor reads a local file specified in ui.listFilePathEditor into ui.listContentEditor.
func (ui *gioUI) loadFileIntoListEditor() {
	path := strings.Trim(strings.TrimSpace(ui.listFilePathEditor.Text()), `"'`)
	if path == "" {
		ui.setToast("Укажите путь к файлу для импорта", true)
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		ui.setToast("Не удалось прочитать файл: "+err.Error(), true)
		return
	}
	if len(b) > listMaxBytes {
		ui.setToast("Файл превышает 32 МБ", true)
		return
	}
	ui.listContentEditor.SetText(string(b))
	ui.setToast("Файл загружен в редактор — нажмите «Предпросмотр» или «Сохранить список»", false)
}


func (ui *gioUI) layoutListsStandaloneTab(gtx layout.Context) layout.Dimensions {
	sections := []layout.Widget{
		ui.layoutListsCatalogCard,
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return ui.mainList.Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				return sections[i](gtx)
			})
		}),
	)
}
