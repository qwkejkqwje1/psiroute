//go:build windows

package main

import (
	"fmt"
	"image"
	"image/color"
	"io"
	"strings"
	"time"

	"gioui.org/f32"
	"gioui.org/font"
	"gioui.org/io/clipboard"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// ---------- Drawing & Widget Helpers ----------

func fillRect(gtx layout.Context, size image.Point, radius int, fill color.NRGBA) {
	r := image.Rectangle{Max: size}
	rr := clip.UniformRRect(r, radius)
	paint.FillShape(gtx.Ops, fill, rr.Op(gtx.Ops))
}

func strokeRect(gtx layout.Context, size image.Point, radius int, width float32, stroke color.NRGBA) {
	r := image.Rectangle{Max: size}
	rr := clip.UniformRRect(r, radius)
	paint.FillShape(gtx.Ops, stroke, clip.Stroke{Path: rr.Path(gtx.Ops), Width: width}.Op())
}

func (ui *gioUI) card(gtx layout.Context, inset unit.Dp, content layout.Widget) layout.Dimensions {
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			rad := gtx.Dp(16)
			fillRect(gtx, gtx.Constraints.Min, rad, ui.pal.card)
			strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), ui.pal.border)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(inset).Layout(gtx, content)
		},
	)
}

func (ui *gioUI) subCard(gtx layout.Context, bg, borderCol color.NRGBA, inset unit.Dp, content layout.Widget) layout.Dimensions {
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			rad := gtx.Dp(8)
			fillRect(gtx, gtx.Constraints.Min, rad, bg)
			strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), borderCol)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(inset).Layout(gtx, content)
		},
	)
}

func (ui *gioUI) label(gtx layout.Context, size unit.Sp, col color.NRGBA, weight font.Weight, txt string) layout.Dimensions {
	l := material.Label(ui.th, size, privacyDisplay(txt, ui.privacyMode))
	l.Color = col
	l.Font.Weight = weight
	return l.Layout(gtx)
}

func (ui *gioUI) pillButton(gtx layout.Context, btn *widget.Clickable, txt string, active bool, style string) layout.Dimensions {
	return ui.iconButton(gtx, btn, "", txt, active, style)
}

// segRouteButton рисует компактную кнопку внутри сегмент-переключателя маршрута (Tactical Minimal):
// неактивные варианты отображаются спокойным приглушённым текстом без рамок, а выбранный маршрут
// или кнопка при наведении подсвечивается своим фирменным семантическим цветом.
func (ui *gioUI) segRouteButton(gtx layout.Context, btn *widget.Clickable, txt string, active bool, style string) layout.Dimensions {
	_, fg, _, solid := ui.styleColors(style)
	bg := color.NRGBA{}
	textCol := ui.pal.mut
	weight := font.Medium
	if active {
		bg = solid
		textCol = rgb(0xFFFFFF)
		weight = font.Bold
	} else if btn.Hovered() {
		bg = tint(solid, 38)
		textCol = fg
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				if bg.A > 0 {
					fillRect(gtx, gtx.Constraints.Min, gtx.Dp(6), bg)
				}
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4), Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontSmall, textCol, weight, txt)
				})
			},
		)
	})
}


func (ui *gioUI) flagButton(gtx layout.Context, btn *widget.Clickable, cc, txt string, active bool, style string) layout.Dimensions {
	bg, fg, bdr, solid := ui.styleColors(style)
	if active {
		bg, fg, bdr = solid, rgb(0xFFFFFF), solid
	}
	if btn.Hovered() {
		switch {
		case active || style == "primary":
			bg = mix(bg, rgb(0xFFFFFF), 0.12)
			bdr = bg
		case style == "":
			bg = ui.pal.hover
			bdr = tint(ui.pal.dim, 120)
		default:
			bdr = fg
		}
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				rad := gtx.Dp(8)
				fillRect(gtx, gtx.Constraints.Min, rad, bg)
				strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), bdr)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(8), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return drawCountryFlag(gtx, cc, unit.Dp(16), unit.Dp(11))
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontBody, fg, font.Medium, txt)
						}),
					)
				})
			},
		)
	})
}

func (ui *gioUI) styleColors(style string) (bg, fg, bdr, solid color.NRGBA) {
	switch style {
	case "primary":
		return ui.pal.acc, rgb(0xFFFFFF), ui.pal.acc, ui.pal.acc
	case "ok":
		return ui.pal.okSoft, ui.pal.ok, tint(ui.pal.ok, 70), ui.pal.ok
	case "danger":
		return ui.pal.errSoft, ui.pal.err, tint(ui.pal.err, 70), ui.pal.err
	case "vio":
		return ui.pal.vioSoft, ui.pal.vio, tint(ui.pal.vio, 70), ui.pal.vio
	case "teal":
		return ui.pal.tealSoft, ui.pal.teal, tint(ui.pal.teal, 70), ui.pal.teal
	case "warn":
		return ui.pal.warnSoft, ui.pal.warn, tint(ui.pal.warn, 70), ui.pal.warn
	}
	return ui.pal.card2, ui.pal.text, ui.pal.border, ui.pal.acc
}

func (ui *gioUI) iconButton(gtx layout.Context, btn *widget.Clickable, icon, txt string, active bool, style string) layout.Dimensions {
	bg, fg, bdr, solid := ui.styleColors(style)
	if active {
		bg, fg, bdr = solid, rgb(0xFFFFFF), solid
	}
	if btn.Hovered() {
		switch {
		case active || style == "primary":
			bg = mix(bg, rgb(0xFFFFFF), 0.12)
			bdr = bg
		case style == "":
			bg = ui.pal.hover
			bdr = tint(ui.pal.dim, 120)
		default:
			bdr = fg
		}
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				rad := gtx.Dp(8)
				fillRect(gtx, gtx.Constraints.Min, rad, bg)
				strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), bdr)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					if icon != "" && txt == "" {
						return drawIcon(gtx, icon, unit.Dp(15), fg)
					}
					lbl := func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontBody, fg, font.Medium, txt)
					}
					if icon == "" {
						return lbl(gtx)
					}
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return drawIcon(gtx, icon, unit.Dp(14), fg)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
						layout.Rigid(lbl),
					)
				})
			},
		)
	})
}

// emptyState renders a clear human-readable message with an optional action button.
func (ui *gioUI) emptyState(gtx layout.Context, icon, title, sub, btnTxt string, btn *widget.Clickable) layout.Dimensions {
	return ui.subCard(gtx, ui.pal.card2, ui.pal.border, space2, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.iconBadge(gtx, orDefault(icon, "search"), ui.pal.acc, ui.pal.accSoft, unit.Dp(32))
					}),
					layout.Rigid(layout.Spacer{Width: space2}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return ui.label(gtx, fontBody, ui.pal.text, font.SemiBold, title)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if sub == "" {
									return layout.Dimensions{}
								}
								return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, sub)
							}),
						)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if btn == nil || btnTxt == "" {
					return layout.Dimensions{}
				}
				return layout.Inset{Left: space2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, btn, btnTxt, false, "primary")
				})
			}),
		)
	})
}

func (ui *gioUI) pasteBtn(keyID string) *widget.Clickable {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	b := ui.pasteBtns[keyID]
	if b == nil {
		b = new(widget.Clickable)
		ui.pasteBtns[keyID] = b
	}
	return b
}

func (ui *gioUI) focusBtn(keyID string) *widget.Clickable {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	b := ui.focusBtns[keyID]
	if b == nil {
		b = new(widget.Clickable)
		ui.focusBtns[keyID] = b
	}
	return b
}

// editorBox оборачивает любое поле ввода material.Editor (Раздел 1.2 ТЗ):
//   - клик по рамке/отступам контейнера ставит фокус в поле ввода (key.FocusCmd{Tag: ed});
//   - при активном фокусе рамка подсвечивается цветом акцента (ui.pal.acc);
//   - справа выводится компактная кнопка «Вставить» (чтение из Win32 буфера обмена + фокус),
//     гарантирующая вставку текста при любой раскладке клавиатуры.
func (ui *gioUI) editorBox(gtx layout.Context, keyID string, ed *widget.Editor, hint string) layout.Dimensions {
	pBtn := ui.pasteBtn(keyID)
	fBtn := ui.focusBtn(keyID)
	if pBtn.Clicked(gtx) {
		gtx.Execute(key.FocusCmd{Tag: ed})
		if clipTxt := strings.TrimSpace(readClipboardText()); clipTxt != "" {
			if ed.SingleLine {
				clipTxt = strings.ReplaceAll(strings.ReplaceAll(clipTxt, "\r\n", " "), "\n", " ")
				cur := strings.TrimSpace(ed.Text())
				if cur == "" {
					ed.SetText(clipTxt)
				} else {
					ed.SetText(cur + ", " + clipTxt)
				}
			} else {
				cur := ed.Text()
				if cur == "" || strings.HasSuffix(cur, "\n") {
					ed.SetText(cur + clipTxt)
				} else {
					ed.SetText(cur + "\n" + clipTxt)
				}
			}
			ed.MoveCaret(ed.Len(), ed.Len())
			ui.setToast("Вставлено из буфера обмена", false)
		} else {
			gtx.Execute(clipboard.ReadCmd{Tag: ed})
		}
	}
	if fBtn.Clicked(gtx) {
		gtx.Execute(key.FocusCmd{Tag: ed})
	}
	bdr := ui.pal.border
	if gtx.Focused(ed) {
		bdr = ui.pal.acc
	}
	return ui.subCard(gtx, ui.pal.card2, bdr, unit.Dp(6), func(gtx layout.Context) layout.Dimensions {
		align := layout.Middle
		if !ed.SingleLine {
			align = layout.Start
		}
		return layout.Flex{Axis: layout.Horizontal, Alignment: align}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				_ = fBtn
				pointer.CursorText.Add(gtx.Ops)
				me := material.Editor(ui.th, ed, hint)
				me.Color = ui.pal.text
				me.HintColor = ui.pal.dim
				me.TextSize = fontBody
				return me.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.iconButton(gtx, pBtn, "copy", "Вставить", false, "")
			}),
		)
	})
}

func (ui *gioUI) searchBox(gtx layout.Context) layout.Dimensions {
	w := gtx.Dp(310)
	if w > gtx.Constraints.Max.X {
		w = gtx.Constraints.Max.X
	}
	gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
	gtx.Constraints.Min.Y = 0
	d := ui.editorBox(gtx, "app-search", &ui.appSearch, "Поиск (Ctrl+F): discord, chrome…")
	if q := ui.appSearch.Text(); q != ui.lastAppQ {
		ui.lastAppQ = q
		gtx.Execute(op.InvalidateCmd{})
	}
	return d
}

func emptyAppsMsg(q string) string {
	if q != "" {
		return "Ничего не найдено по запросу «" + q + "»"
	}
	return "Загрузка списка запущенных программ…"
}

func (ui *gioUI) routeBadge(gtx layout.Context, ob string) layout.Dimensions {
	bg, fg := ui.pal.card2, ui.pal.mut
	title := ob
	switch {
	case ob == obDirect || ob == "tun-exclude":
		bg, fg = ui.pal.okSoft, ui.pal.ok
		if ob == "tun-exclude" {
			title = "Напрямую (мимо TUN)"
		} else {
			title = "Напрямую"
		}
	case ob == obDesync:
		bg, fg = ui.pal.tealSoft, ui.pal.teal
		title = "Обход DPI"
	case ob == obWarp:
		bg, fg = ui.pal.warnSoft, ui.pal.warn
		title = "WARP"
	case ob == obPsiphon || strings.HasPrefix(ob, "psiphon:"):
		bg, fg = ui.pal.vioSoft, ui.pal.vio
		if ob == obPsiphon {
			title = "Psiphon VPN"
		} else {
			title = "Psiphon " + strings.ToUpper(ob[8:])
		}
	case ob == obBlock:
		bg, fg = ui.pal.errSoft, ui.pal.err
		title = "Блокировать"
	case ob == obAuto:
		bg, fg = ui.pal.accSoft, ui.pal.acc
		title = "Умный обход"
	case ob == "":
		title = "По общим правилам"
	}
	flagCC := ""
	if strings.HasPrefix(ob, "psiphon:") && len(ob) > 8 {
		flagCC = ob[8:]
	}
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fillRect(gtx, gtx.Constraints.Min, gtx.Dp(6), bg)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4), Left: space1, Right: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				if flagCC == "" {
					return ui.label(gtx, fontSmall, fg, font.SemiBold, title)
				}
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return drawCountryFlag(gtx, flagCC, unit.Dp(15), unit.Dp(10))
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.label(gtx, fontSmall, fg, font.SemiBold, title)
					}),
				)
			})
		},
	)
}

// ---------- Layout primitives (8dp grid + <900px responsive) ----------

func flowWrap(gtx layout.Context, gapX, gapY unit.Dp, children ...layout.Widget) layout.Dimensions {
	maxW := gtx.Constraints.Max.X
	gx, gy := gtx.Dp(gapX), gtx.Dp(gapY)
	cgtx := gtx
	cgtx.Constraints.Min = image.Point{}
	type placed struct {
		call op.CallOp
		size image.Point
	}
	items := make([]placed, 0, len(children))
	for _, w := range children {
		m := op.Record(gtx.Ops)
		d := w(cgtx)
		items = append(items, placed{call: m.Stop(), size: d.Size})
	}
	x, y, rowH, width := 0, 0, 0, 0
	for _, it := range items {
		if x > 0 && x+it.size.X > maxW {
			x = 0
			y += rowH + gy
			rowH = 0
		}
		st := op.Offset(image.Pt(x, y)).Push(gtx.Ops)
		it.call.Add(gtx.Ops)
		st.Pop()
		if x+it.size.X > width {
			width = x + it.size.X
		}
		x += it.size.X + gx
		if it.size.Y > rowH {
			rowH = it.size.Y
		}
	}
	if width < gtx.Constraints.Min.X {
		width = gtx.Constraints.Min.X
	}
	return layout.Dimensions{Size: image.Pt(width, y+rowH)}
}

func (ui *gioUI) grid(gtx layout.Context, minCell unit.Dp, maxCols int, items []layout.Widget) layout.Dimensions {
	cell := gtx.Dp(minCell)
	if cell < 1 {
		cell = 1
	}
	cols := gtx.Constraints.Max.X / cell
	if cols < 1 {
		cols = 1
	}
	if cols > maxCols {
		cols = maxCols
	}
	var rows []layout.FlexChild
	for start := 0; start < len(items); start += cols {
		s := start
		if s > 0 {
			rows = append(rows, layout.Rigid(layout.Spacer{Height: space1}.Layout))
		}
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			var cells []layout.FlexChild
			for c := 0; c < cols; c++ {
				if c > 0 {
					cells = append(cells, layout.Rigid(layout.Spacer{Width: space1}.Layout))
				}
				idx := s + c
				if idx < len(items) {
					cells = append(cells, layout.Flexed(1, items[idx]))
				} else {
					cells = append(cells, layout.Flexed(1, layout.Spacer{}.Layout))
				}
			}
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, cells...)
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
}

// twoCol places two columns side by side, or stacks the right column under the
// left column when the window width is under 900dp (content width < 820dp).
func (ui *gioUI) twoCol(gtx layout.Context, lw, rw float32, left, right layout.Widget) layout.Dimensions {
	if gtx.Constraints.Max.X < gtx.Dp(600) {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(left),
			layout.Rigid(layout.Spacer{Height: space2}.Layout),
			layout.Rigid(right),
		)
	}
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Flexed(lw, left),
		layout.Rigid(layout.Spacer{Width: space2}.Layout),
		layout.Flexed(rw, right),
	)
}

func fillGradient(gtx layout.Context, size image.Point, radius int, c1, c2 color.NRGBA) {
	defer clip.UniformRRect(image.Rectangle{Max: size}, radius).Push(gtx.Ops).Pop()
	paint.LinearGradientOp{
		Stop1:  f32.Pt(0, 0),
		Color1: c1,
		Stop2:  f32.Pt(float32(size.X), float32(size.Y)),
		Color2: c2,
	}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)
}

func dotWidget(gtx layout.Context, d unit.Dp, col color.NRGBA) layout.Dimensions {
	s := gtx.Dp(d)
	paint.FillShape(gtx.Ops, col, clip.Ellipse{Max: image.Pt(s, s)}.Op(gtx.Ops))
	return layout.Dimensions{Size: image.Pt(s, s)}
}

func (ui *gioUI) labelLine(gtx layout.Context, size unit.Sp, col color.NRGBA, weight font.Weight, txt string) layout.Dimensions {
	l := material.Label(ui.th, size, privacyDisplay(txt, ui.privacyMode))
	l.Color = col
	l.Font.Weight = weight
	l.MaxLines = 1
	return l.Layout(gtx)
}

func (ui *gioUI) monoLabel(gtx layout.Context, size unit.Sp, col color.NRGBA, txt string) layout.Dimensions {
	l := material.Label(ui.th, size, privacyDisplay(txt, ui.privacyMode))
	l.Color = col
	l.Font.Typeface = "Go Mono"
	l.MaxLines = 1
	return l.Layout(gtx)
}

func (ui *gioUI) caption(gtx layout.Context, txt string) layout.Dimensions {
	return ui.labelLine(gtx, fontSmall, ui.pal.dim, font.Bold, strings.ToUpper(txt))
}

func (ui *gioUI) divider(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: space1, Bottom: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		sz := image.Pt(gtx.Constraints.Max.X, gtx.Dp(1))
		paint.FillShape(gtx.Ops, ui.pal.border, clip.Rect{Max: sz}.Op())
		return layout.Dimensions{Size: sz}
	})
}

func (ui *gioUI) iconBadge(gtx layout.Context, icon string, fg, bg color.NRGBA, size unit.Dp) layout.Dimensions {
	s := gtx.Dp(size)
	sz := image.Pt(s, s)
	fillRect(gtx, sz, s*3/10, bg)
	is := gtx.Dp(size * 0.55)
	off := (s - is) / 2
	t := op.Offset(image.Pt(off, off)).Push(gtx.Ops)
	drawIcon(gtx, icon, size*0.55, fg)
	t.Pop()
	return layout.Dimensions{Size: sz}
}

func (ui *gioUI) cardHeader(gtx layout.Context, icon, title, sub string, right layout.Widget) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return ui.iconBadge(gtx, icon, ui.pal.acc, ui.pal.accSoft, unit.Dp(32))
		}),
		layout.Rigid(layout.Spacer{Width: space1}.Layout),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.labelLine(gtx, fontTitle, ui.pal.text, font.Bold, title)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if sub == "" {
						return layout.Dimensions{}
					}
					return ui.label(gtx, fontSmall, ui.pal.mut, font.Normal, sub)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if right == nil {
				return layout.Dimensions{}
			}
			return layout.Inset{Left: space1}.Layout(gtx, right)
		}),
	)
}

func (ui *gioUI) heroCard(gtx layout.Context, accent color.NRGBA, content layout.Widget) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			rad := gtx.Dp(16)
			sz := gtx.Constraints.Min
			fillGradient(gtx, sz, rad, mix(ui.pal.card, accent, 0.14), ui.pal.card)
			strokeRect(gtx, sz, rad, float32(gtx.Dp(1)), mix(ui.pal.border, accent, 0.35))
			return layout.Dimensions{Size: sz}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(space2).Layout(gtx, content)
		},
	)
}

func (ui *gioUI) statusPill(gtx layout.Context, pState string) layout.Dimensions {
	col := ui.statusColor(pState)
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fillRect(gtx, gtx.Constraints.Min, gtx.Constraints.Min.Y/2, tint(col, 36))
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: space1, Right: space2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return dotWidget(gtx, unit.Dp(8), col)
					}),
					layout.Rigid(layout.Spacer{Width: space1}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontSmall, col, font.SemiBold, stateTitle(pState))
					}),
				)
			})
		},
	)
}

func (ui *gioUI) drawSwitch(gtx layout.Context, on bool) layout.Dimensions {
	w, h := gtx.Dp(36), gtx.Dp(20)
	track := ui.pal.hover
	if on {
		track = ui.pal.ok
	}
	paint.FillShape(gtx.Ops, track, clip.UniformRRect(image.Rect(0, 0, w, h), h/2).Op(gtx.Ops))
	if !on {
		strokeRect(gtx, image.Pt(w, h), h/2, float32(gtx.Dp(1)), ui.pal.border)
	}
	k := gtx.Dp(14)
	pad := (h - k) / 2
	x := pad
	if on {
		x = w - pad - k
	}
	knob := rgb(0xFFFFFF)
	if !on && ui.pal.dark {
		knob = ui.pal.mut
	}
	paint.FillShape(gtx.Ops, knob, clip.Ellipse{Min: image.Pt(x, pad), Max: image.Pt(x+k, pad+k)}.Op(gtx.Ops))
	return layout.Dimensions{Size: image.Pt(w, h)}
}

func (ui *gioUI) switchButton(gtx layout.Context, btn *widget.Clickable, on bool) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		return ui.drawSwitch(gtx, on)
	})
}

func (ui *gioUI) switchTile(gtx layout.Context, btn *widget.Clickable, icon, title, sub string, on bool) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		bg, bdr := ui.pal.card2, ui.pal.border
		icFg, icBg := ui.pal.mut, ui.pal.hover
		if on {
			bg = mix(ui.pal.card2, ui.pal.ok, 0.08)
			bdr = tint(ui.pal.ok, 110)
			icFg, icBg = ui.pal.ok, ui.pal.okSoft
		}
		if btn.Hovered() {
			bg = mix(bg, ui.pal.hover, 0.6)
			bdr = tint(ui.pal.acc, 150)
		}
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				rad := gtx.Dp(8)
				fillRect(gtx, gtx.Constraints.Min, rad, bg)
				strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), bdr)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(space1).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.iconBadge(gtx, icon, icFg, icBg, unit.Dp(28))
						}),
						layout.Rigid(layout.Spacer{Width: space1}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontBody, ui.pal.text, font.SemiBold, title)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, sub)
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Width: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.drawSwitch(gtx, on)
						}),
					)
				})
			},
		)
	})
}

func (ui *gioUI) segmented(gtx layout.Context, btns []*widget.Clickable, labels []string, active int) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			rad := gtx.Dp(8)
			fillRect(gtx, gtx.Constraints.Min, rad, ui.pal.card2)
			strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), ui.pal.border)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				var ch []layout.FlexChild
				for i := range btns {
					idx := i
					if idx > 0 {
						ch = append(ch, layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout))
					}
					ch = append(ch, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.X = gtx.Constraints.Max.X
						b := btns[idx]
						on := idx == active
						return b.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							pointer.CursorPointer.Add(gtx.Ops)
							fg := ui.pal.mut
							var bg color.NRGBA
							if on {
								fg, bg = rgb(0xFFFFFF), ui.pal.acc
							} else if b.Hovered() {
								fg, bg = ui.pal.text, ui.pal.hover
							}
							return layout.Background{}.Layout(gtx,
								func(gtx layout.Context) layout.Dimensions {
									if bg.A > 0 {
										fillRect(gtx, gtx.Constraints.Min, gtx.Dp(6), bg)
									}
									return layout.Dimensions{Size: gtx.Constraints.Min}
								},
								func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(6), Right: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return ui.labelLine(gtx, fontBody, fg, font.SemiBold, labels[idx])
										})
									})
								},
							)
						})
					}))
				}
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, ch...)
			})
		},
	)
}

func (ui *gioUI) metricPill(gtx layout.Context, title, val string) layout.Dimensions {
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			rad := gtx.Dp(8)
			fillRect(gtx, gtx.Constraints.Min, rad, ui.pal.card2)
			strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), ui.pal.border)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: space1, Right: space2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontSmall, ui.pal.dim, font.Medium, title)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontBody, ui.pal.text, font.Bold, val)
					}),
				)
			})
		},
	)
}

func (ui *gioUI) avatar(gtx layout.Context, name, route string) layout.Dimensions {
	col := ui.routeColor(route)
	s := gtx.Dp(32)
	sz := image.Pt(s, s)
	fillRect(gtx, sz, gtx.Dp(8), tint(col, 40))
	letter := "?"
	if r := []rune(strings.TrimSpace(name)); len(r) > 0 {
		letter = strings.ToUpper(string(r[0]))
	}
	gtx.Constraints = layout.Exact(sz)
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return ui.label(gtx, fontBody, col, font.Bold, letter)
	})
}

// ---------- Copy to clipboard ----------

func (ui *gioUI) copyBtn(key string) *widget.Clickable {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	b := ui.copyBtns[key]
	if b == nil {
		b = new(widget.Clickable)
		ui.copyBtns[key] = b
	}
	return b
}

func (ui *gioUI) copyText(gtx layout.Context, key, val string) {
	if val == "" {
		return
	}
	writeClipboardText(val)
	gtx.Execute(clipboard.WriteCmd{Type: "application/text", Data: io.NopCloser(strings.NewReader(val))})
	ui.mu.Lock()
	ui.copiedKey = key
	ui.copiedAt = time.Now()
	ui.mu.Unlock()
	ui.setToast("Скопировано в буфер обмена: "+val, false)
}

func (ui *gioUI) isCopied(key string) bool {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	return ui.copiedKey == key && time.Since(ui.copiedAt) < 2500*time.Millisecond
}

func (ui *gioUI) copyRow(gtx layout.Context, key, title, val string) layout.Dimensions {
	btn := ui.copyBtn(key)
	if btn.Clicked(gtx) {
		ui.copyText(gtx, key, val)
	}
	copied := ui.isCopied(key)
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		bg, bdr := ui.pal.card2, ui.pal.border
		if btn.Hovered() {
			bg, bdr = ui.pal.hover, tint(ui.pal.acc, 150)
		}
		if copied {
			bdr = ui.pal.ok
		}
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				rad := gtx.Dp(8)
				fillRect(gtx, gtx.Constraints.Min, rad, bg)
				strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), bdr)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: space1, Bottom: space1, Left: space2, Right: space2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							w := gtx.Dp(128)
							if w > gtx.Constraints.Max.X/3 {
								w = gtx.Constraints.Max.X / 3
							}
							gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
							return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Medium, title)
						}),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return ui.monoLabel(gtx, fontBody, ui.pal.text, val)
						}),
						layout.Rigid(layout.Spacer{Width: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							ic, txt, col := "copy", "Копировать", ui.pal.acc
							if copied {
								ic, txt, col = "check", "Скопировано", ui.pal.ok
							}
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return drawIcon(gtx, ic, unit.Dp(14), col)
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(5)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.labelLine(gtx, fontSmall, col, font.SemiBold, txt)
								}),
							)
						}),
					)
				})
			},
		)
	})
}

func (ui *gioUI) copyChip(gtx layout.Context, key, title, val string) layout.Dimensions {
	btn := ui.copyBtn(key)
	if btn.Clicked(gtx) {
		ui.copyText(gtx, key, val)
	}
	copied := ui.isCopied(key)
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		pointer.CursorPointer.Add(gtx.Ops)
		bg, bdr := ui.pal.card2, ui.pal.border
		if btn.Hovered() {
			bg, bdr = ui.pal.hover, tint(ui.pal.acc, 150)
		}
		ic, icCol := "copy", ui.pal.acc
		if copied {
			bdr, ic, icCol = ui.pal.ok, "check", ui.pal.ok
		}
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				rad := gtx.Dp(8)
				fillRect(gtx, gtx.Constraints.Min, rad, bg)
				strokeRect(gtx, gtx.Constraints.Min, rad, float32(gtx.Dp(1)), bdr)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: space1, Right: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Medium, title)
						}),
						layout.Rigid(layout.Spacer{Width: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.monoLabel(gtx, fontBody, ui.pal.text, val)
						}),
						layout.Rigid(layout.Spacer{Width: space1}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return drawIcon(gtx, ic, unit.Dp(13), icCol)
						}),
					)
				})
			},
		)
	})
}

// ---------- Shared control groups ----------

func (ui *gioUI) favoriteCountriesList() []string {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()
	if st != nil {
		if arr, ok := st["favorite_countries"].([]any); ok && len(arr) > 0 {
			out := make([]string, 0, len(arr))
			for _, it := range arr {
				if s, ok := it.(string); ok && len(s) == 2 {
					out = append(out, strings.ToUpper(s))
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return []string{"DE", "NL", "US", "FI", "GB"}
}

func (ui *gioUI) isFavoriteCountry(cc string) bool {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if cc == "" || cc == "AUTO" {
		return false
	}
	for _, f := range ui.favoriteCountriesList() {
		if f == cc {
			return true
		}
	}
	return false
}

func nativeCountryIndex(cc string) int {
	for i, c := range nativeCountries {
		if strings.EqualFold(c, cc) {
			return i
		}
	}
	return -1
}

// countryChips рендерит все 28 стран выхода с кнопкой-звёздочкой (★/☆) для добавления в избранное (Раздел 4.1 ТЗ).
func (ui *gioUI) countryChips(gtx layout.Context, cfgReg string) layout.Dimensions {
	var ws []layout.Widget
	for i := 0; i < len(nativeCountries) && i < len(ui.countryBtns); i++ {
		idx := i
		cc := nativeCountries[idx]
		active := strings.EqualFold(cfgReg, cc) || (cfgReg == "" && (cc == "" || cc == "auto"))
		isFav := ui.isFavoriteCountry(cc)
		ws = append(ws, func(gtx layout.Context) layout.Dimensions {
			if cc == "" || cc == "auto" {
				return ui.flagButton(gtx, &ui.countryBtns[idx], cc, nativeCountryNames[idx], active, "")
			}
			starTxt := "☆"
			starStyle := ""
			if isFav {
				starTxt = "★"
				starStyle = "teal"
			}
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.flagButton(gtx, &ui.countryBtns[idx], cc, nativeCountryNames[idx], active, "")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(2)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.pillButton(gtx, &ui.favStarBtns[idx], starTxt, isFav, starStyle)
				}),
			)
		})
	}
	return flowWrap(gtx, space1, space1, ws...)
}

// favoriteCountryChips рендерит только избранные страны пользователя для быстрого переключения (Раздел 4.1 ТЗ).
func (ui *gioUI) favoriteCountryChips(gtx layout.Context, cfgReg string) layout.Dimensions {
	favs := ui.favoriteCountriesList()
	var ws []layout.Widget
	ws = append(ws, func(gtx layout.Context) layout.Dimensions {
		active := cfgReg == "" || strings.EqualFold(cfgReg, "auto")
		return ui.flagButton(gtx, &ui.favCountryBtns[0], "", "Авто (лучшая)", active, "")
	})
	for _, cc := range favs {
		idx := nativeCountryIndex(cc)
		if idx <= 0 || idx >= len(ui.favCountryBtns) {
			continue
		}
		active := strings.EqualFold(cfgReg, cc)
		ws = append(ws, func(gtx layout.Context) layout.Dimensions {
			return ui.flagButton(gtx, &ui.favCountryBtns[idx], cc, "★ "+nativeCountryNames[idx], active, "")
		})
	}
	return flowWrap(gtx, space1, space1, ws...)
}

// compactCountryRow на Главной отображает «Авто (лучшая)», избранные страны пользователя и «Все страны (28) →».
func (ui *gioUI) compactCountryRow(gtx layout.Context, cfgReg string) layout.Dimensions {
	favs := ui.favoriteCountriesList()
	var ws []layout.Widget
	ws = append(ws, func(gtx layout.Context) layout.Dimensions {
		active := cfgReg == "" || strings.EqualFold(cfgReg, "auto")
		return ui.flagButton(gtx, &ui.favCountryBtns[0], "", "Авто (лучшая)", active, "")
	})
	shown := 0
	for _, cc := range favs {
		if shown >= 6 {
			break
		}
		idx := nativeCountryIndex(cc)
		if idx <= 0 || idx >= len(ui.favCountryBtns) {
			continue
		}
		shown++
		lbl := cnameShort(cc)
		active := strings.EqualFold(cfgReg, cc)
		ws = append(ws, func(gtx layout.Context) layout.Dimensions {
			return ui.flagButton(gtx, &ui.favCountryBtns[idx], cc, lbl, active, "")
		})
	}
	ws = append(ws, func(gtx layout.Context) layout.Dimensions {
		return ui.pillButton(gtx, &ui.allCountriesBtn, fmt.Sprintf("Все страны (%d) →", len(nativeCountries)-1), false, "")
	})
	return flowWrap(gtx, space1, space1, ws...)
}

func (ui *gioUI) dpiChips(gtx layout.Context, dpiMode string) layout.Dimensions {
	var ws []layout.Widget
	for i := 0; i < len(nativeDPIModes) && i < len(ui.dpiModeBtns); i++ {
		idx := i
		active := dpiMode == nativeDPIModes[idx]
		ws = append(ws, func(gtx layout.Context) layout.Dimensions {
			return ui.pillButton(gtx, &ui.dpiModeBtns[idx], nativeDPINames[idx], active, "teal")
		})
	}
	return flowWrap(gtx, space1, space1, ws...)
}

func (ui *gioUI) toggleTile(st map[string]any, key string) layout.Widget {
	b := func(k string) bool {
		v, _ := st[k].(bool)
		return v
	}
	tile := func(btn *widget.Clickable, icon, title, sub string, on bool) layout.Widget {
		return func(gtx layout.Context) layout.Dimensions {
			return ui.switchTile(gtx, btn, icon, title, sub, on)
		}
	}
	switch key {
	case "sysproxy":
		return tile(&ui.sysProxyBtn, "globe", "Системный прокси", "браузеры и программы Windows", b("sysproxy"))
	case "tun":
		tunMap, _ := st["tun"].(map[string]any)
		on, _ := tunMap["on"].(bool)
		txt, _ := tunMap["text"].(string)
		return tile(&ui.tunBtn, "shield", "Режим TUN", orDefault(txt, "весь трафик компьютера"), on)
	case "warp":
		warpMap, _ := st["warp"].(map[string]any)
		txt, _ := warpMap["text"].(string)
		return tile(&ui.warpBtn, "bolt", "Cloudflare WARP", orDefault(txt, "WireGuard / MASQUE"), b("warp_on"))
	case "kill":
		return tile(&ui.killSwitchBtn, "lock", "Kill Switch", "защита при обрыве VPN", b("kill_switch"))
	case "doh":
		return tile(&ui.dohBtn, "lock", "Шифрованный DNS", "DoH + ECH · 1.1.1.1 / 8.8.8.8", b("dns_on"))
	case "localdns":
		addr, _ := st["local_dns_addr"].(string)
		return tile(&ui.localDNSBtn, "route", "Локальный DNS-сервер", orDefault(addr, "127.0.0.1:5353"), b("local_dns_on"))
	case "fakeip":
		cnt, _ := st["fakeip_count"].(float64)
		return tile(&ui.fakeIPBtn, "apps", "FakeIP", fmt.Sprintf("198.18.0.0/15 · доменов: %.0f", cnt), b("fake_ip"))
	case "quic":
		return tile(&ui.blockQUICBtn, "stop", "Блокировать QUIC", "перевод браузеров на TCP + DPI", b("block_quic"))
	case "stun":
		return tile(&ui.blockSTUNBtn, "shield", "Защита WebRTC", "блокировка утечки IP через STUN", b("block_stun"))
	case "lan":
		return tile(&ui.bypassLANBtn, "lan", "Локальная сеть напрямую", "роутер, принтер, NAS — без VPN", b("bypass_lan"))
	case "share":
		return tile(&ui.shareBtn, "lan", "Раздача в сеть (LAN)", "прокси для телефона и ТВ", b("share_on"))
	case "single":
		return tile(&ui.singleProcBtn, "chart", "Страны в одном процессе", "экономия ~25 МБ ОЗУ", b("single_process_countries"))
	}
	return func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }
}

func (ui *gioUI) toggleTiles(st map[string]any, keys ...string) []layout.Widget {
	out := make([]layout.Widget, 0, len(keys))
	for _, k := range keys {
		out = append(out, ui.toggleTile(st, k))
	}
	return out
}

func (ui *gioUI) maintenanceButtons(gtx layout.Context, withQuit bool) layout.Dimensions {
	ws := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.selftestBtn, "check", "Самопроверка", false, "primary")
		},
		func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.dpiTestBtn, "play", "Тест методов DPI", false, "")
		},
		func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.clearDNSBtn, "refresh", "Сбросить кэш DNS", false, "")
		},
		func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.warpReconnBtn, "refresh", "Новый поток WARP", false, "")
		},
		func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.stopCountryBtn, "stop", "Остановить процессы стран", false, "")
		},
		func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.refreshListBtn, "download", "Обновить списки", false, "")
		},
		func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.clearLearnBtn, "swap", "Забыть выученные маршруты", false, "")
		},
		func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.reportBtn, "download", "Отчёт (.zip)", false, "")
		},
	}
	if withQuit {
		ws = append(ws, func(gtx layout.Context) layout.Dimensions {
			return ui.iconButton(gtx, &ui.quitBtn, "power", "Выйти из Psiroute", false, "danger")
		})
	}
	return flowWrap(gtx, space1, space1, ws...)
}

// ---------- Main Layout & Responsive Sidebar ----------

func (ui *gioUI) Layout(gtx layout.Context) layout.Dimensions {
	ui.applyPendingUIUpdates()
	ui.narrowWindow = gtx.Constraints.Max.X < gtx.Dp(1020)
	paint.Fill(gtx.Ops, ui.pal.bg)

	// ВАЖНО (Исправление бага с неработающими кликами в Gio v0.9):
	// 1. Сначала регистрируем глобальные хоткеи внутри pointer.PassOp{} ДО дерева виджетов,
	//    чтобы тег &ui.keyTag НИКОГДА не перекрывал мышиный hit-test кнопок поверх окна.
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()
	psi, _ := st["psiphon"].(map[string]any)
	pState, _ := psi["state"].(string)
	ui.handleHotkeys(gtx, pState)

	// 2. Обрабатываем клики по всем кнопкам ДО и ПОСЛЕ построения дерева виджетов,
	//    чтобы ни одно нажатие не терялось между кадрами.
	ui.handleEvents(gtx)

	sideW := unit.Dp(196)
	if ui.narrowWindow {
		sideW = unit.Dp(64)
	}

	dims := layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			w := gtx.Dp(sideW)
			gtx.Constraints.Min.X = w
			gtx.Constraints.Max.X = w
			return ui.layoutSidebar(gtx, ui.narrowWindow)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: space2, Right: space2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(ui.layoutPageHeader),
					layout.Rigid(ui.layoutToastBanner),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						switch ui.tab {
						case 0:
							return ui.layoutHomeTab(gtx)
						case 1:
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.layoutSubTabBar(gtx, 1, []string{"Умные правила (Приоритеты 1–4)", "Программы (Split Tunneling)", "Каталог списков и пресетов"})
								}),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									switch ui.subTabs[1] {
									case 1:
										return ui.layoutAppsTab(gtx)
									case 2:
										return ui.layoutListsStandaloneTab(gtx)
									default:
										return ui.layoutRulesTab(gtx)
									}
								}),
							)
						case 2:
							// Вкладка «Потоки» активна ТОЛЬКО когда пользователь нажал на неё (ui.tab == 2)
							return ui.layoutStreamsTab(gtx)
						case 3:
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.layoutSubTabBar(gtx, 3, []string{"Страны, обход DPI и WARP", "Раздача в LAN и устройства"})
								}),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									if ui.subTabs[3] == 1 {
										return ui.layoutDevicesTab(gtx)
									}
									return ui.layoutCountriesDPITab(gtx)
								}),
							)
						default:
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return ui.layoutSubTabBar(gtx, 4, []string{"Живой журнал событий", "Настройки сети, DNS и защиты", "Самопроверка и диагностика сайта"})
								}),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									switch ui.subTabs[4] {
									case 1:
										return ui.layoutSettingsOnlyTab(gtx)
									case 2:
										return ui.layoutTrafficDiagTab(gtx)
									default:
										return ui.layoutLiveLogOnlyTab(gtx)
									}
								}),
							)
						}
					}),
				)
			})
		}),
	)
	return dims
}

func (ui *gioUI) layoutPageHeader(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()
	psi, _ := st["psiphon"].(map[string]any)
	pState, _ := psi["state"].(string)
	if pState == "" {
		pState = "stopped"
	}
	listen, _ := st["listen"].(string)
	host, port := proxyHostPort(listen)
	tab := ui.tab
	if tab < 0 || tab >= len(navTitles) {
		tab = 0
	}
	return layout.Inset{Bottom: space2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontHero, ui.pal.text, font.Bold, navTitles[tab])
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontSmall, ui.pal.mut, font.Normal, navHints[tab])
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.subCard(gtx, ui.pal.accSoft, tint(ui.pal.acc, 90), unit.Dp(6), func(gtx layout.Context) layout.Dimensions {
					return ui.monoLabel(gtx, fontSmall, ui.pal.acc, "PsiRoute v"+version)
				})
			}),
			layout.Rigid(layout.Spacer{Width: space1}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.statusPill(gtx, pState)
			}),
			layout.Rigid(layout.Spacer{Width: space1}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.copyChip(gtx, "hdr", "Прокси", host+":"+port)
			}),
			layout.Rigid(layout.Spacer{Width: space1}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				thmLbl := "Тема: Obsidian"
				thmStyle := ""
				if ui.pal.themeID == "cyber-amber" {
					thmLbl = "Тема: Cyber-Amber"
					thmStyle = "warn"
				}
				return ui.pillButton(gtx, &ui.themeToggleBtn, thmLbl, ui.pal.themeID == "cyber-amber", thmStyle)
			}),
			layout.Rigid(layout.Spacer{Width: space1}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := "Чистый экран"
				if ui.privacyMode {
					lbl = "IP скрыты ●"
				}
				return ui.pillButton(gtx, &ui.privacyBtn, lbl, ui.privacyMode, "teal")
			}),
			layout.Rigid(layout.Spacer{Width: space1}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return ui.iconButton(gtx, &ui.webBtn, "globe", "Веб-панель", false, "")
			}),
		)
	})
}

func (ui *gioUI) layoutSidebar(gtx layout.Context, collapsed bool) layout.Dimensions {
	fillRect(gtx, image.Point{X: gtx.Constraints.Max.X, Y: gtx.Constraints.Max.Y}, 0, ui.pal.side)
	bdrRect := image.Rect(gtx.Constraints.Max.X-gtx.Dp(1), 0, gtx.Constraints.Max.X, gtx.Constraints.Max.Y)
	paint.FillShape(gtx.Ops, ui.pal.border, clip.Rect(bdrRect).Op())

	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()

	pState := "stopped"
	reg := ""
	var spDown, spUp, memTot, memApp float64
	tunOn, warpOn := false, false
	if st != nil {
		if psi, ok := st["psiphon"].(map[string]any); ok {
			if s, ok := psi["state"].(string); ok && s != "" {
				pState = s
			}
			reg, _ = psi["egress_region"].(string)
		}
		if stats, ok := st["stats"].(map[string]any); ok {
			if spd, ok := stats["speed"].(map[string]any); ok {
				spDown, _ = spd["down"].(float64)
				spUp, _ = spd["up"].(float64)
			}
		}
		if mem, ok := st["mem"].(map[string]any); ok {
			memTot, _ = mem["total"].(float64)
			memApp, _ = mem["app"].(float64)
		}
		if tm, ok := st["tun"].(map[string]any); ok {
			tunOn, _ = tm["on"].(bool)
		}
		warpOn, _ = st["warp_on"].(bool)
	}
	stCol := ui.statusColor(pState)

	navGroups := []struct {
		title string
		tabs  []int
	}{
		{"КОМАНДНЫЙ ЦЕНТР", []int{0}},
		{"МАРШРУТИЗАЦИЯ", []int{1, 2}},
		{"СЕТЬ И СИСТЕМА", []int{3, 4}},
	}

	renderNavItem := func(idx int) layout.FlexChild {
		return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Bottom: unit.Dp(3)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				active := ui.tab == idx
				bg := color.NRGBA{}
				fg := ui.pal.mut
				w := font.Medium
				if active {
					bg, fg, w = ui.pal.accSoft, ui.pal.acc, font.SemiBold
				} else if ui.navBtns[idx].Hovered() {
					bg, fg = ui.pal.hover, ui.pal.text
				}
				return ui.navBtns[idx].Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					pointer.CursorPointer.Add(gtx.Ops)
					return layout.Background{}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							if bg.A > 0 {
								fillRect(gtx, gtx.Constraints.Min, gtx.Dp(8), bg)
							}
							if active && gtx.Constraints.Min.Y > gtx.Dp(16) {
								bar := image.Rect(0, gtx.Dp(7), gtx.Dp(3), gtx.Constraints.Min.Y-gtx.Dp(7))
								paint.FillShape(gtx.Ops, ui.pal.acc, clip.UniformRRect(bar, gtx.Dp(2)).Op(gtx.Ops))
							}
							return layout.Dimensions{Size: gtx.Constraints.Min}
						},
						func(gtx layout.Context) layout.Dimensions {
							gtx.Constraints.Min.X = gtx.Constraints.Max.X
							return layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7), Left: unit.Dp(12), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								if collapsed {
									return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return drawIcon(gtx, navIcons[idx], unit.Dp(18), fg)
									})
								}
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return drawIcon(gtx, navIcons[idx], unit.Dp(16), fg)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontBody, fg, w, navTitles[idx])
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if idx == 0 {
											return dotWidget(gtx, unit.Dp(7), stCol)
										}
										return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Normal, fmt.Sprintf("^%d", idx+1))
									}),
								)
							})
						},
					)
				})
			})
		})
	}

	return layout.UniformInset(space1).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		var navChildren []layout.FlexChild
		for gi, grp := range navGroups {
			if !collapsed {
				gTitle := grp.title
				topPad := unit.Dp(10)
				if gi == 0 {
					topPad = unit.Dp(2)
				}
				navChildren = append(navChildren, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: topPad, Bottom: unit.Dp(4), Left: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Bold, gTitle)
					})
				}))
			} else if gi > 0 {
				navChildren = append(navChildren, layout.Rigid(ui.divider))
			}
			for _, tabIdx := range grp.tabs {
				navChildren = append(navChildren, renderNavItem(tabIdx))
			}
		}

		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// Brand Header
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Bottom: space2, Left: space1, Top: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							s := gtx.Dp(34)
							sz := image.Pt(s, s)
							fillGradient(gtx, sz, gtx.Dp(9), ui.pal.acc, ui.pal.vio)
							is := gtx.Dp(18)
							t := op.Offset(image.Pt((s-is)/2, (s-is)/2)).Push(gtx.Ops)
							drawIcon(gtx, "shield", unit.Dp(18), rgb(0xFFFFFF))
							t.Pop()
							return layout.Dimensions{Size: sz}
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if collapsed {
								return layout.Dimensions{}
							}
							return layout.Inset{Left: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontTitle, ui.pal.text, font.Bold, "PsiRoute")
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return ui.labelLine(gtx, fontSmall, ui.pal.acc, font.Bold, "Версия v"+version+" · PORTABLE")
									}),
								)
							})
						}),
					)
				})
			}),
			// Grouped Navigation
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, navChildren...)
			}),
			layout.Flexed(1, layout.Spacer{}.Layout),
			// Compact System Health Card at Sidebar Footer
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if collapsed {
					return layout.Dimensions{}
				}
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				return ui.subCard(gtx, ui.pal.card2, ui.pal.border, unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
					badges := []string{"Psiphon"}
					if tunOn {
						badges = append(badges, "TUN")
					}
					if warpOn {
						badges = append(badges, "WARP")
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return dotWidget(gtx, unit.Dp(7), stCol)
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return ui.labelLine(gtx, fontSmall, stCol, font.Bold, stateTitle(pState))
										}),
									)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if reg == "" {
										return layout.Dimensions{}
									}
									return ui.labelLine(gtx, fontSmall, ui.pal.text, font.Bold, cnameShort(reg))
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontMicro, ui.pal.mut, font.Normal,
								fmt.Sprintf("↓ %s · ↑ %s", fmtSpeed(spDown), fmtSpeed(spUp)))
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.labelLine(gtx, fontMicro, ui.pal.dim, font.Normal,
								fmt.Sprintf("ОЗУ: %.0f МБ (ядро %.0f) · %s", memTot/1048576, memApp/1048576, strings.Join(badges, " + ")))
						}),
					)
				})
			}),
		)
	})
}

func (ui *gioUI) layoutToastBanner(gtx layout.Context) layout.Dimensions {
	ui.mu.Lock()
	msg := ui.statusToast
	isErr := ui.toastErr
	until := ui.toastUntil
	st := ui.state
	ui.mu.Unlock()
	if (msg == "" || time.Now().After(until)) && st != nil {
		if cfgErr, _ := st["config_error"].(string); cfgErr != "" {
			msg = cfgErr
			isErr = true
			until = time.Now().Add(time.Minute)
		}
	}
	if msg == "" || time.Now().After(until) {
		return layout.Dimensions{}
	}
	bg, fg, ic := ui.pal.accSoft, ui.pal.acc, "check"
	if isErr {
		bg, fg, ic = ui.pal.errSoft, ui.pal.err, "stop"
	}
	return layout.Inset{Bottom: space1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return ui.subCard(gtx, bg, tint(fg, 110), space1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return drawIcon(gtx, ic, unit.Dp(15), fg)
				}),
				layout.Rigid(layout.Spacer{Width: space1}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					if ui.tab == 0 {
						return ui.labelLine(gtx, fontSmall, fg, font.SemiBold, msg)
					}
					return ui.label(gtx, fontBody, fg, font.SemiBold, msg)
				}),
			)
		})
	})
}

// layoutSubTabBar рисует современный сегмент-переключатель подвкладок внутри рельсы card2.
func (ui *gioUI) layoutSubTabBar(gtx layout.Context, tabIdx int, titles []string) layout.Dimensions {
	return layout.Inset{Bottom: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return ui.subCard(gtx, ui.pal.card, ui.pal.border, unit.Dp(4), func(gtx layout.Context) layout.Dimensions {
			var children []layout.FlexChild
			for i, t := range titles {
				idx := i
				title := t
				active := ui.subTabs[tabIdx] == idx
				if i > 0 {
					children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout))
				}
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return ui.segRouteButton(gtx, &ui.subTabBtns[tabIdx][idx], title, active, "primary")
				}))
			}
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
		})
	})
}
