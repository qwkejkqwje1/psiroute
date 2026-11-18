//go:build windows

package main

import (
	"image"
	"image/color"
	"math"
	"strings"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
)

// Векторные иконки и векторные флаги стран для Gio-интерфейса.
//
// Встроенный шрифт Go (gofont) не содержит эмодзи и региональных индикаторов
// флагов (🇩🇪, 🇳🇱, 🇺🇸 рисуются пустыми квадратиками). Поэтому все иконки и
// флаги стран рисуются аппаратными векторными примитивами Gio (Direct3D 11 /
// OpenGL), не требуют внешних шрифтов и идеально масштабируются под любой DPI.

type iconPen struct {
	gtx layout.Context
	k   float32 // пикселей на единицу сетки 24×24
	w   float32 // толщина линии
	col color.NRGBA
}

func (p iconPen) pt(x, y float32) f32.Point { return f32.Pt(x*p.k, y*p.k) }

// poly рисует ломаную (fill=false) или залитый многоугольник (fill=true).
func (p iconPen) poly(closed, fill bool, pts ...float32) {
	if len(pts) < 4 {
		return
	}
	var path clip.Path
	path.Begin(p.gtx.Ops)
	path.MoveTo(p.pt(pts[0], pts[1]))
	for i := 2; i+1 < len(pts); i += 2 {
		path.LineTo(p.pt(pts[i], pts[i+1]))
	}
	if closed || fill {
		path.Close()
	}
	spec := path.End()
	if fill {
		paint.FillShape(p.gtx.Ops, p.col, clip.Outline{Path: spec}.Op())
		return
	}
	paint.FillShape(p.gtx.Ops, p.col, clip.Stroke{Path: spec, Width: p.w}.Op())
}

func (p iconPen) rect(x0, y0, x1, y1 float32) image.Rectangle {
	return image.Rect(int(x0*p.k+0.5), int(y0*p.k+0.5), int(x1*p.k+0.5), int(y1*p.k+0.5))
}

func (p iconPen) circle(cx, cy, r float32, fill bool) {
	e := clip.Ellipse(p.rect(cx-r, cy-r, cx+r, cy+r))
	if fill {
		paint.FillShape(p.gtx.Ops, p.col, e.Op(p.gtx.Ops))
		return
	}
	paint.FillShape(p.gtx.Ops, p.col, clip.Stroke{Path: e.Path(p.gtx.Ops), Width: p.w}.Op())
}

func (p iconPen) ellipse(cx, cy, rx, ry float32) {
	e := clip.Ellipse(p.rect(cx-rx, cy-ry, cx+rx, cy+ry))
	paint.FillShape(p.gtx.Ops, p.col, clip.Stroke{Path: e.Path(p.gtx.Ops), Width: p.w}.Op())
}

func (p iconPen) rrect(x0, y0, x1, y1, r float32) {
	paint.FillShape(p.gtx.Ops, p.col, clip.UniformRRect(p.rect(x0, y0, x1, y1), int(r*p.k+0.5)).Op(p.gtx.Ops))
}

// arcPts — дуга окружности ломаной (углы в радианах, по часовой на экране).
func arcPts(cx, cy, r float64, a0, a1 float64, n int) []float32 {
	out := make([]float32, 0, 2*(n+1))
	for i := 0; i <= n; i++ {
		a := a0 + (a1-a0)*float64(i)/float64(n)
		out = append(out, float32(cx+r*math.Cos(a)), float32(cy+r*math.Sin(a)))
	}
	return out
}

func (p iconPen) rays(n int, r0, r1, phase float64) {
	for i := 0; i < n; i++ {
		a := phase + 2*math.Pi*float64(i)/float64(n)
		c, s := math.Cos(a), math.Sin(a)
		p.poly(false, false, float32(12+c*r0), float32(12+s*r0), float32(12+c*r1), float32(12+s*r1))
	}
}

// moonPts — полумесяц: внешний круг минус круг-«вырез».
func moonPts() []float32 {
	const ocx, ocy, or = 12.0, 12.0, 8.5
	const ccx, ccy, cr = 16.5, 7.5, 7.0
	inside := func(x, y, cx, cy, r float64) bool {
		dx, dy := x-cx, y-cy
		return dx*dx+dy*dy < r*r
	}
	var outer, cut []float32
	const n = 64
	start := math.Atan2(ccy-ocy, ccx-ocx)
	for i := 0; i <= n; i++ {
		a := start + 2*math.Pi*float64(i)/n
		x, y := ocx+or*math.Cos(a), ocy+or*math.Sin(a)
		if !inside(x, y, ccx, ccy, cr) {
			outer = append(outer, float32(x), float32(y))
		}
	}
	startC := math.Atan2(ocy-ccy, ocx-ccx) + math.Pi
	for i := 0; i <= n; i++ {
		a := startC + 2*math.Pi*float64(i)/n
		x, y := ccx+cr*math.Cos(a), ccy+cr*math.Sin(a)
		if inside(x, y, ocx, ocy, or) {
			cut = append(cut, float32(x), float32(y))
		}
	}
	if len(outer) < 4 || len(cut) < 4 {
		return outer
	}
	lx, ly := outer[len(outer)-2], outer[len(outer)-1]
	d := func(i int) float32 { dx, dy := cut[i]-lx, cut[i+1]-ly; return dx*dx + dy*dy }
	if d(len(cut)-2) < d(0) {
		for i, j := 0, len(cut)-2; i < j; i, j = i+2, j-2 {
			cut[i], cut[j] = cut[j], cut[i]
			cut[i+1], cut[j+1] = cut[j+1], cut[i+1]
		}
	}
	return append(outer, cut...)
}

var moonCache = moonPts()

// drawIcon рисует иконку kind размером size цветом col.
func drawIcon(gtx layout.Context, kind string, size unit.Dp, col color.NRGBA) layout.Dimensions {
	s := gtx.Dp(size)
	p := iconPen{gtx: gtx, k: float32(s) / 24, col: col}
	p.w = 2 * p.k
	if p.w < 1.2 {
		p.w = 1.2
	}
	switch kind {
	case "bolt":
		p.poly(true, true, 13.5, 2, 4.5, 13.5, 11, 13.5, 10, 22, 19.5, 10, 13, 10)
	case "apps":
		p.rrect(3.5, 3.5, 10.5, 10.5, 2)
		p.rrect(13.5, 3.5, 20.5, 10.5, 2)
		p.rrect(3.5, 13.5, 10.5, 20.5, 2)
		p.rrect(13.5, 13.5, 20.5, 20.5, 2)
	case "route":
		p.poly(false, false, 6, 8, 6, 16)
		p.poly(false, false, 6, 12.5, 10, 12.5, 13.5, 9.5, 16, 7.5)
		p.circle(6, 5.5, 2.6, true)
		p.circle(6, 18.5, 2.6, true)
		p.circle(18, 6, 2.6, true)
	case "shield":
		p.poly(true, false, 12, 2.5, 19.5, 5.5, 19.5, 11, 17.5, 16.5, 12, 21.5, 6.5, 16.5, 4.5, 11, 4.5, 5.5)
		p.poly(false, false, 8.5, 12, 11, 14.5, 15.5, 9.5)
	case "chart":
		p.rrect(3.5, 13, 7.5, 20.5, 1.2)
		p.rrect(10, 8, 14, 20.5, 1.2)
		p.rrect(16.5, 3.5, 20.5, 20.5, 1.2)
	case "gear":
		p.circle(12, 12, 6.5, false)
		p.circle(12, 12, 2.6, false)
		q := p
		q.w = 2.6 * p.k
		q.rays(8, 7.2, 10, math.Pi/8)
	case "sun":
		p.circle(12, 12, 4.2, true)
		p.rays(8, 6.8, 9.8, 0)
	case "moon":
		p.poly(true, true, moonCache...)
	case "globe":
		p.circle(12, 12, 9, false)
		p.ellipse(12, 12, 3.8, 9)
		p.poly(false, false, 3, 12, 21, 12)
	case "refresh":
		p.poly(false, false, arcPts(12, 12, 7.5, -math.Pi*0.15, math.Pi*1.55, 28)...)
		p.poly(true, true, 15.5, 2.5, 21.5, 5.5, 16, 9.5)
	case "swap":
		p.poly(false, false, 4, 8, 19, 8)
		p.poly(false, false, 15, 4, 19, 8, 15, 12)
		p.poly(false, false, 20, 16, 5, 16)
		p.poly(false, false, 9, 12, 5, 16, 9, 20)
	case "check":
		q := p
		q.w = 2.4 * p.k
		q.poly(false, false, 4.5, 12.5, 9.5, 17.5, 19.5, 6.5)
	case "play":
		p.poly(true, true, 7, 4, 19.5, 12, 7, 20)
	case "stop":
		p.rrect(6, 6, 18, 18, 2)
	case "download":
		p.poly(false, false, 12, 3.5, 12, 15)
		p.poly(false, false, 7, 10.5, 12, 15.5, 17, 10.5)
		p.poly(false, false, 4.5, 20, 19.5, 20)
	case "search":
		p.circle(10.5, 10.5, 6.5, false)
		q := p
		q.w = 2.4 * p.k
		q.poly(false, false, 15.5, 15.5, 20.5, 20.5)
	case "copy":
		p.poly(true, false, 8.5, 8.5, 19.5, 8.5, 19.5, 20.5, 8.5, 20.5)
		p.poly(false, false, 5, 16, 5, 4.5, 15.5, 4.5)
	case "power":
		p.poly(false, false, arcPts(12, 13, 7.5, -math.Pi/2+0.8, 3*math.Pi/2-0.8, 32)...)
		p.poly(false, false, 12, 3, 12, 11.5)
	case "lock":
		p.poly(true, false, 5, 11, 19, 11, 19, 20.5, 5, 20.5)
		p.poly(false, false, arcPts(12, 8, 4.5, math.Pi, 2*math.Pi, 16)...)
		p.poly(false, false, 7.5, 8, 7.5, 11)
		p.poly(false, false, 16.5, 8, 16.5, 11)
		p.circle(12, 15.5, 1.4, true)
	case "lan":
		p.rrect(9, 3, 15, 8, 1.2)
		p.rrect(3, 16, 9, 21, 1.2)
		p.rrect(15, 16, 21, 21, 1.2)
		p.poly(false, false, 12, 8, 12, 12)
		p.poly(false, false, 6, 16, 6, 12, 18, 12, 18, 16)
	case "home":
		p.poly(true, false, 4, 10.5, 12, 3.5, 20, 10.5, 20, 20.5, 4, 20.5)
		p.poly(false, false, 10, 20.5, 10, 14.5, 14, 14.5, 14, 20.5)
	case "plus":
		p.poly(false, false, 12, 5, 12, 19)
		p.poly(false, false, 5, 12, 19, 12)
	case "trash":
		p.poly(false, false, 4.5, 7, 19.5, 7)
		p.poly(false, false, 9, 7, 9, 4.5, 15, 4.5, 15, 7)
		p.poly(true, false, 6.5, 7, 17.5, 7, 16.5, 20, 7.5, 20)
	case "edit":
		p.poly(true, false, 4, 20, 4, 16, 15.5, 4.5, 19.5, 8.5, 8, 20)
	case "up":
		p.poly(false, false, 12, 19, 12, 5)
		p.poly(false, false, 6.5, 10.5, 12, 5, 17.5, 10.5)
	case "down":
		p.poly(false, false, 12, 5, 12, 19)
		p.poly(false, false, 6.5, 13.5, 12, 19, 17.5, 13.5)
	case "list":
		p.poly(false, false, 8, 6, 20, 6)
		p.poly(false, false, 8, 12, 20, 12)
		p.poly(false, false, 8, 18, 20, 18)
		p.circle(4.5, 6, 1.4, true)
		p.circle(4.5, 12, 1.4, true)
		p.circle(4.5, 18, 1.4, true)
	case "dot":
		p.circle(12, 12, 5, true)
	case "more":
		p.circle(5.5, 12, 1.8, true)
		p.circle(12, 12, 1.8, true)
		p.circle(18.5, 12, 1.8, true)
	}
	return layout.Dimensions{Size: image.Pt(s, s)}
}

var navIcons = [5]string{"home", "route", "lan", "globe", "chart"}

// ---------- Vector Country Flags (Gio GPU Primitives) ----------

// drawCountryFlag рисует чёткий векторный флаг страны по двухбуквенному ISO-коду
// (или значок «авто» для "" / "AUTO") в прямоугольнике wDp × hDp со скруглёнными углами.
func drawCountryFlag(gtx layout.Context, code string, wDp, hDp unit.Dp) layout.Dimensions {
	w := gtx.Dp(wDp)
	h := gtx.Dp(hDp)
	if w < 12 {
		w = 12
	}
	if h < 9 {
		h = 9
	}
	sz := image.Pt(w, h)
	rad := max(h/5, 2)
	cc := strings.ToUpper(strings.TrimSpace(code))
	if strings.HasPrefix(cc, "PSIPHON:") {
		cc = strings.TrimSpace(cc[8:])
	}

	rr := clip.UniformRRect(image.Rectangle{Max: sz}, rad)
	stack := rr.Push(gtx.Ops)

	fillBox := func(x0, y0, x1, y1 float32, hex uint32) {
		r := image.Rect(
			int(x0*float32(w)+0.5),
			int(y0*float32(h)+0.5),
			int(x1*float32(w)+0.5),
			int(y1*float32(h)+0.5),
		)
		paint.FillShape(gtx.Ops, rgb(hex), clip.Rect(r).Op())
	}
	h3 := func(c1, c2, c3 uint32) {
		fillBox(0, 0, 1, 0.34, c1)
		fillBox(0, 0.33, 1, 0.67, c2)
		fillBox(0, 0.66, 1, 1, c3)
	}
	h2 := func(c1, c2 uint32) {
		fillBox(0, 0, 1, 0.51, c1)
		fillBox(0, 0.50, 1, 1, c2)
	}
	v3 := func(c1, c2, c3 uint32) {
		fillBox(0, 0, 0.34, 1, c1)
		fillBox(0.33, 0, 0.67, 1, c2)
		fillBox(0.66, 0, 1, 1, c3)
	}
	nordic := func(bg, cross uint32, inner *uint32) {
		fillBox(0, 0, 1, 1, bg)
		fillBox(0.26, 0, 0.44, 1, cross)
		fillBox(0, 0.36, 1, 0.64, cross)
		if inner != nil {
			fillBox(0.30, 0, 0.40, 1, *inner)
			fillBox(0, 0.42, 1, 0.58, *inner)
		}
	}
	disc := func(cx, cy, r float32, hex uint32) {
		radPx := int(r*float32(h) + 0.5)
		px := int(cx*float32(w) + 0.5)
		py := int(cy*float32(h) + 0.5)
		paint.FillShape(gtx.Ops, rgb(hex), clip.Ellipse{
			Min: image.Pt(px-radPx, py-radPx),
			Max: image.Pt(px+radPx, py+radPx),
		}.Op(gtx.Ops))
	}
	polyFill := func(hex uint32, pts ...float32) {
		if len(pts) < 6 {
			return
		}
		var path clip.Path
		path.Begin(gtx.Ops)
		path.MoveTo(f32.Pt(pts[0]*float32(w), pts[1]*float32(h)))
		for i := 2; i+1 < len(pts); i += 2 {
			path.LineTo(f32.Pt(pts[i]*float32(w), pts[i+1]*float32(h)))
		}
		path.Close()
		paint.FillShape(gtx.Ops, rgb(hex), clip.Outline{Path: path.End()}.Op())
	}

	switch cc {
	case "", "AUTO":
		fillBox(0, 0, 1, 1, 0x4F5BEA)
		disc(0.5, 0.5, 0.28, 0xFFFFFF)
		disc(0.5, 0.5, 0.16, 0x4F5BEA)
	case "DE":
		h3(0x18181B, 0xDD0000, 0xFFCE00)
	case "NL":
		h3(0xAE1C28, 0xFFFFFF, 0x21468B)
	case "AT":
		h3(0xED2939, 0xFFFFFF, 0xED2939)
	case "HU":
		h3(0xCE2939, 0xFFFFFF, 0x477050)
	case "BG":
		h3(0xFFFFFF, 0x00966E, 0xD62612)
	case "EE":
		h3(0x0072CE, 0x111111, 0xFFFFFF)
	case "LT":
		h3(0xFDB913, 0x006A44, 0xC1272D)
	case "LV":
		fillBox(0, 0, 1, 1, 0x9E3039)
		fillBox(0, 0.40, 1, 0.60, 0xFFFFFF)
	case "RU":
		h3(0xFFFFFF, 0x0039A6, 0xD52B1E)
	case "RS":
		h3(0xC6363C, 0x0C4076, 0xFFFFFF)
	case "SK":
		h3(0xFFFFFF, 0x0B4EA2, 0xEE1C25)
	case "SI":
		h3(0xFFFFFF, 0x005DA4, 0xED1C24)
	case "LU":
		h3(0xED2939, 0xFFFFFF, 0x00A1DE)
	case "AM":
		h3(0xD90012, 0x0033A0, 0xF2A800)
	case "HR":
		h3(0xFF0000, 0xFFFFFF, 0x171796)
	case "IN":
		h3(0xFF9933, 0xFFFFFF, 0x138808)
		disc(0.5, 0.5, 0.13, 0x000080)
	case "AR":
		h3(0x74ACDF, 0xFFFFFF, 0x74ACDF)
		disc(0.5, 0.5, 0.12, 0xF6B40E)
	case "ES":
		fillBox(0, 0, 1, 1, 0xAA151B)
		fillBox(0, 0.25, 1, 0.75, 0xF1BF00)
	case "PL":
		h2(0xFFFFFF, 0xDC143C)
	case "UA":
		h2(0x0057B7, 0xFFD700)
	case "ID", "MC":
		h2(0xCE1126, 0xFFFFFF)
	case "SG":
		h2(0xEF3340, 0xFFFFFF)
		disc(0.28, 0.26, 0.15, 0xFFFFFF)
		disc(0.33, 0.26, 0.13, 0xEF3340)
	case "FR":
		v3(0x0055A4, 0xFFFFFF, 0xEF4135)
	case "IT":
		v3(0x009246, 0xFFFFFF, 0xCE2B37)
	case "BE":
		v3(0x111111, 0xFDDA24, 0xEF3340)
	case "IE":
		v3(0x169B62, 0xFFFFFF, 0xFF883E)
	case "RO":
		v3(0x002B7F, 0xFCD116, 0xCE1126)
	case "MX":
		v3(0x006847, 0xFFFFFF, 0xCE1126)
		disc(0.5, 0.5, 0.11, 0x6B4C35)
	case "MD":
		v3(0x0046AE, 0xFFD200, 0xCC092F)
	case "CA":
		fillBox(0, 0, 1, 1, 0xFFFFFF)
		fillBox(0, 0, 0.26, 1, 0xD52B1E)
		fillBox(0.74, 0, 1, 1, 0xD52B1E)
		disc(0.5, 0.5, 0.20, 0xD52B1E)
	case "FI":
		nordic(0xFFFFFF, 0x002F6C, nil)
	case "SE":
		nordic(0x006AA7, 0xFECC00, nil)
	case "DK":
		nordic(0xC8102E, 0xFFFFFF, nil)
	case "NO":
		in := uint32(0x00205B)
		nordic(0xBA0C2F, 0xFFFFFF, &in)
	case "IS":
		in := uint32(0xDC1E35)
		nordic(0x02529C, 0xFFFFFF, &in)
	case "CH":
		fillBox(0, 0, 1, 1, 0xD52B1E)
		fillBox(0.41, 0.18, 0.59, 0.82, 0xFFFFFF)
		fillBox(0.26, 0.38, 0.74, 0.62, 0xFFFFFF)
	case "GE":
		fillBox(0, 0, 1, 1, 0xFFFFFF)
		fillBox(0.42, 0, 0.58, 1, 0xFF0000)
		fillBox(0, 0.38, 1, 0.62, 0xFF0000)
	case "JP":
		fillBox(0, 0, 1, 1, 0xFFFFFF)
		disc(0.5, 0.5, 0.28, 0xBC002D)
	case "KR":
		fillBox(0, 0, 1, 1, 0xFFFFFF)
		disc(0.5, 0.5, 0.26, 0xCD2E3A)
		fillBox(0.32, 0.5, 0.68, 0.76, 0x0047A0)
	case "CZ":
		h2(0xFFFFFF, 0xD7141A)
		polyFill(0x11457E, 0, 0, 0.5, 0.5, 0, 1)
	case "US":
		fillBox(0, 0, 1, 1, 0xFFFFFF)
		for s := 0; s < 7; s += 2 {
			y0 := float32(s) / 7.0
			y1 := float32(s+1) / 7.0
			fillBox(0, y0, 1, y1, 0xB22234)
		}
		fillBox(0, 0, 0.46, 0.56, 0x3C3B6E)
	case "GB", "UK":
		fillBox(0, 0, 1, 1, 0x012169)
		polyFill(0xFFFFFF, 0, 0, 0.16, 0, 1, 0.84, 1, 1, 0.84, 1, 0, 0.16)
		polyFill(0xFFFFFF, 0.84, 0, 1, 0, 1, 0.16, 0.16, 1, 0, 1, 0, 0.84)
		fillBox(0.38, 0, 0.62, 1, 0xFFFFFF)
		fillBox(0, 0.34, 1, 0.66, 0xFFFFFF)
		fillBox(0.43, 0, 0.57, 1, 0xC8102E)
		fillBox(0, 0.41, 1, 0.59, 0xC8102E)
	case "TR":
		fillBox(0, 0, 1, 1, 0xE30A17)
		disc(0.44, 0.5, 0.25, 0xFFFFFF)
		disc(0.50, 0.5, 0.20, 0xE30A17)
	case "IL":
		fillBox(0, 0, 1, 1, 0xFFFFFF)
		fillBox(0, 0.12, 1, 0.26, 0x0038B8)
		fillBox(0, 0.74, 1, 0.88, 0x0038B8)
		disc(0.5, 0.5, 0.14, 0x0038B8)
	case "GR":
		fillBox(0, 0, 1, 1, 0x0D5EAF)
		fillBox(0, 0.22, 1, 0.36, 0xFFFFFF)
		fillBox(0, 0.55, 1, 0.69, 0xFFFFFF)
		fillBox(0, 0, 0.42, 0.55, 0x0D5EAF)
		fillBox(0.16, 0, 0.26, 0.55, 0xFFFFFF)
		fillBox(0, 0.21, 0.42, 0.35, 0xFFFFFF)
	case "PT":
		fillBox(0, 0, 0.4, 1, 0x006600)
		fillBox(0.4, 0, 1, 1, 0xFF0000)
		disc(0.4, 0.5, 0.16, 0xFFCC00)
	case "BR":
		fillBox(0, 0, 1, 1, 0x009C3B)
		polyFill(0xFFDF00, 0.5, 0.14, 0.88, 0.5, 0.5, 0.86, 0.12, 0.5)
		disc(0.5, 0.5, 0.20, 0x002776)
	case "AE":
		h3(0x00732F, 0xFFFFFF, 0x111111)
		fillBox(0, 0, 0.28, 1, 0xFF0000)
	case "TH":
		fillBox(0, 0, 1, 1, 0xA51931)
		fillBox(0, 0.17, 1, 0.83, 0xF4F5F8)
		fillBox(0, 0.33, 1, 0.67, 0x2D2A4A)
	case "VN":
		fillBox(0, 0, 1, 1, 0xDA251D)
		disc(0.5, 0.5, 0.20, 0xFFCD00)
	case "HK":
		fillBox(0, 0, 1, 1, 0xDE2910)
		disc(0.5, 0.5, 0.20, 0xFFFFFF)
	case "TW":
		fillBox(0, 0, 1, 1, 0xFE0000)
		fillBox(0, 0, 0.5, 0.54, 0x000095)
		disc(0.25, 0.27, 0.12, 0xFFFFFF)
	case "KZ":
		fillBox(0, 0, 1, 1, 0x00AFCA)
		disc(0.5, 0.5, 0.20, 0xFFEC2D)
	case "ZA":
		h3(0xE03C31, 0x007749, 0x001489)
		polyFill(0x007749, 0, 0, 0.45, 0.5, 0, 1)
	case "CL":
		h2(0xFFFFFF, 0xD52B1E)
		fillBox(0, 0, 0.36, 0.5, 0x0039A6)
	case "AU", "NZ":
		fillBox(0, 0, 1, 1, 0x012169)
		fillBox(0, 0, 0.48, 0.52, 0xFFFFFF)
		fillBox(0.19, 0, 0.29, 0.52, 0xC8102E)
		fillBox(0, 0.20, 0.48, 0.32, 0xC8102E)
	default:
		fillBox(0, 0, 1, 1, 0x3B4252)
		disc(0.5, 0.5, 0.22, 0x7A8BFF)
	}
	stack.Pop()
	strokeRect(gtx, sz, rad, 1, color.NRGBA{R: 128, G: 138, B: 160, A: 65})
	return layout.Dimensions{Size: sz}
}
