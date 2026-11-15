//go:build windows

package main

import (
	"fmt"
	"image/color"
	"strings"

	"gioui.org/unit"
)

// Дизайн-система PsiRoute 2.0.3 (Obsidian Dark / Porcelain Light).
// Типографская шкала и модульная сетка отступов, кратная 8dp.
const (
	fontMicro = unit.Sp(10.5)
	fontSmall = unit.Sp(11.5)
	fontBody  = unit.Sp(13)
	fontSub   = unit.Sp(14.5)
	fontTitle = unit.Sp(18)
	fontHero  = unit.Sp(21)

	space0 = unit.Dp(4)
	space1 = unit.Dp(8)
	space2 = unit.Dp(16)
	space3 = unit.Dp(24)
)

type gioPalette struct {
	dark     bool
	bg       color.NRGBA // основной фон рабочей области
	side     color.NRGBA // фон боковой панели
	card     color.NRGBA // основная поверхность карточек
	card2    color.NRGBA // углублённая поверхность (инпуты, метрики, плитки)
	hover    color.NRGBA // состояние наведения
	border   color.NRGBA // тонкая граница 1dp
	borderHi color.NRGBA // акцентная граница при фокусе/выделении
	text     color.NRGBA // основной текст (WCAG >= 7:1)
	mut      color.NRGBA // вторичный текст
	dim      color.NRGBA // третичный текст / подписи
	acc      color.NRGBA // основной акцент (Electric Indigo)
	accSoft  color.NRGBA
	ok       color.NRGBA // успех / прямое / подключено (Emerald)
	okSoft   color.NRGBA
	warn     color.NRGBA // предупреждение / подключение / WARP (Amber)
	warnSoft color.NRGBA
	err      color.NRGBA // ошибка / блокировка (Coral Rose)
	errSoft  color.NRGBA
	vio      color.NRGBA // Psiphon VPN (Violet)
	vioSoft  color.NRGBA
	teal     color.NRGBA // DPI-обход (Cyan Teal)
	tealSoft color.NRGBA
}

func paletteFor(_ bool) gioPalette {
	return gioPalette{
		dark:     true,
		bg:       rgb(0x090B10),
		side:     rgb(0x0D1017),
		card:     rgb(0x131822),
		card2:    rgb(0x1A202D),
		hover:    rgb(0x222938),
		border:   rgb(0x232B3B),
		borderHi: rgb(0x36435C),
		text:     rgb(0xF1F5F9),
		mut:      rgb(0x94A3B8),
		dim:      rgb(0x64748B),
		acc:      rgb(0x5B7CFA),
		accSoft:  rgba(0x5B7CFA, 38),
		ok:       rgb(0x10B981),
		okSoft:   rgba(0x10B981, 34),
		warn:     rgb(0xF59E0B),
		warnSoft: rgba(0xF59E0B, 34),
		err:      rgb(0xF43F5E),
		errSoft:  rgba(0xF43F5E, 34),
		vio:      rgb(0xA855F7),
		vioSoft:  rgba(0xA855F7, 38),
		teal:     rgb(0x06B6D4),
		tealSoft: rgba(0x06B6D4, 34),
	}
}

func tint(c color.NRGBA, a uint8) color.NRGBA {
	c.A = a
	return c
}

func mix(a, b color.NRGBA, t float32) color.NRGBA {
	inv := 1 - t
	return color.NRGBA{
		R: uint8(float32(a.R)*inv + float32(b.R)*t),
		G: uint8(float32(a.G)*inv + float32(b.G)*t),
		B: uint8(float32(a.B)*inv + float32(b.B)*t),
		A: 255,
	}
}

func rgb(hex uint32) color.NRGBA {
	return rgba(hex, 255)
}

func rgba(hex uint32, a uint8) color.NRGBA {
	return color.NRGBA{R: uint8(hex >> 16), G: uint8(hex >> 8), B: uint8(hex), A: a}
}

func capFirst(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func proxyHostPort(listen string) (string, string) {
	host, port := "127.0.0.1", "1080"
	if listen == "" {
		return host, port
	}
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		h := strings.Trim(listen[:i], "[]")
		if p := listen[i+1:]; p != "" {
			port = p
		}
		if h != "" && h != "0.0.0.0" && h != "::" {
			host = h
		}
	}
	return host, port
}

func countryLabel(cc string) string {
	if cc == "" || strings.EqualFold(cc, "auto") {
		return "авто"
	}
	for i := 0; i < len(nativeCountries); i++ {
		if strings.EqualFold(nativeCountries[i], cc) {
			return nativeCountryNames[i]
		}
	}
	return strings.ToUpper(cc)
}

func fmtSpeed(bps float64) string {
	if bps >= 1048576 {
		return fmt.Sprintf("%.1f МБ/с", bps/1048576)
	}
	return fmt.Sprintf("%.0f КБ/с", bps/1024)
}

func (ui *gioUI) statusColor(pState string) color.NRGBA {
	switch pState {
	case "connected":
		return ui.pal.ok
	case "connecting", "reconnecting":
		return ui.pal.warn
	case "error":
		return ui.pal.err
	}
	return ui.pal.acc
}

// routeColor реализует единую цветовую кодировку 5 типов выхода (Раздел 2 ТЗ):
//   - Изумрудный (ok)     — Direct (Напрямую)
//   - Голубой (teal)      — Direct-DPI (Обход DPI)
//   - Фиолетовый (vio)    — WARP (Быстрый туннель Cloudflare)
//   - Янтарный (warn)     — Psiphon / Psiphon:CC (VPN со сменой страны)
//   - Красный (err)       — Block (Блокировать)
func (ui *gioUI) routeColor(ob string) color.NRGBA {
	switch {
	case ob == obDirect || ob == "tun-exclude":
		return ui.pal.ok
	case ob == obDesync:
		return ui.pal.teal
	case ob == obWarp:
		return ui.pal.vio
	case ob == obPsiphon || strings.HasPrefix(ob, obPsiphon+":"):
		return ui.pal.warn
	case ob == obBlock:
		return ui.pal.err
	case ob == obAuto:
		return ui.pal.acc
	}
	return ui.pal.mut
}

func routeShortRu(ob string) string {
	switch {
	case ob == obDirect || ob == "tun-exclude":
		return "Напрямую"
	case ob == obDesync:
		return "Обход DPI"
	case ob == obWarp:
		return "WARP"
	case ob == obPsiphon:
		return "VPN"
	case strings.HasPrefix(ob, obPsiphon+":"):
		return "VPN " + strings.ToUpper(strings.TrimPrefix(ob, obPsiphon+":"))
	case ob == obBlock:
		return "Блок"
	case ob == obAuto || ob == "":
		return "Умный"
	}
	return ob
}

func onOffRu(on bool) string {
	if on {
		return "вкл"
	}
	return "выкл"
}

func onOffStatus(on bool, detail string) string {
	if on {
		return "Вкл · " + detail
	}
	return "Выкл · " + detail
}

func cnameShort(cc string) string {
	if cc == "" || cc == "auto" {
		return "Авто"
	}
	return strings.ToUpper(cc)
}

func stateTitle(s string) string {
	switch s {
	case "connected":
		return "Защищено"
	case "connecting":
		return "Подключение…"
	case "reconnecting":
		return "Переподключение…"
	case "error":
		return "Ошибка связи"
	}
	return "Отключено"
}

// maskSensitive скрывает чувствительные данные (реальный IP провайдера и посещённые домены)
// под звёздочками в режиме «Чистый экран» (для безопасных скриншотов и стримов в Discord).
func (ui *gioUI) maskSensitive(s string) string {
	if !ui.privacyMode || strings.TrimSpace(s) == "" {
		return s
	}
	s = strings.TrimSpace(s)
	if strings.Count(s, ".") == 3 || strings.Contains(s, ":") {
		return "***.***.***.***"
	}
	parts := strings.Split(s, ".")
	if len(parts) >= 2 {
		first := parts[0]
		tld := parts[len(parts)-1]
		if len([]rune(first)) > 1 {
			r := []rune(first)
			return string(r[0]) + "******." + tld
		}
		return "******." + tld
	}
	return "********"
}
