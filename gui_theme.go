//go:build windows

package main

import (
	"fmt"
	"image/color"
	"strings"

	"gioui.org/unit"
)

// Дизайн-система PsiRoute 2.0.5:
//   - По умолчанию: "obsidian" (Tactical Glass / Obsidian Dark — глубокий графит #0B0E14, индиго #6366F1, бирюза #06B6D4)
//   - Опциональный переключатель: "cyber-amber" (USSR Retrofuturism / Cyber-Amber Terminal HUD — угольный #0D0F0E, янтарный люминофор #FFB000)
//   - Единая модульная сетка кратно 8dp и контраст текста >= 7:1.
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
	themeID  string
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
	acc      color.NRGBA // основной акцент
	accSoft  color.NRGBA
	ok       color.NRGBA // успех / прямое / подключено (Emerald)
	okSoft   color.NRGBA
	warn     color.NRGBA // предупреждение / WARP / Янтарь (Amber)
	warnSoft color.NRGBA
	err      color.NRGBA // ошибка / блокировка (Coral Rose)
	errSoft  color.NRGBA
	vio      color.NRGBA // Psiphon VPN (Violet)
	vioSoft  color.NRGBA
	teal     color.NRGBA // DPI-обход (Cyan Teal)
	tealSoft color.NRGBA
}

func paletteFor(_ bool) gioPalette {
	return paletteByTheme("obsidian")
}

func paletteByTheme(theme string) gioPalette {
	switch strings.ToLower(strings.TrimSpace(theme)) {
	case "cyber-amber", "amber", "ussr", "retro":
		return gioPalette{
			dark:     true,
			themeID:  "cyber-amber",
			bg:       rgb(0x0B0D0C),
			side:     rgb(0x101412),
			card:     rgb(0x151A17),
			card2:    rgb(0x1C231F),
			hover:    rgb(0x252E29),
			border:   rgb(0x2B3630),
			borderHi: rgb(0xFFB000),
			text:     rgb(0xF6F3E8),
			mut:      rgb(0xB5B09C),
			dim:      rgb(0x787566),
			acc:      rgb(0xFFB000),
			accSoft:  rgba(0xFFB000, 38),
			ok:       rgb(0x22C55E),
			okSoft:   rgba(0x22C55E, 36),
			warn:     rgb(0xF59E0B),
			warnSoft: rgba(0xF59E0B, 36),
			err:      rgb(0xEF4444),
			errSoft:  rgba(0xEF4444, 36),
			vio:      rgb(0xFFB000),
			vioSoft:  rgba(0xFFB000, 38),
			teal:     rgb(0x14B8A6),
			tealSoft: rgba(0x14B8A6, 36),
		}
	default:
		// Obsidian Pro v2.2 (#080B12 bg, #0B0F18 side, #111623 card, #161D2E card2)
		return gioPalette{
			dark:     true,
			themeID:  "obsidian",
			bg:       rgb(0x080B12),
			side:     rgb(0x0B0F18),
			card:     rgb(0x111623),
			card2:    rgb(0x161D2E),
			hover:    rgb(0x1E273D),
			border:   rgb(0x232E47),
			borderHi: rgb(0x6366F1),
			text:     rgb(0xEDF2F7),
			mut:      rgb(0x94A3B8),
			dim:      rgb(0x64748B),
			acc:      rgb(0x6366F1),
			accSoft:  rgba(0x6366F1, 40),
			ok:       rgb(0x10B981),
			okSoft:   rgba(0x10B981, 36),
			warn:     rgb(0xF59E0B),
			warnSoft: rgba(0xF59E0B, 36),
			err:      rgb(0xF43F5E),
			errSoft:  rgba(0xF43F5E, 36),
			vio:      rgb(0x8B5CF6),
			vioSoft:  rgba(0x8B5CF6, 40),
			teal:     rgb(0x06B6D4),
			tealSoft: rgba(0x06B6D4, 36),
		}
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
	case "stopping":
		return ui.pal.err
	case "error":
		return ui.pal.err
	}
	return ui.pal.acc
}

// routeColor реализует единую семантическую кодировку маршрутов (Часть 3.1):
//   - Изумрудный (ok)     — Direct (Напрямую)
//   - Бирюзовый (teal)    — Direct-DPI (Обход ТСПУ)
//   - Янтарный (warn)     — Cloudflare WARP (UDP/MASQUE)
//   - Фиолетовый (vio)    — Psiphon / Psiphon:CC (VPN со сменой страны)
//   - Рубиновый (err)     — Block (Блокировать)
func (ui *gioUI) routeColor(ob string) color.NRGBA {
	switch {
	case ob == obDirect || ob == "tun-exclude":
		return ui.pal.ok
	case ob == obDesync:
		return ui.pal.teal
	case ob == obWarp:
		return ui.pal.warn
	case ob == obPsiphon || strings.HasPrefix(ob, obPsiphon+":"):
		return ui.pal.vio
	case ob == obBlock:
		return ui.pal.err
	case ob == obAuto:
		return ui.pal.acc
	}
	return ui.pal.mut
}

func routeShortRu(ob string) string {
	switch {
	case ob == obDirect:
		return "Напрямую"
	case ob == "tun-exclude":
		return "Вне TUN"
	case ob == obDesync:
		return "Обход DPI"
	case ob == obWarp:
		return "WARP"
	case ob == obPsiphon:
		return "Psiphon VPN"
	case strings.HasPrefix(ob, obPsiphon+":"):
		return "VPN " + strings.ToUpper(strings.TrimPrefix(ob, obPsiphon+":"))
	case ob == obBlock:
		return "Блок"
	case ob == obAuto || ob == "":
		return "Авто"
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
	case "stopping":
		return "Отключение…"
	case "error":
		return "Ошибка связи"
	}
	return "Отключено"
}

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
