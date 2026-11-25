//go:build windows

package main

import (
	"fmt"
	"image/color"
	"strings"

	"gioui.org/unit"
)

// Дизайн-система PsiRoute «Aurora Dark» (единая с веб-панелью ui/index.html):
//   - Глубокий ночной фон #070914, акцентный градиент #7C5CFF → #00D1FF,
//     карточки со скруглением 16–18dp и мягкой подсветкой состояния.
//   - Только тёмная тема (Dark-only), модульная сетка кратно 8dp, контраст >= 7:1.
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
	dark      bool
	themeID   string
	bg        color.NRGBA // основной фон рабочей области
	side      color.NRGBA // фон боковой панели
	card      color.NRGBA // основная поверхность карточек
	card2     color.NRGBA // углублённая поверхность (инпуты, метрики, плитки)
	hover     color.NRGBA // состояние наведения
	border    color.NRGBA // тонкая граница 1dp
	borderHi  color.NRGBA // акцентная граница при фокусе/выделении
	text      color.NRGBA // основной текст (WCAG >= 7:1)
	mut       color.NRGBA // вторичный текст
	dim       color.NRGBA // третичный текст / подписи
	acc       color.NRGBA // основной акцент (фиолетовый #7C5CFF)
	accSoft   color.NRGBA
	acc2      color.NRGBA // второй цвет градиента (голубой #00D1FF)
	ok        color.NRGBA // успех / прямое / подключено (Emerald #22D3A0)
	okSoft    color.NRGBA
	warn      color.NRGBA // предупреждение / WARP / Янтарь (#FBBF24)
	warnSoft  color.NRGBA
	err       color.NRGBA // ошибка / блокировка (Coral Rose #FB5E7C)
	errSoft   color.NRGBA
	vio       color.NRGBA // Psiphon VPN (Violet #8B7BFF)
	vioSoft   color.NRGBA
	teal      color.NRGBA // DPI-обход (Cyan Teal #22D3EE)
	tealSoft  color.NRGBA
	clean     color.NRGBA // Clean-IP каскад (#2DD4BF)
	cleanSoft color.NRGBA
}

func paletteFor(_ bool) gioPalette {
	return paletteByTheme("obsidian")
}

func paletteByTheme(_ string) gioPalette {
	return gioPalette{
		dark:      true,
		themeID:   "obsidian",
		bg:        rgb(0x070914),
		side:      rgb(0x0A0D1B),
		card:      rgb(0x0F1426),
		card2:     rgb(0x151B30),
		hover:     rgb(0x1D2542),
		border:    rgb(0x252E4D),
		borderHi:  rgb(0x7C5CFF),
		text:      rgb(0xEAEEFB),
		mut:       rgb(0xA3ACCB),
		dim:       rgb(0x7F89AD),
		acc:       rgb(0x7C5CFF),
		accSoft:   rgba(0x7C5CFF, 52),
		acc2:      rgb(0x00D1FF),
		ok:        rgb(0x22D3A0),
		okSoft:    rgba(0x22D3A0, 36),
		warn:      rgb(0xFBBF24),
		warnSoft:  rgba(0xFBBF24, 36),
		err:       rgb(0xFB5E7C),
		errSoft:   rgba(0xFB5E7C, 36),
		vio:       rgb(0x8B7BFF),
		vioSoft:   rgba(0x8B7BFF, 44),
		teal:      rgb(0x22D3EE),
		tealSoft:  rgba(0x22D3EE, 36),
		clean:     rgb(0x2DD4BF),
		cleanSoft: rgba(0x2DD4BF, 38),
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

func fmtDur(sec float64) string {
	s := int(sec)
	if s < 0 {
		s = 0
	}
	h := s / 3600
	m := (s % 3600) / 60
	x := s % 60
	if h > 0 {
		return fmt.Sprintf("%dч %02dм", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dм %02dс", m, x)
	}
	return fmt.Sprintf("%dс", x)
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

// routeColor реализует единую семантическую кодировку маршрутов:
//   - Изумрудный (ok)     — Direct (Напрямую)
//   - Бирюзовый (teal)    — Direct-DPI (Обход ТСПУ)
//   - Янтарный (warn)     — Cloudflare WARP (UDP/MASQUE)
//   - Фиолетовый (vio)    — Psiphon / Psiphon:CC (VPN со сменой страны)
//   - Мятный (clean)      — Clean-IP (WARP → VPN → WARP)
//   - Рубиновый (err)     — Block (Блокировать)
func (ui *gioUI) routeColor(ob string) color.NRGBA {
	switch {
	case ob == obDirect || ob == "tun-exclude":
		return ui.pal.ok
	case ob == obDesync:
		return ui.pal.teal
	case ob == obWarp:
		return ui.pal.warn
	case ob == obCleanIP:
		return ui.pal.clean
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
	case ob == obCleanIP:
		return "Clean-IP"
	case ob == obPsiphon:
		return "Psiphon VPN"
	case strings.HasPrefix(ob, obPsiphon+":"):
		return "VPN " + strings.ToUpper(strings.TrimPrefix(ob, obPsiphon+":"))
	case ob == obBlock:
		return "Блок"
	case ob == obProxy:
		return "Прокси"
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
	if cc == "" || strings.EqualFold(cc, "auto") {
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
