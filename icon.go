package main

import (
	"encoding/binary"
	"math"
)

// Tray and window icons are drawn at runtime: the exe carries no resources,
// and a generated icon can show the connection state by its colour.

var iconColors = map[string]uint32{
	"connected":    0x2ea44f,
	"connecting":   0x2783de,
	"reconnecting": 0x2783de,
	"error":        0xd24a3d,
	"stopped":      0x8e8b86,
}

func iconColor(state string) uint32 {
	if c, ok := iconColors[state]; ok {
		return c
	}
	return iconColors["stopped"]
}

// inP: a bold "P" in unit coordinates (v grows downwards).
func inP(u, v float64) bool {
	const cx, cy, ro, ri = 0.50, 0.41, 0.18, 0.075
	if u >= 0.31 && u <= 0.43 && v >= 0.23 && v <= 0.77 {
		return true // stem
	}
	outer := (u >= cx && math.Hypot(u-cx, v-cy) <= ro) || (u >= 0.31 && u < cx && math.Abs(v-cy) <= ro)
	hole := (u >= cx && math.Hypot(u-cx, v-cy) <= ri) || (u >= 0.43 && u < cx && math.Abs(v-cy) <= ri)
	return outer && !hole
}

// iconCoverage: how much of pixel (x, y) of a size×size icon the disc and the
// white "P" cover (4×4 supersampling, for smooth edges).
func iconCoverage(size, x, y int) (disc, glyph float64) {
	const n = 4
	for sy := 0; sy < n; sy++ {
		for sx := 0; sx < n; sx++ {
			u := (float64(x) + (float64(sx)+0.5)/n) / float64(size)
			v := (float64(y) + (float64(sy)+0.5)/n) / float64(size)
			if math.Hypot(u-0.5, v-0.5) > 0.47 {
				continue
			}
			disc++
			if inP(u, v) {
				glyph++
			}
		}
	}
	return disc / (n * n), glyph / (n * n)
}

// iconImage returns the icon as a 32-bit DIB in the .ico image layout
// (BITMAPINFOHEADER, bottom-up BGRA rows with straight alpha, then the AND
// mask), which is what CreateIconFromResourceEx takes.
func iconImage(size int, rgb uint32) []byte {
	maskRow := (size + 31) / 32 * 4
	colour := size * size * 4
	img := make([]byte, 40+colour+maskRow*size)
	binary.LittleEndian.PutUint32(img[0:], 40)
	binary.LittleEndian.PutUint32(img[4:], uint32(size))
	binary.LittleEndian.PutUint32(img[8:], uint32(size*2)) // colour + mask
	binary.LittleEndian.PutUint16(img[12:], 1)
	binary.LittleEndian.PutUint16(img[14:], 32)
	binary.LittleEndian.PutUint32(img[20:], uint32(colour+maskRow*size))
	r, g, b := float64(rgb>>16&0xff), float64(rgb>>8&0xff), float64(rgb&0xff)
	px, mask := img[40:40+colour], img[40+colour:]
	for y := 0; y < size; y++ {
		row := size - 1 - y // bottom-up
		for x := 0; x < size; x++ {
			d, gl := iconCoverage(size, x, y)
			if d == 0 {
				mask[row*maskRow+x/8] |= 0x80 >> (x % 8) // transparent
				continue
			}
			w := gl / d // share of white in the covered part
			o := (row*size + x) * 4
			px[o+0] = byte(b + (255-b)*w + 0.5)
			px[o+1] = byte(g + (255-g)*w + 0.5)
			px[o+2] = byte(r + (255-r)*w + 0.5)
			px[o+3] = byte(255*d + 0.5)
		}
	}
	return img
}

// flagBands returns 3 horizontal or vertical color bands (top, mid, bot, vertical) for a 2-letter country code.
func flagIconColors(cc string) (c1, c2, c3 uint32, vert bool, ok bool) {
	switch cc {
	case "DE", "de":
		return 0x111111, 0xDD0000, 0xFFCE00, false, true
	case "NL", "nl":
		return 0xAE1C28, 0xFFFFFF, 0x21468B, false, true
	case "FI", "fi":
		return 0xFFFFFF, 0x003580, 0xFFFFFF, false, true
	case "SE", "se":
		return 0x006AA7, 0xFECC02, 0x006AA7, false, true
	case "FR", "fr":
		return 0x002395, 0xFFFFFF, 0xED2939, true, true
	case "IT", "it":
		return 0x009246, 0xFFFFFF, 0xCE2B37, true, true
	case "BE", "be":
		return 0x111111, 0xFAE042, 0xED2939, true, true
	case "IE", "ie":
		return 0x169B62, 0xFFFFFF, 0xFF883E, true, true
	case "RO", "ro":
		return 0x002B7F, 0xFCD116, 0xCE1126, true, true
	case "PL", "pl":
		return 0xFFFFFF, 0xFFFFFF, 0xDC143C, false, true
	case "AT", "at":
		return 0xED2939, 0xFFFFFF, 0xED2939, false, true
	case "LV", "lv":
		return 0x9E3039, 0xFFFFFF, 0x9E3039, false, true
	case "EE", "ee":
		return 0x0072CE, 0x111111, 0xFFFFFF, false, true
	case "LT", "lt":
		return 0xFDB913, 0x006A44, 0xC1272D, false, true
	case "BG", "bg":
		return 0xFFFFFF, 0x00966E, 0xD62612, false, true
	case "HU", "hu":
		return 0xCE2939, 0xFFFFFF, 0x477050, false, true
	case "ES", "es":
		return 0xAA151B, 0xF1BF00, 0xAA151B, false, true
	case "RU", "ru":
		return 0xFFFFFF, 0x0039A6, 0xD52B1E, false, true
	case "US", "us":
		return 0x3C3B6E, 0xFFFFFF, 0xB22234, false, true
	case "GB", "gb", "UK", "uk":
		return 0x012169, 0xC8102E, 0x012169, false, true
	case "CA", "ca":
		return 0xFF0000, 0xFFFFFF, 0xFF0000, true, true
	case "CH", "ch":
		return 0xD52B1E, 0xFFFFFF, 0xD52B1E, false, true
	case "JP", "jp":
		return 0xFFFFFF, 0xBC002D, 0xFFFFFF, false, true
	case "SG", "sg":
		return 0xEF3340, 0xEF3340, 0xFFFFFF, false, true
	case "CZ", "cz":
		return 0xFFFFFF, 0x11457E, 0xD7141A, false, true
	case "NO", "no", "DK", "dk":
		return 0xBA0C2F, 0x00205B, 0xBA0C2F, false, true
	case "TR", "tr":
		return 0xE30A17, 0xFFFFFF, 0xE30A17, false, true
	case "KZ", "kz":
		return 0x00AFCA, 0xFFEC2D, 0x00AFCA, false, true
	}
	return 0, 0, 0, false, false
}

// iconFlagImage renders a circular badge with an emerald ring and a large country flag in the center
// for the taskbar (Пуск) and system tray when Psiphon is connected.
func iconFlagImage(size int, borderRGB uint32, cc string) []byte {
	c1, c2, c3, vert, ok := flagIconColors(cc)
	if !ok {
		return iconImage(size, borderRGB)
	}
	maskRow := (size + 31) / 32 * 4
	colour := size * size * 4
	img := make([]byte, 40+colour+maskRow*size)
	binary.LittleEndian.PutUint32(img[0:], 40)
	binary.LittleEndian.PutUint32(img[4:], uint32(size))
	binary.LittleEndian.PutUint32(img[8:], uint32(size*2))
	binary.LittleEndian.PutUint16(img[12:], 1)
	binary.LittleEndian.PutUint16(img[14:], 32)
	binary.LittleEndian.PutUint32(img[20:], uint32(colour+maskRow*size))
	px, mask := img[40:40+colour], img[40+colour:]

	for y := 0; y < size; y++ {
		row := size - 1 - y
		for x := 0; x < size; x++ {
			u := (float64(x) + 0.5) / float64(size)
			v := (float64(y) + 0.5) / float64(size)
			dist := math.Hypot(u-0.5, v-0.5)
			if dist > 0.48 {
				mask[row*maskRow+x/8] |= 0x80 >> (x % 8)
				continue
			}
			var col uint32
			if dist > 0.39 {
				col = borderRGB
			} else {
				coord := v
				if vert {
					coord = u
				}
				// Map inner circle [0.11..0.89] into 3 bands
				norm := (coord - 0.14) / 0.72
				if norm < 0.333 {
					col = c1
				} else if norm < 0.666 {
					col = c2
				} else {
					col = c3
				}
			}
			alpha := 1.0
			if dist > 0.44 {
				alpha = (0.48 - dist) / 0.04
			}
			o := (row*size + x) * 4
			px[o+0] = byte(col & 0xff)
			px[o+1] = byte((col >> 8) & 0xff)
			px[o+2] = byte((col >> 16) & 0xff)
			px[o+3] = byte(255*alpha + 0.5)
		}
	}
	return img
}
