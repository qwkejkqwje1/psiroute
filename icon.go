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
