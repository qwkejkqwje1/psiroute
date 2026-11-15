package main

import (
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

// iconToImage decodes iconImage's DIB back into an image.
func iconToImage(b []byte) *image.NRGBA {
	size := int(binary.LittleEndian.Uint32(b[4:]))
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	px := b[40:]
	for y := 0; y < size; y++ {
		row := size - 1 - y
		for x := 0; x < size; x++ {
			o := (row*size + x) * 4
			img.SetNRGBA(x, y, color.NRGBA{px[o+2], px[o+1], px[o], px[o+3]})
		}
	}
	return img
}

func TestIconImage(t *testing.T) {
	green := iconColor("connected")
	for _, size := range []int{16, 32, 48} {
		b := iconImage(size, green)
		maskRow := (size + 31) / 32 * 4
		if len(b) != 40+size*size*4+maskRow*size {
			t.Fatalf("%d px: len %d", size, len(b))
		}
		if binary.LittleEndian.Uint32(b[0:]) != 40 || int(binary.LittleEndian.Uint32(b[4:])) != size ||
			int(binary.LittleEndian.Uint32(b[8:])) != 2*size || binary.LittleEndian.Uint16(b[14:]) != 32 {
			t.Fatalf("%d px: bad header % x", size, b[:16])
		}
		img := iconToImage(b)
		if a := img.NRGBAAt(0, 0).A; a != 0 {
			t.Fatalf("%d px: corner alpha %d", size, a)
		}
		mask := b[40+size*size*4:]
		if mask[(size-1)*maskRow]&0x80 == 0 { // top-left pixel = last (bottom-up) mask row
			t.Fatalf("%d px: corner not transparent in the mask", size)
		}
		if mask[(size/2)*maskRow+(size/2)/8]&(0x80>>((size/2)%8)) != 0 {
			t.Fatalf("%d px: centre masked out", size)
		}
		if c := img.NRGBAAt(size*37/100, size/2); c != (color.NRGBA{255, 255, 255, 255}) {
			t.Fatalf("%d px: stem of the P = %v, want white", size, c)
		}
		if c := img.NRGBAAt(size*3/4, size*3/4); c != (color.NRGBA{0x2e, 0xa4, 0x4f, 255}) {
			t.Fatalf("%d px: disc = %v, want the state colour", size, c)
		}
		if size >= 32 {
			if c := img.NRGBAAt(size*47/100, size*41/100); c != (color.NRGBA{0x2e, 0xa4, 0x4f, 255}) {
				t.Fatalf("%d px: hole of the P = %v, want the state colour", size, c)
			}
		}
	}
	// PSIROUTE_ICON_PNG=dir: write the icons (and 8x previews) to look at.
	if dir := os.Getenv("PSIROUTE_ICON_PNG"); dir != "" {
		for _, st := range []string{"connected", "connecting", "error", "stopped"} {
			for _, size := range []int{16, 32} {
				src := iconToImage(iconImage(size, iconColor(st)))
				big := image.NewNRGBA(image.Rect(0, 0, size*8, size*8))
				for y := 0; y < size*8; y++ {
					for x := 0; x < size*8; x++ {
						big.SetNRGBA(x, y, src.NRGBAAt(x/8, y/8))
					}
				}
				for name, im := range map[string]image.Image{"": src, "-x8": big} {
					f, err := os.Create(filepath.Join(dir, st+"-"+itoa(size)+name+".png"))
					if err != nil {
						t.Fatal(err)
					}
					_ = png.Encode(f, im)
					f.Close()
				}
			}
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

func TestMemHelpers(t *testing.T) {
	if got := mbText(3<<20 + 600<<10); got != "4 МБ" {
		t.Fatalf("mbText = %q", got)
	}
	if got := mbText(0); got != "0 МБ" {
		t.Fatalf("mbText(0) = %q", got)
	}
	if iconColor("nonsense") != iconColors["stopped"] || iconColor("reconnecting") != iconColors["connecting"] {
		t.Fatal("iconColor mapping")
	}
	m := memView()
	if m.App == 0 || m.Go == 0 || m.Total != m.App+m.Workers+m.Window {
		t.Fatalf("memView = %+v", m)
	}
	if again := memView(); again != m {
		t.Fatalf("memView not cached: %+v vs %+v", again, m)
	}
}
