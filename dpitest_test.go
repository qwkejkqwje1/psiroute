package main

import "testing"

func TestDpiNormSites(t *testing.T) {
	got := dpiNormSites([]string{" https://YouTube.com/ ", "youtube.com", "", "a b", "x.com"})
	if len(got) != 2 || got[0] != "YouTube.com" || got[1] != "x.com" {
		t.Fatalf("got %v", got)
	}
	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, string(rune('a'+i%26))+string(rune('a'+i/26))+".com")
	}
	if n := len(dpiNormSites(many)); n != dpiTestMaxSites {
		t.Fatalf("cap: %d", n)
	}
}

func TestDpiSplitSite(t *testing.T) {
	cases := []struct{ in, host, path string }{
		{"speed.cloudflare.com/__down?bytes=1", "speed.cloudflare.com", "/__down?bytes=1"},
		{"x.com?a=1", "x.com", "/?a=1"},
		{"Host.example:8443", "host.example", "/"},
		{"discord.com", "discord.com", "/"},
	}
	for _, c := range cases {
		h, p := dpiSplitSite(c.in)
		if h != c.host || p != c.path {
			t.Fatalf("%s: %s %s", c.in, h, p)
		}
	}
}

func TestDpiBest(t *testing.T) {
	scores := []dpiScore{
		{ID: "none", OK: 5},
		{ID: "a", OK: 2, Ms: 100},
		{ID: "b", OK: 2, Ms: 50},
		{ID: "c", OK: 0},
	}
	if b := dpiBest(scores); b != "b" {
		t.Fatalf("best %q", b)
	}
	if b := dpiBest([]dpiScore{{ID: "none", OK: 3}, {ID: "a"}}); b != "" {
		t.Fatalf("best %q", b)
	}
}

func TestDpiScores(t *testing.T) {
	id := obfsMethods[0].id
	cells := []dpiCell{
		{Site: "a", Method: id, OK: true, Ms: 100},
		{Site: "b", Method: id, OK: true, Ms: 300},
		{Site: "c", Method: id},
		{Site: "a", Method: "none"},
	}
	for _, s := range dpiScores(cells) {
		switch s.ID {
		case id:
			if s.OK != 2 || s.Fail != 1 || s.Ms != 200 {
				t.Fatalf("%+v", s)
			}
		case "none":
			if s.Fail != 1 {
				t.Fatalf("%+v", s)
			}
		}
	}
}
