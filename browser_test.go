package main

import (
	"strings"
	"testing"
)

func TestBrowserHostPort(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:1080": "127.0.0.1:1080",
		"0.0.0.0:1081":   "127.0.0.1:1081",
		"[::]:1082":      "127.0.0.1:1082",
		":1083":          "127.0.0.1:1083",
		"[::1]:1084":     "[::1]:1084",
	}
	for in, want := range cases {
		if _, got := browserHostPort(in); got != want {
			t.Errorf("browserHostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBrowserPAC(t *testing.T) {
	pac := browserPAC("0.0.0.0:1080")
	for _, s := range []string{"function FindProxyForURL", `"DIRECT"`, "SOCKS5 127.0.0.1:1080; PROXY 127.0.0.1:1080"} {
		if !strings.Contains(pac, s) {
			t.Errorf("PAC has no %q", s)
		}
	}
}
