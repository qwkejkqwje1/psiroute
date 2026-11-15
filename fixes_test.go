package main

import (
	"net"
	"testing"
)

func TestHostMatchesIPExact(t *testing.T) {
	cases := []struct {
		host, pat string
		want      bool
	}{
		{"a.example.com", "example.com", true},
		{"example.com.", "*.example.com", true},
		{"badexample.com", "example.com", false},
		{"1.2.3.4", "2.3.4", false},
		{"1.2.3.4", "1.2.3.4", true},
		{"x.com", "", false},
	}
	for _, c := range cases {
		if got := hostMatches(c.host, c.pat); got != c.want {
			t.Errorf("hostMatches(%q,%q)=%v want %v", c.host, c.pat, got, c.want)
		}
	}
}

func TestParseCIDRCachedBareIP(t *testing.T) {
	n := parseCIDRCached("10.0.0.1")
	if n == nil || !n.Contains(net.ParseIP("10.0.0.1")) || n.Contains(net.ParseIP("10.0.0.2")) {
		t.Fatalf("bare IP must be /32, got %v", n)
	}
	if parseCIDRCached("garbage") != nil {
		t.Fatal("invalid CIDR must be nil")
	}
}

// The reported bug: a foreign program holds the UI port -> must fall back.
func TestListenFallbackPortBusy(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer busy.Close()
	addr := busy.Addr().String()
	ln, err := listenFallback(addr, 20)
	if err != nil {
		t.Fatalf("fallback failed: %v", err)
	}
	defer ln.Close()
	if ln.Addr().String() == addr {
		t.Fatal("got the busy address")
	}
	host, _, _ := net.SplitHostPort(ln.Addr().String())
	if host != "127.0.0.1" {
		t.Fatalf("fallback must stay on loopback, got %s", host)
	}
}

func TestIsPsirouteAtForeign(t *testing.T) {
	if isPsirouteAt("") {
		t.Fatal("empty addr")
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nprom"))
			c.Close()
		}
	}()
	if isPsirouteAt(ln.Addr().String()) {
		t.Fatal("foreign server must not be detected as psiroute")
	}
}

func TestEqConst(t *testing.T) {
	if !eqConst("abc", "abc") || eqConst("abc", "abd") || eqConst("", "a") {
		t.Fatal("eqConst")
	}
}

func TestPsiRSLURLsBase64(t *testing.T) {
	u := psiRSLURLs()
	if len(u) < 1 || u[0].URL == psiRSLURL {
		t.Fatal("RSL URL must be base64-encoded")
	}
}
