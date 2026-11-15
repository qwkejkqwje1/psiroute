//go:build !windows

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

// Off Windows the platform functions are stubs.
func TestPlatformStubs(t *testing.T) {
	if err := setSystemProxy("127.0.0.1:1080", true); !errors.Is(err, errWindowsOnly) {
		t.Fatalf("setSystemProxy = %v", err)
	}
	if err := setAutostart(true); !errors.Is(err, errWindowsOnly) {
		t.Fatalf("setAutostart = %v", err)
	}
	if autostartEnabled() {
		t.Fatal("autostartEnabled must be false off Windows")
	}
	hideConsole(nil)
	app := testApp(t)
	if err := app.setSysProxy(true); !errors.Is(err, errWindowsOnly) {
		t.Fatalf("App.setSysProxy = %v", err)
	}
	if app.uiURL() == "" || !strings.HasPrefix(app.uiURL(), "http://127.0.0.1:") {
		t.Fatalf("uiURL = %q", app.uiURL())
	}
	if got := appForConn(&net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1}); got != "8.8.8.8" {
		t.Fatalf("appForConn(remote) = %q", got)
	}
	if got := appForConn(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}); got != "" {
		t.Fatalf("appForConn(loopback) = %q", got)
	}
	if d := dataDirFor(); d == "" {
		t.Fatal("dataDirFor returned empty")
	}
	// runDesktop with a cancelled context returns at once (openNow=false: no browser)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runDesktop(ctx, app, os.TempDir(), false)
	// state() assembles without the engine
	st := app.state()
	if m, ok := st["mem"].(memSnap); !ok || m.App == 0 || m.Total < m.App {
		t.Fatalf("state mem = %+v", st["mem"])
	}
	if st["version"] != version || st["mode"] != "psiphon" {
		t.Fatalf("state = %v", st)
	}
}
