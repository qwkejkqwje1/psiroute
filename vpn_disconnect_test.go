package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDisconnectVPNPreventsAutoRestartAndRespectsKillSwitch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	a := NewApp(ctx, cancel, dir+"/psiroute.json", dir)
	defer a.Shutdown()

	a.cfg.mu.Lock()
	a.cfg.Routing.Mode = "psiphon"
	a.cfg.Routing.KillSwitch = false
	a.cfg.mu.Unlock()

	// Before manual disconnect, psiphon mode routes to obPsiphon.
	ord, _ := a.router.planForProto("tcp", "example.com", "", 443, "chrome.exe")
	if len(ord) == 0 || ord[0] != obPsiphon {
		t.Fatalf("expected [psiphon] before manual disconnect, got %v", ord)
	}

	// Simulate manual disconnect via Power button (/api/psiphon/stop).
	req := httptest.NewRequest(http.MethodPost, "/api/psiphon/stop", nil)
	req.Header.Set("X-Psiroute", a.token)
	rec := httptest.NewRecorder()
	a.api(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/psiphon/stop status = %d: %s", rec.Code, rec.Body.String())
	}

	if !a.psi.isUserStopped() {
		t.Fatal("expected userStopped=true after /api/psiphon/stop")
	}

	// With KillSwitch OFF, manual disconnect falls back cleanly to direct (no internet outage).
	ord, rule := a.router.planForProto("tcp", "example.com", "", 443, "chrome.exe")
	if len(ord) != 1 || ord[0] != obDirect {
		t.Fatalf("expected [direct] after manual disconnect without KillSwitch, got %v (%q)", ord, rule)
	}

	// Dialer must NOT auto-restart Psiphon when userStopped is true.
	d := a.router.dialer(obPsiphon)
	if _, err := d(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected error dialing psiphon while userStopped=true")
	}
	if a.psi.running() {
		t.Fatal("router dialer auto-restarted Psiphon after manual DisconnectVPN!")
	}

	// With KillSwitch ON, manual disconnect must still block VPN traffic.
	a.cfg.mu.Lock()
	a.cfg.Routing.KillSwitch = true
	a.cfg.mu.Unlock()
	a.router.InvalidateRules()
	ord, _ = a.router.planForProto("tcp", "example.com", "", 443, "chrome.exe")
	if len(ord) != 1 || ord[0] != obBlock {
		t.Fatalf("expected [block] when KillSwitch=true and VPN disconnected, got %v", ord)
	}
}
