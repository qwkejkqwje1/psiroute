package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Offline tests for Step 4 (Tuning & DNS), Step 5 (Client Identity & Tactics),
// and Step 6 (Connection State UX & HTTP API).

func TestStep4_TuningPresetsAndDNSPerCarrier(t *testing.T) {
	a := testApp(t)
	p := a.psi
	p.netKeyFunc = func() string { return "net-tuning-test" }

	// Poisoned DNS preflight report
	p.mu.Lock()
	p.lastPreflight = &CarrierReport{NetKey: "net-tuning-test", DNSPoisoned: true}
	p.mu.Unlock()

	directStrat, _ := strategyByID("meek")
	warpStrat, _ := strategyByID("via-warp")

	// 1. Fast preset on direct carrier with poisoned DNS -> mult 1.0, pool 10, alt DNS enabled
	setCfg(a, func(c *Config) { c.Psiphon.Preset = PresetFast })
	cfgFast := p.configFor(directStrat, 90)
	if cfgFast.NetworkLatencyMultiplier != 1.0 || cfgFast.ConnectionWorkerPoolSize != 10 {
		t.Fatalf("fast direct config: mult=%v pool=%d, want 1.0 and 10", cfgFast.NetworkLatencyMultiplier, cfgFast.ConnectionWorkerPoolSize)
	}
	if len(cfgFast.DNSResolverAlternateServers) == 0 || cfgFast.DNSResolverPreferAlternateServerProbability == nil || *cfgFast.DNSResolverPreferAlternateServerProbability != 1.0 {
		t.Fatalf("expected alternate DNS servers when DNSPoisoned=true: %+v", cfgFast.DNSResolverAlternateServers)
	}

	// 2. Balanced preset on WARP -> mult 2.0, pool 12, stagger 150, UpstreamProxyAllowAllServerEntrySources=true
	setCfg(a, func(c *Config) { c.Psiphon.Preset = PresetBalanced })
	cfgWarp := p.configFor(warpStrat, 90)
	if cfgWarp.NetworkLatencyMultiplier != 2.0 || cfgWarp.ConnectionWorkerPoolSize != 12 || cfgWarp.StaggerConnectionWorkersMilliseconds != 150 {
		t.Fatalf("balanced warp config: mult=%v pool=%d stagger=%d", cfgWarp.NetworkLatencyMultiplier, cfgWarp.ConnectionWorkerPoolSize, cfgWarp.StaggerConnectionWorkersMilliseconds)
	}
	if cfgWarp.UpstreamProxyAllowAllServerEntrySources == nil || !*cfgWarp.UpstreamProxyAllowAllServerEntrySources {
		t.Fatal("expected UpstreamProxyAllowAllServerEntrySources=true for WARP")
	}

	// 3. Patient preset on WARP -> mult 3.0, pool 16, timeout >= 150 s
	setCfg(a, func(c *Config) { c.Psiphon.Preset = PresetPatient })
	cfgPatient := p.configFor(warpStrat, 90)
	if cfgPatient.NetworkLatencyMultiplier != 3.0 || cfgPatient.ConnectionWorkerPoolSize != 16 {
		t.Fatalf("patient warp config: mult=%v pool=%d", cfgPatient.NetworkLatencyMultiplier, cfgPatient.ConnectionWorkerPoolSize)
	}
	if cfgPatient.EstablishTunnelTimeoutSeconds == nil || *cfgPatient.EstablishTunnelTimeoutSeconds < 150 {
		t.Fatalf("patient timeout = %v, want >= 150", cfgPatient.EstablishTunnelTimeoutSeconds)
	}
}

func TestStep5_ClientIdentityValidationRoundTripAndTacticsNotice(t *testing.T) {
	a := testApp(t)
	p := a.psi

	// Reject invalid hex IDs
	if err := validateHexID16("1234"); err == nil {
		t.Fatal("expected error for short hex ID")
	}
	if err := validateHexID16("GGGGGGGGGGGGGGGG"); err == nil {
		t.Fatal("expected error for non-hex ID")
	}
	if err := validateHexID16("0123456789ABCDEF"); err != nil {
		t.Fatalf("unexpected error for valid 16-hex ID: %v", err)
	}

	// Invalid ID via setKey is ignored; valid ID persists and flows into configFor
	a.cfg.setKey("psiphon.propagation_channel_id", "BAD")
	if a.cfg.values()["psiphon.propagation_channel_id"] != "" {
		t.Fatalf("invalid propagation_channel_id should not be accepted")
	}
	a.cfg.setKey("psiphon.propagation_channel_id", "a1b2c3d4e5f60718")
	a.cfg.setKey("psiphon.sponsor_id", "1122334455667788")
	a.cfg.setKey("psiphon.client_platform", "Windows_10_PsiRouteCustom")

	s, _ := strategyByID("meek")
	cfg := p.configFor(s, 90)
	if cfg.PropagationChannelId != "A1B2C3D4E5F60718" || cfg.SponsorId != "1122334455667788" || cfg.ClientPlatform != "Windows_10_PsiRouteCustom" {
		t.Fatalf("identity did not round-trip to psiphon.Config: prop=%q sponsor=%q platform=%q", cfg.PropagationChannelId, cfg.SponsorId, cfg.ClientPlatform)
	}

	// Before tactics notice: state reports tactics_applied=false and honest hint
	st0 := p.connectionStateView()
	if st0["tactics_applied"] != false || st0["tactics_hint"] == "" {
		t.Fatalf("expected tactics_applied=false with hint: %+v", st0)
	}

	// Simulate tunnel-core Info notice with tactics applied tag (secret-like hex tag gets masked)
	noticeJSON := `{"noticeType":"Info","data":{"message":"applied 5 parameters with tag 'deadbeef0123456789abcdef0123456789abcdef'"}}`
	p.onNotice([]byte(noticeJSON))

	st1 := p.connectionStateView()
	if st1["tactics_applied"] != true {
		t.Fatalf("expected tactics_applied=true after notice: %+v", st1)
	}
	if statusStr, _ := st1["tactics_status"].(string); strings.Contains(statusStr, "deadbeef") {
		t.Fatalf("tactics_status leaked raw long hex tag: %q", statusStr)
	}
}

func TestStep6_AllDiagCodesHaveMessageAndActionsAndHTTPAPI(t *testing.T) {
	codes := []string{
		DiagNoNetwork, DiagClockSkew, DiagDNSPoisoned, DiagListHostBlocked,
		DiagNoSeed, DiagCarrierThrottled16KB, DiagUDPBlocked, DiagHandshakeReset,
		DiagAllProtocolsTimeout, DiagTunnelUnstable,
	}
	for _, code := range codes {
		info := diagInfoForCode(code)
		acts := actionsForDiagCode(code)
		if info.Message == "" || len(acts) == 0 {
			t.Fatalf("code %q missing message or actions: info=%+v acts=%+v", code, info, acts)
		}
	}

	a := testApp(t)
	// Test GET /api/psiphon/state
	rec := apiCall(t, a, "GET", "/api/psiphon/state", true, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/psiphon/state status=%d: %s", rec.Code, rec.Body.String())
	}
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"stage", "carrier_ranking", "seed_health", "tactics_applied", "actions", "timeline", "counters"} {
		if _, ok := st[key]; !ok {
			t.Fatalf("/api/psiphon/state missing key %q", key)
		}
	}

	// Test POST /api/psiphon/action retry_patient
	recAct := apiCall(t, a, "POST", "/api/psiphon/action", true, `{"action":"retry_patient"}`)
	if recAct.Code != http.StatusOK {
		t.Fatalf("POST /api/psiphon/action retry_patient status=%d: %s", recAct.Code, recAct.Body.String())
	}
	if a.cfg.values()["psiphon.preset"] != PresetPatient {
		t.Fatalf("preset after retry_patient = %v, want %q", a.cfg.values()["psiphon.preset"], PresetPatient)
	}

	// Unknown action returns 400
	recBad := apiCall(t, a, "POST", "/api/psiphon/action", true, `{"action":"nonexistent"}`)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("unknown action status = %d, want 400", recBad.Code)
	}
}
