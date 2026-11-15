package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPsiOrderByNetworkHistoryAndNetworkSwitch(t *testing.T) {
	a := testApp(t)
	p := a.psi
	curNet := "net-home-fiber"
	p.netKeyFunc = func() string { return curNet }

	enabled := p.enabled()
	if len(enabled) < 4 {
		t.Fatalf("expected at least 4 enabled strategies, got %d", len(enabled))
	}

	// On home fiber, "quic" connects fast (800 ms) and holds for 30 minutes
	for i := 0; i < 4; i++ {
		p.recordStrategyAttempt("net-home-fiber", "quic")
		p.recordStrategySuccess("net-home-fiber", "quic", 800)
		p.recordStrategyLifetime("net-home-fiber", "quic", 30*time.Minute)
	}
	// Meanwhile "auto" failed 3 times on home fiber
	for i := 0; i < 3; i++ {
		p.recordStrategyAttempt("net-home-fiber", "auto")
	}

	// On mobile hotspot, "quic" fails, while "meek" succeeds reliably
	for i := 0; i < 4; i++ {
		p.recordStrategyAttempt("net-mobile-lte", "quic")
	}
	for i := 0; i < 4; i++ {
		p.recordStrategyAttempt("net-mobile-lte", "meek")
		p.recordStrategySuccess("net-mobile-lte", "meek", 1400)
		p.recordStrategyLifetime("net-mobile-lte", "meek", 20*time.Minute)
	}

	// 1. Verify order on home fiber puts "quic" #1
	homeOrder := p.order(enabled, "")
	if homeOrder[0].ID != "quic" {
		t.Fatalf("home network #1 strategy = %q, want quic (order: %+v)", homeOrder[0].ID, homeOrder)
	}

	// 2. Switch network to mobile LTE -> order immediately adapts and puts "meek" #1
	curNet = "net-mobile-lte"
	mobileOrder := p.order(enabled, "")
	if mobileOrder[0].ID != "meek" {
		t.Fatalf("mobile network #1 strategy = %q, want meek (order: %+v)", mobileOrder[0].ID, mobileOrder)
	}

	// 3. Verify persistence in psiroute-strategies.json across a fresh Psi instance
	p2 := newPsi(a, a.dataDir)
	p2.netKeyFunc = func() string { return "net-home-fiber" }
	reloadedHome := p2.order(enabled, "")
	if reloadedHome[0].ID != "quic" {
		t.Fatalf("reloaded home #1 strategy = %q, want quic", reloadedHome[0].ID)
	}
}

func TestPsiBuildRoundZeroPlanAndProtocolRace(t *testing.T) {
	a := testApp(t)
	p := a.psi
	ordered := p.enabled()
	plan := p.buildRoundZeroPlan(ordered)
	if len(plan) < 2 {
		t.Fatalf("expected round 0 plan with >= 2 steps, got %d", len(plan))
	}
	if plan[0].ID != ordered[0].ID {
		t.Fatalf("plan[0] = %q, want %q", plan[0].ID, ordered[0].ID)
	}
	if plan[1].ID != "race-direct" || len(plan[1].CustomProtos) < 5 {
		t.Fatalf("plan[1] = %+v, want combined race-direct with merged protocols", plan[1])
	}
	if bestStrategyShortTimeout+combinedRaceTimeout > 60 {
		t.Fatalf("first round total direct budget = %d s, must be <= 60 s", bestStrategyShortTimeout+combinedRaceTimeout)
	}
}

func TestPsiMultiTargetPingPartialAndTotalFailure(t *testing.T) {
	a := testApp(t)
	p := a.psi

	// Case 1: first two targets fail, third target succeeds -> ping succeeds!
	calls := 0
	p.pingTargetFunc = func(ctx context.Context, host, path string) (int, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("connection reset")
		}
		return 42, nil
	}
	ms, err := p.ping(context.Background())
	if err != nil || ms != 42 || calls != 3 {
		t.Fatalf("partial failure ping: ms=%d err=%v calls=%d, want ms=42 err=nil calls=3", ms, err, calls)
	}

	// Case 2: all targets fail -> ping returns error
	p.pingTargetFunc = func(ctx context.Context, host, path string) (int, error) {
		return 0, errors.New("timeout")
	}
	if _, err := p.ping(context.Background()); err == nil {
		t.Fatal("expected ping to fail when all targets fail")
	}
}

func TestPsiNetworkIDPreservedAndBoundToNetwork(t *testing.T) {
	a := testApp(t)
	p := a.psi
	curNet := "net-eth0-home"
	p.netKeyFunc = func() string { return curNet }

	id1 := p.netID()
	if id1 != "net-eth0-home" {
		t.Fatalf("netID = %q, want net-eth0-home", id1)
	}
	// Automatic config generation must keep the exact same NetworkID
	cfg1 := p.configFor(psiStrategies[0], 20)
	cfg2 := p.configFor(psiStrategies[1], 35)
	if cfg1.NetworkID != id1 || cfg2.NetworkID != id1 {
		t.Fatalf("configFor changed NetworkID: %q vs %q", cfg1.NetworkID, cfg2.NetworkID)
	}

	// Switching real network changes NetworkID to match the new network
	curNet = "net-wlan0-cafe"
	if got := p.netID(); got != "net-wlan0-cafe" {
		t.Fatalf("netID after network change = %q, want net-wlan0-cafe", got)
	}

	// Explicit manual rotation appends manual epoch suffix
	p.rotateNetID()
	if got := p.netID(); got != "net-wlan0-cafe-m1" {
		t.Fatalf("netID after manual rotate = %q, want net-wlan0-cafe-m1", got)
	}

	// Баг №2: перезапуск newPsi должен восстанавливать manualEpoch из файла psiroute-netid
	pRestarted := newPsi(a, a.dataDir)
	pRestarted.netKeyFunc = func() string { return curNet }
	if got := pRestarted.netID(); got != "net-wlan0-cafe-m1" {
		t.Fatalf("netID after restart = %q, want net-wlan0-cafe-m1 (manualEpoch must persist)", got)
	}
}

func TestPsiFailureDiagnosticsAndStatsAPI(t *testing.T) {
	a := testApp(t)
	p := a.psi
	p.netKeyFunc = func() string { return "net-test" }

	// 1. Offline direct network -> classified as no_network
	p.directAliveFunc = func(ctx context.Context) bool { return false }
	code, _, _ := p.classifyFailure(context.Background(), psiStrategies[0], errTimeout)
	if code != "no_network" {
		t.Fatalf("classifyFailure offline = %q, want no_network", code)
	}

	// 2. Direct network alive, 0 candidates -> classified as no_candidates
	p.directAliveFunc = func(ctx context.Context) bool { return true }
	p.candidates = 0
	code, _, _ = p.classifyFailure(context.Background(), psiStrategies[0], errTimeout)
	if code != "no_candidates" {
		t.Fatalf("classifyFailure 0 candidates = %q, want no_candidates", code)
	}

	// 3. Candidate servers available, timeout -> all_timeout
	p.candidates = 12
	code, _, _ = p.classifyFailure(context.Background(), psiStrategies[0], errTimeout)
	if code != "all_timeout" {
		t.Fatalf("classifyFailure timeout = %q, want all_timeout", code)
	}

	// 4. Handshake reset / unstable -> handshake_reset
	code, _, _ = p.classifyFailure(context.Background(), psiStrategies[0], errUnstable)
	if code != "handshake_reset" {
		t.Fatalf("classifyFailure unstable = %q, want handshake_reset", code)
	}

	// 5. Баг №5: мусорные hex-строки отклоняются валидатором protocol.DecodeServerEntryFields (400 Bad Request)
	badHex := strings.Repeat("ab", 32)
	recBad := apiCall(t, a, "POST", "/api/psiphon/server-entries", true, `{"data":"`+badHex+`"}`)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("garbage server entry must return 400, got %d: %s", recBad.Code, recBad.Body.String())
	}

	// Валидная запись в формате psiphon-tunnel-core успешно проходит DecodeServerEntryFields и дедуплицируется по IP
	validEntryRaw := `198.51.100.10 80 US web {"ipAddress":"198.51.100.10","webServerPort":"80","webServerSecret":"sec123","webServerCertificate":"cert","sshPort":22,"sshPassword":"pw","sshHostKey":"hk","sshObfuscatedPort":443,"sshObfuscatedKey":"obkey","region":"US","capabilities":["OSSH","TLS-OSSH","UNFRONTED-MEEK"]}`
	hexEntry := hex.EncodeToString([]byte(validEntryRaw))
	rec := apiCall(t, a, "POST", "/api/psiphon/server-entries", true, `{"data":"`+hexEntry+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/psiphon/server-entries status=%d: %s", rec.Code, rec.Body.String())
	}
	// Повторная отправка того же сервера учитывается как дубликат
	recDup := apiCall(t, a, "POST", "/api/psiphon/server-entries", true, `{"data":"`+hexEntry+`"}`)
	if recDup.Code != http.StatusOK {
		t.Fatalf("duplicate server entry status=%d: %s", recDup.Code, recDup.Body.String())
	}

	rec2 := apiCall(t, a, "GET", "/api/psiphon/stats", true, "")
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET /api/psiphon/stats status=%d: %s", rec2.Code, rec2.Body.String())
	}
	var st map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st["net_key"] != "net-test" || int(st["imported_entries"].(float64)) != 1 {
		t.Fatalf("unexpected /api/psiphon/stats: %+v", st)
	}
}

// TestPsiEmergencyBootstrapDNSTXTAndECH verifies Priority 4:
// Ed25519 signature verification, multi-chunk DNS TXT assembly, emergency
// server entries import via DNS TXT, and ECH fallback via DNS TXT.
func TestPsiEmergencyBootstrapDNSTXTAndECH(t *testing.T) {
	a := testApp(t)
	p := a.psi

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)

	validEntryRaw := `203.0.113.55 80 DE web {"ipAddress":"203.0.113.55","webServerPort":"80","webServerSecret":"sec999","webServerCertificate":"cert","sshPort":22,"sshPassword":"pw","sshHostKey":"hk","sshObfuscatedPort":443,"sshObfuscatedKey":"obkey","region":"DE","capabilities":["OSSH","TLS-OSSH"]}`
	hexEntry := hex.EncodeToString([]byte(validEntryRaw))
	sig := ed25519.Sign(priv, []byte(hexEntry))
	signedPayload := "sig=" + hex.EncodeToString(sig) + ";data=" + hexEntry

	// Split signed payload into 2 chunked DNS TXT records
	mid := len(signedPayload) / 2
	chunk0 := "v=psiroute1;seq=0;data=" + signedPayload[:mid]
	chunk1 := "v=psiroute1;seq=1;data=" + signedPayload[mid:]

	echRaw := buildSyntheticECHConfigList("cloudflare-ech.com", 0x55)
	echB64 := base64.StdEncoding.EncodeToString(echRaw)
	echSig := ed25519.Sign(priv, []byte(echB64))
	signedECHTXT := "sig=" + hex.EncodeToString(echSig) + ";data=" + echB64

	setDNSTXTLookupHook(func(ctx context.Context, domain string) ([]string, error) {
		switch domain {
		case psiBootstrapTXTDomains[0]:
			return []string{chunk1, chunk0}, nil // out of order to test seq sorting
		case "_ech.test-ech-fallback.example.com":
			return []string{signedECHTXT}, nil
		default:
			return nil, errors.New("nxdomain")
		}
	})
	defer setDNSTXTLookupHook(nil)

	added := p.bootstrapEmergencyServerEntries(context.Background(), pubHex)
	if added != 1 || p.importedServerEntriesCount() != 1 {
		t.Fatalf("bootstrapEmergencyServerEntries added=%d count=%d, want 1", added, p.importedServerEntriesCount())
	}

	// Verify ECH TXT fallback decoding and validation
	gotECH, ok := parseECHFromTXT([]string{signedECHTXT}, pubHex)
	if !ok || string(gotECH) != string(echRaw) {
		t.Fatalf("parseECHFromTXT failed: ok=%v got=%x want=%x", ok, gotECH, echRaw)
	}
}

// TestPsiParallelTwoTunnelLoadBalancing verifies Priority 6:
// when Psiphon.Parallel >= 2 and a secondary tunnel slot is active, DialBalanced
// distributes concurrent connections across both slots without data races.
func TestPsiParallelTwoTunnelLoadBalancing(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Psiphon.Parallel = 2
	})
	p := a.psi

	var slot0Calls, slot1Calls atomic.Int32
	p.primaryDialHook = func(ctx context.Context, network, addr string) (net.Conn, error) {
		slot0Calls.Add(1)
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	a.countries.mu.Lock()
	a.countries.poolDialHook = func(ctx context.Context, cc, addr string) (net.Conn, error) {
		slot1Calls.Add(1)
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	a.countries.mu.Unlock()

	var conns []net.Conn
	for i := 0; i < 6; i++ {
		c, err := p.DialBalanced(context.Background(), "tcp", "example.com:443")
		if err != nil {
			t.Fatalf("DialBalanced #%d: %v", i, err)
		}
		conns = append(conns, c)
	}
	if slot0Calls.Load() != 3 || slot1Calls.Load() != 3 {
		t.Fatalf("expected 3+3 balanced dials across 2 tunnels, got slot0=%d slot1=%d", slot0Calls.Load(), slot1Calls.Load())
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if p.activeConns0.Load() != 0 || p.activeConns1.Load() != 0 {
		t.Fatalf("active connection counters not decremented on Close: c0=%d c1=%d", p.activeConns0.Load(), p.activeConns1.Load())
	}
}
