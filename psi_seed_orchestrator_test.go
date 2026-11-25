package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Offline tests for Step 2 (Seed pipeline) and Step 3 (Long-lived controller & staged escalation).

func makeTestServerEntryHex(ip, region string, caps []string) string {
	capsJSON, _ := json.Marshal(caps)
	raw := ip + ` 80 ` + region + ` web {"ipAddress":"` + ip + `","webServerPort":"80","webServerSecret":"sec123","webServerCertificate":"cert","sshPort":22,"sshPassword":"pw","sshHostKey":"hk","sshObfuscatedPort":443,"sshObfuscatedKey":"obkey","region":"` + region + `","capabilities":` + string(capsJSON) + `}`
	return hex.EncodeToString([]byte(raw))
}

func TestStep2_ParallelSeedAcquisitionOverHealthyCarrierWhenDirectBlocked(t *testing.T) {
	a := testApp(t)
	p := a.psi

	h := newFakeNetworkHarness()
	h.SetCarrier(carrierDirect, fakeCarrierProfile{FailAll: true})
	h.SetCarrier(carrierWARP, fakeCarrierProfile{PayloadSize: 64 << 10})
	h.SetCarrier(carrierWorker, fakeCarrierProfile{PayloadSize: 64 << 10})

	directC := newBaseCarrier(carrierDirect, true, h.DialContext(carrierDirect), nil)
	directC.healthy.Store(false)
	warpC := newBaseCarrier(carrierWARP, true, h.DialContext(carrierWARP), nil)
	warpC.healthy.Store(true)
	workerC := newBaseCarrier(carrierWorker, true, h.DialContext(carrierWorker), nil)
	workerC.healthy.Store(true)

	entriesPayload := strings.Join([]string{
		makeTestServerEntryHex("198.51.100.1", "DE", []string{"OSSH", "TLS-OSSH"}),
		makeTestServerEntryHex("198.51.100.2", "NL", []string{"FRONTED-MEEK-OSSH", "TLS-OSSH"}),
		makeTestServerEntryHex("198.51.100.3", "FI", []string{"OSSH", "QUIC-OSSH"}),
	}, "\n")

	res := p.AcquireSeedsParallel(
		context.Background(),
		[]Carrier{directC, warpC, workerC},
		"https://my-worker.example.workers.dev/entries",
		func(ctx context.Context, c Carrier, targetURL string) (string, error) {
			if c.Name() == carrierWARP {
				return "", errors.New("simulated warp mirror timeout")
			}
			return entriesPayload, nil
		},
	)
	if !res.Succeeded || res.Added != 3 || res.Carrier != carrierWorker {
		t.Fatalf("AcquireSeedsParallel = %+v, want Succeeded=true Added=3 Carrier=worker", res)
	}

	sh := p.SeedHealth()
	if !sh.Healthy || sh.Total != 3 || sh.ByProtocol["TLS-OSSH"] != 2 || sh.ByProtocol["OSSH"] != 2 {
		t.Fatalf("unexpected SeedHealth: %+v", sh)
	}
}

func TestStep2_NoHealthyCarrierSetsNoSeedDiagAndImportUX(t *testing.T) {
	a := testApp(t)
	p := a.psi

	res := p.AcquireSeedsParallel(context.Background(), nil, "https://my-worker.example.workers.dev/entries", nil)
	if res.Succeeded || res.DiagCode != DiagNoSeed {
		t.Fatalf("expected NO_SEED when no carrier healthy, got %+v", res)
	}

	// Verify state API exposes NO_SEED with import_servers action
	recState := apiCall(t, a, "GET", "/api/psiphon/state", true, "")
	if recState.Code != http.StatusOK {
		t.Fatalf("GET /api/psiphon/state status=%d", recState.Code)
	}
	var st map[string]any
	if err := json.Unmarshal(recState.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st["diag_code"] != DiagNoSeed {
		t.Fatalf("state diag_code = %v, want %q", st["diag_code"], DiagNoSeed)
	}

	// Manual import returns counts + trust warning + seed_health
	e1 := makeTestServerEntryHex("203.0.113.10", "DE", []string{"TLS-OSSH"})
	recImp := apiCall(t, a, "POST", "/api/psiphon/server-entries", true, `{"data":"`+e1+`\nbadhex","source":"qr"}`)
	if recImp.Code != http.StatusOK {
		t.Fatalf("POST /api/psiphon/server-entries status=%d: %s", recImp.Code, recImp.Body.String())
	}
	var imp SeedImportResult
	if err := json.Unmarshal(recImp.Body.Bytes(), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.Added != 1 || imp.Invalid != 1 || imp.Source != "qr" || imp.TrustWarning == "" {
		t.Fatalf("unexpected SeedImportResult: %+v", imp)
	}
	if imp.SeedHealth.Total != 1 || imp.SeedHealth.Healthy {
		t.Fatalf("expected low seed warning for 1 entry: %+v", imp.SeedHealth)
	}
}

func TestStep2_OptionalSeedBundleLoadedOnStartup(t *testing.T) {
	a := testApp(t)
	bundle := makeTestServerEntryHex("198.51.100.77", "NL", []string{"OSSH", "TLS-OSSH"})
	if err := os.WriteFile(filepath.Join(a.dataDir, seedBundleFilename), []byte(bundle+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p2 := newPsi(a, a.dataDir)
	if sh := p2.SeedHealth(); sh.Total != 1 {
		t.Fatalf("expected 1 entry loaded from seed-bundle.txt, got %+v", sh)
	}
}

func TestStep3_LongLivedBudgetsAndDelayedListDelivery(t *testing.T) {
	// Verify escalation budgets: 35 -> 75 -> 150 s, the 2.3.9-fixed ladder
	// (Alla's decision 2026-11-24 after live comparison: 90/150/240 made dead
	// attempts hang 2.5-3x longer on her network than in 2.3.9-fixed).
	if attemptTimeout(0) != 35 || attemptTimeout(1) != 75 || attemptTimeout(2) != 150 {
		t.Fatalf("attemptTimeout = (%d, %d, %d), want (35, 75, 150)", attemptTimeout(0), attemptTimeout(1), attemptTimeout(2))
	}
	if bestStrategyShortTimeout != 15 || combinedRaceTimeout != 25 || tspuEchelonTimeout != 25 {
		t.Fatalf("round 0 timeouts: best=%d race=%d tspu=%d, want 15/25/25 (2.3.9-fixed)", bestStrategyShortTimeout, combinedRaceTimeout, tspuEchelonTimeout)
	}

	// Simulate a network that takes 60 s to deliver the server list:
	// round 0 (35 s) fast-fails by design, but the final round budget absorbs
	// 60 s list delivery + 20 s tunnel dial = 80 s <= 150 s. A list delivery
	// still in progress also extends the running attempt via rslGrace in
	// attemptOnce, so a slow list does not burn every round.
	const simulatedListDeliverySec = 60
	const simulatedTunnelDialSec = 20
	if simulatedListDeliverySec+simulatedTunnelDialSec > attemptTimeout(2) {
		t.Fatalf("final round budget (%d s) cannot absorb 60 s list delivery + dial", attemptTimeout(2))
	}

	// Protocol unions: QUIC only when UDP reachable; Conduit only when tactics applied
	uNoUDPNoTactics := buildStagedUnionProtocols(false, false)
	for _, pr := range uNoUDPNoTactics {
		if pr == "QUIC-OSSH" || strings.HasPrefix(pr, "INPROXY-") {
			t.Fatalf("unexpected protocol %q when udp=false tactics=false", pr)
		}
	}
	uFull := buildStagedUnionProtocols(true, true)
	hasQUIC, hasConduit := false, false
	for _, pr := range uFull {
		if pr == "QUIC-OSSH" {
			hasQUIC = true
		}
		if strings.HasPrefix(pr, "INPROXY-") {
			hasConduit = true
		}
	}
	if !hasQUIC || !hasConduit {
		t.Fatalf("expected QUIC and Conduit when udp=true tactics=true: %v", uFull)
	}
}
