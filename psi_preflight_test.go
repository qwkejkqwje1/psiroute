package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// Offline Stage 0 Preflight and Carrier ranking tests (Step 1).
// Uses fakeNetworkHarness from Step 0 — zero real internet traffic.

func harnessCarriers(h *fakeNetworkHarness, names []string, unconfigured map[string]bool) []Carrier {
	out := make([]Carrier, 0, len(names))
	for _, name := range names {
		n := name
		cfgd := !unconfigured[n]
		dialFn := h.DialContext(n)
		probeFn := func(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (int, int, error) {
			t0 := time.Now()
			tctx, cancel := context.WithTimeout(ctx, 180*time.Millisecond)
			defer cancel()
			readN, err := probeTransfer64KB(tctx, dial, "speed.cloudflare.com:443", []byte("GET /__down?bytes=73728 HTTP/1.1\r\n\r\n"))
			return readN, int(time.Since(t0).Milliseconds()), err
		}
		out = append(out, newBaseCarrier(n, cfgd, dialFn, probeFn))
	}
	return out
}

func harnessTLSProbe(ctx context.Context, c Carrier, addr string, fragmented bool) error {
	tctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	conn, err := c.Dial(tctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := tctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	hello := append([]byte{0x16, 0x03, 0x01, 0x00, 0x3c}, bytes.Repeat([]byte{0x01}, 60)...)
	if fragmented {
		if _, err := conn.Write(hello[:5]); err != nil {
			return err
		}
		if _, err := conn.Write(hello[5:]); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write(hello); err != nil {
			return err
		}
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		if err == nil {
			return io.EOF
		}
		return err
	}
	return nil
}

func baseProbes(h *fakeNetworkHarness, skew time.Duration) *preflightProbes {
	return &preflightProbes{
		ResolveSystem: h.ResolveSystem,
		ResolveDoH:    h.ResolveDoH,
		ClockSkewCheck: func(ctx context.Context) (time.Duration, error) {
			return skew, nil
		},
		TLSHandshake: harnessTLSProbe,
		// Second destination of the 64 KB test (official list host, A-02/A-09); the
		// fake carrier stalls/serves it the same way as the first destination.
		RangeProbe: func(ctx context.Context, c Carrier, rawURL string, n int) (int, error) {
			tctx, cancel := context.WithTimeout(ctx, 180*time.Millisecond)
			defer cancel()
			return probeTransfer64KB(tctx, c.Dial, "s3.amazonaws.com:443", []byte("GET /list HTTP/1.1\r\n\r\n"))
		},
	}
}

func TestPreflight_BlockedListHostRanksHealthyFallbackFirst(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"52.216.10.1"}, []string{"52.216.10.1"})
	h.SetCarrier(carrierDirect, fakeCarrierProfile{
		BlockedHosts: map[string]bool{preflightListHost: true},
		PayloadSize:  64 << 10,
	})
	h.SetCarrier(carrierDirectDPI, fakeCarrierProfile{
		BlockedHosts: map[string]bool{preflightListHost: true},
		PayloadSize:  64 << 10,
	})
	h.SetCarrier(carrierWARP, fakeCarrierProfile{PayloadSize: 64 << 10})

	carriers := harnessCarriers(h, []string{carrierDirect, carrierDirectDPI, carrierWARP}, nil)
	rep := runPreflight(context.Background(), "net-blocked-s3", carriers, baseProbes(h, 0))

	if rep.ClassifiedCode != DiagListHostBlocked {
		t.Fatalf("ClassifiedCode = %q, want %q", rep.ClassifiedCode, DiagListHostBlocked)
	}
	if len(rep.Ranking) < 1 || rep.Ranking[0] != carrierWARP {
		t.Fatalf("Ranking = %v, want %q first", rep.Ranking, carrierWARP)
	}
	if !rep.ListHostReachable {
		t.Fatal("expected ListHostReachable=true via WARP")
	}
}

func TestPreflight_DNSPoisonedDetected(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"10.10.34.35"}, []string{"52.216.10.1"})
	h.SetDNS(preflightDNSHostB, []string{"10.10.34.36"}, []string{"104.18.2.1"}) // A-09: poisoned on a second host too
	h.SetCarrier(carrierDirect, fakeCarrierProfile{PayloadSize: 64 << 10})
	h.SetCarrier(carrierDirectDPI, fakeCarrierProfile{PayloadSize: 64 << 10})

	carriers := harnessCarriers(h, []string{carrierDirect, carrierDirectDPI}, nil)
	rep := runPreflight(context.Background(), "net-dns-poison", carriers, baseProbes(h, 0))

	if !rep.DNSPoisoned {
		t.Fatal("expected DNSPoisoned=true")
	}
	if rep.ClassifiedCode != DiagDNSPoisoned {
		t.Fatalf("ClassifiedCode = %q, want %q", rep.ClassifiedCode, DiagDNSPoisoned)
	}
	if rep.Reason == "" || rep.ManualAction == "" {
		t.Fatalf("expected Russian reason and manual action, got %+v", rep)
	}
}

func TestPreflight_HandshakeResetRanksDirectDPIAboveDirect(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"52.216.10.1"}, []string{"52.216.10.1"})
	h.SetCarrier(carrierDirect, fakeCarrierProfile{
		ResetAfterClientHello: true,
		AllowFragmentedHello:  false,
		PayloadSize:           64 << 10,
	})
	h.SetCarrier(carrierDirectDPI, fakeCarrierProfile{
		ResetAfterClientHello: true,
		AllowFragmentedHello:  true,
		PayloadSize:           64 << 10,
	})

	carriers := harnessCarriers(h, []string{carrierDirect, carrierDirectDPI}, nil)
	rep := runPreflight(context.Background(), "net-dpi-rst", carriers, baseProbes(h, 0))

	if rep.ClassifiedCode != DiagHandshakeReset {
		t.Fatalf("ClassifiedCode = %q, want %q", rep.ClassifiedCode, DiagHandshakeReset)
	}
	if len(rep.Ranking) < 2 || rep.Ranking[0] != carrierDirectDPI {
		t.Fatalf("Ranking = %v, want %q ranked #1 over plain direct", rep.Ranking, carrierDirectDPI)
	}
	if !rep.Carriers[carrierDirect].HandshakeReset || !rep.Carriers[carrierDirectDPI].TLSFragOK {
		t.Fatalf("unexpected TLS probe flags: direct=%+v dpi=%+v", rep.Carriers[carrierDirect], rep.Carriers[carrierDirectDPI])
	}
}

func TestPreflight_StallAfter16KBClassifiedAndDeprioritized(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"52.216.10.1"}, []string{"52.216.10.1"})
	h.SetCarrier(carrierDirect, fakeCarrierProfile{StallAfterBytes: 16 << 10})
	h.SetCarrier(carrierWARP, fakeCarrierProfile{StallAfterBytes: 16 << 10})
	h.SetCarrier(carrierWorker, fakeCarrierProfile{PayloadSize: 64 << 10})

	carriers := harnessCarriers(h, []string{carrierDirect, carrierWARP, carrierWorker}, nil)
	rep := runPreflight(context.Background(), "net-16kb", carriers, baseProbes(h, 0))

	if rep.ClassifiedCode != DiagCarrierThrottled16KB {
		t.Fatalf("ClassifiedCode = %q, want %q", rep.ClassifiedCode, DiagCarrierThrottled16KB)
	}
	if len(rep.Ranking) < 1 || rep.Ranking[0] != carrierWorker {
		t.Fatalf("Ranking = %v, want %q #1 (non-throttled)", rep.Ranking, carrierWorker)
	}
	if !rep.Carriers[carrierWARP].Throttled16KB || rep.Carriers[carrierWARP].Healthy {
		t.Fatalf("WARP should be marked Throttled16KB and unhealthy: %+v", rep.Carriers[carrierWARP])
	}
}

func TestPreflight_UDPBlockedClassified(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"52.216.10.1"}, []string{"52.216.10.1"})
	h.SetCarrier(carrierDirect, fakeCarrierProfile{UDPBlocked: true, PayloadSize: 64 << 10})

	carriers := harnessCarriers(h, []string{carrierDirect}, nil)
	rep := runPreflight(context.Background(), "net-no-udp", carriers, baseProbes(h, 0))

	if rep.UDPReachable {
		t.Fatal("expected UDPReachable=false")
	}
	if rep.ClassifiedCode != DiagUDPBlocked {
		t.Fatalf("ClassifiedCode = %q, want %q", rep.ClassifiedCode, DiagUDPBlocked)
	}
}

func TestPreflight_NoNetworkAndClockSkew(t *testing.T) {
	// 1. Total outage -> NO_NETWORK
	h := newFakeNetworkHarness()
	h.SetCarrier(carrierDirect, fakeCarrierProfile{FailAll: true})
	h.SetCarrier(carrierWARP, fakeCarrierProfile{FailAll: true})
	carriers := harnessCarriers(h, []string{carrierDirect, carrierWARP}, nil)
	rep := runPreflight(context.Background(), "net-offline", carriers, baseProbes(h, 0))
	if rep.ClassifiedCode != DiagNoNetwork {
		t.Fatalf("offline ClassifiedCode = %q, want %q", rep.ClassifiedCode, DiagNoNetwork)
	}

	// 2. Clock skew > 5 min -> CLOCK_SKEW
	h2 := newFakeNetworkHarness()
	h2.SetCarrier(carrierDirect, fakeCarrierProfile{PayloadSize: 64 << 10})
	rep2 := runPreflight(context.Background(), "net-skew", harnessCarriers(h2, []string{carrierDirect}, nil), baseProbes(h2, 12*time.Minute))
	if !rep2.ClockSkewDetected || rep2.ClassifiedCode != DiagClockSkew {
		t.Fatalf("clock skew report = %+v, want %q", rep2, DiagClockSkew)
	}
}

func TestPreflight_CacheTTLAndNetworkChangeInvalidation(t *testing.T) {
	a := testApp(t)
	p := a.psi
	curNet := "net-home-1"
	p.netKeyFunc = func() string { return curNet }

	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"52.216.10.1"}, []string{"52.216.10.1"})
	h.SetCarrier(carrierDirect, fakeCarrierProfile{PayloadSize: 64 << 10})

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	runs := 0
	probes := baseProbes(h, 0)
	probes.Now = func() time.Time { return now }
	probes.ClockSkewCheck = func(ctx context.Context) (time.Duration, error) {
		runs++
		return 0, nil
	}
	p.preflightProbes = probes
	p.preflightCarriersFn = func() []Carrier {
		return harnessCarriers(h, []string{carrierDirect}, nil)
	}
	p.preflight = newPreflightCache(2 * time.Minute)

	// 1st run executes preflight
	r1 := p.RunPreflight(context.Background(), false)
	if r1 == nil || runs != 1 {
		t.Fatalf("1st RunPreflight: runs=%d rep=%+v", runs, r1)
	}
	// 2nd run within TTL returns cached result without re-running probes
	now = now.Add(30 * time.Second)
	r2 := p.RunPreflight(context.Background(), false)
	if r2 == nil || runs != 1 {
		t.Fatalf("cached RunPreflight should not re-run probes: runs=%d", runs)
	}
	// After TTL expires, re-runs preflight
	now = now.Add(3 * time.Minute)
	_ = p.RunPreflight(context.Background(), false)
	if runs != 2 {
		t.Fatalf("expired TTL should re-run preflight: runs=%d, want 2", runs)
	}
	// Switching network key runs fresh preflight for new key
	curNet = "net-lte-2"
	_ = p.RunPreflight(context.Background(), false)
	if runs != 3 {
		t.Fatalf("network switch should run preflight for new key: runs=%d, want 3", runs)
	}
	// Explicit invalidation forces re-run on same network key
	p.invalidatePreflight(curNet)
	_ = p.RunPreflight(context.Background(), false)
	if runs != 4 {
		t.Fatalf("invalidated cache should re-run preflight: runs=%d, want 4", runs)
	}
}

func TestPreflight_DiagInfoCoversAllCodes(t *testing.T) {
	codes := []string{
		DiagNoNetwork, DiagClockSkew, DiagDNSPoisoned, DiagListHostBlocked,
		DiagNoSeed, DiagCarrierThrottled16KB, DiagUDPBlocked, DiagHandshakeReset,
		DiagAllProtocolsTimeout, DiagTunnelUnstable,
	}
	for _, code := range codes {
		info := diagInfoForCode(code)
		if info.Code != code || info.Message == "" || info.AutoAction == "" || info.ManualAction == "" {
			t.Fatalf("incomplete DiagInfo for %q: %+v", code, info)
		}
	}
	// Verify probeChunk64KBWithDial rejects nil dialer cleanly
	if _, _, err := probeChunk64KBWithDial(context.Background(), nil, ""); err == nil {
		t.Fatal("expected error for nil dialer")
	}
}
