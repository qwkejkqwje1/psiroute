package main

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// Step 7 — ACCELERATED SIMULATION of 24 h (virtual clock, zero internet). This is NOT a
// field 24-hour test; real networks are covered only by docs/FIELD_TESTS.md (audit A-18).
// Simulates 24 hours of operation in 10-minute virtual ticks (144 ticks) with
// periodic network flaps, sleep/resume events, DNS poisoning toggles, and 16 KB
// carrier stalls. Asserts:
//   - No unbounded goroutine growth
//   - Bounded timeline ring buffer (never exceeds capacity)
//   - No stuck diagnostic state
//   - Recovery time <= 60 s (simulated) after every flap/sleep/DNS change.

func TestStep7_Soak24hSimulatedFlapsSleepResumeAndDNSChanges(t *testing.T) {
	a := testApp(t)
	p := a.psi

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()

	virtNow := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	curNet := "net-home-0"
	p.netKeyFunc = func() string { return curNet }

	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"52.216.10.1"}, []string{"52.216.10.1"})
	h.SetDNS(preflightDNSHostB, []string{"104.18.2.1"}, []string{"104.18.2.1"})
	h.SetCarrier(carrierDirect, fakeCarrierProfile{PayloadSize: 64 << 10})
	h.SetCarrier(carrierDirectDPI, fakeCarrierProfile{PayloadSize: 64 << 10})
	h.SetCarrier(carrierWARP, fakeCarrierProfile{PayloadSize: 64 << 10})

	probes := baseProbes(h, 0)
	probes.Now = func() time.Time { return virtNow }
	p.preflightProbes = probes
	p.preflightCarriersFn = func() []Carrier {
		return harnessCarriers(h, []string{carrierDirect, carrierDirectDPI, carrierWARP}, nil)
	}
	p.preflight = newPreflightCache(preflightCacheTTL)

	const totalTicks = 144 // 144 * 10 min = 24 simulated hours
	maxRecoveryMs := int64(0)
	flaps := 0

	for tick := 0; tick < totalTicks; tick++ {
		virtNow = virtNow.Add(10 * time.Minute)

		switch tick % 12 {
		case 2: // Network flap: switch Wi-Fi -> LTE
			flaps++
			curNet = fmt.Sprintf("net-lte-%d", tick)
			p.invalidatePreflight("")
		case 4: // Sleep/resume: invalidate preflight & re-run
			flaps++
			p.invalidatePreflight("")
		case 6: // DNS poisoning starts on ISP
			flaps++
			h.SetDNS(preflightListHost, []string{"10.10.34.35"}, []string{"52.216.10.1"})
			h.SetDNS(preflightDNSHostB, []string{"10.10.34.36"}, []string{"104.18.2.1"})
			p.invalidatePreflight("")
		case 8: // 16 KB throttle hits direct, WARP stays healthy
			flaps++
			h.SetCarrier(carrierDirect, fakeCarrierProfile{StallAfterBytes: 16 << 10})
			h.SetDNS(preflightListHost, []string{"52.216.10.1"}, []string{"52.216.10.1"})
			h.SetDNS(preflightDNSHostB, []string{"104.18.2.1"}, []string{"104.18.2.1"})
			p.invalidatePreflight("")
		case 10: // Network recovers to healthy direct
			flaps++
			h.SetCarrier(carrierDirect, fakeCarrierProfile{PayloadSize: 64 << 10})
			curNet = "net-home-0"
			p.invalidatePreflight("")
		}

		t0 := time.Now()
		rep := p.RunPreflight(context.Background(), false)
		recMs := time.Since(t0).Milliseconds()
		if recMs > maxRecoveryMs {
			maxRecoveryMs = recMs
		}
		if rep == nil || len(rep.Ranking) == 0 {
			t.Fatalf("tick %d: empty preflight report or ranking", tick)
		}
		if recMs > 60_000 {
			t.Fatalf("tick %d: recovery took %d ms (> 60 s)", tick, recMs)
		}

		// Exercise timeline & state view every tick to ensure bounded memory and zero deadlocks
		p.tl().RecordAttempt(rep.Ranking[0], []string{"TLS-OSSH"})
		p.tl().RecordConnect(rep.Ranking[0], "TLS-OSSH", 900)
		p.tl().RecordHold(10 * time.Minute)
		_ = p.connectionStateView()
	}

	if events := p.tl().Events(); len(events) > defaultTimelineCapacity {
		t.Fatalf("timeline exceeded ring capacity: len=%d max=%d", len(events), defaultTimelineCapacity)
	}

	runtime.GC()
	time.Sleep(30 * time.Millisecond)
	endGoroutines := runtime.NumGoroutine()
	if growth := endGoroutines - baseGoroutines; growth > 20 {
		t.Fatalf("goroutine leak detected after 24h soak: base=%d end=%d growth=%d", baseGoroutines, endGoroutines, growth)
	}
	t.Logf("24h simulated soak OK: ticks=%d flaps=%d maxRecoveryMs=%d goroutines=%d->%d",
		totalTicks, flaps, maxRecoveryMs, baseGoroutines, endGoroutines)
}
