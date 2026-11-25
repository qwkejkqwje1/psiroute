package main

import (
	"context"
	"errors"
	"testing"
)

// A-02/A-09: pure verdict helpers.
func TestThrottledVerdictNeedsTwoAddressees(t *testing.T) {
	cut := probeSample{N: 16 << 10, Err: errors.New("stall")}
	ok := probeSample{N: probeChunkMinBytes}
	early := probeSample{N: 2 << 10, Err: errors.New("reset")}
	if !throttledVerdict(cut, cut) {
		t.Error("cut at ~16 KB on both addressees must be a throttle verdict")
	}
	if throttledVerdict(cut, ok) || throttledVerdict(ok, cut) {
		t.Error("cut at one addressee only must NOT be a throttle verdict")
	}
	if throttledVerdict(cut, early) {
		t.Error("a reset far from 12-24 KB at the other addressee is not the 16 KB signature")
	}
	if !cut.cutNear16KB() || early.cutNear16KB() || ok.cutNear16KB() {
		t.Error("cutNear16KB window wrong")
	}
}

func TestDNSPoisonedVerdictNeedsTwoHosts(t *testing.T) {
	if dnsPoisonedVerdict(nil) || dnsPoisonedVerdict([]string{"s3.amazonaws.com"}) {
		t.Error("one host (or none) must not be a poisoning verdict")
	}
	if !dnsPoisonedVerdict([]string{"s3.amazonaws.com", "speed.cloudflare.com"}) {
		t.Error("two hosts must be a poisoning verdict")
	}
}

// One poisoned host only: not DNSPoisoned (a CDN may answer differently).
func TestPreflight_SingleHostDNSDifferenceIsNotPoisoning(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"10.10.34.35"}, []string{"52.216.10.1"})
	h.SetDNS(preflightDNSHostB, []string{"104.18.2.1"}, []string{"104.18.2.1"})
	h.SetCarrier(carrierDirect, fakeCarrierProfile{PayloadSize: 64 << 10})
	rep := runPreflight(context.Background(), "net-one-host-dns", harnessCarriers(h, []string{carrierDirect}, nil), baseProbes(h, 0))
	if rep.DNSPoisoned {
		t.Fatalf("one disagreeing host must not set DNSPoisoned: %+v", rep.DNSPoisonedHosts)
	}
	if len(rep.DNSPoisonedHosts) != 1 {
		t.Fatalf("DNSPoisonedHosts = %v, want exactly the list host", rep.DNSPoisonedHosts)
	}
}

// The first destination stalls at 16 KB but the official list host passes: the
// carrier is NOT throttled and stays healthy.
func TestPreflight_StallAtOneAddresseeIsNotCarrierThrottle(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetDNS(preflightListHost, []string{"52.216.10.1"}, []string{"52.216.10.1"})
	h.SetCarrier(carrierDirect, fakeCarrierProfile{PayloadSize: 64 << 10, StallAfterBytes: 16 << 10})
	probes := baseProbes(h, 0)
	probes.RangeProbe = func(ctx context.Context, c Carrier, rawURL string, n int) (int, error) {
		return probeChunkMinBytes, nil
	}
	rep := runPreflight(context.Background(), "net-one-addressee", harnessCarriers(h, []string{carrierDirect}, nil), probes)
	c, found := rep.Carriers[carrierDirect]
	if !found {
		t.Fatal("no result for the direct carrier")
	}
	if c.Throttled16KB || !c.Probe64KBOK || !c.Healthy {
		t.Fatalf("direct must stay healthy and unthrottled: %+v", c)
	}
}

// An unconfigured carrier is refused by the range probe.
func TestProbeRangeOverCarrierRefusesUnconfigured(t *testing.T) {
	c := newBaseCarrier("x", false, nil, nil)
	if _, err := probeRangeOverCarrier(context.Background(), c, "https://example.invalid/", 1024); err == nil {
		t.Fatal("unconfigured carrier must be refused")
	}
}
