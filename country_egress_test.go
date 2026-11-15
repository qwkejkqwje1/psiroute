package main

import (
	"context"
	"errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"net"
	"testing"
	"time"
)

func TestExactCountryWaitsForConfirmedEgress(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Psiphon.Country = "DE"
		c.Psiphon.SingleProcessCountries = true
		c.Psiphon.Parallel = 2
	})
	a.psi.mu.Lock()
	a.psi.state = "connected"
	a.psi.egress = "US"
	a.psi.confirmedEgress = "US"
	a.psi.mu.Unlock()
	called := make(chan struct{}, 1)
	sentinel := errors.New("verified primary selected")
	a.psi.primaryDialHook = func(context.Context, string, string) (net.Conn, error) { called <- struct{}{}; return nil, sentinel }
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _, err := a.countries.Dial(ctx, "DE", "target.example:443"); done <- err }()
	select {
	case <-called:
		t.Fatal("used old US egress")
	case <-time.After(30 * time.Millisecond):
	}
	a.psi.mu.Lock()
	a.psi.egress = "DE"
	a.psi.confirmedEgress = "DE"
	a.psi.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, sentinel) {
			t.Fatalf("dial error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not use confirmed DE")
	}
}
func TestExactCountryCancellationNeverDialsOldEgress(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) { c.Psiphon.Country = "DE"; c.Psiphon.SingleProcessCountries = true })
	a.psi.mu.Lock()
	a.psi.state = "connected"
	a.psi.egress = "US"
	a.psi.confirmedEgress = "US"
	a.psi.mu.Unlock()
	a.psi.primaryDialHook = func(context.Context, string, string) (net.Conn, error) {
		t.Error("wrong-country dial")
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := a.countries.Dial(ctx, "DE", "target.example:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation=%v", err)
	}
}

func TestExactCountryRejectsMetadataFromPreviousController(t *testing.T) {
	a := testApp(t)
	oldController, newController := &psiphon.Controller{}, &psiphon.Controller{}
	a.psi.mu.Lock()
	a.psi.state = "connected"
	a.psi.egress = "DE"
	a.psi.confirmedEgress = "DE"
	a.psi.confirmedController = oldController
	a.psi.cur.Store(newController)
	a.psi.mu.Unlock()
	a.psi.primaryDialHook = func(context.Context, string, string) (net.Conn, error) {
		t.Error("stale DE metadata authorized new controller")
		return nil, nil
	}
	_, ready, _ := a.countries.dialConfirmedMainCountry(context.Background(), "DE", "target.example:443")
	if ready {
		t.Fatal("previous-controller confirmation accepted")
	}
	a.psi.cur.Store(nil)
}
