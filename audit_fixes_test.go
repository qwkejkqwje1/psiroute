package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- A-06: safeGo / safeLoop ----------

func TestSafeGoSurvivesPanic(t *testing.T) {
	before := panicsCaught.Load()
	done := make(chan struct{})
	safeGo("test-panic", func() {
		defer close(done)
		panic("boom")
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine did not run")
	}
	deadline := time.Now().Add(2 * time.Second)
	for panicsCaught.Load() == before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if panicsCaught.Load() == before {
		t.Fatal("panic was not reported")
	}
}

func fakeLoopClock() (func() time.Time, func(context.Context, time.Duration), *[]time.Duration) {
	now := time.Unix(1_000_000, 0)
	var sleeps []time.Duration
	return func() time.Time { return now },
		func(_ context.Context, d time.Duration) { sleeps = append(sleeps, d); now = now.Add(d) },
		&sleeps
}

func TestLoopFailsAfterFiveCrashesPerMinute(t *testing.T) {
	const name = "test-loop-fail"
	defer failedComponents.Delete(name)
	nowFn, sleepFn, sleeps := fakeLoopClock()
	calls := 0
	failed := runLoopSupervised(context.Background(), name, func() { calls++; panic("x") }, nowFn, sleepFn)
	if !failed || calls != loopMaxCrashes {
		t.Fatalf("failed=%v calls=%d, want failed after %d crashes", failed, calls, loopMaxCrashes)
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second}
	if len(*sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", *sleeps, want)
	}
	for i := range want {
		if (*sleeps)[i] != want[i] {
			t.Fatalf("backoff[%d] = %v, want %v", i, (*sleeps)[i], want[i])
		}
	}
	if !componentFailed(name) {
		t.Fatal("component must be marked failed")
	}
}

func TestLoopSlowCrashesDoNotFail(t *testing.T) {
	const name = "test-loop-slow"
	defer failedComponents.Delete(name)
	now := time.Unix(1_000_000, 0)
	nowFn := func() time.Time { return now }
	sleepFn := func(context.Context, time.Duration) { now = now.Add(61 * time.Second) } // crashes never share a minute
	calls := 0
	failed := runLoopSupervised(context.Background(), name, func() {
		calls++
		if calls <= 8 {
			panic("x")
		}
	}, nowFn, sleepFn)
	if failed || calls != 9 || componentFailed(name) {
		t.Fatalf("failed=%v calls=%d: sparse crashes must keep restarting", failed, calls)
	}
}

func TestLoopNormalReturnAndCancel(t *testing.T) {
	nowFn, sleepFn, _ := fakeLoopClock()
	calls := 0
	if runLoopSupervised(context.Background(), "test-loop-ok", func() { calls++ }, nowFn, sleepFn) || calls != 1 {
		t.Fatalf("a loop that returns normally must run once, calls=%d", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	if runLoopSupervised(ctx, "test-loop-cancel", func() { calls++; cancel(); panic("x") }, nowFn, sleepFn) || calls != 1 {
		t.Fatalf("cancelled context must stop restarts, calls=%d", calls)
	}
}

func TestLoopBackoffCapped(t *testing.T) {
	if loopBackoff(1) != 500*time.Millisecond || loopBackoff(20) != loopBackoffMax {
		t.Fatalf("backoff: %v %v", loopBackoff(1), loopBackoff(20))
	}
}

// ---------- A-04: seeds ----------

func TestSeedEntryRejectsNonGlobalAddresses(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.9", "172.16.5.5", "169.254.10.10", "0.0.0.0", "224.0.0.5", "::1", "fe80::1"} {
		if _, ok := validateServerEntryHex(makeTestServerEntryHex(ip, "DE", []string{"OSSH"})); ok {
			t.Errorf("address %s must be rejected", ip)
		}
	}
	if _, ok := validateServerEntryHex(makeTestServerEntryHex("203.0.113.10", "DE", []string{"OSSH"})); !ok {
		t.Error("a public address must be accepted")
	}
}

func TestSeedImportCap(t *testing.T) {
	a := testApp(t)
	var lines []string
	for _, prefix := range []string{"203.0.113.", "198.51.100.", "192.0.2."} {
		for i := 1; i <= 200; i++ {
			lines = append(lines, makeTestServerEntryHex(fmt.Sprintf("%s%d", prefix, i), "DE", []string{"OSSH"}))
		}
	}
	added, _, invalid, err := a.psi.importServerEntriesWithoutRestart(strings.Join(lines, "\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if added != seedImportMaxEntries || invalid != len(lines)-seedImportMaxEntries {
		t.Fatalf("added=%d invalid=%d, want %d and %d", added, invalid, seedImportMaxEntries, len(lines)-seedImportMaxEntries)
	}
}

func TestMirrorRedirectPolicy(t *testing.T) {
	mk := func(u string) *http.Request {
		r, err := http.NewRequest("GET", u, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := mk("https://mirror.example.com/a")
	if err := sameHostHTTPSRedirect(mk("https://mirror.example.com/b"), []*http.Request{first}); err != nil {
		t.Fatalf("same-host https redirect must pass: %v", err)
	}
	for _, bad := range []string{"http://mirror.example.com/b", "https://evil.example.net/x"} {
		err := sameHostHTTPSRedirect(mk(bad), []*http.Request{first})
		if err == nil || !strings.Contains(err.Error(), "редирект зеркала запрещён") {
			t.Errorf("redirect to %s must be refused, got %v", bad, err)
		}
	}
}

func TestTrustWarningOnlyForNewSource(t *testing.T) {
	a := testApp(t)
	post := func(ip string) SeedImportResult {
		rec := apiCall(t, a, "POST", "/api/psiphon/server-entries", true, `{"data":"`+makeTestServerEntryHex(ip, "DE", []string{"OSSH"})+`","source":"QR"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var r SeedImportResult
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := post("203.0.113.21")
	if !first.NewSource || first.TrustWarning == "" {
		t.Fatalf("first import from a source must warn: %+v", first)
	}
	second := post("203.0.113.22")
	if second.NewSource || second.TrustWarning != "" {
		t.Fatalf("second import from the same source must not warn again: %+v", second)
	}
	if !newPsi(a, a.dataDir).noteSeedSource("other") || newPsi(a, a.dataDir).noteSeedSource("qr") {
		t.Fatal("known sources must persist on disk")
	}
}

// ---------- A-03: honest seed status ----------

func fakeHealthyCarrier(name string) *baseCarrier {
	c := newBaseCarrier(name, true, nil, nil)
	c.healthy.Store(true)
	return c
}

func TestSeedStatusWithoutMirrorIsHonest(t *testing.T) {
	a := testApp(t)
	p := a.psi
	carriers := []Carrier{fakeHealthyCarrier("c1")}

	p.seedProbe = func(ctx context.Context, c Carrier, rawURL string, n int) (int, error) { return n, nil }
	res := p.AcquireSeedsParallel(context.Background(), carriers, "", nil)
	if res.Succeeded || res.Status != seedStatusReachable {
		t.Fatalf("a reachable probe is not a seed success: %+v", res)
	}

	p.seedProbe = func(ctx context.Context, c Carrier, rawURL string, n int) (int, error) { return 0, errors.New("connection reset") }
	res = p.AcquireSeedsParallel(context.Background(), carriers, "", nil)
	if res.Succeeded || res.Status != seedStatusFailed || res.DiagCode != DiagNoSeed {
		t.Fatalf("a failed probe must be reported as failed: %+v", res)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.seedProbe = func(ctx context.Context, c Carrier, rawURL string, n int) (int, error) { return 0, ctx.Err() }
	res = p.AcquireSeedsParallel(ctx, carriers, "", nil)
	if res.Succeeded || res.Status != seedStatusUnchecked {
		t.Fatalf("an interrupted check is 'unchecked': %+v", res)
	}
}

// ---------- A-10: saves are not swallowed ----------

func TestSaveOrFailReturns500(t *testing.T) {
	a := testApp(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.cfg.mu.Lock()
	a.cfg.path = filepath.Join(blocker, "sub", "psiroute.json") // a path below a regular file cannot be written
	a.cfg.mu.Unlock()
	rec := httptest.NewRecorder()
	if a.saveOrFail(rec, "test") {
		t.Fatal("saveOrFail must report the failure")
	}
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Настройки не сохранены") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := a.cfg.saveOrReport("test"); err == nil || saveFailed(err) == nil {
		t.Fatal("saveOrReport must return the error")
	}
}

// ---------- A-17: damaged-config warning ----------

func TestCorruptWarningSurvivesSaveUntilAcknowledged(t *testing.T) {
	c := defaultConfig()
	c.path = filepath.Join(t.TempDir(), "psiroute.json")
	c.corruptErr = "Ошибка синтаксиса psiroute.json"
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	if c.corruptError() == "" {
		t.Fatal("save must not drop the damaged-config warning")
	}
	c.ackCorruptError()
	if c.corruptError() != "" {
		t.Fatal("the user's confirmation must clear the warning")
	}
}

// ---------- A-05: autostart plan ----------

func TestPlanAutostart(t *testing.T) {
	cases := []struct {
		name                                    string
		elevated, writable, taskExists          bool
		checkErr                                error
		useTask, useRun, rmTask, rmRun, warning bool
	}{
		{"elevated protected dir", true, false, false, nil, true, false, false, true, false},
		{"elevated writable dir", true, true, true, nil, false, true, true, false, true},
		{"elevated unknown acl", true, false, false, errors.New("x"), false, true, true, false, true},
		{"user, no task", false, false, false, nil, false, true, false, false, false},
		{"user, old task kept", false, true, true, nil, false, false, false, true, false},
	}
	for _, tc := range cases {
		p := planAutostart(tc.elevated, tc.writable, tc.checkErr, tc.taskExists)
		if p.UseTask != tc.useTask || p.UseRunKey != tc.useRun || p.RemoveTask != tc.rmTask || p.RemoveRunKey != tc.rmRun || (p.Warning != "") != tc.warning {
			t.Errorf("%s: %+v", tc.name, p)
		}
		if p.UseTask && p.UseRunKey {
			t.Errorf("%s: two mechanisms at once", tc.name)
		}
	}
}

func TestAceMaskAllowsWrite(t *testing.T) {
	for _, m := range []uint32{aclFileWriteData, aclFileAppendData, aclDelete, aclWriteDAC, aclWriteOwner, aclGenericAll, aclGenericWrite} {
		if !aceMaskAllowsWrite(m) {
			t.Errorf("mask %#x must count as write", m)
		}
	}
	if aceMaskAllowsWrite(0x001200A9) { // FILE_GENERIC_READ|EXECUTE
		t.Error("read+execute must not count as write")
	}
}

// ---------- misc ----------

func TestHTTPURLAndPprofLoopback(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:9090/", "https://example.com/x"} {
		if !isHTTPURL(ok) {
			t.Errorf("%s must be allowed", ok)
		}
	}
	for _, bad := range []string{"file:///C:/Windows/system32/calc.exe", "javascript:alert(1)", "ms-msdt:/id", "calc.exe", ""} {
		if isHTTPURL(bad) {
			t.Errorf("%s must be refused", bad)
		}
	}
	if l, w := pprofLoopbackAddr("127.0.0.1:6060"); l != "127.0.0.1:6060" || w != "" {
		t.Errorf("loopback kept: %q %q", l, w)
	}
	if l, w := pprofLoopbackAddr("0.0.0.0:6060"); l != "127.0.0.1:6060" || w == "" {
		t.Errorf("public address must be forced to loopback with a warning: %q %q", l, w)
	}
	if l, _ := pprofLoopbackAddr(":6060"); l != "127.0.0.1:6060" {
		t.Errorf("empty host must become loopback: %q", l)
	}
}

func TestQUICKeysReturnErrorsNotPanics(t *testing.T) {
	key, iv, hp, err := quicClientKeys([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil || len(key) != 16 || len(iv) != 12 || len(hp) != 16 {
		t.Fatalf("keys: %d %d %d err=%v", len(key), len(iv), len(hp), err)
	}
}

// UI hooks (A-05, A-06, A-17): the status carries the fields the banners read.
func TestStatusCarriesNoticeFields(t *testing.T) {
	a := testApp(t)
	rec := apiCall(t, a, "GET", "/api/state?compact=1", true, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"autostart_on", "autostart_warning", "failed_components", "config_error"} {
		if _, ok := st[k]; !ok {
			t.Errorf("state is missing %q", k)
		}
	}
	// A confirmed damaged-config warning disappears from the status.
	a.cfg.mu.Lock()
	a.cfg.corruptErr = "повреждён"
	a.cfg.mu.Unlock()
	if rec := apiCall(t, a, "POST", "/api/config/ack-corrupt", true, ""); rec.Code != http.StatusOK {
		t.Fatalf("ack status %d: %s", rec.Code, rec.Body.String())
	}
	if a.cfg.corruptError() != "" {
		t.Fatal("ack-corrupt must clear the warning")
	}
}
