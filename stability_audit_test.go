package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestPsiRSLURLsValidSingleSlash(t *testing.T) {
	urls := psiRSLURLs()
	if len(urls) < 2 {
		t.Fatalf("expected >= 2 RSL URLs, got %d", len(urls))
	}
	seen := map[string]bool{}
	hasZeroAttempt := false
	for i, tu := range urls {
		raw, err := base64.StdEncoding.DecodeString(tu.URL)
		if err != nil {
			t.Fatalf("URL[%d] invalid base64: %v", i, err)
		}
		s := string(raw)
		if strings.Contains(strings.TrimPrefix(s, "https://"), "//") {
			t.Fatalf("URL[%d] contains double slash path bug: %q", i, s)
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Fatalf("URL[%d] invalid URL %q: %v", i, s, err)
		}
		if seen[s] {
			t.Fatalf("URL[%d] duplicate endpoint %q", i, s)
		}
		seen[s] = true
		if tu.OnlyAfterAttempts == 0 {
			hasZeroAttempt = true
		}
	}
	if !hasZeroAttempt {
		t.Fatal("missing OnlyAfterAttempts=0 RSL URL")
	}
}

func TestPsiDeviceBinderAndPreferredDNSConfig(t *testing.T) {
	a := testApp(t)
	p := a.psi
	p.netKeyFunc = func() string { return "net-binder-test" }

	p.mu.Lock()
	p.lastPreflight = &CarrierReport{NetKey: "net-binder-test", DNSPoisoned: true}
	p.mu.Unlock()

	directStrat, _ := strategyByID("meek")
	warpStrat, _ := strategyByID("via-warp")
	desyncStrat, _ := strategyByID("direct-dpi")

	setCfg(a, func(c *Config) { c.Psiphon.Preset = PresetFast })

	cfgDirect := p.configFor(directStrat, 35)
	if cfgDirect.DeviceBinder == nil {
		t.Fatal("direct strategy must attach psiDeviceBinder")
	}
	if cfgDirect.DNSServerGetter == nil {
		t.Fatal("direct strategy with DeviceBinder must attach psiDNSServerGetter")
	}
	if len(cfgDirect.DNSResolverPreferredAlternateServers) == 0 {
		t.Fatal("poisoned DNS must set DNSResolverPreferredAlternateServers so tunnel-core prefers alternate DNS")
	}
	if _, err := json.Marshal(cfgDirect); err != nil {
		t.Fatalf("cfgDirect must marshal cleanly: %v", err)
	}
	if err := cfgDirect.Commit(true); err != nil {
		t.Fatalf("cfgDirect Commit failed: %v", err)
	}

	cfgWarp := p.configFor(warpStrat, 80)
	if cfgWarp.DeviceBinder != nil {
		t.Fatal("loopback WARP proxy strategy must not attach DeviceBinder")
	}
	cfgDesync := p.configFor(desyncStrat, 35)
	if cfgDesync.DeviceBinder != nil {
		t.Fatal("loopback desync proxy strategy must not attach DeviceBinder")
	}

	if servers := (psiDNSServerGetter{}).GetDNSServers(); len(servers) == 0 {
		t.Fatal("psiDNSServerGetter returned empty server list")
	}
}

func TestPhysUDPBindTransientRecvErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"closed", net.ErrClosed, false},
		{"eof", errors.New("eof"), false},
		{"wsa-connreset", syscall.Errno(10054), true},
		{"wsa-netreset", syscall.Errno(10052), true},
		{"wsa-msgsize", syscall.Errno(10040), true},
		{"wsa-hostunreach", syscall.Errno(10065), true},
		{"posix-connreset", syscall.ECONNRESET, true},
		{"wrapped-wsa", &net.OpError{Op: "readfrom", Net: "udp", Err: syscall.Errno(10054)}, true},
	}
	for _, tc := range cases {
		if got := isTransientUDPRecvErr(tc.err); got != tc.want {
			t.Errorf("isTransientUDPRecvErr(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}

	b := newPhysUDPBind()
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("physUDPBind.Open failed: %v", err)
	}
	if port == 0 || len(fns) == 0 {
		t.Fatalf("unexpected Open result: port=%d fns=%d", port, len(fns))
	}
	_ = b.Close()
}

func TestNetWatchSkipsTunVirtualAdapters(t *testing.T) {
	if !isTunOrVirtualIP(net.ParseIP("172.19.0.1")) {
		t.Fatal("tunAddr4 172.19.0.1 must be flagged as TUN IP")
	}
	if !isTunOrVirtualIP(net.ParseIP("fdfe:dcba:9876::1")) {
		t.Fatal("tunAddr6 must be flagged as TUN IP")
	}
	if isTunOrVirtualIP(net.ParseIP("192.168.1.42")) {
		t.Fatal("physical LAN IP must not be flagged as TUN IP")
	}
	if isPhysicalInterface(net.Interface{Name: "Psiroute", Flags: net.FlagUp}) {
		t.Fatal("Psiroute TUN interface must not be treated as physical")
	}
	if isPhysicalInterface(net.Interface{Name: "Wintun Userspace Tunnel", Flags: net.FlagUp}) {
		t.Fatal("Wintun interface must not be treated as physical")
	}
	nk := detectNetworkFingerprint()
	if strings.Contains(nk, "psiroute") {
		t.Fatalf("detectNetworkFingerprint picked virtual adapter: %q", nk)
	}
}

func TestWarpWaitWakesOnError(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := NewApp(ctx, cancel, dir+"/psiroute.json", dir)
	w := a.warp
	defer w.Close()

	go func() {
		time.Sleep(40 * time.Millisecond)
		w.setState("error", "test udp blocked")
	}()

	t0 := time.Now()
	_, err := w.wait(ctx, 10*time.Second)
	if err == nil || !strings.Contains(err.Error(), "test udp blocked") {
		t.Fatalf("expected immediate error from w.wait, got %v", err)
	}
	if time.Since(t0) > 2*time.Second {
		t.Fatalf("w.wait blocked too long after error transition: %v", time.Since(t0))
	}
}

func TestEnsureLocalDesyncProxyNilAppContext(t *testing.T) {
	p := &Psi{}
	addr := p.ensureLocalDesyncProxy()
	if addr == "" {
		t.Fatal("ensureLocalDesyncProxy returned empty addr")
	}
	p.mu.Lock()
	ln := p.desyncLn
	p.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

func TestPsiRSLFrontingAndPoolAndDPIProtocols(t *testing.T) {
	urls := psiRSLURLs()
	if len(urls) < 2 || len(urls[1].FrontingSpecs) == 0 {
		t.Fatalf("expected backup RSL URLs to include FrontingSpecs, got %+v", urls)
	}
	if err := urls.DecodeAndValidate(); err != nil {
		t.Fatalf("psiRSLURLs DecodeAndValidate failed: %v", err)
	}
	a := testApp(t)
	s, _ := strategyByID("meek")
	cfg := a.psi.configFor(s, 35)
	if cfg.TunnelPoolSize != 1 {
		t.Fatalf("expected TunnelPoolSize=1, got %d", cfg.TunnelPoolSize)
	}
	if len(cfg.FragmentorLimitProtocols) == 0 {
		t.Fatal("expected FragmentorLimitProtocols to be set in default DPI mode")
	}
}

func TestPsiOnNoticeEvictsOldestWhenFull(t *testing.T) {
	a := testApp(t)
	p := a.psi
	for i := 0; i < cap(p.notes); i++ {
		p.notes <- psiNotice{Type: "EstablishTunnelTimeout"}
	}
	p.onNotice([]byte(`{"noticeType":"Tunnels","data":{"count":1}}`))
	var sawTunnels bool
	for len(p.notes) > 0 {
		n := <-p.notes
		if n.Type == "Tunnels" {
			sawTunnels = true
		}
	}
	if !sawTunnels {
		t.Fatal("expected Tunnels notice to evict oldest entry instead of being dropped")
	}
}

func TestWarpApplyLicenseSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || !strings.HasSuffix(r.URL.Path, "/account") {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"account_type":"plus"}`))
	}))
	defer srv.Close()

	id := &warpIdentity{ID: "dev1", Token: "tok1", Account: "free"}
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			u, _ := url.Parse(srv.URL + req.URL.Path)
			req2 := req.Clone(req.Context())
			req2.URL = u
			return http.DefaultTransport.RoundTrip(req2)
		}),
	}
	if err := warpApplyLicense([]*http.Client{client}, id, "KEY-PLUS-123"); err != nil {
		t.Fatalf("warpApplyLicense failed: %v", err)
	}
	if id.Account != "plus" || id.License != "KEY-PLUS-123" {
		t.Fatalf("unexpected identity after license apply: %+v", id)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPsiOrderDoesNotPenalizeShortLivedWorkingStrategy(t *testing.T) {
	a := testApp(t)
	p := a.psi
	p.netKeyFunc = func() string { return "net-lifetime-test" }

	// Reproduce real log scenario: via-warp connected 3 times and held 60-136s
	// before manual stop (< 3 min holdOK), while direct strategies timed out.
	for i := 0; i < 3; i++ {
		p.recordStrategyAttempt("net-lifetime-test", "via-warp")
		p.recordStrategyLifetime("net-lifetime-test", "via-warp", 63*time.Second)
	}
	for i := 0; i < 2; i++ {
		p.recordStrategyAttempt("net-lifetime-test", "meek")
		p.recordStrategyAttempt("net-lifetime-test", "conduit")
	}

	enabled := p.enabled()
	// Ensure via-warp is in enabled list for this test
	setCfg(a, func(c *Config) { c.Warp.Enabled = true })
	enabled = p.enabled()
	ordered := p.order(enabled, "")
	if len(ordered) == 0 || ordered[0].ID != "via-warp" {
		t.Fatalf("expected via-warp with 63s median lifetime to stay #1, got %v", ordered)
	}
}

func TestApplyTuningPreservesShortRound0Budget(t *testing.T) {
	a := testApp(t)
	p := a.psi
	s, _ := strategyByID("meek")
	setCfg(a, func(c *Config) { c.Psiphon.Preset = PresetBalanced })

	cfg := p.configFor(s, 15)
	// When seeds are already present (seedEmptyOrRSL=false), round-0 short budget (15s) must stay 15s.
	cfg.EstablishTunnelTimeoutSeconds = ptr(15)
	applyTuning(cfg, PresetBalanced, carrierDirect, nil, 0, false)
	if cfg.EstablishTunnelTimeoutSeconds == nil || *cfg.EstablishTunnelTimeoutSeconds != 15 {
		t.Fatalf("expected short round-0 timeout 15s to be preserved, got %v", cfg.EstablishTunnelTimeoutSeconds)
	}
}

func TestWarpRacePrioritizesForeignOverDME(t *testing.T) {
	// Case 1: Domestic DME arrives first, foreign FRA arrives shortly after -> must pick FRA and close DME.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rctx, rcancel := context.WithCancel(ctx)
	defer rcancel()
	ch := make(chan warpRaceRes, 3)

	var dmeClosed atomic.Bool
	dmeT := &warpTunnel{ep: "162.159.192.1:2408", colo: "DME"}
	fraT := &warpTunnel{ep: "162.159.193.2:2408", colo: "FRA"}

	ch <- warpRaceRes{t: dmeT, colo: "DME", close: func() { dmeClosed.Store(true) }}
	go func() {
		time.Sleep(40 * time.Millisecond)
		ch <- warpRaceRes{t: fraT, colo: "FRA", close: func() {}}
		ch <- warpRaceRes{err: context.Canceled}
	}()

	win, err := collectWarpRaceWinner(rctx, rcancel, ch, 3, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("collectWarpRaceWinner failed: %v", err)
	}
	if win != fraT {
		t.Fatalf("expected foreign FRA tunnel to win race, got colo=%q", win.colo)
	}
	if !dmeClosed.Load() {
		t.Fatal("expected superseded domestic DME fallback tunnel to be closed")
	}

	// Case 2: Only DME connects while other branches hang -> returns DME once grace expires.
	ch2 := make(chan warpRaceRes, 2)
	var canceled atomic.Bool
	rc2 := func() { canceled.Store(true); ch2 <- warpRaceRes{err: context.Canceled} }
	dmeOnly := &warpTunnel{ep: "162.159.192.3:2408", colo: "DME"}
	ch2 <- warpRaceRes{t: dmeOnly, colo: "DME", close: func() {}}
	win2, err2 := collectWarpRaceWinner(ctx, rc2, ch2, 2, 50*time.Millisecond)
	if err2 != nil || win2 != dmeOnly {
		t.Fatalf("expected DME fallback after grace expiry, got win=%v err=%v", win2, err2)
	}
	if !canceled.Load() {
		t.Fatal("expected rcancel to be invoked when grace expires")
	}
}

type slowTrickleReader struct {
	chunk []byte
	delay time.Duration
	left  int
}

func (r *slowTrickleReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	time.Sleep(r.delay)
	n := min(len(p), len(r.chunk))
	if n > r.left {
		n = r.left
	}
	copy(p[:n], r.chunk[:n])
	r.left -= n
	return n, nil
}

func TestSlowTransferNotMisclassifiedAs16KBThrottle(t *testing.T) {
	// Slow active trickle (multiple chunks across 150ms, total ~16 KB when outer deadline hits)
	// must return errSlowTransfer so cutNear16KB() is false.
	tctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go func() {
		defer serverConn.Close()
		tr := &slowTrickleReader{chunk: bytes.Repeat([]byte("S"), 4096), delay: 30 * time.Millisecond, left: 64 << 10}
		_, _ = io.Copy(serverConn, tr)
	}()
	go func() {
		<-tctx.Done()
		_ = clientConn.SetDeadline(time.Now())
	}()

	got, err := readProbeBodyWithProgress(tctx, cancel, clientConn, 64<<10, time.Second)
	s := probeSample{N: int(got), Err: err}
	if s.N == 0 {
		t.Fatalf("expected non-zero bytes read before deadline, got 0 (err=%v)", err)
	}
	// If timing varies on slow CI, also verify direct cutNear16KB behavior on errSlowTransfer vs stall.
	slowSamp := probeSample{N: 16 << 10, Err: fmtErrorSlow()}
	if slowSamp.cutNear16KB() {
		t.Fatal("slow continuous transfer must not classify as TSPU 16 KB cut")
	}
	stallSamp := probeSample{N: 16 << 10, Err: errProbeIdleStall}
	if !stallSamp.cutNear16KB() {
		t.Fatal("idle mid-stream stall at 16 KB must classify as TSPU 16 KB cut")
	}
}

func fmtErrorSlow() error { return errors.Join(errSlowTransfer, context.DeadlineExceeded) }

func TestRouterDomainRoutingAndCacheInvalidation(t *testing.T) {
	if got := cleanHostKey("YouTube.COM.:443"); got != "youtube.com" {
		t.Fatalf("cleanHostKey with port/dot = %q, want youtube.com", got)
	}
	if got := cleanHostKey("[2001:db8::1]"); got != "2001:db8::1" {
		t.Fatalf("cleanHostKey IPv6 = %q, want 2001:db8::1", got)
	}

	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obWarp
		c.Warp.Enabled = false
	})
	// Cached decision when Warp.Enabled=false falls back to direct.
	ord1, _ := a.router.planFor("cachecheck.example", 443, "chrome.exe")
	if len(ord1) == 0 || ord1[0] != obDirect {
		t.Fatalf("expected direct while warp disabled, got %v", ord1)
	}
	// Toggling Warp.Enabled=true must not return stale cached direct route!
	setCfg(a, func(c *Config) { c.Warp.Enabled = true })
	ord2, _ := a.router.planFor("cachecheck.example", 443, "chrome.exe")
	if len(ord2) == 0 || ord2[0] != obWarp {
		t.Fatalf("expected warp after toggling Warp.Enabled, got %v", ord2)
	}
}

func TestStatsRecentTracksTrafficBytes(t *testing.T) {
	s := newStats("")
	tr := s.openProto("udp", "chrome.exe", "youtube.com", "", 443, obWarp, "YouTube")
	s.add(tr, 1200, 48000)
	s.close(tr, nil)

	rec := s.recentList()
	if len(rec) != 1 {
		t.Fatalf("recentList len = %d, want 1", len(rec))
	}
	if rec[0].Up != 1200 || rec[0].Down != 48000 || rec[0].Proto != "udp" {
		t.Fatalf("unexpected recentConn metrics: %+v", rec[0])
	}
	conns := s.connsList()
	if len(conns) != 1 || conns[0]["rx"].(int64) != 48000 || conns[0]["tx"].(int64) != 1200 {
		t.Fatalf("unexpected connsList row: %+v", conns)
	}
}

func TestSafeGoReplyAndRelayNeverHangOnPanic(t *testing.T) {
	// 1. safeGoReply must deliver panic fallback immediately.
	ch := make(chan error, 1)
	safeGoReply("test-panic-reply", ch, func(r any) error {
		return errors.New("recovered panic")
	}, func() error {
		panic("boom")
	})
	select {
	case err := <-ch:
		if err == nil || !strings.Contains(err.Error(), "recovered") {
			t.Fatalf("unexpected reply error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("safeGoReply hung caller after panic")
	}

	// 2. dialHappyEyeballs with a panicking multi-address dialer must return error instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, derr := dialHappyEyeballs(ctx, func(context.Context, string, string) (net.Conn, error) {
		panic("dialer panic")
	}, []string{"1.1.1.1:443", "1.0.0.1:443"})
	if derr == nil || ctx.Err() != nil {
		t.Fatalf("expected immediate error from dialHappyEyeballs on panic, got %v (ctxErr=%v)", derr, ctx.Err())
	}

	// 3. App.relay with a panicking upstream Conn must terminate cleanly without deadlocking.
	a := testApp(t)
	clientIn, clientOut := net.Pipe()
	defer clientOut.Close()
	up := &panicReadConn{Conn: &dummyConn{}}
	done := make(chan error, 1)
	go func() {
		err, _ := a.relay(clientIn, bufio.NewReader(clientIn), up, nil)
		done <- err
	}()
	_, _ = clientOut.Write([]byte("hello"))
	_ = clientOut.Close()
	select {
	case rerr := <-done:
		if rerr == nil {
			t.Fatal("expected relay to return error after upstream panic")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("App.relay deadlocked after goroutine panic")
	}
}

type panicReadConn struct{ net.Conn }

func (p *panicReadConn) Read([]byte) (int, error)  { panic("read panic") }
func (p *panicReadConn) Write(b []byte) (int, error) { return len(b), nil }
func (p *panicReadConn) Close() error              { return nil }

type dummyConn struct{}

func (d *dummyConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (d *dummyConn) Write(b []byte) (int, error)        { return len(b), nil }
func (d *dummyConn) Close() error                       { return nil }
func (d *dummyConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (d *dummyConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (d *dummyConn) SetDeadline(time.Time) error        { return nil }
func (d *dummyConn) SetReadDeadline(time.Time) error    { return nil }
func (d *dummyConn) SetWriteDeadline(time.Time) error   { return nil }
