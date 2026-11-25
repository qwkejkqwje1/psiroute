package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

type mockWFPBackend struct {
	mu       sync.Mutex
	applies  int
	clears   int
	lastExe  string
	lastMode bool
}

func (m *mockWFPBackend) Apply(exePath string, strict bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applies++
	m.lastExe = exePath
	m.lastMode = strict
	return nil
}

func (m *mockWFPBackend) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clears++
	return nil
}

func TestCoreFSMTransitionsAndSubscribers(t *testing.T) {
	fsm := newCoreFSM()
	if fsm.State() != CoreIdle {
		t.Fatalf("expected initial CoreIdle, got %q", fsm.State())
	}

	subID, ch := fsm.Subscribe()
	defer fsm.Unsubscribe(subID)

	initSnap := <-ch
	if initSnap.State != CoreIdle || initSnap.StageIndex != 0 {
		t.Fatalf("unexpected initial snapshot: %+v", initSnap)
	}

	if !fsm.Transition(CoreBootstrapping, StageBootstrap, "init") {
		t.Fatal("Idle -> Bootstrapping should succeed")
	}
	snap := <-ch
	if snap.State != CoreBootstrapping || snap.Stage != StageBootstrap || snap.StageIndex != 1 {
		t.Fatalf("unexpected bootstrapping snapshot: %+v", snap)
	}

	if !fsm.Transition(CoreConnecting, StageTunnel, "dial") {
		t.Fatal("Bootstrapping -> Connecting should succeed")
	}
	<-ch

	if !fsm.Transition(CoreConnected, StageReady, "") {
		t.Fatal("Connecting -> Connected should succeed")
	}
	snap = <-ch
	if snap.State != CoreConnected || snap.StageIndex != 5 {
		t.Fatalf("unexpected connected snapshot: %+v", snap)
	}

	if !fsm.Transition(CoreStopping, StageNone, "user stop") {
		t.Fatal("Connected -> Stopping should succeed")
	}
	<-ch

	// Invalid transition: Stopping -> Connected must be rejected.
	if fsm.Transition(CoreConnected, StageReady, "stale callback") {
		t.Fatal("Stopping -> Connected must be rejected by FSM")
	}
	if fsm.State() != CoreStopping {
		t.Fatalf("state should remain CoreStopping, got %q", fsm.State())
	}

	if !fsm.Transition(CoreIdle, StageNone, "stopped") {
		t.Fatal("Stopping -> Idle should succeed")
	}
}

func TestWFPKillSwitchModesAndOrphanCleanup(t *testing.T) {
	dir := t.TempDir()
	mock := &mockWFPBackend{}
	ks := &wfpKillSwitch{
		dataDir: dir,
		mode:    wfpModeOff,
		backend: mock,
	}

	// Simulate leftover lock file from a crash.
	lockFile := filepath.Join(dir, "psiroute-wfp.lock")
	if err := os.WriteFile(lockFile, []byte("strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ks.CleanupOrphans()
	if mock.clears != 1 {
		t.Fatalf("expected 1 Clear() on CleanupOrphans, got %d", mock.clears)
	}
	if _, err := os.Stat(lockFile); !os.IsNotExist(err) {
		t.Fatal("orphan lock file should be removed")
	}

	// Auto mode: VPN is UP -> should NOT engage.
	ks.Sync(wfpModeAuto, true, false, true)
	if ks.engaged || mock.applies != 0 {
		t.Fatalf("auto mode must not engage when VPN is up (engaged=%v applies=%d)", ks.engaged, mock.applies)
	}

	// Auto mode: TUN active + VPN dropped unexpectedly -> MUST engage.
	ks.Sync(wfpModeAuto, false, false, true)
	if !ks.engaged || mock.applies != 1 || mock.lastMode {
		t.Fatalf("auto mode must engage non-strict WFP on VPN drop (engaged=%v applies=%d strict=%v)", ks.engaged, mock.applies, mock.lastMode)
	}

	// Auto mode: VPN recovers -> MUST disengage.
	ks.Sync(wfpModeAuto, true, false, true)
	if ks.engaged || mock.clears != 2 {
		t.Fatalf("auto mode must disengage on VPN recovery (engaged=%v clears=%d)", ks.engaged, mock.clears)
	}

	// Strict mode: engages immediately even when VPN is up.
	ks.Sync(wfpModeStrict, true, false, true)
	if !ks.engaged || mock.applies != 2 || !mock.lastMode {
		t.Fatalf("strict mode must engage strict WFP (engaged=%v applies=%d strict=%v)", ks.engaged, mock.applies, mock.lastMode)
	}

	ks.Close()
	if ks.engaged {
		t.Fatal("Close() must disengage WFP Kill Switch")
	}
}

func TestCleanChainMTUAndMSSClamping(t *testing.T) {
	if got := effectiveTunMTUWithClean(1500, true, true, true); got != cleanExitWarpMTU {
		t.Fatalf("expected Clean-IP MTU %d, got %d", cleanExitWarpMTU, got)
	}
	if got := effectiveTunMSSWithClean(1500, false, true, true, true); got > cleanChainMSS4 {
		t.Fatalf("expected IPv4 TCP MSS <= %d for Clean-IP cascade, got %d", cleanChainMSS4, got)
	}
	if got := effectiveTunMSSWithClean(1500, true, true, true, true); got > cleanChainMSS6 {
		t.Fatalf("expected IPv6 TCP MSS <= %d for Clean-IP cascade, got %d", cleanChainMSS6, got)
	}
}

func TestCleanIPOutboundRoutingAndValidation(t *testing.T) {
	if !validOutbound(obCleanIP) {
		t.Fatal("obCleanIP must be accepted by validOutbound")
	}
	if err := checkRule(Rule{Name: "AI Clean", Outbound: obCleanIP, Domains: []string{"chatgpt.com"}}); err != nil {
		t.Fatalf("checkRule rejected clean-ip rule: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	a := NewApp(ctx, cancel, filepath.Join(dir, "psiroute.json"), dir)
	a.cfg.Routing.Mode = "rules"
	a.cfg.Routing.Rules = []Rule{
		{Name: "AI Clean", Outbound: obCleanIP, Domains: []string{"chatgpt.com"}},
	}
	a.cleanChain.testDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	ord, rule := a.router.plan("chatgpt.com", 443)
	if len(ord) == 0 || ord[0] != obCleanIP {
		t.Fatalf("expected chatgpt.com -> clean-ip, got %v (rule=%q)", ord, rule)
	}
	if !a.cleanChain.Healthy() && a.cleanChain.Name() != obCleanIP {
		t.Fatalf("unexpected CleanChain name: %q", a.cleanChain.Name())
	}
}

func TestUDPGWBindEndpointParsing(t *testing.T) {
	pb := newPhysUDPBind()
	ep, err := pb.ParseEndpoint("162.159.192.1:2408")
	if err != nil {
		t.Fatalf("physUDPBind.ParseEndpoint failed: %v", err)
	}
	if ep.DstToString() != "162.159.192.1:2408" {
		t.Fatalf("unexpected endpoint string: %q", ep.DstToString())
	}

	ub := newUDPGWBind(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, context.Canceled
	})
	ep2, err := ub.ParseEndpoint("188.114.96.1:2408")
	if err != nil {
		t.Fatalf("udpgwBind.ParseEndpoint failed: %v", err)
	}
	if ep2.DstIP().String() != "188.114.96.1" {
		t.Fatalf("unexpected udpgw endpoint IP: %q", ep2.DstIP().String())
	}
}

func TestResolveTCPHostPrefersRealSNIOverStaleFakeIP(t *testing.T) {
	dst := netip.MustParseAddr("198.18.0.5")
	// Stale browser FakeIP collision: browser wants 2ip.io, FakeIP pool mapped 198.18.0.5 to google.com.
	if got := resolveTCPHost(dst, "2ip.io", "google.com"); got != "2ip.io" {
		t.Fatalf("real SNI must win over colliding fakeDomain, got %q", got)
	}
	// ECH outer SNI: must still resolve to real fakeDomain.
	if got := resolveTCPHost(dst, "cloudflare-ech.com", "youtube.com"); got != "youtube.com" {
		t.Fatalf("ECH outer SNI should fall back to fakeDomain, got %q", got)
	}
	// Empty SNI (non-TLS): must use fakeDomain.
	if got := resolveTCPHost(dst, "", "discord.gg"); got != "discord.gg" {
		t.Fatalf("empty SNI should use fakeDomain, got %q", got)
	}
}

func TestFakeIPRandomRangeAvoidsOtherVPNCollision(t *testing.T) {
	pool := &fakeIPPool{
		next:   randomFakeIPStart(),
		byHost: map[string]*fakeEntry{},
		byAddr: map[netip.Addr]*fakeEntry{},
	}
	ip := pool.Assign("2ip.io")
	if !isFakeIP(ip) {
		t.Fatalf("allocated IP %s must be inside 198.18.0.0/15", ip)
	}
	b := ip.As4()
	if b[0] != 198 || b[1] != 19 {
		t.Fatalf("allocated IP %s should be in 198.19.x.y to avoid 198.18.0.x VPN collisions", ip)
	}
}

func TestIsVirtualVPNAdapterDetection(t *testing.T) {
	for _, tc := range [][2]string{
		{"sing-tun", "Wintun Userspace Tunnel"},
		{"Clash", "Meta TUN"},
		{"AmneziaWG", "AmneziaWG Tunnel"},
		{"CloudflareWARP", "Cloudflare WARP"},
		{"v2rayN", "Wintun Adapter"},
	} {
		if !isVirtualVPNAdapterName(tc[0], tc[1]) {
			t.Fatalf("expected virtual VPN adapter %v to be detected", tc)
		}
	}
	for _, tc := range [][2]string{
		{"Ethernet", "Realtek PCIe GbE Family Controller"},
		{"Беспроводная сеть", "Intel(R) Wi-Fi 6 AX201"},
	} {
		if isVirtualVPNAdapterName(tc[0], tc[1]) {
			t.Fatalf("physical NIC %v must not be flagged as virtual VPN", tc)
		}
	}
}

func TestBlockedCountriesBlacklist(t *testing.T) {
	cfg := defaultConfig()
	cfg.setKey("psiphon.blocked_countries", []any{"ru", "BY", "ir", "AUTO", "invalid"})
	if !cfg.isCountryBlocked("RU") || !cfg.isCountryBlocked("by") || !cfg.isCountryBlocked("IR") {
		t.Fatalf("expected RU/BY/IR to be blocked, got %v", cfg.Psiphon.BlockedCountries)
	}
	if cfg.isCountryBlocked("NL") || cfg.isCountryBlocked("AUTO") {
		t.Fatalf("NL and AUTO must not be blocked: %v", cfg.Psiphon.BlockedCountries)
	}
}

func TestDirectPsiphonStrategiesBeforeWarpFallback(t *testing.T) {
	cfg := defaultConfig()
	// Restored order (Rocky fix 8): via-warp is first by default, the direct and
	// desync strategies stay in the list behind it.
	if len(cfg.Psiphon.Strategies) == 0 || cfg.Psiphon.Strategies[0] != "via-warp" {
		t.Fatalf("expected via-warp first, got %v", cfg.Psiphon.Strategies)
	}
	if !slices.Contains(cfg.Psiphon.Strategies, "direct-dpi") {
		t.Fatalf("direct-dpi must stay in the default list, got %v", cfg.Psiphon.Strategies)
	}
	// Enabling WARP must not move or duplicate via-warp
	cfg.setKey("warp.enabled", true)
	if cfg.Psiphon.Strategies[0] != "via-warp" || strings.Count(strings.Join(cfg.Psiphon.Strategies, ","), "via-warp") != 1 {
		t.Fatalf("enabling warp must keep a single via-warp first, got %v", cfg.Psiphon.Strategies)
	}
	if _, ok := strategyByID("direct-dpi"); !ok {
		t.Fatal("direct-dpi strategy must be registered in psiStrategies")
	}
}

func TestRoundZeroTriesDirectBeforeWarpEvenWithHistory(t *testing.T) {
	ordered := []strategyDef{
		{ID: "via-warp", Transport: "warp"},
		{ID: "direct-dpi", Transport: "desync", Protos: "tls"},
		{ID: "desync-meek", Transport: "desync", Protos: "meek"},
	}
	p := &Psi{}
	// Rocky fix 9: no forced promotion of direct/desync ahead of WARP; the
	// configured/learned order is respected.
	plan := p.buildRoundZeroPlan(ordered)
	if len(plan) == 0 || plan[0].ID != "via-warp" {
		t.Fatalf("Round 0 must keep the configured first strategy (via-warp), got %v", plan)
	}
	reversed := []strategyDef{ordered[1], ordered[0], ordered[2]}
	if plan := p.buildRoundZeroPlan(reversed); len(plan) == 0 || plan[0].ID != "direct-dpi" {
		t.Fatalf("when direct-dpi is configured first it stays first, got %v", plan)
	}
}
