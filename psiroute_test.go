package main

// Unit tests per docs/TESTING_TZ.md section 2. No network access is used:
// everything runs against in-process helpers and crypto/tls-generated data.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// testApp builds an App rooted in a temp dir (config, learned, days files).
func testApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	a := NewApp(ctx, cancel, filepath.Join(dir, "psiroute.json"), dir)
	t.Cleanup(func() {
		cancel()
		a.Shutdown()
	})
	return a
}

func setCfg(app *App, f func(c *Config)) {
	app.cfg.mu.Lock()
	f(app.cfg)
	app.cfg.mu.Unlock()
	if app.router != nil {
		app.router.InvalidateRules()
	}
}

// ---------- router.go: hostMatches ----------

func TestHostMatches(t *testing.T) {
	cases := []struct {
		host, pat string
		want      bool
	}{
		{"example.com", "example.com", true},   // exact
		{"a.example.com", "example.com", true}, // subdomain
		{"a.b.com", "b.com", true},             // deep subdomain
		{"b.com", "*.b.com", true},             // *. template on the apex
		{"a.b.com", "*.b.com", true},           // *. template on a subdomain
		{"EXAMPLE.com", "example.COM", true},   // case-insensitive
		{"1.2.3.4", "1.2.3.4", true},           // IP exact
		{"1.2.3.4", "2.3.4", false},            // IP suffix must not match across the dot
		{"xb.com", "b.com", false},             // suffix without a dot boundary
		{"example.com", "ample.com", false},
		{"", "example.com", false}, // empty host
		{"example.com", "", false}, // empty pattern
		{"", "", false},            // 1.0.3: an empty pattern matches nothing
	}
	for _, c := range cases {
		if got := hostMatches(c.host, c.pat); got != c.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", c.host, c.pat, got, c.want)
		}
	}
}

// ---------- router.go: Router.plan ----------

func TestRouterPlanPsiphonMode(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) { c.Routing.Learn = false })
	order, rule := app.router.plan("anything.test", 443)
	if len(order) != 1 || order[0] != obPsiphon {
		t.Fatalf("plan = %v, want [psiphon]", order)
	}
	if rule != "всё через Psiphon" {
		t.Fatalf("rule = %q", rule)
	}
}

func TestRouterPlanRulesMode(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Learn = false
		c.Routing.Failover = true
		c.Routing.Default = obPsiphon
		c.Routing.Rules = []Rule{
			{Name: "прямой", Outbound: obDirect, Domains: []string{"blocked.test"}},
			{Name: "почта", Outbound: obDirect, Ports: []int{25}},
			{Name: "ключ", Outbound: obDesync, Keywords: []string{"video"}},
		}
	})
	// rule by domain: explicit direct rule never appends psiphon failover
	order, name := app.router.plan("www.blocked.test", 443)
	if len(order) != 1 || order[0] != obDirect || name != "прямой" {
		t.Fatalf("domain plan = %v (%q)", order, name)
	}
	// rule by port matches even when the domain does not
	order, name = app.router.plan("other.test", 25)
	if len(order) != 1 || order[0] != obDirect || name != "почта" {
		t.Fatalf("port plan = %v (%q)", order, name)
	}
	// rule by keyword: in "rules" mode Failover must NOT append obPsiphon to obDesync
	order, name = app.router.plan("my-video.test", 443)
	if len(order) != 1 || order[0] != obDesync || name != "ключ" {
		t.Fatalf("keyword plan = %v (%q), want [direct-dpi] without psiphon failover", order, name)
	}
	// no rule: in "rules" mode unmatched traffic goes to obDirect ("по умолчанию (мимо VPN)") without psiphon failover
	order, name = app.router.plan("unknown.test", 443)
	if len(order) != 1 || order[0] != obDirect || name != "по умолчанию (мимо VPN)" {
		t.Fatalf("default plan = %v (%q), want [direct] (\"по умолчанию (мимо VPN)\")", order, name)
	}
}

func TestRouterPlanAutoMode(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "auto"
		c.Routing.Learn = false
		c.Routing.Failover = false
		c.Routing.Chain = []string{obDirect, obDesync, obPsiphon}
		c.Desync.Enabled = true
	})
	order, _ := app.router.plan("x.test", 443)
	if strings.Join(order, ",") != "direct,direct-dpi,psiphon" {
		t.Fatalf("auto plan = %v", order)
	}
	// desync disabled: direct-dpi is skipped from the chain
	setCfg(app, func(c *Config) { c.Desync.Enabled = false })
	order, _ = app.router.plan("x.test", 443)
	if strings.Join(order, ",") != "direct,psiphon" {
		t.Fatalf("auto plan without desync = %v", order)
	}
	// failover appends psiphon when the chain lacks it
	setCfg(app, func(c *Config) {
		c.Routing.Failover = true
		c.Routing.Chain = []string{obDirect}
	})
	order, _ = app.router.plan("x.test", 443)
	if strings.Join(order, ",") != "direct,psiphon" {
		t.Fatalf("auto plan with failover = %v", order)
	}
}

func TestRouterPlanLearnedFirst(t *testing.T) {
	app := testApp(t)
	// 1.0.3: learned routes are an AUTO-mode feature only.
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "auto"
		c.Routing.Chain = []string{obWarp, obDirect}
		c.Routing.Default = obPsiphon
		c.Routing.Learn = true
		c.Routing.Failover = true
	})
	app.router.remember("learned.test", obDirect, "тест", true)
	order, name := app.router.plan("learned.test", 443)
	if len(order) != 2 || order[0] != obDirect || order[1] != obPsiphon {
		t.Fatalf("learned plan = %v (%q)", order, name)
	}
	// In rules mode a learned VPN/WARP entry must NOT hijack unmatched traffic:
	// unmatched hosts go to obDirect ("по умолчанию (мимо VPN)") without psiphon failover.
	app.router.remember("learned-vpn.test", obWarp, "тест-vpn", true)
	setCfg(app, func(c *Config) { c.Routing.Mode = "rules" })
	order, name = app.router.plan("learned-vpn.test", 443)
	if len(order) != 1 || order[0] != obDirect || name != "по умолчанию (мимо VPN)" {
		t.Fatalf("rules mode must ignore learned and route unmatched to direct, plan = %v (%q)", order, name)
	}
}

// ---------- router.go: remember / forget / clearLearned ----------

func TestLearnedPersist(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) { c.Routing.Learn = true })
	file := filepath.Join(app.dataDir, "psiroute-learned.json")

	app.router.remember("a.test", obDirect, "r1", true)
	// 1.0.3: a failure against a host with no entry creates nothing.
	app.router.remember("b.test", obPsiphon, "r2", false)

	list := app.router.learnedList()
	if len(list) != 1 || list[0]["host"] != "a.test" || list[0]["hits"] != 0 {
		t.Fatalf("learnedList = %v", list)
	}
	// hits grow on USE (learnedFor), not on remember.
	if got := app.router.learnedFor("a.test"); got != obDirect {
		t.Fatalf("learnedFor = %q", got)
	}
	if list := app.router.learnedList(); list[0]["hits"] != 1 {
		t.Fatalf("hits must grow on use: %v", list)
	}

	app.router.flush() // saves are debounced in 1.0.3; flush forces the write

	// a fresh router over the same file sees the saved entries
	r2 := newRouter(app, file)
	r2.mu.Lock()
	_, okA := r2.seen["a.test"]
	_, okB := r2.seen["b.test"]
	r2.mu.Unlock()
	if !okA || okB {
		t.Fatalf("reloaded router wrong: a=%v b=%v (b must be absent)", okA, okB)
	}

	// forget(host) also drops learned subdomains (1.0.3).
	app.router.remember("sub.a.test", obWarp, "r3", true)
	app.router.forget("a.test")
	app.router.mu.Lock()
	_, stillA := app.router.seen["a.test"]
	_, stillSub := app.router.seen["sub.a.test"]
	app.router.mu.Unlock()
	if stillA || stillSub {
		t.Fatal("forget did not remove a.test and its subdomain")
	}

	app.router.clearLearned()
	app.router.flush()
	if n := len(app.router.learnedList()); n != 0 {
		t.Fatalf("after clearLearned: %d entries", n)
	}
	b, err := os.ReadFile(file)
	if err != nil || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("learned file after clear = %q, err=%v", b, err)
	}
}

// ---------- desync.go: parseSNI / splitClientHello ----------

// clientHello generates a real TLS ClientHello (crypto/tls) for a server name.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		tc := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec // test data generation
		_ = tc.Handshake()
		client.Close()
	}()
	var out []byte
	buf := make([]byte, 8192)
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 8; i++ {
		n, err := server.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil || parseSNI(out) == serverName {
			break
		}
	}
	if len(out) < 6 || out[0] != 0x16 {
		t.Fatalf("no ClientHello captured (%d bytes)", len(out))
	}
	return out
}

func TestParseSNI(t *testing.T) {
	hello := clientHello(t, "blocked.test")
	if got := parseSNI(hello); got != "blocked.test" {
		t.Fatalf("parseSNI(real ClientHello) = %q, want blocked.test", got)
	}
	if got := parseSNI(hello[:20]); got != "" { // truncated
		t.Fatalf("parseSNI(truncated) = %q, want empty", got)
	}
	if got := parseSNI([]byte("GET / HTTP/1.1\r\n\r\n")); got != "" { // not TLS
		t.Fatalf("parseSNI(http) = %q, want empty", got)
	}
	if got := parseSNI(nil); got != "" {
		t.Fatalf("parseSNI(nil) = %q", got)
	}
	if got := parseSNI([]byte{0x16, 0x03, 0x01}); got != "" { // header only
		t.Fatalf("parseSNI(short) = %q", got)
	}
}

func TestSplitClientHello(t *testing.T) {
	hello := clientHello(t, "blocked.test")
	parts := splitClientHello(hello)
	if len(parts) != 2 {
		t.Fatalf("splitClientHello -> %d parts, want 2", len(parts))
	}
	// reassembling the record bodies must reproduce the original record body
	body := func(rec []byte) []byte {
		if len(rec) < 5 || rec[0] != 0x16 {
			t.Fatalf("part is not a TLS handshake record: % x", rec[:min(5, len(rec))])
		}
		l := int(rec[3])<<8 | int(rec[4])
		if 5+l > len(rec) {
			t.Fatalf("record declares %d body bytes, has %d", l, len(rec)-5)
		}
		return rec[5 : 5+l]
	}
	joined := append(body(parts[0]), body(parts[1])...)
	origLen := int(hello[3])<<8 | int(hello[4])
	if string(joined) != string(hello[5:5+origLen]) {
		t.Fatal("reassembled ClientHello differs from the original")
	}
	// the cut must land inside the SNI: neither part alone contains the name
	if strings.Contains(string(parts[0]), "blocked.test") || strings.Contains(string(parts[1]), "blocked.test") {
		t.Fatal("one part still contains the full SNI")
	}
	off, n := findSNI(hello[5 : 5+origLen])
	if off < 0 {
		t.Fatal("findSNI failed on a real ClientHello")
	}
	cut := len(body(parts[0]))
	if cut <= off || cut >= off+n {
		t.Fatalf("cut at %d, SNI at [%d,%d) — cut is not inside the SNI", cut, off, off+n)
	}
	// non-TLS data passes through unchanged
	raw := []byte("plain data, not TLS")
	if p := splitClientHello(raw); len(p) != 1 || string(p[0]) != string(raw) {
		t.Fatal("non-TLS data must be returned unchanged")
	}
}

// ---------- config.go ----------

func TestDefaultConfig(t *testing.T) {
	c := defaultConfig()
	if c.Psiphon.Parallel != 2 || !c.Psiphon.Standby {
		t.Fatal("unexpected psiphon defaults")
	}
	if c.General.Listen != "127.0.0.1:1080" || c.General.UI != "127.0.0.1:9090" {
		t.Fatal("unexpected listen defaults")
	}
	if c.Routing.Mode != "psiphon" || !c.Routing.Failover || !c.Routing.Learn {
		t.Fatal("unexpected routing defaults")
	}
	if len(c.Psiphon.Strategies) == 0 || len(c.Routing.Chain) == 0 || len(c.Routing.Rules) != 0 {
		t.Fatal("unexpected list defaults")
	}
}

func TestConfigSetKeyAndValues(t *testing.T) {
	c := defaultConfig()
	restartKeys := map[string]bool{
		"psiphon.parallel": true, "psiphon.standby": true,
		"psiphon.health_interval_secs": false, "psiphon.min_speed_kbps": false,
		"psiphon.dpi": true, "psiphon.single_process_countries": false,
		// 5 keys added by the merge (42 in total): tuning preset, seed mirror and Psiphon identity
		"psiphon.preset": true, "psiphon.mirror_url": false,
		"psiphon.propagation_channel_id": true, "psiphon.sponsor_id": true, "psiphon.client_platform": true,
		"desync.enabled": false, "desync.method": false,
		"warp.enabled": true, "warp.socks": true,
		"warp.engine": true, "warp.mask": false, "warp.endpoint": false,
		"proxy.enabled": true, "proxy.upstream": true,
		"dns.enabled": false, "dns.local_server": false, "dns.local_addr": false, "udp.mode": false,
		"tun.enabled": false, "tun.mtu": false, "tun.dns_hijack": false, "tun.fake_ip": false, "tun.ipv6": false, "tun.exclude_apps": false,
		"routing.failover": false, "routing.learn": false,
		"routing.bypass_lan": false, "routing.block_quic": false, "routing.kill_switch": false, "routing.kill_switch_mode": false, "routing.block_stun": false,
		"clean_chain.enabled": false, "clean_chain.auto_chain": false,
		"general.watch_config": false, "general.system_proxy": false, "general.ui_mode": false,
	}
	vals := c.values()
	if len(restartKeys) != 42 {
		t.Fatalf("test table must cover 42 keys, has %d", len(restartKeys))
	}
	if len(vals) != len(restartKeys) {
		t.Fatalf("values() has %d keys, test table has %d", len(vals), len(restartKeys))
	}
	for key, wantRestart := range restartKeys {
		var v any
		wantInt := 7
		switch vals[key].(type) {
		case bool:
			v = true
		case int:
			if key == "tun.mtu" {
				wantInt = 1400
			}
			v = float64(wantInt)
		case string:
			v = "changed"
			switch key {
			case "udp.mode": // only route/direct/psiphon/off are accepted
				v = "direct"
			case "desync.method": // only auto or a valid obfs method id
				v = "split"
			case "general.ui_mode": // only native or browser
				v = "browser"
			case "routing.kill_switch_mode": // off | auto | strict
				v = "strict"
			case "psiphon.preset": // only fast | balanced | patient are kept
				v = PresetFast
			case "psiphon.mirror_url": // https URL with a host
				v = "https://mirror.example.com/seeds.txt"
			case "psiphon.propagation_channel_id", "psiphon.sponsor_id": // exactly 16 hex chars
				v = "0123456789ABCDEF"
			}
		}
		if got := c.setKey(key, v); got != wantRestart {
			t.Errorf("setKey(%q) restart = %v, want %v", key, got, wantRestart)
		}
		if c.values()[key] != v && key != "psiphon.parallel" {
			if iv, ok := c.values()[key].(int); !ok || iv != wantInt {
				t.Errorf("setKey(%q): value did not stick: %v", key, c.values()[key])
			}
		}
	}
	if got := c.setKey("no.such.key", true); got {
		t.Error("unknown key must not request a restart")
	}
}

func TestReloadConfigBrokenKeepsOld(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) { c.Psiphon.Parallel = 3 })
	if err := app.cfg.save(); err != nil {
		t.Fatal(err)
	}
	// valid edit applies
	good, _ := os.ReadFile(app.cfgPath)
	var m map[string]any
	_ = json.Unmarshal(good, &m)
	m["psiphon"].(map[string]any)["parallel"] = float64(4)
	b, _ := json.Marshal(m)
	_ = os.WriteFile(app.cfgPath, b, 0o600)
	app.reloadConfig()
	app.cfg.mu.Lock()
	if app.cfg.Psiphon.Parallel != 4 {
		t.Fatalf("after valid reload parallel = %d, want 4", app.cfg.Psiphon.Parallel)
	}
	app.cfg.mu.Unlock()
	// broken file: settings stay untouched
	_ = os.WriteFile(app.cfgPath, []byte("{broken json"), 0o600)
	app.reloadConfig()
	app.cfg.mu.Lock()
	defer app.cfg.mu.Unlock()
	if app.cfg.Psiphon.Parallel != 4 {
		t.Fatalf("broken reload changed settings: parallel = %d", app.cfg.Psiphon.Parallel)
	}
}

// ---------- dns.go ----------

func TestDNSCache(t *testing.T) {
	theDNS.clear()
	theDNS.mu.Lock()
	theDNS.m["cached.test"] = dnsEntry{ips: []string{"203.0.113.7"}, exp: time.Now().Add(time.Minute)}
	theDNS.mu.Unlock()

	ctx := context.Background()
	ips, err := resolve(ctx, "cached.test", false)
	if err != nil || len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Fatalf("resolve(cached) = %v, %v", ips, err)
	}
	// literal IPs resolve to themselves without any lookup
	ips, err = resolve(ctx, "192.0.2.55", true)
	if err != nil || ips[0] != "192.0.2.55" {
		t.Fatalf("resolve(IP) = %v, %v", ips, err)
	}
	// concurrent readers/writers (matters under -race)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = resolve(ctx, "cached.test", false)
			theDNS.clear()
			theDNS.mu.Lock()
			theDNS.m["cached.test"] = dnsEntry{ips: []string{"203.0.113.7"}, exp: time.Now().Add(time.Minute)}
			theDNS.mu.Unlock()
		}()
	}
	wg.Wait()
	theDNS.clear()
	theDNS.mu.Lock()
	n := len(theDNS.m)
	theDNS.mu.Unlock()
	if n != 0 {
		t.Fatalf("clear() left %d entries", n)
	}
}

// ---------- psi.go ----------

func TestApplyDPI(t *testing.T) {
	modes := []struct {
		mode     string
		fragProb float64
		tlsProb  float64
	}{
		{"off", 0, 0},
		{"hello", 0, 1},
		{"light", 1, 1},
		{"strong", 1, 1},
		{"", 1, 1},        // standard
		{"unknown", 1, 1}, // falls through to standard
	}
	for _, m := range modes {
		c := &psiphon.Config{}
		applyDPI(c, m.mode)
		if c.FragmentorProbability == nil || *c.FragmentorProbability != m.fragProb {
			t.Errorf("applyDPI(%q): FragmentorProbability = %v", m.mode, c.FragmentorProbability)
		}
		if c.TLSFragmentClientHelloProbability == nil || *c.TLSFragmentClientHelloProbability != m.tlsProb {
			t.Errorf("applyDPI(%q): TLSFragmentClientHelloProbability = %v", m.mode, c.TLSFragmentClientHelloProbability)
		}
	}
	// strong fragments finer than light
	cl, cs := &psiphon.Config{}, &psiphon.Config{}
	applyDPI(cl, "light")
	applyDPI(cs, "strong")
	if *cs.FragmentorMaxWriteBytes >= *cl.FragmentorMaxWriteBytes {
		t.Error("strong mode must use smaller writes than light mode")
	}
}

func TestConfigForStrategies(t *testing.T) {
	app := testApp(t)
	for _, s := range psiStrategies {
		cfg := app.psi.configFor(s, 0)
		if cfg == nil {
			t.Fatalf("configFor(%s) = nil", s.ID)
		}
		if len(cfg.RemoteServerListURLs) == 0 {
			t.Fatalf("configFor(%s): no RemoteServerListURLs", s.ID)
		}
		raw, err := base64.StdEncoding.DecodeString(cfg.RemoteServerListURLs[0].URL)
		if err != nil || string(raw) != psiRSLURL {
			t.Fatalf("configFor(%s): RSL URL is not the base64 of psiRSLURL (%q, %v)", s.ID, raw, err)
		}
		if _, err := json.Marshal(cfg); err != nil {
			t.Fatalf("configFor(%s) does not marshal to JSON: %v", s.ID, err)
		}
		if err := cfg.Commit(true); err != nil {
			t.Fatalf("configFor(%s) fails Commit: %v", s.ID, err)
		}
	}
	// strategies with an upstream must not fragment; direct ones carry DPI settings
	byID := map[string]strategyDef{}
	for _, s := range psiStrategies {
		byID[s.ID] = s
	}
	if cfg := app.psi.configFor(byID["via-warp"], 0); cfg.UpstreamProxyURL == "" {
		t.Error("via-warp config has no upstream proxy URL")
	}
	if cfg := app.psi.configFor(byID["quic"], 0); cfg.TLSFragmentClientHelloProbability == nil || *cfg.TLSFragmentClientHelloProbability != 0 {
		t.Error("quic strategy forces DPI off: TLS fragmentation must be 0")
	}
}

func TestCleanPsiErr(t *testing.T) {
	in := "psiphon.(*Config).Commit#2090: failed to decode URL: illegal base64 data"
	if got := cleanPsiErr(in); got != "failed to decode URL: illegal base64 data" {
		t.Fatalf("cleanPsiErr = %q", got)
	}
	long := strings.Repeat("x", 300)
	if got := cleanPsiErr(long); len([]rune(got)) != 201 { // 200 + ellipsis
		t.Fatalf("cleanPsiErr must truncate to 200 runes + ellipsis, got %d", len([]rune(got)))
	}
}

func TestPsiHelpers(t *testing.T) {
	if strategy, ok := strategyByID("meek"); !ok || strategy.Protos != "meek" {
		t.Fatal("strategyByID(meek) broken")
	}
	if _, ok := strategyByID("nope"); ok {
		t.Fatal("strategyByID(nope) must not be found")
	}
	if got := short("привет, мир", 6); got != "привет…" {
		t.Fatalf("short = %q", got)
	}
	if num(float64(42)) != 42 || num("x") != 0 {
		t.Fatal("num broken")
	}
	if l := strList([]any{"a", 1, "b"}); len(l) != 2 || l[0] != "a" || l[1] != "b" {
		t.Fatalf("strList = %v", l)
	}
	if len(psiDPIStrategies()) != 9 {
		t.Fatalf("probe matrix = %d entries, want 9", len(psiDPIStrategies()))
	}
}

// ---------- stats.go ----------

func TestStatsConcurrent(t *testing.T) {
	s := newStats(filepath.Join(t.TempDir(), "days.json"))
	const conns = 100
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := s.open("test", "host.test", "", 443, obDirect, "тест")
			s.add(tr, 100, 200)
			s.close(tr, nil)
		}()
	}
	wg.Wait()
	if got := s.totUp.Load(); got != conns*100 {
		t.Fatalf("total up = %d, want %d", got, conns*100)
	}
	if got := s.totDown.Load(); got != conns*200 {
		t.Fatalf("total down = %d, want %d", got, conns*200)
	}
	s.tick()
	s.mu.Lock()
	day := s.days[time.Now().Format("2006-01-02")]
	s.mu.Unlock()
	if day == nil || day[0] != conns*100 || day[1] != conns*200 {
		t.Fatalf("day totals = %v", day)
	}
	snap := s.snapshot()
	total := snap["total"].(map[string]any)
	if total["up"].(int64) != conns*100 || total["down"].(int64) != conns*200 {
		t.Fatalf("snapshot total = %v", total)
	}
	if h := s.history(); len(h) != 1 {
		t.Fatalf("history = %v", h)
	}
	// double close must not double-count
	tr := s.open("test", "h", "", 80, obDirect, "")
	s.add(tr, 5, 5)
	s.close(tr, nil)
	s.close(tr, nil)
	if got := s.totUp.Load(); got != conns*100+5 {
		t.Fatalf("after double close up = %d", got)
	}
}

// ---------- share.go ----------

func TestShareInfoAndQR(t *testing.T) {
	app := testApp(t)
	info := app.shareInfo()
	if info["enabled"] != false {
		t.Fatal("share must start disabled")
	}
	socks, _ := info["socks"].(string)
	if !strings.HasPrefix(socks, "socks5://") || !strings.Contains(socks, "@") || !strings.Contains(socks, ":1081") {
		t.Fatalf("socks link = %q", socks)
	}
	tg, _ := info["qr"].(string)
	_ = tg
	// qr fields are SVGs; check both the raw helper and shareInfo output
	svg := qrSVG(socks)
	if !strings.HasPrefix(svg, "<svg") || !strings.HasSuffix(svg, "</svg>") {
		t.Fatalf("qrSVG is not an SVG: %.40q", svg)
	}
	var doc any
	if err := xml.Unmarshal([]byte(svg), &doc); err != nil {
		// xml.Unmarshal into *any is not supported everywhere; fall back to a decoder walk
		d := xml.NewDecoder(strings.NewReader(svg))
		for {
			_, err := d.Token()
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				t.Fatalf("qrSVG is not valid XML: %v", err)
			}
		}
	}
	full := app.shareInfo()
	qrTg, _ := full["qr_tg"].(string)
	if !strings.HasPrefix(qrTg, "<svg") {
		t.Fatal("qr_tg is not an SVG")
	}
	p1, p2 := randomPass(10), randomPass(10)
	if len(p1) != 10 || p1 == p2 {
		t.Fatal("randomPass broken")
	}
	for _, ch := range p1 {
		if !strings.ContainsRune("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", ch) {
			t.Fatalf("randomPass produced %q", ch)
		}
	}
}

// ---------- proxy.go helpers ----------

func TestIsPrivateAddr(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want bool
	}{
		{&net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, true},
		{&net.TCPAddr{IP: net.ParseIP("192.168.1.5")}, true},
		{&net.TCPAddr{IP: net.ParseIP("10.0.0.9")}, true},
		{&net.TCPAddr{IP: net.ParseIP("8.8.8.8")}, false},
		{&net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, false}, // not a TCPAddr
	}
	for _, c := range cases {
		if got := isPrivateAddr(c.addr); got != c.want {
			t.Errorf("isPrivateAddr(%v) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestCleanHost(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/path?q=1": "example.com",
		"example.com:8443":             "example.com",
		"example.com":                  "example.com",
		"  EXAMPLE.com  ":              "example.com",
		"[::1]:443":                    "::1",
	}
	for in, want := range cases {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, want %q", in, got, want)
		}
	}
}
