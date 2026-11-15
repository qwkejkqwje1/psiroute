package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------- 1.0.9: block and auto outbounds in rules ----------

func TestRouterPlanBlockAndAutoRules(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Failover = true
		c.Routing.Learn = true
		c.Routing.Default = obPsiphon
		c.Routing.Chain = []string{obDirect, obDesync, obPsiphon}
		c.Desync.Enabled = true
		c.Routing.Rules = []Rule{
			{Name: "телеметрия", Outbound: obBlock, Domains: []string{"ads.example.com"}, Always: true},
			{Name: "авто-правило", Outbound: obAuto, Domains: []string{"video.example.com"}},
		}
	})

	// 1. A block rule must never append psiphon failover, even when failover=true.
	order, rule := app.router.plan("sub.ads.example.com", 443)
	if len(order) != 1 || order[0] != obBlock || rule != "телеметрия" {
		t.Fatalf("block rule plan = %v (%q), want [block]", order, rule)
	}

	// 2. An Always block rule also wins in psiphon mode.
	setCfg(app, func(c *Config) { c.Routing.Mode = "psiphon" })
	order, rule = app.router.plan("ads.example.com", 443)
	if len(order) != 1 || order[0] != obBlock || rule != "телеметрия" {
		t.Fatalf("always block rule in psiphon mode = %v (%q)", order, rule)
	}

	// 3. An "auto" rule in rules mode expands to the auto chain and respects learned routes.
	setCfg(app, func(c *Config) { c.Routing.Mode = "rules" })
	order, rule = app.router.plan("video.example.com", 443)
	if strings.Join(order, ",") != "direct,direct-dpi,psiphon" || rule != "авто-правило" {
		t.Fatalf("auto rule plan = %v (%q)", order, rule)
	}
	app.router.remember("video.example.com", obDesync, "тест", true)
	order, rule = app.router.plan("video.example.com", 443)
	if strings.Join(order, ",") != "direct-dpi,psiphon" || rule != "авто-правило" {
		t.Fatalf("auto rule plan with learned = %v (%q)", order, rule)
	}

	// 4. UDP for a blocked host returns empty outbound (dropped).
	if ob, _ := app.planUDP("ads.example.com", 443, ""); ob != "" {
		t.Fatalf("planUDP for blocked host = %q, want empty", ob)
	}

	// 5. Dialing obBlock directly returns errBlocked and socksErrCode = 2.
	if _, err := app.router.dialer(obBlock)(context.Background(), "tcp", "127.0.0.1:443"); !errors.Is(err, errBlocked) {
		t.Fatalf("dialer(obBlock) err = %v, want errBlocked", err)
	}
	if code := socksErrCode(errBlocked); code != 2 {
		t.Fatalf("socksErrCode(errBlocked) = %d, want 2", code)
	}
}

func TestProxyBlockRuleRejectsSocksAndHTTP(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	_, proxy := proxyApp(t, nil, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Failover = true
		c.Routing.Rules = []Rule{
			{Name: "блок", Outbound: obBlock, Domains: []string{"blocked.local"}},
		}
	})

	// SOCKS5 to blocked domain must fail (reply code 2)
	_, port, _ := net.SplitHostPort(echo)
	if _, err := dialSocks5(context.Background(), proxy, "blocked.local:"+port, "", ""); err == nil {
		t.Fatal("SOCKS5 to blocked domain must fail")
	}

	// HTTP CONNECT to blocked domain must return 403 Forbidden
	c, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "CONNECT blocked.local:443 HTTP/1.1\r\nHost: blocked.local:443\r\n\r\n")
	buf := make([]byte, 128)
	n, _ := c.Read(buf)
	if !strings.Contains(string(buf[:n]), "403 Forbidden") {
		t.Fatalf("HTTP CONNECT to blocked domain returned %q, want 403 Forbidden", buf[:n])
	}
}

// ---------- 1.0.9: CIDR and IP-list matching with cached DNS / packet IP ----------

func TestMatchRuleWithCachedDNSAndPacketIP(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Failover = false
		c.Routing.Rules = []Rule{
			{Name: "подсеть", Outbound: obPsiphon, CIDR: []string{"149.154.160.0/20"}},
			{Name: "список IP", Outbound: obWarp, Lists: []string{"telegram-ip"}},
		}
	})
	u, _ := resolveListURL("telegram-ip")
	app.lists.data[u] = parseList(strings.NewReader("91.108.4.0/22\n"))

	// 1. Domain with packet destination IP (as in TUN mode after SNI sniff) matches CIDR and IP-list rules.
	order, rule := app.router.planForIP("web.telegram.org", "149.154.167.99", 443, "")
	if len(order) != 1 || order[0] != obPsiphon || rule != "подсеть" {
		t.Fatalf("planForIP(CIDR) = %v (%q)", order, rule)
	}
	order, rule = app.router.planForIP("core.telegram.org", "91.108.5.10", 443, "")
	if len(order) != 1 || order[0] != obWarp || rule != "список IP" {
		t.Fatalf("planForIP(IP list) = %v (%q)", order, rule)
	}

	// 2. Domain whose IP is in the DNS cache matches CIDR rules even without dstIP.
	theDNS.clear()
	theDNS.mu.Lock()
	theDNS.m["cached-tg.example"] = dnsEntry{ips: []string{"149.154.165.1"}, exp: time.Now().Add(time.Minute)}
	theDNS.mu.Unlock()
	t.Cleanup(theDNS.clear)

	order, rule = app.router.plan("cached-tg.example", 443)
	if len(order) != 1 || order[0] != obPsiphon || rule != "подсеть" {
		t.Fatalf("plan with cached DNS IP = %v (%q)", order, rule)
	}
}

// ---------- 1.0.9: obfsConn concurrent Read before Write ----------

func TestObfsConcurrentReadBeforeWriteSilence(t *testing.T) {
	old := obfsFirstByte
	obfsFirstByte = 250 * time.Millisecond
	t.Cleanup(func() { obfsFirstByte = old })
	obfs.reset()
	t.Cleanup(obfs.reset)

	hello := obfsTestHello("concurrent.example")
	addr := obfsTestServer(t, len(hello), func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c) // blackhole: never replies
	})

	c, err := dialObfs(context.Background(), "tcp", addr, "auto")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Start Read in a goroutine BEFORE Write is called (just like proxy.go:relay).
	readDone := make(chan error, 1)
	got := make([]byte, 2)
	go func() {
		_, rerr := io.ReadFull(c, got)
		readDone <- rerr
	}()

	time.Sleep(40 * time.Millisecond) // ensure Read is already blocked on the initial socket
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case rerr := <-readDone:
		if rerr != nil || string(got) != "OK" {
			t.Fatalf("concurrent Read = %q, err=%v", got, rerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Read hung on silent DPI blackhole")
	}
}

func TestObfsHTTPNonASCIIPrefix(t *testing.T) {
	// Multi-byte UTF-8 characters before Host header must not shift the "hoSt" cut offset.
	req := []byte("GET /путь/страница HTTP/1.1\r\nX-Note: ИИ\r\nHost: example.com\r\n\r\n")
	segs := obfsHTTP(req)
	if len(segs) != 2 {
		t.Fatalf("segments = %d, want 2", len(segs))
	}
	joined := bytes.Join(segs, nil)
	if !strings.Contains(string(joined), "\r\nhoSt: example.com\r\n") {
		t.Fatalf("corrupted Host header: %q", joined)
	}
}

// ---------- 1.0.9: wire-format DoH cache ----------

func TestDoHWireCache(t *testing.T) {
	theDoHWire.clear()
	t.Cleanup(theDoHWire.clear)

	q1 := dnsQuery(0x1111, "Example.COM.", 1)
	q2 := dnsQuery(0x2222, "example.com", 1)
	k1 := dnsWireKey(obDirect, q1)
	k2 := dnsWireKey(obDirect, q2)
	if k1 == "" || k1 != k2 {
		t.Fatalf("keys differ: %q vs %q", k1, k2)
	}

	resp := append([]byte(nil), q1...)
	resp[2], resp[3] = 0x81, 0x80 // QR=1, RCODE=0
	resp[7] = 1
	resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
	theDoHWire.put(k1, resp, time.Minute)

	got := theDoHWire.get(k2, q2[0], q2[1])
	if got == nil || got[0] != 0x22 || got[1] != 0x22 {
		t.Fatalf("cached response transaction ID not rewritten: % x", got)
	}
	ips, err := dnsAnswers(got)
	if err != nil || len(ips) != 1 || ips[0].String() != "1.2.3.4" {
		t.Fatalf("dnsAnswers(cached) = %v, %v", ips, err)
	}
}

// ---------- 1.0.9: batch rules/add and deduplication + reloadConfig TUN ----------

func TestBatchRulesAddAndDeduplicate(t *testing.T) {
	app := testApp(t)
	// Batch add 2 hosts
	rec := apiCall(t, app, "POST", "/api/rules/add", true, `{"hosts":["https://A.test/path","b.test:443","a.test"],"outbound":"psiphon","name":"Тест DPI"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch rules/add code = %d: %s", rec.Code, rec.Body.String())
	}
	app.cfg.mu.Lock()
	if len(app.cfg.Routing.Rules) != 1 || len(app.cfg.Routing.Rules[0].Domains) != 2 {
		t.Fatalf("rules after batch add = %+v", app.cfg.Routing.Rules)
	}
	app.cfg.mu.Unlock()

	// Single add + update existing single-domain rule without duplicating
	rec = apiCall(t, app, "POST", "/api/rules/add?host=single.test&outbound=direct-dpi", true, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("single add code = %d", rec.Code)
	}
	rec = apiCall(t, app, "POST", "/api/rules/add?host=single.test&outbound=psiphon", true, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("single update code = %d", rec.Code)
	}
	app.cfg.mu.Lock()
	defer app.cfg.mu.Unlock()
	if len(app.cfg.Routing.Rules) != 2 || app.cfg.Routing.Rules[1].Outbound != obPsiphon {
		t.Fatalf("rules after deduplicated update = %+v", app.cfg.Routing.Rules)
	}
}

func TestReloadConfigPreservesTunSettings(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Tun.MTU = 1420
		c.Tun.Exclude = []string{"bank.exe"}
	})
	if err := app.cfg.save(); err != nil {
		t.Fatal(err)
	}
	// Modify MTU on disk and reload
	b, _ := os.ReadFile(app.cfgPath)
	s := strings.Replace(string(b), `"mtu": 1420`, `"mtu": 1380`, 1)
	_ = os.WriteFile(app.cfgPath, []byte(s), 0o600)
	app.reloadConfig()
	app.cfg.mu.Lock()
	defer app.cfg.mu.Unlock()
	if app.cfg.Tun.MTU != 1380 || len(app.cfg.Tun.Exclude) != 1 || app.cfg.Tun.Exclude[0] != "bank.exe" {
		t.Fatalf("Tun after reloadConfig = %+v", app.cfg.Tun)
	}
}


func TestRoutingPipelineSevenLevelsAndExplainRoute(t *testing.T) {
	app := testApp(t)
	u, _ := resolveListURL("ai-services")
	app.lists.data[u] = parseList(strings.NewReader("openai.com\nchatgpt.com\n"))

	setCfg(app, func(c *Config) {
		c.Routing.Mode = "auto"
		c.Routing.BypassLAN = true
		c.Routing.Learn = true
		// Intentionally place a preset list rule (Tier 5) BEFORE personal (Tier 3) and app (Tier 2) rules
		// to verify the 7-level Top-to-Bottom Pipeline enforces strict priority order regardless of slice index.
		c.Routing.Rules = []Rule{
			{Name: "Список ИИ", Outbound: obPsiphon, Lists: []string{"ai-services"}, Always: true},
			{Name: "Личное правило OpenAI", Outbound: obWarp, Domains: []string{"platform.openai.com"}, Always: true},
			{Name: "Программа CS2", Outbound: obDirect, Apps: []string{"cs2.exe"}, Always: true},
		}
	})

	// Level 1: LAN / psiroute.exe -> Direct (Stage 1)
	exp1 := app.router.ExplainRoute("tcp", "192.168.1.1", "", 443, "cs2.exe")
	if exp1.Outbound != obDirect || exp1.Stage != 1 {
		t.Fatalf("Level 1 LAN failed: %+v", exp1)
	}
	expSelf := app.router.ExplainRoute("tcp", "openai.com", "", 443, "psiroute.exe")
	if expSelf.Outbound != obDirect || expSelf.Stage != 1 {
		t.Fatalf("Level 1 psiroute.exe self-protection failed: %+v", expSelf)
	}

	// Level 2: App rule (cs2.exe -> Direct) overrides Tier 5 list rule (openai.com -> Psiphon)
	exp2 := app.router.ExplainRoute("tcp", "openai.com", "", 443, "cs2.exe")
	if exp2.Outbound != obDirect || exp2.Stage != 2 {
		t.Fatalf("Level 2 App rule should override list rule: %+v", exp2)
	}

	// Level 3: Personal domain rule (platform.openai.com -> WARP) overrides Tier 5 list rule (openai.com -> Psiphon)
	exp3 := app.router.ExplainRoute("tcp", "platform.openai.com", "", 443, "chrome.exe")
	if exp3.Outbound != obWarp || exp3.Stage != 3 {
		t.Fatalf("Level 3 Personal rule should override list rule: %+v", exp3)
	}

	// Level 4: Russian whitelist in Smart (auto) mode -> Direct (Stage 4)
	exp4 := app.router.ExplainRoute("tcp", "gosuslugi.ru", "", 443, "chrome.exe")
	if exp4.Outbound != obDirect || exp4.Stage != 4 {
		t.Fatalf("Level 4 RU Whitelist in auto mode failed: %+v", exp4)
	}

	// Level 5: Preset list rule (chatgpt.com -> Psiphon, Stage 5)
	exp5 := app.router.ExplainRoute("tcp", "chatgpt.com", "", 443, "chrome.exe")
	if exp5.Outbound != obPsiphon || exp5.Stage != 5 {
		t.Fatalf("Level 5 Preset list rule failed: %+v", exp5)
	}

	// Level 6: Auto-learned route (Stage 6)
	app.router.remember("learned-dpi.example.org", obDesync, "dpi-rst", true)
	exp6 := app.router.ExplainRoute("tcp", "learned-dpi.example.org", "", 443, "chrome.exe")
	if exp6.Outbound != obDesync || exp6.Stage != 6 {
		t.Fatalf("Level 6 Learned route failed: %+v", exp6)
	}

	// Level 7: Default auto chain (Stage 7)
	exp7 := app.router.ExplainRoute("tcp", "unseen.example.org", "", 443, "chrome.exe")
	if exp7.Stage != 7 || exp7.Badge == "" {
		t.Fatalf("Level 7 Default route failed: %+v", exp7)
	}

	// Verify POST /api/repair endpoint
	rec := apiCall(t, app, "POST", "/api/repair", true, "{}")
	if rec.Code != 200 {
		t.Fatalf("POST /api/repair failed with status %d: %s", rec.Code, rec.Body.String())
	}
}
