package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---------- 1.1.0 & 1.2.0: Security, Routing, Split Tunneling, FakeIP, ECH, MASQUE & Stability ----------

func TestRoutingNegationPortRangesProtoAndDisabled(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Failover = false
		c.Routing.Rules = []Rule{
			{
				Name:     "Отключённое правило",
				Outbound: obBlock,
				Domains:  []string{"youtube.com"},
				Disabled: true,
			},
			{
				Name:     "YouTube: блок QUIC (только UDP 443)",
				Outbound: obBlock,
				Proto:    "udp",
				Ports:    []int{443},
				Domains:  []string{"*.googlevideo.com", "youtube.com"},
			},
			{
				Name:       "Discord голос (диапазон портов UDP)",
				Outbound:   obPsiphon,
				Proto:      "udp",
				PortRanges: []string{"50000-65535"},
				Apps:       []string{"Discord.exe"},
			},
			{
				Name:     "Все кроме .ru и банка",
				Outbound: obPsiphon,
				Domains:  []string{"!ru", "!xn--p1ai", "!exact:mybank.com"},
				Apps:     []string{"!steam.exe"},
			},
		}
	})

	// 1. Disabled rule is skipped; TCP 443 to youtube.com falls through to rule 4 (psiphon).
	order, rule := app.router.planForProto("tcp", "www.youtube.com", "", 443, "chrome.exe")
	if len(order) != 1 || order[0] != obPsiphon || rule != "Все кроме .ru и банка" {
		t.Fatalf("TCP youtube.com plan = %v (%q)", order, rule)
	}

	// 2. UDP 443 to googlevideo.com matches the UDP-only QUIC block rule.
	order, rule = app.router.planForProto("udp", "rr1---sn-abc.googlevideo.com", "", 443, "chrome.exe")
	if len(order) != 1 || order[0] != obBlock || rule != "YouTube: блок QUIC (только UDP 443)" {
		t.Fatalf("UDP googlevideo.com plan = %v (%q)", order, rule)
	}

	// 3. Port range 50000-65535 on UDP for Discord.exe matches.
	order, rule = app.router.planForProto("udp", "162.159.135.232", "", 55123, "Discord.exe")
	if len(order) != 1 || order[0] != obPsiphon || rule != "Discord голос (диапазон портов UDP)" {
		t.Fatalf("Discord UDP port range plan = %v (%q)", order, rule)
	}

	// 4. Negation: .ru domain is excluded from rule 4 and falls back to Default (direct).
	order, rule = app.router.planForProto("tcp", "gosuslugi.ru", "", 443, "chrome.exe")
	if len(order) != 1 || order[0] != obDirect || rule != "по умолчанию" {
		t.Fatalf("negated .ru domain plan = %v (%q)", order, rule)
	}

	// 5. Exact negation: mybank.com is excluded, but sub.mybank.com is not.
	order, _ = app.router.planForProto("tcp", "mybank.com", "", 443, "chrome.exe")
	if len(order) != 1 || order[0] != obDirect {
		t.Fatalf("exact negated mybank.com plan = %v", order)
	}
	order, _ = app.router.planForProto("tcp", "sub.mybank.com", "", 443, "chrome.exe")
	if len(order) != 1 || order[0] != obPsiphon {
		t.Fatalf("subdomain of exact negated mybank.com plan = %v", order)
	}

	// 6. Negated app: steam.exe is excluded from rule 4.
	order, _ = app.router.planForProto("tcp", "store.steampowered.com", "", 443, "steam.exe")
	if len(order) != 1 || order[0] != obDirect {
		t.Fatalf("negated app steam.exe plan = %v", order)
	}
}

func TestRoutingBypassLANAndBlockQUICAndRevDNS(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "psiphon"
		c.Routing.BypassLAN = true
		c.Routing.BlockQUIC = true
	})

	// 1. BypassLAN sends private IPs and .local domains direct even in psiphon mode.
	for _, h := range []string{"192.168.1.1", "10.0.0.5", "nas.local", "router.lan"} {
		order, rule := app.router.planForProto("tcp", h, "", 80, "")
		if len(order) != 1 || order[0] != obDirect || rule != "локальная сеть" {
			t.Fatalf("BypassLAN for %s = %v (%q)", h, order, rule)
		}
	}

	// 2. BlockQUIC blocks UDP:443 on non-direct routes.
	if ob, rule := app.planUDPIP("www.youtube.com", "", 443, ""); ob != "" || !strings.Contains(rule, "QUIC") {
		t.Fatalf("BlockQUIC planUDPIP = %q (%q), want blocked", ob, rule)
	}

	// 3. Reverse DNS map resolves raw IP back to domain for rule matching.
	theRevDNS.clear()
	t.Cleanup(theRevDNS.clear)
	theRevDNS.put(net.ParseIP("149.154.167.99"), "web.telegram.org", time.Minute)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Rules = []Rule{{Name: "TG", Outbound: obPsiphon, Domains: []string{"telegram.org"}}}
	})
	order, rule := app.router.planForProto("tcp", "149.154.167.99", "", 443, "")
	if len(order) == 0 || order[0] != obPsiphon || rule != "TG" {
		t.Fatalf("reverse DNS IP match = %v (%q)", order, rule)
	}
}

func TestFakeIPPoolAndRouterIntegration(t *testing.T) {
	theFakeIP.clear()
	t.Cleanup(theFakeIP.clear)

	ip := theFakeIP.Assign("discord.media")
	if !ip.IsValid() || !isFakeIP(ip) {
		t.Fatalf("Assign returned invalid FakeIP: %v", ip)
	}
	if got := theFakeIP.Lookup(ip); got != "discord.media" {
		t.Fatalf("Lookup(%v) = %q, want discord.media", ip, got)
	}
	if got := theFakeIP.LookupString(ip.String()); got != "discord.media" {
		t.Fatalf("LookupString(%s) = %q, want discord.media", ip.String(), got)
	}

	// Verify router resolves FakeIP back to domain in planForProto
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Rules = []Rule{{Name: "Discord", Outbound: obPsiphon, Domains: []string{"discord.media"}}}
	})
	order, rule := app.router.planForProto("udp", ip.String(), "", 50005, "")
	if len(order) == 0 || order[0] != obPsiphon || rule != "Discord" {
		t.Fatalf("FakeIP router plan = %v (%q), want [psiphon] (Discord)", order, rule)
	}
}

func TestKillSwitchAndBlockSTUN(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obPsiphon
		c.Routing.Failover = true
		c.Routing.KillSwitch = true
		c.Routing.BlockSTUN = true
		c.Routing.Rules = []Rule{
			{Name: "Через WARP", Outbound: obWarp, Domains: []string{"warp.test"}},
		}
	})

	// 1. BlockSTUN blocks UDP 3478/19302/5349 and stun.* domains
	for _, port := range []int{3478, 19302, 5349} {
		order, rule := app.router.planForProto("udp", "74.125.250.129", "", port, "chrome.exe")
		if len(order) != 1 || order[0] != obBlock || !strings.Contains(rule, "STUN") {
			t.Fatalf("BlockSTUN port %d = %v (%q)", port, order, rule)
		}
	}
	order, rule := app.router.planForProto("udp", "stun.l.google.com", "", 443, "chrome.exe")
	if len(order) != 1 || order[0] != obBlock || !strings.Contains(rule, "STUN") {
		t.Fatalf("BlockSTUN domain stun.l.google.com = %v (%q)", order, rule)
	}

	// 2. KillSwitch prevents direct fallback when Psiphon is not connected
	order, rule = app.router.planForProto("tcp", "blocked.example", "", 443, "chrome.exe")
	if len(order) != 1 || order[0] != obBlock || !strings.Contains(rule, "Kill Switch") {
		t.Fatalf("KillSwitch when disconnected = %v (%q), want [block]", order, rule)
	}
}

func TestSplitTunnelingAppsAPI(t *testing.T) {
	app := testApp(t)

	// Set route for Discord.exe -> psiphon
	rec := apiCall(t, app, "POST", "/api/apps", true, `{"exe":"Discord.exe","outbound":"psiphon"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/apps status = %d: %s", rec.Code, rec.Body.String())
	}
	order, rule := app.router.planForProto("tcp", "anything.example", "", 443, "Discord.exe")
	if len(order) == 0 || order[0] != obPsiphon || !strings.Contains(rule, "Discord.exe") {
		t.Fatalf("after SetAppRoute Discord.exe plan = %v (%q)", order, rule)
	}

	// Set route for steam.exe -> direct
	_ = apiCall(t, app, "POST", "/api/apps", true, `{"exe":"steam.exe","outbound":"direct"}`)
	order, _ = app.router.planForProto("tcp", "cdn.steamstatic.com", "", 443, "steam.exe")
	if len(order) == 0 || order[0] != obDirect {
		t.Fatalf("after SetAppRoute steam.exe plan = %v", order)
	}

	// Remove route for Discord.exe
	_ = apiCall(t, app, "POST", "/api/apps", true, `{"exe":"Discord.exe","outbound":""}`)
	if got := app.appCurrentRoute("Discord.exe"); got != "" {
		t.Fatalf("expected Discord.exe route removed, got %q", got)
	}
}

func TestClashSingboxAndHostsListParsing(t *testing.T) {
	clash := parseList(strings.NewReader(`
# Clash rule list
DOMAIN-SUFFIX,youtube.com,PROXY
DOMAIN,api.discord.gg
DOMAIN-KEYWORD,googlevideo
IP-CIDR,1.1.1.1/32,no-resolve
full:exact.example.net
regexp:^ads[0-9]+\.example\.com$
0.0.0.0 telemetry.example.com
`))
	for host, want := range map[string]bool{
		"youtube.com":                  true,
		"www.youtube.com":              true,  // suffix
		"api.discord.gg":               true,  // exact
		"x.api.discord.gg":             false, // DOMAIN is exact, not suffix
		"rr3---sn-abc.googlevideo.com": true,  // keyword
		"exact.example.net":            true,
		"sub.exact.example.net":        false,
		"telemetry.example.com":        true,
		"example.com":                  false, // regexp must not become a domain
	} {
		if got := clash.match(host, netip.Addr{}); got != want {
			t.Errorf("clash match(%q) = %v, want %v", host, got, want)
		}
	}
	if !clash.match("", netip.MustParseAddr("1.1.1.1")) {
		t.Error("IP-CIDR 1.1.1.1/32 not matched")
	}

	sb := parseList(strings.NewReader(`{"version":1,"rules":[{"domain":["exact.example.org"],"domain_suffix":[".cdn.example.org","media.example.org"],"domain_keyword":["tracker"]}]}`))
	for host, want := range map[string]bool{
		"exact.example.org":   true,
		"a.exact.example.org": false,
		"x.cdn.example.org":   true,
		"media.example.org":   true,
		"tracker.example.com": true,
		"other.example.org":   false,
	} {
		if got := sb.match(host, netip.Addr{}); got != want {
			t.Errorf("sing-box match(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestECHParserAndMASQUEMask(t *testing.T) {
	// Build a minimal DNS response with 1 Question and 1 HTTPS (RRType 65) answer containing SvcParamKey 5 (ech)
	var pkt []byte
	pkt = append(pkt, 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	// Question: "\x04test\x00" type 65 class 1
	pkt = append(pkt, 0x04, 't', 'e', 's', 't', 0x00, 0x00, 65, 0x00, 0x01)
	// Answer: pointer 0xc00c, type 65, class 1, ttl 60
	echPayload := []byte{0xfe, 0x0d, 0x00, 0x20, 1, 2, 3, 4}
	// RDATA: SvcPriority(2)=1, TargetName(1)=0x00, SvcParamKey(2)=5, SvcParamLen(2)=len(echPayload), echPayload
	rdata := append([]byte{0x00, 0x01, 0x00, 0x00, 0x05, 0x00, byte(len(echPayload))}, echPayload...)
	pkt = append(pkt, 0xc0, 0x0c, 0x00, 65, 0x00, 0x01, 0x00, 0x00, 0x00, 60, 0x00, byte(len(rdata)))
	pkt = append(pkt, rdata...)

	got, err := parseECHFromDNS(pkt)
	if err != nil || string(got) != string(echPayload) {
		t.Fatalf("parseECHFromDNS = %x, want %x", got, echPayload)
	}
}

func TestSingleProcessCountryReuseCheck(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Psiphon.Country = "DE"
		c.Psiphon.SingleProcessCountries = true
	})
	if !app.countries.canReuseMain("DE") {
		t.Fatal("canReuseMain(DE) should be true when main country is DE")
	}
}

func TestSecurityHeadersOriginAndSelfUIProtection(t *testing.T) {
	app := testApp(t)
	app.mu.Lock()
	app.uiActual = "127.0.0.1:19090"
	app.mu.Unlock()

	// 1. Self-UI protection blocks proxy from dialing Psiroute's own UI port.
	if !app.isSelfUI("127.0.0.1", 19090) || !app.isSelfUI("localhost", 19090) || app.isSelfUI("127.0.0.1", 8080) {
		t.Fatal("isSelfUI check failed")
	}

	// 2. Cross-Origin and Sec-Fetch-Site protection on Web UI.
	srv := httptest.NewServer(app.routes())
	defer srv.Close()
	cl := srv.Client()

	req, _ := http.NewRequest("GET", srv.URL+"/api/state", nil)
	req.Header.Set("X-Psiroute", app.token)
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin request status = %d, want 403", resp.StatusCode)
	}

	req2, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req2.Header.Set("Sec-Fetch-Site", "cross-site")
	resp2, err := cl.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("Sec-Fetch-Site: cross-site status = %d, want 403", resp2.StatusCode)
	}

	// 3. Valid local request gets security headers and compact state.
	req3, _ := http.NewRequest("GET", srv.URL+"/api/state?compact=1", nil)
	req3.Header.Set("X-Psiroute", app.token)
	resp3, err := cl.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.Header.Get("X-Frame-Options") != "DENY" || resp3.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers: %v", resp3.Header)
	}
	var st map[string]any
	if err := json.NewDecoder(resp3.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st["log"] != nil {
		t.Fatalf("compact=1 should omit log slice, got %v", st["log"])
	}
}

func TestProcessesAPIAndRuleToggle(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Rules = []Rule{{Name: "R1", Outbound: obPsiphon, Domains: []string{"a.test"}}}
	})

	// 1. Toggle rule disabled state
	rec := apiCall(t, app, "POST", "/api/rules/toggle", true, `{"index":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rules/toggle status = %d: %s", rec.Code, rec.Body.String())
	}
	if !app.cfg.Routing.Rules[0].Disabled {
		t.Fatal("rule 0 should be disabled after first toggle")
	}
	_ = apiCall(t, app, "POST", "/api/rules/toggle", true, `{"index":0}`)
	if app.cfg.Routing.Rules[0].Disabled {
		t.Fatal("rule 0 should be enabled after second toggle")
	}

	// 2. Process control API (stop action does not require network)
	rec2 := apiCall(t, app, "POST", "/api/processes", true, `{"service":"psiphon","action":"stop"}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("POST /api/processes stop status = %d: %s", rec2.Code, rec2.Body.String())
	}

	rec3 := apiCall(t, app, "GET", "/api/processes", true, "")
	if rec3.Code != http.StatusOK {
		t.Fatalf("GET /api/processes status = %d", rec3.Code)
	}
	b, _ := io.ReadAll(rec3.Body)
	if !strings.Contains(string(b), `"psiphon"`) || !strings.Contains(string(b), `"warp"`) || !strings.Contains(string(b), `"tun"`) {
		t.Fatalf("GET /api/processes missing services: %s", b)
	}
}

func TestBrowserCanaryDoHAndIPv6BlockAAAA(t *testing.T) {
	app := testApp(t)
	// 1. Canary domains (Firefox use-application-dns.net, Chrome/Edge DDR _dns.resolver.arpa) must return NXDOMAIN (rcode 3)
	for _, canary := range []string{"use-application-dns.net", "mask.icloud.com", "_dns.resolver.arpa"} {
		q := dnsQuery(0x1122, canary, 1)
		resp := app.answerLocalDNS(q)
		if len(resp) < 12 || (resp[3]&0x0f) != 3 {
			t.Fatalf("canary %s expected NXDOMAIN (rcode 3), got resp=%x", canary, resp)
		}
	}

	// 2. BlockAAAA when Tun.IPv6 is false returns empty NOERROR (rcode 0, ancount 0)
	setCfg(app, func(c *Config) {
		c.Tun.IPv6 = false
		c.Tun.FakeIP = false
	})
	q6 := dnsQuery(0x3344, "example.com", 28)
	resp6 := app.answerLocalDNS(q6)
	if len(resp6) < 12 || (resp6[3]&0x0f) != 0 || resp6[6] != 0 || resp6[7] != 0 {
		t.Fatalf("BlockAAAA expected rcode 0 and ANCOUNT 0, got %x", resp6)
	}

	// 3. IPv6 FakeIP ULA pool (fc00::/7) assignment and lookup
	ip6 := theFakeIP.AssignIPv6("ipv6-target.example.org")
	if !ip6.IsValid() || !isFakeIP(ip6) {
		t.Fatalf("AssignIPv6 returned invalid FakeIPv6: %v", ip6)
	}
	if got := theFakeIP.Lookup(ip6); got != "ipv6-target.example.org" {
		t.Fatalf("Lookup(FakeIPv6) = %q, want ipv6-target.example.org", got)
	}
}

func TestCaptivePortalWhitelistAnd16KBBlackholeAndBitTorrent(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "psiphon"
		c.Routing.KillSwitch = true
	})

	// 1. Captive Portal host is whitelisted to Direct (Stage 1) even when KillSwitch and VPN mode are active
	app.net.setCaptivePortalState(true, "http://wifi-login.airport.local/portal?id=1")
	exp := app.router.ExplainRoute("tcp", "wifi-login.airport.local", "", 80, "chrome.exe")
	if exp.Outbound != obDirect || exp.Stage != 1 {
		t.Fatalf("Captive portal host must bypass KillSwitch to Direct (Stage 1), got %+v", exp)
	}

	// 2. 16-32 KB TSPU Blackhole detector
	if is16KBBlackholeBlock(18*1024, 512, 4*time.Second, nil, false) {
		t.Fatal("normal server EOF is not evidence of a failed transfer")
	}
	if is16KBBlackholeBlock(128*1024, 512, 4*time.Second, nil, false) {
		t.Fatal("128 KB transfer must not be flagged as 16KB blackhole")
	}

	// 3. BitTorrent TCP & UDP signature detection
	btHandshake := append([]byte{19}, []byte("BitTorrent protocol00000000")...)
	if !isBitTorrentTCP(btHandshake) {
		t.Fatal("expected BitTorrent handshake to be detected")
	}
	dhtQuery := []byte("d1:ad2:id20:abcdefghij0123456789e1:q9:get_peers1:t2:aa1:y1:qe")
	if !isBitTorrentUDP(dhtQuery) {
		t.Fatal("expected BitTorrent DHT query to be detected")
	}
}

func TestConfigSchemaMigrationAndPauseTimerAndUpdater(t *testing.T) {
	// 1. Config schema v1 -> v2 migration creates psiroute.json.bak and preserves rules
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "psiroute.json")
	legacyJSON := `{"routing":{"mode":"rules","default":"tunnel","rules":[{"name":"Мой банк","outbound":"direct","domains":["sberbank.ru"]}]}}`
	if err := os.WriteFile(cfgFile, []byte(legacyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadConfig(cfgFile)
	if c.SchemaVersion != currentConfigSchemaVersion || c.Routing.Default != obPsiphon || len(c.Routing.Rules) != 1 {
		t.Fatalf("migrated config unexpected: schema=%d default=%q rules=%d", c.SchemaVersion, c.Routing.Default, len(c.Routing.Rules))
	}
	if _, err := os.Stat(cfgFile + ".bak"); err != nil {
		t.Fatalf("expected backup file %s.bak to be created on migration: %v", cfgFile, err)
	}

	// 2. Pause Timer (5 / 15 min) routes all traffic Direct and resumes on 0
	app := testApp(t)
	setCfg(app, func(c *Config) { c.Routing.Mode = "psiphon" })
	rec := apiCall(t, app, "POST", "/api/pause", true, `{"minutes":5}`)
	if rec.Code != 200 || !app.IsPaused() || app.PauseRemainingSec() <= 0 {
		t.Fatalf("POST /api/pause(5) failed: code=%d paused=%v rem=%d", rec.Code, app.IsPaused(), app.PauseRemainingSec())
	}
	ord, rule := app.router.plan("youtube.com", 443)
	if len(ord) == 0 || ord[0] != obDirect || !strings.Contains(rule, "пауза") {
		t.Fatalf("while paused, expected Direct route, got %v (%q)", ord, rule)
	}
	app.SetPause(0)
	if app.IsPaused() {
		t.Fatal("expected pause cleared after SetPause(0)")
	}

	// 3. Updater SHA-256 + Ed25519 signature verification
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	fakeExe := []byte("MZ-psiroute-signed-release-binary")
	sum := sha256.Sum256(fakeExe)
	sumHex := hex.EncodeToString(sum[:])
	binSigHex := hex.EncodeToString(ed25519.Sign(priv, sum[:]))

	if err := VerifyUpdateBinary(fakeExe, sumHex, binSigHex, pubHex); err != nil {
		t.Fatalf("VerifyUpdateBinary valid failed: %v", err)
	}
	if err := VerifyUpdateBinary(append(fakeExe, 'x'), sumHex, binSigHex, pubHex); err == nil {
		t.Fatal("VerifyUpdateBinary must reject tampered binary")
	}

	manifest := &UpdateManifest{
		Version: "2.1.0",
		URL:     "https://updates.example.com/psiroute-2.1.0.exe",
		SHA256:  sumHex,
	}
	manifest.Ed25519Sig = hex.EncodeToString(ed25519.Sign(priv, manifest.CanonicalPayload()))
	if err := manifest.VerifyManifestSignature(pubHex); err != nil {
		t.Fatalf("VerifyManifestSignature valid failed: %v", err)
	}
}

func TestP2PDoesNotEscapePsiphon(t *testing.T) {
	a := testApp(t)
	for _, outbound := range []string{obPsiphon, "psiphon:US"} {
		for _, kill := range []bool{false, true} {
			setCfg(a, func(c *Config) { c.Routing.KillSwitch = kill })
			client, server := net.Pipe()
			upstream, remote := net.Pipe()
			tracked := a.stats.open("test", "127.0.0.1", "", 1, outbound, "explicit")
			go func() { _, _ = client.Write(append([]byte{19}, []byte("BitTorrent protocol00000000")...)) }()
			done := make(chan error, 1)
			go func() { err, _ := a.relay(server, bufio.NewReader(server), upstream, tracked); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, errBlocked) {
					t.Fatalf("expected block, got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("P2P block stalled")
			}
			client.Close()
			server.Close()
			upstream.Close()
			remote.Close()
		}
	}
}
func TestTransferInterruptionRequiresNetworkFailure(t *testing.T) {
	for _, clientFirst := range []bool{false, true} {
		for _, err := range []error{nil, io.EOF, syscall.ECONNRESET} {
			got := is16KBBlackholeBlock(18*1024, 512, time.Second, err, clientFirst)
			if got != (!clientFirst && err == syscall.ECONNRESET) {
				t.Fatalf("clientFirst=%v err=%v got=%v", clientFirst, err, got)
			}
		}
	}
}
