package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestObfsScoreJSONPersistence verifies BUG-202-01 fix:
// exported Ok/Fail fields in obfsScore are properly marshaled/unmarshaled
// and writeFileAtomic(path, raw, 0o600) writes the score file cleanly.
func TestObfsScoreJSONPersistence(t *testing.T) {
	dir := t.TempDir()
	scoreFile := filepath.Join(dir, "psiroute-obfs.json")

	b1 := &obfsBook{}
	b1.loadFile(scoreFile)
	b1.result("youtube.com", "split", true)
	b1.result("youtube.com", "split", true)
	b1.result("discord.com", "tlsrec", false)
	b1.rescued()

	b1.mu.Lock()
	p := obfsPersist{
		Sites: make(map[string]struct {
			Method string `json:"method"`
			Exp    int64  `json:"exp"`
		}, len(b1.sites)),
		Score: make(map[string]*obfsScore, len(b1.score)),
		Saved: b1.saved,
	}
	for k, v := range b1.sites {
		p.Sites[k] = struct {
			Method string `json:"method"`
			Exp    int64  `json:"exp"`
		}{Method: v.method, Exp: v.exp.Unix()}
	}
	for k, v := range b1.score {
		cp := *v
		p.Score[k] = &cp
	}
	b1.mu.Unlock()

	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("json.Marshal(obfsPersist): %v", err)
	}
	if err := writeFileAtomic(scoreFile, raw, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	b2 := &obfsBook{}
	b2.loadFile(scoreFile)
	b2.mu.Lock()
	splitScore := b2.score["split"]
	tlsrecScore := b2.score["tlsrec"]
	saved := b2.saved
	b2.mu.Unlock()

	if splitScore == nil || splitScore.Ok <= 1.5 {
		t.Fatalf("expected persisted splitScore.Ok > 1.5, got %+v", splitScore)
	}
	if tlsrecScore == nil || tlsrecScore.Fail <= 0.5 {
		t.Fatalf("expected persisted tlsrecScore.Fail > 0.5, got %+v", tlsrecScore)
	}
	if saved != 1 {
		t.Fatalf("expected saved=1, got %d", saved)
	}
}

// TestRelayDynamicSNIRouteHandoff verifies BUG-202-03 fix.
func TestRelayDynamicSNIRouteHandoff(t *testing.T) {
	hello := obfsTestHello("sni-routed.example.com")
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, len(hello))
				if _, rerr := io.ReadFull(c, buf); rerr != nil {
					return
				}
				_, _ = c.Write([]byte("SERVER-HELLO-OK"))
			}(c)
		}
	}()

	initialClient, initialServer := net.Pipe()
	defer initialServer.Close()
	go func() {
		_, _ = io.Copy(io.Discard, initialServer)
	}()

	connectProxy := fakeConnectProxy(t, "")
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Failover = false
		c.Proxy.Enabled = true
		c.Proxy.Upstream = "http://" + connectProxy
		c.Routing.Rules = []Rule{
			{Name: "SNI Proxy Rule", Outbound: obProxy, Domains: []string{"sni-routed.example.com"}, Always: true},
		}
	})

	_, portStr, _ := net.SplitHostPort(targetLn.Addr().String())
	port := atoiSafe(portStr)
	tr := app.stats.open("chrome.exe", "127.0.0.1", "", port, obDirect, "по умолчанию")

	cClient, cProxy := net.Pipe()
	defer cClient.Close()

	relayDone := make(chan error, 1)
	go func() {
		cc := &countConn{Conn: initialClient, s: app.stats, t: tr}
		rerr, _ := app.relay(cProxy, bufio.NewReader(cProxy), cc, tr)
		_ = cProxy.Close()
		relayDone <- rerr
	}()

	_ = cClient.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cClient.Write(hello); err != nil {
		t.Fatalf("client write ClientHello: %v", err)
	}
	reply := make([]byte, len("SERVER-HELLO-OK"))
	if _, err := io.ReadFull(cClient, reply); err != nil {
		t.Fatalf("client read ServerHello after SNI switch failed: %v", err)
	}
	if string(reply) != "SERVER-HELLO-OK" {
		t.Fatalf("unexpected reply after SNI handoff: %q", string(reply))
	}
	_ = cClient.Close()

	select {
	case <-relayDone:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not exit cleanly after client close")
	}

	_, _, _, _, finalOb := app.stats.routeAndHost(tr)
	if finalOb != obProxy {
		t.Fatalf("expected tracked outbound updated to %q, got %q", obProxy, finalOb)
	}
	app.stats.close(tr, nil)
	tr.closersMu.Lock()
	remClosers := len(tr.closers)
	tr.closersMu.Unlock()
	if remClosers != 0 {
		t.Fatalf("expected tr.closers cleared on close(), got %d", remClosers)
	}
}

// TestBlockQUICAndRouteCacheInvalidation verifies BUG-202-04 and BUG-202-05 fixes
// along with Audit 2 strict "rules" mode behavior (unmatched -> obDirect).
func TestBlockQUICAndRouteCacheInvalidation(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obPsiphon
		c.Routing.BlockQUIC = true
		c.Routing.Failover = false
		c.Routing.Rules = []Rule{
			{Name: "Direct Site", Outbound: obDirect, Domains: []string{"direct.example.com"}, Always: true},
			{Name: "DPI Site", Outbound: obDesync, Domains: []string{"dpi.example.com"}, Always: true},
			{Name: "VPN Media", Outbound: obPsiphon, Domains: []string{"youtube.com", "discord.media"}, Always: true},
		}
	})

	if ob, rule := app.planUDPIP("youtube.com", "", 443, ""); ob != "" || !strings.Contains(rule, "QUIC") {
		t.Fatalf("expected UDP:443 via psiphon blocked by BlockQUIC, got ob=%q rule=%q", ob, rule)
	}
	if ob, rule := app.planUDPIP("dpi.example.com", "", 443, ""); ob != "" || !strings.Contains(rule, "QUIC") {
		t.Fatalf("expected UDP:443 via direct-dpi blocked by BlockQUIC, got ob=%q rule=%q", ob, rule)
	}
	if ob, _ := app.planUDPIP("direct.example.com", "", 443, ""); ob != obDirect {
		t.Fatalf("expected UDP:443 on explicit direct rule allowed, got %q", ob)
	}
	if ob, _ := app.planUDPIP("discord.media", "", 50000, ""); ob != obPsiphon {
		t.Fatalf("expected UDP:50000 via psiphon allowed, got %q", ob)
	}

	_, _ = app.lists.SaveLocalList("dyn-list", "cached-list.example.com\n")
	setCfg(app, func(c *Config) {
		c.Routing.Rules = append([]Rule{
			{Name: "List Rule", Outbound: obWarp, Lists: []string{"local:dyn-list.lst"}, Always: true},
		}, c.Routing.Rules...)
	})
	// Before adding new-member.example.com to dyn-list, unmatched host in "rules" mode goes to obDirect ("по умолчанию (мимо VPN)")
	ord1, rname1 := app.router.planForProto("tcp", "new-member.example.com", "", 443, "chrome.exe")
	if len(ord1) != 1 || ord1[0] != obDirect || rname1 != "по умолчанию (мимо VPN)" {
		t.Fatalf("expected initial unmatched route obDirect ('по умолчанию (мимо VPN)'), got %v (%q)", ord1, rname1)
	}
	_, err := app.lists.SaveLocalList("dyn-list", "cached-list.example.com\nnew-member.example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	ord2, rname2 := app.router.planForProto("tcp", "new-member.example.com", "", 443, "chrome.exe")
	if len(ord2) == 0 || ord2[0] != obWarp || rname2 != "List Rule" {
		t.Fatalf("routeCache was not invalidated after SaveLocalList: got %v (%q)", ord2, rname2)
	}
}

// TestBatchAndQuickConnRuleValidation verifies BUG-202-07 fix.
func TestBatchAndQuickConnRuleValidation(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Learn = true
	})
	app.router.remember("batch-target.example.com", obDirect, "old", true)

	recBadOb := apiCall(t, app, "POST", "/api/rules/batch", true, `{"text":"example.com","outbound":"invalid_outbound"}`)
	if recBadOb.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid outbound in batch, got %d: %s", recBadOb.Code, recBadOb.Body.String())
	}

	recBadQuick := apiCall(t, app, "POST", "/api/rules/from-conn", true, `{"host":"example.com","outbound":"psiphon:INVALID"}`)
	if recBadQuick.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid country outbound in quickConnRuleAPI, got %d: %s", recBadQuick.Code, recBadQuick.Body.String())
	}

	recGood := apiCall(t, app, "POST", "/api/rules/batch", true, `{"text":"batch-target.example.com\nport:8443","outbound":"psiphon"}`)
	if recGood.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid batch import, got %d: %s", recGood.Code, recGood.Body.String())
	}
	if got := app.router.learnedFor("batch-target.example.com"); got != "" {
		t.Fatalf("expected learned route forgotten after batch import, got %q", got)
	}
}

// TestStatsConcurrentRaceAndFlushDelta verifies BUG-202-06 fix.
func TestStatsConcurrentRaceAndFlushDelta(t *testing.T) {
	dir := t.TempDir()
	dayFile := filepath.Join(dir, "days.json")
	s := newStats(dayFile)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tr := s.open("chrome.exe", "1.1.1.1", "", 443, obDirect, "r")
			s.add(tr, 500, 1500)
			s.setSNI(tr, "sni.example.com")
			s.setRoute(tr, obPsiphon, "switched")
			s.add(tr, 500, 1500)
			_, _, _, _, _ = s.routeAndHost(tr)
			s.close(tr, nil)
		}(i)
	}
	wg.Wait()

	s.Flush()

	s2 := newStats(dayFile)
	today := time.Now().Format("2006-01-02")
	s2.mu.Lock()
	dayTotals := s2.days[today]
	s2.mu.Unlock()
	if dayTotals == nil || dayTotals[0] != 20*1000 || dayTotals[1] != 20*3000 {
		t.Fatalf("Flush() did not persist un-ticked day delta: got %+v", dayTotals)
	}
}

// TestServeWorkerSocksHalfClose verifies BUG-202-08 fix.
func TestServeWorkerSocksHalfClose(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	payload := bytes.Repeat([]byte("RESPONSE-BLOCK-"), 1024)
	go func() {
		c, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.ReadAll(c)
		_, _ = c.Write(payload)
	}()

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()
	go func() {
		c, err := socksLn.Accept()
		if err != nil {
			return
		}
		serveWorkerSocks(context.Background(), c, dialDirect)
	}()

	conn, err := dialSocks5(context.Background(), socksLn.Addr().String(), targetLn.Addr().String(), "", "")
	if err != nil {
		t.Fatalf("dialSocks5: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("half-close truncated response: got %d bytes (want %d), err=%v", len(got), len(payload), err)
	}
}

// TestBrowserAppRuleDoesNotBreakDomainRules (Finding 8 & Bug 6):
// Setting a browser route (chrome.exe -> auto or browser.exe -> direct) via SetAppRoute
// must NOT add the browser to Tun.Exclude, must NOT override personal domain rules (Tier 3),
// and must NOT shadow combo rules (chrome.exe + youtube.com -> psiphon:NL, Tier 2).
func TestBrowserAppRuleDoesNotBreakDomainRules(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Failover = false
		c.Routing.Rules = []Rule{
			{Name: "YouTube VPN", Outbound: obPsiphon, Domains: []string{"www.youtube.com"}, Always: true},
			{Name: "Chrome YouTube NL", Outbound: "psiphon:NL", Apps: []string{"chrome.exe"}, Domains: []string{"youtube.com"}, Always: true},
		}
	})

	if err := app.SetAppRoute("browser.exe", obDirect); err != nil {
		t.Fatalf("SetAppRoute(browser.exe, direct): %v", err)
	}
	if err := app.SetAppRoute("chrome.exe", obAuto); err != nil {
		t.Fatalf("SetAppRoute(chrome.exe, auto): %v", err)
	}

	// 1. Tun.Exclude must remain empty for "direct" (only "tun-exclude" adds to Tun.Exclude)
	app.cfg.mu.Lock()
	excl := append([]string(nil), app.cfg.Tun.Exclude...)
	app.cfg.mu.Unlock()
	if len(excl) != 0 {
		t.Fatalf("SetAppRoute(direct) polluted Tun.Exclude: %v", excl)
	}

	// 2. Inside browser.exe (set to direct), youtube.com and companion googlevideo.com still route via obPsiphon!
	expYT := app.router.ExplainRoute("tcp", "r1---sn.googlevideo.com", "", 443, "browser.exe")
	if expYT.Outbound != obPsiphon || expYT.Stage != 3 {
		t.Fatalf("domain rule inside browser.exe was overridden by app rule: %+v", expYT)
	}
	if expYT.Conflict == "" {
		t.Fatalf("expected ExplainRoute conflict warning when domain rule overrides browser.exe rule: %+v", expYT)
	}

	// 3. Inside chrome.exe, combo rule (chrome.exe + youtube.com -> psiphon:NL) wins over pure chrome.exe -> auto!
	expCombo := app.router.ExplainRoute("tcp", "www.youtube.com", "", 443, "chrome.exe")
	if expCombo.Outbound != "psiphon:NL" || expCombo.Stage != 2 {
		t.Fatalf("combo rule (chrome.exe + youtube.com) was shadowed by SetAppRoute(chrome.exe): %+v", expCombo)
	}

	// 4. Other domains in browser.exe use browser.exe -> direct
	expOther := app.router.ExplainRoute("tcp", "unmatched.example.org", "", 443, "browser.exe")
	if expOther.Outbound != obDirect || expOther.Stage != 2 {
		t.Fatalf("expected unmatched domain in browser.exe to use app rule direct: %+v", expOther)
	}
}

// TestCanReuseMainDoesNotMutateGlobalCountry (Finding 12):
// requesting a country worker (e.g. psiphon:NL) when SingleProcessCountries=true
// must never overwrite Config.Psiphon.Country when the main tunnel is in another country.
func TestCanReuseMainDoesNotMutateGlobalCountry(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Psiphon.SingleProcessCountries = true
		c.Psiphon.Country = "DE"
	})
	if app.countries.canReuseMain("NL") {
		t.Fatal("canReuseMain(NL) returned true when main country is DE")
	}
	app.cfg.mu.Lock()
	gotCountry := app.cfg.Psiphon.Country
	app.cfg.mu.Unlock()
	if gotCountry != "DE" {
		t.Fatalf("canReuseMain mutated Config.Psiphon.Country to %q, want DE", gotCountry)
	}
}

// TestOnRulesChangedClosesBlockedSessionsAndPreservesFakeIP (Finding 11):
// adding an obBlock rule must immediately close existing tracked connections to that host,
// and onRulesChanged() must preserve FakeIP mappings.
func TestOnRulesChangedClosesBlockedSessionsAndPreservesFakeIP(t *testing.T) {
	app := testApp(t)
	fip := theFakeIP.Assign("keep-alive.example.com")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tr := app.stats.open("chrome.exe", "bad-ads.example.com", "", 443, obDirect, "по умолчанию")
	tr.addCloser(c1)

	setCfg(app, func(c *Config) {
		c.Routing.Rules = []Rule{
			{Name: "Block Ads", Outbound: obBlock, Domains: []string{"bad-ads.example.com"}, Always: true},
		}
	})
	app.onRulesChanged()

	_ = c2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("expected active connection to blocked domain to be closed by onRulesChanged()")
	}
	if got := theFakeIP.Lookup(fip); got != "keep-alive.example.com" {
		t.Fatalf("onRulesChanged() wiped FakeIP table: Lookup(%v) = %q", fip, got)
	}
	if !isKnownPublicDoHIP(netip.MustParseAddr("8.8.8.8")) || !isKnownPublicDoHIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("isKnownPublicDoHIP failed on 8.8.8.8 / 1.1.1.1")
	}
}

// TestNoDoubleSNISniffDelayWhenBuffered verifies Audit 2 Finding 4:
// when tunnelAppAddr is called from TUN onTCP after e.sniff already buffered initial bytes
// (br.Buffered() > 0) without a parsed SNI, tunnelAppAddr must NOT run a second 250ms sniffBufferedConn wait.
func TestNoDoubleSNISniffDelayWhenBuffered(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obWarp // Stage 7 (>= 6), and dialer(obWarp) fails in 0ms when Warp.Enabled == false
		c.Routing.Failover = false
		c.Warp.Enabled = false
	})

	cClient, cProxy := net.Pipe()
	defer cClient.Close()
	defer cProxy.Close()

	// Partial 3-byte TLS record header (0x16, 0x03, 0x01) causes sniffWantMore() == true,
	// which would block on cProxy.Read for the full 250ms deadline if sniffBufferedConn were called when br.Buffered() > 0.
	firstBytes := []byte{0x16, 0x03, 0x01}
	br := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(firstBytes), cProxy), 8<<10)
	if _, err := br.Peek(len(firstBytes)); err != nil || br.Buffered() != len(firstBytes) {
		t.Fatalf("expected br.Buffered()=%d, got %d (err=%v)", len(firstBytes), br.Buffered(), err)
	}

	doneCh := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		app.tunnelAppAddr(cProxy, br, "203.0.113.55", "203.0.113.55", 443, "Telegram.exe", func(up net.Conn, err error) error {
			return nil
		})
		doneCh <- time.Since(start)
	}()

	select {
	case elapsed := <-doneCh:
		if elapsed >= 200*time.Millisecond {
			t.Fatalf("tunnelAppAddr incurred double SNI sniff delay (%v >= 200ms) despite br.Buffered() > 0", elapsed)
		}
		if br.Buffered() != len(firstBytes) {
			t.Fatalf("expected buffered bytes preserved without extra sniff read, got Buffered()=%d", br.Buffered())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tunnelAppAddr timed out")
	}
}

// TestTelegramUDPCallsRouting verifies Audit 2 Telegram UDP call routing:
// 1. Adding the "telegram" preset or Telegram.exe rule routes Telegram UDP call packets (ports 443, 599, 1400, 10000-65535)
//    through the configured tunnel (WARP / Psiphon) even when connected to raw Telegram DC IPs.
// 2. Unmatched UDP traffic from other apps in "rules" mode continues to route via obDirect ("по умолчанию (мимо VPN)").
func TestTelegramUDPCallsRouting(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obPsiphon // normalized to obDirect in "rules" mode
		c.Routing.Failover = true
		c.Routing.BlockQUIC = false
		c.Routing.BlockSTUN = false
		c.Warp.Enabled = true
	})

	if err := app.addQuickRulePreset("telegram", obWarp); err != nil {
		t.Fatalf("addQuickRulePreset(telegram, warp): %v", err)
	}

	// 1. Telegram.exe UDP voice/video call to raw Telegram DC IP on UDP port 1400 or 50005 routes via obWarp
	for _, port := range []int{443, 599, 1400, 12400, 50005} {
		ob, rname := app.planUDPIP("149.154.167.99", "149.154.167.99", port, `C:\Users\User\AppData\Roaming\Telegram Desktop\Telegram.exe`)
		if ob != obWarp {
			t.Fatalf("Telegram.exe UDP call on port %d routed to %q (%q), want %q", port, ob, rname, obWarp)
		}
	}

	// 2. Telegram web/desktop domain & companion domains (t.me, tdesktop.com, telesco.pe) match the rule
	for _, dom := range []string{"web.telegram.org", "t.me", "tdesktop.com", "telesco.pe"} {
		ord, rname := app.router.planForProto("udp", dom, "", 443, "Telegram.exe")
		if len(ord) != 1 || ord[0] != obWarp {
			t.Fatalf("expected %s for Telegram.exe to route via [warp] without psiphon failover, got %v (%q)", dom, ord, rname)
		}
	}

	// 3. Unmatched UDP traffic from another process in "rules" mode stays on obDirect ("по умолчанию (мимо VPN)")
	obOther, ruleOther := app.planUDPIP("198.51.100.42", "198.51.100.42", 27015, "cs2.exe")
	if obOther != obDirect || ruleOther != "по умолчанию (мимо VPN)" {
		t.Fatalf("expected unmatched UDP in rules mode to use obDirect ('по умолчанию (мимо VPN)'), got %q (%q)", obOther, ruleOther)
	}
}
