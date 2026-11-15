package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
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

	// Force immediate write using the exact same persist structure
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

// TestRelayDynamicSNIRouteHandoff verifies BUG-202-03 fix:
// when a client connects to a raw IP ( initially routed to obDirect ) and sends
// a TLS ClientHello whose SNI matches a rule with a different outbound (e.g. obProxy),
// relay() seamlessly dials the new outbound, hands off the downstream reader without
// dropping the ServerHello or leaking sockets, and updates tracked route metadata.
func TestRelayDynamicSNIRouteHandoff(t *testing.T) {
	// Start a fake target server that responds with "SERVER-HELLO-OK" after reading ClientHello
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

	// Initial dummy connection (representing the pre-SNI raw-IP connection that never answers)
	initialClient, initialServer := net.Pipe()
	defer initialServer.Close()
	go func() {
		_, _ = io.Copy(io.Discard, initialServer)
	}()

	// Configure app so sni-routed.example.com routes via obProxy (pointing to fakeConnectProxy)
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

	// Client sends TLS ClientHello with SNI="sni-routed.example.com" and reads response
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

// TestBlockQUICAndRouteCacheInvalidation verifies BUG-202-04 and BUG-202-05 fixes.
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
		}
	})

	// 1. BlockQUIC drops UDP:443 for Psiphon and Desync routes, but allows UDP:443 on explicit Direct route and UDP:50000
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

	// 2. RouteCache hit and invalidation when local list is updated
	_, _ = app.lists.SaveLocalList("dyn-list", "cached-list.example.com\n")
	setCfg(app, func(c *Config) {
		c.Routing.Rules = append([]Rule{
			{Name: "List Rule", Outbound: obWarp, Lists: []string{"local:dyn-list.lst"}, Always: true},
		}, c.Routing.Rules...)
	})
	ord1, _ := app.router.planForProto("tcp", "new-member.example.com", "", 443, "chrome.exe")
	if len(ord1) == 0 || ord1[0] != obPsiphon {
		t.Fatalf("expected initial route obPsiphon, got %v", ord1)
	}
	// Update local list to include new-member.example.com -> must automatically invalidate routeCache
	_, err := app.lists.SaveLocalList("dyn-list", "cached-list.example.com\nnew-member.example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	ord2, rname := app.router.planForProto("tcp", "new-member.example.com", "", 443, "chrome.exe")
	if len(ord2) == 0 || ord2[0] != obWarp || rname != "List Rule" {
		t.Fatalf("routeCache was not invalidated after SaveLocalList: got %v (%q)", ord2, rname)
	}
}

// TestBatchAndQuickConnRuleValidation verifies BUG-202-07 fix:
// invalid outbounds, bad port ranges, or missing lists are rejected with 400 Bad Request,
// while port-only batch rules and learned-route forgetting work properly.
func TestBatchAndQuickConnRuleValidation(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Learn = true
	})
	app.router.remember("batch-target.example.com", obDirect, "old", true)

	// 1. Invalid outbound in /api/rules/batch must return 400
	recBadOb := apiCall(t, app, "POST", "/api/rules/batch", true, `{"text":"example.com","outbound":"invalid_outbound"}`)
	if recBadOb.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid outbound in batch, got %d: %s", recBadOb.Code, recBadOb.Body.String())
	}

	// 2. Invalid outbound in /api/rules/from-conn must return 400
	recBadQuick := apiCall(t, app, "POST", "/api/rules/from-conn", true, `{"host":"example.com","outbound":"psiphon:INVALID"}`)
	if recBadQuick.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid country outbound in quickConnRuleAPI, got %d: %s", recBadQuick.Code, recBadQuick.Body.String())
	}

	// 3. Port-only batch rule + domain batch import clears learned route
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

	// Flush WITHOUT calling tick() first: dayFile must still capture the full delta!
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

// TestServeWorkerSocksHalfClose verifies BUG-202-08 fix:
// when the client closes its write half (EOF) immediately after sending a request,
// serveWorkerSocks still delivers the full upstream response before closing.
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
		_, _ = io.ReadAll(c) // wait for client FIN (CloseWrite)
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
