package main

// Additional tests closing the TZ section 2 coverage requirement (>= 60%):
// diagnostics, upstream dialers, LAN share, Psiphon engine helpers, platform
// stubs and the remaining Web API branches. Still no external network:
// upstreams, proxies and TLS servers are all local fakes.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------- diag.go ----------

func TestDiagnoseLocal(t *testing.T) {
	// an HTTP upstream: diagnose completes connect+http stages for direct
	// outbounds. (The TLS stage of checkOutbound triggers only on port 443
	// and needs a publicly trusted cert, so it is covered indirectly by the
	// DPI integration test, where a real ClientHello flows end to end.)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 32<<10))
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	_, portStr, _ := net.SplitHostPort(u.Host)
	port := atoiSafe(portStr)

	app := testApp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := app.diagnose(ctx, "127.0.0.1", port)
	if res["host"] != "127.0.0.1" {
		t.Fatalf("diagnose host = %v", res["host"])
	}
	results := res["results"].([]map[string]any)
	byOb := map[string]map[string]any{}
	for _, r := range results {
		byOb[r["outbound"].(string)] = r
	}
	if byOb[obDirect]["ok"] != true {
		t.Fatalf("diagnose direct = %v", byOb[obDirect])
	}
	if byOb[obDesync]["ok"] != true {
		t.Fatalf("diagnose desync = %v", byOb[obDesync])
	}
	if byOb[obPsiphon]["ok"] != false {
		t.Fatalf("diagnose psiphon (engine off) = %v", byOb[obPsiphon])
	}
	if res["best"] == "" {
		t.Fatal("diagnose found no working outbound for a local HTTP server")
	}
	// a dead port diagnoses as a connect-stage failure
	res2 := app.checkOutbound(ctx, obDirect, "127.0.0.1", freePort(t), nil)
	if res2["ok"] != false || res2["stage"] != "connect" {
		t.Fatalf("checkOutbound dead port = %v", res2)
	}
	if nz(nil) == nil || errStr(nil) != "" || errStr(errors.New("boom")) != "boom" {
		t.Fatal("nz/errStr broken")
	}
}

// ---------- router.go: dialUpstream / dialHTTPConnect ----------

// fakeConnectProxy is a minimal HTTP CONNECT proxy used as an upstream.
func fakeConnectProxy(t *testing.T, wantAuth string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, "CONNECT ") {
					return
				}
				target := strings.Fields(line)[1]
				auth := ""
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
					if kv := strings.SplitN(l, ":", 2); len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "Proxy-Authorization") {
						auth = strings.TrimSpace(kv[1])
					}
				}
				if wantAuth != "" && auth != wantAuth {
					_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				th, tp, _ := net.SplitHostPort(target)
				if th == "sni-routed.example.com" || strings.HasSuffix(th, ".example.com") || strings.HasSuffix(th, ".test") {
					target = net.JoinHostPort("127.0.0.1", tp)
				}
				up, err := net.DialTimeout("tcp", target, 3*time.Second)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestDialUpstream(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	ctx := context.Background()

	// through an HTTP CONNECT upstream (anonymous)
	proxyAddr := fakeConnectProxy(t, "")
	c, err := dialUpstream(ctx, "http://"+proxyAddr, echo)
	if err != nil {
		t.Fatalf("dialUpstream http: %v", err)
	}
	roundTrip(t, c, "via-http-upstream")
	c.Close()

	// through an HTTP CONNECT upstream that requires Basic auth
	proxyAddr2 := fakeConnectProxy(t, "Basic "+base64Of("bob:pw"))
	c, err = dialUpstream(ctx, "http://bob:pw@"+proxyAddr2, echo)
	if err != nil {
		t.Fatalf("dialUpstream http+auth: %v", err)
	}
	roundTrip(t, c, "via-auth-upstream")
	c.Close()

	// through a SOCKS5 upstream: reuse our own proxy as the upstream server
	_, socksUp := proxyApp(t, nil, nil)
	c, err = dialUpstream(ctx, "socks5://"+socksUp, echo)
	if err != nil {
		t.Fatalf("dialUpstream socks5: %v", err)
	}
	roundTrip(t, c, "via-socks-upstream")
	c.Close()

	// invalid upstreams
	if _, err := dialUpstream(ctx, "ftp://127.0.0.1:21", echo); err == nil {
		t.Fatal("ftp upstream must be rejected")
	}
	if _, err := dialUpstream(ctx, "", echo); err == nil {
		t.Fatal("empty upstream must be rejected")
	}
}

func base64Of(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// ---------- share.go: setShare ----------

func TestSetShare(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	app := testApp(t)
	port := freePort(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Learn = false
		c.DNS.Enabled = false
		c.Share.Port = port
		c.Share.NoPwdLAN = true
	})
	if err := app.setShare(true); err != nil {
		t.Fatalf("setShare(true): %v", err)
	}
	app.cfg.mu.Lock()
	enabled, pass := app.cfg.Share.Enabled, app.cfg.Share.Password
	app.cfg.mu.Unlock()
	if !enabled || len(pass) != 10 {
		t.Fatalf("share enabled=%v password len=%d", enabled, len(pass))
	}
	// the share port really proxies (LAN clients from loopback need no password)
	c, err := dialSocks5(context.Background(), fmt.Sprintf("127.0.0.1:%d", port), echo, "", "")
	if err != nil {
		t.Fatalf("socks via share port: %v", err)
	}
	roundTrip(t, c, "shared")
	c.Close()
	if info := app.shareInfo(); info["enabled"] != true {
		t.Fatal("shareInfo must report enabled")
	}
	if err := app.setShare(false); err != nil {
		t.Fatalf("setShare(false): %v", err)
	}
	if info := app.shareInfo(); info["enabled"] != false {
		t.Fatal("shareInfo must report disabled after setShare(false)")
	}
	// occupied port -> error, not a crash
	ln, _ := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	defer ln.Close()
	app2 := testApp(t)
	setCfg(app2, func(c *Config) { c.Share.Port = port })
	if err := app2.setShare(true); err == nil {
		t.Fatal("setShare on an occupied port must fail")
	}
}

// TestSharePasswordFromLAN (TZ 3.7): a client that does not come from a
// private/loopback address must authenticate even when lanFree is on.
func TestSharePasswordFromLAN(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	app := testApp(t)
	port := freePort(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Learn = false
		c.DNS.Enabled = false
		c.Share.Port = port
		c.Share.NoPwdLAN = true // free only for private addresses
		c.Share.User = "lan"
		c.Share.Password = "lanpass"
	})
	if err := app.setShare(true); err != nil {
		t.Fatalf("setShare: %v", err)
	}
	defer app.setShare(false)
	ip := ""
	if addrs, _ := net.InterfaceAddrs(); addrs != nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
			}
		}
	}
	if ip == "" {
		t.Skip("no non-loopback interface in this environment")
	}
	// Go does not count the sandbox's 198.19/15-style address as private;
	// on a real LAN the same code path triggers for any non-RFC1918 source.
	if isPrivateAddr(&net.TCPAddr{IP: net.ParseIP(ip)}) {
		t.Skipf("%s is private: lanFree would legitimately apply", ip)
	}
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	// sanity: the greeting must be answered by our own SOCKS server. In the
	// CI sandbox all non-loopback traffic is intercepted by the host, so the
	// answer comes from a foreign proxy and the scenario cannot be emulated.
	probe, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial share via LAN IP: %v", err)
	}
	_ = probe.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := probe.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(probe, rep); err != nil || rep[0] != 5 {
		probe.Close()
		t.Skipf("non-loopback traffic is intercepted in this environment (greeting answer %v, err %v)", rep, err)
	}
	probe.Close()

	ctx := context.Background()
	c, err := dialSocks5(ctx, addr, echo, "lan", "lanpass")
	if err != nil {
		t.Fatalf("share with password from LAN: %v", err)
	}
	roundTrip(t, c, "lan-auth")
	c.Close()
	if _, err := dialSocks5(ctx, addr, echo, "", ""); err == nil {
		t.Fatal("share without password from a non-private address must fail")
	}
	if _, err := dialSocks5(ctx, addr, echo, "lan", "wrong"); err == nil {
		t.Fatal("share with a wrong password from LAN must fail")
	}
}

// ---------- psi.go: engine helpers without a tunnel ----------

func TestPsiEngineHelpers(t *testing.T) {
	app := testApp(t)
	p := app.psi

	// netID: non-empty, then rotated value increments epoch suffix
	initial := p.netID()
	if initial == "" {
		t.Fatal("netID must not be empty")
	}
	p.rotateNetID()
	if got := p.netID(); !strings.HasSuffix(got, "-m1") {
		t.Fatalf("rotated netID = %q, want -m1 suffix", got)
	}

	// control commands are buffered and safe while stopped
	p.Next()
	p.NewNode()
	for i := 0; i < 8; i++ {
		p.send("next") // overflow must drop, not block
	}
	if p.running() {
		t.Fatal("engine must not be running")
	}

	// notices update the visible state
	p.onNotice(mustJSON(t, psiNotice{Type: "AvailableEgressRegions", Data: map[string]any{"regions": []any{"DE", "NL"}}}))
	p.onNotice(mustJSON(t, psiNotice{Type: "ConnectedServerRegion", Data: map[string]any{"serverRegion": "DE"}}))
	p.onNotice(mustJSON(t, psiNotice{Type: "ActiveTunnel", Data: map[string]any{"protocol": "OSSH", "diagnosticID": "srv1"}}))
	p.onNotice(mustJSON(t, psiNotice{Type: "ClientRegion", Data: map[string]any{"region": "RU"}}))
	p.onNotice(mustJSON(t, psiNotice{Type: "Warning", Data: map[string]any{"message": "DSL something"}})) // noise: filtered
	p.onNotice(mustJSON(t, psiNotice{Type: "Warning", Data: map[string]any{"message": "real warning"}}))
	p.onNotice(mustJSON(t, psiNotice{Type: "Tunnels", Data: map[string]any{"count": float64(0)}}))
	select {
	case n := <-p.notes:
		if n.Type != "Tunnels" {
			t.Fatalf("notes channel got %q", n.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("Tunnels notice was not forwarded")
	}
	v := p.view()
	if v["egress_region"] != "DE" || v["protocol"] != "OSSH" || v["state"] != "stopped" {
		t.Fatalf("view = %v", v)
	}
	info := p.info()
	if regs := info["regions"].([]string); len(regs) != 2 {
		t.Fatalf("info regions = %v", regs)
	}
	if slots := p.slots(); len(slots) != 2 { // default parallel = 2
		t.Fatalf("slots = %v", slots)
	}

	// SpeedTest with the engine off fails cleanly
	if st := p.SpeedTest(context.Background()); st["ok"] != false {
		t.Fatalf("SpeedTest while stopped = %v", st)
	}
	// Dial with the engine off fails fast (no 20s wait)
	t0 := time.Now()
	if _, err := p.Dial(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("Dial while stopped must fail")
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Fatalf("Dial while stopped took %v", d)
	}

	// Start/Stop cycle does not hang or panic
	p.Start()
	if !p.running() {
		t.Fatal("engine not marked running after Start")
	}
	p.Stop()
	if p.running() {
		t.Fatal("engine still running after Stop")
	}
}

func mustJSON(t *testing.T, n psiNotice) []byte {
	t.Helper()
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------- app.go / platform / main helpers ----------

func TestProbeStateAndApplyError(t *testing.T) {
	app := testApp(t)
	st := app.probeState()
	if st["running"] != false || st["total"] != 9 {
		t.Fatalf("probeState = %v", st)
	}
	if err := app.applyProbe("std"); err == nil {
		t.Fatal("applyProbe without results must fail")
	}
	if err := app.startProbe(); err != nil {
		t.Fatalf("startProbe: %v", err)
	}
	// a second start while the first is still running must be rejected;
	// (if the child already exited, the second start legitimately succeeds)
	if err := app.startProbe(); err != nil {
		if !strings.Contains(err.Error(), "уже идёт") {
			t.Fatalf("second startProbe error = %v", err)
		}
	} else {
		app.stopProbe()
	}
	// the probe child is the test binary with unknown flags: it exits at
	// once, and the collector marks the run finished
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if app.probeState()["running"] == false {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if app.probeState()["running"] != false {
		t.Fatal("probe run never finished")
	}
}

func TestStatsLoadDays(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "days.json")
	_ = os.WriteFile(file, []byte(`{"2026-01-02":[111,222]}`), 0o600)
	s := newStats(file)
	h := s.history()
	if len(h) != 1 || h[0]["date"] != "2026-01-02" {
		t.Fatalf("history = %v", h)
	}
	tot := h[0]["total"].(map[string]any)
	if tot["up"].(int64) != 111 || tot["down"].(int64) != 222 {
		t.Fatalf("loaded day = %v", tot)
	}
}

func TestConfigValueConverters(t *testing.T) {
	if toInt(float64(3.9)) != 3 || toInt(5) != 5 || toInt(true) != 1 || toInt("x") != 0 {
		t.Fatal("toInt broken")
	}
	if !toBool(true) || toBool(false) || !toBool(float64(2)) || toBool("true") {
		t.Fatal("toBool broken")
	}
	if toStr("a") != "a" || toStr(1) != "" {
		t.Fatal("toStr broken")
	}
}

// ---------- web.go: remaining API branches ----------

func TestWebAPIBranches(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) { c.Share.Port = freePort(t) })
	srv := httptest.NewServer(app.routes())
	defer srv.Close()
	cl := srv.Client()
	do := func(method, path, body string) (int, map[string]any) {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rdr)
		req.Header.Set("X-Psiroute", app.token)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		return resp.StatusCode, v
	}

	if code, _ := do("POST", "/api/rules", `{"default":"direct","auto_chain":["direct","psiphon"],"rules":[{"name":"r","outbound":"direct","domains":["x.test"]}]}`); code != 200 {
		t.Fatalf("POST /api/rules = %d", code)
	}
	if code, v := do("GET", "/api/rules", ""); code != 200 || v["default"] != "direct" {
		t.Fatalf("GET /api/rules = %d %v", code, v)
	}
	if code, _ := do("POST", "/api/rules/add?host=y.test&outbound=direct", ""); code != 200 {
		t.Fatalf("rules/add = %d", code)
	}
	if code, _ := do("POST", "/api/rules/add", ""); code != 400 {
		t.Fatalf("rules/add without host = %d, want 400", code)
	}
	if code, _ := do("POST", "/api/psi/region", `{"region":"de"}`); code != 200 {
		t.Fatalf("psi/region = %d", code)
	}
	app.cfg.mu.Lock()
	region := app.cfg.Psiphon.Country
	app.cfg.mu.Unlock()
	if region != "DE" {
		t.Fatalf("region = %q, want DE", region)
	}
	if code, _ := do("POST", "/api/psi/strategies", `{"strategies":["auto","meek","bogus"]}`); code != 200 {
		t.Fatalf("psi/strategies = %d", code)
	}
	app.cfg.mu.Lock()
	strats := append([]string(nil), app.cfg.Psiphon.Strategies...)
	app.cfg.mu.Unlock()
	if len(strats) != 2 {
		t.Fatalf("strategies after filtering = %v", strats)
	}
	if code, _ := do("POST", "/api/mode/bogus", ""); code != 400 {
		t.Fatalf("mode/bogus = %d, want 400", code)
	}
	if code, _ := do("POST", "/api/reload", ""); code != 200 {
		t.Fatalf("reload = %d", code)
	}
	if code, _ := do("POST", "/api/learned/forget?host=y.test", ""); code != 200 {
		t.Fatalf("learned/forget = %d", code)
	}
	if runtime.GOOS == "windows" {
		if code, _ := do("POST", "/api/sysproxy/on", ""); code != 200 {
			t.Fatalf("sysproxy/on on Windows = %d, want 200", code)
		}
		if code, _ := do("POST", "/api/autostart/on", ""); code != 200 {
			t.Fatalf("autostart/on on Windows = %d, want 200", code)
		}
	} else {
		// platform-dependent endpoints fail cleanly off Windows
		if code, _ := do("POST", "/api/sysproxy/on", ""); code != 500 {
			t.Fatalf("sysproxy/on off Windows = %d, want 500", code)
		}
		if code, _ := do("POST", "/api/autostart/on", ""); code != 500 {
			t.Fatalf("autostart/on off Windows = %d, want 500", code)
		}
	}
	// share on/off through the API
	if code, v := do("POST", "/api/share/on", ""); code != 200 || v["enabled"] != true {
		t.Fatalf("share/on = %d %v", code, v)
	}
	if code, v := do("POST", "/api/share/off", ""); code != 200 || v["enabled"] != false {
		t.Fatalf("share/off = %d %v", code, v)
	}
	// engine start/stop through the API
	if code, _ := do("POST", "/api/psiphon/start", ""); code != 200 {
		t.Fatalf("psiphon/start = %d", code)
	}
	if code, _ := do("POST", "/api/psiphon/next", ""); code != 200 {
		t.Fatalf("psiphon/next = %d", code)
	}
	if code, _ := do("POST", "/api/psiphon/newnode", ""); code != 200 {
		t.Fatalf("psiphon/newnode = %d", code)
	}
	if code, _ := do("POST", "/api/psiphon/bogus", ""); code != 404 {
		t.Fatalf("psiphon/bogus = %d, want 404", code)
	}
	if code, _ := do("POST", "/api/psiphon/stop", ""); code != 200 {
		t.Fatalf("psiphon/stop = %d", code)
	}
	app.psi.Stop()
	deadline := time.Now().Add(15 * time.Second)
	for app.psi.running() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	// diagnose endpoint validates its input without a token-less network call
	if code, _ := do("GET", "/api/diagnose", ""); code != 400 {
		t.Fatalf("diagnose without host = %d, want 400", code)
	}
	if code, v := do("GET", "/api/route?host=example.com&port=443", ""); code != 200 || v["host"] != "example.com" {
		t.Fatalf("route = %d %v", code, v)
	}
}
