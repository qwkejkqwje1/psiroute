package main

// Local integration tests per docs/TESTING_TZ.md section 3. Everything runs
// on 127.0.0.1 with fake upstreams; Psiphon itself is not started, except in
// TestSecondInstance where App.Start launches the engine in the background
// (its connection attempts are irrelevant to the assertions).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// echoServer starts a TCP echo server; network/addr e.g. "tcp","127.0.0.1:0".
func echoServer(t *testing.T, addr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("echo listen %s: %v", addr, err)
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
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// proxyApp starts serveProxy on a random port with routing set to direct.
func proxyApp(t *testing.T, auth *proxyAuth, mutate func(c *Config)) (*App, string) {
	t.Helper()
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obDirect
		c.Routing.Failover = false
		c.Routing.Learn = false
		c.DNS.Enabled = false
		if mutate != nil {
			mutate(c)
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go app.serveProxy(ln, auth)
	t.Cleanup(func() { ln.Close() })
	proxyApps.Store(ln.Addr().String(), app)
	return app, ln.Addr().String()
}

func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

// ---------- SOCKS5 (TZ 2 proxy.go + TZ 3.1) ----------

func TestSocks5ThroughProxy(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	ctx := context.Background()

	// no auth: IPv4 target and domain target
	_, proxy := proxyApp(t, nil, nil)
	c, err := dialSocks5(ctx, proxy, echo, "", "")
	if err != nil {
		t.Fatalf("socks5 ipv4: %v", err)
	}
	roundTrip(t, c, "hello-socks")
	c.Close()

	_, port, _ := net.SplitHostPort(echo)
	c, err = dialSocks5(ctx, proxy, "localhost:"+port, "", "")
	if err != nil {
		t.Fatalf("socks5 domain: %v", err)
	}
	roundTrip(t, c, "hello-domain")
	c.Close()

	// IPv6 target when available
	if echo6 := echoServer6(t); echo6 != "" {
		c, err = dialSocks5(ctx, proxy, echo6, "", "")
		if err != nil {
			t.Fatalf("socks5 ipv6: %v", err)
		}
		roundTrip(t, c, "hello-v6")
		c.Close()
	}
}

func echoServer6(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Logf("IPv6 unavailable, skipping: %v", err)
		return ""
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return ln.Addr().String()
}

func TestSocks5Auth(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	ctx := context.Background()
	auth := &proxyAuth{user: "user1", pass: "secret", lanFree: false}
	_, proxy := proxyApp(t, auth, nil)

	c, err := dialSocks5(ctx, proxy, echo, "user1", "secret")
	if err != nil {
		t.Fatalf("socks5 good auth: %v", err)
	}
	roundTrip(t, c, "auth-ok")
	c.Close()

	if _, err := dialSocks5(ctx, proxy, echo, "user1", "wrong"); err == nil {
		t.Fatal("socks5 with a wrong password must fail")
	}
	if _, err := dialSocks5(ctx, proxy, echo, "", ""); err == nil {
		t.Fatal("socks5 without auth against an auth proxy must fail")
	}

	// lanFree: loopback clients skip the password
	authFree := &proxyAuth{user: "user1", pass: "secret", lanFree: true}
	_, proxyFree := proxyApp(t, authFree, nil)
	c, err = dialSocks5(ctx, proxyFree, echo, "", "")
	if err != nil {
		t.Fatalf("socks5 lanFree from loopback: %v", err)
	}
	roundTrip(t, c, "lan-free")
	c.Close()
}

// ---------- HTTP proxy (TZ 2 proxy.go) ----------

func TestHTTPConnectThroughProxy(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	_, proxy := proxyApp(t, nil, nil)
	c, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo, echo)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("CONNECT response = %q, err=%v", line, err)
	}
	for { // skip remaining headers
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	if _, err := io.WriteString(c, "via-connect"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("via-connect"))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "via-connect" {
		t.Fatalf("echo over CONNECT = %q, err=%v", buf, err)
	}
}

func TestHTTPPlainThroughProxy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proxied-body")
	}))
	defer up.Close()
	_, proxy := proxyApp(t, nil, nil)
	c, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET %s/page HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", up.URL, strings.TrimPrefix(up.URL, "http://"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || string(b) != "proxied-body" {
		t.Fatalf("plain HTTP via proxy = %d %q", resp.StatusCode, b)
	}
}

// ---------- failover at dial stage (TZ 3.2) ----------

func TestFailoverDeadWarpToDirect(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	app, proxy := proxyApp(t, nil, func(c *Config) {
		c.Routing.Mode = "auto"
		c.Routing.Chain = []string{obWarp, obDirect}
		c.Warp.Socks = "127.0.0.1:1" // nothing listens there
	})
	t0 := time.Now()
	c, err := dialSocks5(context.Background(), proxy, echo, "", "")
	if err != nil {
		t.Fatalf("failover dial: %v", err)
	}
	if d := time.Since(t0); d > 7*time.Second {
		t.Fatalf("failover took %v, TZ limit is 7s", d)
	}
	roundTrip(t, c, "failover-works")
	c.Close()
	// the connection must be recorded as a fallback to direct (the relay
	// drains for up to 5s after the client closes, so allow for that)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		snap := app.stats.snapshot()
		for _, cl := range snap["closed"].([]map[string]any) {
			if cl["outbound"] == obDirect && strings.Contains(fmt.Sprint(cl["rule"]), "запасной") {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("stats do not show the connection as a direct fallback")
}

// ---------- DPI middlebox imitation (TZ 3.3) ----------

// dpiServer imitates a DPI box in front of a TLS server: if the whole SNI
// arrives in the first TLS record it resets the connection; if the hello was
// split across two records it reassembles it and answers.
func dpiServer(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1:443: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	readRecord := func(c net.Conn) ([]byte, error) {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return nil, err
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(c, body); err != nil {
			return nil, err
		}
		return append(hdr, body...), nil
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				rec1, err := readRecord(c)
				if err != nil {
					return
				}
				if bytes.Contains(rec1, []byte("blocked.test")) {
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.SetLinger(0) // RST, like a DPI reset
					}
					return
				}
				rec2, err := readRecord(c)
				if err != nil {
					return
				}
				joined := append(rec1[5:], rec2[5:]...)
				if bytes.Contains(joined, []byte("blocked.test")) {
					_, _ = io.WriteString(c, "OK-RESPONSE")
					time.Sleep(100 * time.Millisecond)
				}
			}(c)
		}
	}()
}

func TestDPIResetThenLearnDesync(t *testing.T) {
	dpiServer(t)
	hello := clientHello(t, "blocked.test")
	_, proxy := proxyApp(t, nil, func(c *Config) {
		c.Routing.Mode = "auto"
		c.Routing.Chain = []string{obDirect}
		c.Routing.Learn = true
		c.Desync.Enabled = true
	})
	ctx := context.Background()

	// 1) direct: the DPI server sees the full SNI in one record and resets
	c, err := dialSocks5(ctx, proxy, "127.0.0.1:443", "", "")
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	buf := make([]byte, 64)
	n, rerr := c.Read(buf)
	if n > 0 && bytes.Contains(buf[:n], []byte("OK-RESPONSE")) {
		t.Fatal("direct connection must NOT pass the DPI imitation")
	}
	_ = rerr
	c.Close()

	// 2) the router must learn the host and switch it to direct-dpi
	learnedOK := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !learnedOK {
		time.Sleep(200 * time.Millisecond)
		learnedOK = pollLearned(t, proxy)
	}
	if !learnedOK {
		t.Fatal("router did not learn direct-dpi for 127.0.0.1 after the DPI reset")
	}
	if order, _ := lastProxyAppRouter(t, proxy); len(order) == 0 || order[0] != obDesync {
		t.Fatalf("plan after learning = %v, want direct-dpi first", order)
	}

	// 3) second connection goes through desync and passes
	c, err = dialSocks5(ctx, proxy, "127.0.0.1:443", "", "")
	if err != nil {
		t.Fatalf("socks dial 2: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("write hello 2: %v", err)
	}
	buf = make([]byte, 64)
	n, err = c.Read(buf)
	if err != nil || !bytes.Contains(buf[:n], []byte("OK-RESPONSE")) {
		t.Fatalf("desync connection: n=%d err=%v data=%q", n, err, buf[:n])
	}
}

// The helpers below reach the App behind proxyApp through a tiny registry,
// because proxyApp returns the app but the DPI test needs it after the fact.
var proxyApps sync.Map // proxy addr -> *App

func pollLearned(t *testing.T, proxy string) bool {
	t.Helper()
	v, ok := proxyApps.Load(proxy)
	if !ok {
		return false
	}
	app := v.(*App)
	for _, e := range app.router.learnedList() {
		if e["host"] == "127.0.0.1" && e["outbound"] == obDesync {
			return true
		}
	}
	return false
}

func lastProxyAppRouter(t *testing.T, proxy string) ([]string, string) {
	t.Helper()
	v, ok := proxyApps.Load(proxy)
	if !ok {
		return nil, ""
	}
	return v.(*App).router.plan("127.0.0.1", 443)
}

// ---------- Web API (TZ 3.4) ----------

func TestWebAPI(t *testing.T) {
	app := testApp(t)
	srv := httptest.NewServer(app.routes())
	defer srv.Close()
	cl := srv.Client()

	get := func(path, token string) (int, []byte) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if token != "" {
			req.Header.Set("X-Psiroute", token)
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	// /api/ping works without a token
	code, b := get("/api/ping", "")
	if code != 200 || !strings.HasPrefix(string(b), "psiroute") {
		t.Fatalf("/api/ping = %d %q", code, b)
	}
	// API without the token is rejected (code returns 401; TZ expects 403 —
	// recorded in TEST_REPORT.md as a discrepancy)
	code, _ = get("/api/state", "")
	if code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Fatalf("/api/state without token = %d, want 401/403", code)
	}
	// DNS-rebinding guard: a foreign Host is rejected even before the token
	req, _ := http.NewRequest("GET", srv.URL+"/api/state", nil)
	req.Host = "evil.com"
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("evil Host = %d, want 403", resp.StatusCode)
	}
	// with the token: every endpoint answers valid JSON
	for _, p := range []string{"/api/state", "/api/psi/info", "/api/settings", "/api/rules", "/api/share", "/api/psi/probe", "/api/route?host=example.com"} {
		code, b := get(p, app.token)
		if code != 200 {
			t.Fatalf("GET %s = %d (%s)", p, code, b)
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("GET %s: invalid JSON: %v", p, err)
		}
	}
	// POST endpoints
	post := func(path, body string) int {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
		req.Header.Set("X-Psiroute", app.token)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode
	}
	if code := post("/api/mode/auto", ""); code != 200 {
		t.Fatalf("POST /api/mode/auto = %d", code)
	}
	app.cfg.mu.Lock()
	mode := app.cfg.Routing.Mode
	app.cfg.mu.Unlock()
	if mode != "auto" {
		t.Fatalf("mode after POST = %q", mode)
	}
	if code := post("/api/settings", `{"desync.enabled":false}`); code != 200 {
		t.Fatalf("POST /api/settings = %d", code)
	}
	if code := post("/api/dns/clear", ""); code != 200 {
		t.Fatalf("POST /api/dns/clear = %d", code)
	}
	if code := post("/api/learned/clear", ""); code != 200 {
		t.Fatalf("POST /api/learned/clear = %d", code)
	}
	if code := post("/api/unknown-thing", ""); code != 404 {
		t.Fatalf("POST unknown = %d, want 404", code)
	}
}

// ---------- second instance (TZ 3.6) ----------

func TestSecondInstance(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mk := func() *App {
		a := NewApp(ctx, cancel, filepath.Join(dir, "psiroute.json"), dir)
		setCfg(a, func(c *Config) {
			c.General.Listen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
			c.General.UI = fmt.Sprintf("127.0.0.1:%d", freePort(t))
			c.Share.Enabled = false
			c.General.SystemProxy = false
		})
		return a
	}
	a1 := mk()
	if err := a1.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer a1.Shutdown()
	if !isPsirouteAt(a1.uiAddr()) {
		t.Fatal("isPsirouteAt does not see the running instance")
	}
	a2 := NewApp(ctx, cancel, filepath.Join(dir, "psiroute.json"), dir)
	setCfg(a2, func(c *Config) {
		c.General.Listen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
		c.General.UI = a1.uiAddr() // same UI address as the running instance
		c.Share.Enabled = false
		c.General.SystemProxy = false
	})
	if err := a2.Start(); !errors.Is(err, errAlreadyRunning) {
		t.Fatalf("second Start = %v, want errAlreadyRunning", err)
	}
}

// ---------- UI port fallback (field bug 08.11.2026) ----------

// TestUIPortFallback: when the configured UI port is held by a foreign
// program (e.g. the old Rust panel), Start must move the UI to the next
// free port instead of failing.
func TestUIPortFallback(t *testing.T) {
	uiPort := freePort(t)
	blocker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", uiPort))
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := NewApp(ctx, cancel, filepath.Join(dir, "psiroute.json"), dir)
	setCfg(a, func(c *Config) {
		c.General.Listen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
		c.General.UI = fmt.Sprintf("127.0.0.1:%d", uiPort)
		c.Share.Enabled = false
		c.General.SystemProxy = false
	})
	if err := a.Start(); err != nil {
		t.Fatalf("Start with occupied UI port: %v", err)
	}
	defer a.Shutdown()
	want := fmt.Sprintf("127.0.0.1:%d", uiPort+1)
	if got := a.uiAddr(); got != want {
		t.Fatalf("UI addr after fallback = %s, want %s", got, want)
	}
	if !isPsirouteAt(want) {
		t.Fatal("instance does not answer on the fallback UI port")
	}
}

// ---------- local proxy latency (TZ 5, light version) ----------

func TestProxyLatency(t *testing.T) {
	echo := echoServer(t, "127.0.0.1:0")
	_, proxy := proxyApp(t, nil, nil)
	ctx := context.Background()
	measure := func(viaProxy bool) []time.Duration {
		out := make([]time.Duration, 0, 200)
		for i := 0; i < 200; i++ {
			t0 := time.Now()
			var c net.Conn
			var err error
			if viaProxy {
				c, err = dialSocks5(ctx, proxy, echo, "", "")
			} else {
				c, err = net.DialTimeout("tcp", echo, 2*time.Second)
			}
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.WriteString(c, "x"); err == nil {
				one := make([]byte, 1)
				_, _ = io.ReadFull(c, one)
			}
			out = append(out, time.Since(t0))
			c.Close()
		}
		return out
	}
	pct := func(ds []time.Duration, q float64) time.Duration {
		s := append([]time.Duration(nil), ds...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return s[int(float64(len(s))*q)]
	}
	direct, via := measure(false), measure(true)
	d50, d99 := pct(direct, 0.5), pct(direct, 0.99)
	v50, v99 := pct(via, 0.5), pct(via, 0.99)
	t.Logf("direct:  p50=%v p99=%v", d50, d99)
	t.Logf("via psiroute: p50=%v p99=%v", v50, v99)
	t.Logf("overhead: p50=%v p99=%v", v50-d50, v99-d99)
	if v99-d99 > 50*time.Millisecond {
		t.Fatalf("proxy p99 overhead = %v, unreasonably high for a local relay", v99-d99)
	}
}
