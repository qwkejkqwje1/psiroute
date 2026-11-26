package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// diagnose checks one site through every outbound and explains what blocks it:
// DNS spoofing, TCP block, TLS/SNI reset, slow throttling, and whether ECH
// (Encrypted ClientHello) is available in DNS HTTPS records.
func (a *App) diagnose(ctx context.Context, host string, port int) map[string]any {
	sys, sysErr := net.DefaultResolver.LookupHost(ctx, host)
	doh, dohErr := dohLookup(ctx, host)
	suspicious := false
	if len(sys) > 0 && len(doh) > 0 {
		common := false
		for _, x := range sys {
			for _, y := range doh {
				if x == y {
					common = true
				}
			}
		}
		suspicious = !common
	}
	for _, x := range sys {
		if ip := net.ParseIP(x); ip != nil && (ip.IsPrivate() || ip.IsUnspecified() || ip.IsLoopback()) {
			suspicious = true
		}
	}
	echBytes, hasECH := a.lookupECH(ctx, host)
	dnsInfo := map[string]any{
		"system": nz(sys), "system_error": errStr(sysErr),
		"doh": nz(doh), "doh_error": errStr(dohErr),
		"suspicious": suspicious,
		"ech":        hasECH, "ech_len": len(echBytes),
	}

	obs := []string{obDirect, obDesync, obPsiphon}
	a.cfg.mu.Lock()
	if a.cfg.Warp.Enabled {
		obs = append(obs, obWarp)
	}
	if a.cfg.Proxy.Enabled && a.cfg.Proxy.Upstream != "" {
		obs = append(obs, obProxy)
	}
	a.cfg.mu.Unlock()

	results := make([]map[string]any, len(obs))
	var wg sync.WaitGroup
	for i, ob := range obs {
		wg.Add(1)
		func(i int, ob string) { safeGo("App.diagnose", func() {
			defer wg.Done()
			results[i] = a.checkOutbound(ctx, ob, host, port, doh)
		}) }(i, ob)
	}
	wg.Wait()
	best := ""
	bestKbps := -1
	for _, r := range results {
		if r["ok"] == true {
			if k, _ := r["kbps"].(int); k > bestKbps {
				best, bestKbps = r["outbound"].(string), k
			}
		}
	}
	return map[string]any{"ok": best != "", "host": host, "best": best, "dns": dnsInfo, "results": results}
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return short(err.Error(), 160)
}

func (a *App) checkOutbound(ctx context.Context, ob, host string, port int, doh []string) map[string]any {
	r := map[string]any{"outbound": ob, "ok": false, "stage": "connect", "connect_ms": 0, "tls_ms": 0, "ttfb_ms": 0, "kbps": 0, "error": ""}
	if ob == obPsiphon && (a.psi == nil || (!a.psi.running() && a.psi.cur.Load() == nil && a.psi.primaryDialHook == nil)) {
		r["error"] = "Psiphon не подключён"
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if (ob == obDirect || ob == obDesync) && len(doh) > 0 {
		addr = net.JoinHostPort(doh[0], strconv.Itoa(port)) // avoid spoofed DNS
	}
	t0 := time.Now()
	c, err := a.router.dialer(ob)(ctx, "tcp", addr)
	if err != nil {
		r["error"] = errStr(err)
		return r
	}
	defer c.Close()
	r["connect_ms"] = int(time.Since(t0).Milliseconds())
	if dl, okd := ctx.Deadline(); okd {
		_ = c.SetDeadline(dl)
	}
	var conn net.Conn = c
	if port == 443 {
		r["stage"] = "tls"
		t1 := time.Now()
		tc := tls.Client(c, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
		if err := tc.HandshakeContext(ctx); err != nil {
			r["error"] = errStr(err)
			return r
		}
		r["tls_ms"] = int(time.Since(t1).Milliseconds())
		conn = tc
	}
	r["stage"] = "http"
	t2 := time.Now()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: Mozilla/5.0 psiroute\r\nAccept: */*\r\nConnection: close\r\n\r\n"); err != nil {
		r["error"] = errStr(err)
		return r
	}
	br := bufio.NewReader(conn)
	if _, err := br.Peek(1); err != nil {
		r["error"] = errStr(err)
		return r
	}
	r["ttfb_ms"] = int(time.Since(t2).Milliseconds())
	t3 := time.Now()
	n, _ := io.CopyN(io.Discard, br, 2<<20)
	if secs := time.Since(t3).Seconds(); n >= 16<<10 && secs > 0 {
		r["kbps"] = int(float64(n) / 1024 / secs)
	}
	r["ok"] = true
	r["stage"] = "done"
	return r
}
