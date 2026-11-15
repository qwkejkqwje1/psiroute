package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Minimal DNS wire format, for DNS over UDP through the tunnels (udp.go),
// TUN DNS hijacking (tun.go) and for the self-test: build a query, read
// A/AAAA answers, and cache wire-format DoH responses.

type dohWireEntry struct {
	msg []byte
	exp time.Time
}

type dohWireCache struct {
	mu sync.Mutex
	m  map[string]dohWireEntry
}

var theDoHWire = &dohWireCache{m: map[string]dohWireEntry{}}

func (c *dohWireCache) clear() {
	c.mu.Lock()
	c.m = map[string]dohWireEntry{}
	c.mu.Unlock()
}

func (c *dohWireCache) prune() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) == 0 {
		return
	}
	for k, v := range c.m {
		if now.After(v.exp) {
			delete(c.m, k)
		}
	}
}

func dnsWireKey(ob string, q []byte) string {
	name, end := dnsQName(q)
	if end < 4 || end > len(q) || name == "" {
		return ""
	}
	qtype := binary.BigEndian.Uint16(q[end-4 : end-2])
	qclass := binary.BigEndian.Uint16(q[end-2 : end])
	return fmt.Sprintf("%s\x00%s\x00%d:%d", ob, name, qtype, qclass)
}

func (c *dohWireCache) get(key string, id0, id1 byte) []byte {
	if key == "" {
		return nil
	}
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if !ok || len(e.msg) < 12 || time.Now().After(e.exp) {
		return nil
	}
	out := bytes.Clone(e.msg)
	out[0], out[1] = id0, id1
	return out
}

func (c *dohWireCache) put(key string, msg []byte, ttl time.Duration) {
	if key == "" || len(msg) < 12 || msg[3]&0x0f != 0 {
		return
	}
	now := time.Now()
	cp := bytes.Clone(msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 1024 {
		for k, v := range c.m {
			if now.After(v.exp) {
				delete(c.m, k)
			}
		}
		if len(c.m) > 1024 {
			c.m = map[string]dohWireEntry{}
		}
	}
	c.m[strings.Clone(key)] = dohWireEntry{msg: cp, exp: now.Add(ttl)}
}

func dnsQuery(id uint16, name string, qtype uint16) []byte {
	b := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" || len(l) > 63 {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

var errDNSShort = errors.New("DNS: короткий ответ")

func dnsSkipName(msg []byte, off int) int {
	for off < len(msg) {
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return -1
			}
			return off + 2
		case l&0xc0 != 0:
			return -1
		default:
			off += 1 + l
		}
	}
	return -1
}

// dnsAnswers returns the A and AAAA addresses of a DNS response.
func dnsAnswers(msg []byte) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, errDNSShort
	}
	if rc := msg[3] & 0x0f; rc != 0 {
		return nil, fmt.Errorf("DNS: код ответа %d", rc)
	}
	qd, an := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for range qd {
		if off = dnsSkipName(msg, off); off < 0 || off+4 > len(msg) {
			return nil, errDNSShort
		}
		off += 4
	}
	var ips []net.IP
	for range an {
		if off = dnsSkipName(msg, off); off < 0 || off+10 > len(msg) {
			break
		}
		typ, rdl := binary.BigEndian.Uint16(msg[off:]), int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdl > len(msg) {
			break
		}
		if (typ == 1 && rdl == 4) || (typ == 28 && rdl == 16) {
			ips = append(ips, net.IP(bytes.Clone(msg[off:off+rdl])))
		}
		off += rdl
	}
	return ips, nil
}

// DNS over HTTPS through an outbound (Psiphon, WARP): works on every server,
// unlike plain UDP, and the provider sees nothing.
var dohEndpoints = []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query", "https://8.8.8.8/dns-query"}

var dohTestTLS *tls.Config // tests: trust the local server

func (a *App) dohClient(ob string) *http.Client {
	if v, ok := a.dohClients.Load(ob); ok {
		return v.(*http.Client)
	}
	dial := a.router.dialer(ob)
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dial(ctx, "tcp", addr)
		},
		TLSClientConfig:     dohTestTLS,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 8 * time.Second,
		IdleConnTimeout:     60 * time.Second,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
	}}
	v, _ := a.dohClients.LoadOrStore(ob, cl)
	return v.(*http.Client)
}

// dohReset drops kept-alive DoH connections (they die with a tunnel).
func (a *App) dohReset() {
	theDoHWire.clear()
	a.dohClients.Range(func(_, v any) bool {
		v.(*http.Client).CloseIdleConnections()
		return true
	})
}

func (a *App) dohExchange(ctx context.Context, ob string, q []byte) ([]byte, error) {
	if len(q) < 12 {
		return nil, errDNSShort
	}
	qname, _ := dnsQName(q)
	key := dnsWireKey(ob, q)
	if cached := theDoHWire.get(key, q[0], q[1]); cached != nil {
		return cached, nil
	}
	cl := a.dohClient(ob)
	var lastErr error
	for _, u := range dohEndpoints {
		req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(q))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := cl.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || len(b) < 12 {
			lastErr = fmt.Errorf("DoH %s: ответ %d", u, resp.StatusCode)
			continue
		}
		theDoHWire.put(key, b, 2*time.Minute)
		if qname != "" {
			if ips, err := dnsAnswers(b); err == nil {
				for _, ip := range ips {
					theRevDNS.put(ip, qname, 10*time.Minute)
				}
			}
		}
		return b, nil
	}
	if lastErr == nil {
		lastErr = errors.New("DoH: нет серверов")
	}
	return nil, lastErr
}

// tunnelLookup resolves a name inside the tunnel (A first, then AAAA).
func (a *App) tunnelLookup(ctx context.Context, ob, host string) (net.IP, error) {
	for _, qt := range []uint16{1, 28} {
		resp, err := a.dohExchange(ctx, ob, dnsQuery(0, host, qt))
		if err != nil {
			return nil, err
		}
		if ips, err := dnsAnswers(resp); err == nil && len(ips) > 0 {
			return ips[0], nil
		}
	}
	return nil, fmt.Errorf("%s: адрес не найден", host)
}
