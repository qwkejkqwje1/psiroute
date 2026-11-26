package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// obfsTestHello builds a minimal TLS ClientHello with an SNI and padding.
func obfsTestHello(name string) []byte {
	sn := []byte(name)
	list := append([]byte{0x00, byte(len(sn) >> 8), byte(len(sn))}, sn...)
	list = append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	ext := []byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}
	ext = append(ext, list...)
	ext = append(ext, 0x00, 0x15, 0x00, 0xc8) // padding extension
	ext = append(ext, make([]byte, 200)...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)   // random
	body = append(body, 0x00)                  // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func obfsJoinRecords(t *testing.T, segs [][]byte) []byte {
	t.Helper()
	stream := bytes.Join(segs, nil)
	var body []byte
	for len(stream) > 0 {
		if len(stream) < 5 || stream[0] != 0x16 {
			t.Fatalf("not a TLS record: % x", stream[:min(len(stream), 8)])
		}
		l := int(stream[3])<<8 | int(stream[4])
		if l == 0 || 5+l > len(stream) {
			t.Fatalf("bad record length %d", l)
		}
		body = append(body, stream[5:5+l]...)
		stream = append([]byte(nil), stream[5+l:]...)
	}
	return body
}

func TestObfsMethodsKeepDataAndHideName(t *testing.T) {
	const name = "www.example-blocked.com"
	hello := obfsTestHello(name)
	if parseSNI(hello) != name {
		t.Fatalf("test hello: sni %q", parseSNI(hello))
	}
	for _, m := range obfsMethods {
		for i := 0; i < 50; i++ { // the cut points are random
			segs := m.cut(append([]byte(nil), hello...))
			if len(segs) < 2 {
				t.Fatalf("%s: %d segments", m.id, len(segs))
			}
			for _, s := range segs {
				if len(s) == 0 {
					t.Fatalf("%s: empty segment", m.id)
				}
				if bytes.Contains(s, []byte(name)) {
					t.Fatalf("%s: one segment holds the whole name", m.id)
				}
			}
			switch m.id {
			case "split", "chunk":
				if !bytes.Equal(bytes.Join(segs, nil), hello) {
					t.Fatalf("%s: the stream changed", m.id)
				}
			default:
				if got := obfsJoinRecords(t, segs); !bytes.Equal(got, hello[5:]) {
					t.Fatalf("%s: the handshake changed", m.id)
				}
			}
		}
	}
	raw := []byte("SSH-2.0-OpenSSH_9.0\r\n")
	for _, m := range obfsMethods {
		if segs := m.cut(raw); len(segs) != 1 || !bytes.Equal(segs[0], raw) {
			t.Fatalf("%s: non-TLS data must pass unchanged", m.id)
		}
	}
}

func TestObfsHTTP(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: rutracker.org\r\nUser-Agent: x\r\n\r\n")
	if !obfsLooksHTTP(req) || obfsLooksHTTP([]byte{0x16, 3, 1}) {
		t.Fatal("obfsLooksHTTP")
	}
	for i := 0; i < 30; i++ {
		segs := obfsHTTP(req)
		if len(segs) != 2 {
			t.Fatalf("%d segments", len(segs))
		}
		j := bytes.Join(segs, nil)
		if !strings.Contains(string(j), "\r\nhoSt: rutracker.org\r\n") || !bytes.EqualFold(j, req) {
			t.Fatalf("bad request: %q", j)
		}
		for _, s := range segs {
			if bytes.Contains(s, []byte("rutracker.org")) {
				t.Fatal("one segment holds the whole host")
			}
		}
	}
}

func TestObfsHelloNeed(t *testing.T) {
	h := obfsTestHello("a.example")
	if n := obfsHelloNeed(h[:3]); n != 5 {
		t.Fatalf("3 bytes: %d", n)
	}
	if n := obfsHelloNeed(h[:40]); n != len(h) {
		t.Fatalf("40 bytes: %d, want %d", n, len(h))
	}
	if n := obfsHelloNeed([]byte("GET /")); n != 5 {
		t.Fatalf("http: %d", n)
	}
}

func TestObfsBookOrder(t *testing.T) {
	obfs.reset()
	t.Cleanup(obfs.reset)
	if o := obfs.order("a.com", "auto"); len(o) != len(obfsMethods) || o[0] != "tlsrec" {
		t.Fatalf("default order %v", o)
	}
	if o := obfs.order("a.com", "chunk"); len(o) != 1 || o[0] != "chunk" {
		t.Fatalf("forced %v", o)
	}
	obfs.result("a.com", "multirec", true)
	if o := obfs.order("a.com", "auto"); o[0] != "multirec" {
		t.Fatalf("the site's method must go first: %v", o)
	}
	for i := 0; i < 5; i++ {
		obfs.result("b.com", "tlsrec", false)
	}
	if o := obfs.order("c.com", "auto"); o[0] == "tlsrec" {
		t.Fatalf("a failing method must not go first: %v", o)
	}
}

func TestObfsBackgroundAutoTuneOnErrorSpike(t *testing.T) {
	obfs.reset()
	t.Cleanup(obfs.reset)

	// Record strong performance for "double"
	for i := 0; i < 4; i++ {
		obfs.result("good.example", "double", true)
	}
	// While "chunk" is healthy, forced "chunk" returns only ["chunk"]
	if o := obfs.order("x.example", "chunk"); len(o) != 1 || o[0] != "chunk" {
		t.Fatalf("healthy forced chunk = %v", o)
	}

	var hookedFailed, hookedNext string
	obfs.mu.Lock()
	obfs.onAutoTune = func(failedMethod, nextMethod string) {
		hookedFailed, hookedNext = failedMethod, nextMethod
	}
	obfs.mu.Unlock()
	defer func() {
		obfs.mu.Lock()
		obfs.onAutoTune = nil
		obfs.mu.Unlock()
	}()

	// Simulate 3 consecutive failures on "chunk" -> auto-tune triggers!
	for i := 0; i < 3; i++ {
		obfs.result("x.example", "chunk", false)
	}
	if hookedFailed != "chunk" || hookedNext != "double" {
		t.Fatalf("auto-tune hook = (%q -> %q), want (chunk -> double)", hookedFailed, hookedNext)
	}
	// Now even if forced=="chunk", order() unlocks the fallback chain with "double" #1
	o := obfs.order("x.example", "chunk")
	if len(o) < 2 || o[0] != "double" {
		t.Fatalf("degraded forced method order = %v, want double first", o)
	}
}

func TestObfsAutoTuneCooldownPreventsPingPong(t *testing.T) {
	obfs.reset()
	t.Cleanup(obfs.reset)

	// Give "double" and "multirec" baseline successes so both look viable initially.
	for i := 0; i < 4; i++ {
		obfs.result("ok1.example", "double", true)
		obfs.result("ok2.example", "multirec", true)
	}

	switches := 0
	obfs.mu.Lock()
	obfs.onAutoTune = func(_, _ string) { switches++ }
	obfs.mu.Unlock()
	defer func() {
		obfs.mu.Lock()
		obfs.onAutoTune = nil
		obfs.mu.Unlock()
	}()

	// First spike switches away from "chunk" once.
	for i := 0; i < 3; i++ {
		obfs.result("blocked.example", "chunk", false)
	}
	if switches != 1 {
		t.Fatalf("initial switches = %d, want 1", switches)
	}

	// Simulate failures hitting the active auto-tuned method and fallbacks within seconds
	// (e.g. an unreachable DoT host): cooldown must prevent 1s ping-pong switching.
	obfs.mu.Lock()
	cur := obfs.autoTunedMethod
	obfs.mu.Unlock()
	for i := 0; i < 6; i++ {
		obfs.result("common.dot.dns.yandex.net", cur, false)
	}
	for i := 0; i < 6; i++ {
		obfs.result("common.dot.dns.yandex.net", "split", false)
	}
	if switches != 1 {
		t.Fatalf("switches during cooldown = %d, want 1 (ping-pong not prevented)", switches)
	}
}

func TestQUICInitialDesyncFakes(t *testing.T) {
	qPkt, err := quicInitial("www.youtube.com")
	if err != nil {
		t.Fatal(err)
	}
	if !isQUICInitial(qPkt) {
		t.Fatal("quicInitial packet not recognized by isQUICInitial")
	}
	if isQUICInitial([]byte("short-udp")) || isQUICInitial(make([]byte, 100)) {
		t.Fatal("non-QUIC packet recognized as QUIC Initial")
	}
	fakes := buildQUICDesyncPackets(qPkt)
	if len(fakes) != 2 || len(fakes[0]) < 128 || len(fakes[1]) != 64 {
		t.Fatalf("unexpected QUIC desync fake packets: len=%d", len(fakes))
	}
}

func TestPsiDPIAuto(t *testing.T) {
	var a psiDPIAuto
	for i, want := range []string{"", "hello"} {
		if m := a.next(); m != want {
			t.Fatalf("attempt %d: %q, want %q", i, m, want)
		}
	}
	a.good()
	if m := a.next(); m != "hello" {
		t.Fatalf("a mode that connected must be kept: %q", m)
	}
	if m := a.next(); m != "light" {
		t.Fatalf("after a failure: %q", m)
	}
}

// obfsTestServer: the first connection is handled by first (a DPI imitation),
// the others get "OK" after the whole ClientHello.
func obfsTestServer(t *testing.T, size int, first func(net.Conn)) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for i := 0; ; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if i == 0 {
				go first(c)
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4096)
				for got := 0; got < size; {
					n, err := c.Read(buf)
					got += n
					if err != nil {
						return
					}
				}
				_, _ = c.Write([]byte("OK"))
				time.Sleep(200 * time.Millisecond)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func obfsTestRescue(t *testing.T, first func(net.Conn)) {
	obfs.reset()
	t.Cleanup(obfs.reset)
	hello := obfsTestHello("blocked.example")
	addr := obfsTestServer(t, len(hello), first)
	c, err := dialObfs(context.Background(), "tcp", addr, "auto")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "OK" {
		t.Fatalf("read %q: %v", buf, err)
	}
	if v := obfs.view(); v["saved"].(int64) != 1 {
		t.Fatalf("saved = %v", v["saved"])
	}
}

func TestObfsResendAfterReset(t *testing.T) {
	obfsTestRescue(t, func(c net.Conn) {
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		_ = c.Close() // unread data: the peer gets a reset, like from DPI
	})
}

func TestObfsResendAfterSilence(t *testing.T) {
	old := obfsFirstByte
	obfsFirstByte = 300 * time.Millisecond
	t.Cleanup(func() { obfsFirstByte = old })
	obfsTestRescue(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c) // swallow everything, never answer
	})
}

// The split ClientHello written in two pieces must still be cut as a whole.
func TestObfsHelloInPieces(t *testing.T) {
	obfs.reset()
	t.Cleanup(obfs.reset)
	hello := obfsTestHello("pieces.example")
	addr := obfsTestServer(t, len(hello), func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		var got []byte
		for len(got) < len(hello) {
			n, err := c.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				return
			}
		}
		if bytes.Contains(got, hello[5:]) {
			return // the hello went out as one record: no answer
		}
		_, _ = c.Write([]byte("OK"))
		time.Sleep(200 * time.Millisecond)
	})
	c, err := dialObfs(context.Background(), "tcp", addr, "tlsrec")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(hello[:100]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(hello[100:]); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "OK" {
		t.Fatalf("read %q: %v", buf, err)
	}
}
