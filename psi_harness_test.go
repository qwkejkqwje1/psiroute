package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fake-network test harness (Step 0).
// Provides injectable per-carrier dialers and DNS resolvers that simulate
// hostile Russian network conditions strictly in-memory (no real sockets,
// no internet access, deterministic and -race safe).

var (
	errSimHostBlocked      = errors.New("simulated: list host blocked (connection refused)")
	errSimTCPReset         = errors.New("simulated: connection reset by peer after ClientHello")
	errSimUDPBlocked       = errors.New("simulated: udp packets dropped")
	errSimCarrierOffline   = errors.New("simulated: carrier unreachable (no network)")
	errSimUnknownCarrier   = errors.New("simulated: unknown carrier")
)

type fakeCarrierProfile struct {
	FailAll               bool
	BlockedHosts          map[string]bool
	ResetAfterClientHello bool
	AllowFragmentedHello  bool // when true, small fragmented ClientHello writes (<32 bytes) bypass RST
	StallAfterBytes       int  // if > 0, stalls reads/writes after this many bytes until deadline/close
	UDPBlocked            bool
	BaseRTT               time.Duration
	PayloadSize           int // bytes served by fake remote peer on successful TCP stream (default 128 KB)
}

type fakeDialRecord struct {
	Carrier string
	Network string
	Addr    string
	Err     string
}

type fakeNetworkHarness struct {
	mu          sync.Mutex
	carriers    map[string]*fakeCarrierProfile
	systemDNS   map[string][]string
	dohDNS      map[string][]string
	dials       []fakeDialRecord
}

func newFakeNetworkHarness() *fakeNetworkHarness {
	return &fakeNetworkHarness{
		carriers:  map[string]*fakeCarrierProfile{},
		systemDNS: map[string][]string{},
		dohDNS:    map[string][]string{},
	}
}

func (h *fakeNetworkHarness) SetCarrier(name string, p fakeCarrierProfile) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cp := p
	if p.BlockedHosts != nil {
		cp.BlockedHosts = make(map[string]bool, len(p.BlockedHosts))
		for k, v := range p.BlockedHosts {
			cp.BlockedHosts[strings.ToLower(k)] = v
		}
	}
	if cp.PayloadSize <= 0 {
		cp.PayloadSize = 128 << 10
	}
	h.carriers[name] = &cp
}

func (h *fakeNetworkHarness) SetDNS(host string, systemIPs, dohIPs []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := strings.ToLower(host)
	h.systemDNS[k] = append([]string(nil), systemIPs...)
	h.dohDNS[k] = append([]string(nil), dohIPs...)
}

func (h *fakeNetworkHarness) ResolveSystem(ctx context.Context, host string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	ips := h.systemDNS[strings.ToLower(host)]
	if len(ips) == 0 {
		return nil, errors.New("simulated: system dns nxdomain")
	}
	return append([]string(nil), ips...), nil
}

func (h *fakeNetworkHarness) ResolveDoH(ctx context.Context, host string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	ips := h.dohDNS[strings.ToLower(host)]
	if len(ips) == 0 {
		return nil, errors.New("simulated: doh dns nxdomain")
	}
	return append([]string(nil), ips...), nil
}

func (h *fakeNetworkHarness) DialRecords() []fakeDialRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]fakeDialRecord, len(h.dials))
	copy(out, h.dials)
	return out
}

func (h *fakeNetworkHarness) recordDial(carrier, network, addr string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := fakeDialRecord{Carrier: carrier, Network: network, Addr: addr}
	if err != nil {
		rec.Err = err.Error()
	}
	h.dials = append(h.dials, rec)
}

// DialContext returns an injectable net dialer for the named carrier.
func (h *fakeNetworkHarness) DialContext(carrier string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		h.mu.Lock()
		prof, ok := h.carriers[carrier]
		var cp fakeCarrierProfile
		if ok {
			cp = *prof
		}
		h.mu.Unlock()

		if !ok {
			h.recordDial(carrier, network, addr, errSimUnknownCarrier)
			return nil, errSimUnknownCarrier
		}
		if cp.FailAll {
			h.recordDial(carrier, network, addr, errSimCarrierOffline)
			return nil, errSimCarrierOffline
		}
		if strings.HasPrefix(strings.ToLower(network), "udp") && cp.UDPBlocked {
			h.recordDial(carrier, network, addr, errSimUDPBlocked)
			return nil, errSimUDPBlocked
		}
		host := addr
		if hPart, _, err := net.SplitHostPort(addr); err == nil {
			host = hPart
		}
		if cp.BlockedHosts[strings.ToLower(host)] || cp.BlockedHosts[strings.ToLower(addr)] {
			h.recordDial(carrier, network, addr, errSimHostBlocked)
			return nil, errSimHostBlocked
		}
		if cp.BaseRTT > 0 {
			timer := time.NewTimer(cp.BaseRTT)
			select {
			case <-ctx.Done():
				timer.Stop()
				h.recordDial(carrier, network, addr, ctx.Err())
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		clientConn, serverConn := net.Pipe()
		go serveFakePeer(serverConn, cp)
		h.recordDial(carrier, network, addr, nil)
		return clientConn, nil
	}
}

// serveFakePeer simulates server-side DPI/TSPU behavior over an in-memory pipe.
func serveFakePeer(conn net.Conn, prof fakeCarrierProfile) {
	defer conn.Close()

	// Wait briefly for initial client payload (e.g., TLS ClientHello or HTTP GET).
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	first := buf[:n]

	// Simulate DPI RST when an unfragmented TLS ClientHello (0x16 0x03 ...) arrives.
	if prof.ResetAfterClientHello && len(first) >= 2 && first[0] == 0x16 && first[1] == 0x03 {
		if !(prof.AllowFragmentedHello && len(first) < 32) {
			// Immediately drop the pipe without responding (triggers EOF/reset on reader).
			return
		}
		// Fragmented ClientHello allowed: drain second fragment if sent.
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = conn.Read(buf)
	}

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	total := prof.PayloadSize
	if total <= 0 {
		total = 128 << 10
	}
	chunk := bytes.Repeat([]byte("A"), 4096)
	sent := 0
	for sent < total {
		toWrite := min(len(chunk), total-sent)
		if prof.StallAfterBytes > 0 && sent >= prof.StallAfterBytes {
			// Hold connection open without sending any more bytes until peer closes or times out.
			_ = conn.SetReadDeadline(time.Time{})
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		if prof.StallAfterBytes > 0 && sent+toWrite > prof.StallAfterBytes {
			toWrite = prof.StallAfterBytes - sent
		}
		w, werr := conn.Write(chunk[:toWrite])
		if werr != nil {
			return
		}
		sent += w
	}
}

// probeTransfer64KB is a harness helper that sends a request and verifies >= 64 KB
// can be read before timeout (detecting the ~16 KB stall).
func probeTransfer64KB(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), addr string, payload []byte) (int, error) {
	c, err := dial(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if len(payload) > 0 {
		if _, err := c.Write(payload); err != nil {
			return 0, err
		}
	}
	const want = 64 << 10
	n, err := io.CopyN(io.Discard, c, want)
	if err != nil {
		return int(n), err
	}
	return int(n), nil
}

// ---- 10 Offline Scenario Tests (Step 0) ----

func TestHarnessScenario_BlockedListHost(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetCarrier(carrierDirect, fakeCarrierProfile{
		BlockedHosts: map[string]bool{"s3.amazonaws.com": true},
	})
	h.SetCarrier(carrierWARP, fakeCarrierProfile{PayloadSize: 64 << 10})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := h.DialContext(carrierDirect)(ctx, "tcp", "s3.amazonaws.com:443"); !errors.Is(err, errSimHostBlocked) {
		t.Fatalf("direct list host err = %v, want errSimHostBlocked", err)
	}
	n, err := probeTransfer64KB(ctx, h.DialContext(carrierWARP), "s3.amazonaws.com:443", []byte("GET /list HTTP/1.1\r\n\r\n"))
	if err != nil || n < 64<<10 {
		t.Fatalf("warp list host transfer: n=%d err=%v, want >= 64KB", n, err)
	}
}

func TestHarnessScenario_PoisonedSystemDNSVsDoH(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetDNS("s3.amazonaws.com", []string{"10.10.34.35"}, []string{"52.216.10.1"})

	ctx := context.Background()
	sysIPs, err := h.ResolveSystem(ctx, "s3.amazonaws.com")
	if err != nil {
		t.Fatalf("ResolveSystem: %v", err)
	}
	dohIPs, err := h.ResolveDoH(ctx, "s3.amazonaws.com")
	if err != nil {
		t.Fatalf("ResolveDoH: %v", err)
	}
	if sysIPs[0] == dohIPs[0] {
		t.Fatalf("expected poisoned system DNS (%v) to differ from DoH (%v)", sysIPs, dohIPs)
	}
	if sysIPs[0] != "10.10.34.35" || dohIPs[0] != "52.216.10.1" {
		t.Fatalf("unexpected DNS answers: sys=%v doh=%v", sysIPs, dohIPs)
	}
}

func TestHarnessScenario_TCPResetAfterClientHello(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetCarrier(carrierDirect, fakeCarrierProfile{
		ResetAfterClientHello: true,
		AllowFragmentedHello:  false,
	})
	h.SetCarrier(carrierDirectDPI, fakeCarrierProfile{
		ResetAfterClientHello: true,
		AllowFragmentedHello:  true,
		PayloadSize:           64 << 10,
	})

	// Synthetic TLS 1.2 ClientHello header (64 bytes, unfragmented).
	hello := append([]byte{0x16, 0x03, 0x01, 0x00, 0x3c}, bytes.Repeat([]byte{0x01}, 60)...)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Unfragmented write on direct carrier must fail immediately (EOF/reset).
	if n, err := probeTransfer64KB(ctx, h.DialContext(carrierDirect), "front.example.net:443", hello); err == nil || n > 0 {
		t.Fatalf("direct unfragmented ClientHello should fail, got n=%d err=%v", n, err)
	}

	// Fragmented write (<32 bytes first chunk) on direct+dpi carrier must succeed.
	c, err := h.DialContext(carrierDirectDPI)(ctx, "tcp", "front.example.net:443")
	if err != nil {
		t.Fatalf("direct+dpi dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(hello[:5]); err != nil {
		t.Fatalf("fragment 1 write: %v", err)
	}
	if _, err := c.Write(hello[5:]); err != nil {
		t.Fatalf("fragment 2 write: %v", err)
	}
	n, err := io.CopyN(io.Discard, c, 64<<10)
	if err != nil || n != 64<<10 {
		t.Fatalf("direct+dpi fragmented read: n=%d err=%v, want 64KB", n, err)
	}
}

func TestHarnessScenario_StallAfter16KB(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetCarrier(carrierWARP, fakeCarrierProfile{
		StallAfterBytes: 16 << 10,
		PayloadSize:     128 << 10,
	})

	// Small 4 KB read succeeds (would fool a tiny ping).
	ctxSmall, cancelSmall := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelSmall()
	cSmall, err := h.DialContext(carrierWARP)(ctxSmall, "tcp", "speed.cloudflare.com:443")
	if err != nil {
		t.Fatalf("small dial: %v", err)
	}
	_ = cSmall.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = cSmall.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	if n, err := io.CopyN(io.Discard, cSmall, 4<<10); err != nil || n != 4<<10 {
		_ = cSmall.Close()
		t.Fatalf("4KB read should succeed before 16KB stall, got n=%d err=%v", n, err)
	}
	_ = cSmall.Close()

	// 64 KB probe must detect the stall at 16 KB and fail on deadline.
	ctx64, cancel64 := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel64()
	n, err := probeTransfer64KB(ctx64, h.DialContext(carrierWARP), "speed.cloudflare.com:443", []byte("GET / HTTP/1.1\r\n\r\n"))
	if err == nil {
		t.Fatalf("expected 64KB probe to fail on 16KB stall, got n=%d err=nil", n)
	}
	if n != 16<<10 {
		t.Fatalf("expected stall exactly at 16KB (16384 bytes), got %d bytes (err=%v)", n, err)
	}
}

func TestHarnessScenario_UDPBlocked(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetCarrier(carrierDirect, fakeCarrierProfile{
		UDPBlocked:  true,
		PayloadSize: 64 << 10,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := h.DialContext(carrierDirect)(ctx, "udp", "162.159.192.1:2408"); !errors.Is(err, errSimUDPBlocked) {
		t.Fatalf("udp dial err = %v, want errSimUDPBlocked", err)
	}
	if n, err := probeTransfer64KB(ctx, h.DialContext(carrierDirect), "162.159.192.1:443", []byte("hello")); err != nil || n != 64<<10 {
		t.Fatalf("tcp dial on udp-blocked carrier: n=%d err=%v, want 64KB", n, err)
	}
}

func TestHarnessScenario_SlowRTTAndContextTimeout(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetCarrier(carrierProxy, fakeCarrierProfile{
		BaseRTT:     60 * time.Millisecond,
		PayloadSize: 64 << 10,
	})

	// Tight budget (< RTT) must fail with context.DeadlineExceeded.
	shortCtx, cancelShort := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancelShort()
	if _, err := h.DialContext(carrierProxy)(shortCtx, "tcp", "example.com:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("short budget err = %v, want DeadlineExceeded", err)
	}

	// Patient budget (> RTT) must succeed.
	longCtx, cancelLong := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelLong()
	if n, err := probeTransfer64KB(longCtx, h.DialContext(carrierProxy), "example.com:443", []byte("GET / HTTP/1.1\r\n\r\n")); err != nil || n != 64<<10 {
		t.Fatalf("patient budget transfer: n=%d err=%v, want 64KB", n, err)
	}
}

func TestHarnessScenario_TotalNetworkOutage(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetCarrier(carrierDirect, fakeCarrierProfile{FailAll: true})

	a := testApp(t)
	p := a.psi
	p.directAliveFunc = func(ctx context.Context) bool {
		c, err := h.DialContext(carrierDirect)(ctx, "tcp", "1.1.1.1:443")
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}

	code, _, _ := p.classifyFailure(context.Background(), psiStrategies[0], errTimeout)
	if code != "no_network" {
		t.Fatalf("classifyFailure under outage = %q, want no_network", code)
	}
}

func TestHarnessScenario_HealthyMultiCarrierFallback(t *testing.T) {
	h := newFakeNetworkHarness()
	h.SetCarrier(carrierDirect, fakeCarrierProfile{BlockedHosts: map[string]bool{"target.example:443": true}})
	h.SetCarrier(carrierWARP, fakeCarrierProfile{StallAfterBytes: 16 << 10})
	h.SetCarrier(carrierWorker, fakeCarrierProfile{PayloadSize: 64 << 10})

	order := []string{carrierDirect, carrierWARP, carrierWorker}
	winner := ""
	for _, carrier := range order {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
		n, err := probeTransfer64KB(ctx, h.DialContext(carrier), "target.example:443", []byte("GET / HTTP/1.1\r\n\r\n"))
		cancel()
		if err == nil && n >= 64<<10 {
			winner = carrier
			break
		}
	}
	if winner != carrierWorker {
		t.Fatalf("multi-carrier fallback winner = %q, want %q (dials=%+v)", winner, carrierWorker, h.DialRecords())
	}
}

func TestTimeline_RecordingCountersAndRingBound(t *testing.T) {
	tl := newConnTimeline(4)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tl.RecordAttempt(carrierDirectDPI, []string{"TLS-OSSH"})
			tl.Record(connTimelineEvent{
				Stage:      "attempt_start",
				Carrier:    carrierDirectDPI,
				StrategyID: "direct-dpi",
				Protocols:  []string{"TLS-OSSH"},
				Attempt:    idx + 1,
				Outcome:    "info",
			})
		}(i)
	}
	wg.Wait()

	tl.RecordConnect(carrierDirectDPI, "TLS-OSSH", 1200)
	tl.RecordConnect(carrierDirectDPI, "TLS-OSSH", 1800)
	tl.RecordConnect(carrierDirectDPI, "TLS-OSSH", 1500)
	tl.RecordHold(45 * time.Second)
	tl.RecordStall16KB()

	events := tl.Events()
	if len(events) != 4 {
		t.Fatalf("ring buffer len = %d, want 4", len(events))
	}
	if events[0].Seq != 7 || events[3].Seq != 10 {
		t.Fatalf("unexpected ring sequence bounds: first=%d last=%d", events[0].Seq, events[3].Seq)
	}
	c := tl.Counters()
	if c.AttemptsByCarrier[carrierDirectDPI] != 10 {
		t.Fatalf("AttemptsByCarrier = %d, want 10", c.AttemptsByCarrier[carrierDirectDPI])
	}
	if c.SuccessesByCarrier[carrierDirectDPI] != 3 {
		t.Fatalf("SuccessesByCarrier = %d, want 3", c.SuccessesByCarrier[carrierDirectDPI])
	}
	if c.MedianConnectMs != 1500 {
		t.Fatalf("MedianConnectMs = %d, want 1500", c.MedianConnectMs)
	}
	if c.TotalHoldSec != 45 || c.Stall16KBEvents != 1 {
		t.Fatalf("hold=%d stall=%d, want 45 and 1", c.TotalHoldSec, c.Stall16KBEvents)
	}
}

func TestTimeline_SecretMaskingInEventsAndReport(t *testing.T) {
	a := testApp(t)
	p := a.psi

	rawSecretDetail := "proxy socks5://alice:supersecret@10.0.0.1:1080 failed uuid 123e4567-e89b-12d3-a456-426614174000 token=mySecretToken99 entry=" + strings.Repeat("ab", 24)
	p.tl().Record(connTimelineEvent{
		Stage:   "attempt_end",
		Carrier: carrierProxy,
		Outcome: "failed",
		Detail:  rawSecretDetail,
	})

	events := p.tl().Events()
	if len(events) == 0 {
		t.Fatal("expected at least 1 timeline event")
	}
	got := events[len(events)-1].Detail
	for _, forbidden := range []string{"supersecret", "123e4567-e89b-12d3-a456-426614174000", "mySecretToken99", strings.Repeat("ab", 24)} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("timeline detail leaked secret %q: %s", forbidden, got)
		}
	}

	// Verify timeline & counters appear in statsView and reportState without leaking secrets.
	sv := p.statsView()
	if _, ok := sv["timeline"]; !ok {
		t.Fatal("statsView missing timeline key")
	}
	if _, ok := sv["timeline_counters"]; !ok {
		t.Fatal("statsView missing timeline_counters key")
	}
	repBytes := a.reportState()
	if strings.Contains(string(repBytes), "supersecret") {
		t.Fatalf("reportState leaked secret: %s", string(repBytes))
	}
	var rep map[string]any
	if err := json.Unmarshal(repBytes, &rep); err != nil {
		t.Fatalf("reportState invalid JSON: %v", err)
	}
	if _, ok := rep["psiphon_timeline"]; !ok {
		t.Fatal("reportState missing psiphon_timeline key")
	}
	if _, ok := rep["psiphon_counters"]; !ok {
		t.Fatal("reportState missing psiphon_counters key")
	}
}
