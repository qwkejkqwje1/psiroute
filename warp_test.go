package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

type fakeBind struct{ sent [][]byte }

func (f *fakeBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		sizes[0] = copy(bufs[0], []byte{4, 7, 7, 7, 1, 2, 3, 4})
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, 2408, nil
}
func (f *fakeBind) Close() error                                { return nil }
func (f *fakeBind) SetMark(uint32) error                        { return nil }
func (f *fakeBind) ParseEndpoint(string) (conn.Endpoint, error) { return nil, nil }
func (f *fakeBind) BatchSize() int                              { return 1 }
func (f *fakeBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, b := range bufs {
		f.sent = append(f.sent, append([]byte(nil), b...))
	}
	return nil
}

func TestWarpSignature(t *testing.T) {
	parts, err := parseWarpSig("<b 0x0102ff><r 5> <rc 3><rd 2><t><c>")
	if err != nil {
		t.Fatal(err)
	}
	p := buildWarpSig(parts, 7)
	if len(p) != 3+5+3+2+4+4 || !bytes.HasPrefix(p, []byte{1, 2, 0xff}) || p[len(p)-1] != 7 {
		t.Fatalf("packet = %x", p)
	}
	for _, c := range p[8:11] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			t.Errorf("<rc> gave %q", p[8:11])
		}
	}
	for _, c := range p[11:13] {
		if c < '0' || c > '9' {
			t.Errorf("<rd> gave %q", p[11:13])
		}
	}
	for _, bad := range []string{"<x 1>", "<b zz>", "<r 99999>", "<r>", "b 0x01", "<b 0x01", "<>"} {
		if _, err := parseWarpSig(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWarpMasks(t *testing.T) {
	for _, id := range warpMaskOrder {
		m, err := makeWarpMask(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if m.Title == "" || (id == "off") != (m.I1 == "") {
			t.Errorf("%s: %+v", id, m)
		}
		if m.I1 == "" {
			continue
		}
		for stepIdx, rawSig := range []string{m.I1, m.I2, m.I3, m.I4, m.I5} {
			if rawSig == "" {
				t.Errorf("%s: missing I%d signature in chain", id, stepIdx+1)
				continue
			}
			parts, err := parseWarpSig(rawSig)
			if err != nil {
				t.Fatalf("%s I%d: %v", id, stepIdx+1, err)
			}
			p := buildWarpSig(parts, uint32(stepIdx+1))
			if len(p) == 0 || len(p) > 2000 {
				t.Errorf("%s I%d: %d bytes", id, stepIdx+1, len(p))
			}
			if stepIdx == 0 && (id == "quic" || id == "masque") && (len(p) < 1200 || p[0]&0xc0 != 0xc0) {
				t.Errorf("%s I1: %d bytes, first byte %#x", id, len(p), p[0])
			}
		}
	}
	if _, err := makeWarpMask("nope"); err == nil {
		t.Error("unknown masking accepted")
	}
}

func TestWarpBind(t *testing.T) {
	fb := &fakeBind{}
	sig, _ := parseWarpSig("<b 0xaabb>")
	b := &warpBind{Bind: fb, reserved: [3]byte{1, 2, 3}, jc: 3, jmin: 10, jmax: 20, i1: sig}
	hello := make([]byte, device.MessageInitiationSize)
	hello[0] = 1
	if err := b.Send([][]byte{hello}, nil); err != nil {
		t.Fatal(err)
	}
	if len(fb.sent) != 5 || !bytes.Equal(fb.sent[0], []byte{0xaa, 0xbb}) {
		t.Fatalf("sent %d packets, first %x", len(fb.sent), fb.sent[0])
	}
	for _, j := range fb.sent[1:4] {
		if len(j) < 10 || len(j) > 20 {
			t.Errorf("junk of %d bytes", len(j))
		}
	}
	if h := fb.sent[4]; len(h) != device.MessageInitiationSize || !bytes.Equal(h[:4], []byte{1, 1, 2, 3}) {
		t.Errorf("initiation header %x", h[:4])
	}
	fb.sent = nil
	data := make([]byte, 64)
	data[0] = 4
	_ = b.Send([][]byte{data}, nil)
	if len(fb.sent) != 1 || !bytes.Equal(fb.sent[0][:4], []byte{4, 1, 2, 3}) {
		t.Errorf("data packet: %d sent", len(fb.sent))
	}
	fns, port, err := b.Open(0)
	if err != nil || port != 2408 || len(fns) != 1 {
		t.Fatal(err, port, len(fns))
	}
	bufs, sizes := [][]byte{make([]byte, 64)}, []int{0}
	if n, err := fns[0](bufs, sizes, make([]conn.Endpoint, 1)); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	if got := bufs[0][:sizes[0]]; !bytes.Equal(got, []byte{4, 0, 0, 0, 1, 2, 3, 4}) {
		t.Errorf("received %x: reserved bytes not cleared", got)
	}
}

func TestWarpCleanIPScannerAndI1ToI5Bind(t *testing.T) {
	theWarpScanner.reset()
	t.Cleanup(theWarpScanner.reset)

	// 1. Test full I1..I5 chain in warpBind preamble
	fb := &fakeBind{}
	m, err := makeWarpMask("masque")
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := parseWarpSig(m.I1)
	s2, _ := parseWarpSig(m.I2)
	s3, _ := parseWarpSig(m.I3)
	s4, _ := parseWarpSig(m.I4)
	s5, _ := parseWarpSig(m.I5)
	wb := &warpBind{
		Bind: fb, reserved: [3]byte{9, 8, 7},
		i1: s1, i2: s2, i3: s3, i4: s4, i5: s5,
		jc: 2, jmin: 16, jmax: 32,
	}
	initPkt := make([]byte, device.MessageInitiationSize)
	initPkt[0] = 1
	if err := wb.Send([][]byte{initPkt}, nil); err != nil {
		t.Fatal(err)
	}
	// Expect 5 signature packets (I1..I5) + 2 junk packets + 1 WG initiation = 8 packets
	if len(fb.sent) != 8 {
		t.Fatalf("expected 8 packets with I1..I5 + 2 junk + 1 init, got %d", len(fb.sent))
	}

	// 2. Test Cloudflare Clean IP Auto-Scanner sorting and candidate injection
	theWarpScanner.mu.Lock()
	theWarpScanner.probeFunc = func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
		switch addr {
		case "162.159.204.10:443":
			return 18 * time.Millisecond, nil
		case "188.114.97.42:2408":
			return 45 * time.Millisecond, nil
		default:
			return 0, errors.New("timeout")
		}
	}
	theWarpScanner.mu.Unlock()
	defer func() {
		theWarpScanner.mu.Lock()
		theWarpScanner.probeFunc = nil
		theWarpScanner.mu.Unlock()
	}()

	targets := []string{"162.159.192.99:2408", "188.114.97.42:2408", "162.159.204.10:443"}
	found := theWarpScanner.Scan(context.Background(), targets, 4, 200*time.Millisecond)
	if len(found) != 2 || found[0].Endpoint != "162.159.204.10:443" || found[1].Endpoint != "188.114.97.42:2408" {
		t.Fatalf("unexpected scanner results: %+v", found)
	}

	cands := warpCandidates(&warpIdentity{Endpoint: "162.159.195.7:500", Colo: "FRA"}, "")
	if cands[0] != "162.159.195.7:500" || cands[1] != "162.159.192.1:2408" || cands[2] != "162.159.204.10:443" || cands[3] != "188.114.97.42:2408" {
		t.Fatalf("clean IPs not prioritized in warpCandidates: %v", cands[:6])
	}
}

func TestWarpCandidatesAndNodes(t *testing.T) {
	theWarpScanner.reset()
	if warpNodeOK("DME") || warpNodeOK("msq") || !warpNodeOK("FRA") || !warpNodeOK("") {
		t.Error("node policy")
	}
	id := &warpIdentity{Endpoint: "162.159.195.7:500", Colo: "FRA"}
	c := warpCandidates(id, "")
	if len(c) < 24 || c[0] != id.Endpoint || c[1] != "162.159.192.1:2408" {
		t.Fatalf("candidates %v", c)
	}
	seen := map[string]bool{}
	for _, ep := range c {
		if _, err := netip.ParseAddrPort(ep); err != nil || seen[ep] {
			t.Errorf("bad or repeated endpoint %q", ep)
		}
		seen[ep] = true
	}
	id.Colo = "DME" // the last endpoint led to a filtered node
	if c := warpCandidates(id, ""); c[0] == id.Endpoint {
		t.Error("endpoint of a filtered node tried first")
	}
	if c := warpCandidates(id, "1.2.3.4:500"); len(c) != 1 || c[0] != "1.2.3.4:500" {
		t.Errorf("fixed endpoint: %v", c)
	}
	if c := warpCandidates(id, "1.2.3.4"); len(c) != 1 || c[0] != "1.2.3.4:2408" {
		t.Errorf("endpoint without a port: %v", c)
	}
}

func TestWarpSOCKSAndIdle(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := NewApp(ctx, cancel, filepath.Join(dir, "psiroute.json"), dir)
	w := a.warp
	defer w.Close()
	if v := w.view(); v["state"] != "off" || w.wanted() {
		t.Errorf("WARP off: view %v, wanted %v", v, w.wanted())
	}
	if _, err := w.Dial(ctx, "tcp", "example.com:443"); err == nil {
		t.Error("dial through a disabled WARP succeeded")
	}
	var asked atomic.Value
	w.testDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		asked.Store(addr)
		return (&net.Dialer{}).DialContext(ctx, "tcp", echo.Addr().String())
	}
	c, err := dialSocks5(ctx, w.Addr(), "example.com:443", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q %v", buf, err)
	}
	if got, _ := asked.Load().(string); got != "example.com:443" {
		t.Errorf("dialed %q", got)
	}
	if n := w.active.Load(); n != 1 {
		t.Errorf("active = %d", n)
	}
	c.Close()
	for i := 0; i < 100 && w.active.Load() != 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if n := w.active.Load(); n != 0 {
		t.Errorf("active after close = %d", n)
	}
	a.cfg.mu.Lock()
	a.cfg.Warp.Enabled = true
	a.cfg.mu.Unlock()
	if !w.wanted() {
		t.Error("used a moment ago but not wanted")
	}
	w.lastUse.Store(time.Now().Add(-warpIdle - time.Minute).UnixNano())
	if w.wanted() {
		t.Error("idle tunnel still wanted")
	}
	if v := w.view(); v["state"] != "idle" || !strings.Contains(v["text"].(string), "Через WARP") {
		t.Errorf("view: %v", v)
	}
	a.cfg.mu.Lock()
	a.cfg.Warp.Engine = "socks"
	a.cfg.mu.Unlock()
	if v := w.view(); v["state"] != "external" || w.builtin() {
		t.Errorf("external engine: %v", v)
	}
}

func TestPsiOrderUnstableDebounce(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := NewApp(ctx, cancel, filepath.Join(dir, "psiroute.json"), dir)
	p := a.psi
	byID := map[string]strategyDef{}
	for _, s := range psiStrategies {
		byID[s.ID] = s
	}
	list := []strategyDef{byID["quic"], byID["auto"], byID["meek"], byID["tls"]}
	ids := func(l []strategyDef) string {
		var out []string
		for _, s := range l {
			out = append(out, s.ID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(p.order(list, "tls")); got != "tls,quic,auto,meek" {
		t.Errorf("remembered method first: %s", got)
	}
	p.markUnstable("quic", true)
	if got := ids(p.order(list, "")); got != "auto,meek,tls,quic" {
		t.Errorf("unstable method last: %s", got)
	}
	if got := ids(p.order(list, "quic")); got != "auto,meek,tls,quic" {
		t.Errorf("unstable method stays last even if remembered: %s", got)
	}
	if !newPsi(a, dir).isUnstable("quic") {
		t.Error("unstable mark not saved")
	}
	p.markUnstable("quic", false)
	if p.isUnstable("quic") || newPsi(a, dir).isUnstable("quic") {
		t.Error("unstable mark not cleared")
	}
	if ids(list) != "quic,auto,meek,tls" {
		t.Error("order changed its input")
	}
	for round, want := range []int{35, 75, 150, 150} {
		if got := attemptTimeout(round); got != want {
			t.Errorf("round %d: %d s, want %d", round, got, want)
		}
	}
	if p.Next() != 0 {
		t.Error("press ignored while the engine is stopped")
	}
	p.mu.Lock()
	p.cancel = func() {}
	p.attemptAt = time.Now()
	p.mu.Unlock()
	if left := p.NewNode(); left < 1 || left > int(cmdGap/time.Second) {
		t.Errorf("press right after the attempt started: wait %d", left)
	}
	p.mu.Lock()
	p.attemptAt, p.cmdAt = time.Now().Add(-time.Minute), time.Time{}
	p.mu.Unlock()
	if p.NewNode() != 0 {
		t.Error("press a minute into the attempt ignored")
	}
	if p.Next() == 0 {
		t.Error("second press right away passed on")
	}
	p.mu.Lock()
	p.cancel = nil
	p.mu.Unlock()
}

func TestWarpSettingsKeys(t *testing.T) {
	c := defaultConfig()
	if c.Warp.Engine != "builtin" || c.Warp.Mask != "auto" || c.Psiphon.Strategies[0] != "via-warp" {
		t.Fatalf("defaults: %+v %v", c.Warp, c.Psiphon.Strategies)
	}
	c.Psiphon.Strategies = []string{"quic", "auto"}
	c.setKey("warp.enabled", true)
	c.setKey("warp.enabled", true)
	if got := strings.Join(c.Psiphon.Strategies, ","); got != "quic,auto,via-warp" {
		t.Errorf("turning WARP on: %s", got)
	}
	c.setKey("warp.mask", "bwg")
	c.setKey("warp.endpoint", " 162.159.192.9:500 ")
	if !c.setKey("warp.engine", "socks") {
		t.Error("changing the WARP engine needs a restart")
	}
	v := c.values()
	if v["warp.mask"] != "bwg" || v["warp.endpoint"] != "162.159.192.9:500" || v["warp.engine"] != "socks" {
		t.Errorf("values: %v %v %v", v["warp.mask"], v["warp.endpoint"], v["warp.engine"])
	}
}

func TestWarpScanRejectsCancelledResults(t *testing.T) {
	var scanner warpCleanScanner
	ctx, cancel := context.WithCancel(context.Background())
	got := scanner.scanWithProbe(ctx, []string{"a", "b"}, 1, time.Second, func(context.Context, string, time.Duration) (time.Duration, error) {
		cancel()
		return time.Millisecond, nil
	})
	if len(got) != 0 || len(scanner.cachedEndpoints()) != 0 {
		t.Fatal("cancelled scan published results")
	}
}
func TestWarpScanRequiresAuthenticatedProbe(t *testing.T) {
	var scanner warpCleanScanner
	if got := scanner.Scan(context.Background(), []string{"127.0.0.1:1"}, 1, time.Millisecond); len(got) != 0 {
		t.Fatal("scan without identity/probe accepted endpoint")
	}
}
