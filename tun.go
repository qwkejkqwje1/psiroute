package main

// TUN mode: a Wintun virtual adapter takes the whole system traffic
// (games, Discord voice, launchers - everything that ignores the system
// proxy). Packets go into a gvisor user-space TCP/IP stack; every TCP and UDP
// flow is then routed by the usual Psiroute rules (direct, DPI bypass,
// Psiphon, WARP). Supports FakeIP (198.18.0.0/15) for 100% domain attribution,
// plus dynamic MTU and TCP MSS clamping for the TUN -> WARP -> Psiphon cascade.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// tunDevice is satisfied by golang.zx2c4.com/wireguard/tun.Device.
type tunDevice interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	BatchSize() int
	Close() error
}

// tunCtl is embedded in App; the zero value is "off".
type tunCtl struct {
	mu      sync.Mutex
	eng     *tunEngine
	busy    bool
	stopReq bool
	state   string
	err     string
	flows   atomic.Int64
	total   atomic.Int64
}

func (t *tunCtl) start(a *App) error {
	t.mu.Lock()
	if t.eng != nil || t.busy {
		t.mu.Unlock()
		return nil
	}
	if !tunSupported {
		t.state, t.err = "error", errTunUnsupported.Error()
		t.mu.Unlock()
		return errTunUnsupported
	}
	if !isElevated() {
		t.state, t.err = "error", errNeedAdmin.Error()
		t.mu.Unlock()
		return errNeedAdmin
	}
	t.busy, t.stopReq, t.state, t.err = true, false, "starting", ""
	t.mu.Unlock()

	e, err := newTunEngine(a, t)

	t.mu.Lock()
	defer t.mu.Unlock()
	t.busy = false
	if err != nil {
		t.state, t.err = "error", err.Error()
		return err
	}
	if t.stopReq || a.ctx.Err() != nil {
		t.stopReq, t.state = false, "off"
		go e.close()
		return nil
	}
	t.eng, t.state = e, "on"
	logf("info", "Режим TUN включён: весь трафик компьютера идёт через Psiroute (выход: %s, MTU=%d, MSS=%d)",
		tunPhysText(), e.curMTU.Load(), e.mss4.Load())
	return nil
}

func (t *tunCtl) stop() {
	t.mu.Lock()
	e := t.eng
	t.eng = nil
	if t.busy {
		t.stopReq = true
	} else {
		t.state, t.err = "off", ""
	}
	t.mu.Unlock()
	if e != nil {
		e.close()
		logf("info", "Режим TUN выключен")
	}
}

func (t *tunCtl) fail(e *tunEngine, msg string) {
	t.mu.Lock()
	if t.eng != e {
		t.mu.Unlock()
		return
	}
	t.eng, t.state, t.err = nil, "error", msg
	t.mu.Unlock()
	e.close()
	logf("warn", "Режим TUN остановлен: %s", msg)
}

// refresh re-detects the real adapter and recalculates dynamic MTU/MSS after a network or tunnel change.
func (t *tunCtl) refresh() {
	t.mu.Lock()
	e := t.eng
	t.mu.Unlock()
	if e != nil {
		_ = refreshPhys()
		e.syncDynamicMTU()
	}
}

func (t *tunCtl) view() map[string]any {
	t.mu.Lock()
	e, state, errS := t.eng, t.state, t.err
	t.mu.Unlock()
	on := e != nil
	if state == "" {
		state = "off"
	}
	admin := isElevated()
	needAdmin := errS == errNeedAdmin.Error()
	effMTU, mss4, mss6 := int32(0), uint32(0), uint32(0)
	clamped := int64(0)
	if e != nil {
		effMTU = e.curMTU.Load()
		mss4 = e.mss4.Load()
		mss6 = e.mss6.Load()
		clamped = e.clampedPkts.Load()
	}
	var text string
	switch {
	case !tunSupported:
		text = "только для Windows"
	case on:
		text = fmt.Sprintf("работает · соединений сейчас: %d · MTU %d / MSS %d · выход в сеть: %s",
			t.flows.Load(), effMTU, mss4, tunPhysText())
	case state == "starting":
		text = "запускается…"
	case needAdmin && !admin:
		text = "нужны права администратора"
	case state == "error":
		text = "ошибка: " + errS
	default:
		text = "выключен"
	}
	return map[string]any{
		"on": on, "state": state, "error": errS, "text": text,
		"admin": admin, "need_admin": needAdmin && !admin,
		"flows": t.flows.Load(), "total": t.total.Load(), "supported": tunSupported,
		"fakeip_count": theFakeIP.count(),
		"effective_mtu": effMTU, "tcp_mss": mss4, "tcp_mss6": mss6, "mss_clamped": clamped,
	}
}

// ---------- App glue ----------

func (c *Config) tunWanted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Tun.Enabled
}

func (c *Config) tunOpts() (dns bool, fakeIP bool, exclude []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Tun.DNS, c.Tun.FakeIP, append([]string(nil), c.Tun.Exclude...)
}

func (a *App) setTun(on bool) error {
	a.cfg.setKey("tun.enabled", on)
	_ = a.cfg.save()
	if !on {
		a.tun.stop()
		return nil
	}
	err := a.tun.start(a)
	if err != nil && !errors.Is(err, errNeedAdmin) {
		a.cfg.setKey("tun.enabled", false)
		_ = a.cfg.save()
	}
	return err
}

// relaunchForTun starts an elevated copy (UAC prompt) that waits for this
// one to exit; the caller then quits normally.
func (a *App) relaunchForTun() error {
	a.cfg.setKey("tun.enabled", true)
	_ = a.cfg.save()
	pid := os.Getpid()
	if watchdogPID > 0 {
		pid = int(watchdogPID)
	}
	if err := relaunchElevated(pid); err != nil {
		return err
	}
	logf("info", "Перезапускаю Psiroute с правами администратора для режима TUN")
	return nil
}

// ---------- engine ----------

type tunEngine struct {
	a           *App
	ctl         *tunCtl
	dev         tunDevice
	s           *stack.Stack
	ep          *channel.Endpoint
	ctx         context.Context
	cancel      context.CancelFunc
	mtu         int
	curMTU      atomic.Int32
	mss4        atomic.Uint32
	mss6        atomic.Uint32
	clampedPkts atomic.Int64
	v6          bool
	rev         revMap
	dnsPsi      atomic.Bool // last working DoH path was Psiphon
	once        sync.Once
}

func (e *tunEngine) cascadeState() (cfgMTU int, warpCascade, psiActive bool) {
	if e.a == nil || e.a.cfg == nil {
		return e.mtu, false, false
	}
	e.a.cfg.mu.Lock()
	cfgMTU = e.a.cfg.Tun.MTU
	warpEnabled := e.a.cfg.Warp.Enabled
	e.a.cfg.mu.Unlock()
	if cfgMTU < tunMinMTU || cfgMTU > tunMaxMTU {
		cfgMTU = tunDefaultMTU
	}
	psiActive = e.a.psi != nil && (e.a.psi.running() || e.a.psi.cur.Load() != nil)
	warpCascade = warpEnabled || (e.a.warp != nil && e.a.warp.connected())
	if e.a.psi != nil {
		e.a.psi.mu.Lock()
		if e.a.psi.strategy.Transport == "warp" {
			warpCascade = true
		}
		e.a.psi.mu.Unlock()
	}
	return cfgMTU, warpCascade, psiActive
}

// syncDynamicMTU recalculates the effective MTU and TCP MSS ceiling for the
// active cascade (TUN -> WARP -> Psiphon) and updates the Wintun adapter if needed.
func (e *tunEngine) syncDynamicMTU() {
	cfgMTU, warpCascade, psiActive := e.cascadeState()
	effMTU := effectiveTunMTU(cfgMTU, warpCascade, psiActive)
	m4 := effectiveTunMSS(cfgMTU, false, warpCascade, psiActive)
	m6 := effectiveTunMSS(cfgMTU, true, warpCascade, psiActive)
	e.mss4.Store(uint32(m4))
	e.mss6.Store(uint32(m6))
	prevMTU := int(e.curMTU.Swap(int32(effMTU)))
	if prevMTU != 0 && prevMTU != effMTU && e.dev != nil {
		_ = setTunAdapterMTU(e.dev, effMTU, e.v6)
		logf("info", "TUN: динамическая коррекция каскада: MTU %d → %d, TCP MSS=%d (WARP=%v, Psiphon=%v)",
			prevMTU, effMTU, m4, warpCascade, psiActive)
	}
}

func newTunEngine(a *App, ctl *tunCtl) (*tunEngine, error) {
	a.cfg.mu.Lock()
	mtu, v6 := a.cfg.Tun.MTU, a.cfg.Tun.IPv6
	warpEnabled := a.cfg.Warp.Enabled
	a.cfg.mu.Unlock()
	if mtu < tunMinMTU || mtu > tunMaxMTU {
		mtu = tunDefaultMTU
	}
	if err := refreshPhys(); err != nil {
		return nil, err
	}
	v6 = v6 && physIdx6.Load() != 0
	psiActive := a.psi != nil && a.psi.running()
	warpCascade := warpEnabled || (a.warp != nil && a.warp.connected())
	effMTU := effectiveTunMTU(mtu, warpCascade, psiActive)

	tunActive.Store(true) // from now on our own sockets go to the real adapter
	dev, err := openTunDevice(a, effMTU, v6)
	if err != nil {
		tunActive.Store(false)
		return nil, err
	}
	e := &tunEngine{a: a, ctl: ctl, dev: dev, mtu: mtu, v6: v6}
	e.curMTU.Store(int32(effMTU))
	e.syncDynamicMTU()
	e.ctx, e.cancel = context.WithCancel(a.ctx)
	if err := e.initStack(effMTU); err != nil {
		e.cancel()
		_ = dev.Close()
		tunActive.Store(false)
		return nil, err
	}
	goSafe("TUN: приём", e.readLoop)
	goSafe("TUN: отправка", e.writeLoop)
	goSafe("TUN: адаптер", func() {
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-tk.C:
				_ = refreshPhys()
				e.syncDynamicMTU()
				e.rev.prune()
			}
		}
	})
	return e, nil
}

func (e *tunEngine) initStack(mtu int) error {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	// Reduced channel queue depth (256 instead of 1024) and bounded TCP receive
	// window to prevent multi-megabyte buffer hoarding in gVisor netstack.
	ep := channel.New(256, uint32(mtu), "")
	if terr := s.CreateNIC(1, ep); terr != nil {
		s.Close()
		return fmt.Errorf("netstack: %v", terr)
	}
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mod)

	tf := tcp.NewForwarder(s, 32<<10, 512, e.onTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	uf := udp.NewForwarder(s, e.onUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	e.s, e.ep = s, ep
	return nil
}

func (e *tunEngine) close() {
	e.once.Do(func() {
		e.cancel()
		_ = e.dev.Close() // removes the adapter together with its routes
		tunActive.Store(false)
		e.ep.Close()
		e.s.Close()
		e.rev.clear()
	})
}

func (e *tunEngine) readLoop() {
	n := e.dev.BatchSize()
	if n < 1 {
		n = 1
	}
	if n > 64 {
		n = 64
	}
	// Allocate MTU-sized packet buffers (plus headroom) instead of 65535 bytes
	// per batch slot, saving ~7–8 MB of permanent heap allocation in Wintun.
	pktBufSize := max(e.mtu+128, 2048)
	if pktBufSize < 16<<10 {
		pktBufSize = 16 << 10
	}
	bufs := make([][]byte, n)
	sizes := make([]int, n)
	for i := range bufs {
		bufs[i] = make([]byte, pktBufSize)
	}
	fails := 0
	for {
		cnt, err := e.dev.Read(bufs, sizes, 0)
		if e.ctx.Err() != nil {
			return
		}
		if err != nil {
			if fails++; fails > 200 {
				go e.ctl.fail(e, "адаптер перестал отвечать: "+err.Error())
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		fails = 0
		for i := 0; i < cnt; i++ {
			e.inject(bufs[i][:sizes[i]])
		}
	}
}

func (e *tunEngine) inject(p []byte) {
	if len(p) < 20 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch p[0] >> 4 {
	case 4:
		if p[9] == 1 { // ICMP: the stack would answer every ping itself
			return
		}
		proto = header.IPv4ProtocolNumber
	case 6:
		if !e.v6 || len(p) < 41 || (p[6] == 58 && p[40] == 128) {
			return
		}
		proto = header.IPv6ProtocolNumber
	default:
		return
	}
	// Clamp TCP MSS on outbound SYN packets from Windows applications
	if clampTCPMSS(p, uint16(e.mss4.Load()), uint16(e.mss6.Load())) {
		e.clampedPkts.Add(1)
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	e.ep.InjectInbound(proto, pkb)
	pkb.DecRef()
}

func (e *tunEngine) writeLoop() {
	for {
		pkt := e.ep.ReadContext(e.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		pkt.DecRef()
		raw := v.AsSlice()
		// Clamp TCP MSS on inbound SYN+ACK packets returning to Windows applications
		if clampTCPMSS(raw, uint16(e.mss4.Load()), uint16(e.mss6.Load())) {
			e.clampedPkts.Add(1)
		}
		_, _ = e.dev.Write([][]byte{raw}, 0)
		v.Release()
	}
}

func tunAddrOf(a tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return ip.Unmap()
}

func tunLookupOwner(proto string, v6 bool, port uint16) uint32 {
	for i := 0; i < 3; i++ {
		if pid := ownerPID(proto, v6, port); pid != 0 {
			return pid
		}
		time.Sleep(15 * time.Millisecond)
	}
	return 0
}

func tunRecover(where string) {
	if r := recover(); r != nil {
		logf("warn", "TUN: сбой в %s: %v", where, r)
	}
}

// resolveRealDst resolves a FakeIP (198.18.x.y) to a real destination IP when
// an excluded app or direct outbound connects directly.
func (e *tunEngine) resolveRealDst(dst netip.Addr, host string, port int) (netip.Addr, error) {
	if !isFakeIP(dst) {
		return dst, nil
	}
	if host == "" || host == dst.String() {
		host = theFakeIP.Lookup(dst)
	}
	if host == "" {
		return netip.Addr{}, errors.New("FakeIP: домен устарел или не найден")
	}
	ctx, cancel := context.WithTimeout(e.ctx, 8*time.Second)
	defer cancel()
	addrs, err := e.a.directAddrs(ctx, host, port)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("DNS для %s: %v", host, err)
	}
	h, _, err := net.SplitHostPort(addrs[0])
	if err != nil {
		return netip.Addr{}, err
	}
	realIP, err := netip.ParseAddr(h)
	return realIP, err
}

// ---------- TCP ----------

func (e *tunEngine) onTCP(r *tcp.ForwarderRequest) {
	defer tunRecover("TCP")
	id := r.ID()
	dst := tunAddrOf(id.LocalAddress)
	dport := int(id.LocalPort)
	if !dst.IsValid() || dst.IsUnspecified() || dst.IsMulticast() || tunInternal(dst) {
		r.Complete(true)
		return
	}
	pid := tunLookupOwner("tcp", dst.Is6(), id.RemotePort)
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	c := gonet.NewTCPConn(&wq, ep)
	defer c.Close()
	e.ctl.flows.Add(1)
	e.ctl.total.Add(1)
	defer e.ctl.flows.Add(-1)

	app := tunProcName(pid)
	if isSelfProc(pid, app) {
		e.directTCP(c, dst, "", dport, nil)
		return
	}
	hijackDNS, _, exclude := e.a.cfg.tunOpts()
	// Гасим внешние подключения к DNS-over-TLS (порт 853), чтобы браузеры не обходили FakeIP
	if dport == 853 && hijackDNS {
		return
	}
	fakeDomain := theFakeIP.Lookup(dst)
	if tunAppMatch(app, exclude) {
		host := fakeDomain
		if host == "" {
			host = e.rev.get(dst)
		}
		if host == "" {
			host = dst.String()
		}
		e.directTCP(c, dst, host, dport, e.a.stats.open(app, host, "", dport, obDirect, "исключение TUN"))
		return
	}
	first, host := e.sniff(c, dst, dport)
	if fakeDomain != "" && (host == "" || host == dst.String()) {
		host = fakeDomain
	}
	dstIPStr := dst.String()
	if isFakeIP(dst) {
		dstIPStr = "" // force directAddrs resolution if routed direct
	}
	br := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(first), c), 8<<10)
	e.a.tunnelAppAddr(c, br, host, dstIPStr, dport, app, func(net.Conn, error) error { return nil })
}

// sniff reads the first client bytes (up to 300 ms) to learn the domain.
func (e *tunEngine) sniff(c net.Conn, dst netip.Addr, port int) ([]byte, string) {
	var buf []byte
	if !tunServerFirst(port) {
		tmpPtr := getSmallBuf()
		tmp := *tmpPtr
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for len(buf) < len(tmp) {
			n, err := c.Read(tmp[:len(tmp)-len(buf)])
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil || !sniffWantMore(buf) {
				break
			}
		}
		putSmallBuf(tmpPtr)
		_ = c.SetReadDeadline(time.Time{})
	}
	host := sniffHost(buf)
	if host != "" {
		if !isFakeIP(dst) {
			e.rev.put(net.IP(dst.AsSlice()), host, 10*time.Minute)
			theRevDNS.put(net.IP(dst.AsSlice()), host, 10*time.Minute)
		}
	} else {
		host = theFakeIP.Lookup(dst)
		if host == "" {
			host = e.rev.get(dst)
		}
		if host == "" {
			host = theRevDNS.get(dst)
		}
	}
	if host == "" {
		host = dst.String()
	}
	return buf, host
}

// directTCP: straight to the real adapter (own traffic, excluded apps).
func (e *tunEngine) directTCP(c net.Conn, dst netip.Addr, host string, port int, t *tracked) {
	finish := func(err error) {
		if t != nil {
			e.a.stats.close(t, err)
		}
	}
	realDst, err := e.resolveRealDst(dst, host, port)
	if err != nil {
		finish(err)
		return
	}
	if tunPhysIdx(realDst) == 0 {
		finish(errors.New("нет сетевого адаптера"))
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	up, err := tunDialBound(ctx, "tcp", netip.AddrPortFrom(realDst, uint16(port)).String())
	cancel()
	if err != nil {
		finish(err)
		return
	}
	defer up.Close()
	if tc, ok := up.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	u, d := tunPipe(c, up)
	if t != nil {
		e.a.stats.add(t, u, d)
	}
	finish(nil)
}

func tunHalfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func tunPipe(c, up net.Conn) (int64, int64) {
	var upN int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		bPtr := getRelayBuf()
		upN, _ = io.CopyBuffer(up, c, *bPtr)
		putRelayBuf(bPtr)
		tunHalfClose(up)
		_ = up.SetReadDeadline(time.Now().Add(2 * time.Minute))
	}()
	bPtr := getRelayBuf()
	downN, _ := io.CopyBuffer(c, up, *bPtr)
	putRelayBuf(bPtr)
	tunHalfClose(c)
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	<-done
	return upN, downN
}

// ---------- UDP ----------

// onUDP handles incoming UDP flows in gVisor netstack (signature is void).
func (e *tunEngine) onUDP(r *udp.ForwarderRequest) {
	defer tunRecover("UDP")
	id := r.ID()
	dst := tunAddrOf(id.LocalAddress)
	if !tunUDPTarget(dst) {
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	c := gonet.NewUDPConn(&wq, ep)
	dport, sport := int(id.LocalPort), id.RemotePort
	goSafe("TUN: UDP", func() { e.serveUDP(c, dst, dport, sport) })
}

func (e *tunEngine) serveUDP(c net.Conn, dst netip.Addr, dport int, sport uint16) {
	defer c.Close()
	e.ctl.flows.Add(1)
	e.ctl.total.Add(1)
	defer e.ctl.flows.Add(-1)

	toUs := dst == tunDNS4 || dst == tunDNS6
	if toUs && dport == 53 {
		e.serveDNS(c)
		return
	}
	if tunInternal(dst) {
		return
	}
	pid := tunLookupOwner("udp", dst.Is6(), sport)
	app := tunProcName(pid)
	self := isSelfProc(pid, app)
	hijack, _, exclude := e.a.cfg.tunOpts()
	if dport == 53 && hijack && !self {
		e.serveDNS(c)
		return
	}
	host := theFakeIP.Lookup(dst)
	if host == "" {
		host = e.rev.get(dst)
	}
	if host == "" {
		host = theRevDNS.get(dst)
	}
	if host == "" {
		host = dst.String()
	}
	realDst := dst
	if isFakeIP(dst) {
		if rd, err := e.resolveRealDst(dst, host, dport); err == nil {
			realDst = rd
		} else {
			return
		}
	}
	addr := netip.AddrPortFrom(realDst, uint16(dport)).String()
	if self {
		if tunPhysIdx(realDst) == 0 {
			return
		}
		up, err := tunDialBound(e.ctx, "udp", addr)
		if err != nil {
			return
		}
		e.udpRelay(c, up, nil, false)
		return
	}
	ob, rule := obDirect, "исключение TUN"
	if !tunAppMatch(app, exclude) {
		ob, rule = e.a.planUDPIP(host, realDst.String(), dport, app)
	}
	if ob == "" {
		return // UDP is off or blocked
	}
	t := e.a.stats.open(app, host, "", dport, ob, rule+" · TUN UDP")
	switch ob {
	case obDirect, obDesync:
		if tunPhysIdx(realDst) == 0 {
			e.a.stats.close(t, errors.New("нет сетевого адаптера"))
			return
		}
		up, err := tunDialBound(e.ctx, "udp", addr)
		if err != nil {
			e.a.stats.close(t, err)
			return
		}
		e.udpRelay(c, up, t, ob == obDesync || (dport == 443 && e.a.quicDesyncEnabled()))
	case obWarp:
		ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
		up, err := e.a.warp.Dial(ctx, "udp", addr)
		cancel()
		if err != nil {
			e.a.stats.close(t, err)
			return
		}
		e.udpRelay(c, up, t, false)
	default:
		e.udpGW(c, realDst, dport, t)
	}
}

// udpRelay copies datagrams both ways until udpIdle passes without traffic.
// When quicDesync is true, the first QUIC Initial packet on UDP:443 is preceded
// by low-TTL/invalid-version UDP fake packets (Priority 5).
func (e *tunEngine) udpRelay(c, up net.Conn, t *tracked, quicDesync bool) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	alive := func() bool {
		return e.ctx.Err() == nil && time.Since(time.Unix(0, last.Load())) < udpIdle
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer tunRecover("UDP")
		bufPtr := getUDPBuf()
		defer putUDPBuf(bufPtr)
		buf := *bufPtr
		for {
			_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := up.Read(buf)
			if err != nil {
				if (isTimeout(err) || isConnReset(err)) && alive() {
					continue
				}
				_ = c.Close()
				return
			}
			last.Store(time.Now().UnixNano())
			if t != nil {
				e.a.stats.add(t, 0, int64(n))
			}
			if _, err := c.Write(buf[:n]); err != nil {
				_ = up.Close()
				return
			}
		}
	}()
	bufPtr := getUDPBuf()
	defer putUDPBuf(bufPtr)
	buf := *bufPtr
	firstPkt := true
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			if isTimeout(err) && alive() {
				continue
			}
			break
		}
		last.Store(time.Now().UnixNano())
		if t != nil {
			e.a.stats.add(t, int64(n), 0)
		}
		payload := buf[:n]
		if firstPkt {
			firstPkt = false
			if quicDesync && isQUICInitial(payload) {
				if err := writeUDPWithQUICDesync(up, payload); err != nil && !isConnReset(err) {
					break
				}
				continue
			}
		}
		if _, err := up.Write(payload); err != nil && !isConnReset(err) {
			break
		}
	}
	_ = up.Close()
	_ = c.Close()
	<-done
	if t != nil {
		e.a.stats.close(t, nil)
	}
}

// udpGW sends one UDP flow through Psiphon's udpgw (one TCP stream per flow).
func (e *tunEngine) udpGW(c net.Conn, dst netip.Addr, port int, t *tracked) {
	ctx, cancel := context.WithTimeout(e.ctx, 20*time.Second)
	gw, err := e.a.psi.Dial(ctx, "tcp", udpgwServer)
	cancel()
	if err != nil {
		e.a.stats.close(t, err)
		return
	}
	const conid = 1
	ip := net.IP(dst.AsSlice())
	var wmu sync.Mutex
	write := func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		_ = gw.SetWriteDeadline(time.Now().Add(15 * time.Second))
		_, err := gw.Write(b)
		return err
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	alive := func() bool {
		return e.ctx.Err() == nil && time.Since(time.Unix(0, last.Load())) < udpIdle
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer tunRecover("udpgw")
		br := bufio.NewReaderSize(gw, 16<<10)
		bufPtr := getUDPBuf()
		defer putUDPBuf(bufPtr)
		buf := *bufPtr
		for {
			flags, id, _, _, data, err := udpgwRead(br, buf)
			if err != nil {
				_ = c.Close()
				return
			}
			if flags&udpgwFlagKeepalive != 0 || id != conid {
				continue
			}
			last.Store(time.Now().UnixNano())
			e.a.stats.add(t, 0, int64(len(data)))
			if _, err := c.Write(data); err != nil {
				_ = gw.Close()
				return
			}
		}
	}()
	stopKA := make(chan struct{})
	go func() {
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stopKA:
				return
			case <-tk.C:
				if write(udpgwKeepalive()) != nil {
					return
				}
			}
		}
	}()
	sent := false
	bufPtr := getUDPBuf()
	defer putUDPBuf(bufPtr)
	buf := *bufPtr
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			if isTimeout(err) && alive() {
				continue
			}
			break
		}
		if n > udpgwMaxData {
			continue
		}
		var flags byte
		if !sent {
			flags, sent = udpgwFlagRebind, true
		}
		last.Store(time.Now().UnixNano())
		e.a.stats.add(t, int64(n), 0)
		if write(udpgwEncode(flags, conid, ip, port, buf[:n])) != nil {
			break
		}
	}
	close(stopKA)
	_ = gw.Close()
	_ = c.Close()
	<-done
	e.a.stats.close(t, nil)
}

// ---------- DNS ----------

func (e *tunEngine) serveDNS(c net.Conn) {
	buf := make([]byte, 4096)
	wait := 5 * time.Second
	for {
		_ = c.SetReadDeadline(time.Now().Add(wait))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		wait = 2 * time.Second // close quickly after answering
		q := append([]byte(nil), buf[:n]...)
		if resp := e.resolveDNS(q); resp != nil {
			_, _ = c.Write(resp)
		}
	}
}

// resolveDNS answers through FakeIP (198.18.0.0/15) when enabled, or through
// DoH (direct with DPI bypass, then Psiphon) and remembers IP -> domain.
func (e *tunEngine) resolveDNS(q []byte) []byte {
	name, end := dnsQName(q)
	if end < 4 {
		return nil
	}
	if isBrowserCanaryDomain(name) {
		if nx := dnsNXDomain(q); nx != nil {
			return nx
		}
	}
	qtype := binary.BigEndian.Uint16(q[end-4 : end-2])
	if qtype == 28 && !e.v6 {
		if nodata := dnsNoDataResponse(q); nodata != nil {
			return nodata
		}
	}
	_, useFake, _ := e.a.cfg.tunOpts()
	if useFake && name != "" && !strings.HasSuffix(name, ".arpa") && !strings.HasSuffix(name, ".local") {
		if qtype == 1 || qtype == 28 {
			fip := theFakeIP.Assign(name)
			e.rev.put(net.IP(fip.AsSlice()), name, fakeIPTTL)
			if resp := dnsFakeIPResponse(q, fip); resp != nil {
				return resp
			}
		}
	}
	id0, id1 := q[0], q[1]
	obs := []string{obDirect, obPsiphon}
	if e.dnsPsi.Load() {
		obs = []string{obPsiphon, obDirect}
	}
	for _, ob := range obs {
		if ob == obPsiphon && !e.a.psi.running() {
			continue
		}
		ctx, cancel := context.WithTimeout(e.ctx, 4*time.Second)
		resp, err := e.a.dohExchange(ctx, ob, append([]byte(nil), q...))
		cancel()
		if err != nil || len(resp) < 12 {
			continue
		}
		e.dnsPsi.Store(ob == obPsiphon)
		resp[0], resp[1] = id0, id1
		if name != "" {
			if ips, err := dnsAnswers(resp); err == nil {
				for _, ip := range ips {
					e.rev.put(ip, name, 10*time.Minute)
					theRevDNS.put(ip, name, 10*time.Minute)
				}
			}
		}
		return resp
	}
	return dnsServfail(q)
}
