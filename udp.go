package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// SOCKS5 UDP ASSOCIATE (1.0.7+) & QUIC Initial Desync (Priority 5).
// Programs that send UDP through SOCKS5 or TUN get it routed like TCP:
//   - direct: a plain UDP socket;
//   - direct-dpi (or UDP:443 when BlockQUIC is off and Desync is on):
//     QUIC Initial (UDP:443) packets are preceded by low-TTL / GREASE-version
//     UDP fake packets (sendUDPWithQUICDesync), accelerating HTTP/3 video and
//     voice calls without forcing a slow fallback to TCP;
//   - Psiphon: udpgw, the UDP-in-tunnel protocol of Psiphon servers;
//   - built-in WARP: UDP inside the WireGuard tunnel;
//   - DNS (port 53) through Psiphon or WARP becomes DNS over HTTPS inside
//     the tunnel: it works on every server and the provider sees nothing.

const (
	udpgwServer  = "127.0.0.1:7300" // udpgw on every Psiphon server, reached through the tunnel
	udpIdle      = 40 * time.Second // жёсткий лимит неактивных UDP-сессий (30–45 с по ТЗ)
	udpDNSIdle   = 5 * time.Second  // жёсткий лимит для DNS-запросов (5 с по ТЗ)
	udpMaxFlows  = 128
	udpgwMaxData = 32 << 10

	udpgwFlagKeepalive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3
)

var udpStats struct {
	sessions, flows atomic.Int64
}

func (a *App) udpMode() string {
	a.cfg.mu.Lock()
	m := a.cfg.UDP.Mode
	a.cfg.mu.Unlock()
	switch m {
	case "psiphon", "direct", "off":
		return m
	}
	return "route"
}

// quicDesyncEnabled reports whether QUIC Initial (UDP:443) desynchronization
// (fakes/fragmentation) is active instead of coarse BlockQUIC dropping.
func (a *App) quicDesyncEnabled() bool {
	if a == nil || a.cfg == nil {
		return false
	}
	a.cfg.mu.Lock()
	defer a.cfg.mu.Unlock()
	return !a.cfg.Routing.BlockQUIC && a.cfg.Desync.Enabled
}

// planUDP picks the UDP outbound. UDP has fewer ways out than TCP: direct-dpi
// uses direct UDP (with QUIC Initial desynchronization on port 443 when
// BlockQUIC is disabled), country exits use the main Psiphon tunnel, the
// external proxy cannot carry UDP, and "block" drops UDP.
func (a *App) planUDP(host string, port int, app string) (ob, rule string) {
	return a.planUDPIP(host, "", port, app)
}

func (a *App) planUDPIP(host, dstIP string, port int, app string) (ob, rule string) {
	a.cfg.mu.Lock()
	blockQUIC := a.cfg.Routing.BlockQUIC
	a.cfg.mu.Unlock()
	switch a.udpMode() {
	case "off":
		return "", "UDP выключен"
	case "psiphon":
		if blockQUIC && port == 443 {
			return "", "блок QUIC (UDP 443)"
		}
		return obPsiphon, "глобальный режим UDP: весь трафик через Psiphon (правила UDP не применяются)"
	case "direct":
		return obDirect, "глобальный режим UDP: весь трафик напрямую (правила UDP не применяются)"
	}
	order, rule := a.router.planForProto("udp", host, dstIP, port, app)
	for _, o := range order {
		switch {
		case o == obBlock:
			return "", rule
		case o == obDirect:
			return obDirect, rule
		case o == obDesync:
			if blockQUIC && port == 443 {
				return "", "блок QUIC (UDP 443)"
			}
			return obDirect, rule
		case o == obPsiphon || isCountryOb(o):
			if blockQUIC && port == 443 {
				return "", "блок QUIC (UDP 443)"
			}
			return obPsiphon, rule
		case o == obWarp && a.warp.builtin():
			if blockQUIC && port == 443 {
				return "", "блок QUIC (UDP 443)"
			}
			return obWarp, rule
		}
	}
	if blockQUIC && port == 443 {
		return "", "блок QUIC (UDP 443)"
	}
	return obPsiphon, rule
}

// socksAddr encodes ATYP, address and port (SOCKS5 replies and UDP headers).
func socksAddr(host string, port int) []byte {
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append([]byte{1}, ip4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return append(b, byte(port>>8), byte(port))
}

// parseSocksUDP reads the SOCKS5 UDP header. Fragments are not supported
// (RFC 1928 allows that, and no client sends them).
func parseSocksUDP(b []byte) (host string, port int, data []byte, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return
	}
	i := 4
	switch b[3] {
	case 1:
		if len(b) < i+6 {
			return
		}
		host = net.IP(b[i : i+4]).String()
		i += 4
	case 4:
		if len(b) < i+18 {
			return
		}
		host = net.IP(b[i : i+16]).String()
		i += 16
	case 3:
		if len(b) < i+1 {
			return
		}
		n := int(b[i])
		i++
		if n == 0 || len(b) < i+n+2 {
			return
		}
		host = string(b[i : i+n])
		i += n
	default:
		return
	}
	port = int(binary.BigEndian.Uint16(b[i:]))
	if port == 0 {
		return "", 0, nil, false
	}
	return host, port, b[i+2:], true
}

// ---------- udpgw framing ----------
//
// Each message: length (2 bytes, little endian, counts what follows), flags
// (1), connection id (2, little endian), IPv4 (4) or IPv6 (16, flag 1<<3),
// port (2, big endian), payload. A keepalive is the header alone.

func udpgwEncode(flags byte, conid uint16, ip net.IP, port int, data []byte) []byte {
	ip4 := ip.To4()
	addrLen := 6
	if ip4 == nil {
		addrLen = 18
		flags |= udpgwFlagIPv6
	}
	n := 3 + addrLen + len(data)
	b := make([]byte, 2+n)
	binary.LittleEndian.PutUint16(b[0:], uint16(n))
	b[2] = flags
	binary.LittleEndian.PutUint16(b[3:], conid)
	if ip4 != nil {
		copy(b[5:9], ip4)
		binary.BigEndian.PutUint16(b[9:], uint16(port))
		copy(b[11:], data)
	} else {
		copy(b[5:21], ip.To16())
		binary.BigEndian.PutUint16(b[21:], uint16(port))
		copy(b[23:], data)
	}
	return b
}

func udpgwKeepalive() []byte { return []byte{3, 0, udpgwFlagKeepalive, 0, 0} }

var errUDPGW = errors.New("udpgw: неверное сообщение")

func udpgwRead(r io.Reader, buf []byte) (flags byte, conid uint16, ip net.IP, port int, data []byte, err error) {
	for {
		if _, err = io.ReadFull(r, buf[:2]); err != nil {
			return
		}
		n := int(binary.LittleEndian.Uint16(buf))
		if n < 3 || n > len(buf) {
			return 0, 0, nil, 0, nil, errUDPGW
		}
		if _, err = io.ReadFull(r, buf[:n]); err != nil {
			return
		}
		flags, conid = buf[0], binary.LittleEndian.Uint16(buf[1:])
		if flags&udpgwFlagKeepalive != 0 {
			continue
		}
		if flags&udpgwFlagIPv6 != 0 {
			if n < 21 {
				return 0, 0, nil, 0, nil, errUDPGW
			}
			return flags, conid, net.IP(append([]byte(nil), buf[3:19]...)), int(binary.BigEndian.Uint16(buf[19:])), buf[21:n], nil
		}
		if n < 9 {
			return 0, 0, nil, 0, nil, errUDPGW
		}
		return flags, conid, net.IP(append([]byte(nil), buf[3:7]...)), int(binary.BigEndian.Uint16(buf[7:])), buf[9:n], nil
	}
}

// ---------- association ----------

// udpAssociate serves one UDP ASSOCIATE: it binds a UDP port on the address
// the client reached us at, tells the client, and relays until the control
// TCP connection closes (RFC 1928).
func (a *App) udpAssociate(c net.Conn, br *bufio.Reader) {
	fail := func(code byte) { _, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if a.udpMode() == "off" {
		fail(7)
		return
	}
	la, ok1 := c.LocalAddr().(*net.TCPAddr)
	ra, ok2 := c.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		fail(1)
		return
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: la.IP})
	if err != nil {
		fail(1)
		return
	}
	s := &udpSession{a: a, ln: ln, clientIP: ra.IP, app: appForConn(c.RemoteAddr()),
		flows: map[string]*udpFlow{}, byAddr: map[string]*udpFlow{}, failed: map[string]time.Time{},
		done: make(chan struct{}), dnsSem: make(chan struct{}, 16)}
	defer s.close()
	bnd := ln.LocalAddr().(*net.UDPAddr)
	if _, err := c.Write(append([]byte{5, 0, 0}, socksAddr(bnd.IP.String(), bnd.Port)...)); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	udpStats.sessions.Add(1)
	goSafe("UDP", s.readClient)
	goSafe("UDP", s.janitor)
	_, _ = io.Copy(io.Discard, br) // lives as long as the TCP connection
}

type udpSession struct {
	a        *App
	ln       *net.UDPConn
	clientIP net.IP
	app      string
	dnsSem   chan struct{}

	mu     sync.Mutex
	client *net.UDPAddr
	flows  map[string]*udpFlow // by destination as the client wrote it
	byAddr map[string]*udpFlow // direct flows by resolved address
	failed map[string]time.Time
	direct *net.UDPConn
	gw     *udpgwConn
	gwErr  time.Time
	closed bool
	done   chan struct{}
}

type udpFlow struct {
	key        string
	host       string
	port       int
	ob         string
	dns        bool
	quicDesync bool
	t          *tracked
	ip         net.IP       // psiphon: destination address
	addr       *net.UDPAddr // direct
	conn       net.Conn     // warp
	gw         *udpgwConn   // psiphon
	conid      uint16
	sent       bool
	last       atomic.Int64
}

func (f *udpFlow) touch() { f.last.Store(time.Now().UnixNano()) }

type udpgwConn struct {
	c    net.Conn
	wmu  sync.Mutex
	mu   sync.Mutex
	next uint16
	byID map[uint16]*udpFlow
}

func (g *udpgwConn) write(b []byte) error {
	g.wmu.Lock()
	defer g.wmu.Unlock()
	_ = g.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := g.c.Write(b)
	if err != nil {
		_ = g.c.Close() // the reader cleans up
	}
	return err
}

func (s *udpSession) readClient() {
	bufPtr := getUDPBuf()
	defer putUDPBuf(bufPtr)
	buf := *bufPtr
	for {
		n, from, err := s.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !from.IP.Equal(s.clientIP) && !(from.IP.IsLoopback() && s.clientIP.IsLoopback()) {
			continue // only the program that opened the association
		}
		host, port, data, ok := parseSocksUDP(buf[:n])
		if !ok || s.a.isSelfUI(host, port) {
			continue
		}
		s.mu.Lock()
		if s.client == nil {
			s.client = from // lock onto the first client UDP port to prevent local port spoofing
		} else if s.client.Port != from.Port {
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()
		s.send(host, port, append([]byte(nil), data...))
	}
}

func (s *udpSession) send(host string, port int, data []byte) {
	if isBitTorrentUDP(data) {
		s.a.cfg.mu.Lock()
		ks := s.a.cfg.Routing.KillSwitch
		s.a.cfg.mu.Unlock()
		if ks {
			return
		}
	}
	f := s.flow(host, port)
	if f == nil {
		return
	}
	if isBitTorrentUDP(data) && f.ob != obDirect && !f.dns {
		// Не пускаем UDP-торренты (DHT/uTP) в узкий канал Psiphon
		return
	}
	f.touch()
	s.a.stats.add(f.t, int64(len(data)), 0)
	switch {
	case f.dns:
		select {
		case s.dnsSem <- struct{}{}:
			goSafe("DNS через туннель", func() { defer func() { <-s.dnsSem }(); s.dnsTunnel(f, data) })
		default: // too many at once: the client will repeat
		}
	case f.ob == obDirect:
		s.mu.Lock()
		d := s.direct
		s.mu.Unlock()
		if d != nil {
			if !f.sent {
				f.sent = true
				if f.quicDesync && isQUICInitial(data) {
					_ = sendUDPWithQUICDesync(d, f.addr, data)
					return
				}
			}
			_, _ = d.WriteToUDP(data, f.addr)
		}
	case f.ob == obWarp:
		_, _ = f.conn.Write(data)
	default:
		if len(data) > udpgwMaxData {
			return
		}
		var flags byte
		if !f.sent {
			flags, f.sent = udpgwFlagRebind, true // a reused id starts clean on the server
		}
		_ = f.gw.write(udpgwEncode(flags, f.conid, f.ip, f.port, data))
	}
}

// flow returns the flow for a destination, opening it on the first packet.
// Only readClient calls it, so flows are never opened twice.
func (s *udpSession) flow(host string, port int) *udpFlow {
	key := net.JoinHostPort(host, strconv.Itoa(port))
	ob, rule := s.a.planUDP(host, port, s.app)
	s.mu.Lock()
	if f := s.flows[key]; f != nil {
		if ob != "" && f.ob == ob {
			s.mu.Unlock()
			return f
		}
		delete(s.flows, key)
		s.endFlow(f)
	}
	if ob == "" {
		s.mu.Unlock()
		return nil
	}
	if s.closed || time.Since(s.failed[key]) < 10*time.Second {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	f := &udpFlow{
		key:        key,
		host:       host,
		port:       port,
		ob:         ob,
		dns:        port == 53 && ob != obDirect,
		quicDesync: port == 443 && ob == obDirect && s.a.quicDesyncEnabled(),
	}
	var err error
	switch {
	case f.dns:
	case ob == obDirect:
		err = s.openDirect(f)
	case ob == obWarp:
		err = s.openWarp(f)
	default:
		err = s.openGW(f)
	}
	f.t = s.a.stats.openProto("udp", s.app, host, "", port, ob, rule+" · UDP")
	if err != nil {
		s.a.stats.close(f.t, err)
		s.mu.Lock()
		s.failed[key] = time.Now()
		s.mu.Unlock()
		return nil
	}
	udpStats.flows.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.endFlow(f)
		return nil
	}
	if len(s.flows) >= udpMaxFlows {
		s.evictLocked()
	}
	s.flows[key] = f
	if f.addr != nil {
		s.byAddr[udpKey(f.addr.IP, f.addr.Port)] = f
	}
	return f
}

func udpKey(ip net.IP, port int) string {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

func (s *udpSession) openDirect(f *udpFlow) error {
	ip := net.ParseIP(f.host)
	if ip == nil {
		ctx, cancel := context.WithTimeout(s.a.ctx, 8*time.Second)
		defer cancel()
		addrs, err := s.a.directAddrs(ctx, f.host, f.port)
		if err != nil {
			return err
		}
		for _, ad := range addrs {
			if h, _, err := net.SplitHostPort(ad); err == nil {
				if ip = net.ParseIP(h); ip != nil {
					break
				}
			}
		}
		if ip == nil {
			return errors.New(f.host + ": адрес не найден")
		}
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	f.addr = &net.UDPAddr{IP: ip, Port: f.port}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.direct == nil {
		d, err := listenUDPDirectFor(ip)
		if err != nil {
			return err
		}
		s.direct = d
		goSafe("UDP напрямую", func() { s.readDirect(d) })
	}
	return nil
}

func (s *udpSession) readDirect(d *net.UDPConn) {
	bufPtr := getUDPBuf()
	defer putUDPBuf(bufPtr)
	buf := *bufPtr
	for {
		n, from, err := d.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.mu.Lock()
		f := s.byAddr[udpKey(from.IP, from.Port)]
		s.mu.Unlock()
		if f == nil {
			continue // answers only from addresses this program talked to
		}
		f.touch()
		s.a.stats.add(f.t, 0, int64(n))
		fromIP := from.IP
		if ip4 := fromIP.To4(); ip4 != nil {
			fromIP = ip4
		}
		s.reply(fromIP.String(), from.Port, buf[:n])
	}
}

func (s *udpSession) openWarp(f *udpFlow) error {
	ctx, cancel := context.WithTimeout(s.a.ctx, 45*time.Second)
	defer cancel()
	c, err := s.a.warp.Dial(ctx, "udp", f.key)
	if err != nil {
		return err
	}
	f.conn = c
	goSafe("UDP через WARP", func() {
		bufPtr := getUDPBuf()
		defer putUDPBuf(bufPtr)
		buf := *bufPtr
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			f.touch()
			s.a.stats.add(f.t, 0, int64(n))
			s.reply(f.host, f.port, buf[:n])
		}
	})
	return nil
}

var errUDPGWDown = errors.New("UDP через Psiphon сейчас недоступен")

func (s *udpSession) openGW(f *udpFlow) error {
	ip := net.ParseIP(f.host)
	if ip == nil {
		ctx, cancel := context.WithTimeout(s.a.ctx, 10*time.Second)
		defer cancel()
		var err error
		if ip, err = s.a.tunnelLookup(ctx, obPsiphon, f.host); err != nil {
			return err
		}
	}
	f.ip = ip
	g, err := s.gateway()
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.next++
	if g.next == 0 {
		g.next = 1
	}
	f.conid, f.gw = g.next, g
	g.byID[f.conid] = f
	g.mu.Unlock()
	return nil
}

// gateway: one udpgw channel per association, opened on first use and again
// after the tunnel reconnects.
func (s *udpSession) gateway() (*udpgwConn, error) {
	s.mu.Lock()
	if g := s.gw; g != nil {
		s.mu.Unlock()
		return g, nil
	}
	if time.Since(s.gwErr) < 10*time.Second {
		s.mu.Unlock()
		return nil, errUDPGWDown
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(s.a.ctx, 25*time.Second)
	defer cancel()
	c, err := s.a.psi.Dial(ctx, "tcp", udpgwServer)
	if err != nil {
		s.mu.Lock()
		s.gwErr = time.Now()
		s.mu.Unlock()
		return nil, err
	}
	g := &udpgwConn{c: c, byID: map[uint16]*udpFlow{}}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	s.gw = g
	s.mu.Unlock()
	goSafe("UDP через Psiphon", func() { s.readGW(g) })
	goSafe("UDP через Psiphon", func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				if g.write(udpgwKeepalive()) != nil {
					return
				}
			}
		}
	})
	return g, nil
}

func (s *udpSession) readGW(g *udpgwConn) {
	br := bufio.NewReaderSize(g.c, 16<<10)
	bufPtr := getUDPBuf()
	defer putUDPBuf(bufPtr)
	buf := *bufPtr
	for {
		_, conid, ip, port, data, err := udpgwRead(br, buf)
		if err != nil {
			break
		}
		g.mu.Lock()
		f := g.byID[conid]
		g.mu.Unlock()
		if f == nil {
			continue
		}
		f.touch()
		s.a.stats.add(f.t, 0, int64(len(data)))
		s.reply(ip.String(), port, data)
	}
	_ = g.c.Close()
	// The channel is gone (usually the tunnel reconnected): forget its
	// flows, the next packet opens them on a new channel.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gw == g {
		s.gw = nil
	}
	for k, f := range s.flows {
		if f.gw == g {
			delete(s.flows, k)
			s.endFlow(f)
		}
	}
}

func (s *udpSession) dnsTunnel(f *udpFlow, q []byte) {
	ctx, cancel := context.WithTimeout(s.a.ctx, 10*time.Second)
	defer cancel()
	resp, err := s.a.dohExchange(ctx, f.ob, q)
	if err != nil {
		return // the client repeats the query
	}
	f.touch()
	s.a.stats.add(f.t, 0, int64(len(resp)))
	s.reply(f.host, f.port, resp)
}

func (s *udpSession) reply(host string, port int, data []byte) {
	s.mu.Lock()
	cl := s.client
	s.mu.Unlock()
	if cl == nil {
		return
	}
	pkt := append([]byte{0, 0, 0}, socksAddr(host, port)...)
	pkt = append(pkt, data...)
	_, _ = s.ln.WriteToUDP(pkt, cl)
}

// endFlow closes a flow already removed from the maps (s.mu held or not
// needed).
func (s *udpSession) endFlow(f *udpFlow) {
	if f.conn != nil {
		_ = f.conn.Close()
	}
	if f.gw != nil {
		f.gw.mu.Lock()
		if f.gw.byID[f.conid] == f {
			delete(f.gw.byID, f.conid)
		}
		f.gw.mu.Unlock()
	}
	if f.addr != nil && s.byAddr[udpKey(f.addr.IP, f.addr.Port)] == f {
		delete(s.byAddr, udpKey(f.addr.IP, f.addr.Port))
	}
	s.a.stats.close(f.t, nil)
}

func (s *udpSession) evictLocked() {
	var old *udpFlow
	for _, f := range s.flows {
		if old == nil || f.last.Load() < old.last.Load() {
			old = f
		}
	}
	if old != nil {
		delete(s.flows, old.key)
		s.endFlow(old)
	}
}

func (s *udpSession) janitor() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		now := time.Now()
		cutUDP := now.Add(-udpIdle).UnixNano()
		cutDNS := now.Add(-udpDNSIdle).UnixNano()
		s.mu.Lock()
		for k, f := range s.flows {
			limit := cutUDP
			if f.dns || f.port == 53 {
				limit = cutDNS
			}
			if f.last.Load() < limit {
				delete(s.flows, k)
				s.endFlow(f)
			}
		}
		for k, at := range s.failed {
			if time.Since(at) > time.Minute {
				delete(s.failed, k)
			}
		}
		s.mu.Unlock()
	}
}

func (s *udpSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	gw, direct := s.gw, s.direct
	for k, f := range s.flows {
		delete(s.flows, k)
		s.endFlow(f)
	}
	s.mu.Unlock()
	_ = s.ln.Close()
	if direct != nil {
		_ = direct.Close()
	}
	if gw != nil {
		_ = gw.c.Close()
	}
}
