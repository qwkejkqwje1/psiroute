package main

// Platform-independent helpers for the TUN mode (tun.go): addresses, socket
// binding to the real adapter, dynamic MTU & TCP MSS clamping for the
// TUN -> WARP -> Psiphon cascade, traffic sniffing, the reverse DNS map, and
// reusable packet buffer pools.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	tunDefaultMTU         = 1500
	tunMinMTU             = 1280
	tunMaxMTU             = 9000
	tunCascadeWarpMTU     = 1280 // WireGuard / Cloudflare WARP inner tunnel MTU
	tunCascadePsiOverhead = 60   // SSH/OSSH/TLS/Meek encapsulation overhead inside Psiphon
	tunMinMSS4            = 536  // RFC 879 / RFC 1122 minimum IPv4 MSS
	tunMinMSS6            = 1120 // Practical lower bound for cascaded IPv6 tunnels
)

var (
	tunAddr4 = netip.MustParseAddr("172.19.0.1")
	tunDNS4  = netip.MustParseAddr("172.19.0.2")
	tunNet4  = netip.MustParsePrefix("172.19.0.0/30")
	tunAddr6 = netip.MustParseAddr("fdfe:dcba:9876::1")
	tunDNS6  = netip.MustParseAddr("fdfe:dcba:9876::2")
	tunNet6  = netip.MustParsePrefix("fdfe:dcba:9876::/126")

	errNeedAdmin      = errors.New("need_admin")
	errTunUnsupported = errors.New("режим TUN есть только в Windows")

	// tunActive: while TUN is on, our own direct sockets are bound to the
	// real adapter (physIdx4/6), otherwise they would loop back into TUN.
	tunActive          atomic.Bool
	physIdx4, physIdx6 atomic.Uint32
	physAlias          atomic.Value // string

	// theRevDNS maps resolved IPs back to domain names across DoH, UDP, SOCKS5 and TUN.
	theRevDNS = &revMap{}

	// Shared buffer pools to eliminate 2KB/16KB/32KB/64KB heap allocations per flow.
	mtuBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 2048)
			return &b
		},
	}
	smallBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 16<<10)
			return &b
		},
	}
	relayBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 32<<10)
			return &b
		},
	}
	udpBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535)
			return &b
		},
	}
)

func getMTUBuf() *[]byte { return mtuBufPool.Get().(*[]byte) }
func putMTUBuf(b *[]byte) {
	if b != nil {
		clear(*b)
		mtuBufPool.Put(b)
	}
}

func getSmallBuf() *[]byte { return smallBufPool.Get().(*[]byte) }
func putSmallBuf(b *[]byte) {
	if b != nil {
		smallBufPool.Put(b)
	}
}

func getRelayBuf() *[]byte  { return relayBufPool.Get().(*[]byte) }
func putRelayBuf(b *[]byte) { relayBufPool.Put(b) }

func getUDPBuf() *[]byte  { return udpBufPool.Get().(*[]byte) }
func putUDPBuf(b *[]byte) { udpBufPool.Put(b) }

// ---------- Dynamic MTU & TCP MSS Clamping (Priority 1) ----------

// effectiveTunMTU calculates the optimal interface MTU for the active tunnel
// cascade (TUN -> WARP -> Psiphon). When WARP is active in the cascade, the
// inner MTU is capped at 1280 bytes so packets never fragment across WireGuard;
// when only Psiphon is active with the default 1500 setting, 1380 is used to
// leave headroom for OSSH/TLS/Meek framing.
func effectiveTunMTU(configuredMTU int, warpCascade, psiActive bool) int {
	mtu := configuredMTU
	if mtu < tunMinMTU || mtu > tunMaxMTU {
		mtu = tunDefaultMTU
	}
	if warpCascade {
		if mtu > tunCascadeWarpMTU {
			mtu = tunCascadeWarpMTU
		}
		return mtu
	}
	if psiActive && configuredMTU == tunDefaultMTU {
		return 1380
	}
	return mtu
}

// effectiveTunMSS computes the TCP Maximum Segment Size (MSS) ceiling for IPv4
// or IPv6 packets traversing the TUN -> WARP -> Psiphon cascade. Clamping MSS
// on SYN and SYN+ACK packets prevents PMTUD blackholes ("hanging" sites after
// TLS handshake and dropped large file downloads).
func effectiveTunMSS(configuredMTU int, isIPv6, warpCascade, psiActive bool) uint16 {
	effMTU := effectiveTunMTU(configuredMTU, warpCascade, psiActive)
	overhead := 40 // 20 bytes IPv4 + 20 bytes TCP
	minMSS := tunMinMSS4
	if isIPv6 {
		overhead = 60 // 40 bytes IPv6 + 20 bytes TCP
		minMSS = tunMinMSS6
	}
	if psiActive {
		overhead += tunCascadePsiOverhead
	}
	mss := effMTU - overhead
	// Extra safety ceiling for double encapsulation (TUN -> WARP 1280 -> Psiphon)
	if warpCascade && psiActive {
		if !isIPv6 && mss > 1180 {
			mss = 1180
		} else if isIPv6 && mss > 1160 {
			mss = 1160
		}
	} else if warpCascade {
		if !isIPv6 && mss > 1220 {
			mss = 1220
		} else if isIPv6 && mss > 1200 {
			mss = 1200
		}
	}
	if mss < minMSS {
		mss = minMSS
	}
	return uint16(mss)
}

// updateTCPChecksum16 incrementally updates a 16-bit one's complement TCP
// checksum (RFC 1624) when a 16-bit word in the TCP header changes from oldVal
// to newVal.
func updateTCPChecksum16(csumBytes []byte, oldVal, newVal uint16) {
	if len(csumBytes) < 2 || oldVal == newVal {
		return
	}
	oldCsum := binary.BigEndian.Uint16(csumBytes)
	// HC' = ~(~HC + ~m + m') in 1's complement arithmetic
	hc := uint32(^oldCsum)
	m := uint32(^oldVal)
	mp := uint32(newVal)
	sum := hc + m + mp
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	newCsum := ^uint16(sum)
	binary.BigEndian.PutUint16(csumBytes, newCsum)
}

// clampTCPMSS inspects a raw IPv4 or IPv6 packet and, if it is a TCP SYN or
// SYN+ACK segment carrying an MSS option (kind=2, len=4) larger than the
// allowed ceiling (maxMSS4 / maxMSS6), rewrites the MSS in-place and updates
// the TCP checksum incrementally. Returns true if the packet was modified.
func clampTCPMSS(pkt []byte, maxMSS4, maxMSS6 uint16) bool {
	if len(pkt) < 40 {
		return false
	}
	var tcpOff int
	var maxMSS uint16
	switch pkt[0] >> 4 {
	case 4:
		if maxMSS4 == 0 {
			return false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+20 || pkt[9] != 6 {
			return false
		}
		// Skip non-initial IPv4 fragments (fragment offset != 0)
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
			return false
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen < ihl+20 || totalLen > len(pkt) {
			return false
		}
		pkt = pkt[:totalLen]
		tcpOff = ihl
		maxMSS = maxMSS4
	case 6:
		if maxMSS6 == 0 || len(pkt) < 60 {
			return false
		}
		// Jumbograms require parsing a Jumbo Payload option and are not
		// supported here. Never interpret trailing buffer bytes as TCP data.
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if payloadLen < 20 || 40+payloadLen > len(pkt) {
			return false
		}
		pkt = pkt[:40+payloadLen]
		nxt := pkt[6]
		off := 40
		// Skip common IPv6 extension headers (Hop-by-Hop=0, Routing=43, DestOpts=60)
		for ext := 0; ext < 4 && (nxt == 0 || nxt == 43 || nxt == 60); ext++ {
			if off+2 > len(pkt) {
				return false
			}
			hdrLen := (int(pkt[off+1]) + 1) * 8
			nxt = pkt[off]
			off += hdrLen
		}
		if nxt != 6 || len(pkt) < off+20 {
			return false
		}
		tcpOff = off
		maxMSS = maxMSS6
	default:
		return false
	}

	tcpHdr := pkt[tcpOff:]
	// Check TCP SYN flag (bit 1 of byte 13)
	if tcpHdr[13]&0x02 == 0 {
		return false
	}
	dataOff := int(tcpHdr[12]>>4) * 4
	if dataOff <= 20 || len(tcpHdr) < dataOff {
		return false
	}
	opts := tcpHdr[20:dataOff]
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 { // End of Option List
			break
		}
		if kind == 1 { // NOP
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			break
		}
		if kind == 2 && optLen == 4 {
			curMSS := binary.BigEndian.Uint16(opts[i+2 : i+4])
			if curMSS > maxMSS {
				binary.BigEndian.PutUint16(opts[i+2:i+4], maxMSS)
				updateTCPChecksum16(tcpHdr[16:18], curMSS, maxMSS)
				return true
			}
			return false
		}
		i += optLen
	}
	return false
}

func isLoopbackTargetAddr(address string) bool {
	if address == "" {
		return false
	}
	h := address
	if host, _, err := net.SplitHostPort(address); err == nil {
		h = host
	}
	h = strings.Trim(strings.TrimSpace(h), "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.IsLoopback()
	}
	return false
}

// directControl is set as net.Dialer.Control / ListenConfig.Control on every
// direct outbound socket of Psiroute. Loopback targets (127.0.0.1 / ::1) are
// never pinned to the physical adapter so local tests and local services work.
func directControl(network, address string, c syscall.RawConn) error {
	if !tunActive.Load() || isLoopbackTargetAddr(address) {
		return nil
	}
	return bindPhys(network, address, c)
}

func tunDialBound(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: directControl}
	return d.DialContext(ctx, network, addr)
}

// listenUDPDirect replaces net.ListenUDP("udp", nil) for outbound UDP.
func listenUDPDirect() (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: directControl}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	if u, ok := pc.(*net.UDPConn); ok {
		return u, nil
	}
	pc.Close()
	return nil, errors.New("udp: неожиданный тип сокета")
}

// listenUDPDirectFor opens an outbound UDP socket appropriate for dstIP.
// When dstIP is loopback (e.g. 127.0.0.1 in tests or local services), it binds
// without IP_UNICAST_IF so Windows routes loopback datagrams properly.
func listenUDPDirectFor(dstIP net.IP) (*net.UDPConn, error) {
	if dstIP != nil && dstIP.IsLoopback() {
		netw := "udp"
		if dstIP.To4() != nil {
			netw = "udp4"
		}
		return net.ListenUDP(netw, nil)
	}
	return listenUDPDirect()
}

func tunPhysIdx(ip netip.Addr) uint32 {
	if ip.Is4() {
		return physIdx4.Load()
	}
	return physIdx6.Load()
}

func tunPhysText() string {
	if s, _ := physAlias.Load().(string); s != "" {
		return s
	}
	return "—"
}

func tunErrText(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errNeedAdmin) {
		return "Для режима TUN нужны права администратора — нажмите «Перезапустить от администратора»"
	}
	return err.Error()
}

func tunInternal(ip netip.Addr) bool { return tunNet4.Contains(ip) || tunNet6.Contains(ip) }

// tunUDPTarget drops multicast and broadcast: they never leave the LAN.
func tunUDPTarget(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return !(ip.Is4() && ip.As4() == [4]byte{255, 255, 255, 255})
}

var tunSelfExe = func() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Base(p)
}()

// isSelfProc: Psiroute itself, its Psiphon, WARP, country workers and the
// probe. Their traffic goes straight to the real adapter, never to Psiphon.
func isSelfProc(pid uint32, name string) bool {
	if pid == 0 {
		return false
	}
	if int(pid) == os.Getpid() {
		return true
	}
	return name != "" && tunSelfExe != "" && strings.EqualFold(name, tunSelfExe)
}

func tunSplitApps(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func tunAppMatch(app string, list []string) bool {
	if app == "" {
		return false
	}
	a := strings.TrimSuffix(strings.ToLower(app), ".exe")
	for _, x := range list {
		if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(x)), ".exe") == a {
			return true
		}
	}
	return false
}

// ---------- sniffing ----------

var tunHTTPMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

func tunLooksHTTP(b []byte) bool {
	for _, m := range tunHTTPMethods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

func tunCleanHost(h string) string {
	h = strings.Trim(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), "."), "[]")
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\\x00") {
		return ""
	}
	return h
}

// sniffHost returns the TLS SNI or the HTTP Host of the first client bytes.
func sniffHost(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if b[0] == 0x16 {
		return tunCleanHost(parseSNI(b))
	}
	if !tunLooksHTTP(b) {
		return ""
	}
	lines := bytes.Split(b, []byte("\r\n"))
	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		if len(line) > 5 && strings.EqualFold(string(line[:5]), "host:") {
			h := strings.TrimSpace(string(line[5:]))
			if hh, _, err := net.SplitHostPort(h); err == nil {
				h = hh
			}
			return tunCleanHost(h)
		}
	}
	return ""
}

// sniffWantMore: the ClientHello or the HTTP headers are not complete yet.
func sniffWantMore(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if b[0] == 0x16 {
		if len(b) < 5 {
			return true
		}
		need := 5 + (int(b[3])<<8 | int(b[4]))
		return len(b) < need && len(b) < 16<<10
	}
	if tunLooksHTTP(b) {
		return !bytes.Contains(b, []byte("\r\n\r\n")) && len(b) < 8<<10
	}
	return false
}

// tunServerFirst: protocols where the server speaks first, waiting for the
// client would only add delay.
func tunServerFirst(port int) bool {
	switch port {
	case 21, 22, 23, 25, 110, 143, 587, 3306:
		return true
	}
	return false
}

// ---------- reverse DNS map: IP -> domain from our own DNS answers ----------

type revEntry struct {
	name string
	exp  time.Time
}

type revMap struct {
	mu sync.Mutex
	m  map[netip.Addr]revEntry
}

func (r *revMap) clear() {
	r.mu.Lock()
	r.m = nil
	r.mu.Unlock()
}

func (r *revMap) prune() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m) == 0 {
		return
	}
	for k, v := range r.m {
		if now.After(v.exp) {
			delete(r.m, k)
		}
	}
}

func (r *revMap) put(ip net.IP, name string, ttl time.Duration) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok || name == "" {
		return
	}
	a = a.Unmap()
	now := time.Now()
	name = strings.Clone(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[netip.Addr]revEntry{}
	}
	if len(r.m) > 8192 {
		for k, v := range r.m {
			if now.After(v.exp) {
				delete(r.m, k)
			}
		}
		if len(r.m) > 8192 {
			r.m = map[netip.Addr]revEntry{}
		}
	}
	r.m[a] = revEntry{name, now.Add(ttl)}
}

func (r *revMap) get(a netip.Addr) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[a.Unmap()]
	if !ok || time.Now().After(e.exp) {
		return ""
	}
	return e.name
}

// ---------- DNS helpers ----------

// dnsQName returns the first question name and the offset right after the
// question (end < 0: not a valid query).
func dnsQName(q []byte) (name string, end int) {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:]) == 0 {
		return "", -1
	}
	off := 12
	var sb strings.Builder
	for {
		if off >= len(q) {
			return "", -1
		}
		l := int(q[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(q) {
			return "", -1
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(q[off : off+l])
		off += l
	}
	if off+4 > len(q) {
		return "", -1
	}
	return strings.ToLower(sb.String()), off + 4
}

// dnsServfail builds a SERVFAIL answer so programs do not wait for a timeout.
func dnsServfail(q []byte) []byte {
	_, end := dnsQName(q)
	if end < 0 {
		return nil
	}
	r := append([]byte(nil), q[:end]...)
	r[2] = q[2]&0x79 | 0x80 // QR, keep opcode and RD
	r[3] = 0x80 | 2         // RA, SERVFAIL
	binary.BigEndian.PutUint16(r[4:], 1)
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	return r
}
