package main

// Platform-independent helpers for the TUN mode (tun.go): addresses, socket
// binding to the real adapter, dynamic MTU & TCP MSS clamping for the
// TUN -> WARP -> Psiphon cascade, traffic sniffing, QUIC Initial SNI parsing,
// browser DoH IP detection, the reverse DNS map, and reusable packet buffer pools.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
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

// knownPublicDoHIPs содержит публичные IP-адреса встроенных в браузеры и клиенты (Telegram, Chrome)
// DoH-резолверов (Google, Cloudflare, Quad9, Yandex, AdGuard, OpenDNS, NextDNS). Когда включён
// перехват DNS в TUN, блокировка прямых обращений к этим IP на порт 443 заставляет приложения
// мгновенно откатиться на системный DNS (172.19.0.2) и получать FakeIP (Баг 3).
var knownPublicDoHIPs = map[netip.Addr]struct{}{
	netip.MustParseAddr("8.8.8.8"):                {},
	netip.MustParseAddr("8.8.4.4"):                {},
	netip.MustParseAddr("1.1.1.1"):                {},
	netip.MustParseAddr("1.0.0.1"):                {},
	netip.MustParseAddr("1.1.1.2"):                {},
	netip.MustParseAddr("1.0.0.2"):                {},
	netip.MustParseAddr("1.1.1.3"):                {},
	netip.MustParseAddr("1.0.0.3"):                {},
	netip.MustParseAddr("9.9.9.9"):                {},
	netip.MustParseAddr("9.9.9.10"):               {},
	netip.MustParseAddr("9.9.9.11"):               {},
	netip.MustParseAddr("149.112.112.112"):        {},
	netip.MustParseAddr("149.112.112.10"):         {},
	netip.MustParseAddr("149.112.112.11"):         {},
	netip.MustParseAddr("77.88.8.8"):              {},
	netip.MustParseAddr("77.88.8.1"):              {},
	netip.MustParseAddr("77.88.8.2"):              {},
	netip.MustParseAddr("77.88.8.88"):             {},
	netip.MustParseAddr("94.140.14.14"):           {},
	netip.MustParseAddr("94.140.15.15"):           {},
	netip.MustParseAddr("208.67.222.222"):         {},
	netip.MustParseAddr("208.67.220.220"):         {},
	netip.MustParseAddr("45.90.28.0"):             {},
	netip.MustParseAddr("45.90.30.0"):             {},
	netip.MustParseAddr("2001:4860:4860::8888"):   {},
	netip.MustParseAddr("2001:4860:4860::8844"):   {},
	netip.MustParseAddr("2606:4700:4700::1111"):   {},
	netip.MustParseAddr("2606:4700:4700::1001"):   {},
	netip.MustParseAddr("2606:4700:4700::1112"):   {},
	netip.MustParseAddr("2606:4700:4700::1002"):   {},
	netip.MustParseAddr("2620:fe::fe"):            {},
	netip.MustParseAddr("2620:fe::9"):             {},
	netip.MustParseAddr("2a02:6b8::feed:0ff"):     {},
	netip.MustParseAddr("2a02:6b8:0:1::feed:0ff"): {},
	netip.MustParseAddr("2a10:50c0::ad1:ff"):      {},
	netip.MustParseAddr("2a10:50c0::ad2:ff"):      {},
	netip.MustParseAddr("2620:119:35::35"):        {},
	netip.MustParseAddr("2620:119:53::53"):        {},
}

func isKnownPublicDoHIP(ip netip.Addr) bool {
	_, ok := knownPublicDoHIPs[ip.Unmap()]
	return ok
}

var knownPublicDoHHosts = map[string]struct{}{
	"dns.google":                  {},
	"dns.google.com":              {},
	"8888.google":                 {},
	"cloudflare-dns.com":          {},
	"mozilla.cloudflare-dns.com":  {},
	"one.one.one.one":             {},
	"1dot1dot1dot1.cloudflare-dns.com": {},
	"dns.quad9.net":               {},
	"common.dot.dns.yandex.net":   {},
	"dns.adguard-dns.com":         {},
	"dns.adguard.com":             {},
	"doh.opendns.com":             {},
	"dns.nextdns.io":              {},
}

func isKnownPublicDoHHost(host string) bool {
	h := tunCleanHost(host)
	if h == "" {
		return false
	}
	_, ok := knownPublicDoHHosts[h]
	return ok
}

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

func effectiveTunMTUWithClean(configuredMTU int, warpCascade, psiActive, cleanChain bool) int {
	mtu := effectiveTunMTU(configuredMTU, warpCascade, psiActive)
	if cleanChain && mtu > cleanExitWarpMTU {
		mtu = cleanExitWarpMTU
	}
	return mtu
}

func effectiveTunMSSWithClean(configuredMTU int, isIPv6, warpCascade, psiActive, cleanChain bool) uint16 {
	mss := effectiveTunMSS(configuredMTU, isIPv6, warpCascade, psiActive)
	if cleanChain {
		if !isIPv6 && mss > cleanChainMSS4 {
			mss = cleanChainMSS4
		} else if isIPv6 && mss > cleanChainMSS6 {
			mss = cleanChainMSS6
		}
	}
	return mss
}

func updateTCPChecksum16(csumBytes []byte, oldVal, newVal uint16) {
	if len(csumBytes) < 2 || oldVal == newVal {
		return
	}
	oldCsum := binary.BigEndian.Uint16(csumBytes)
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
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if payloadLen < 20 || 40+payloadLen > len(pkt) {
			return false
		}
		pkt = pkt[:40+payloadLen]
		nxt := pkt[6]
		off := 40
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
		if kind == 0 {
			break
		}
		if kind == 1 {
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

func tunServerFirst(port int) bool {
	switch port {
	case 21, 22, 23, 25, 110, 143, 587, 3306:
		return true
	}
	return false
}

// ---------- QUIC Initial (RFC 9001) SNI Parser ----------

var (
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

func hkdfExtractSHA256(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpandLabelSHA256(prk []byte, label string, outLen int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1)
	binary.BigEndian.PutUint16(info[0:2], uint16(outLen))
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = 0

	var out []byte
	var prev []byte
	counter := byte(1)
	for len(out) < outLen {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:outLen]
}

func readQUICVarInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0
	}
	val := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length
}

// parseQUICInitialSNI расшифровывает первый пакет QUIC Initial (RFC 9001, порт UDP 443)
// стандартными ключами Initial Secret и извлекает TLS SNI из фрейма CRYPTO (Баг 3).
func parseQUICInitialSNI(pkt []byte) string {
	if len(pkt) < 64 || pkt[0]&0xc0 != 0xc0 {
		return ""
	}
	ver := binary.BigEndian.Uint32(pkt[1:5])
	salt := quicSaltV1
	keyLabel, ivLabel, hpLabel := "quic key", "quic iv", "quic hp"
	if ver == 0x6b3343cf { // QUIC v2 (RFC 9369)
		salt = quicSaltV2
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
		if (pkt[0]&0x30)>>4 != 0x01 {
			return ""
		}
	} else if ver == 0x00000001 {
		if (pkt[0]&0x30)>>4 != 0x00 {
			return ""
		}
	} else {
		return ""
	}
	off := 5
	if off >= len(pkt) {
		return ""
	}
	dcidLen := int(pkt[off])
	off++
	if dcidLen > 20 || off+dcidLen >= len(pkt) {
		return ""
	}
	dcid := pkt[off : off+dcidLen]
	off += dcidLen
	scidLen := int(pkt[off])
	off++
	if scidLen > 20 || off+scidLen >= len(pkt) {
		return ""
	}
	off += scidLen

	tokLen, n := readQUICVarInt(pkt[off:])
	if n == 0 || off+n+int(tokLen) >= len(pkt) {
		return ""
	}
	off += n + int(tokLen)

	remLen, n := readQUICVarInt(pkt[off:])
	if n == 0 || remLen < 20 {
		return ""
	}
	off += n
	pnOffset := off
	if pnOffset+4+16 > len(pkt) {
		return ""
	}

	initialSecret := hkdfExtractSHA256(salt, dcid)
	clientSecret := hkdfExpandLabelSHA256(initialSecret, "client in", 32)
	key := hkdfExpandLabelSHA256(clientSecret, keyLabel, 16)
	iv := hkdfExpandLabelSHA256(clientSecret, ivLabel, 12)
	hpKey := hkdfExpandLabelSHA256(clientSecret, hpLabel, 16)

	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return ""
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+20])

	hdr := append([]byte(nil), pkt[:pnOffset+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	if pnOffset+pnLen+16 > len(pkt) || int(remLen) < pnLen+16 {
		return ""
	}
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		pn = (pn << 8) | uint64(hdr[pnOffset+i])
	}

	cipherLen := int(remLen) - pnLen
	if pnOffset+pnLen+cipherLen > len(pkt) {
		cipherLen = len(pkt) - (pnOffset + pnLen)
	}
	if cipherLen < 16 {
		return ""
	}

	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	aeadBlk, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	aead, err := cipher.NewGCM(aeadBlk)
	if err != nil {
		return ""
	}
	plain, err := aead.Open(nil, nonce, pkt[pnOffset+pnLen:pnOffset+pnLen+cipherLen], hdr[:pnOffset+pnLen])
	if err != nil {
		return ""
	}

	// Сборка CRYPTO-фреймов (тип 0x06) и передача в parseSNI (обёрнуто в TLS record 0x16)
	cryptoBuf := make([]byte, 4096)
	maxEnd := 0
	for i := 0; i < len(plain); {
		ft := plain[i]
		i++
		if ft == 0x00 || ft == 0x01 { // PADDING or PING
			continue
		}
		if ft == 0x06 { // CRYPTO frame
			cOff, n1 := readQUICVarInt(plain[i:])
			if n1 == 0 {
				break
			}
			i += n1
			cLen, n2 := readQUICVarInt(plain[i:])
			if n2 == 0 || i+n2+int(cLen) > len(plain) {
				break
			}
			i += n2
			data := plain[i : i+int(cLen)]
			i += int(cLen)
			end := int(cOff) + len(data)
			if end <= len(cryptoBuf) {
				copy(cryptoBuf[int(cOff):end], data)
				if end > maxEnd {
					maxEnd = end
				}
			}
			continue
		}
		break
	}
	if maxEnd < 32 || cryptoBuf[0] != 0x01 { // HandshakeType ClientHello = 1
		return ""
	}
	tlsRec := make([]byte, 5+maxEnd)
	tlsRec[0] = 0x16
	tlsRec[1] = 0x03
	tlsRec[2] = 0x01
	binary.BigEndian.PutUint16(tlsRec[3:5], uint16(maxEnd))
	copy(tlsRec[5:], cryptoBuf[:maxEnd])
	return tunCleanHost(parseSNI(tlsRec))
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
	if ip == nil || ip.IsLoopback() {
		return
	}
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

// isVirtualVPNAdapterName reports whether a network adapter alias or description
// belongs to a virtual VPN/TUN/TAP/WireGuard interface (e.g., left behind by
// Clash, Sing-box, Amnezia, WARP, v2rayN, OpenVPN, Tailscale, ZeroTier, etc.).
func isVirtualVPNAdapterName(alias, desc string) bool {
	s := strings.ToLower(alias + " " + desc)
	for _, kw := range []string{
		"psiroute", "wintun", "wireguard", "amnezia", "cloudflare", "warp",
		"sing-tun", "sing-box", "clash", "mihomo", "v2ray", "xray", "nekoray",
		"hiddify", "outline", "openvpn", "tap-windows", "tailscale", "zerotier",
		"radmin", "hamachi", "nordlynx", "proton", "mullvad", "utun", "tun0",
		"virtualbox", "vmware", "vethernet", "hyper-v", "loopback",
	} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}
