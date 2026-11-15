package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// FakeIP (198.18.0.0/15, RFC 2544) and Encrypted ClientHello (ECH, DNS RRType 65
// + DNS TXT / signed mirror fallback, Priority 4) plus an optional local DNS
// server (127.0.0.1:5353).
//
// In TUN mode (and when using the local DNS server), FakeIP hands out a
// synthetic IPv4 address from 198.18.0.1..198.19.255.254 for every queried
// domain. When the application opens a TCP or UDP socket to that synthetic IP,
// Psiroute knows the exact domain name with 100% certainty — even for games,
// voice protocols (Discord/STUN), or non-TLS connections that carry no SNI,
// and even when dozens of domains share a single Cloudflare/CDN IP.

var (
	fakeIPPrefix   = netip.MustParsePrefix("198.18.0.0/15")
	fakeIPv6Prefix = netip.MustParsePrefix("fc00::/7")
)

// browserCanaryDomains перечисляет канареечные домены современных браузеров и ОС:
// возврат NXDOMAIN (RCODE=3) для них заставляет Firefox, Chrome, Edge и Safari
// отключить обходной встроенный DoH/Private Relay и использовать локальный DNS с FakeIP.
var browserCanaryDomains = map[string]bool{
	"use-application-dns.net": true,
	"mask.icloud.com":         true,
	"mask-h2.icloud.com":      true,
	"mask-api.icloud.com":     true,
	"_dns.resolver.arpa":      true,
	" resolver.arpa":          true,
}

func isBrowserCanaryDomain(name string) bool {
	h := cleanHostKey(name)
	if h == "" {
		return false
	}
	if browserCanaryDomains[h] {
		return true
	}
	for k := range browserCanaryDomains {
		if strings.HasSuffix(h, "."+k) {
			return true
		}
	}
	return false
}

// dnsNXDomain формирует DNS-ответ с кодом RCODE=3 (NXDOMAIN) для канареечных доменов браузеров.
func dnsNXDomain(q []byte) []byte {
	_, end := dnsQName(q)
	if end < 4 || end > len(q) {
		return nil
	}
	r := make([]byte, end)
	copy(r, q[:end])
	r[2] = (q[2] & 0x79) | 0x80 // QR=1, AA=0, RD preserved
	r[3] = 0x83                 // RA=1, RCODE=3 (NXDOMAIN)
	binary.BigEndian.PutUint16(r[4:6], 1)
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	return r
}

// dnsNoDataResponse формирует пустой успешный ответ (RCODE=0, ANCOUNT=0) для фильтрации AAAA (BlockAAAA),
// чтобы приложения не уходили в обход туннеля по прямому IPv6 провайдера.
func dnsNoDataResponse(q []byte) []byte {
	_, end := dnsQName(q)
	if end < 4 || end > len(q) {
		return nil
	}
	r := make([]byte, end)
	copy(r, q[:end])
	r[2] = (q[2] & 0x79) | 0x80
	r[3] = 0x80 // RA=1, RCODE=0 (NOERROR)
	binary.BigEndian.PutUint16(r[4:6], 1)
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	return r
}

const (
	fakeIPBase uint32 = 0xc6120001 // 198.18.0.1
	fakeIPMax  uint32 = 0xc613fffe // 198.19.255.254
	fakeIPTTL         = 15 * time.Minute
	fakeIPCap         = 8192
)

type fakeEntry struct {
	domain string
	addr   netip.Addr
	exp    time.Time
}

type fakeIPPool struct {
	mu     sync.Mutex
	next   uint32
	byHost map[string]*fakeEntry
	byAddr map[netip.Addr]*fakeEntry
}

var theFakeIP = &fakeIPPool{
	next:   fakeIPBase,
	byHost: map[string]*fakeEntry{},
	byAddr: map[netip.Addr]*fakeEntry{},
}

func isFakeIP(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	u := a.Unmap()
	if u.Is4() {
		return fakeIPPrefix.Contains(u)
	}
	return fakeIPv6Prefix.Contains(u)
}

// AssignIPv6 выдаёт синтетический IPv6-адрес из ULA-пула fc00::/7 (fd00:7073:6972::xxxx:yyyy),
// связанный с тем же 32-битным индексом FakeIP для 100% атрибуции домена по IPv6.
func (p *fakeIPPool) AssignIPv6(domain string) netip.Addr {
	v4 := p.Assign(domain)
	if !v4.IsValid() {
		return netip.Addr{}
	}
	b4 := v4.As4()
	var b16 [16]byte
	// fd00:7073:6972:0000:0000:0000:c612:xxxx (внутри fc00::/7)
	b16[0] = 0xfd
	b16[1] = 0x00
	b16[2] = 0x70
	b16[3] = 0x73
	b16[4] = 0x69
	b16[5] = 0x72
	copy(b16[12:16], b4[:])
	v6 := netip.AddrFrom16(b16)
	p.mu.Lock()
	p.byAddr[v6] = &fakeEntry{domain: cleanHostKey(domain), addr: v6, exp: time.Now().Add(fakeIPTTL)}
	p.mu.Unlock()
	theRevDNS.put(net.IP(v6.AsSlice()), cleanHostKey(domain), fakeIPTTL)
	return v6
}

func isFakeIPStr(s string) bool {
	a, err := netip.ParseAddr(cleanHostKey(s))
	return err == nil && isFakeIP(a)
}

func (p *fakeIPPool) clear() {
	p.mu.Lock()
	p.byHost = map[string]*fakeEntry{}
	p.byAddr = map[netip.Addr]*fakeEntry{}
	p.next = fakeIPBase
	p.mu.Unlock()
}

// Clear is an exported alias of clear() used by tests and external callers.
func (p *fakeIPPool) Clear() { p.clear() }

// IsFakeIP reports whether a is inside the 198.18.0.0/15 FakeIP pool.
func (p *fakeIPPool) IsFakeIP(a netip.Addr) bool { return isFakeIP(a) }

func (p *fakeIPPool) prune() {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.byHost) == 0 {
		return
	}
	for k, e := range p.byHost {
		if now.After(e.exp) {
			delete(p.byHost, k)
			delete(p.byAddr, e.addr)
		}
	}
}

// Assign returns the synthetic 198.18.x.y address for domain, allocating one
// if needed, and registers it in theRevDNS as well.
func (p *fakeIPPool) Assign(domain string) netip.Addr {
	domain = strings.Clone(cleanHostKey(domain))
	if domain == "" {
		return netip.Addr{}
	}
	now := time.Now()
	p.mu.Lock()
	if e, ok := p.byHost[domain]; ok {
		e.exp = now.Add(fakeIPTTL)
		addr := e.addr
		p.mu.Unlock()
		theRevDNS.put(net.IP(addr.AsSlice()), domain, fakeIPTTL)
		return addr
	}
	if len(p.byHost) >= fakeIPCap {
		for k, e := range p.byHost {
			if now.After(e.exp) {
				delete(p.byHost, k)
				delete(p.byAddr, e.addr)
			}
		}
	}
	raw := p.next
	p.next++
	if p.next > fakeIPMax {
		p.next = fakeIPBase
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], raw)
	addr := netip.AddrFrom4(b)
	if old, ok := p.byAddr[addr]; ok {
		delete(p.byHost, old.domain)
	}
	e := &fakeEntry{domain: domain, addr: addr, exp: now.Add(fakeIPTTL)}
	p.byHost[domain] = e
	p.byAddr[addr] = e
	p.mu.Unlock()
	theRevDNS.put(net.IP(addr.AsSlice()), domain, fakeIPTTL)
	return addr
}

// Lookup returns the domain mapped to a 198.18.x.y FakeIP ("" if unknown/expired).
func (p *fakeIPPool) Lookup(a netip.Addr) string {
	a = a.Unmap()
	if !isFakeIP(a) {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byAddr[a]
	if !ok || time.Now().After(e.exp) {
		return ""
	}
	e.exp = time.Now().Add(fakeIPTTL)
	return e.domain
}

func (p *fakeIPPool) LookupString(s string) string {
	a, err := netip.ParseAddr(cleanHostKey(s))
	if err != nil {
		return ""
	}
	return p.Lookup(a)
}

func (p *fakeIPPool) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byHost)
}

// dnsFakeIPResponse constructs a DNS wire-format response for a FakeIP query.
// For QTYPE=A (1), it returns the 198.18.x.y address with a 60s TTL.
// For QTYPE=AAAA (28), it returns an empty NOERROR (NODATA) response so the
// client immediately connects to the IPv4 FakeIP.
func dnsFakeIPResponse(q []byte, fakeAddr netip.Addr) []byte {
	_, end := dnsQName(q)
	if end < 4 || end > len(q) || !fakeAddr.Is4() {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[end-4 : end-2])
	qclass := binary.BigEndian.Uint16(q[end-2 : end])
	if qclass != 1 || (qtype != 1 && qtype != 28) {
		return nil
	}
	r := make([]byte, end)
	copy(r, q[:end])
	r[2] = (q[2] & 0x79) | 0x80 // QR=1, keep opcode & RD
	r[3] = 0x80                 // RA=1, RCODE=0
	binary.BigEndian.PutUint16(r[4:6], 1)
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	if qtype == 28 {
		// NODATA for AAAA when FakeIP v4 is used
		return r
	}
	// ANCOUNT = 1
	binary.BigEndian.PutUint16(r[6:8], 1)
	ip4 := fakeAddr.As4()
	// Pointer to question name (0xc00c), TYPE=A (1), CLASS=IN (1), TTL=60, RDLENGTH=4, RDATA=ip4
	ans := []byte{
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 60,
		0x00, 0x04,
		ip4[0], ip4[1], ip4[2], ip4[3],
	}
	return append(r, ans...)
}

// ---------- Encrypted ClientHello (ECH) DNS HTTPS (RRType 65) + DNS TXT Fallback ----------

const (
	dnsTypeHTTPS        uint16 = 65
	svcParamKeyECH      uint16 = 5
	echCacheMaxEntries         = 1024
	echCacheTTL                = 15 * time.Minute
)

type echEntry struct {
	config []byte
	exp    time.Time
}

type echCache struct {
	mu sync.Mutex
	m  map[string]echEntry
}

var theECHCache = &echCache{m: map[string]echEntry{}}

func (c *echCache) clear() {
	c.mu.Lock()
	c.m = map[string]echEntry{}
	c.mu.Unlock()
}

func (c *echCache) prune() {
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

// buildSyntheticECHConfigList constructs a valid RFC-formatted ECHConfigList
// (version 0xfe0d, X25519 DHKEM 0x0020, HKDF-SHA256 0x0001, AES-128-GCM 0x0001)
// for publicName, used as a fallback when ISP DPI strips DNS RRType 65 records.
func buildSyntheticECHConfigList(publicName string, cfgID byte) []byte {
	if publicName == "" {
		publicName = "cloudflare-ech.com"
	}
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(0x21 + i*7)
	}
	var content []byte
	content = append(content, cfgID)              // config_id
	content = append(content, 0x00, 0x20)         // kem_id = DHKEM(X25519, HKDF-SHA256)
	content = append(content, 0x00, 0x20)         // public_key length = 32
	content = append(content, pubKey...)          // 32-byte X25519 public key
	content = append(content, 0x00, 0x04)         // cipher_suites length = 4
	content = append(content, 0x00, 0x01, 0x00, 0x01) // KDF=HKDF-SHA256(1), AEAD=AES-128-GCM(1)
	content = append(content, 0x00)               // maximum_name_length = 0
	content = append(content, byte(len(publicName)))
	content = append(content, publicName...)
	content = append(content, 0x00, 0x00) // extensions length = 0

	var cfg []byte
	cfg = append(cfg, 0xfe, 0x0d) // ECH version 0xfe0d
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(content)))
	cfg = append(cfg, content...)

	var list []byte
	list = binary.BigEndian.AppendUint16(list, uint16(len(cfg)))
	list = append(list, cfg...)
	return list
}

// cachedOrFallbackECH returns a cached ECHConfigList for host if available,
// or a fallback ECHConfigList for known Cloudflare / Google / MASQUE hosts.
func cachedOrFallbackECH(host string) []byte {
	host = cleanHostKey(host)
	if host != "" {
		theECHCache.mu.Lock()
		if e, ok := theECHCache.m[host]; ok && time.Now().Before(e.exp) && len(e.config) > 0 {
			theECHCache.mu.Unlock()
			return e.config
		}
		theECHCache.mu.Unlock()
	}
	if strings.Contains(host, "cloudflare") || strings.Contains(host, "masque") || strings.Contains(host, "discord") {
		return buildSyntheticECHConfigList("cloudflare-ech.com", 0x42)
	}
	if strings.Contains(host, "google") || strings.Contains(host, "youtube") || strings.Contains(host, "gstatic") {
		return buildSyntheticECHConfigList("www.google.com", 0x7a)
	}
	return nil
}

// validateECHConfigList verifies that raw bytes represent a well-formed TLS 1.3
// ECHConfigList (starts with 2-byte total length followed by version 0xfe0d).
func validateECHConfigList(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	// Either a full ECHConfigList (2-byte len + 0xfe0d) or a direct ECHConfig (0xfe0d)
	if b[0] == 0xfe && b[1] == 0x0d {
		return true
	}
	totalLen := int(binary.BigEndian.Uint16(b[0:2]))
	return totalLen > 4 && totalLen+2 <= len(b) && b[2] == 0xfe && b[3] == 0x0d
}

// parseECHFromTXT extracts and validates an ECHConfigList from DNS TXT records
// (supporting signed payloads "sig=...;data=<b64>", "ech=<b64>", or raw base64).
func parseECHFromTXT(txts []string, pubKeyHex string) ([]byte, bool) {
	assembled := assembleChunkedTXTRecords(txts)
	candidates := append([]string{assembled}, txts...)
	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if verified, ok := verifySignedBootstrapPayload(raw, pubKeyHex); ok {
			raw = verified
		}
		if rest, ok := strings.CutPrefix(raw, "ech="); ok {
			raw = strings.TrimSpace(rest)
		} else if rest, ok := strings.CutPrefix(raw, "psiroute-ech:"); ok {
			raw = strings.TrimSpace(rest)
		}
		for _, part := range strings.Split(raw, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(k, "ech") {
				raw = strings.TrimSpace(v)
			}
		}
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && validateECHConfigList(decoded) {
			return decoded, true
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && validateECHConfigList(decoded) {
			return decoded, true
		}
	}
	return nil, false
}

// parseECHFromDNS extracts the ECHConfigList bytes (SvcParamKey=5) from a
// DNS HTTPS (type 65) wire-format response.
func parseECHFromDNS(msg []byte) ([]byte, error) {
	if len(msg) < 12 {
		return nil, errDNSShort
	}
	if rc := msg[3] & 0x0f; rc != 0 {
		return nil, errors.New("DNS HTTPS: rcode != 0")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for range qd {
		if off = dnsSkipName(msg, off); off < 0 || off+4 > len(msg) {
			return nil, errDNSShort
		}
		off += 4
	}
	for range an {
		if off = dnsSkipName(msg, off); off < 0 || off+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdl := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdl > len(msg) {
			break
		}
		rdata := msg[off : off+rdl]
		off += rdl
		if typ != dnsTypeHTTPS || len(rdata) < 3 {
			continue
		}
		// SvcPriority (2 bytes) + TargetName
		p := dnsSkipName(rdata, 2)
		if p < 0 {
			continue
		}
		for p+4 <= len(rdata) {
			key := binary.BigEndian.Uint16(rdata[p : p+2])
			vlen := int(binary.BigEndian.Uint16(rdata[p+2 : p+4]))
			p += 4
			if p+vlen > len(rdata) {
				break
			}
			if key == svcParamKeyECH && vlen > 0 {
				out := make([]byte, vlen)
				copy(out, rdata[p:p+vlen])
				return out, nil
			}
			p += vlen
		}
	}
	return nil, errors.New("ECH config not found")
}

// lookupECH fetches and caches the ECHConfigList for host over DoH (RRType 65),
// falling back to DNS TXT (_ech.<host>) and signed bootstrap ECH configs when
// RRType 65 is blocked or stripped during shutdowns (Priority 4).
func (a *App) lookupECH(ctx context.Context, host string) ([]byte, bool) {
	host = cleanHostKey(host)
	if host == "" || net.ParseIP(host) != nil {
		return nil, false
	}
	theECHCache.mu.Lock()
	if e, ok := theECHCache.m[host]; ok && time.Now().Before(e.exp) {
		theECHCache.mu.Unlock()
		return e.config, len(e.config) > 0
	}
	theECHCache.mu.Unlock()

	q := dnsQuery(0xec48, host, dnsTypeHTTPS)
	var ech []byte
	for _, via := range []string{obDirect, obPsiphon} {
		if via == obPsiphon && (a.psi == nil || !a.psi.running()) {
			continue
		}
		qctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		resp, err := a.dohExchange(qctx, via, q)
		cancel()
		if err == nil {
			if cfg, perr := parseECHFromDNS(resp); perr == nil && len(cfg) > 0 {
				ech = cfg
				break
			}
			break // valid DNS answer without ECH record
		}
	}

	// Fallback 1 (Priority 4): query DNS TXT records (_ech.<host>)
	if len(ech) == 0 {
		for _, txtDom := range []string{"_ech." + host, "ech." + host} {
			tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			txts, err := a.lookupDNSTXT(tctx, txtDom)
			cancel()
			if err == nil && len(txts) > 0 {
				if cfg, ok := parseECHFromTXT(txts, defaultBootstrapEd25519PubHex); ok {
					ech = cfg
					break
				}
			}
		}
	}

	// Fallback 2 (Priority 4): built-in synthetic ECH config for known CDN/MASQUE hosts
	if len(ech) == 0 {
		if fb := cachedOrFallbackECH(host); len(fb) > 0 {
			ech = fb
		}
	}

	theECHCache.mu.Lock()
	if len(theECHCache.m) >= echCacheMaxEntries {
		now := time.Now()
		for k, v := range theECHCache.m {
			if now.After(v.exp) {
				delete(theECHCache.m, k)
			}
		}
		if len(theECHCache.m) >= echCacheMaxEntries {
			theECHCache.m = map[string]echEntry{}
		}
	}
	theECHCache.m[strings.Clone(host)] = echEntry{config: ech, exp: time.Now().Add(echCacheTTL)}
	theECHCache.mu.Unlock()
	return ech, len(ech) > 0
}

// ---------- Local DNS Server (127.0.0.1:5353) ----------

func (a *App) setLocalDNS(on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !on {
		if a.dnsUDP != nil {
			_ = a.dnsUDP.Close()
			a.dnsUDP = nil
		}
		a.cfg.setKey("dns.local_server", false)
		_ = a.cfg.save()
		logf("info", "Локальный DNS-сервер выключен")
		return nil
	}
	if a.dnsUDP != nil {
		return nil
	}
	a.cfg.mu.Lock()
	addr := strings.TrimSpace(a.cfg.DNS.LocalAddr)
	a.cfg.mu.Unlock()
	if addr == "" {
		addr = "127.0.0.1:5353"
	}
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	a.dnsUDP = conn
	a.cfg.setKey("dns.local_server", true)
	_ = a.cfg.save()
	goSafe("локальный DNS", func() { a.serveLocalDNSUDP(conn) })
	logf("info", "Локальный DNS-сервер запущен на %s (DoH + FakeIP)", conn.LocalAddr().String())
	return nil
}

func (a *App) serveLocalDNSUDP(conn *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		goSafe("локальный DNS-запрос", func() {
			resp := a.answerLocalDNS(q)
			if len(resp) > 0 {
				_, _ = conn.WriteToUDP(resp, from)
			}
		})
	}
}

func (a *App) answerLocalDNS(q []byte) []byte {
	name, end := dnsQName(q)
	if end < 4 || name == "" {
		return nil
	}
	// Перехват канареечных доменов DoH браузеров (Firefox use-application-dns.net, Chrome/Edge DDR _dns.resolver.arpa)
	if isBrowserCanaryDomain(name) {
		if nx := dnsNXDomain(q); nx != nil {
			return nx
		}
	}
	qtype := binary.BigEndian.Uint16(q[end-4 : end-2])
	a.cfg.mu.Lock()
	useFake := a.cfg.Tun.FakeIP
	v6On := a.cfg.Tun.IPv6
	a.cfg.mu.Unlock()
	// BlockAAAA при отключённом IPv6: исключаем утечку трафика мимо туннеля по IPv6 провайдера
	if qtype == 28 && !v6On {
		if nodata := dnsNoDataResponse(q); nodata != nil {
			return nodata
		}
	}
	if useFake && !strings.HasSuffix(name, ".arpa") && !strings.HasSuffix(name, ".local") {
		if qtype == 1 || qtype == 28 {
			fip := theFakeIP.Assign(name)
			if resp := dnsFakeIPResponse(q, fip); resp != nil {
				return resp
			}
		}
	}
	id0, id1 := q[0], q[1]
	for _, ob := range []string{obDirect, obPsiphon} {
		if ob == obPsiphon && !a.psi.running() {
			continue
		}
		ctx, cancel := context.WithTimeout(a.ctx, 4*time.Second)
		resp, err := a.dohExchange(ctx, ob, append([]byte(nil), q...))
		cancel()
		if err == nil && len(resp) >= 12 {
			resp[0], resp[1] = id0, id1
			return resp
		}
	}
	return dnsServfail(q)
}
