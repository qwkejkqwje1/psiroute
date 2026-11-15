package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Encrypted DNS: direct connections resolve names over DoH (Cloudflare / Google
// by IP) so DNS spoofing by the ISP does not break them. Falls back to the
// system resolver. Also provides DNS TXT lookup over DoH/wire-format and
// Ed25519 signature verification for emergency bootstrap of Psiphon server
// entries and ECH configs during network shutdowns (Priority 4).

const dnsTypeTXT uint16 = 16

// Default Ed25519 public key (hex) for verifying signed mirror / DNS TXT payloads.
const defaultBootstrapEd25519PubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

type dnsEntry struct {
	ips []string
	exp time.Time
}

type dnsCache struct {
	mu sync.Mutex
	m  map[string]dnsEntry
}

var theDNS = &dnsCache{m: map[string]dnsEntry{}}

// dnsTXTLookupHook allows unit tests to inject deterministic DNS TXT records
// without external network calls.
var (
	dnsTXTHookMu     sync.RWMutex
	dnsTXTLookupHook func(ctx context.Context, domain string) ([]string, error)
)

func setDNSTXTLookupHook(fn func(ctx context.Context, domain string) ([]string, error)) {
	dnsTXTHookMu.Lock()
	dnsTXTLookupHook = fn
	dnsTXTHookMu.Unlock()
}

func getDNSTXTLookupHook() func(ctx context.Context, domain string) ([]string, error) {
	dnsTXTHookMu.RLock()
	defer dnsTXTHookMu.RUnlock()
	return dnsTXTLookupHook
}

func (d *dnsCache) clear() {
	d.mu.Lock()
	d.m = map[string]dnsEntry{}
	d.mu.Unlock()
	theDoHWire.clear()
	theRevDNS.clear()
	theFakeIP.clear()
	theECHCache.clear()
}

func (d *dnsCache) prune() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.m) == 0 {
		return
	}
	for k, v := range d.m {
		if now.After(v.exp) {
			delete(d.m, k)
		}
	}
}

// cachedIPs returns the already-cached IP addresses for host without
// performing any network lookup.
func (d *dnsCache) cachedIPs(host string) []net.IP {
	d.mu.Lock()
	e, ok := d.m[host]
	d.mu.Unlock()
	if !ok || len(e.ips) == 0 || time.Now().After(e.exp) {
		return nil
	}
	out := make([]net.IP, 0, len(e.ips))
	for _, s := range e.ips {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

var dohClient = &http.Client{
	Timeout: 6 * time.Second,
	Transport: &http.Transport{
		DialContext:         dialDesync,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     45 * time.Second,
	},
}

var dohJSONEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://1.0.0.1/dns-query",
	"https://8.8.8.8/resolve",
}

func dohLookup(ctx context.Context, host string) ([]string, error) {
	var lastErr error
	for _, base := range dohJSONEndpoints {
		u := base + "?name=" + url.QueryEscape(host) + "&type=A"
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("accept", "application/dns-json")
		resp, err := dohClient.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("DoH: HTTP %d", resp.StatusCode)
			continue
		}
		var r struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(&r)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		var ips []string
		for _, a := range r.Answer {
			if a.Type == 1 && net.ParseIP(a.Data) != nil {
				ips = append(ips, strings.Clone(a.Data))
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
		lastErr = errors.New("DoH: нет адресов")
	}
	if lastErr == nil {
		lastErr = errors.New("DoH: нет адресов")
	}
	return nil, lastErr
}

// ---------- DNS TXT Lookup & Signed Mirror Helpers (Priority 4) ----------

// parseDNSTXTWire extracts TXT strings (RRType 16) from a DNS wire-format response.
func parseDNSTXTWire(msg []byte) ([]string, error) {
	if len(msg) < 12 {
		return nil, errDNSShort
	}
	if rc := msg[3] & 0x0f; rc != 0 {
		return nil, fmt.Errorf("DNS TXT: код ответа %d", rc)
	}
	qd, an := int(binary.BigEndian.Uint16(msg[4:6])), int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for range qd {
		if off = dnsSkipName(msg, off); off < 0 || off+4 > len(msg) {
			return nil, errDNSShort
		}
		off += 4
	}
	var out []string
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
		if typ != dnsTypeTXT || len(rdata) == 0 {
			continue
		}
		var sb strings.Builder
		for p := 0; p < len(rdata); {
			slen := int(rdata[p])
			p++
			if p+slen > len(rdata) {
				break
			}
			sb.Write(rdata[p : p+slen])
			p += slen
		}
		if sb.Len() > 0 {
			out = append(out, sb.String())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("DNS TXT: нет записей")
	}
	return out, nil
}

// cleanJSONTXT unquotes a TXT string returned by DoH JSON endpoints.
func cleanJSONTXT(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, `" "`, "")
	s = strings.Trim(s, `"`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	return strings.TrimSpace(s)
}

// dohLookupTXT queries DoH JSON endpoints for TXT (type 16) records of domain.
func dohLookupTXT(ctx context.Context, domain string) ([]string, error) {
	if fn := getDNSTXTLookupHook(); fn != nil {
		return fn(ctx, domain)
	}
	var lastErr error
	for _, base := range dohJSONEndpoints {
		u := base + "?name=" + url.QueryEscape(domain) + "&type=TXT"
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("accept", "application/dns-json")
		resp, err := dohClient.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("DoH TXT: HTTP %d", resp.StatusCode)
			continue
		}
		var r struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		var txts []string
		for _, a := range r.Answer {
			if a.Type == int(dnsTypeTXT) {
				if v := cleanJSONTXT(a.Data); v != "" {
					txts = append(txts, v)
				}
			}
		}
		if len(txts) > 0 {
			return txts, nil
		}
		lastErr = errors.New("DoH TXT: нет записей")
	}
	if lastErr == nil {
		lastErr = errors.New("DoH TXT: нет записей")
	}
	return nil, lastErr
}

// lookupDNSTXT resolves TXT records for domain using wire-format DoH (direct and
// Psiphon), JSON DoH, and the OS resolver as last resort.
func (a *App) lookupDNSTXT(ctx context.Context, domain string) ([]string, error) {
	domain = cleanHostKey(domain)
	if domain == "" {
		return nil, errors.New("пустое имя домена")
	}
	if fn := getDNSTXTLookupHook(); fn != nil {
		return fn(ctx, domain)
	}
	if a != nil {
		q := dnsQuery(0x7478, domain, dnsTypeTXT)
		for _, via := range []string{obDirect, obPsiphon} {
			if via == obPsiphon && (a.psi == nil || !a.psi.running()) {
				continue
			}
			qctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			resp, err := a.dohExchange(qctx, via, q)
			cancel()
			if err == nil {
				if txts, perr := parseDNSTXTWire(resp); perr == nil && len(txts) > 0 {
					return txts, nil
				}
			}
		}
	}
	if txts, err := dohLookupTXT(ctx, domain); err == nil && len(txts) > 0 {
		return txts, nil
	}
	return net.DefaultResolver.LookupTXT(ctx, domain)
}

// assembleChunkedTXTRecords reassembles multi-record DNS TXT payloads formatted
// as "v=psiroute1;seq=N;data=<chunk>" (ordered by seq) or single-record payloads.
func assembleChunkedTXTRecords(txts []string) string {
	type chunk struct {
		seq  int
		data string
	}
	var chunks []chunk
	var plain []string
	for _, raw := range txts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "seq=") && strings.Contains(raw, "data=") {
			seq := -1
			var d string
			for _, part := range strings.Split(raw, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
				if !ok {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "seq":
					if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
						seq = n
					}
				case "data":
					d = strings.TrimSpace(v)
				}
			}
			if seq >= 0 && d != "" {
				chunks = append(chunks, chunk{seq: seq, data: d})
				continue
			}
		}
		plain = append(plain, raw)
	}
	if len(chunks) > 0 {
		sort.Slice(chunks, func(i, j int) bool { return chunks[i].seq < chunks[j].seq })
		var sb strings.Builder
		for _, c := range chunks {
			sb.WriteString(c.data)
		}
		return sb.String()
	}
	return strings.Join(plain, "\n")
}

// verifySignedBootstrapPayload verifies an Ed25519-signed mirror or DNS TXT
// payload formatted as "sig=<hex_or_b64>;data=<payload>" or JSON
// {"sig":"...","data":"..."}. Returns the verified data string and true on match.
func verifySignedBootstrapPayload(raw string, pubKeyHex string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if pubKeyHex == "" {
		pubKeyHex = defaultBootstrapEd25519PubHex
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return "", false
	}
	pub := ed25519.PublicKey(pubBytes)

	var sigStr, dataStr string
	if strings.HasPrefix(raw, "{") {
		var j struct {
			Sig  string `json:"sig"`
			Data string `json:"data"`
		}
		if json.Unmarshal([]byte(raw), &j) == nil {
			sigStr, dataStr = strings.TrimSpace(j.Sig), strings.TrimSpace(j.Data)
		}
	} else {
		for _, part := range strings.Split(raw, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "sig", "signature":
				sigStr = strings.TrimSpace(v)
			case "data", "payload", "ech", "entries":
				dataStr = strings.TrimSpace(v)
			}
		}
	}
	if sigStr == "" || dataStr == "" {
		return "", false
	}
	sigBytes, err := hex.DecodeString(sigStr)
	if err != nil {
		sigBytes, err = base64.StdEncoding.DecodeString(sigStr)
		if err != nil {
			sigBytes, err = base64.RawURLEncoding.DecodeString(sigStr)
		}
	}
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return "", false
	}
	if !ed25519.Verify(pub, []byte(dataStr), sigBytes) {
		return "", false
	}
	return dataStr, true
}

func resolve(ctx context.Context, host string, useDoH bool) ([]string, error) {
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}
	cleanH := strings.Clone(cleanHostKey(host))
	theDNS.mu.Lock()
	e, ok := theDNS.m[cleanH]
	theDNS.mu.Unlock()
	if ok && time.Now().Before(e.exp) {
		if len(e.ips) == 0 {
			return nil, errors.New("адрес не найден (кэш)")
		}
		return e.ips, nil
	}
	var ips []string
	var err error
	if useDoH {
		ips, err = dohLookup(ctx, cleanH)
		if err != nil {
			logf("debug", "DoH для %s не ответил (%v) — системный DNS", cleanH, err)
		}
	}
	if len(ips) == 0 {
		ips, err = net.DefaultResolver.LookupHost(ctx, cleanH)
	}
	if err == nil && len(ips) == 0 {
		err = errors.New("адрес не найден")
	}
	if err != nil {
		if ctx.Err() == nil { // negative cache: do not hammer DNS for dead names
			theDNS.mu.Lock()
			theDNS.m[cleanH] = dnsEntry{exp: time.Now().Add(30 * time.Second)}
			theDNS.mu.Unlock()
		}
		return nil, err
	}
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil {
			theRevDNS.put(ip, cleanH, 10*time.Minute)
		}
	}
	theDNS.mu.Lock()
	if len(theDNS.m) > 2048 { // cap: drop everything expired, else reset
		now := time.Now()
		for k, v := range theDNS.m {
			if now.After(v.exp) {
				delete(theDNS.m, k)
			}
		}
		if len(theDNS.m) > 2048 {
			theDNS.m = map[string]dnsEntry{}
		}
	}
	theDNS.m[cleanH] = dnsEntry{ips: ips, exp: time.Now().Add(5 * time.Minute)}
	theDNS.mu.Unlock()
	return ips, nil
}
