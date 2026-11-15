package main

// Built-in Cloudflare WARP as an underlay for Psiphon («Через WARP»): the
// provider sees a WireGuard/QUIC/MASQUE flow to Cloudflare instead of a
// connection to Psiphon. Includes a fast parallel Cloudflare Clean IP
// Auto-Scanner and I1–I5 multi-packet CPS masking (Priority 2).

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	warpAPI          = "https://api.cloudflareclient.com/v0a4005"
	warpMTU          = 1280             // WARP's own MTU
	warpIdle         = 10 * time.Minute // unused this long: the tunnel closes
	warpSearch       = 30 * time.Second // search for a node abroad once a tunnel works
	warpScanCacheTTL = 25 * time.Minute // TTL for auto-scanned clean Cloudflare IPs
	warpScanTimeout  = 750 * time.Millisecond
)

var warpHeaders = map[string]string{"User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.30-3596"}

// ---------- device (warp-identity.json in the data directory) ----------

type warpIdentity struct {
	PrivateKey string `json:"private_key"`
	ID         string `json:"id"`
	Token      string `json:"token"`
	ClientID   string `json:"client_id"`
	V4         string `json:"v4"`
	V6         string `json:"v6"`
	PeerKey    string `json:"peer_public_key"`
	PeerHost   string `json:"peer_host"`
	Account    string `json:"account_type"`
	Endpoint   string `json:"endpoint,omitempty"` // the endpoint that worked last
	Colo       string `json:"colo,omitempty"`     // its data center
	Mask       string `json:"mask,omitempty"`     // the masking that worked
	Created    int64  `json:"created"`
}

type warpRegResp struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
	Account struct {
		AccountType string `json:"account_type"`
	} `json:"account"`
}

func loadWarpIdentity(path string) (*warpIdentity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var id warpIdentity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, err
	}
	if id.PrivateKey == "" || id.PeerKey == "" || id.V4 == "" {
		return nil, errors.New("неполные данные WARP")
	}
	return &id, nil
}

func saveWarpIdentity(path string, id *warpIdentity) error {
	b, _ := json.MarshalIndent(id, "", "  ")
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// warpAPIDo calls the registration API through the first client that
// reaches it.
func warpAPIDo(clients []*http.Client, method, path, token string, body any) ([]byte, error) {
	var last error
	for i, c := range clients {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, warpAPI+path, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		for k, v := range warpHeaders {
			req.Header.Set(k, v)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.Do(req)
		if err != nil {
			last = err
			if i == 0 && len(clients) > 1 {
				logf("warn", "WARP: API Cloudflare напрямую недоступен (%s), пробую в обход", short(err.Error(), 120))
			}
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("API Cloudflare: %s: %.200s", resp.Status, b)
		}
		return b, nil
	}
	return nil, fmt.Errorf("API Cloudflare недоступен: %w", last)
}

// warpRegister creates a free WARP device.
func warpRegister(clients []*http.Client) (*warpIdentity, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"install_id": "", "fcm_token": "", "tos": time.Now().UTC().Format(time.RFC3339Nano),
		"key":  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		"type": "Android", "model": "PC", "locale": "en_US", "warp_enabled": true,
	}
	b, err := warpAPIDo(clients, "POST", "/reg", "", body)
	if err != nil {
		return nil, err
	}
	var r warpRegResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if len(r.Config.Peers) == 0 || r.Config.Interface.Addresses.V4 == "" {
		return nil, errors.New("API Cloudflare вернул неполные данные")
	}
	return &warpIdentity{
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()), ID: r.ID, Token: r.Token,
		ClientID: r.Config.ClientID, V4: r.Config.Interface.Addresses.V4, V6: r.Config.Interface.Addresses.V6,
		PeerKey: r.Config.Peers[0].PublicKey, PeerHost: r.Config.Peers[0].Endpoint.Host,
		Account: r.Account.AccountType, Created: time.Now().Unix(),
	}, nil
}

// ---------- handshake masking (I1–I5 CPS chain + MASQUE HTTP/3 & ECH) ----------

// warpMask is a masking preset: a multi-packet signature chain (I1..I5) and
// junk packets sent before every handshake so that the flow looks like
// legitimate QUIC / MASQUE HTTP/3 / DNS / STUN traffic rather than WireGuard.
type warpMask struct {
	ID, Title          string
	I1, I2, I3, I4, I5 string // signature packet chain, AmneziaWG 1.5/2.0 syntax ("" = none)
	Jc, Jmin, Jmax     int    // junk packets and their size range
}

// warpMaskOrder is what "auto" tries, after the masking that worked last.
var warpMaskOrder = []string{"quic", "masque", "bwg", "dns", "off"}

func makeWarpMask(id string) (warpMask, error) {
	switch id {
	case "quic":
		i1, i2, i3, i4, i5, _, err := genI1Chain("quic", "www.google.com")
		return warpMask{
			ID: id, Title: "QUIC + ECH (I1–I5 HTTP/3 к www.google.com)",
			I1: i1, I2: i2, I3: i3, I4: i4, I5: i5,
			Jc: 4, Jmin: 40, Jmax: 70,
		}, err
	case "masque":
		i1, i2, i3, i4, i5, _, err := genI1Chain("masque", "consumer-masque.cloudflareclient.com")
		return warpMask{
			ID: id, Title: "MASQUE HTTP/3 (CONNECT-UDP Cloudflare + ECH, I1–I5)",
			I1: i1, I2: i2, I3: i3, I4: i4, I5: i5,
			Jc: 6, Jmin: 64, Jmax: 192,
		}, err
	case "bwg":
		return warpMask{
			ID: id, Title: "как в bash-warp-generator (I1–I5)",
			I1: bwgI1, I2: bwgI2, I3: bwgI3, I4: bwgI4, I5: bwgI5,
			Jc: 120, Jmin: 23, Jmax: 911,
		}, nil
	case "dns":
		i1, i2, i3, i4, i5, _, err := genI1Chain("dns", "icloud.com")
		return warpMask{
			ID: id, Title: "DNS + HTTPS/ECH цепочка (I1–I5)",
			I1: i1, I2: i2, I3: i3, I4: i4, I5: i5,
			Jc: 6, Jmin: 10, Jmax: 50,
		}, err
	case "off":
		return warpMask{ID: id, Title: "без маскировки"}, nil
	}
	return warpMask{}, fmt.Errorf("неизвестная маскировка %q", id)
}

// warpSigPart is one tag of a signature packet: <b 0x…> bytes, <r N> random
// bytes, <rc N> random letters, <rd N> random digits, <t> unix time, <c> the
// packet counter.
type warpSigPart struct {
	kind string
	data []byte
	n    int
}

func parseWarpSig(s string) ([]warpSigPart, error) {
	var parts []warpSigPart
	s = strings.TrimSpace(s)
	for s != "" {
		if s[0] != '<' {
			return nil, fmt.Errorf("подпись: ожидался тег, а не %.20q", s)
		}
		end := strings.IndexByte(s, '>')
		if end < 0 {
			return nil, errors.New("подпись: тег не закрыт")
		}
		f := strings.Fields(s[1:end])
		s = strings.TrimSpace(s[end+1:])
		if len(f) == 0 {
			return nil, errors.New("подпись: пустой тег")
		}
		p := warpSigPart{kind: f[0]}
		switch f[0] {
		case "b":
			if len(f) != 2 {
				return nil, errors.New("подпись: <b> без данных")
			}
			b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(f[1], "0x"), "0X"))
			if err != nil {
				return nil, fmt.Errorf("подпись: %w", err)
			}
			p.data = b
		case "r", "rc", "rd":
			n := -1
			if len(f) == 2 {
				if v, err := strconv.Atoi(f[1]); err == nil {
					n = v
				}
			}
			if n < 0 || n > 1400 {
				return nil, fmt.Errorf("подпись: неверная длина в <%s>", strings.Join(f, " "))
			}
			p.n = n
		case "t", "c":
		default:
			return nil, fmt.Errorf("подпись: неизвестный тег <%s>", f[0])
		}
		parts = append(parts, p)
	}
	return parts, nil
}

func buildWarpSig(parts []warpSigPart, counter uint32) []byte {
	var out []byte
	for _, p := range parts {
		switch p.kind {
		case "b":
			out = append(out, p.data...)
		case "r":
			b := make([]byte, p.n)
			_, _ = rand.Read(b)
			out = append(out, b...)
		case "rc":
			for range p.n {
				out = append(out, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[mrand.IntN(52)])
			}
		case "rd":
			for range p.n {
				out = append(out, byte('0'+mrand.IntN(10)))
			}
		case "t":
			out = binary.BigEndian.AppendUint32(out, uint32(time.Now().Unix()))
		case "c":
			out = binary.BigEndian.AppendUint32(out, counter)
		}
	}
	return out
}

// ---------- Cloudflare Clean IP Auto-Scanner (Priority 2) ----------

type warpCleanResult struct {
	Endpoint string        `json:"endpoint"`
	RTT      time.Duration `json:"rtt"`
}

type warpCleanScanner struct {
	mu        sync.Mutex
	results   []warpCleanResult
	updatedAt time.Time
	probeFunc func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error)
}

var theWarpScanner = &warpCleanScanner{}

// reset clears cached clean endpoints (used in tests or network switches).
func (s *warpCleanScanner) reset() {
	s.mu.Lock()
	s.results = nil
	s.updatedAt = time.Time{}
	s.mu.Unlock()
}

// cachedEndpoints returns the verified clean Cloudflare endpoints ordered by
// lowest RTT if the cache is still fresh.
func (s *warpCleanScanner) cachedEndpoints() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.results) == 0 || time.Since(s.updatedAt) > warpScanCacheTTL {
		return nil
	}
	out := make([]string, 0, len(s.results))
	for _, r := range s.results {
		out = append(out, r.Endpoint)
	}
	return out
}

// generateScanTargets produces a diverse sample of Cloudflare WARP & MASQUE
// IP:port pairs across all known clean /24 prefixes and ports.
func generateWarpScanTargets(count int) []string {
	if count <= 0 {
		count = 24
	}
	out := make([]string, 0, count)
	seen := make(map[string]bool, count)
	// Always include known primary Anycast seeds on non-standard MASQUE/WARP ports
	seeds := append([]string{
		"162.159.192.1:2408",
		"162.159.193.1:500",
		"162.159.195.1:1701",
		"162.159.204.1:443",
		"188.114.96.1:4500",
		"188.114.97.1:2408",
		"188.114.98.1:854",
		"188.114.99.1:880",
	}, warpCleanIPv6Seeds...)
	for _, ep := range seeds {
		if len(out) >= count {
			break
		}
		seen[ep] = true
		out = append(out, ep)
	}
	for i := 0; len(out) < count && i < count*6; i++ {
		pool := warpCleanScanPools[i%len(warpCleanScanPools)]
		port := warpMasquePorts[(i/len(warpCleanScanPools)+mrand.IntN(len(warpMasquePorts)))%len(warpMasquePorts)]
		hostOctet := 1 + mrand.IntN(254)
		ep := fmt.Sprintf("%s%d:%d", pool, hostOctet, port)
		if _, err := netip.ParseAddrPort(ep); err == nil && !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out
}

// probeWarpCleanUDP sends a QUIC Version Negotiation trigger packet (Long Header
// with version 0x00000000 and 1200 bytes total) or WireGuard initiation probe to
// a Cloudflare endpoint. Cloudflare UDP/QUIC/WARP edge servers respond immediately
// with a QUIC Version Negotiation or WG Cookie/Handshake response, whereas
// blackholed IPs time out.
func probeWarpCleanUDP(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	conn, err := listenUDPDirectFor(uaddr.IP)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	dl := time.Now().Add(timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	_ = conn.SetDeadline(dl)

	// Construct a 1200-byte QUIC v0 probe (triggers instant RFC 9000 Version Negotiation
	// from Cloudflare UDP/MASQUE/QUIC edge servers) plus a 148-byte WireGuard-shaped probe.
	probe := make([]byte, 1200)
	probe[0] = 0xc0 // QUIC Long Header
	// Version 0x00000000 (bytes 1..4) triggers Version Negotiation
	probe[5] = 8 // DCID length
	_, _ = rand.Read(probe[6:14])
	probe[14] = 8 // SCID length
	_, _ = rand.Read(probe[15:23])

	t0 := time.Now()
	if _, err := conn.WriteToUDP(probe, uaddr); err != nil {
		return 0, err
	}
	// Also send a compact 148-byte WireGuard initiation-sized packet with random MACs
	wgProbe := make([]byte, 148)
	wgProbe[0] = 1
	_, _ = rand.Read(wgProbe[4:])
	_, _ = conn.WriteToUDP(wgProbe, uaddr)

	resp := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(resp)
	if err != nil || n == 0 {
		return 0, errors.New("нет UDP-ответа")
	}
	return time.Since(t0), nil
}

// Scan probes candidate Cloudflare endpoints in parallel and caches the fastest
// responding clean IPs sorted by RTT.
func (s *warpCleanScanner) Scan(ctx context.Context, targets []string, concurrency int, timeout time.Duration) []warpCleanResult {
	if len(targets) == 0 {
		targets = generateWarpScanTargets(24)
	}
	if concurrency < 1 {
		concurrency = 12
	}
	if timeout <= 0 {
		timeout = warpScanTimeout
	}
	s.mu.Lock()
	pfn := s.probeFunc
	s.mu.Unlock()
	if pfn == nil {
		pfn = probeWarpCleanUDP
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var found []warpCleanResult

	for _, ep := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			rtt, err := pfn(ctx, endpoint, timeout)
			if err == nil && rtt >= 0 {
				mu.Lock()
				found = append(found, warpCleanResult{Endpoint: endpoint, RTT: rtt})
				mu.Unlock()
			}
		}(ep)
	}
	wg.Wait()

	sort.Slice(found, func(i, j int) bool {
		if found[i].RTT != found[j].RTT {
			return found[i].RTT < found[j].RTT
		}
		return found[i].Endpoint < found[j].Endpoint
	})

	if len(found) > 0 {
		s.mu.Lock()
		s.results = found
		s.updatedAt = time.Now()
		s.mu.Unlock()
		logf("info", "WARP: автосканер нашёл %d чистых IP Cloudflare (лучший: %s, %d мс)",
			len(found), found[0].Endpoint, found[0].RTT.Milliseconds())
	}
	return found
}

// EnsureScanned runs a quick parallel scan if the clean IP cache is empty or expired.
func (s *warpCleanScanner) EnsureScanned(ctx context.Context) []string {
	if cached := s.cachedEndpoints(); len(cached) > 0 {
		return cached
	}
	sctx, cancel := context.WithTimeout(ctx, 1600*time.Millisecond)
	defer cancel()
	res := s.Scan(sctx, generateWarpScanTargets(20), 10, warpScanTimeout)
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.Endpoint)
	}
	return out
}
