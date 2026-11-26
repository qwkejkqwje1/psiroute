package main

// Built-in Cloudflare WARP as an underlay for Psiphon («Через WARP»): the
// provider sees WireGuard with optional UDP preambles to Cloudflare instead
// of a connection to Psiphon. Preambles do not implement QUIC or MASQUE. Includes a fast parallel Cloudflare Clean IP
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
	License    string `json:"license,omitempty"`  // applied WARP+ license key
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

// warpApplyLicense binds a WARP+ license key to an existing Cloudflare device.
func warpApplyLicense(clients []*http.Client, id *warpIdentity, license string) error {
	license = strings.TrimSpace(license)
	if id == nil || id.ID == "" || id.Token == "" || license == "" {
		return errors.New("неполные данные для активации WARP+")
	}
	b, err := warpAPIDo(clients, "PUT", "/reg/"+id.ID+"/account", id.Token, map[string]string{"license": license})
	if err != nil {
		return err
	}
	var res struct {
		AccountType string `json:"account_type"`
	}
	_ = json.Unmarshal(b, &res)
	if res.AccountType != "" {
		id.Account = res.AccountType
	} else {
		id.Account = "plus"
	}
	id.License = license
	return nil
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
	RTT      time.Duration `json:"rtt"` // Includes tunnel setup, handshake and TCP probe; retained JSON field for compatibility.
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

// probeWarpTunnel verifies usable traffic through an authenticated WireGuard
// tunnel. Unauthenticated UDP replies cannot establish WARP availability.
func probeWarpTunnel(ctx context.Context, id *warpIdentity, mask warpMask, addr string, timeout time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if id == nil {
		return 0, errors.New("WARP identity is required")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	tunnel, err := openWarpTunnel(id, addr, mask)
	if err != nil {
		return 0, err
	}
	defer tunnel.Close()
	if err := tunnel.probe(ctx); err != nil {
		return 0, err
	}
	hs, _, _ := tunnel.stats()
	if hs.IsZero() {
		return 0, errors.New("WARP handshake not confirmed")
	}
	return time.Since(started), nil
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
	return s.scanWithProbe(ctx, targets, concurrency, timeout, pfn)
}

func (s *warpCleanScanner) scanWithProbe(ctx context.Context, targets []string, concurrency int, timeout time.Duration, pfn func(context.Context, string, time.Duration) (time.Duration, error)) []warpCleanResult {
	if pfn == nil {
		return nil
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
		func(endpoint string) { safeGo("warpCleanScanner.scanWithProbe", func() {
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
		}) }(ep)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}

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
		logf("info", "WARP: проверено %d туннелей Cloudflare (лучший: %s, установка и TCP-проверка %d мс)",
			len(found), found[0].Endpoint, found[0].RTT.Milliseconds())
	}
	return found
}

// EnsureScanned verifies endpoints serially when the authenticated cache expires.
func (s *warpCleanScanner) EnsureScanned(ctx context.Context, id *warpIdentity, mask warpMask) []string {
	if cached := s.cachedEndpoints(); len(cached) > 0 {
		return cached
	}
	sctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	// Cloudflare allows one active session per identity; serial probes avoid
	// replacing each other's peer sessions. Include both endpoint families.
	targets := generateWarpScanTargets(4)
	targets = append(targets, warpCleanIPv6Seeds[:min(2, len(warpCleanIPv6Seeds))]...)
	res := s.scanWithProbe(sctx, targets, 1, 750*time.Millisecond, func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
		return probeWarpTunnel(ctx, id, mask, addr, timeout)
	})
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.Endpoint)
	}
	return out
}
