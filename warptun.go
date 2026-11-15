package main

// The WARP tunnel itself: wireguard-go with the I1–I5 multi-packet masking
// bind, the endpoints to try (including auto-scanned clean Cloudflare IPs)
// and the data centers to avoid.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// warpBind wraps the UDP bind of wireguard-go: it writes the WARP client id
// into the reserved header bytes (and clears them on receive) and sends the
// I1–I5 signature chain + junk packets before every handshake initiation.
type warpBind struct {
	conn.Bind
	reserved           [3]byte
	jc, jmin, jmax     int
	i1, i2, i3, i4, i5 []warpSigPart
	counter            atomic.Uint32
}

func (b *warpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		out[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(bufs, sizes, eps)
			for j := 0; j < n; j++ {
				if sizes[j] >= 4 {
					bufs[j][1], bufs[j][2], bufs[j][3] = 0, 0, 0
				}
			}
			return n, err
		}
	}
	return out, actual, nil
}

func (b *warpBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if len(buf) < 4 {
			continue
		}
		if buf[0] == 1 && len(buf) == device.MessageInitiationSize {
			b.preamble(ep)
		}
		buf[1], buf[2], buf[3] = b.reserved[0], b.reserved[1], b.reserved[2]
	}
	return b.Bind.Send(bufs, ep)
}

// preamble sends the masking before a handshake initiation: the I1..I5
// signature packet sequence, then jc junk packets of jmin..jmax random bytes.
func (b *warpBind) preamble(ep conn.Endpoint) {
	var pkts [][]byte
	for _, sig := range [][]warpSigPart{b.i1, b.i2, b.i3, b.i4, b.i5} {
		if len(sig) > 0 {
			if p := buildWarpSig(sig, b.counter.Add(1)); len(p) > 0 {
				pkts = append(pkts, p)
			}
		}
	}
	for range b.jc {
		n := b.jmin
		if b.jmax > b.jmin {
			n += mrand.IntN(b.jmax - b.jmin + 1)
		}
		p := make([]byte, n)
		_, _ = rand.Read(p)
		pkts = append(pkts, p)
	}
	for _, p := range pkts {
		_ = b.Bind.Send([][]byte{p}, ep)
	}
}

type warpTunnel struct {
	dev  *device.Device
	tnet *netstack.Net
	ep   string // Cloudflare endpoint ip:port
	peer string // the peer's public key, hex
	mask warpMask
	colo string // data center, from the trace
}

func warpHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return "", errors.New("неверный ключ WARP")
	}
	return hex.EncodeToString(b), nil
}

// warpAddr parses an interface address with or without a prefix length.
func warpAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil
}

func warpPeerConf(peer, ep string) string {
	return fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", peer, ep)
}

func openWarpTunnel(id *warpIdentity, ep string, m warpMask) (*warpTunnel, error) {
	parseOpt := func(raw string) ([]warpSigPart, error) {
		if raw == "" {
			return nil, nil
		}
		return parseWarpSig(raw)
	}
	sig1, err := parseOpt(m.I1)
	if err != nil {
		return nil, err
	}
	sig2, err := parseOpt(m.I2)
	if err != nil {
		return nil, err
	}
	sig3, err := parseOpt(m.I3)
	if err != nil {
		return nil, err
	}
	sig4, err := parseOpt(m.I4)
	if err != nil {
		return nil, err
	}
	sig5, err := parseOpt(m.I5)
	if err != nil {
		return nil, err
	}
	priv, err := warpHex(id.PrivateKey)
	if err != nil {
		return nil, err
	}
	peer, err := warpHex(id.PeerKey)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for _, s := range []string{id.V4, id.V6} {
		if a, ok := warpAddr(s); ok {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("у устройства WARP нет адресов")
	}
	dns := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	tdev, tnet, err := netstack.CreateNetTUN(addrs, dns, warpMTU)
	if err != nil {
		return nil, err
	}
	bind := &warpBind{
		Bind: conn.NewDefaultBind(),
		i1:   sig1, i2: sig2, i3: sig3, i4: sig4, i5: sig5,
		jc: m.Jc, jmin: m.Jmin, jmax: m.Jmax,
	}
	if r, err := base64.StdEncoding.DecodeString(id.ClientID); err == nil && len(r) >= 3 {
		copy(bind.reserved[:], r[:3])
	}
	dev := device.NewDevice(tdev, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet("private_key=" + priv + "\n" + warpPeerConf(peer, ep)); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &warpTunnel{dev: dev, tnet: tnet, ep: ep, peer: peer, mask: m}, nil
}

func (t *warpTunnel) Close() { t.dev.Close() }

// dial connects through the tunnel. Names and IPv4 go over IPv4: the
// netstack tries IPv6 first, and that may hang where WARP's IPv6 is broken.
func (t *warpTunnel) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if host, _, err := net.SplitHostPort(addr); err == nil && strings.HasPrefix(network, "tcp") {
		if ip, err := netip.ParseAddr(host); err != nil || ip.Is4() {
			network = "tcp4"
		}
	}
	return t.tnet.DialContext(ctx, network, addr)
}

func (t *warpTunnel) probe(ctx context.Context) error {
	c, err := t.tnet.DialContext(ctx, "tcp4", "1.1.1.1:80")
	if err != nil {
		return err
	}
	return c.Close()
}

// stats: the last handshake and the bytes received and sent on this flow.
func (t *warpTunnel) stats() (hs time.Time, rx, tx int64) {
	s, err := t.dev.IpcGet()
	if err != nil {
		return
	}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "last_handshake_time_sec":
			if n > 0 {
				hs = time.Unix(n, 0)
			}
		case "rx_bytes":
			rx = n
		case "tx_bytes":
			tx = n
		}
	}
	return
}

// refresh opens a new UDP flow (a new source port) and drops the session,
// so the next packet starts a fresh, masked handshake.
func (t *warpTunnel) refresh() error {
	if err := t.dev.IpcSet("listen_port=0\n"); err != nil {
		return err
	}
	return t.dev.IpcSet("public_key=" + t.peer + "\nremove=true\n" + warpPeerConf(t.peer, t.ep))
}

// waitHandshake waits up to d for a handshake made after since.
func (t *warpTunnel) waitHandshake(ctx context.Context, since time.Time, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) && ctx.Err() == nil {
		if hs, _, _ := t.stats(); !hs.IsZero() && !hs.Before(since.Truncate(time.Second)) {
			return true
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	return false
}

// settle re-handshakes on a fresh flow: Cloudflare keeps one session per
// device, so after parallel attempts only the newest one is valid.
func (t *warpTunnel) settle(ctx context.Context) {
	at := time.Now()
	if t.refresh() == nil {
		t.waitHandshake(ctx, at, 5*time.Second)
	}
}

// ---------- endpoints and nodes ----------

var warpPools = warpCleanScanPools

var warpPrimaryPorts = []int{2408, 500, 1701, 4500}

var warpPorts = []int{2408, 500, 1701, 4500, 443, 8443, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886}

func warpRandomEndpoint(ports []int) string {
	return fmt.Sprintf("%s%d:%d", warpPools[mrand.IntN(len(warpPools))], 1+mrand.IntN(254), ports[mrand.IntN(len(ports))])
}

// warpResolve turns host[:port] into ip:port (port 2408 by default).
func warpResolve(ep string) string {
	ep = strings.TrimSpace(ep)
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		host, port = ep, "2408"
	}
	if _, err := netip.ParseAddr(host); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host); err == nil && len(ips) > 0 {
			host = ips[0].String()
		}
	}
	return net.JoinHostPort(host, port)
}

// warpCandidates: the endpoint fixed in the settings, else the one that
// worked last (unless it led to a filtered node), the standard one, the
// auto-scanned clean Cloudflare IPs (ordered by lowest RTT), the registered
// host, and random addresses of Cloudflare's WARP & MASQUE ranges.
func warpCandidates(id *warpIdentity, fixed string) []string {
	if strings.TrimSpace(fixed) != "" {
		return []string{warpResolve(fixed)}
	}
	var out []string
	seen := map[string]bool{}
	add := func(ep string) {
		if _, err := netip.ParseAddrPort(ep); err == nil && !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	if id != nil && warpNodeOK(id.Colo) {
		add(id.Endpoint)
	}
	add("162.159.192.1:2408")
	for _, cleanEP := range theWarpScanner.cachedEndpoints() {
		add(cleanEP)
	}
	if id != nil && id.PeerHost != "" {
		add(warpResolve(id.PeerHost))
	}
	for i := 0; len(out) < 24 && i < 200; i++ {
		add(warpRandomEndpoint(warpPrimaryPorts))
	}
	for i := 0; len(out) < 40 && i < 200; i++ {
		add(warpRandomEndpoint(warpPorts))
	}
	return out
}

// warpFiltered are data centers whose traffic leaves through a national
// filter (since April 2026 the Moscow node is filtered like any Russian
// connection): Psiphon through them meets the same blocking as without WARP.
var warpFiltered = map[string]bool{"DME": true, "SVX": true, "KJA": true, "OVB": true, "KZN": true, "MSQ": true}

func warpNodeOK(colo string) bool { return !warpFiltered[strings.ToUpper(colo)] }
