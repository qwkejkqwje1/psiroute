package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	obCleanIP        = "clean-ip"
	cleanEntryMTU    = 1280 // Outer WARP-1 MTU
	cleanExitWarpMTU = 1200 // Inner WARP-3 MTU (3-layer encryption headroom)
	cleanChainMSS4   = 1140 // Strict TCP MSS ceiling for 3-hop Clean-IP cascade (IPv4)
	cleanChainMSS6   = 1120 // Strict TCP MSS ceiling for 3-hop Clean-IP cascade (IPv6)
)

// ---------- simpleWarpEndpoint (conn.Endpoint) ----------

type simpleWarpEndpoint struct {
	ap netip.AddrPort
}

func (e simpleWarpEndpoint) ClearSrc()           {}
func (e simpleWarpEndpoint) SrcToString() string { return "" }
func (e simpleWarpEndpoint) DstToString() string { return e.ap.String() }
func (e simpleWarpEndpoint) DstToBytes() []byte {
	b, _ := e.ap.MarshalBinary()
	return b
}
func (e simpleWarpEndpoint) DstIP() netip.Addr { return e.ap.Addr() }
func (e simpleWarpEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// ---------- physUDPBind (EntryWarp bound directly to physical NIC via IP_UNICAST_IF) ----------

// physUDPBind implements wireguard-go's conn.Bind while pinning the underlying
// UDP socket to the physical network adapter (bindPhys / IP_UNICAST_IF),
// preventing routing loops through Wintun when TUN mode is enabled.
type physUDPBind struct {
	mu     sync.Mutex
	pc     net.PacketConn
	port   uint16
	closed atomic.Bool
}

func newPhysUDPBind() conn.Bind { return &physUDPBind{} }

// isTransientUDPRecvErr reports whether a ReadFrom error on a shared WireGuard
// UDP socket represents a transient per-packet ICMP or socket error (such as
// Windows WSAECONNRESET / WSAENETRESET / WSAEMSGSIZE after AmneziaWG junk)
// rather than socket closure. Returning such errors to wireguard-go kills
// RoutineReceiveIncoming because net.OpError.Temporary() is false.
func isTransientUDPRecvErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EINTR, syscall.EAGAIN,
			syscall.ECONNRESET, syscall.ENETRESET,
			syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EMSGSIZE,
			10040, // WSAEMSGSIZE
			10051, // WSAENETUNREACH
			10052, // WSAENETRESET
			10054, // WSAECONNRESET
			10055, // WSAENOBUFS
			10065: // WSAEHOSTUNREACH
			return true
		}
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "wsaeconnreset") ||
		strings.Contains(s, "wsaenetreset") ||
		strings.Contains(s, "wsamsgsize") ||
		strings.Contains(s, "message too long") ||
		strings.Contains(s, "unreachable")
}

func (b *physUDPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		_ = b.pc.Close()
		b.pc = nil
	}
	b.closed.Store(false)
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			_ = disableUDPConnResetRaw(c)
			return bindPhys(network, address, c)
		},
	}
	addr := fmt.Sprintf(":%d", port)
	pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil && !tunActive.Load() {
		// Fall back to default UDP socket only when TUN is off so WARP never loops into Wintun.
		lcFallback := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				return disableUDPConnResetRaw(c)
			},
		}
		pc, err = lcFallback.ListenPacket(context.Background(), "udp4", addr)
	}
	if err != nil {
		return nil, 0, err
	}
	b.pc = pc
	actual := port
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		actual = uint16(ua.Port)
	}
	b.port = actual
	rf := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 {
			return 0, nil
		}
		for {
			n, raddr, err := pc.ReadFrom(bufs[0])
			if err != nil {
				if !b.closed.Load() && isTransientUDPRecvErr(err) {
					continue
				}
				return 0, err
			}
			sizes[0] = n
			if ua, ok := raddr.(*net.UDPAddr); ok {
				if ap, ok := netip.AddrFromSlice(ua.IP); ok {
					eps[0] = simpleWarpEndpoint{ap: netip.AddrPortFrom(ap.Unmap(), uint16(ua.Port))}
				}
			}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{rf}, actual, nil
}

func (b *physUDPBind) Close() error {
	b.closed.Store(true)
	b.mu.Lock()
	pc := b.pc
	b.pc = nil
	b.mu.Unlock()
	if pc != nil {
		return pc.Close()
	}
	return nil
}

func (b *physUDPBind) SetMark(uint32) error { return nil }
func (b *physUDPBind) BatchSize() int       { return 1 }

func (b *physUDPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return simpleWarpEndpoint{ap: ap}, nil
}

func (b *physUDPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	se, ok := ep.(simpleWarpEndpoint)
	if !ok {
		ap, err := netip.ParseAddrPort(ep.DstToString())
		if err != nil {
			return err
		}
		se = simpleWarpEndpoint{ap: ap}
	}
	dst := net.UDPAddrFromAddrPort(se.ap)
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

// ---------- udpgwBind (ExitWarp WireGuard UDP encapsulated over Psiphon TCP udpgw) ----------

// udpgwBind encapsulates WireGuard UDP datagrams for the 3rd hop (ExitWarp)
// inside a TCP udpgw stream dialed through the 2nd hop (Psiphon / VLESS),
// enabling WARP -> VPN -> WARP without raw UDP support or a 2nd Windows TUN.
type udpgwBind struct {
	dialHop func(ctx context.Context, network, addr string) (net.Conn, error)

	mu     sync.Mutex
	gw     net.Conn
	br     *bufio.Reader
	writeM sync.Mutex
	conid  uint16
	sent   bool
	closed bool
	stopCh chan struct{}
}

func newUDPGWBind(dialHop func(ctx context.Context, network, addr string) (net.Conn, error)) conn.Bind {
	return &udpgwBind{dialHop: dialHop, conid: 77}
}

func (b *udpgwBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.gw != nil {
		_ = b.gw.Close()
		b.gw = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	gw, err := b.dialHop(ctx, "tcp", udpgwServer)
	cancel()
	if err != nil {
		return nil, 0, fmt.Errorf("ExitWarp udpgw мост: %w", err)
	}
	b.gw = gw
	b.br = bufio.NewReaderSize(gw, 16<<10)
	b.sent = false
	b.closed = false
	stopCh := make(chan struct{})
	b.stopCh = stopCh

	// Periodic udpgw keepalive so the 2nd hop never idles out the ExitWarp stream.
	goSafe("ExitWarp udpgw keepalive", func() {
		tk := time.NewTicker(25 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-tk.C:
				b.writeM.Lock()
				if b.gw != nil {
					_, _ = b.gw.Write(udpgwKeepalive())
				}
				b.writeM.Unlock()
			}
		}
	})

	rf := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 {
			return 0, nil
		}
		tmp := make([]byte, udpgwMaxData+64)
		for {
			b.mu.Lock()
			br := b.br
			closed := b.closed
			b.mu.Unlock()
			if closed || br == nil {
				return 0, net.ErrClosed
			}
			flags, id, ip, rport, data, err := udpgwRead(br, tmp)
			if err != nil {
				return 0, err
			}
			if flags&udpgwFlagKeepalive != 0 || id != b.conid {
				continue
			}
			n := copy(bufs[0], data)
			sizes[0] = n
			if addr, ok := netip.AddrFromSlice(ip); ok {
				eps[0] = simpleWarpEndpoint{ap: netip.AddrPortFrom(addr.Unmap(), uint16(rport))}
			}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{rf}, 1, nil
}

func (b *udpgwBind) Close() error {
	b.mu.Lock()
	if b.stopCh != nil {
		close(b.stopCh)
		b.stopCh = nil
	}
	b.closed = true
	gw := b.gw
	b.gw = nil
	b.br = nil
	b.mu.Unlock()
	if gw != nil {
		return gw.Close()
	}
	return nil
}

func (b *udpgwBind) SetMark(uint32) error { return nil }
func (b *udpgwBind) BatchSize() int       { return 1 }

func (b *udpgwBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return simpleWarpEndpoint{ap: ap}, nil
}

func (b *udpgwBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	gw := b.gw
	closed := b.closed
	b.mu.Unlock()
	if closed || gw == nil {
		return net.ErrClosed
	}
	se, ok := ep.(simpleWarpEndpoint)
	if !ok {
		ap, err := netip.ParseAddrPort(ep.DstToString())
		if err != nil {
			return err
		}
		se = simpleWarpEndpoint{ap: ap}
	}
	ip := net.IP(se.ap.Addr().AsSlice())
	port := int(se.ap.Port())
	b.writeM.Lock()
	defer b.writeM.Unlock()
	for _, pkt := range bufs {
		if len(pkt) == 0 || len(pkt) > udpgwMaxData {
			continue
		}
		var flags byte
		if !b.sent {
			flags = udpgwFlagRebind
			b.sent = true
		}
		frame := udpgwEncode(flags, b.conid, ip, port, pkt)
		if _, err := gw.Write(frame); err != nil {
			return err
		}
	}
	return nil
}

// openWarpTunnelWithBind creates an isolated userspace WireGuard netstack
// instance (zero OS TUN adapters) using an explicit MTU and conn.Bind.
func openWarpTunnelWithBind(id *warpIdentity, ep string, m warpMask, mtu int, baseBind conn.Bind) (*warpTunnel, error) {
	if mtu < 1160 || mtu > 1420 {
		mtu = warpMTU
	}
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
	tdev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, err
	}
	if baseBind == nil {
		baseBind = newPhysUDPBind()
	}
	bind := &warpBind{
		Bind: baseBind,
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

// ---------- CleanChain (WARP -> VPN -> WARP / Adaptive Auto-Chain) ----------

// CleanChain manages the 3rd-hop ExitWarp userspace netstack running over the
// 2nd-hop VPN (Psiphon), producing a clean Cloudflare WARP exit IP for routes
// tagged with outbound "clean-ip".
type CleanChain struct {
	app     *App
	dataDir string

	mu        sync.Mutex
	state     string // "off" | "connecting" | "connected" | "error"
	text      string
	exitIP    string
	exitLoc   string
	exitColo  string
	hopsLabel string
	lastErr    string
	lastVerify map[string]any

	exitTun atomic.Pointer[warpTunnel]
	connectMu sync.Mutex
	testDial  func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newCleanChain(a *App, dataDir string) *CleanChain {
	return &CleanChain{
		app:     a,
		dataDir: dataDir,
		state:   "off",
		text:    "выключен",
	}
}

func (c *CleanChain) Name() string { return obCleanIP }

func (c *CleanChain) Healthy() bool {
	return c != nil && c.exitTun.Load() != nil
}

func (c *CleanChain) exitIDPath() string {
	return filepath.Join(c.dataDir, "warp-exit-identity.json")
}

func (c *CleanChain) enabled() bool {
	if c == nil || c.app == nil || c.app.cfg == nil {
		return false
	}
	c.app.cfg.mu.Lock()
	on := c.app.cfg.CleanChain.Enabled
	c.app.cfg.mu.Unlock()
	return on
}

func (c *CleanChain) autoChain() bool {
	if c == nil || c.app == nil || c.app.cfg == nil {
		return true
	}
	c.app.cfg.mu.Lock()
	ac := c.app.cfg.CleanChain.AutoChain
	c.app.cfg.mu.Unlock()
	return ac
}

// activeHopsLabel describes the current effective hop chain:
//   - "WARP → PSI → WARP" when EntryWarp + Psiphon + ExitWarp are all active
//   - "PSI → WARP" when Auto-Chain bypassed EntryWarp (direct Psiphon works)
func (c *CleanChain) activeHopsLabel() string {
	if c == nil || c.app == nil {
		return "PSI → WARP"
	}
	if c.app.warp != nil && c.app.warp.connected() {
		return "WARP → PSI → WARP"
	}
	if c.autoChain() {
		return "PSI → WARP (Auto)"
	}
	return "WARP → PSI → WARP"
}

func (c *CleanChain) setStatus(st, txt, errMsg string) {
	c.mu.Lock()
	c.state = st
	c.text = txt
	c.lastErr = errMsg
	c.hopsLabel = c.activeHopsLabel()
	c.mu.Unlock()
}

func (c *CleanChain) ensureExitIdentity(ctx context.Context) (*warpIdentity, error) {
	if b, err := os.ReadFile(c.exitIDPath()); err == nil {
		var id warpIdentity
		if json.Unmarshal(b, &id) == nil && id.PrivateKey != "" && id.PeerKey != "" {
			return &id, nil
		}
	}
	// Register a separate ExitWarp keypair through Psiphon so EntryWarp and ExitWarp
	// never share keys or client IDs.
	cl := &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			DialContext: c.app.psi.Dial,
		},
	}
	id, err := warpRegister([]*http.Client{cl})
	if err != nil {
		return nil, fmt.Errorf("регистрация ключа ExitWarp: %w", err)
	}
	if raw, err := json.MarshalIndent(id, "", "  "); err == nil {
		_ = writeFileAtomic(c.exitIDPath(), raw, 0o600)
	}
	return id, nil
}

// EnsureConnected brings up the ExitWarp userspace netstack over Psiphon udpgw
// on demand (reusing an existing healthy tunnel).
func (c *CleanChain) EnsureConnected(ctx context.Context) (*warpTunnel, error) {
	if t := c.exitTun.Load(); t != nil {
		return t, nil
	}
	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	if t := c.exitTun.Load(); t != nil {
		return t, nil
	}
	if c.app == nil || c.app.psi == nil {
		return nil, errors.New("Psiphon не инициализирован для Clean-IP")
	}
	if c.app.psi.isUserStopped() {
		return nil, errors.New("VPN отключён пользователем")
	}
	if !c.app.psi.running() && c.app.psi.cur.Load() == nil {
		c.app.psi.Start()
	}

	c.setStatus("connecting", "поднимаю ExitWarp поверх Psiphon…", "")
	id, err := c.ensureExitIdentity(ctx)
	if err != nil {
		c.setStatus("error", "ошибка ключа ExitWarp", err.Error())
		return nil, err
	}

	// Standard clean Cloudflare WARP endpoints reachable from Psiphon exit nodes.
	endpoints := []string{
		"162.159.192.1:2408",
		"162.159.193.1:2408",
		"162.159.195.1:2408",
		"188.114.96.1:2408",
	}
	var lastErr error
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			lastErr = ctx.Err()
			break
		}
		ub := newUDPGWBind(c.app.psi.Dial)
		// ExitWarp runs inside an already-encrypted Psiphon tunnel, so no DPI mask needed.
		t, err := openWarpTunnelWithBind(id, ep, warpMask{ID: "off"}, cleanExitWarpMTU, ub)
		if err != nil {
			lastErr = err
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		err = t.probe(pctx)
		cancel()
		if err != nil {
			t.Close()
			lastErr = err
			continue
		}
		tctx, tcancel := context.WithTimeout(ctx, 8*time.Second)
		tr, terr := getTrace(tctx, t.dial)
		tcancel()
		c.mu.Lock()
		if terr == nil {
			c.exitIP = tr.IP
			c.exitLoc = tr.Loc
			c.exitColo = tr.Colo
		}
		c.state = "connected"
		c.hopsLabel = c.activeHopsLabel()
		c.text = fmt.Sprintf("чистый IP %s (%s)", c.exitIP, c.exitLoc)
		c.lastErr = ""
		c.mu.Unlock()
		c.exitTun.Store(t)
		if c.app != nil {
			c.app.tun.refresh() // Re-clamp TUN TCP MSS to <= 1140 for 3-hop Clean-IP
		}
		logf("info", "Clean-IP каскад (%s) активен: выход %s (%s, MTU %d / MSS %d)",
			c.activeHopsLabel(), c.exitIP, c.exitLoc, cleanExitWarpMTU, cleanChainMSS4)
		return t, nil
	}
	if lastErr == nil {
		lastErr = errors.New("не удалось подключить ExitWarp")
	}
	c.setStatus("error", "не удалось поднять Clean-IP", lastErr.Error())
	return nil, lastErr
}

func (c *CleanChain) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if c == nil {
		return nil, errors.New("Clean-IP не инициализирован")
	}
	if c.testDial != nil {
		return c.testDial(ctx, network, addr)
	}
	t, err := c.EnsureConnected(ctx)
	if err != nil {
		return nil, err
	}
	return t.dial(ctx, network, addr)
}

func (c *CleanChain) Close() {
	if c == nil {
		return
	}
	if old := c.exitTun.Swap(nil); old != nil {
		old.Close()
	}
	c.setStatus("off", "выключен", "")
}

func (c *CleanChain) View() map[string]any {
	if c == nil {
		return map[string]any{"enabled": false, "state": "off"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{
		"enabled":    c.enabled(),
		"auto_chain": c.autoChain(),
		"state":      c.state,
		"text":       c.text,
		"hops":       c.hopsLabel,
		"exit_ip":    c.exitIP,
		"exit_loc":   c.exitLoc,
		"exit_colo":  c.exitColo,
		"entry_mtu":  cleanEntryMTU,
		"exit_mtu":   cleanExitWarpMTU,
		"mss4":       cleanChainMSS4,
		"mss6":       cleanChainMSS6,
		"error":       c.lastErr,
		"last_verify": c.lastVerify,
	}
}

// Verify runs a real 3-hop diagnostic across EntryWarp -> Psiphon -> ExitWarp
// using Cloudflare /cdn-cgi/trace and proves whether ExitWarp yields a clean
// Cloudflare WARP IP (warp=on/plus) distinct from the Psiphon exit node.
func (c *CleanChain) Verify(ctx context.Context) map[string]any {
	res := map[string]any{
		"ok":             false,
		"verified":       false,
		"hops_label":     c.activeHopsLabel(),
		"entry_mtu":      cleanEntryMTU,
		"exit_mtu":       cleanExitWarpMTU,
		"mss4":           cleanChainMSS4,
		"checked_at":     time.Now().Unix(),
		"ip_changed":     false,
		"warp_confirmed": false,
	}
	if c == nil || c.app == nil {
		res["error"] = "Clean-IP не инициализирован"
		return res
	}

	// Hop 1: EntryWarp
	hop1 := map[string]any{"name": "Звено 1 · Входной WARP", "ok": false, "bypassed": false}
	if c.app.warp != nil && c.app.warp.connected() {
		t0 := time.Now()
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		tr, err := getTrace(hctx, c.app.warp.Dial)
		cancel()
		hop1["ms"] = time.Since(t0).Milliseconds()
		if err != nil {
			hop1["error"] = err.Error()
		} else {
			hop1["ok"] = true
			hop1["ip"] = tr.IP
			hop1["loc"] = tr.Loc
			hop1["colo"] = tr.Colo
			hop1["warp"] = tr.Warp
		}
	} else {
		hop1["bypassed"] = true
		hop1["note"] = "Входной WARP не активен (Auto-Chain / прямой вход в Psiphon)"
	}
	res["hop1"] = hop1

	// Hop 2: Transit Psiphon VPN
	hop2 := map[string]any{"name": "Звено 2 · Psiphon VPN", "ok": false}
	var psiIP string
	if c.app.psi != nil && (c.app.psi.running() || c.app.psi.cur.Load() != nil) {
		t0 := time.Now()
		hctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		tr, err := getTrace(hctx, c.app.psi.Dial)
		cancel()
		hop2["ms"] = time.Since(t0).Milliseconds()
		if err != nil {
			hop2["error"] = err.Error()
		} else {
			hop2["ok"] = true
			hop2["ip"] = tr.IP
			hop2["loc"] = tr.Loc
			hop2["colo"] = tr.Colo
			hop2["warp"] = tr.Warp
			psiIP = tr.IP
		}
	} else {
		hop2["error"] = "Psiphon не подключён"
	}
	res["hop2"] = hop2

	// Hop 3: ExitWarp (Clean-IP) over Psiphon udpgw
	hop3 := map[string]any{"name": "Звено 3 · Выходной WARP (Clean-IP)", "ok": false}
	t0 := time.Now()
	hctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	tun, err := c.EnsureConnected(hctx)
	if err != nil {
		cancel()
		hop3["error"] = err.Error()
		res["error"] = "Звено 3 (ExitWarp): " + err.Error()
	} else {
		tr, terr := getTrace(hctx, tun.dial)
		cancel()
		hop3["ms"] = time.Since(t0).Milliseconds()
		if terr != nil {
			hop3["error"] = terr.Error()
			res["error"] = "Трасса ExitWarp: " + terr.Error()
		} else {
			hop3["ok"] = true
			hop3["ip"] = tr.IP
			hop3["loc"] = tr.Loc
			hop3["colo"] = tr.Colo
			hop3["warp"] = tr.Warp
			warpOK := tr.Warp == "on" || tr.Warp == "plus"
			ipChanged := psiIP != "" && tr.IP != "" && tr.IP != psiIP
			res["warp_confirmed"] = warpOK
			res["ip_changed"] = ipChanged
			res["ok"] = true
			res["verified"] = hop2["ok"] == true && warpOK && ipChanged
		}
	}
	res["hop3"] = hop3
	res["hops_label"] = c.activeHopsLabel()

	c.mu.Lock()
	c.lastVerify = res
	c.mu.Unlock()
	return res
}
