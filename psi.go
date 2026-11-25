package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// Psiphon runs in-process through tunnel-core (the same library the official
// clients use). We control the fragmentor / TLS ClientHello split, tunnel
// protocols, upstream proxy, per-network strategy memory, parallel protocol
// racing, emergency bootstrap of server entries via signed mirrors / DNS TXT
// (Priority 4), and optional 2-tunnel parallel load-balancing pool (Priority 6).

const (
	// psiRSLKey — публичный RSA-ключ Psiphon для проверки цифровой подписи
	// скачиваемых списков серверов (Remote Server List / OSL). Без точного
	// совпадения ключа tunnel-core отклонит загруженный список серверов.
	psiRSLKey = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="

	// psiRSLURL — основной URL сжатого списка серверов Psiphon на S3.
	psiRSLURL = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"

	// psiRSLBackupURL1..4 — запасные URL списка серверов (используются tunnel-core
	// с OnlyAfterAttempts > 0, если основной адрес недоступен или заблокирован).
	psiRSLBackupURL1 = "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	psiRSLBackupURL2 = "https://s3.dualstack.us-east-1.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	psiRSLBackupURL3 = "https://s3-external-1.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	psiRSLBackupURL4 = "https://psiphon.s3.amazonaws.com/web/mjr4-p23r-puwl/server_list_compressed"

	// psiPropagationChannelID и psiSponsorID — идентификаторы канала распространения
	// и спонсора в протоколе рукопожатия Psiphon (16 шестнадцатеричных символов).
	psiPropagationChannelID = "FFFFFFFFFFFFFFFF"
	psiSponsorID            = "FFFFFFFFFFFFFFFF"

	// psiPlatform — строка клиентской платформы, передаваемая в запрос тактик
	// и рукопожатие Psiphon.
	psiPlatform = "Android_4.0.4_com.example.exampleClientLibraryApp"

	speedURL = "https://speed.cloudflare.com/__down?bytes=20000000"
)

// psiPingTargets — независимые цели для проверки связности внутри туннеля.
// Туннель считается потерявшим связь только в том случае, если не ответили ВСЕ цели.
var psiPingTargets = []struct {
	Host string
	Path string
}{
	{Host: "www.gstatic.com:80", Path: "/generate_204"},
	{Host: "cp.cloudflare.com:80", Path: "/generate_204"},
	{Host: "connectivitycheck.gstatic.com:80", Path: "/generate_204"},
}

var psiProtoSets = map[string][]string{
	"meek": {"FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH"},
	"tls":  {"TLS-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH", "UNFRONTED-MEEK-SESSION-TICKET-OSSH"},
	"quic": {"QUIC-OSSH"},
	"ossh": {"OSSH", "SHADOWSOCKS-OSSH", "UNFRONTED-MEEK-OSSH"},
	// Conduit / in-proxy: the tunnel goes through volunteer Conduit
	// proxies (home IPs, WebRTC), matched by Psiphon brokers.
	"conduit": {"INPROXY-WEBRTC-OSSH", "INPROXY-WEBRTC-TLS-OSSH", "INPROXY-WEBRTC-UNFRONTED-MEEK-OSSH",
		"INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH", "INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH", "INPROXY-WEBRTC-QUIC-OSSH"},
}

var psiDPINames = map[string]string{
	"":       "стандартный обход",
	"off":    "без обхода",
	"hello":  "только разрез TLS-приветствия",
	"light":  "лёгкое дробление",
	"strong": "сильное дробление",
	"auto":   "авто: перебор и запоминание",
}

// strategyDef is one way of reaching Psiphon. Enabled strategies are tried in
// the per-network scored order until one connects.
type strategyDef struct {
	ID           string
	Title        string
	Transport    string   // direct | warp | proxy | desync
	Protos       string   // key of psiProtoSets, "" = all, "race" = CustomProtos
	CustomProtos []string // explicit protocol list for combined first-round race
	DPI          string   // forced DPI mode, "" = use settings
	Upstream     string   // None | Warp | Proxy (for the UI)
}

var psiStrategies = []strategyDef{
	{ID: "direct-dpi", Title: "Прямой + DPI-обход TLS (без WARP)", Transport: "desync", Protos: "tls", Upstream: "None"},
	{ID: "desync-meek", Title: "CDN Meek + DPI-обход (без WARP)", Transport: "desync", Protos: "meek", Upstream: "None"},
	{ID: "desync-ossh", Title: "OSSH / Shadowsocks + TCP-дробление", Transport: "desync", Protos: "ossh", Upstream: "None"},
	{ID: "auto", Title: "Авто (все протоколы)", Transport: "direct", Upstream: "None"},
	{ID: "conduit", Title: "Conduit (через добровольцев)", Transport: "direct", Protos: "conduit", Upstream: "None"},
	{ID: "meek", Title: "Через CDN (meek)", Transport: "direct", Protos: "meek", Upstream: "None"},
	{ID: "tls", Title: "TLS (сильное дробление ClientHello)", Transport: "direct", Protos: "tls", DPI: "strong", Upstream: "None"},
	{ID: "quic", Title: "QUIC", Transport: "direct", Protos: "quic", DPI: "off", Upstream: "None"},
	{ID: "ossh", Title: "OSSH и Shadowsocks", Transport: "direct", Protos: "ossh", Upstream: "None"},
	{ID: "via-warp", Title: "Через WARP", Transport: "warp", Upstream: "Warp"},
	{ID: "via-proxy", Title: "Через внешний прокси", Transport: "proxy", Upstream: "Proxy"},
}

func strategyByID(id string) (strategyDef, bool) {
	for _, s := range psiStrategies {
		if s.ID == id {
			return s, true
		}
	}
	return strategyDef{}, false
}

type psiNotice struct {
	Type string         `json:"noticeType"`
	Data map[string]any `json:"data"`
}

var (
	errRotate      = errors.New("переподключение к узлу")
	errForceRotate = errors.New("принудительная смена узла")
	errNext        = errors.New("следующий способ")
	errUnstable    = errors.New("туннели рвутся вскоре после подключения")
	errTimeout     = errors.New("не удалось подключиться за отведённое время")
	psiErrRe       = regexp.MustCompile(`\S+#\d+: `)
	psiNoise       = []string{"Config migration", "DSL", "RoundTripperFailedError", "tactics request aborted", "context canceled", "is not a Closer"}
)

// Psi is the Psiphon engine.
type Psi struct {
	app     *App
	dataDir string
	dpiAuto psiDPIAuto // psiphon.dpi = auto: rotation of fragmentation modes

	opMu            sync.Mutex // serializes Start / Stop / Restart state transitions
	mu              sync.Mutex
	state           string
	lastErr         string
	diagCode        string
	diagReason      string
	diagAdvice      string
	strategy        strategyDef
	attempt         int
	egress          string
	clientReg       string
	server          string
	protocol        string
	speedKBps       int
	healthMs        int
	since           time.Time
	tunnels         int
	candidates      int
	rslFailed       int
	regions         []string
	nodes           []map[string]any
	regionStats     map[string]map[string]any
	warnSeen        map[string]bool
	cmdAt           time.Time           // last button press passed on (userCmd)
	attemptAt       time.Time           // start of the current attempt
	unstable        map[string]int64    // method -> unix time until which it goes last
	stratMem        *strategyMemoryFile // per-network strategy performance store
	manualEpoch     int                 // incremented ONLY on explicit repeated manual node rotation
	desyncLn        net.Listener        // local TCP Desync SOCKS5 wrapper listener for Direct+Desync->Psiphon
	desyncProxyAddr string
	restartMu       sync.Mutex
	lastBootstrapAt time.Time

	// Traffic watermark to detect active tunnel transfers during health checks.
	lastTrafficBytes int64
	lastTrafficAt    time.Time

	// Injectable hooks for deterministic offline unit tests.
	netKeyFunc      func() string
	pingTargetFunc  func(ctx context.Context, host, path string) (int, error)
	directAliveFunc func(ctx context.Context) bool
	mirrorFetchFunc func(ctx context.Context, url string) (string, error)
	primaryDialHook func(ctx context.Context, network, addr string) (net.Conn, error)

	// Priority 6: Optional 2-tunnel load-balancing pool counters (atomic, race-free).
	activeConns0  atomic.Int32
	activeConns1  atomic.Int32
	poolRR        atomic.Uint64
	balancedDials atomic.Int64

	confirmedController *psiphon.Controller
	confirmedEgress     string
	cur                 atomic.Pointer[psiphon.Controller]
	standby             atomic.Pointer[psiphon.Controller]
	userStopped         atomic.Bool
	dialFails           atomic.Int32
	lastCheck           atomic.Int64
	notes               chan psiNotice
	cmd                 chan string
	cancel              context.CancelFunc
	timeline            *connTimeline
	preflight           *preflightCache
	lastPreflight       *CarrierReport
	preflightProbes     *preflightProbes
	preflightCarriersFn func() []Carrier
	seedProbe           func(ctx context.Context, c Carrier, rawURL string, n int) (int, error) // tests; nil = probeRangeOverCarrier
	seedSourcesMu       sync.Mutex
	stage               string
	tacticsApplied      bool
	tacticsTag          string
	rslInProgress       atomic.Bool
	tacticsInProgress   atomic.Bool
	done                chan struct{}
}

func newPsi(app *App, dataDir string) *Psi {
	p := &Psi{
		app:         app,
		dataDir:     dataDir,
		state:       "stopped",
		candidates:  -1,
		regionStats: map[string]map[string]any{},
		notes:       make(chan psiNotice, 64),
		cmd:         make(chan string, 4),
		warnSeen:    map[string]bool{},
		timeline:    newConnTimeline(defaultTimelineCapacity),
		preflight:   newPreflightCache(preflightCacheTTL),
	}
	p.loadSavedNetID()
	p.loadOptionalSeedBundle()
	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(p.onNotice))
	return p
}

// tl returns the connection timeline, lazily initializing it if needed.
func (p *Psi) tl() *connTimeline {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timeline == nil {
		p.timeline = newConnTimeline(defaultTimelineCapacity)
	}
	return p.timeline
}

// RunPreflight executes Stage 0 carrier preflight (<= 8 s, parallel) with
// per-network TTL caching and records a summary event in the connection timeline.
func (p *Psi) RunPreflight(ctx context.Context, force bool) *CarrierReport {
	if p == nil {
		return nil
	}
	netKey := p.currentNetKey()
	p.mu.Lock()
	if p.preflight == nil {
		p.preflight = newPreflightCache(preflightCacheTTL)
	}
	cache := p.preflight
	probes := p.preflightProbes
	carriersFn := p.preflightCarriersFn
	p.mu.Unlock()

	nowFn := time.Now
	if probes != nil && probes.Now != nil {
		nowFn = probes.Now
	}
	if !force {
		if cached := cache.Get(netKey, nowFn()); cached != nil {
			p.mu.Lock()
			p.lastPreflight = cached.Clone()
			p.mu.Unlock()
			return cached
		}
	}
	var carriers []Carrier
	if carriersFn != nil {
		carriers = carriersFn()
	} else {
		carriers = p.buildCarriers()
	}
	rep := runPreflight(ctx, netKey, carriers, probes)
	cache.Set(netKey, rep)
	p.mu.Lock()
	p.lastPreflight = rep.Clone()
	p.mu.Unlock()

	outcome := "ok"
	if rep.ClassifiedCode != "" {
		outcome = "info"
	}
	p.tl().Record(connTimelineEvent{
		Stage:      "preflight",
		DurationMs: rep.DurationMs,
		Outcome:    outcome,
		DiagCode:   rep.ClassifiedCode,
		Detail:     "ranking=" + strings.Join(rep.Ranking, ","),
	})
	return rep
}

func (p *Psi) invalidatePreflight(netKey string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	cache := p.preflight
	p.mu.Unlock()
	if cache != nil {
		cache.Invalidate(netKey)
	}
}

func (p *Psi) lastPreflightReport() *CarrierReport {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPreflight.Clone()
}

// loadSavedNetID восстанавливает сохранённый счётчик ручной смены узла (manualEpoch)
// из файла psiroute-netid при перезапуске программы (Баг №2).
func (p *Psi) loadSavedNetID() {
	if p == nil || p.dataDir == "" {
		return
	}
	b, err := os.ReadFile(p.file("psiroute-netid"))
	if err != nil {
		return
	}
	s := strings.TrimSpace(string(b))
	if idx := strings.LastIndex(s, "-m"); idx >= 0 {
		if ep, perr := strconv.Atoi(s[idx+2:]); perr == nil && ep > 0 {
			p.manualEpoch = ep
		}
	}
}

func ptr[T any](v T) *T { return &v }

// psiRSLURLs returns the remote server list in the plural config form with
// primary and backup endpoints using OnlyAfterAttempts so tunnel-core falls
// back automatically if the primary S3 endpoint fails or times out.
func psiRSLURLs() parameters.TransferURLs {
	return parameters.TransferURLs{
		{
			URL:               base64.StdEncoding.EncodeToString([]byte(psiRSLURL)),
			OnlyAfterAttempts: 0,
		},
		{
			URL:               base64.StdEncoding.EncodeToString([]byte(psiRSLBackupURL1)),
			OnlyAfterAttempts: 1,
		},
		{
			URL:               base64.StdEncoding.EncodeToString([]byte(psiRSLBackupURL2)),
			OnlyAfterAttempts: 2,
		},
		{
			URL:               base64.StdEncoding.EncodeToString([]byte(psiRSLBackupURL3)),
			OnlyAfterAttempts: 3,
		},
		{
			URL:               base64.StdEncoding.EncodeToString([]byte(psiRSLBackupURL4)),
			OnlyAfterAttempts: 4,
		},
	}
}

func short(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func num(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func strList(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func cleanPsiErr(s string) string { return short(psiErrRe.ReplaceAllString(s, ""), 200) }

func (p *Psi) set(f func()) {
	p.mu.Lock()
	f()
	p.mu.Unlock()
}

// ---- control ----

func (p *Psi) isUserStopped() bool {
	return p != nil && p.userStopped.Load()
}

func (p *Psi) Start() {
	p.opMu.Lock()
	defer p.opMu.Unlock()
	p.userStopped.Store(false)
	p.mu.Lock()
	if p.cancel != nil {
		p.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(p.app.ctx)
	p.cancel = cancel
	p.done = make(chan struct{})
	p.state = "connecting"
	p.lastErr = ""
	p.diagCode = ""
	p.diagReason = ""
	p.diagAdvice = ""
	done := p.done
	p.mu.Unlock()
	if p.app != nil {
		p.app.tun.refresh()
	}
	safeGo("Psi.Start", func() {
		defer close(done)
		for catchPanic("Psiphon", func() { p.run(ctx) }) && ctx.Err() == nil {
			p.set(func() { p.state = "reconnecting" })
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
	})
}

func (p *Psi) Stop() {
	p.stopInternal(true)
}

func (p *Psi) stopInternal(manual bool) {
	p.opMu.Lock()
	defer p.opMu.Unlock()
	if manual {
		p.userStopped.Store(true)
	}
	p.cur.Store(nil)
	p.standby.Store(nil)
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.cancel = nil
	if cancel != nil {
		p.state = "stopping"
	} else {
		p.state = "stopped"
		p.tunnels = 0
		p.since = time.Time{}
	}
	p.mu.Unlock()
	if cancel == nil {
		if p.app != nil {
			p.app.tun.refresh()
		}
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	p.cur.Store(nil)
	p.standby.Store(nil)
	p.mu.Lock()
	if p.desyncLn != nil {
		_ = p.desyncLn.Close()
		p.desyncLn = nil
		p.desyncProxyAddr = ""
	}
	p.mu.Unlock()
	p.set(func() { p.state = "stopped"; p.tunnels = 0; p.since = time.Time{} })
	if p.app != nil {
		p.app.tun.refresh()
	}
	logf("info", "Psiphon остановлен")
}

// ensureLocalDesyncProxy поднимает локальный SOCKS5-обёрточный прокси (127.0.0.1:0),
// который устанавливает исходящие TCP-соединения к серверам Psiphon через локальный
// обходчик DPI (dialObfs: фрагментация/разрез TLS ClientHello из desync.go и obfs.go)
// без участия WARP (Раздел 3.2 ТЗ: Direct + Desync -> Psiphon).
func (p *Psi) ensureLocalDesyncProxy() string {
	p.mu.Lock()
	if p.desyncProxyAddr != "" && p.desyncLn != nil {
		addr := p.desyncProxyAddr
		p.mu.Unlock()
		return addr
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		p.mu.Unlock()
		return ""
	}
	p.desyncLn = ln
	p.desyncProxyAddr = ln.Addr().String()
	addr := p.desyncProxyAddr
	p.mu.Unlock()

	safeGo("Psi.ensureLocalDesyncProxy", func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			safeGo("Psi.ensureLocalDesyncProxy#2", func() { serveWorkerSocks(p.app.ctx, c, func(ctx context.Context, network, targetAddr string) (net.Conn, error) {
				method := "auto"
				if p.app != nil && p.app.cfg != nil {
					p.app.cfg.mu.Lock()
					if p.app.cfg.Desync.Method != "" {
						method = p.app.cfg.Desync.Method
					}
					p.app.cfg.mu.Unlock()
				}
				conn, derr := dialObfs(ctx, network, targetAddr, method)
				if derr != nil {
					return nil, derr
				}
				return &psiRawSplitConn{Conn: conn}, nil
			}) })
		}
	})
	return addr
}

// psiRawSplitConn fragments the first non-TLS / non-HTTP write (e.g. OSSH or
// Shadowsocks handshake) into tiny 1–4 byte TCP chunks with 2 ms pacing to
// break TSPU first-packet entropy/signature classification without WARP.
type psiRawSplitConn struct {
	net.Conn
	done atomic.Bool
}

func (c *psiRawSplitConn) Write(p []byte) (int, error) {
	if c.done.Swap(true) || len(p) <= 6 {
		return c.Conn.Write(p)
	}
	// TLS ClientHello (0x16 0x03) and HTTP are already fragmented by obfsConn inside dialObfs.
	if (p[0] == 0x16 && p[1] == 0x03) || obfsLooksHTTP(p) {
		return c.Conn.Write(p)
	}
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	splitLimit := min(len(p), 48)
	written := 0
	for written < splitLimit {
		chunk := min(3, splitLimit-written)
		n, err := c.Conn.Write(p[written : written+chunk])
		written += n
		if err != nil {
			return written, err
		}
		time.Sleep(2 * time.Millisecond)
	}
	if written < len(p) {
		n, err := c.Conn.Write(p[written:])
		written += n
		return written, err
	}
	return written, nil
}

func (p *Psi) Restart() {
	p.restartMu.Lock()
	defer p.restartMu.Unlock()
	p.stopInternal(false)
	p.Start()
}

func (p *Psi) send(c string) {
	select {
	case p.cmd <- c:
	default:
	}
}

// Next skips to the next connection strategy.
func (p *Psi) Next() int { return p.userCmd("next") }

// NewNode triggers a node switch.
func (p *Psi) NewNode() int { return p.userCmd("manual-rotate") }

func (p *Psi) running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cancel != nil
}

// ---- engine loop ----

func (p *Psi) enabled() []strategyDef {
	c := p.app.cfg
	c.mu.Lock()
	ids := append([]string(nil), c.Psiphon.Strategies...)
	c.mu.Unlock()
	out := []strategyDef{}
	for _, id := range ids {
		if s, ok := strategyByID(id); ok && p.available(s) {
			out = append(out, s)
		}
	}
	return out
}

func (p *Psi) available(s strategyDef) bool {
	c := p.app.cfg
	c.mu.Lock()
	defer c.mu.Unlock()
	switch s.Transport {
	case "warp":
		return c.Warp.Enabled && (c.Warp.Engine != "socks" || c.Warp.Socks != "")
	case "proxy":
		return c.Proxy.Enabled && c.Proxy.Upstream != ""
	}
	return true
}

func (p *Psi) file(name string) string { return filepath.Join(p.dataDir, name) }

// netID returns the NetworkID bound to the real network fingerprint (gateway +
// adapter hash). It changes automatically ONLY when the physical/logical
// network changes, preserving tunnel-core's learned server affinity, tactics,
// and protocol replay parameters across reconnects on the same network.
func (p *Psi) netID() string {
	nk := p.currentNetKey()
	if nk == "" {
		nk = "net-default"
	}
	var b strings.Builder
	for _, r := range nk {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	clean := b.String()
	if clean == "" {
		clean = "psiroute"
	}
	p.mu.Lock()
	ep := p.manualEpoch
	p.mu.Unlock()
	if ep > 0 {
		return fmt.Sprintf("%s-m%d", clean, ep)
	}
	return clean
}

// rotateNetID increments manualEpoch ONLY when explicitly requested by the user's
// manual button press; automatic recovery never calls rotateNetID.
func (p *Psi) rotateNetID() {
	p.mu.Lock()
	p.manualEpoch++
	id := fmt.Sprintf("%s-m%d", p.currentNetKey(), p.manualEpoch)
	p.mu.Unlock()
	if p.dataDir != "" {
		_ = writeFileAtomic(p.file("psiroute-netid"), []byte(id), 0o600)
	}
}

func (p *Psi) run(ctx context.Context) {
	fails := 0
	prevCarrier := ""
	p.set(func() { p.stage = "stage0_preflight" })
	rep := p.RunPreflight(ctx, false)
	// Stage 1: check seed health and optionally fetch from user-configured mirror over healthy carriers.
	p.set(func() { p.stage = "stage1_seed" })
	sh := p.SeedHealth()
	var mirrorURL string
	if p.app != nil && p.app.cfg != nil {
		p.app.cfg.mu.Lock()
		mirrorURL = p.app.cfg.Psiphon.MirrorURL
		p.app.cfg.mu.Unlock()
	}
	if !sh.Healthy && mirrorURL != "" {
		var carriers []Carrier
		if p.preflightCarriersFn != nil {
			carriers = p.preflightCarriersFn()
		} else {
			carriers = p.buildCarriers()
		}
		_ = p.AcquireSeedsParallel(ctx, carriers, mirrorURL, nil)
	}
	_ = rep
	p.set(func() { p.stage = "stage2_connect" })
	for ctx.Err() == nil {
		netKey := p.currentNetKey()
		ordered := p.orderForNetwork(netKey, p.enabled(), p.lastGood())
		if len(ordered) == 0 {
			p.set(func() {
				p.state = "error"
				p.lastErr = "нет доступных способов подключения — включите хотя бы один"
				p.diagCode = "no_strategies"
				p.diagReason = "Все способы подключения отключены"
				p.diagAdvice = "Включите хотя бы один способ подключения в настройках Psiphon"
			})
			p.tl().Record(connTimelineEvent{
				Stage:    "error",
				Outcome:  "failed",
				DiagCode: "no_strategies",
				Detail:   "Все способы подключения отключены",
			})
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}

		// Round 0 uses the fast race plan: #1 strategy (20 s) -> combined direct
		// protocol race (35 s) -> separate transport strategies. Later rounds
		// step through the scored list with longer timeouts.
		round0Plan := p.buildRoundZeroPlan(ordered)
		var s strategyDef
		var timeout int
		if fails < len(round0Plan) {
			s = round0Plan[fails]
			if len(ordered) > 1 {
				if fails == 0 && s.Transport == "direct" {
					timeout = bestStrategyShortTimeout
				} else if s.ID == "race-direct" {
					timeout = combinedRaceTimeout
				} else if s.ID == "desync-direct" {
					timeout = tspuEchelonTimeout
				} else {
					timeout = attemptTimeout(0)
				}
			}
		} else {
			adj := fails - len(round0Plan)
			round := 1 + adj/len(ordered)
			s = ordered[adj%len(ordered)]
			if len(ordered) > 1 {
				timeout = attemptTimeout(round)
			}
		}
		if timeout > 0 && s.Transport == "warp" && !p.warpUp() {
			timeout += 45 // WARP itself may still be connecting
		}

		p.set(func() {
			p.attempt++
			p.strategy = s
			p.attemptAt = time.Now()
			if p.state != "connected" {
				if fails > 0 {
					p.state = "reconnecting"
				} else {
					p.state = "connecting"
				}
			}
			p.warnSeen = map[string]bool{}
		})
		p.recordStrategyAttempt(netKey, s.ID)

		if timeout > 0 {
			logf("info", "Psiphon [%s]: пробую «%s» (до %d с)", netKey, s.Title, timeout)
		} else {
			logf("info", "Psiphon [%s]: пробую «%s»", netKey, s.Title)
		}
		carrier := carrierNameForStrategy(s)
		if prevCarrier != "" && (prevCarrier == carrierDirect || prevCarrier == carrierDirectDPI) && (carrier == carrierWARP || carrier == carrierWorker || carrier == carrierProxy) {
			p.set(func() { p.stage = "stage3_escalate" })
			p.RunPreflight(ctx, false)
		}
		prevCarrier = carrier
		attemptStart := time.Now()
		protos := protocolsForStrategy(s)
		p.mu.Lock()
		attemptNum := p.attempt
		p.mu.Unlock()
		p.tl().RecordAttempt(carrier, protos)
		p.tl().Record(connTimelineEvent{
			Stage:      "attempt_start",
			Carrier:    carrier,
			StrategyID: s.ID,
			Protocols:  protos,
			Attempt:    attemptNum,
			Outcome:    "info",
			Detail:     s.Title,
		})
		wasUnstable := p.isUnstable(s.ID)
		wasConnected, err := p.attemptOnce(ctx, s, timeout)
		if ctx.Err() != nil {
			return
		}
		attemptDurMs := time.Since(attemptStart).Milliseconds()
		switch {
		case errors.Is(err, errRotate), errors.Is(err, errForceRotate), errors.Is(err, errNetChange):
			p.tl().Record(connTimelineEvent{
				Stage:      "attempt_end",
				Carrier:    carrier,
				StrategyID: s.ID,
				Protocols:  protos,
				Attempt:    attemptNum,
				DurationMs: attemptDurMs,
				Outcome:    "rotate",
				Detail:     err.Error(),
			})
			if errors.Is(err, errNetChange) {
				p.invalidatePreflight("")
				p.RunPreflight(ctx, true)
			}
			p.set(func() { p.state = "reconnecting" })
			continue
		case errors.Is(err, errNext):
			p.tl().Record(connTimelineEvent{
				Stage:      "attempt_end",
				Carrier:    carrier,
				StrategyID: s.ID,
				Protocols:  protos,
				Attempt:    attemptNum,
				DurationMs: attemptDurMs,
				Outcome:    "next",
			})
			fails++
			p.set(func() { p.state = "reconnecting" })
			continue
		case errors.Is(err, errUnstable):
			p.tl().Record(connTimelineEvent{
				Stage:      "attempt_end",
				Carrier:    carrier,
				StrategyID: s.ID,
				Protocols:  protos,
				Attempt:    attemptNum,
				DurationMs: attemptDurMs,
				Outcome:    "unstable",
				DiagCode:   "handshake_reset",
				Detail:     err.Error(),
			})
			if wasUnstable || len(ordered) == 1 {
				fails++
			}
			p.set(func() { p.state = "reconnecting" })
			continue
		}
		if wasConnected {
			fails = 0
		} else {
			fails++
		}
		msg := "соединение потеряно"
		if err != nil {
			msg = cleanPsiErr(err.Error())
		}
		code, reason, advice := p.classifyFailure(ctx, s, err)
		p.set(func() {
			p.state = "reconnecting"
			p.lastErr = msg
			p.diagCode = code
			p.diagReason = reason
			p.diagAdvice = advice
		})
		outcome := "failed"
		if errors.Is(err, errTimeout) {
			outcome = "timeout"
		}
		p.tl().Record(connTimelineEvent{
			Stage:      "attempt_end",
			Carrier:    carrier,
			StrategyID: s.ID,
			Protocols:  protos,
			Attempt:    attemptNum,
			DurationMs: attemptDurMs,
			Outcome:    outcome,
			DiagCode:   code,
			Detail:     reason,
		})
		logf("warn", "Psiphon «%s»: %s (%s)", s.Title, msg, reason)
		if len(ordered) == 1 || fails >= len(round0Plan) && (fails-len(round0Plan))%len(ordered) == 0 {
			wait := time.Duration(min(5<<min(fails/max(len(ordered), 1), 5), 120)) * time.Second
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}
}

func (p *Psi) configFor(s strategyDef, timeout int) *psiphon.Config {
	c := p.app.cfg
	c.mu.Lock()
	region := strings.ToUpper(c.Psiphon.Country)
	pool := c.Psiphon.Parallel
	dpi := c.Psiphon.DPI
	preset := normalizePreset(c.Psiphon.Preset)
	propID := strings.TrimSpace(c.Psiphon.PropagationChannelID)
	sponsorID := strings.TrimSpace(c.Psiphon.SponsorID)
	platform := strings.TrimSpace(c.Psiphon.ClientPlatform)
	warp := c.Warp.Socks
	builtinWarp := c.Warp.Engine != "socks"
	upstream := c.Proxy.Upstream
	c.mu.Unlock()
	if propID == "" || validateHexID16(propID) != nil {
		propID = psiPropagationChannelID
	}
	if sponsorID == "" || validateHexID16(sponsorID) != nil {
		sponsorID = psiSponsorID
	}
	if platform == "" {
		platform = psiPlatform
	}
	if pool < 1 {
		pool = 1
	}
	if pool > 4 {
		pool = 4
	}
	dir := filepath.Join(p.dataDir, "psiphon")
	_ = os.MkdirAll(dir, 0o700)
	cfg := &psiphon.Config{
		EgressRegion:                       region,
		DisableLocalSocksProxy:             true,
		DisableLocalHTTPProxy:              true,
		PropagationChannelId:               propID,
		SponsorId:                          sponsorID,
		RemoteServerListDownloadFilename:   "remote_server_list",
		RemoteServerListSignaturePublicKey: psiRSLKey,
		RemoteServerListURLs:               psiRSLURLs(),
		EmitDiagnosticNotices:              true,
		NetworkID:                          p.netID(),
		ClientPlatform:                     platform,
		DataRootDirectory:                  dir,
		TunnelPoolSize:                     pool,
		EstablishTunnelPausePeriodSeconds:  ptr(2),
	}
	if timeout > 0 {
		cfg.EstablishTunnelTimeoutSeconds = &timeout
	}
	seedEmptyOrRSL := p.importedServerEntriesCount() == 0 || p.rslInProgress.Load()
	switch s.Transport {
	case "warp":
		if builtinWarp && p.app != nil {
			if addr := p.app.warp.Addr(); addr != "" {
				warp = addr
				p.app.warp.Want()
			}
		}
		cfg.UpstreamProxyURL = "socks5://" + strings.TrimPrefix(warp, "socks5://")
	case "proxy":
		cfg.UpstreamProxyURL = upstream
	case "desync":
		if addr := p.ensureLocalDesyncProxy(); addr != "" {
			cfg.UpstreamProxyURL = "socks5://" + addr
		}
	}
	if len(s.CustomProtos) > 0 {
		cfg.LimitTunnelProtocols = append([]string(nil), s.CustomProtos...)
	} else if set := psiProtoSets[s.Protos]; len(set) > 0 {
		cfg.LimitTunnelProtocols = append([]string(nil), set...)
	}
	carrier := carrierNameForStrategy(s)
	lastRep := p.lastPreflightReport()
	roundGuess := 0
	if timeout >= 150 {
		roundGuess = 2
	} else if timeout >= 75 {
		roundGuess = 1
	}
	applyTuning(cfg, preset, carrier, lastRep, roundGuess, seedEmptyOrRSL)
	if cfg.UpstreamProxyURL != "" {
		cfg.UpstreamProxyAllowAllServerEntrySources = ptr(true)
		return cfg
	}
	if s.DPI != "" {
		dpi = s.DPI
	}
	if dpi == "auto" {
		dpi = p.dpiAuto.next()
	}
	applyDPI(cfg, dpi)
	return cfg
}

// applyDPI configures tunnel-core's fragmentor and TLS ClientHello fragmentation.
func applyDPI(c *psiphon.Config, mode string) {
	frag := func(minT, maxT, minW, maxW, minD, maxD int) {
		c.FragmentorProbability = ptr(1.0)
		c.FragmentorMinTotalBytes = ptr(minT)
		c.FragmentorMaxTotalBytes = ptr(maxT)
		c.FragmentorMinWriteBytes = ptr(minW)
		c.FragmentorMaxWriteBytes = ptr(maxW)
		c.FragmentorMinDelayMicroseconds = ptr(minD)
		c.FragmentorMaxDelayMicroseconds = ptr(maxD)
	}
	switch mode {
	case "off":
		c.FragmentorProbability = ptr(0.0)
		c.TLSFragmentClientHelloProbability = ptr(0.0)
		return
	case "hello":
		c.FragmentorProbability = ptr(0.0)
	case "light":
		frag(100, 600, 20, 200, 100, 2000)
	case "strong":
		frag(1000, 3000, 1, 10, 5000, 30000)
	default:
		frag(256, 1400, 1, 16, 1000, 8000)
	}
	c.TLSFragmentClientHelloProbability = ptr(1.0)
}

// adaptiveHealthInterval adjusts the healthcheck period: shorter right after
// a failure (10 s) to quickly verify recovery, and gradually longer (up to 2x
// baseSec, max 90 s) when the tunnel has been consistently healthy.
func adaptiveHealthInterval(baseSec, consecutiveOK, consecutiveFails int) time.Duration {
	if baseSec < 10 {
		baseSec = 10
	}
	if consecutiveFails > 0 {
		return 10 * time.Second
	}
	if consecutiveOK >= 6 {
		return time.Duration(min(baseSec*2, 90)) * time.Second
	}
	if consecutiveOK >= 3 {
		return time.Duration(min(baseSec*3/2, 75)) * time.Second
	}
	return time.Duration(baseSec) * time.Second
}

// hasRecentTunnelTraffic reports whether traffic flowed through Psiphon within
// the last 15 seconds. Active tunnels carrying traffic are never torn down by
// a background ping timeout.
func (p *Psi) hasRecentTunnelTraffic() bool {
	if p == nil || p.app == nil || p.app.stats == nil {
		return false
	}
	snap := p.app.stats.snapshot()
	obs, _ := snap["outbounds"].([]map[string]any)
	var curBytes int64
	for _, ob := range obs {
		name, _ := ob["outbound"].(string)
		if name == obPsiphon || strings.HasPrefix(name, obPsiphon+":") {
			d, _ := ob["down"].(int64)
			u, _ := ob["up"].(int64)
			curBytes += d + u
		}
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if curBytes > p.lastTrafficBytes {
		p.lastTrafficBytes = curBytes
		p.lastTrafficAt = now
		return true
	}
	return !p.lastTrafficAt.IsZero() && now.Sub(p.lastTrafficAt) < 15*time.Second
}

// checkDirectNetAlive checks whether the local internet connection itself is
// alive (direct TCP handshake to common public DNS/CDN endpoints).
func (p *Psi) checkDirectNetAlive(ctx context.Context) bool {
	if p != nil && p.directAliveFunc != nil {
		return p.directAliveFunc(ctx)
	}
	targets := []string{"1.1.1.1:443", "8.8.8.8:53", "77.88.8.8:53"}
	for _, addr := range targets {
		dctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		c, err := dialDirect(dctx, "tcp", addr)
		cancel()
		if err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}

func (p *Psi) attemptOnce(ctx context.Context, s strategyDef, timeout int) (connected bool, err error) {
	netKey := p.currentNetKey()
	startAttempt := time.Now()
	carrier := carrierNameForStrategy(s)
	protos := protocolsForStrategy(s)
	cfg := p.configFor(s, timeout)
	if err := cfg.Commit(true); err != nil {
		return false, err
	}
	if err := psiphon.OpenDataStore(cfg); err != nil {
		return false, err
	}
	defer psiphon.CloseDataStore()

	p.loadSavedServerEntriesIntoStore(cfg)

	ctl, err := psiphon.NewController(cfg)
	if err != nil {
		return false, err
	}
	for len(p.notes) > 0 {
		<-p.notes
	}
	actx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	safeGo("Psi.attemptOnce", func() {
		ctl.Run(actx)
		close(runDone)
	})
	defer func() {
		// Graceful handover only on automatic rotation; manual Stop drops standby immediately.
		if !p.isUserStopped() {
			p.standby.Store(ctl)
		} else {
			p.standby.CompareAndSwap(ctl, nil)
		}
		p.cur.CompareAndSwap(ctl, nil)
		cancel()
		waitDur := 8 * time.Second
		if p.isUserStopped() {
			waitDur = 3 * time.Second
		}
		select {
		case <-runDone:
		case <-time.After(waitDur):
		}
		p.standby.CompareAndSwap(ctl, nil)
		p.set(func() { p.tunnels = 0 })
	}()

	baseHealthSec := func() int {
		p.app.cfg.mu.Lock()
		defer p.app.cfg.mu.Unlock()
		return max(p.app.cfg.Psiphon.HealthIntervalS, 10)
	}
	healthOK := 0
	healthFails := 0
	health := time.NewTicker(adaptiveHealthInterval(baseHealthSec(), 0, 0))
	defer health.Stop()

	var upAt time.Time
	var pendingConnMs int
	var rslGraceExtended bool
	quick := 0
	var holdC <-chan time.Time

	defer func() {
		if !upAt.IsZero() {
			life := time.Since(upAt)
			p.recordStrategyLifetime(netKey, p.effectiveStrategyID(s), life)
			p.tl().RecordHold(life)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return connected, ctx.Err()
		case <-runDone:
			return connected, errors.New("Psiphon завершил работу")
		case n := <-p.notes:
			switch n.Type {
			case "Tunnels":
				count := num(n.Data["count"])
				p.set(func() { p.tunnels = count })
				if count > 0 && p.cur.Load() == nil {
					connected = true
					connMs := int(time.Since(startAttempt).Milliseconds())
					pendingConnMs = connMs
					p.cur.Store(ctl)
					effID := p.effectiveStrategyID(s)
					p.set(func() {
						p.state = "connected"
						p.stage = "stage4_hold"
						p.lastErr = ""
						p.diagCode = ""
						p.diagReason = ""
						p.diagAdvice = ""
						p.since = time.Now()
					})
					if p.app != nil {
						p.app.tun.refresh()
					}
					p.mu.Lock()
					activeProto := p.protocol
					p.mu.Unlock()
					p.tl().RecordConnect(carrier, activeProto, connMs)
					connProtos := protos
					if activeProto != "" {
						connProtos = []string{activeProto}
					}
					p.tl().Record(connTimelineEvent{
						Stage:      "connected",
						Carrier:    carrier,
						StrategyID: effID,
						Protocols:  connProtos,
						DurationMs: int64(connMs),
						Outcome:    "ok",
					})
					logf("info", "Psiphon подключён: «%s» (%d мс, сеть %s)", s.Title, connMs, netKey)
					upAt, holdC = time.Now(), time.After(holdOK)
					{
						actx, s, ctl := actx, s, ctl // snapshot: the loop reuses these names
						safeGo("Psi.attemptOnce#2", func() { p.onConnected(actx, s, ctl) })
					}
				} else if count == 0 && p.cur.Load() != nil {
					p.cur.Store(nil)
					p.set(func() { p.state = "reconnecting"; p.since = time.Time{} })
					logf("warn", "Psiphon: туннели потеряны, переподключаюсь")
					holdC = nil
					if life := time.Since(upAt); !upAt.IsZero() {
						p.recordStrategyLifetime(netKey, p.effectiveStrategyID(s), life)
						p.tl().RecordHold(life)
						p.tl().Record(connTimelineEvent{
							Stage:      "disconnected",
							Carrier:    carrier,
							StrategyID: p.effectiveStrategyID(s),
							DurationMs: life.Milliseconds(),
							Outcome:    "failed",
						})
						if life < shortLife {
							quick++
							logf("warn", "Psiphon «%s»: туннели продержались всего %s", s.Title, humanDur(life))
							if quick >= 2 {
								p.markUnstable(p.effectiveStrategyID(s), true)
								logf("warn", "Psiphon «%s»: туннели рвутся вскоре после подключения — пробую следующий способ", s.Title)
								return true, errUnstable
							}
						}
						upAt = time.Time{}
					}
				}
			case "EstablishTunnelTimeout":
				if !rslGraceExtended && (p.rslInProgress.Load() || p.tacticsInProgress.Load()) {
					rslGraceExtended = true
					logf("info", "Psiphon «%s»: загрузка списка серверов/тактик ещё идёт — продлеваю ожидание", s.Title)
					continue
				}
				p.tl().Record(connTimelineEvent{
					Stage:      "timeout",
					Carrier:    carrier,
					StrategyID: s.ID,
					Protocols:  protos,
					DurationMs: time.Since(startAttempt).Milliseconds(),
					Outcome:    "timeout",
				})
				return connected, errTimeout
			case "Exiting":
				return connected, errors.New("Psiphon завершил работу")
			}
		case c := <-p.cmd:
			switch c {
			case "rotate":
				logf("info", "Psiphon: переподключаюсь к другому серверу (NetworkID сохранён)")
				return connected, errRotate
			case "manual-rotate":
				p.rotateNetID()
				logf("info", "Psiphon: смена узла по запросу пользователя")
				return connected, errForceRotate
			case "next":
				logf("info", "Psiphon: следующий способ подключения")
				return connected, errNext
			case "check": // after sleep or a network change (netwatch.go)
				if p.cur.Load() == nil {
					continue
				}
				if p.currentNetKey() != netKey {
					logf("info", "Psiphon: профиль сети изменился (%s → %s) — переключаю туннель", netKey, p.currentNetKey())
					return connected, errNetChange
				}
				ms, herr := p.ping(ctx)
				if herr != nil {
					if ctx.Err() != nil {
						return connected, ctx.Err()
					}
					if !p.checkDirectNetAlive(ctx) {
						p.set(func() {
							p.diagCode = "no_network"
							p.diagReason = "Нет подключения к интернету"
							p.diagAdvice = "Проверьте Wi-Fi или кабель — Psiroute переподключится автоматически"
						})
						continue
					}
					logf("warn", "Psiphon: после смены сети туннель не отвечает (%v) — переподключаюсь", herr)
					return connected, errNetChange
				}
				healthFails = 0
				healthOK++
				logf("info", "Psiphon: туннель работает (%d мс)", ms)
			}
		case <-holdC:
			holdC = nil
			effID := p.effectiveStrategyID(s)
			// Stage 4: record strategy as good ONLY after 64 KB transfer succeeds and tunnel held >= 3 min.
			if cerr := p.probeChunk64KB(ctx); cerr != nil {
				p.tl().RecordStall16KB()
				p.tl().Record(connTimelineEvent{
					Stage:      "stall_16kb",
					Carrier:    carrier,
					StrategyID: effID,
					Outcome:    "failed",
					Detail:     cerr.Error(),
				})
				logf("warn", "Psiphon «%s»: 64 КБ проверка после удержания не прошла (%v) — способ не запоминается", s.Title, cerr)
				continue
			}
			p.recordStrategySuccess(netKey, effID, pendingConnMs)
			p.tl().Record(connTimelineEvent{
				Stage:      "hold_ok",
				Carrier:    carrier,
				StrategyID: effID,
				DurationMs: int64(holdOK / time.Millisecond),
				Outcome:    "ok",
			})
			if p.dataDir != "" {
				_ = writeFileAtomic(p.file("psiroute-last"), []byte(effID), 0o600)
			}
			if p.isUnstable(effID) {
				p.markUnstable(effID, false)
			}
		case <-health.C:
			if p.cur.Load() == nil {
				continue
			}
			if p.hasRecentTunnelTraffic() {
				healthFails = 0
				healthOK++
				health.Reset(adaptiveHealthInterval(baseHealthSec(), healthOK, healthFails))
				continue
			}
			ms, herr := p.ping(ctx)
			if herr == nil {
				// Smart Watchdog: verify real >= 64 KB chunk transfer every 3rd health tick
				// to detect TSPU silent drops after ~16 KB while TCP socket stays alive.
				if healthOK > 0 && healthOK%3 == 0 {
					if cerr := p.probeChunk64KB(ctx); cerr != nil {
						p.tl().RecordStall16KB()
						p.tl().Record(connTimelineEvent{
							Stage:      "stall_16kb",
							Carrier:    carrier,
							StrategyID: s.ID,
							Outcome:    "failed",
							Detail:     cerr.Error(),
						})
						herr = fmt.Errorf("тихая блокировка >64 КБ: %w", cerr)
					}
				}
			}
			if herr != nil {
				if !p.checkDirectNetAlive(ctx) {
					logf("warn", "Psiphon: прямая сеть недоступна — ожидаю восстановления интернета, туннель не сбрасываю")
					p.set(func() {
						p.diagCode = "no_network"
						p.diagReason = "Нет прямого доступа к интернету"
						p.diagAdvice = "Проверьте подключение к Wi-Fi или провайдеру"
					})
					if p.app != nil && p.app.fsm != nil {
						p.app.fsm.Transition(CoreDegraded, StageCheck, "Нет прямого доступа к интернету")
					}
					health.Reset(10 * time.Second)
					continue
				}
				healthFails++
				healthOK = 0
				if p.app != nil && p.app.fsm != nil {
					p.app.fsm.Transition(CoreDegraded, StageCheck, short(herr.Error(), 90))
				}
				logf("warn", "Psiphon: проверка связи не прошла (%d/2): %s", healthFails, short(herr.Error(), 120))
				if healthFails >= 2 {
					if p.app != nil && p.app.fsm != nil {
						p.app.fsm.Transition(CoreReconnecting, StageTunnel, "Переключение транспорта после 2 сбоев Watchdog")
					}
					return connected, errRotate
				}
			} else {
				healthFails = 0
				healthOK++
				p.set(func() { p.healthMs = ms })
				if p.app != nil && p.app.fsm != nil {
					p.app.fsm.Transition(CoreConnected, StageReady, "")
				}
			}
			health.Reset(adaptiveHealthInterval(baseHealthSec(), healthOK, healthFails))
		}
	}
}

// effectiveStrategyID maps a combined "race-direct" connection back to the
// specific strategy matching the connected tunnel protocol so per-network
// statistics credit the winning protocol family.
func (p *Psi) effectiveStrategyID(s strategyDef) string {
	if s.ID != "race-direct" && s.ID != "desync-direct" {
		return s.ID
	}
	p.mu.Lock()
	proto := p.protocol
	p.mu.Unlock()
	if proto != "" {
		for k, set := range psiProtoSets {
			for _, pr := range set {
				if pr == proto {
					return k
				}
			}
		}
	}
	return "auto"
}

// onConnected checks where we came out, measures latency and, if a minimum
// speed is set, measures the speed and reconnects slow nodes without wiping NetworkID.
func (p *Psi) onConnected(ctx context.Context, s strategyDef, controller *psiphon.Controller) {
	p.dpiAuto.good()
	p.persistConnectedNodeHint()
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	tr, err := getTrace(tctx, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialCountryController(ctx, controller, addr)
	})
	cancel()
	if err == nil {
		p.set(func() {
			if tr.Loc != "" && p.cur.Load() == controller {
				p.egress = tr.Loc
				p.confirmedEgress = tr.Loc
				p.confirmedController = controller
			}
		})
		logf("info", "Psiphon: выход %s (%s, %s)", tr.IP, tr.Loc, tr.Colo)
		p.app.cfg.mu.Lock()
		pinnedReg := strings.TrimSpace(p.app.cfg.Psiphon.Country)
		p.app.cfg.mu.Unlock()
		if pinnedReg == "" && tr.Loc != "" && p.app.cfg.isCountryBlocked(tr.Loc) {
			logf("warn", "Psiphon: страна выхода %s в чёрном списке — автоматически меняю узел", tr.Loc)
			p.send("manual-rotate")
			return
		}
	}
	ms, _ := p.ping(ctx)
	p.mu.Lock()
	p.healthMs = ms
	node := map[string]any{
		"region":         p.egress,
		"server":         p.server,
		"protocol":       p.protocol,
		"strategy_title": s.Title,
		"net_key":        p.currentNetKey(),
		"since":          time.Now().Unix(),
	}
	p.nodes = append([]map[string]any{node}, p.nodes...)
	if len(p.nodes) > 30 {
		p.nodes = p.nodes[:30]
	}
	p.mu.Unlock()

	p.app.cfg.mu.Lock()
	minSpeed := p.app.cfg.Psiphon.MinSpeedKBps
	p.app.cfg.mu.Unlock()
	if minSpeed <= 0 {
		return
	}
	kbps, err := p.speed(ctx, 8*time.Second)
	if err != nil || ctx.Err() != nil {
		return
	}
	if kbps < minSpeed {
		logf("warn", "Psiphon: узел медленный (%d КБ/с < %d), переподключаю без сброса NetworkID", kbps, minSpeed)
		p.send("rotate")
	}
}

// ---- dialing & optional 2-tunnel parallel load-balancing pool (Priority 6) ----

type poolTrackedConn struct {
	net.Conn
	counter *atomic.Int32
	once    sync.Once
}

func (c *poolTrackedConn) Close() error {
	c.once.Do(func() {
		if c.counter != nil {
			c.counter.Add(-1)
		}
	})
	return c.Conn.Close()
}

func (c *poolTrackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// DialBalanced distributes outgoing TCP streams across up to 2 parallel Psiphon
// tunnels (Priority 6: Least-Active-Connections + Round-Robin) when
// Psiphon.Parallel >= 2 and a secondary tunnel (standby or country pool worker)
// is available, falling back seamlessly to the primary tunnel.
func (p *Psi) DialBalanced(ctx context.Context, network, addr string) (net.Conn, error) {
	if p == nil || p.app == nil || p.app.cfg == nil {
		return p.Dial(ctx, network, addr)
	}
	p.app.cfg.mu.Lock()
	parallel := p.app.cfg.Psiphon.Parallel
	region := strings.ToUpper(strings.TrimSpace(p.app.cfg.Psiphon.Country))
	p.app.cfg.mu.Unlock()

	c0 := p.activeConns0.Load()
	c1 := p.activeConns1.Load()
	seq := p.poolRR.Add(1)

	// When Parallel >= 2 and primary tunnel already has active streams (or on odd
	// round-robin turns when load is equal), try the secondary tunnel slot first.
	if parallel >= 2 && (c0 > c1 || (c0 == c1 && seq%2 == 1)) {
		// 1. Check if an in-process standby controller is ready
		if sb := p.standby.Load(); sb != nil && sb != p.cur.Load() {
			if conn, err := sb.Dial(addr, nil); err == nil && conn != nil {
				p.activeConns1.Add(1)
				p.balancedDials.Add(1)
				return &poolTrackedConn{Conn: conn, counter: &p.activeConns1}, nil
			}
		}
		// 2. Check if a secondary worker tunnel in Countries pool is warm/connected
		if p.app.countries != nil {
			if conn, err := p.app.countries.DialPoolSlot(ctx, region, addr); err == nil && conn != nil {
				p.activeConns1.Add(1)
				p.balancedDials.Add(1)
				return &poolTrackedConn{Conn: conn, counter: &p.activeConns1}, nil
			}
		}
	}

	conn, err := p.Dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	p.activeConns0.Add(1)
	return &poolTrackedConn{Conn: conn, counter: &p.activeConns0}, nil
}

// Dial opens a connection through the active Psiphon tunnel (or the standby
// controller during a graceful switch). If Psiphon is still connecting it
// waits up to 20 seconds.
func (p *Psi) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if p != nil && p.primaryDialHook != nil {
		return p.primaryDialHook(ctx, network, addr)
	}
	deadline := time.Now().Add(20 * time.Second)
	for try := 0; ; try++ {
		ctl := p.cur.Load()
		if ctl == nil {
			ctl = p.standby.Load()
		}
		if ctl == nil {
			if !p.running() || time.Now().After(deadline) {
				return nil, errors.New("Psiphon не подключён")
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
			continue
		}
		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		safeGo("Psi.Dial", func() {
			c, err := ctl.Dial(addr, nil)
			ch <- res{c, err}
		})
		select {
		case <-ctx.Done():
			safeGo("Psi.Dial#2", func() {
				if r := <-ch; r.c != nil {
					r.c.Close()
				}
			})
			return nil, ctx.Err()
		case r := <-ch:
			if r.err == nil {
				p.dialFails.Store(0)
				return r.c, nil
			}
			if try >= 1 {
				if p.dialFails.Add(1) >= 3 {
					now := time.Now().Unix()
					if last := p.lastCheck.Load(); now-last >= 5 && p.lastCheck.CompareAndSwap(last, now) {
						p.dialFails.Store(0)
						p.send("check")
					}
				}
				return nil, errors.New(cleanPsiErr(r.err.Error()))
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
}

// ping probes multiple independent targets (gstatic, cloudflare, connectivitycheck)
// through the tunnel. It succeeds as soon as one target responds and returns
// an error ONLY if all targets fail.
func (p *Psi) ping(ctx context.Context) (int, error) {
	var lastErr error
	for _, tgt := range psiPingTargets {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		ms, err := p.pingOneTarget(ctx, tgt.Host, tgt.Path)
		if err == nil {
			return ms, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("нет ответа от проверочных узлов")
	}
	return 0, lastErr
}

func (p *Psi) pingOneTarget(ctx context.Context, host, path string) (int, error) {
	if p != nil && p.pingTargetFunc != nil {
		return p.pingTargetFunc(ctx, host, path)
	}
	tctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	t0 := time.Now()
	c, err := p.Dial(tctx, "tcp", host)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	hostname := host
	if h, _, serr := net.SplitHostPort(host); serr == nil && h != "" {
		hostname = h
	}
	req := fmt.Sprintf("HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n", path, hostname)
	if _, err := io.WriteString(c, req); err != nil {
		return 0, err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(line, "HTTP/") {
		return 0, errors.New("неожиданный ответ")
	}
	return int(time.Since(t0).Milliseconds()), nil
}

// probeChunk64KB verifies that the active tunnel can transfer at least 64 KB
// of payload data (detecting TSPU silent drops that stall flows after ~16 KB).
func (p *Psi) probeChunk64KB(ctx context.Context) error {
	if p == nil {
		return errors.New("psiphon nil")
	}
	_, _, err := probeChunk64KBWithDial(ctx, p.Dial, probeChunkURL)
	return err
}

// speed downloads for up to d and returns KB/s (0 when under 32 KB came in).
func (p *Psi) speed(ctx context.Context, d time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d+10*time.Second)
	defer cancel()
	cl := &http.Client{Timeout: d + 15*time.Second, Transport: &http.Transport{DialContext: p.DialBalanced}} // A-12: ctx stays, the client timeout is a second guard
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", speedURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	t0 := time.Now()
	buf := make([]byte, 64<<10)
	var total int64
	for time.Since(t0) < d {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
	}
	secs := time.Since(t0).Seconds()
	kbps := 0
	if total >= 32<<10 && secs > 0 {
		kbps = int(float64(total) / 1024 / secs)
	}
	p.mu.Lock()
	p.speedKBps = kbps
	if p.egress != "" {
		p.regionStats[p.egress] = map[string]any{"kbps": kbps, "ms": p.healthMs}
	}
	p.mu.Unlock()
	return kbps, nil
}

// SpeedTest is the "measure speed" button.
func (p *Psi) SpeedTest(ctx context.Context) map[string]any {
	ms, err := p.ping(ctx)
	if err != nil {
		return map[string]any{"ok": false, "error": short(err.Error(), 160)}
	}
	kbps, err := p.speed(ctx, 8*time.Second)
	if err != nil {
		return map[string]any{"ok": false, "error": short(err.Error(), 160)}
	}
	p.mu.Lock()
	p.healthMs = ms
	region := p.egress
	p.mu.Unlock()
	return map[string]any{"ok": true, "kbps": kbps, "ms": ms, "region": region}
}

// ---- Server Entries Import, Emergency DNS TXT / Mirror Bootstrap (Priority 4) & Diagnostics ----

func (p *Psi) serverEntriesFile() string {
	return p.file("psiphon-server-entries.txt")
}

// (Dead hardcoded emergency bootstrap removed in Step 2; see psi_seed.go for multi-carrier seed pipeline.)

// persistConnectedNodeHint сохраняет метаданные успешного подключения в кэш dataDir (Раздел 3.3 ТЗ).
func (p *Psi) persistConnectedNodeHint() {
	if p == nil || p.dataDir == "" {
		return
	}
	p.mu.Lock()
	srv := p.server
	reg := p.egress
	proto := p.protocol
	p.mu.Unlock()
	if srv == "" && reg == "" {
		return
	}
	meta := map[string]any{
		"server":     srv,
		"region":     reg,
		"protocol":   proto,
		"updated_at": time.Now().Unix(),
	}
	if b, err := json.Marshal(meta); err == nil {
		_ = writeFileAtomic(p.file("psiphon-last-node.json"), b, 0o600)
	}
}

// validateServerEntryHex декодирует и проверяет запись сервера через protocol.DecodeServerEntryFields
// из psiphon-tunnel-core (Баг №5: проверка обязательных полей IP, порт/ключи, регион/протоколы).
// isGlobalServerIP reports whether ip is a public unicast address that a server
// entry may legitimately use.
func isGlobalServerIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsUnspecified(), ip.IsLoopback(), ip.IsPrivate(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast():
		return false
	}
	return ip.IsGlobalUnicast()
}

func validateServerEntryHex(hexLine string) (ipAddr string, ok bool) {
	hexLine = strings.TrimSpace(hexLine)
	if len(hexLine) < 32 {
		return "", false
	}
	fields, err := protocol.DecodeServerEntryFields(hexLine, "", protocol.SERVER_ENTRY_SOURCE_TARGET)
	if err != nil || fields == nil {
		return "", false
	}
	ipStr, _ := fields["ipAddress"].(string)
	ipStr = strings.TrimSpace(ipStr)
	// Audit A-04: a seed entry must point at a public internet address. Loopback,
	// private, link-local, unspecified and multicast addresses would turn an
	// imported entry into a way to make the program connect into the local network.
	if ipStr == "" || !isGlobalServerIP(net.ParseIP(ipStr)) {
		return "", false
	}
	hasPort := fields["sshObfuscatedPort"] != nil || fields["sshPort"] != nil ||
		fields["webServerPort"] != nil || fields["meekServerPort"] != nil || fields["frontingSpecs"] != nil
	hasAuth := fields["sshObfuscatedKey"] != nil || fields["sshHostKey"] != nil ||
		fields["webServerSecret"] != nil || fields["meekCookieEncryptionPublicKey"] != nil
	hasCapOrRegion := fields["capabilities"] != nil || fields["region"] != nil
	if !hasPort || !hasAuth || !hasCapOrRegion {
		return "", false
	}
	return ipStr, true
}

func (p *Psi) importServerEntriesWithoutRestart(raw, source string) (added, dup, invalid int, err error) {
	type candEntry struct {
		hex string
		ip  string
	}
	var validEntries []candEntry
	seen := 0
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		// Audit A-04: one import takes at most seedImportMaxEntries records;
		// the rest are counted as skipped so a huge paste cannot stall the app.
		seen++
		if seen > seedImportMaxEntries {
			invalid++
			continue
		}
		hexToken := ""
		if _, herr := hex.DecodeString(token); herr == nil {
			hexToken = strings.ToLower(token)
		} else if decoded, berr := base64.StdEncoding.DecodeString(token); berr == nil && len(decoded) > 16 {
			if _, herr2 := hex.DecodeString(string(decoded)); herr2 == nil {
				hexToken = strings.ToLower(strings.TrimSpace(string(decoded)))
			} else {
				hexToken = hex.EncodeToString(decoded)
			}
		}
		if hexToken == "" {
			invalid++
			continue
		}
		ipAddr, ok := validateServerEntryHex(hexToken)
		if !ok {
			invalid++
			continue
		}
		validEntries = append(validEntries, candEntry{hex: hexToken, ip: ipAddr})
	}
	if seen > seedImportMaxEntries {
		logf("warn", "Psiphon: импорт serverEntries (%s): принято только первые %d записей из %d — остальные пропущены. Импортируйте остаток отдельным списком", source, seedImportMaxEntries, seen)
	}
	if len(validEntries) == 0 {
		return 0, 0, invalid, errors.New("не найдено валидных записей серверов Psiphon (адрес должен быть публичным, а запись — корректной по protocol.DecodeServerEntryFields)")
	}

	existingHex := map[string]bool{}
	existingIP := map[string]bool{}
	var merged []string
	if b, rerr := os.ReadFile(p.serverEntriesFile()); rerr == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.ToLower(strings.TrimSpace(ln))
			if ln == "" {
				continue
			}
			if ipAddr, ok := validateServerEntryHex(ln); ok {
				if !existingHex[ln] && !existingIP[ipAddr] {
					existingHex[ln] = true
					existingIP[ipAddr] = true
					merged = append(merged, ln)
				}
			}
		}
	}
	for _, ce := range validEntries {
		if existingHex[ce.hex] || existingIP[ce.ip] {
			dup++
			continue
		}
		existingHex[ce.hex] = true
		existingIP[ce.ip] = true
		merged = append(merged, ce.hex)
		added++
	}
	if p.dataDir != "" {
		if werr := writeFileAtomic(p.serverEntriesFile(), []byte(strings.Join(merged, "\n")+"\n"), 0o600); werr != nil {
			return 0, 0, invalid, werr
		}
	}
	logf("info", "Psiphon: импорт serverEntries (%s): добавлено %d, дубликатов %d, отброшено %d (всего в базе: %d)", source, added, dup, invalid, len(merged))
	return added, dup, invalid, nil
}

// importServerEntriesDetailed декодирует, строго валидирует через protocol.DecodeServerEntryFields
// и дедуплицирует по IP/ключу записи серверов Psiphon (Баг №5).
func (p *Psi) importServerEntriesDetailed(raw, source string) (added, dup, invalid int, err error) {
	added, dup, invalid, err = p.importServerEntriesWithoutRestart(raw, source)
	if err == nil && added > 0 && p.running() {
		safeGo("Psi.importServerEntriesDetailed", p.Restart)
	}
	return added, dup, invalid, err
}

func (p *Psi) importServerEntries(raw, source string) (int, error) {
	added, dup, _, err := p.importServerEntriesDetailed(raw, source)
	if err != nil {
		return 0, err
	}
	return added + dup, nil
}

func (p *Psi) importedServerEntriesCount() int {
	if p == nil || p.dataDir == "" {
		return 0
	}
	b, err := os.ReadFile(p.serverEntriesFile())
	if err != nil {
		return 0
	}
	n := 0
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}

func (p *Psi) loadSavedServerEntriesIntoStore(cfg *psiphon.Config) {
	if p == nil || p.dataDir == "" {
		return
	}
	b, err := os.ReadFile(p.serverEntriesFile())
	if err != nil {
		return
	}
	var entries []protocol.ServerEntryFields
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			if f, err := protocol.DecodeServerEntryFields(ln, "", protocol.SERVER_ENTRY_SOURCE_TARGET); err == nil && f != nil {
				entries = append(entries, f)
			}
		}
	}
	if len(entries) > 0 {
		_ = psiphon.StoreServerEntries(cfg, entries, false)
	}
}

// classifyFailure analyzes the last connection attempt failure and returns a
// structured diagnostic code, human-readable Russian reason, and actionable advice.
func (p *Psi) classifyFailure(ctx context.Context, s strategyDef, err error) (code, reason, advice string) {
	errStr := ""
	if err != nil {
		errStr = strings.ToLower(err.Error())
	}
	p.mu.Lock()
	lastE := strings.ToLower(p.lastErr)
	cands := p.candidates
	rslFails := p.rslFailed
	p.mu.Unlock()
	combined := errStr + " " + lastE

	// 1. Check direct network connectivity
	if !p.checkDirectNetAlive(ctx) {
		return "no_network",
			"Нет подключения к интернету",
			"Проверьте Wi-Fi, кабель или соединение у провайдера — Psiroute подключится автоматически"
	}
	// 2. Clock skew / certificate time error
	if strings.Contains(combined, "certificate has expired or is not yet valid") ||
		strings.Contains(combined, "clock skew") || strings.Contains(combined, "x509:") && strings.Contains(combined, "time") {
		return "clock_skew",
			"Системные часы спешат или отстают",
			"Включите автоматическую синхронизацию времени в параметрах Windows"
	}
	// 3. Dead upstream proxy / WARP
	if s.Transport == "proxy" || s.Transport == "warp" || strings.Contains(combined, "внешний прокси") || strings.Contains(combined, "upstreamproxy") {
		if s.Transport == "warp" && !p.warpUp() {
			return "upstream_dead",
				"Подложка Cloudflare WARP ещё не подключилась",
				"Подождите подъёма WARP или смените маскировку WARP в разделе «Страны и обход DPI»"
		}
		if s.Transport == "proxy" || strings.Contains(combined, "внешний прокси") {
			return "upstream_dead",
				"Не отвечает внешний прокси-сервер",
				"Проверьте адрес внешнего прокси в настройках или переключитесь на прямое подключение"
		}
	}
	// 4. Zero candidate servers / remote server list unreachable
	if cands == 0 || (rslFails >= 2 && cands <= 0) {
		return "no_candidates",
			"Нет доступных серверов-кандидатов (основной список серверов недоступен)",
			"Включите режим «Через WARP» или импортируйте записи серверов (server entries) во вкладке «Диагностика»"
	}
	// 5. Connection reset right after handshake (active DPI cutting tunnel)
	if errors.Is(err, errUnstable) || strings.Contains(combined, "reset by peer") || strings.Contains(combined, "wsarecv") || strings.Contains(combined, "eof") {
		return "handshake_reset",
			"Провайдер сбрасывает соединение после рукопожатия (блокировка ТСПУ)",
			"Включите «Через WARP» на главной или выберите сильное дробление DPI для Psiphon"
	}
	// 6. Timeout across all candidate servers
	if errors.Is(err, errTimeout) || strings.Contains(combined, "отведённое время") || strings.Contains(combined, "timeout") {
		return "all_timeout",
			"Серверы способа «" + s.Title + "» не ответили вовремя",
			"Переключаюсь на следующий способ; для ускорения можно включить WARP или запустить автоподбор"
	}
	return "unknown",
		"Не удалось установить туннель («" + s.Title + "»)",
		"Psiroute автоматически перебирает доступные способы подключения"
}

// ---- notices ----

func (p *Psi) onNotice(b []byte) {
	var n psiNotice
	if json.Unmarshal(b, &n) != nil {
		return
	}
	switch n.Type {
	case "Tunnels", "EstablishTunnelTimeout", "Exiting":
		select {
		case p.notes <- n:
		default:
		}
	case "AvailableEgressRegions":
		regs := strList(n.Data["regions"])
		p.set(func() { p.regions = regs })
	case "ClientRegion":
		r, _ := n.Data["region"].(string)
		p.set(func() { p.clientReg = r })
	case "ConnectedServerRegion":
		r, _ := n.Data["serverRegion"].(string)
		p.set(func() { p.egress = r })
	case "ActiveTunnel":
		proto, _ := n.Data["protocol"].(string)
		id, _ := n.Data["diagnosticID"].(string)
		p.set(func() {
			p.protocol = proto
			if id != "" {
				p.server = id
			}
		})
	case "ConnectingServer":
		if id, _ := n.Data["diagnosticID"].(string); id != "" {
			p.set(func() {
				if p.state != "connected" {
					p.server = id
				}
			})
		}
	case "CandidateServers":
		cnt := num(n.Data["count"])
		p.set(func() { p.candidates = cnt })
		p.tl().Record(connTimelineEvent{Stage: "notice", Outcome: "info", Detail: fmt.Sprintf("CandidateServers=%d", cnt)})
		if cnt == 0 {
			info := diagInfoForCode(DiagNoSeed)
			p.set(func() {
				p.diagCode = DiagNoSeed
				p.diagReason = info.Message
				p.diagAdvice = info.ManualAction
			})
			logf("warn", "Psiphon: в базе 0 подходящих серверов-кандидатов — требуется загрузка списка через рабочий носитель или ручной импорт")
		} else {
			logf("info", "Psiphon: серверов-кандидатов: %d", cnt)
		}
	case "RemoteServerListResourceDownloadedBytes":
		p.rslInProgress.Store(true)
	case "RemoteServerListResourceDownloaded":
		p.rslInProgress.Store(false)
		p.set(func() { p.rslFailed = 0 })
		p.tl().Record(connTimelineEvent{Stage: "notice", Outcome: "ok", Detail: "RemoteServerListResourceDownloaded"})
		logf("info", "Psiphon: список серверов обновлён")
	case "RemoteServerListResourceDownloadFailed":
		p.rslInProgress.Store(false)
		p.mu.Lock()
		p.rslFailed++
		fails := p.rslFailed
		p.mu.Unlock()
		p.tl().Record(connTimelineEvent{Stage: "notice", Outcome: "failed", Detail: fmt.Sprintf("RemoteServerListResourceDownloadFailed#%d", fails)})
		if fails == 1 || fails%3 == 0 {
			logf("warn", "Psiphon: не удалось скачать список серверов с основного адреса (попытка %d)", fails)
		}
	case "RequestingTactics":
		p.tacticsInProgress.Store(true)
	case "RequestedTactics", "ApplicationParameters":
		p.tacticsInProgress.Store(false)
		p.set(func() { p.tacticsApplied = true })
		p.tl().Record(connTimelineEvent{Stage: "notice", Outcome: "ok", Detail: "tactics_applied"})
		logf("info", "Psiphon: тактики успешно получены и применены")
	case "Info":
		if msg, _ := n.Data["message"].(string); strings.Contains(msg, "applied ") && strings.Contains(msg, "parameters with tag") {
			p.tacticsInProgress.Store(false)
			tag := ""
			if i := strings.Index(msg, "tag '"); i >= 0 {
				rest := msg[i+5:]
				if j := strings.IndexByte(rest, '\''); j >= 0 {
					tag = rest[:j]
				}
			}
			p.set(func() {
				p.tacticsApplied = true
				p.tacticsTag = maskTimelineSecrets(tag)
			})
			p.tl().Record(connTimelineEvent{Stage: "notice", Outcome: "ok", Detail: "tactics_applied"})
		}
	case "UpstreamProxyError":
		msg, _ := n.Data["message"].(string)
		msg = cleanPsiErr(msg)
		p.set(func() {
			p.lastErr = "внешний прокси: " + msg
			p.diagCode = "upstream_dead"
			p.diagReason = "Ошибка внешнего прокси или WARP: " + msg
			p.diagAdvice = "Проверьте работоспособность прокси-сервера или перезапустите WARP"
		})
		p.tl().Record(connTimelineEvent{Stage: "notice", Outcome: "failed", DiagCode: "upstream_dead", Detail: "UpstreamProxyError: " + msg})
		logf("warn", "Psiphon: ошибка внешнего прокси: %s", msg)
	case "Warning", "Error":
		msg, _ := n.Data["message"].(string)
		if strings.Contains(msg, "close tunnel ssh error") && strings.Contains(msg, "use of closed network connection") {
			return
		}
		for _, x := range psiNoise {
			if strings.Contains(msg, x) {
				return
			}
		}
		msg = cleanPsiErr(msg)
		p.mu.Lock()
		key := short(msg, 60)
		fresh := !p.warnSeen[key] && len(p.warnSeen) < 6
		p.warnSeen[key] = true
		p.mu.Unlock()
		if fresh {
			logf("warn", "Psiphon: %s", msg)
		}
	}
}

// ---- views for the API ----

func (p *Psi) view() map[string]any {
	netKey := p.currentNetKey()
	netID := p.netID()
	p.mu.Lock()
	defer p.mu.Unlock()
	since := int64(0)
	if !p.since.IsZero() {
		since = p.since.Unix()
	}
	p.app.cfg.mu.Lock()
	region := p.app.cfg.Psiphon.Country
	p.app.cfg.mu.Unlock()
	return map[string]any{
		"state":            p.state,
		"last_error":       p.lastErr,
		"diag_code":        p.diagCode,
		"diag_reason":      p.diagReason,
		"diag_advice":      p.diagAdvice,
		"strategy_id":      p.strategy.ID,
		"strategy_title":   p.strategy.Title,
		"attempt":          p.attempt,
		"egress_region":    p.egress,
		"region":           region,
		"server":           p.server,
		"protocol":         p.protocol,
		"speed_kbps":       p.speedKBps,
		"health_ms":        p.healthMs,
		"connected_since":  since,
		"active_slot":      0,
		"client_region":    p.clientReg,
		"tunnels":          p.tunnels,
		"candidates":       p.candidates,
		"net_key":          netKey,
		"network_id":       netID,
		"imported_entries": p.importedServerEntriesCount(),
		"balanced_dials":   p.balancedDials.Load(),
		"user_stopped":     p.isUserStopped(),
	}
}

// statsView returns detailed per-network and per-strategy telemetry for
// GET /api/psiphon/stats and the Diagnostics tab.
func (p *Psi) statsView() map[string]any {
	netKey := p.currentNetKey()
	netID := p.netID()
	enabled := p.enabled()
	ordered := p.orderForNetwork(netKey, enabled, p.lastGood())
	now := time.Now()
	timelineEvents := p.tl().Events()
	timelineCounters := p.tl().Counters()
	preflightRep := p.lastPreflightReport()

	p.mu.Lock()
	defer p.mu.Unlock()
	mem := p.stratMemLocked()

	stratRows := make([]map[string]any, 0, len(psiStrategies))
	for i, s := range psiStrategies {
		st := p.netStatsLocked(netKey, s.ID, false)
		attempts, successes, medConnMs, medLifeSec := 0, 0, 0, 0
		lastOK := int64(0)
		unstableUntil := int64(0)
		if st != nil {
			attempts = st.Attempts
			successes = st.Successes
			medConnMs = st.MedianConnectMs
			medLifeSec = st.MedianLifetimeSec
			lastOK = st.LastSuccessUnix
			unstableUntil = st.UnstableUntil
		}
		score := p.scoreStrategyLocked(netKey, s.ID, i, "", now)
		rank := -1
		for rIdx, o := range ordered {
			if o.ID == s.ID {
				rank = rIdx + 1
				break
			}
		}
		stratRows = append(stratRows, map[string]any{
			"id":                  s.ID,
			"title":               s.Title,
			"transport":           s.Transport,
			"rank":                rank,
			"score":               int(score*10) / 10,
			"attempts":            attempts,
			"successes":           successes,
			"median_connect_ms":   medConnMs,
			"median_lifetime_sec": medLifeSec,
			"last_success_unix":   lastOK,
			"unstable_until":      unstableUntil,
			"unstable":            unstableUntil > now.Unix(),
		})
	}

	networksSummary := map[string]any{}
	for nk, m := range mem.Networks {
		networksSummary[nk] = m
	}

	return map[string]any{
		"ok":               true,
		"net_key":          netKey,
		"network_id":       netID,
		"state":            p.state,
		"diag_code":        p.diagCode,
		"diag_reason":      p.diagReason,
		"diag_advice":      p.diagAdvice,
		"candidates":       p.candidates,
		"rsl_failed":       p.rslFailed,
		"imported_entries": p.importedServerEntriesCount(),
		"balanced_dials":   p.balancedDials.Load(),
		"active_conns_0":   p.activeConns0.Load(),
		"active_conns_1":   p.activeConns1.Load(),
		"strategies":        stratRows,
		"networks":          networksSummary,
		"timeline":          timelineEvents,
		"timeline_counters": timelineCounters,
		"preflight":         preflightRep,
	}
}

// slots shows the tunnel pool: slot 0 carries primary traffic, slot 1 carries
// balanced parallel streams or warm standby failover (Priority 6).
func (p *Psi) slots() []map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.app.cfg.mu.Lock()
	n := max(p.app.cfg.Psiphon.Parallel, 1)
	p.app.cfg.mu.Unlock()
	out := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		st := p.state
		switch {
		case p.state == "stopped":
			st = "stopped"
		case i < p.tunnels && i == 0:
			st = "connected"
		case i < p.tunnels:
			st = "standby"
		case p.state == "connected":
			st = "connecting"
		}
		s := map[string]any{"idx": i, "state": st, "strategy": p.strategy.ID, "strategy_title": p.strategy.Title,
			"protocol": "", "server": "", "health_ms": 0, "speed_kbps": 0, "last_error": ""}
		if i == 0 {
			s["protocol"], s["server"], s["health_ms"], s["speed_kbps"], s["last_error"] = p.protocol, p.server, p.healthMs, p.speedKBps, p.lastErr
			s["active_conns"] = p.activeConns0.Load()
		} else if i == 1 {
			s["active_conns"] = p.activeConns1.Load()
			if p.activeConns1.Load() > 0 {
				s["state"] = "connected"
			}
		}
		out = append(out, s)
	}
	return out
}

func (p *Psi) info() map[string]any {
	c := p.app.cfg
	c.mu.Lock()
	order := append([]string(nil), c.Psiphon.Strategies...)
	favs := append([]string(nil), c.Psiphon.FavoriteCountries...)
	parallel, standby := c.Psiphon.Parallel, c.Psiphon.Standby
	health, minSpeed := c.Psiphon.HealthIntervalS, c.Psiphon.MinSpeedKBps
	c.mu.Unlock()
	on := map[string]bool{}
	for _, id := range order {
		on[id] = true
	}
	sorted := []strategyDef{}
	for _, id := range order {
		if s, ok := strategyByID(id); ok {
			sorted = append(sorted, s)
		}
	}
	for _, s := range psiStrategies {
		if !on[s.ID] {
			sorted = append(sorted, s)
		}
	}
	list := []map[string]any{}
	for _, s := range sorted {
		protos := psiProtoSets[s.Protos]
		if protos == nil {
			protos = []string{}
		}
		list = append(list, map[string]any{"id": s.ID, "title": s.Title, "protocols": protos,
			"upstream": s.Upstream, "available": p.available(s), "enabled": on[s.ID]})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	regions := p.regions
	live := len(regions) > 0
	if !live {
		regions = []string{"AT", "BE", "BG", "CA", "CH", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "HU", "IE", "IN", "IT", "JP", "LV", "NL", "NO", "PL", "RO", "RS", "SE", "SG", "SK", "US"}
	}
	nodes := append([]map[string]any(nil), p.nodes...)
	if nodes == nil {
		nodes = []map[string]any{}
	}
	rs := map[string]any{}
	for k, v := range p.regionStats {
		rs[k] = v
	}
	return map[string]any{
		"egress_region": p.egress, "regions": regions, "regions_live": live, "region_stats": rs,
		"favorite_countries": favs,
		"nodes":              nodes, "strategies": list, "order": order, "parallel": parallel, "standby": standby,
		"health_interval_secs": health, "min_speed_kbps": minSpeed, "dpi": psiDPINames,
	}
}
