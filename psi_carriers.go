package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Stage 0 Preflight and Carrier abstraction (Step 1).
// Treats outbound carriers (direct, direct+dpi, warp, worker, proxy) as
// first-class transports, probes them in parallel within <= 8 s, caches
// CarrierReport per network key with TTL, and classifies network faults from
// observed facts rather than fragile error-string heuristics.

const (
	carrierDirect    = "direct"
	carrierDirectDPI = "direct+dpi"
	carrierWARP      = "warp"
	carrierWorker    = "worker"
	carrierProxy     = "proxy"

	preflightBudget    = 8 * time.Second
	preflightCacheTTL  = 2 * time.Minute
	probeChunkMinBytes = 64 << 10 // >= 64 KB to detect ~16 KB TSPU stalls
	probeChunkReqBytes = 73728    // 72 KB request buffer for reliable 64 KB check
	probeChunkURL      = "https://speed.cloudflare.com/__down?bytes=73728"
	preflightListHost  = "s3.amazonaws.com"
	preflightListAddr  = "s3.amazonaws.com:443"
	preflightUDPAddr   = "162.159.192.1:2408"
	// preflightDNSHostB is the second host for the DNS-poisoning verdict (A-09):
	// a CDN may legitimately answer differently from system DNS and DoH, so a
	// single disjoint host proves nothing.
	preflightDNSHostB = "speed.cloudflare.com"
	// A silent ~16 KB cut is only believed when it is reproduced at two different
	// destinations of the same carrier and lies in this window (A-02, A-09).
	throttleCutMinBytes = 12 << 10
	throttleCutMaxBytes = 24 << 10
	clockSkewThreshold = 5 * time.Minute
)

// Fact-based diagnostic failure codes (Section 3.5).
const (
	DiagNoNetwork            = "NO_NETWORK"
	DiagClockSkew            = "CLOCK_SKEW"
	DiagDNSPoisoned          = "DNS_POISONED"
	DiagListHostBlocked      = "LIST_HOST_BLOCKED"
	DiagNoSeed               = "NO_SEED"
	DiagCarrierThrottled16KB = "CARRIER_THROTTLED_16KB"
	DiagUDPBlocked           = "UDP_BLOCKED"
	DiagHandshakeReset       = "HANDSHAKE_RESET"
	DiagAllProtocolsTimeout  = "ALL_PROTOCOLS_TIMEOUT"
	DiagTunnelUnstable       = "TUNNEL_UNSTABLE"
)

// DiagInfo describes a classified failure in Russian with automatic and manual actions.
type DiagInfo struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	AutoAction   string `json:"auto_action"`
	ManualAction string `json:"manual_action"`
}

func diagInfoForCode(code string) DiagInfo {
	switch code {
	case DiagNoNetwork:
		return DiagInfo{
			Code:         DiagNoNetwork,
			Message:      "Нет подключения к интернету",
			AutoAction:   "Ожидаю восстановления сети и повторяю preflight",
			ManualAction: "Проверьте Wi-Fi, кабель или соединение у провайдера",
		}
	case DiagClockSkew:
		return DiagInfo{
			Code:         DiagClockSkew,
			Message:      "Системные часы сильно спешат или отстают",
			AutoAction:   "Останавливаю попытки TLS-подключения до коррекции времени",
			ManualAction: "Включите автоматическую синхронизацию времени в параметрах Windows",
		}
	case DiagDNSPoisoned:
		return DiagInfo{
			Code:         DiagDNSPoisoned,
			Message:      "Системный DNS возвращает подменённые адреса (DNS-отравление)",
			AutoAction:   "Переключаюсь на DoH / локальный desync-прокси с DoH-резолвером",
			ManualAction: "Включите DoH в настройках DNS или используйте режим «Прямой + DPI» / «WARP»",
		}
	case DiagListHostBlocked:
		return DiagInfo{
			Code:         DiagListHostBlocked,
			Message:      "Основной хост списка серверов (S3) заблокирован на прямом канале",
			AutoAction:   "Загружаю список серверов через резервные рабочие носители",
			ManualAction: "Включите WARP / Worker или импортируйте записи серверов во вкладке «Диагностика»",
		}
	case DiagNoSeed:
		return DiagInfo{
			Code:         DiagNoSeed,
			Message:      "Нет ни одной доступной записи сервера Psiphon",
			AutoAction:   "Пробую получить список серверов через все доступные носители",
			ManualAction: "Импортируйте записи серверов (текст, файл или QR) во вкладке «Диагностика»",
		}
	case DiagCarrierThrottled16KB:
		return DiagInfo{
			Code:         DiagCarrierThrottled16KB,
			Message:      "Канал обрывает передачу после ~16 КБ (ограничение ТСПУ)",
			AutoAction:   "Понижаю приоритет носителя и перехожу к следующему носителю",
			ManualAction: "Выберите другой носитель (свой Worker, внешний прокси или другой режим DPI)",
		}
	case DiagUDPBlocked:
		return DiagInfo{
			Code:         DiagUDPBlocked,
			Message:      "UDP-трафик заблокирован в текущей сети",
			AutoAction:   "Исключаю QUIC/UDP-протоколы и подключаюсь по TCP (Meek/TLS/OSSH)",
			ManualAction: "Используйте TCP-протоколы или обход через CDN/Worker",
		}
	case DiagHandshakeReset:
		return DiagInfo{
			Code:         DiagHandshakeReset,
			Message:      "Провайдер сбрасывает TLS-рукопожатие (активный DPI / ТСПУ)",
			AutoAction:   "Перехожу на носитель direct+dpi с фрагментацией ClientHello",
			ManualAction: "Включите фрагментацию DPI, WARP или свой Worker",
		}
	case DiagAllProtocolsTimeout:
		return DiagInfo{
			Code:         DiagAllProtocolsTimeout,
			Message:      "Все протоколы на текущем носителе не ответили за отведённое время",
			AutoAction:   "Эскалирую на следующий носитель из рейтинга preflight",
			ManualAction: "Попробуйте «Терпеливый» пресет подключения, WARP или свой Worker",
		}
	case DiagTunnelUnstable:
		return DiagInfo{
			Code:         DiagTunnelUnstable,
			Message:      "Туннель устанавливается, но обрывается вскоре после старта",
			AutoAction:   "Помечаю стратегию нестабильной и переключаюсь на следующий носитель",
			ManualAction: "Смените носитель или запустите диагностику сети",
		}
	default:
		return DiagInfo{
			Code:         code,
			Message:      "Сеть готова к подключению",
			AutoAction:   "Запускаю подключение по лучшему носителю",
			ManualAction: "",
		}
	}
}

// Carrier represents one outbound transport path for leaving the machine.
type Carrier interface {
	Name() string
	Configured() bool
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	Healthy() bool
	Probe64KB(ctx context.Context) (bytesRead int, rttMs int, err error)
}

// baseCarrier is the standard Carrier implementation backed by an injectable dialer.
type baseCarrier struct {
	name       string
	configured bool
	dialFn     func(ctx context.Context, network, addr string) (net.Conn, error)
	probeFn    func(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (int, int, error)
	healthy    atomic.Bool
}

func newBaseCarrier(
	name string,
	configured bool,
	dialFn func(ctx context.Context, network, addr string) (net.Conn, error),
	probeFn func(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (int, int, error),
) *baseCarrier {
	c := &baseCarrier{
		name:       name,
		configured: configured,
		dialFn:     dialFn,
		probeFn:    probeFn,
	}
	c.healthy.Store(configured)
	return c
}

// setHealthy lets the preflight store the verdict that combines both 64 KB tests.
func (c *baseCarrier) setHealthy(v bool) { c.healthy.Store(v) }

func (c *baseCarrier) Name() string     { return c.name }
func (c *baseCarrier) Configured() bool { return c.configured }
func (c *baseCarrier) Healthy() bool    { return c.configured && c.healthy.Load() }

func (c *baseCarrier) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if !c.configured || c.dialFn == nil {
		return nil, fmt.Errorf("носитель %s не настроен", c.name)
	}
	return c.dialFn(ctx, network, addr)
}

func (c *baseCarrier) Probe64KB(ctx context.Context) (int, int, error) {
	if !c.configured || c.dialFn == nil {
		c.healthy.Store(false)
		return 0, 0, fmt.Errorf("носитель %s не настроен", c.name)
	}
	var (
		n     int
		rttMs int
		err   error
	)
	if c.probeFn != nil {
		n, rttMs, err = c.probeFn(ctx, c.dialFn)
	} else {
		n, rttMs, err = probeChunk64KBWithDial(ctx, c.dialFn, probeChunkURL)
	}
	c.healthy.Store(err == nil && n >= probeChunkMinBytes)
	return n, rttMs, err
}

// probeChunk64KBWithDial verifies that a dialer can transfer >= 64 KB of payload
// data before deadline, detecting ~16 KB TSPU silent drops.
func probeChunk64KBWithDial(
	ctx context.Context,
	dial func(ctx context.Context, network, addr string) (net.Conn, error),
	targetURL string,
) (int, int, error) {
	if dial == nil {
		return 0, 0, errors.New("dialer nil")
	}
	if targetURL == "" {
		targetURL = probeChunkURL
	}
	tctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	t0 := time.Now()
	cl := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: dial}}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, int(time.Since(t0).Milliseconds()), err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, int(time.Since(t0).Milliseconds()), fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	n, rerr := readProbeBodyWithProgress(tctx, cancel, resp.Body, probeChunkReqBytes, 3*time.Second)
	rttMs := int(time.Since(t0).Milliseconds())
	if int(n) < probeChunkMinBytes {
		if rerr != nil {
			return int(n), rttMs, rerr
		}
		return int(n), rttMs, fmt.Errorf("передано только %d байт (< 64 КБ)", n)
	}
	return int(n), rttMs, nil
}

// CarrierProbeResult holds Stage 0 measurement facts for one carrier.
type CarrierProbeResult struct {
	Name           string `json:"name"`
	Configured     bool   `json:"configured"`
	Healthy        bool   `json:"healthy"`
	Reachable      bool   `json:"reachable"`
	ListHostOK     bool   `json:"list_host_ok"`
	TLSPlainOK     bool   `json:"tls_plain_ok"`
	TLSFragOK      bool   `json:"tls_frag_ok"`
	UDPOK          bool   `json:"udp_ok"`
	Probe64KBOK    bool   `json:"probe_64kb_ok"`
	Probe64KBBytes int    `json:"probe_64kb_bytes"`
	Throttled16KB  bool   `json:"throttled_16kb"`
	HandshakeReset bool   `json:"handshake_reset"`
	RTTMs          int    `json:"rtt_ms"`
	Score          int    `json:"score"`
	Error          string `json:"error,omitempty"`
}

// CarrierReport is the structured output of Stage 0 Preflight.
type CarrierReport struct {
	NetKey            string                        `json:"net_key"`
	Timestamp         time.Time                     `json:"ts"`
	DurationMs        int64                         `json:"duration_ms"`
	ClockSkewSec      int64                         `json:"clock_skew_sec"`
	ClockSkewDetected bool                          `json:"clock_skew_detected"`
	DNSPoisoned       bool                          `json:"dns_poisoned"`
	DNSPoisonedHosts  []string                      `json:"dns_poisoned_hosts,omitempty"`
	SystemDNSIPs      []string                      `json:"system_dns_ips,omitempty"`
	DoHDNSIPs         []string                      `json:"doh_dns_ips,omitempty"`
	ListHostReachable bool                          `json:"list_host_reachable"`
	UDPReachable      bool                          `json:"udp_reachable"`
	WARPHealthy       bool                          `json:"warp_healthy"`
	Carriers          map[string]CarrierProbeResult `json:"carriers"`
	Ranking           []string                      `json:"ranking"`
	ClassifiedCode    string                        `json:"classified_code,omitempty"`
	Reason            string                        `json:"reason,omitempty"`
	AutoAction        string                        `json:"auto_action,omitempty"`
	ManualAction      string                        `json:"manual_action,omitempty"`
}

// Clone returns a deep copy of CarrierReport safe for concurrent readers.
func (r *CarrierReport) Clone() *CarrierReport {
	if r == nil {
		return nil
	}
	cp := *r
	if len(r.SystemDNSIPs) > 0 {
		cp.SystemDNSIPs = append([]string(nil), r.SystemDNSIPs...)
	}
	if len(r.DoHDNSIPs) > 0 {
		cp.DoHDNSIPs = append([]string(nil), r.DoHDNSIPs...)
	}
	if len(r.Ranking) > 0 {
		cp.Ranking = append([]string(nil), r.Ranking...)
	}
	cp.Carriers = make(map[string]CarrierProbeResult, len(r.Carriers))
	for k, v := range r.Carriers {
		cp.Carriers[k] = v
	}
	return &cp
}

// preflightProbes allows tests to inject deterministic offline probes.
type preflightProbes struct {
	ResolveSystem  func(ctx context.Context, host string) ([]string, error)
	ResolveDoH     func(ctx context.Context, host string) ([]string, error)
	ClockSkewCheck func(ctx context.Context) (time.Duration, error)
	TLSHandshake   func(ctx context.Context, c Carrier, addr string, fragmented bool) error
	WARPCheck      func(ctx context.Context) bool
	// RangeProbe fetches the first n bytes of rawURL through carrier c. It is the
	// second destination of the 64 KB test (the official server list host).
	// nil means probeRangeOverCarrier.
	RangeProbe func(ctx context.Context, c Carrier, rawURL string, n int) (int, error)
	Now        func() time.Time
}

// preflightDNSHosts are the hosts compared between system DNS and DoH.
var preflightDNSHosts = []string{preflightListHost, preflightDNSHostB}

// dnsPoisonedVerdict: DNS is called poisoned only when at least two different
// hosts disagree with DoH.
func dnsPoisonedVerdict(poisonedHosts []string) bool { return len(poisonedHosts) >= 2 }

var (
	errProbeIdleStall = errors.New("обрыв/зависание передачи (таймаут простоя)")
	errSlowTransfer   = errors.New("канал слишком медленный (данные поступали без обрыва)")
)

// readProbeBodyWithProgress reads up to limit bytes while distinguishing a true
// mid-stream stall (no bytes arriving for idleTimeout) from an active slow link
// that keeps trickling bytes until the outer context deadline expires.
func readProbeBodyWithProgress(
	tctx context.Context,
	cancel context.CancelFunc,
	r io.Reader,
	limit int64,
	idleTimeout time.Duration,
) (int64, error) {
	var idleStalled atomic.Bool
	var timer *time.Timer
	if idleTimeout > 0 {
		timer = time.AfterFunc(idleTimeout, func() {
			idleStalled.Store(true)
			cancel()
		})
		defer timer.Stop()
	}
	buf := make([]byte, 8<<10)
	var total int64
	var chunks int
	for total < limit {
		toRead := limit - total
		if toRead > int64(len(buf)) {
			toRead = int64(len(buf))
		}
		n, err := r.Read(buf[:toRead])
		if n > 0 {
			total += int64(n)
			chunks++
			if timer != nil {
				timer.Reset(idleTimeout)
			}
		}
		if err != nil {
			if idleStalled.Load() {
				return total, errProbeIdleStall
			}
			// If outer budget expired while multiple active chunks arrived without stalling,
			// classify it as slow transfer rather than a TSPU 16 KB cut.
			if (errors.Is(err, context.DeadlineExceeded) || errors.Is(tctx.Err(), context.DeadlineExceeded)) && chunks >= 2 && total > 0 {
				return total, fmt.Errorf("%w: %v", errSlowTransfer, err)
			}
			return total, err
		}
	}
	return total, nil
}

// probeSample is the outcome of one 64 KB transfer test at one destination.
type probeSample struct {
	N   int
	RTT int
	Err error
}

func (s probeSample) ok() bool { return s.Err == nil && s.N >= probeChunkMinBytes }

// cutNear16KB: the transfer stopped inside the ~16 KB TSPU window.
// Active slow trickles that hit the budget without stalling (errSlowTransfer) are excluded.
func (s probeSample) cutNear16KB() bool {
	if errors.Is(s.Err, errSlowTransfer) {
		return false
	}
	return !s.ok() && s.N >= throttleCutMinBytes && s.N <= throttleCutMaxBytes
}

// throttledVerdict is true only if BOTH destinations show the ~16 KB cut and
// neither one passed 64 KB. One bad destination says nothing about the carrier.
func throttledVerdict(a, b probeSample) bool {
	return a.cutNear16KB() && b.cutNear16KB()
}

// probeRangeOverCarrier reads the first n bytes of rawURL through carrier c with
// a Range request. Redirects to another host or to plain http are refused.
func probeRangeOverCarrier(ctx context.Context, c Carrier, rawURL string, n int) (int, error) {
	if c == nil || !c.Configured() {
		return 0, errors.New("носитель не настроен")
	}
	if n <= 0 {
		n = probeChunkMinBytes
	}
	tctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cl := &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{DialContext: c.Dial},
		CheckRedirect: sameHostHTTPSRedirect,
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", n-1))
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	got, rerr := readProbeBodyWithProgress(tctx, cancel, resp.Body, int64(n), 3*time.Second)
	if int(got) < n {
		if rerr != nil {
			return int(got), rerr
		}
		return int(got), fmt.Errorf("передано только %d байт (< %d)", got, n)
	}
	return int(got), nil
}

func defaultTLSHandshakeProbe(ctx context.Context, c Carrier, addr string, fragmented bool) error {
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := c.Dial(dctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	if dl, ok := dctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	host := addr
	if h, _, serr := net.SplitHostPort(addr); serr == nil {
		host = h
	}
	tc := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(dctx); err != nil {
		return err
	}
	return nil
}

func defaultClockSkewCheck(ctx context.Context) (time.Duration, error) {
	tctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: dialDirect}}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(tctx, http.MethodHead, "https://www.gstatic.com/generate_204", nil)
	if err != nil {
		return 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	dateHdr := resp.Header.Get("Date")
	if dateHdr == "" {
		return 0, nil
	}
	srvTime, err := http.ParseTime(dateHdr)
	if err != nil {
		return 0, err
	}
	skew := time.Since(srvTime)
	if skew < 0 {
		skew = -skew
	}
	return skew, nil
}

// runPreflight executes Stage 0 checks in parallel within preflightBudget (<= 8 s).
func runPreflight(ctx context.Context, netKey string, carriers []Carrier, probes *preflightProbes) *CarrierReport {
	nowFn := time.Now
	if probes != nil && probes.Now != nil {
		nowFn = probes.Now
	}
	start := nowFn()
	pctx, cancel := context.WithTimeout(ctx, preflightBudget)
	defer cancel()

	resolveSys := func(ctx context.Context, host string) ([]string, error) {
		return resolve(ctx, host, false)
	}
	resolveDoH := func(ctx context.Context, host string) ([]string, error) {
		return resolve(ctx, host, true)
	}
	clockCheck := defaultClockSkewCheck
	tlsCheck := defaultTLSHandshakeProbe
	if probes != nil {
		if probes.ResolveSystem != nil {
			resolveSys = probes.ResolveSystem
		}
		if probes.ResolveDoH != nil {
			resolveDoH = probes.ResolveDoH
		}
		if probes.ClockSkewCheck != nil {
			clockCheck = probes.ClockSkewCheck
		}
		if probes.TLSHandshake != nil {
			tlsCheck = probes.TLSHandshake
		}
	}

	report := &CarrierReport{
		NetKey:    netKey,
		Timestamp: start,
		Carriers:  make(map[string]CarrierProbeResult, len(carriers)),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// 1. Clock skew check
	wg.Add(1)
	safeGo("runPreflight", func() {
		defer wg.Done()
		skew, err := clockCheck(pctx)
		if err == nil {
			if skew < 0 {
				skew = -skew
			}
			mu.Lock()
			report.ClockSkewSec = int64(skew / time.Second)
			report.ClockSkewDetected = skew > clockSkewThreshold
			mu.Unlock()
		}
	})

	// 2. System DNS vs DoH comparison on two hosts (A-09)
	wg.Add(1)
	safeGo("runPreflight#2", func() {
		defer wg.Done()
		type dnsRes struct {
			host     string
			sys, doh []string
		}
		results := make([]dnsRes, len(preflightDNSHosts))
		var dWg sync.WaitGroup
		for i, h := range preflightDNSHosts {
			i, h := i, h
			results[i].host = h
			dWg.Add(2)
			safeGo("runPreflight.dns-system", func() {
				defer dWg.Done()
				results[i].sys, _ = resolveSys(pctx, h)
			})
			safeGo("runPreflight.dns-doh", func() {
				defer dWg.Done()
				results[i].doh, _ = resolveDoH(pctx, h)
			})
		}
		dWg.Wait()
		var poisonedHosts []string
		for _, r := range results {
			if isDNSPoisoned(r.sys, r.doh) {
				poisonedHosts = append(poisonedHosts, r.host)
			}
		}
		mu.Lock()
		report.SystemDNSIPs = results[0].sys
		report.DoHDNSIPs = results[0].doh
		report.DNSPoisonedHosts = poisonedHosts
		report.DNSPoisoned = dnsPoisonedVerdict(poisonedHosts)
		mu.Unlock()
	})

	// 3. Per-carrier parallel checks
	for _, c := range carriers {
		carrier := c
		wg.Add(1)
		safeGo("runPreflight#3", func() {
			defer wg.Done()
			res := probeOneCarrier(pctx, carrier, tlsCheck, probes)
			mu.Lock()
			report.Carriers[carrier.Name()] = res
			if res.ListHostOK {
				report.ListHostReachable = true
			}
			if carrier.Name() == carrierDirect && res.UDPOK {
				report.UDPReachable = true
			}
			if carrier.Name() == carrierWARP && res.Healthy {
				report.WARPHealthy = true
			}
			mu.Unlock()
		})
	}

	wg.Wait()
	report.DurationMs = nowFn().Sub(start).Milliseconds()
	report.Ranking = rankCarriers(report.Carriers)
	classifyPreflightReport(report)
	return report
}

func probeOneCarrier(
	ctx context.Context,
	c Carrier,
	tlsCheck func(ctx context.Context, c Carrier, addr string, fragmented bool) error,
	probes *preflightProbes,
) CarrierProbeResult {
	res := CarrierProbeResult{
		Name:       c.Name(),
		Configured: c.Configured(),
	}
	if !c.Configured() {
		return res
	}

	// WARP handshake pre-check if provided.
	if c.Name() == carrierWARP && probes != nil && probes.WARPCheck != nil {
		if !probes.WARPCheck(ctx) {
			res.Error = "WARP не подключён"
			return res
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// A. TCP/443 reachability to list host
	wg.Add(1)
	safeGo("probeOneCarrier", func() {
		defer wg.Done()
		t0 := time.Now()
		conn, err := c.Dial(ctx, "tcp", preflightListAddr)
		rtt := int(time.Since(t0).Milliseconds())
		if err == nil {
			_ = conn.Close()
			mu.Lock()
			res.ListHostOK = true
			res.Reachable = true
			if res.RTTMs == 0 || rtt < res.RTTMs {
				res.RTTMs = rtt
			}
			mu.Unlock()
		} else {
			mu.Lock()
			if res.Error == "" {
				res.Error = maskTimelineSecrets(cleanPsiErr(err.Error()))
			}
			mu.Unlock()
		}
	})

	// B. TLS handshake plain vs fragmented (for direct and direct+dpi)
	if c.Name() == carrierDirect || c.Name() == carrierDirectDPI {
		wg.Add(1)
		safeGo("probeOneCarrier#2", func() {
			defer wg.Done()
			frag := c.Name() == carrierDirectDPI
			err := tlsCheck(ctx, c, preflightListAddr, frag)
			mu.Lock()
			if err == nil {
				if frag {
					res.TLSFragOK = true
				} else {
					res.TLSPlainOK = true
				}
				res.Reachable = true
			} else if isResetOrEOF(err) {
				res.HandshakeReset = true
				if res.Error == "" {
					res.Error = maskTimelineSecrets(cleanPsiErr(err.Error()))
				}
			}
			mu.Unlock()
		})
	}

	// C. UDP reachability (only meaningful on direct carrier)
	if c.Name() == carrierDirect {
		wg.Add(1)
		safeGo("probeOneCarrier#3", func() {
			defer wg.Done()
			conn, err := c.Dial(ctx, "udp", preflightUDPAddr)
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				res.UDPOK = true
				mu.Unlock()
			}
		})
	}

	// D. 64 KB payload transfer test at TWO different destinations (A-02, A-09):
	// speed.cloudflare.com and a range request to the official server list host.
	// A single bad destination is not a verdict about the carrier.
	var cfSample, listSample probeSample
	var dwg sync.WaitGroup
	dwg.Add(2)
	safeGo("probeOneCarrier#4", func() {
		defer dwg.Done()
		n, rtt, err := c.Probe64KB(ctx)
		cfSample = probeSample{N: n, RTT: rtt, Err: err}
	})
	safeGo("probeOneCarrier#5", func() {
		defer dwg.Done()
		rangeProbe := probeRangeOverCarrier
		if probes != nil && probes.RangeProbe != nil {
			rangeProbe = probes.RangeProbe
		}
		t0 := time.Now()
		n, err := rangeProbe(ctx, c, psiRSLBackupURL1, probeChunkMinBytes)
		listSample = probeSample{N: n, RTT: int(time.Since(t0).Milliseconds()), Err: err}
	})
	dwg.Wait()
	mu.Lock()
	best := max(cfSample.N, listSample.N)
	res.Probe64KBBytes = best
	for _, rtt := range []int{cfSample.RTT, listSample.RTT} {
		if rtt > 0 && (res.RTTMs == 0 || rtt < res.RTTMs) {
			res.RTTMs = rtt
		}
	}
	switch {
	case cfSample.ok() || listSample.ok():
		res.Probe64KBOK = true
		res.Reachable = true
	case throttledVerdict(cfSample, listSample):
		res.Throttled16KB = true
		res.Reachable = true
	default:
		if cfSample.cutNear16KB() || listSample.cutNear16KB() {
			// Cut seen at one destination only: not enough to blame the carrier.
			res.Reachable = true
			if res.Error == "" {
				res.Error = "обрыв на ~16 КБ замечен только на одном адресате — ограничением носителя не считается"
			}
		}
		for _, e := range []error{cfSample.Err, listSample.Err} {
			if e != nil && res.Error == "" {
				res.Error = maskTimelineSecrets(cleanPsiErr(e.Error()))
			}
		}
	}
	mu.Unlock()

	wg.Wait()

	res.Healthy = res.Probe64KBOK && !res.Throttled16KB
	if hs, ok := c.(interface{ setHealthy(bool) }); ok {
		hs.setHealthy(res.Healthy)
	}
	res.Score = scoreCarrierResult(res)
	return res
}

func isResetOrEOF(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "reset") || strings.Contains(s, "eof") || strings.Contains(s, "broken pipe") || strings.Contains(s, "wsarecv")
}

// isDNSPoisoned compares system DNS answers against DoH answers.
// Returns true if both resolved and system DNS returned a bogon/loopback/private IP
// or an IP set completely disjoint from DoH while DoH returned public IPs.
func isDNSPoisoned(sysIPs, dohIPs []string) bool {
	if len(sysIPs) == 0 || len(dohIPs) == 0 {
		return false
	}
	dohSet := make(map[string]bool, len(dohIPs))
	dohHasPublic := false
	for _, ipStr := range dohIPs {
		dohSet[ipStr] = true
		if ip := net.ParseIP(ipStr); ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() {
			dohHasPublic = true
		}
	}
	if !dohHasPublic {
		return false
	}
	for _, ipStr := range sysIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
				return true
			}
		}
		if dohSet[ipStr] {
			return false
		}
	}
	return true
}

func carrierPreferenceOrder(name string) int {
	switch name {
	case carrierDirect:
		return 0
	case carrierDirectDPI:
		return 1
	case carrierWARP:
		return 2
	case carrierWorker:
		return 3
	case carrierProxy:
		return 4
	default:
		return 9
	}
}

func scoreCarrierResult(r CarrierProbeResult) int {
	if !r.Configured {
		return -1000
	}
	score := 0
	if r.Probe64KBOK {
		score += 100
	}
	if r.ListHostOK {
		score += 40
	}
	if r.TLSFragOK || r.TLSPlainOK {
		score += 20
	}
	if r.Throttled16KB {
		score -= 80
	}
	if r.HandshakeReset && !r.TLSFragOK && !r.Probe64KBOK {
		score -= 60
	}
	if !r.Reachable {
		score -= 100
	}
	if r.RTTMs > 0 {
		score -= min(r.RTTMs/20, 40)
	}
	return score
}

func rankCarriers(results map[string]CarrierProbeResult) []string {
	list := make([]CarrierProbeResult, 0, len(results))
	for _, r := range results {
		if r.Configured {
			list = append(list, r)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Healthy != list[j].Healthy {
			return list[i].Healthy
		}
		if list[i].Score != list[j].Score {
			return list[i].Score > list[j].Score
		}
		return carrierPreferenceOrder(list[i].Name) < carrierPreferenceOrder(list[j].Name)
	})
	out := make([]string, 0, len(list))
	for _, r := range list {
		out = append(out, r.Name)
	}
	return out
}

// classifyPreflightReport sets ClassifiedCode/Reason/AutoAction/ManualAction from facts.
func classifyPreflightReport(rep *CarrierReport) {
	if rep == nil {
		return
	}
	apply := func(code string) {
		info := diagInfoForCode(code)
		rep.ClassifiedCode = info.Code
		rep.Reason = info.Message
		rep.AutoAction = info.AutoAction
		rep.ManualAction = info.ManualAction
	}

	if rep.ClockSkewDetected {
		apply(DiagClockSkew)
		return
	}

	anyReachable := false
	anyHealthy := false
	anyThrottled := false
	for _, r := range rep.Carriers {
		if !r.Configured {
			continue
		}
		if r.Reachable {
			anyReachable = true
		}
		if r.Healthy {
			anyHealthy = true
		}
		if r.Throttled16KB {
			anyThrottled = true
		}
	}

	if !anyReachable {
		apply(DiagNoNetwork)
		return
	}

	direct := rep.Carriers[carrierDirect]
	if rep.DNSPoisoned {
		apply(DiagDNSPoisoned)
		return
	}
	if !anyHealthy && anyThrottled {
		apply(DiagCarrierThrottled16KB)
		return
	}
	if direct.Configured && direct.HandshakeReset && !direct.TLSPlainOK {
		apply(DiagHandshakeReset)
		return
	}
	if direct.Configured && !direct.ListHostOK {
		apply(DiagListHostBlocked)
		return
	}
	if anyThrottled {
		apply(DiagCarrierThrottled16KB)
		return
	}
	if direct.Configured && !rep.UDPReachable {
		apply(DiagUDPBlocked)
		return
	}
	// All checks healthy
	info := diagInfoForCode("")
	rep.ClassifiedCode = ""
	rep.Reason = info.Message
	rep.AutoAction = info.AutoAction
	rep.ManualAction = info.ManualAction
}

// preflightCache stores CarrierReport per network key with TTL.
type preflightCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]*CarrierReport
}

func newPreflightCache(ttl time.Duration) *preflightCache {
	if ttl <= 0 {
		ttl = preflightCacheTTL
	}
	return &preflightCache{
		ttl:     ttl,
		entries: map[string]*CarrierReport{},
	}
}

func (c *preflightCache) Get(netKey string, now time.Time) *CarrierReport {
	if c == nil || netKey == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.entries[netKey]
	if !ok || r == nil {
		return nil
	}
	if now.Sub(r.Timestamp) >= c.ttl {
		delete(c.entries, netKey)
		return nil
	}
	return r.Clone()
}

func (c *preflightCache) Set(netKey string, rep *CarrierReport) {
	if c == nil || netKey == "" || rep == nil {
		return
	}
	c.mu.Lock()
	c.entries[netKey] = rep.Clone()
	c.mu.Unlock()
}

func (c *preflightCache) Invalidate(netKey string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if netKey == "" {
		c.entries = map[string]*CarrierReport{}
	} else {
		delete(c.entries, netKey)
	}
	c.mu.Unlock()
}

// buildCarriers constructs the active Carrier set for Psi from current settings.
func (p *Psi) buildCarriers() []Carrier {
	var (
		desyncMethod = "auto"
		warpSocks    string
		builtinWarp  = true
		upstream     string
	)
	if p != nil && p.app != nil && p.app.cfg != nil {
		p.app.cfg.mu.Lock()
		if p.app.cfg.Desync.Method != "" {
			desyncMethod = p.app.cfg.Desync.Method
		}
		warpSocks = strings.TrimSpace(p.app.cfg.Warp.Socks)
		builtinWarp = p.app.cfg.Warp.Engine != "socks"
		upstream = strings.TrimSpace(p.app.cfg.Proxy.Upstream)
		p.app.cfg.mu.Unlock()
	}

	directC := newBaseCarrier(carrierDirect, true, dialDirect, nil)
	dpiC := newBaseCarrier(carrierDirectDPI, true, func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialObfs(ctx, network, addr, desyncMethod)
		if err != nil {
			return nil, err
		}
		return &psiRawSplitConn{Conn: conn}, nil
	}, nil)

	warpConfigured := false
	var warpDial func(ctx context.Context, network, addr string) (net.Conn, error)
	if builtinWarp && p != nil && p.app != nil && p.app.warp != nil {
		warpConfigured = p.app.warp.connected()
		warpDial = p.app.warp.Dial
	} else if !builtinWarp && warpSocks != "" {
		warpConfigured = true
		u := warpSocks
		if !strings.Contains(u, "://") {
			u = "socks5://" + u
		}
		warpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialUpstream(ctx, u, addr)
		}
	}
	warpC := newBaseCarrier(carrierWARP, warpConfigured, warpDial, nil)

	// Worker carrier is disabled by default unless explicitly configured (no invented endpoints).
	workerC := newBaseCarrier(carrierWorker, false, nil, nil)

	proxyConfigured := upstream != ""
	var proxyDial func(ctx context.Context, network, addr string) (net.Conn, error)
	if proxyConfigured {
		proxyDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialUpstream(ctx, upstream, addr)
		}
	}
	proxyC := newBaseCarrier(carrierProxy, proxyConfigured, proxyDial, nil)

	return []Carrier{directC, dpiC, warpC, workerC, proxyC}
}
