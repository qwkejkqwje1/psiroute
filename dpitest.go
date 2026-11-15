package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DPI panel: «Проверить» opens every test site without a bypass and with each
// method in turn; the quick switch changes the method at once (it applies to
// new connections, nothing restarts). Also provides background auto-tuning
// (Priority 3) when the active method's error rate spikes.

var dpiTestDefaultSites = []string{
	"www.youtube.com",
	"discord.com",
	"rutracker.org",
	"x.com",
	"speed.cloudflare.com/__down?bytes=65536",
}

const (
	dpiTestRead     = 64 << 10 // bytes read per check: enough to see a 16 KB cut-off
	dpiTestTimeout  = 10 * time.Second
	dpiTestMaxSites = 12
	dpiTestParallel = 4 // sites at once; the methods of one site go one by one
)

type dpiCell struct {
	Site   string `json:"site"`
	Method string `json:"method"`
	OK     bool   `json:"ok"`
	Ms     int64  `json:"ms"` // connect + TLS handshake
	KB     int64  `json:"kb"`
	Err    string `json:"err,omitempty"`
}

type dpiScore struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	OK    int    `json:"ok"`
	Fail  int    `json:"fail"`
	Ms    int64  `json:"ms"` // average over the sites that opened
}

type dpiTest struct {
	mu           sync.Mutex
	running      bool
	autoRunning  atomic.Bool
	lastAutoTune time.Time
	cancel       context.CancelFunc
	started      time.Time
	finished     time.Time
	sites        []string
	total        int
	cells        []dpiCell
}

var dpiT = &dpiTest{}

// setupDPIAutoTune binds App to obfsBook so a spike in connection errors on the
// current DPI method triggers a lightweight background auto-tune verification
// and updates the active method without manual user intervention (Priority 3).
func (a *App) setupDPIAutoTune() {
	if a == nil {
		return
	}
	obfs.mu.Lock()
	obfs.onAutoTune = func(failedMethod, nextMethod string) {
		a.maybeRunBackgroundAutoTune(failedMethod, nextMethod)
	}
	obfs.mu.Unlock()
}

// maybeRunBackgroundAutoTune updates the active Desync method when a fixed
// method degrades and launches a non-intrusive background probe across 2 control
// sites to confirm the fastest working bypass method.
func (a *App) maybeRunBackgroundAutoTune(failedMethod, nextMethod string) {
	if a == nil || a.ctx == nil || a.ctx.Err() != nil {
		return
	}
	// If user had a specific method selected that just degraded, switch it immediately to nextMethod
	a.cfg.mu.Lock()
	curMethod := a.cfg.Desync.Method
	desyncOn := a.cfg.Desync.Enabled
	if desyncOn && curMethod != "" && curMethod != "auto" && curMethod == failedMethod && obfsByID(nextMethod) != nil {
		a.cfg.Desync.Method = nextMethod
		a.cfg.mu.Unlock()
		_ = a.cfg.save()
	} else {
		a.cfg.mu.Unlock()
	}

	t := dpiT
	t.mu.Lock()
	if t.running || time.Since(t.lastAutoTune) < obfsAutoTuneCooldown {
		t.mu.Unlock()
		return
	}
	if !t.autoRunning.CompareAndSwap(false, true) {
		t.mu.Unlock()
		return
	}
	t.lastAutoTune = time.Now()
	t.mu.Unlock()

	goSafe("dpi-autotune", func() {
		defer t.autoRunning.Store(false)
		sites := a.dpiSites()
		if len(sites) > 2 {
			sites = sites[:2]
		}
		ctx, cancel := context.WithTimeout(a.ctx, 25*time.Second)
		defer cancel()
		var cells []dpiCell
		for _, site := range sites {
			for _, m := range obfsMethods {
				if ctx.Err() != nil {
					return
				}
				pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
				cell := dpiProbe(pctx, site, m.id)
				pcancel()
				cells = append(cells, cell)
			}
		}
		best := dpiBest(dpiScores(cells))
		if best != "" && obfsByID(best) != nil {
			obfs.setAutoTunedMethod(best)
			a.cfg.mu.Lock()
			if a.cfg.Desync.Enabled && a.cfg.Desync.Method != "auto" {
				a.cfg.Desync.Method = best
				a.cfg.mu.Unlock()
				_ = a.cfg.save()
			} else {
				a.cfg.mu.Unlock()
			}
			logf("info", "DPI авто-тюнинг: фоновая проверка выбрала оптимальный метод «%s»", dpiMethodTitle(best))
		}
	})
}

// dpiTestMethods: "none" first (is a bypass needed at all?), then every method.
func dpiTestMethods() []string {
	ids := []string{"none"}
	for _, m := range obfsMethods {
		ids = append(ids, m.id)
	}
	return ids
}

func dpiMethodTitle(id string) string {
	switch id {
	case "none":
		return "без обхода"
	case "off":
		return "выключен"
	case "auto":
		return "авто"
	case "":
		return "—"
	}
	if m := obfsByID(id); m != nil {
		return m.title
	}
	return id
}

// dpiNormSites trims, drops the scheme, de-duplicates and caps the list.
func dpiNormSites(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimSuffix(s, "/")
		k := strings.ToLower(s)
		if s == "" || strings.ContainsAny(s, " \t") || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
		if len(out) == dpiTestMaxSites {
			break
		}
	}
	return out
}

// dpiSplitSite: "host/path?q" -> host, "/path?q". A port is ignored: always 443.
func dpiSplitSite(site string) (host, path string) {
	host, path = site, "/"
	if i := strings.IndexAny(site, "/?"); i >= 0 {
		host, path = site[:i], site[i:]
		if path[0] == '?' {
			path = "/" + path
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host), path
}

func dpiErrText(stage string, err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.As(err, &dnsErr):
		return "DNS: имя не найдено"
	case errors.As(err, &certErr):
		return stage + ": чужой сертификат (подмена)"
	case isConnReset(err):
		return stage + ": сброс (RST)"
	case isTimeout(err) || errors.Is(err, context.DeadlineExceeded):
		return stage + ": нет ответа"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return stage + ": соединение закрыто"
	}
	s := err.Error()
	if r := []rune(s); len(r) > 90 {
		s = string(r[:90]) + "…"
	}
	return stage + ": " + s
}

// dpiProbe opens one site with one method: TCP, TLS, GET and up to 64 KB of
// the answer, so a connection the DPI cuts after ~16 KB counts as a failure.
func dpiProbe(ctx context.Context, site, method string) (cell dpiCell) {
	cell = dpiCell{Site: site, Method: method}
	host, path := dpiSplitSite(site)
	ctx, cancel := context.WithTimeout(ctx, dpiTestTimeout)
	defer cancel()
	start := time.Now()
	addr := net.JoinHostPort(host, "443")
	var c net.Conn
	var err error
	if method == "none" {
		c, err = obfsDialRaw(ctx, "tcp", addr)
	} else {
		c, err = dialObfs(ctx, "tcp", addr, method)
	}
	if err != nil {
		cell.Err = dpiErrText("подключение", err)
		return
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	tc := tls.Client(c, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := tc.HandshakeContext(ctx); err != nil {
		cell.Err = dpiErrText("TLS", err)
		return
	}
	cell.Ms = time.Since(start).Milliseconds()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host +
		"\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		cell.Err = dpiErrText("запрос", err)
		return
	}
	br := bufio.NewReader(tc)
	head, err := br.Peek(8)
	if err != nil {
		cell.Err = dpiErrText("ответ", err)
		return
	}
	if !strings.HasPrefix(string(head), "HTTP/1.") {
		cell.Err = "ответ: не HTTP"
		return
	}
	n, err := io.CopyN(io.Discard, br, dpiTestRead)
	cell.KB = n >> 10
	cut := n >= 12<<10 && n <= 24<<10
	switch {
	case err == nil || errors.Is(err, io.EOF):
		cell.OK = true
	case cut:
		cell.Err = "обрыв на ~16 КБ (ТСПУ)"
	case errors.Is(err, io.ErrUnexpectedEOF):
		cell.OK = true // closed without close_notify: usual with Connection: close
	default:
		cell.Err = dpiErrText("загрузка", err)
	}
	return
}

func dpiScores(cells []dpiCell) []dpiScore {
	var out []dpiScore
	for _, id := range dpiTestMethods() {
		out = append(out, dpiScore{ID: id, Title: dpiMethodTitle(id)})
	}
	idx := map[string]int{}
	for i := range out {
		idx[out[i].ID] = i
	}
	sum := map[string]int64{}
	for _, c := range cells {
		i, ok := idx[c.Method]
		if !ok {
			continue
		}
		if c.OK {
			out[i].OK++
			sum[c.Method] += c.Ms
		} else {
			out[i].Fail++
		}
	}
	for i := range out {
		if out[i].OK > 0 {
			out[i].Ms = sum[out[i].ID] / int64(out[i].OK)
		}
	}
	return out
}

// dpiBest: the method that opened the most sites, the faster one on a tie;
// "" when no method opened anything.
func dpiBest(scores []dpiScore) string {
	best := ""
	var bs dpiScore
	for _, s := range scores {
		if s.ID == "none" || s.OK == 0 {
			continue
		}
		if best == "" || s.OK > bs.OK || (s.OK == bs.OK && s.Ms < bs.Ms) {
			best, bs = s.ID, s
		}
	}
	return best
}

func (a *App) dpiSites() []string {
	a.cfg.mu.Lock()
	s := append([]string(nil), a.cfg.Desync.TestSites...)
	a.cfg.mu.Unlock()
	if len(s) == 0 {
		s = append([]string(nil), dpiTestDefaultSites...)
	}
	return s
}

// dpiMode: "off", "auto" or a method id — what the quick switch shows.
func (a *App) dpiMode() string {
	a.cfg.mu.Lock()
	defer a.cfg.mu.Unlock()
	if !a.cfg.Desync.Enabled {
		return "off"
	}
	if a.cfg.Desync.Method == "" {
		return "auto"
	}
	return a.cfg.Desync.Method
}

// dpiSetMode is the quick switch. The router reads the method on every dial,
// so new connections use it at once; open ones are left alone.
func (a *App) dpiSetMode(mode string) error {
	if mode != "off" && mode != "auto" && obfsByID(mode) == nil {
		return errors.New("неизвестный метод: " + mode)
	}
	a.cfg.mu.Lock()
	if mode == "off" {
		a.cfg.Desync.Enabled = false
	} else {
		a.cfg.Desync.Enabled = true
		a.cfg.Desync.Method = mode
		if mode != "auto" {
			obfs.setAutoTunedMethod(mode)
		}
	}
	a.cfg.mu.Unlock()
	if err := a.cfg.save(); err != nil {
		return err
	}
	logf("info", "DPI: режим «%s»", dpiMethodTitle(mode))
	return nil
}

func (a *App) dpiTestStart(sites []string) error {
	sites = dpiNormSites(sites)
	if len(sites) == 0 {
		return errors.New("добавьте хотя бы один сайт")
	}
	methods := dpiTestMethods()
	t := dpiT
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return errors.New("проверка уже идёт")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.running, t.cancel = true, cancel
	t.started, t.finished = time.Now(), time.Time{}
	t.sites, t.cells, t.total = sites, nil, len(sites)*len(methods)
	t.mu.Unlock()

	a.cfg.mu.Lock()
	a.cfg.Desync.TestSites = append([]string(nil), sites...)
	a.cfg.mu.Unlock()
	_ = a.cfg.save()
	logf("info", "DPI: проверка %d сайтов × %d вариантов", len(sites), len(methods))

	goSafe("dpitest", func() {
		defer cancel()
		var wg sync.WaitGroup
		sem := make(chan struct{}, dpiTestParallel)
		for _, site := range sites {
			wg.Add(1)
			goSafe("dpitest-site", func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				for _, m := range methods {
					if ctx.Err() != nil {
						return
					}
					cell := dpiProbe(ctx, site, m)
					t.mu.Lock()
					t.cells = append(t.cells, cell)
					t.mu.Unlock()
				}
			})
		}
		wg.Wait()
		t.mu.Lock()
		t.running, t.finished = false, time.Now()
		best := dpiBest(dpiScores(t.cells))
		t.mu.Unlock()
		if best != "" {
			obfs.setAutoTunedMethod(best)
		}
		logf("info", "DPI: проверка завершена, лучший метод: %s", dpiMethodTitle(best))
	})
	return nil
}

func dpiTestStop() {
	dpiT.mu.Lock()
	if dpiT.running && dpiT.cancel != nil {
		dpiT.cancel()
	}
	dpiT.mu.Unlock()
}

func (a *App) dpiTestView() map[string]any {
	t := dpiT
	t.mu.Lock()
	cells := append([]dpiCell(nil), t.cells...)
	sites := append([]string(nil), t.sites...)
	v := map[string]any{
		"running":      t.running,
		"auto_running": t.autoRunning.Load(),
		"done":         len(t.cells),
		"total":        t.total,
	}
	if !t.started.IsZero() {
		v["started"] = t.started.Unix()
	}
	if !t.finished.IsZero() {
		v["finished"] = t.finished.Unix()
	}
	t.mu.Unlock()
	if len(sites) == 0 {
		sites = a.dpiSites()
	}
	scores := dpiScores(cells)
	v["sites"] = sites
	v["cells"] = cells
	v["methods"] = scores
	v["best"] = dpiBest(scores)
	v["mode"] = a.dpiMode()
	v["auto_tuned"] = obfs.currentAutoTuned()
	return v
}
