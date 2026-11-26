package main

// The built-in WARP service: a local SOCKS5 port for Psiphon («Через WARP»)
// and the router's "warp" outbound, and the tunnel behind it. The tunnel is
// opened when something needs it and closed after warpIdle unused.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Warp struct {
	app     *App
	dataDir string

	mu      sync.Mutex
	ln      net.Listener
	id      *warpIdentity
	state   string // idle | connecting | connected | error
	text    string // what the UI shows
	since   time.Time
	ready   chan struct{} // closed when a tunnel comes up
	stateCh chan struct{} // closed whenever state changes (including error)
	errSeq  uint64        // incremented when state transitions to error

	cur     atomic.Pointer[warpTunnel]
	want    chan struct{}
	active  atomic.Int32 // open connections through the tunnel
	lastUse atomic.Int64 // unix nanoseconds

	// the network cutting UDP flows (watch, recovered); run goroutine only
	recoveries int
	rotate     time.Duration
	minLife    time.Duration

	testDial func(ctx context.Context, network, addr string) (net.Conn, error) // tests
}

func newWarp(a *App, dataDir string) *Warp {
	return &Warp{
		app:     a,
		dataDir: dataDir,
		state:   "idle",
		ready:   make(chan struct{}),
		stateCh: make(chan struct{}),
		want:    make(chan struct{}, 1),
	}
}

func (w *Warp) idPath() string { return filepath.Join(w.dataDir, "warp-identity.json") }

func (w *Warp) baseCtx() context.Context {
	if w.app != nil && w.app.ctx != nil {
		return w.app.ctx
	}
	return context.Background()
}

// builtin: WARP is on and the built-in one is chosen.
func (w *Warp) builtin() bool {
	c := w.app.cfg
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Warp.Enabled && c.Warp.Engine != "socks"
}

// cfgKey changes when a setting that needs a new tunnel changes.
func (w *Warp) cfgKey() string {
	c := w.app.cfg
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprint(c.Warp.Enabled, c.Warp.Engine, c.Warp.Mask, c.Warp.Endpoint, c.Warp.License)
}

func (w *Warp) licenseKey() string {
	if w == nil || w.app == nil || w.app.cfg == nil {
		return ""
	}
	w.app.cfg.mu.Lock()
	defer w.app.cfg.mu.Unlock()
	return strings.TrimSpace(w.app.cfg.Warp.License)
}

func (w *Warp) settings() (mask, endpoint string) {
	c := w.app.cfg
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Warp.Mask, c.Warp.Endpoint
}

// wanted: the tunnel is in use or was used less than warpIdle ago.
func (w *Warp) wanted() bool {
	if !w.builtin() {
		return false
	}
	if w.active.Load() > 0 {
		return true
	}
	last := w.lastUse.Load()
	return last != 0 && time.Since(time.Unix(0, last)) < warpIdle
}

func (w *Warp) connected() bool { return w != nil && w.cur.Load() != nil }

// Want asks for the tunnel; it is opened in the background.
func (w *Warp) Want() {
	if w == nil {
		return
	}
	w.lastUse.Store(time.Now().UnixNano())
	select {
	case w.want <- struct{}{}:
	default:
	}
}

// Addr is the local SOCKS5 port of the built-in WARP, opened on first use.
func (w *Warp) Addr() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ln == nil {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			logf("warn", "WARP: не удалось открыть локальный порт: %v", err)
			return ""
		}
		w.ln = ln
		safeLoop(context.Background(), "WARP-сервис", func() { w.serve(ln) })
	}
	return w.ln.Addr().String()
}

// Dial connects through the built-in WARP, waiting for the tunnel if needed.
func (w *Warp) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if w.testDial != nil {
		return w.track(w.testDial(ctx, network, addr))
	}
	if !w.builtin() {
		return nil, errors.New("встроенный WARP выключен в настройках")
	}
	w.Want()
	t, err := w.wait(ctx, 45*time.Second)
	if err != nil {
		return nil, err
	}
	return w.track(t.dial(ctx, network, addr))
}

func (w *Warp) wait(ctx context.Context, d time.Duration) (*warpTunnel, error) {
	w.mu.Lock()
	startErrSeq := w.errSeq
	w.mu.Unlock()
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		if t := w.cur.Load(); t != nil {
			return t, nil
		}
		w.mu.Lock()
		if w.ready == nil {
			w.ready = make(chan struct{})
		}
		if w.stateCh == nil {
			w.stateCh = make(chan struct{})
		}
		ready, stateCh, st, text, seq := w.ready, w.stateCh, w.state, w.text, w.errSeq
		w.mu.Unlock()
		if st == "error" && seq > startErrSeq && text != "" {
			return nil, errors.New("WARP: " + text)
		}
		select {
		case <-ready:
		case <-stateCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			if st == "error" && text != "" {
				return nil, errors.New("WARP: " + text)
			}
			return nil, errors.New("WARP ещё не подключился")
		}
	}
}

// warpConn counts open connections, so an unused tunnel can be closed.
type warpConn struct {
	net.Conn
	w    *Warp
	once sync.Once
}

func (c *warpConn) Close() error {
	c.once.Do(func() {
		c.w.active.Add(-1)
		c.w.lastUse.Store(time.Now().UnixNano())
	})
	return c.Conn.Close()
}

func (c *warpConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (w *Warp) track(c net.Conn, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}
	w.active.Add(1)
	w.lastUse.Store(time.Now().UnixNano())
	return &warpConn{Conn: c, w: w}, nil
}

func (w *Warp) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		safeGo("Warp.serve", func() { w.handle(c) })
	}
}

// handle serves one SOCKS5 CONNECT (Psiphon's upstream connections).
func (w *Warp) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	br := bufio.NewReader(c)
	host, port, cmd, err := socksHandshake(c, br, false, nil)
	if err != nil {
		return
	}
	if cmd != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	ctx, cancel := context.WithTimeout(w.baseCtx(), 50*time.Second)
	up, err := w.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	cancel()
	if err != nil {
		_, _ = c.Write([]byte{5, socksErrCode(err), 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{})
	safeGo("Warp.handle", func() {
		_, _ = io.Copy(up, br)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	})
	_, _ = io.Copy(c, up)
	_ = c.Close()
	<-done
}

// apiClients reach the registration API: directly, else through the
// external proxy of the settings or a Psiphon tunnel that already works.
func (w *Warp) apiClients() []*http.Client {
	out := []*http.Client{{Timeout: 20 * time.Second}}
	c := w.app.cfg
	c.mu.Lock()
	up := ""
	if c.Proxy.Enabled {
		up = strings.TrimSpace(c.Proxy.Upstream)
	}
	c.mu.Unlock()
	if up != "" && !strings.Contains(up, "://") {
		up = "socks5://" + up
	}
	if u, err := url.Parse(up); err == nil && up != "" && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "socks5") {
		out = append(out, &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u)}})
	}
	if p := w.app.psi; p != nil && p.cur.Load() != nil {
		out = append(out, &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: p.Dial}})
	}
	return out
}

func (w *Warp) identity() (*warpIdentity, error) {
	w.mu.Lock()
	id := w.id
	w.mu.Unlock()
	if id != nil {
		return id, nil
	}
	id, err := loadWarpIdentity(w.idPath())
	if err != nil {
		w.setState("connecting", "регистрирую бесплатное устройство WARP…")
		if id, err = warpRegister(w.apiClients()); err != nil {
			return nil, err
		}
		if err := saveWarpIdentity(w.idPath(), id); err != nil {
			logf("warn", "WARP: не удалось сохранить %s: %v", w.idPath(), err)
		}
		logf("info", "WARP: зарегистрировано бесплатное устройство")
	}
	if lic := w.licenseKey(); lic != "" && id.License != lic {
		if lerr := warpApplyLicense(w.apiClients(), id, lic); lerr != nil {
			logf("warn", "WARP+: не удалось активировать лицензию: %v", lerr)
		} else {
			_ = saveWarpIdentity(w.idPath(), id)
			logf("info", "WARP+: лицензия применена (тип аккаунта: %s)", id.Account)
		}
	}
	w.mu.Lock()
	w.id = id
	w.mu.Unlock()
	return id, nil
}

func (w *Warp) remember(id *warpIdentity, t *warpTunnel) {
	if id.Endpoint == t.ep && id.Mask == t.mask.ID && id.Colo == t.colo {
		return
	}
	id.Endpoint, id.Mask, id.Colo = t.ep, t.mask.ID, t.colo
	_ = saveWarpIdentity(w.idPath(), id)
}

// connectMask finds a working endpoint with masking m, three at a time. A
// tunnel to a filtered node is kept as a fallback while the search for a
// node abroad goes on (warpSearch).
func (w *Warp) connectMask(ctx context.Context, id *warpIdentity, m warpMask, cands []string) (*warpTunnel, error) {
	var fb *warpTunnel
	var fbAt time.Time
	for i := 0; i < len(cands) && ctx.Err() == nil; i += 3 {
		if fb != nil && time.Since(fbAt) > warpSearch {
			break
		}
		batch := cands[i:min(i+3, len(cands))]
		bctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		ch := make(chan *warpTunnel, len(batch))
		for _, ep := range batch {
			safeGo("Warp.connectMask", func() {
				sent := false
				defer func() {
					if !sent {
						ch <- nil
					}
				}()
				t, err := openWarpTunnel(id, ep, m)
				if err == nil && t.probe(bctx) != nil {
					t.Close()
					err = errors.New("нет ответа")
				}
				if err != nil {
					t = nil
				}
				ch <- t
				sent = true
			})
		}
		var win *warpTunnel
		others := 0
		for range batch {
			switch t := <-ch; {
			case t == nil:
			case win == nil:
				win = t
				cancel() // the others need not wait
			default:
				t.Close()
				others++
			}
		}
		cancel()
		if win == nil {
			continue
		}
		if others > 0 || fb != nil {
			win.settle(ctx)
		}
		tctx, tcancel := context.WithTimeout(ctx, 10*time.Second)
		tr, err := getTrace(tctx, win.dial)
		tcancel()
		if err == nil {
			win.colo = tr.Colo
		}
		if warpNodeOK(win.colo) {
			if fb != nil {
				fb.Close()
			}
			return win, nil
		}
		if fb == nil {
			fb, fbAt = win, time.Now()
			logf("info", "WARP: %s ведёт в %s — трафик этого узла фильтруется, ищу узел за границей…", win.ep, win.colo)
			continue
		}
		win.Close()
	}
	if fb != nil {
		if ctx.Err() != nil {
			fb.Close()
			return nil, ctx.Err()
		}
		logf("warn", "WARP: узел за границей не найден, остаюсь на %s (%s) — Psiphon через него может блокироваться", fb.ep, fb.colo)
		fb.settle(ctx)
		return fb, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, errors.New("ни одна точка входа Cloudflare не ответила")
}

type warpRaceRes struct {
	t     *warpTunnel
	colo  string
	close func()
	err   error
}

func (r warpRaceRes) tunnelColo() string {
	if r.colo != "" {
		return r.colo
	}
	if r.t != nil {
		return r.t.colo
	}
	return ""
}

func (r warpRaceRes) closeTunnel() {
	if r.close != nil {
		r.close()
	} else if r.t != nil {
		r.t.Close()
	}
}

// collectWarpRaceWinner picks the first foreign WARP tunnel immediately; if the
// first arriving tunnel is domestic/filtered (e.g. DME), it holds it as fallback
// for up to foreignGrace so concurrent branches can land a foreign node (ARN/FRA).
func collectWarpRaceWinner(
	ctx context.Context,
	rcancel context.CancelFunc,
	ch <-chan warpRaceRes,
	total int,
	foreignGrace time.Duration,
) (*warpTunnel, error) {
	if rcancel == nil {
		rcancel = func() {}
	}
	var winner *warpTunnel
	var winItem *warpRaceRes
	var fallback *warpRaceRes
	var lastErr error
	var graceTimer *time.Timer
	var graceC <-chan time.Time
	defer func() {
		if graceTimer != nil {
			graceTimer.Stop()
		}
	}()

	received := 0
	for received < total {
		select {
		case r := <-ch:
			received++
			if r.t != nil {
				colo := r.tunnelColo()
				if warpNodeOK(colo) {
					if fallback != nil {
						fallback.closeTunnel()
						fallback = nil
					}
					rCopy := r
					winItem = &rCopy
					winner = r.t
					rcancel()
					goto drain
				}
				if fallback == nil {
					rCopy := r
					fallback = &rCopy
					if foreignGrace > 0 {
						logf("info", "WARP: гонка нашла фильтруемый узел %s (%s) — даю другим веткам %.1fс на поиск зарубежного узла", r.t.ep, colo, foreignGrace.Seconds())
						graceTimer = time.NewTimer(foreignGrace)
						graceC = graceTimer.C
					} else {
						winItem = fallback
						winner = fallback.t
						fallback = nil
						rcancel()
						goto drain
					}
				} else {
					r.closeTunnel()
				}
			} else if r.err != nil {
				lastErr = r.err
			}
		case <-graceC:
			graceC = nil
			if fallback != nil {
				logf("info", "WARP: зарубежный узел за время ожидания не ответил, использую %s (%s)", fallback.t.ep, fallback.tunnelColo())
				winItem = fallback
				winner = fallback.t
				fallback = nil
			}
			rcancel()
			goto drain
		case <-ctx.Done():
			rcancel()
			if fallback != nil {
				fallback.closeTunnel()
				fallback = nil
			}
			// Drain late race results asynchronously so none leak open WireGuard devices.
			if remaining := total - received; remaining > 0 {
				safeGo("Warp.connectOnce.drain", func() {
					for i := 0; i < remaining; i++ {
						if r, ok := <-ch; ok && r.t != nil {
							r.closeTunnel()
						}
					}
				})
			}
			return nil, ctx.Err()
		}
	}

drain:
	if graceTimer != nil {
		graceTimer.Stop()
	}
	rcancel()
	if winner == nil && fallback != nil {
		winItem = fallback
		winner = fallback.t
		fallback = nil
	}
	for received < total {
		select {
		case r := <-ch:
			received++
			if r.t != nil && (winItem == nil || r.t != winner) {
				r.closeTunnel()
			}
		case <-ctx.Done():
			if remaining := total - received; remaining > 0 {
				safeGo("Warp.connectOnce.drainAfter", func() {
					for i := 0; i < remaining; i++ {
						if r, ok := <-ch; ok && r.t != nil && (winItem == nil || r.t != winner) {
							r.closeTunnel()
						}
					}
				})
			}
			received = total
		}
	}
	if winner != nil {
		return winner, nil
	}
	return nil, lastErr
}

// connectOnce tries the maskings (auto: the one that worked last, then
// warpMaskOrder; three rounds of endpoints each) and the endpoints.
// Runs the Cloudflare Clean IP Auto-Scanner beforehand when no fixed endpoint
// is configured so WARP connects within seconds even on restricted mobile ISPs.
func (w *Warp) connectOnce(ctx context.Context) (*warpTunnel, error) {
	id, err := w.identity()
	if err != nil {
		return nil, err
	}
	mask, fixed := w.settings()
	auto := mask == "" || mask == "auto"
	ids := []string{mask}
	if auto {
		ids = nil
		if slices.Contains(warpMaskOrder, id.Mask) {
			ids = append(ids, id.Mask)
		}
		for _, m := range warpMaskOrder {
			if !slices.Contains(ids, m) {
				ids = append(ids, m)
			}
		}
	}
	if strings.TrimSpace(fixed) == "" && len(ids) > 0 {
		if scanMask, err := makeWarpMask(ids[0]); err == nil {
			w.setState("connecting", "проверяю туннели Cloudflare…")
			_ = theWarpScanner.EnsureScanned(ctx, id, scanMask)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cands := warpCandidates(id, fixed)
	var last error
	// In auto mode, race the top AWG/QUIC/MASQUE masks concurrently.
	// If a branch finishes first with a domestic/filtered colo (e.g. DME), keep it as
	// fallback and grant remaining branches a short grace window to land a foreign node (ARN/FRA).
	if auto && len(ids) > 1 {
		raceN := min(3, len(ids))
		raceIDs := ids[:raceN]
		w.setState("connecting", "гонка подключений WARP (QUIC / MASQUE / AWG)…")
		rctx, rcancel := context.WithCancel(ctx)
		ch := make(chan warpRaceRes, len(raceIDs))
		for _, mid := range raceIDs {
			m, merr := makeWarpMask(mid)
			if merr != nil {
				ch <- warpRaceRes{err: merr}
				continue
			}
			cs := cands
			if len(cs) > 8 {
				cs = cs[:8]
			}
			safeGo("Warp.connectOnce.race", func() {
				sent := false
				defer func() {
					if !sent {
						ch <- warpRaceRes{err: errors.New("паника при подключении ветки WARP")}
					}
				}()
				t, cerr := w.connectMask(rctx, id, m, cs)
				ch <- warpRaceRes{t: t, err: cerr}
				sent = true
			})
		}
		winner, raceErr := collectWarpRaceWinner(ctx, rcancel, ch, len(raceIDs), 3*time.Second)
		if winner != nil {
			w.remember(id, winner)
			return winner, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if raceErr != nil {
			last = raceErr
		}
		ids = ids[raceN:]
	}
	for k, mid := range ids {
		if !w.builtin() {
			return nil, errors.New("встроенный WARP выключен")
		}
		m, err := makeWarpMask(mid)
		if err != nil {
			last = err
			continue
		}
		cs := cands
		if auto && k < len(ids)-1 && len(cs) > 12 {
			cs = cs[:12]
		}
		w.setState("connecting", "подключаюсь к Cloudflare, маскировка: "+m.Title)
		t, err := w.connectMask(ctx, id, m, cs)
		if err == nil {
			w.remember(id, t)
			return t, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if auto && k < len(ids)-1 {
			logf("info", "WARP: с маскировкой «%s» ответа нет, пробую другую", m.Title)
		}
	}
	// If all cached endpoints failed, invalidate clean IP scanner cache for next retry
	theWarpScanner.reset()
	return nil, fmt.Errorf("%v — похоже, WireGuard/UDP к Cloudflare в вашей сети режется", last)
}

// run keeps the tunnel while it is wanted.
func (w *Warp) run(ctx context.Context) {
	backoff := 3 * time.Second
	for ctx.Err() == nil {
		if !w.wanted() {
			w.setState("idle", "")
			select {
			case <-ctx.Done():
				return
			case <-w.want:
			}
			continue
		}
		key := w.cfgKey()
		t, err := w.connectOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			msg := short(err.Error(), 220)
			w.setState("error", msg)
			logf("warn", "WARP: %s; повтор через %s", msg, humanDur(backoff))
			end := time.Now().Add(backoff)
			for time.Now().Before(end) && ctx.Err() == nil && w.cfgKey() == key && w.wanted() {
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
			if w.cfgKey() != key {
				backoff = 3 * time.Second
			} else {
				backoff = min(backoff*2, 2*time.Minute)
			}
			continue
		}
		backoff = 3 * time.Second
		w.up(t)
		at := time.Now()
		why := w.watch(ctx, t, key)
		w.cur.CompareAndSwap(t, nil)
		t.Close()
		if w.app != nil {
			w.app.tun.refresh()
		}
		if why != "" {
			logf("warn", "WARP: связь потеряна через %s (%s), переподключаюсь", humanDur(time.Since(at)), why)
			w.setState("connecting", "переподключаюсь")
		}
	}
}

// watch keeps the flow alive: when handshakes stop or data stops coming
// back it opens a new UDP flow (networks that cut a flow after a while let
// a new one through); when that does not help either it returns why.
func (w *Warp) watch(ctx context.Context, t *warpTunnel, key string) string {
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	var rx0, tx0, txAtRx, sumRx, sumTx int64
	start := time.Now()
	lastRx, flowAt, probeAt := start, start, time.Time{}
	fails, tried := 0, false
	probe := func() error {
		probeAt = time.Now()
		pctx, cancel := context.WithTimeout(ctx, 7*time.Second)
		defer cancel()
		return t.probe(pctx)
	}
	newFlow := func() bool {
		_, rx, tx := t.stats()
		at := time.Now()
		if t.refresh() != nil {
			return false
		}
		sumRx, sumTx = sumRx+rx, sumTx+tx
		rx0, tx0, txAtRx, flowAt = 0, 0, 0, at
		return true
	}
	for {
		select {
		case <-ctx.Done():
			return ""
		case <-tk.C:
		}
		if w.cfgKey() != key {
			if w.builtin() {
				logf("info", "WARP: настройки изменились, переподключаюсь")
			}
			return ""
		}
		if !w.wanted() {
			logf("info", "WARP не используется %s — туннель закрыт до следующего подключения", humanDur(warpIdle))
			return ""
		}
		hs, rx, tx := t.stats()
		now := time.Now()
		if rx > rx0 {
			rx0, lastRx, txAtRx = rx, now, tx
		}
		tx0 = tx
		if w.rotate > 0 && !tried && now.Sub(flowAt) >= w.rotate {
			newFlow()
			continue
		}
		stale := hs.IsZero() && now.Sub(flowAt) > 15*time.Second || !hs.IsZero() && now.Sub(hs) >= 135*time.Second
		silent := tx0-txAtRx > 512 && now.Sub(lastRx) >= 15*time.Second
		if !stale && !silent {
			fails, tried = 0, false
			continue
		}
		if !stale && now.Sub(probeAt) >= 15*time.Second && probe() == nil {
			fails = 0
			continue
		}
		if !tried {
			tried = true
			life := lastRx.Sub(flowAt)
			if stale && !hs.IsZero() {
				life = min(hs.Add(120*time.Second).Sub(flowAt), now.Sub(flowAt))
			}
			if newFlow() && t.waitHandshake(ctx, flowAt, 10*time.Second) && probe() == nil {
				w.recovered(life, stale)
				lastRx = time.Now()
				continue
			}
		}
		if time.Since(probeAt) < 15*time.Second {
			continue
		}
		err := probe()
		if err == nil {
			fails = 0
			continue
		}
		if fails++; fails < 2 {
			continue
		}
		why := "рукопожатий нет"
		if !hs.IsZero() {
			why = "последнее рукопожатие " + humanDur(time.Since(hs)) + " назад"
		}
		return fmt.Sprintf("%s, принято %s, отправлено %s, проверка: %s", why, warpBytes(sumRx+rx0), warpBytes(sumTx+tx0), short(err.Error(), 80))
	}
}

// recovered notes a flow that the network cut; when it keeps happening, new
// flows are opened ahead of time, a bit before the cut is due.
func (w *Warp) recovered(life time.Duration, stale bool) {
	w.recoveries++
	if life > 0 && (w.minLife == 0 || life < w.minLife) {
		w.minLife = life
	}
	what := "UDP-поток WARP перестал отвечать"
	if stale {
		what = "ключи WARP не обновились вовремя"
	}
	switch {
	case w.recoveries == 1:
		logf("info", "WARP: %s — открыт новый UDP-поток, связь восстановлена", what)
	case w.rotate == 0:
		w.rotate = min(max(w.minLife*2/3, 20*time.Second), 100*time.Second)
		logf("warn", "WARP: %s уже %d раза — похоже, сеть обрывает UDP-поток примерно через %s; новый поток будет открываться каждые %s", what, w.recoveries, humanDur(w.minLife), humanDur(w.rotate))
	}
}

func (w *Warp) up(t *warpTunnel) {
	w.cur.Store(t)
	node := t.colo
	if node == "" {
		node = "?"
	}
	logf("info", "WARP подключён: %s, узел %s, маскировка: %s", t.ep, node, t.mask.Title)
	w.mu.Lock()
	w.state, w.since = "connected", time.Now()
	w.text = fmt.Sprintf("подключён через %s, узел %s, маскировка: %s", t.ep, node, t.mask.Title)
	if w.ready != nil {
		close(w.ready)
	}
	w.ready = make(chan struct{})
	if w.stateCh != nil {
		close(w.stateCh)
	}
	w.stateCh = make(chan struct{})
	w.mu.Unlock()
	if w.app != nil {
		w.app.tun.refresh()
		if w.app.cfg != nil && w.app.cfg.tunWanted() && !tunActive.Load() {
			safeGo("Warp.up.tun", func() { _ = w.app.tun.start(w.app) })
		}
	}
}

func (w *Warp) setState(st, text string) {
	w.mu.Lock()
	w.state, w.text = st, text
	if st == "error" {
		w.errSeq++
		if w.stateCh != nil {
			close(w.stateCh)
		}
		w.stateCh = make(chan struct{})
	}
	w.mu.Unlock()
}

// view is what the UI shows.
func (w *Warp) view() map[string]any {
	if w == nil {
		return map[string]any{"state": "off", "text": "выключен"}
	}
	c := w.app.cfg
	c.mu.Lock()
	enabled, external, socks := c.Warp.Enabled, c.Warp.Engine == "socks", c.Warp.Socks
	c.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	st, text := w.state, w.text
	switch {
	case !enabled:
		st, text = "off", "выключен"
	case external:
		st, text = "external", "внешний SOCKS5 "+socks
	case st == "connected":
		text += ", " + humanDur(time.Since(w.since))
	case st == "idle":
		text = "включится, когда Psiphon пойдёт «Через WARP»"
	}
	return map[string]any{
		"state":     st,
		"text":      text,
		"clean_ips": len(theWarpScanner.cachedEndpoints()),
	}
}

// Close stops the local port and the tunnel (at exit).
func (w *Warp) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.ln != nil {
		_ = w.ln.Close()
		w.ln = nil
	}
	w.mu.Unlock()
	if t := w.cur.Swap(nil); t != nil {
		t.Close()
	}
}

func humanDur(d time.Duration) string {
	switch {
	case d < 90*time.Second:
		return fmt.Sprintf("%d с", int(d.Round(time.Second)/time.Second))
	case d < 90*time.Minute:
		return fmt.Sprintf("%d мин", int(d.Round(time.Minute)/time.Minute))
	}
	return fmt.Sprintf("%.1f ч", d.Hours())
}

func warpBytes(n int64) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%d Б", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f КБ", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%.1f МБ", float64(n)/(1<<20))
}

// Reconnect refreshes the active WARP UDP flow or triggers an immediate
// connection attempt when WARP is enabled.
func (w *Warp) Reconnect() {
	if w == nil || !w.builtin() {
		return
	}
	theWarpScanner.reset()
	if t := w.cur.Load(); t != nil {
		if err := t.refresh(); err == nil {
			logf("info", "WARP: открыт новый UDP-поток по запросу пользователя")
			return
		}
		w.cur.CompareAndSwap(t, nil)
		t.Close()
	}
	w.Want()
}
