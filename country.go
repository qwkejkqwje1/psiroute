package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-rule exit country ("psiphon:DE") and optional 2-tunnel parallel download
// load-balancing pool (Priority 6).
//
// Memory optimization (1.1.0+):
//  1. Zero-process fast path: if the main in-process Psiphon controller is
//     already connected to country CC (or configured for CC), traffic goes
//     straight through the main controller (0 extra processes, 0 MB extra RAM).
//  2. Hot-switch mode: if SingleProcessCountries is enabled (or the main
//     tunnel is idle/auto and no conflicting country rule is active), the main
//     in-process controller can hot-switch its EgressRegion to CC without
//     spawning a child process.
//  3. Ultra-slim worker fallback & optional 2nd parallel pool slot (Priority 6):
//     when two different country tunnels are simultaneously active (or when a
//     secondary parallel download tunnel is active), the helper process
//     initializes ONLY a bare Psiphon controller with GOMEMLIMIT=24MiB and
//     GOGC=30, and stops automatically after countryIdle (5 min) of inactivity.

const countryIdle = 5 * time.Minute

// countryOf returns "DE" for "psiphon:de".
func countryOf(ob string) (string, bool) {
	if !strings.HasPrefix(ob, obPsiphon+":") {
		return "", false
	}
	cc := strings.ToUpper(strings.TrimSpace(ob[len(obPsiphon)+1:]))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return "", false
	}
	return cc, true
}

func isCountryOb(ob string) bool { _, ok := countryOf(ob); return ok }

// countryChoices fills the route dropdowns in the UI.
var countryChoices = []string{"DE", "NL", "FI", "SE", "FR", "GB", "US", "CA", "PL", "AT", "CH", "JP", "SG"}

type countryWorker struct {
	cc      string
	cmd     *exec.Cmd
	stdin   io.Closer
	mu      sync.Mutex
	addr    string // SOCKS5 of the worker, "" until it reports
	state   string
	egress  string
	lastUse time.Time
	done    chan struct{}
}

type Countries struct {
	app          *App
	mu           sync.Mutex
	w            map[string]*countryWorker
	hotCountry   string
	hotSwitch    time.Time
	poolDialHook func(ctx context.Context, cc, addr string) (net.Conn, error)
}

func newCountries(app *App) *Countries { return &Countries{app: app, w: map[string]*countryWorker{}} }

func (c *Countries) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				c.StopAll()
				return
			case <-t.C:
				var toStop []*countryWorker
				c.mu.Lock()
				for cc, w := range c.w {
					w.mu.Lock()
					idle := time.Since(w.lastUse) > countryIdle
					w.mu.Unlock()
					if idle {
						logf("info", "Psiphon %s: не используется, останавливаю", cc)
						toStop = append(toStop, w)
						delete(c.w, cc)
					}
				}
				c.mu.Unlock()
				for _, w := range toStop {
					w.stop()
				}
			}
		}
	}()
}

func (c *Countries) StopAll() {
	c.mu.Lock()
	toStop := make([]*countryWorker, 0, len(c.w))
	for cc, w := range c.w {
		toStop = append(toStop, w)
		delete(c.w, cc)
	}
	c.mu.Unlock()
	for _, w := range toStop {
		w.stop()
	}
}

// StopCountry stops a specific country worker process if running.
func (c *Countries) StopCountry(cc string) bool {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	c.mu.Lock()
	w := c.w[cc]
	if w != nil {
		delete(c.w, cc)
	}
	c.mu.Unlock()
	if w == nil {
		return false
	}
	w.stop()
	logf("info", "Psiphon %s: фоновый процесс остановлен", cc)
	return true
}

func (w *countryWorker) stop() {
	if w.stdin != nil {
		_ = w.stdin.Close() // worker exits when its stdin closes
	}
	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		if w.cmd != nil && w.cmd.Process != nil {
			_ = w.cmd.Process.Kill()
		}
	}
}

// Status for the UI.
func (c *Countries) Status() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []map[string]any{}
	if c.app != nil && c.app.psi != nil {
		c.app.psi.mu.Lock()
		mainSt, mainEg := c.app.psi.state, c.app.psi.egress
		c.app.psi.mu.Unlock()
		if mainSt == "connected" && mainEg != "" {
			out = append(out, map[string]any{"country": mainEg, "state": "in-process (0 МБ)", "egress": mainEg})
		}
	}
	for cc, w := range c.w {
		w.mu.Lock()
		out = append(out, map[string]any{"country": cc, "state": w.state, "egress": w.egress})
		w.mu.Unlock()
	}
	return out
}

// DialPoolSlot dials through a warm secondary worker tunnel in the pool if one
// is already connected (or via poolDialHook in tests), used by Psi.DialBalanced
// (Priority 6) for 2-tunnel parallel download speed balancing without blocking
// if the secondary worker is not up.
func (c *Countries) DialPoolSlot(ctx context.Context, region, addr string) (net.Conn, error) {
	if c == nil {
		return nil, errors.New("нет пула туннелей")
	}
	c.mu.Lock()
	hook := c.poolDialHook
	var socks string
	if hook == nil {
		for cc, w := range c.w {
			if region != "" && !strings.EqualFold(cc, region) && !strings.EqualFold(cc, "POOL2") {
				continue
			}
			w.mu.Lock()
			if w.state == "connected" && w.addr != "" {
				w.lastUse = time.Now()
				socks = w.addr
			}
			w.mu.Unlock()
			if socks != "" {
				break
			}
		}
	}
	c.mu.Unlock()
	if hook != nil {
		return hook(ctx, region, addr)
	}
	if socks == "" {
		return nil, errors.New("вторичный туннель не активен")
	}
	return dialSocks5(ctx, socks, addr, "", "")
}

// canReuseMain reports whether the main in-process Psiphon controller already
// serves country cc (or can be hot-switched in single-process mode).
func (c *Countries) canReuseMain(cc string) bool {
	if c.app == nil || c.app.psi == nil {
		return false
	}
	c.app.psi.mu.Lock()
	eg := strings.ToUpper(c.app.psi.egress)
	st := c.app.psi.state
	c.app.psi.mu.Unlock()
	if st == "connected" && eg == cc {
		return true
	}
	c.app.cfg.mu.Lock()
	cfgReg := strings.ToUpper(c.app.cfg.Psiphon.Country)
	singleProc := c.app.cfg.Psiphon.SingleProcessCountries
	c.app.cfg.mu.Unlock()
	if cfgReg == cc && c.app.psi.running() {
		return true
	}
	if singleProc {
		c.mu.Lock()
		canHot := c.hotCountry == cc || time.Since(c.hotSwitch) > 30*time.Second
		if canHot && cfgReg != cc {
			c.hotCountry = cc
			c.hotSwitch = time.Now()
			c.mu.Unlock()
			c.app.cfg.mu.Lock()
			c.app.cfg.Psiphon.Country = cc
			c.app.cfg.mu.Unlock()
			logf("info", "Psiphon: горячее переключение страны выхода на %s в основном процессе (без дочернего процесса)", cc)
			go c.app.psi.Restart()
			return true
		}
		c.mu.Unlock()
		return canHot
	}
	return false
}

func (c *Countries) get(cc string) (*countryWorker, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if w := c.w[cc]; w != nil {
		select {
		case <-w.done:
			delete(c.w, cc) // crashed: start again
		default:
			return w, nil
		}
	}
	if c.app.ctx.Err() != nil {
		return nil, c.app.ctx.Err()
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(c.app.dataDir, "country-"+cc)
	seedPsiphonData(filepath.Join(c.app.dataDir, "psiphon"), filepath.Join(dir, "psiphon"))
	cmd := exec.Command(exe, "--psi-worker", "--worker-dir", dir, "--worker-region", cc, "--config", c.app.cfgPath)
	hideConsole(cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	w := &countryWorker{cc: cc, cmd: cmd, stdin: in, state: "connecting", lastUse: time.Now(), done: make(chan struct{})}
	c.w[cc] = w
	logf("info", "Psiphon %s: запускаю облегчённое подключение для этой страны", cc)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "@listen "):
				w.mu.Lock()
				w.addr = strings.TrimSpace(line[8:])
				w.mu.Unlock()
			case strings.HasPrefix(line, "@state "):
				f := strings.Fields(line[7:])
				w.mu.Lock()
				if len(f) > 0 {
					w.state = f[0]
				}
				if len(f) > 1 {
					w.egress = f[1]
				}
				w.mu.Unlock()
			case strings.HasPrefix(line, "@log "):
				lv, msg, _ := strings.Cut(line[5:], " ")
				logf(lv, "[%s] %s", cc, msg)
			}
		}
		if err := sc.Err(); err != nil {
			logf("warn", "Psiphon %s: связь с процессом прервалась: %v", cc, err)
		}
		_ = cmd.Wait()
		w.mu.Lock()
		w.state, w.addr = "stopped", ""
		w.mu.Unlock()
		close(w.done)
	}()
	return w, nil
}

// Dial goes out through the main Psiphon tunnel when it already matches cc (or
// in single-process hot-switch mode), otherwise through the slim worker for cc.
func (c *Countries) Dial(ctx context.Context, cc, addr string) (net.Conn, error) {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.canReuseMain(cc) {
		return c.waitConfirmedCountry(ctx, cc, addr)
	}
	w, err := c.get(cc)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		w.mu.Lock()
		w.lastUse = time.Now()
		socks, state := w.addr, w.state
		w.mu.Unlock()
		if socks != "" && state == "connected" {
			return dialSocks5(ctx, socks, addr, "", "")
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("Psiphon %s ещё подключается", cc)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-w.done:
			return nil, fmt.Errorf("Psiphon %s: процесс завершился", cc)
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// seedPsiphonData copies only the compact server-list files (< 16 MB) into a
// worker directory once so the worker does not have to re-download the server list.
func seedPsiphonData(from, to string) {
	if _, err := os.Stat(to); err == nil {
		return
	}
	_ = filepath.Walk(from, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, rerr := filepath.Rel(from, p)
		if rerr != nil {
			return nil
		}
		dst := filepath.Join(to, rel)
		if info.IsDir() {
			_ = os.MkdirAll(dst, 0o700)
			return nil
		}
		if strings.HasSuffix(p, ".lock") || info.Size() > 16<<20 {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			_ = os.WriteFile(dst, b, 0o600)
		}
		return nil
	})
	_ = os.MkdirAll(to, 0o700)
}

// ---- ultra-slim worker process ----

// runPsiWorker is the child process: runs ONLY a bare Config + Psi controller
// (no Stats, Router, Lists, NetWatch) with aggressive GC and a 24 MiB soft
// memory limit to minimize RAM usage.
func runPsiWorker(cfgPath, dir, region string) {
	ensurePortableDirs(dir)
	debug.SetGCPercent(30)
	debug.SetMemoryLimit(24 << 20)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }() // parent gone -> exit
	_ = os.MkdirAll(dir, 0o700)

	cfg := loadConfig(cfgPath)
	cfg.mu.Lock()
	cfg.path = "" // never write the user's config from a worker
	cfg.Psiphon.Country = region
	cfg.Psiphon.Standby = false
	cfg.Psiphon.Parallel = 1 // 1 tunnel for country worker to save RAM
	cfg.mu.Unlock()

	slimApp := &App{ctx: ctx, cancel: cancel, cfg: cfg, dataDir: dir}
	if cfg.Warp.Enabled && cfg.Warp.Engine != "socks" {
		slimApp.warp = newWarp(slimApp, filepath.Dir(cfgPath))
	}
	slimApp.psi = newPsi(slimApp, dir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("@log error", err)
		return
	}
	defer ln.Close()
	fmt.Println("@listen", ln.Addr().String())

	go func() {
		sent := 0
		last := ""
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			lines := theLog.snapshot()
			if sent > len(lines) {
				sent = 0
			}
			for _, l := range lines[sent:] {
				fmt.Println("@log", l.Level, strings.ReplaceAll(l.Msg, "\n", " "))
			}
			sent = len(lines)
			slimApp.psi.mu.Lock()
			st := slimApp.psi.state + " " + slimApp.psi.egress
			slimApp.psi.mu.Unlock()
			if st != last {
				fmt.Println("@state", st)
				last = st
			}
		}
	}()

	slimApp.psi.Start()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			break
		}
		go serveWorkerSocks(ctx, c, func(dctx context.Context, network, addr string) (net.Conn, error) {
			return (&Countries{app: slimApp}).waitConfirmedCountry(dctx, region, addr)
		})
	}
	slimApp.psi.Stop()
}

// serveWorkerSocks is a minimal SOCKS5 CONNECT server (no auth). It only
// listens on 127.0.0.1 and is used by the parent process.
func serveWorkerSocks(ctx context.Context, c net.Conn, dial dialFunc) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(40 * time.Second))
	br := bufio.NewReader(c)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, int(l))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	up, err := dial(dctx, "tcp", addr)
	cancel()
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	type copyRes struct {
		fromClient bool
		err        error
	}
	errc := make(chan copyRes, 2)
	go func() {
		bp := getRelayBuf()
		defer putRelayBuf(bp)
		_, err := io.CopyBuffer(up, br, *bp)
		errc <- copyRes{fromClient: true, err: err}
	}()
	go func() {
		bp := getRelayBuf()
		defer putRelayBuf(bp)
		_, err := io.CopyBuffer(c, up, *bp)
		errc <- copyRes{fromClient: false, err: err}
	}()
	r1 := <-errc
	if r1.fromClient {
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	} else if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_ = up.SetDeadline(time.Now().Add(5 * time.Second))
	<-errc
}

// dialConfirmedMainCountry captures the primary controller with its observed
// egress. Balanced/standby fallback is forbidden for an exact country rule.
func (c *Countries) dialConfirmedMainCountry(ctx context.Context, cc, addr string) (net.Conn, bool, error) {
	p := c.app.psi
	p.mu.Lock()
	controller := p.cur.Load()
	ready := p.state == "connected" && strings.EqualFold(p.confirmedEgress, cc) && p.confirmedController == controller
	hook := p.primaryDialHook
	p.mu.Unlock()
	if !ready || (controller == nil && hook == nil) {
		return nil, false, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, true, err
	}
	if hook != nil {
		conn, err := hook(ctx, "tcp", addr)
		return conn, true, err
	}
	conn, err := dialCountryController(ctx, controller, addr)
	return conn, true, err
}

func dialCountryController(ctx context.Context, controller *psiphon.Controller, addr string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 1)
	go func() { conn, err := controller.Dial(addr, nil); results <- result{conn, err} }()
	select {
	case r := <-results:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			r := <-results
			if r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func (c *Countries) waitConfirmedCountry(ctx context.Context, cc, addr string) (net.Conn, error) {
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if conn, ready, err := c.dialConfirmedMainCountry(ctx, cc, addr); ready {
			return conn, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("Psiphon %s: выход ещё не подтверждён", cc)
		case <-ticker.C:
		}
	}
}
