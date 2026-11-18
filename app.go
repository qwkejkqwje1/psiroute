package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errAlreadyRunning = errors.New("psiroute уже запущен")

// App wires everything together: config, Psiphon engine, router, stats,
// local proxy, LAN share, web UI.
type App struct {
	rulesWriteMu sync.Mutex
	tun          tunCtl // TUN mode, tun.go
	ctx          context.Context
	cancel       context.CancelFunc
	cfg          *Config
	cfgPath      string
	dataDir      string
	token        string

	psi    *Psi
	stats  *Stats
	router *Router

	lists     *Lists
	countries *Countries
	warp      *Warp // built-in WARP for Psiphon «Через WARP»

	proxyLn net.Listener
	uiLn    net.Listener

	// Actual addresses after port fallback (may differ from the config when
	// the configured port is taken by another program).
	uiActual     string
	listenActual string

	mu      sync.Mutex
	shareLn net.Listener
	dnsUDP  *net.UDPConn
	sysOn   bool

	probeMu      sync.Mutex
	probeRunning bool
	probeResults []probeResult
	probeCancel  context.CancelFunc

	net        *netWatch // sleep / network change recovery
	started    time.Time
	dohClients sync.Map // outbound -> *http.Client for DoH (dnsmsg.go)

	pauseMu    sync.Mutex
	pauseUntil atomic.Int64 // Unix timestamp (seconds) until protection is paused (0 = active)
	pauseTimer *time.Timer
}

// IsPaused сообщает, включён ли временный «Таймер паузы» (на 5 или 15 минут).
func (a *App) IsPaused() bool {
	if a == nil {
		return false
	}
	until := a.pauseUntil.Load()
	return until > 0 && time.Now().Unix() < until
}

// PauseRemainingSec возвращает остаток времени паузы в секундах (0, если пауза не активна).
func (a *App) PauseRemainingSec() int {
	if a == nil {
		return 0
	}
	until := a.pauseUntil.Load()
	if until <= 0 {
		return 0
	}
	rem := int(until - time.Now().Unix())
	if rem <= 0 {
		a.pauseUntil.Store(0)
		return 0
	}
	return rem
}

// SetPause включает временную паузу маршрутизации на minutes минут (или снимает паузу при minutes <= 0).
// Во время паузы весь трафик идёт напрямую (Direct) без разрыва фонового туннеля, а по истечении таймера
// защита включается обратно автоматически.
func (a *App) SetPause(minutes int) {
	if a == nil {
		return
	}
	a.pauseMu.Lock()
	if a.pauseTimer != nil {
		a.pauseTimer.Stop()
		a.pauseTimer = nil
	}
	if minutes <= 0 {
		a.pauseUntil.Store(0)
		a.pauseMu.Unlock()
		if a.router != nil {
			a.router.InvalidateRules()
		}
		logf("info", "Пауза снята — маршрутизация через защиту возобновлена")
		return
	}
	if minutes > 180 {
		minutes = 180
	}
	dur := time.Duration(minutes) * time.Minute
	a.pauseUntil.Store(time.Now().Add(dur).Unix())
	a.pauseTimer = time.AfterFunc(dur, func() {
		a.pauseUntil.Store(0)
		if a.router != nil {
			a.router.InvalidateRules()
		}
		logf("info", "Таймер паузы (%d мин) истёк — защита автоматически возобновлена", minutes)
	})
	a.pauseMu.Unlock()
	if a.router != nil {
		a.router.InvalidateRules()
	}
	logf("info", "Защита поставлена на паузу на %d мин (весь трафик временно идёт напрямую)", minutes)
}

type sessionLockState struct {
	PID      int    `json:"pid"`
	Listen   string `json:"listen"`
	SysProxy bool   `json:"sysproxy"`
	Tun      bool   `json:"tun"`
	Started  int64  `json:"started"`
}

func sessionLockFile(dir string) string { return filepath.Join(dir, "psiroute.session.lock") }

func recoverDirtySession(dir string, cfg *Config) {
	b, err := os.ReadFile(sessionLockFile(dir))
	if err != nil {
		return
	}
	cfgListen := ""
	if cfg != nil {
		cfg.mu.Lock()
		cfgListen = cfg.General.Listen
		cfg.mu.Unlock()
	}
	var st sessionLockState
	if json.Unmarshal(b, &st) == nil {
		addr := st.Listen
		if addr == "" {
			addr = cfgListen
		}
		if st.SysProxy || systemProxyOwnedBy(addr, cfgListen) {
			_ = setSystemProxy(addr, false)
			logf("warn", "Аварийное восстановление: системный прокси после прошлой сессии (PID %d) сброшен", st.PID)
		}
	}
	_ = os.Remove(sessionLockFile(dir))
}

func writeSessionLock(dir, listen string, sysProxy, tunOn bool) {
	b, err := json.Marshal(sessionLockState{
		PID:      os.Getpid(),
		Listen:   listen,
		SysProxy: sysProxy,
		Tun:      tunOn,
		Started:  time.Now().Unix(),
	})
	if err == nil {
		_ = os.WriteFile(sessionLockFile(dir), b, 0o600)
	}
}

func NewApp(ctx context.Context, cancel context.CancelFunc, cfgPath, dataDir string) *App {
	a := &App{ctx: ctx, cancel: cancel, cfgPath: cfgPath, dataDir: dataDir}
	a.cfg = loadConfig(cfgPath)
	a.cfg.applyCLIOverrides(activeCLIOverrides)
	if a.cfg.General.MemLimitMB > 0 {
		SetCustomMemoryLimitMB(a.cfg.General.MemLimitMB)
	}
	theLog.SetLevel(a.cfg.General.LogLevel)
	a.stats = newStats(filepath.Join(dataDir, "psiroute-days.json"))
	a.psi = newPsi(a, dataDir)
	a.router = newRouter(a, filepath.Join(dataDir, "psiroute-learned.json"))
	obfs.loadFile(filepath.Join(dataDir, "psiroute-obfs.json"))
	a.setupDPIAutoTune()
	a.lists = newLists(a, filepath.Join(dataDir, "lists"))
	a.countries = newCountries(a)
	a.warp = newWarp(a, dataDir)
	a.net = newNetWatch(a)
	theNetWatch = a.net
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error()) // never run with a predictable token
	}
	a.token = hex.EncodeToString(b)
	return a
}

// listenFallback listens on addr; if that port is unavailable it tries the
// next ports and finally lets the OS pick a free one. The host part (normally
// 127.0.0.1) is never changed, so the service stays local-only.
func listenFallback(addr string, tries int, skip ...int) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	firstErr := err
	host, ps, serr := net.SplitHostPort(addr)
	if serr != nil {
		return nil, firstErr
	}
	port := atoiSafe(ps)
next:
	for i := 1; i <= tries && port > 0 && port+i < 65536; i++ {
		for _, sk := range skip {
			if port+i == sk {
				continue next
			}
		}
		if ln, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port+i))); err == nil {
			return ln, nil
		}
	}
	if ln, err := net.Listen("tcp", net.JoinHostPort(host, "0")); err == nil {
		return ln, nil
	}
	return nil, firstErr
}

// The instance file records where the running copy serves its UI, so a
// second launch finds it even after a port fallback.
func instanceFile(dir string) string { return filepath.Join(dir, "psiroute.instance") }

func readInstance(dir string) string { return readInstanceLine(dir, 0) }

// readInstanceLine: line n (0-based) of the instance file, "" if absent.
func readInstanceLine(dir string, n int) string {
	b, err := os.ReadFile(instanceFile(dir))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	if n < 0 || n >= len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[n])
}

// isPsirouteAt reports whether another psiroute answers on the UI address.
func isPsirouteAt(addr string) bool {
	if addr == "" {
		return false
	}
	// Never go through any proxy for this local check.
	cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Get("http://" + addr + "/api/ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	return strings.HasPrefix(string(b), "psiroute")
}

func (a *App) uiAddr() string {
	a.mu.Lock()
	act := a.uiActual
	a.mu.Unlock()
	if act != "" {
		return act
	}
	a.cfg.mu.Lock()
	defer a.cfg.mu.Unlock()
	return a.cfg.General.UI
}

// listenAddr is the proxy address actually in use.
func (a *App) listenAddr() string {
	a.mu.Lock()
	act := a.listenActual
	a.mu.Unlock()
	if act != "" {
		return act
	}
	a.cfg.mu.Lock()
	defer a.cfg.mu.Unlock()
	return a.cfg.General.Listen
}

func (a *App) uiURL() string { return "http://" + a.uiAddr() + "/" }

func (a *App) Start() error {
	a.cfg.mu.Lock()
	listen, ui := a.cfg.General.Listen, a.cfg.General.UI
	noWeb := a.cfg.General.NoWeb
	share, sys := a.cfg.Share.Enabled, a.cfg.General.SystemProxy
	sharePort := a.cfg.Share.Port
	a.cfg.mu.Unlock()

	if !noWeb {
		for _, addr := range []string{readInstance(a.dataDir), ui} {
			if isPsirouteAt(addr) {
				a.mu.Lock()
				a.uiActual = addr
				a.mu.Unlock()
				return errAlreadyRunning
			}
		}
	}
	var uiLn net.Listener
	if !noWeb {
		var err error
		uiLn, err = listenFallback(ui, 20)
		if err != nil {
			return fmt.Errorf("не удалось открыть интерфейс на %s и соседних портах: %w", ui, err)
		}
		if got := uiLn.Addr().String(); got != ui {
			logf("warn", "Адрес интерфейса %s занят другой программой — использую %s", ui, got)
		}
	}
	ln, err := listenFallback(listen, 20, sharePort)
	if err != nil {
		if uiLn != nil {
			uiLn.Close()
		}
		return fmt.Errorf("порт прокси %s занят: %w", listen, err)
	}
	if got := ln.Addr().String(); got != listen {
		logf("warn", "Порт прокси %s занят — использую %s (укажите его в программах, настроенных вручную)", listen, got)
	}
	a.mu.Lock()
	a.uiLn, a.proxyLn = uiLn, ln
	if uiLn != nil {
		a.uiActual = uiLn.Addr().String()
		ui = a.uiActual
	} else {
		a.uiActual = ""
		ui = ""
	}
	a.listenActual = ln.Addr().String()
	a.mu.Unlock()
	listen = a.listenActual
	_ = os.WriteFile(instanceFile(a.dataDir), []byte(ui+"\n"+a.token+"\n"+listen), 0o600)
	a.started = time.Now()

	// Stage 5 Crash Recovery: inspect psiroute.session.lock from any previous unclean exit.
	recoverDirtySession(a.dataDir, a.cfg)
	if !sys {
		if stale := systemProxyOwnedBy(a.cfg.General.Listen, listen); stale {
			if err := setSystemProxy(listen, false); err == nil {
				logf("warn", "Системный прокси остался от прошлого запуска — сброшен")
			}
		}
	}
	writeSessionLock(a.dataDir, listen, sys, a.cfg.tunWanted())
	go a.serveProxy(ln, nil)
	if uiLn != nil {
		go a.serveUI(uiLn)
	}
	goLoop(a.ctx, "основной цикл", a.loop)
	if share {
		if err := a.setShare(true); err != nil {
			logf("warn", "Раздача в сеть не запущена: %v", err)
		}
	}
	if sys {
		if err := a.setSysProxy(true); err != nil {
			logf("warn", "Системный прокси: %v", err)
		}
	}
	a.cfg.mu.Lock()
	localDNS := a.cfg.DNS.LocalServer
	a.cfg.mu.Unlock()
	if localDNS {
		if err := a.setLocalDNS(true); err != nil {
			logf("warn", "Локальный DNS: %v", err)
		}
	}
	a.psi.Start()
	goLoop(a.ctx, "WARP", func() { a.warp.run(a.ctx) })
	goLoop(a.ctx, "слежение за сетью", func() { a.net.run(a.ctx) })
	a.lists.Start(a.ctx)
	a.countries.Start(a.ctx)
	if a.cfg.tunWanted() {
		goSafe("TUN", func() {
			if err := a.tun.start(a); err != nil {
				logf("warn", "Режим TUN: %s", tunErrText(err))
			}
		})
	}
	logf("info", "Psiroute %s: прокси %s (SOCKS5 + HTTP), интерфейс http://%s", version, listen, ui)
	return nil
}

func (a *App) Shutdown() {
	a.mu.Lock()
	sys := a.sysOn
	a.mu.Unlock()
	if sys {
		_ = setSystemProxy(a.listenAddr(), false) // keep the setting: it is restored on next start
	}
	a.tun.stop() // remove the adapter and its routes first
	if a.stats != nil {
		a.stats.Flush()
	}
	a.router.flush()
	_ = os.Remove(sessionLockFile(a.dataDir))
	if readInstance(a.dataDir) == a.uiAddr() {
		_ = os.Remove(instanceFile(a.dataDir))
	}
	a.stopProbe()
	a.countries.StopAll()
	a.psi.Stop()
	a.warp.Close()
	for _, l := range []net.Listener{a.proxyLn, a.uiLn} {
		if l != nil {
			l.Close()
		}
	}
	a.mu.Lock()
	if a.shareLn != nil {
		a.shareLn.Close()
	}
	if a.dnsUDP != nil {
		_ = a.dnsUDP.Close()
		a.dnsUDP = nil
	}
	a.mu.Unlock()
}

func (a *App) loop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var mod time.Time
	if st, err := os.Stat(a.cfgPath); err == nil {
		mod = st.ModTime()
	}
	n := 0
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
			a.stats.tick()
			n++
			if n%3 != 0 {
				continue
			}
			a.cfg.mu.Lock()
			watch := a.cfg.General.WatchConfig
			a.cfg.mu.Unlock()
			if st, err := os.Stat(a.cfgPath); err == nil && st.ModTime().After(mod) {
				mod = st.ModTime()
				// Находка 11: игнорируем изменение ModTime, вызванное собственным a.cfg.save()
				if watch && !a.cfg.isSelfSaveModTime(mod) {
					a.reloadConfig()
				}
			}
		}
	}
}

// reloadConfig re-reads psiroute.json. A broken file is ignored (never
// replaced by defaults) so a half-saved edit cannot wipe the settings.
func (a *App) reloadConfig() {
	b, err := os.ReadFile(a.cfgPath)
	if err != nil {
		return
	}
	n := defaultConfig()
	if err := json.Unmarshal(b, n); err != nil {
		logf("warn", "psiroute.json: ошибка в файле, изменения не применены: %v", err)
		return
	}
	if n.Desync.Method == "" {
		n.Desync.Method = "auto"
	}
	if n.Tun.MTU < 1280 || n.Tun.MTU > 9000 {
		n.Tun.MTU = 1500
	}
	c := a.cfg
	c.mu.Lock()
	before, _ := json.Marshal([]any{c.Psiphon, c.Warp, c.Proxy})
	wasTun := c.Tun.Enabled
	c.Psiphon, c.Desync, c.Warp, c.Proxy, c.DNS, c.Routing, c.Lists = n.Psiphon, n.Desync, n.Warp, n.Proxy, n.DNS, n.Routing, n.Lists
	syncListRegistryLocked(c)
	c.UDP = n.UDP
	c.Tun = n.Tun
	c.General.WatchConfig = n.General.WatchConfig
	if n.General.UITheme != "" {
		c.General.UITheme = n.General.UITheme
	}
	if n.General.UIMode == "browser" || n.General.UIMode == "gio" || n.General.UIMode == "native" {
		if n.General.UIMode == "native" {
			c.General.UIMode = "gio"
		} else {
			c.General.UIMode = n.General.UIMode
		}
	}
	needRestart := n.General.Listen != c.General.Listen || n.General.UI != c.General.UI
	after, _ := json.Marshal([]any{c.Psiphon, c.Warp, c.Proxy})
	nowTun := c.Tun.Enabled
	c.mu.Unlock()

	a.onRulesChanged()
	if a.lists != nil {
		a.lists.Refresh()
	}
	if needRestart {
		logf("info", "Адрес прокси или интерфейса изменён в файле — применится после перезапуска Psiroute")
	}
	if nowTun != wasTun {
		if nowTun {
			goSafe("TUN", func() {
				if err := a.tun.start(a); err != nil {
					logf("warn", "Режим TUN: %s", tunErrText(err))
				}
			})
		} else {
			goSafe("TUN", a.tun.stop)
		}
	} else if nowTun {
		a.tun.refresh()
	}
	if string(before) != string(after) && a.psi.running() {
		logf("info", "Настройки Psiphon изменились — переподключаюсь")
		go a.psi.Restart()
	}
}

func (a *App) setSysProxy(on bool) error {
	l := a.listenAddr()
	if err := setSystemProxy(l, on); err != nil {
		return err
	}
	a.mu.Lock()
	a.sysOn = on
	a.mu.Unlock()
	a.cfg.setKey("general.system_proxy", on)
	_ = a.cfg.save()
	if on {
		logf("info", "Системный прокси включён: %s", l)
	} else {
		logf("info", "Системный прокси выключен")
	}
	return nil
}

// onRulesChanged принудительно сбрасывает кэш маршрутных решений (routeCache),
// кэш прямых A/AAAA ответов (сохраняя таблицу FakeIP и RevDNS!) и немедленно
// закрывает активные TCP/UDP соединения, чей маршрут изменился или заблокирован.
func (a *App) onRulesChanged() int {
	if a == nil {
		return 0
	}
	if a.router != nil {
		a.router.InvalidateRules()
	}
	theDNS.clearLookupCache()
	flushWindowsDNSCache()
	if a.stats == nil || a.router == nil {
		return 0
	}
	closed := a.stats.closeAffectedSessions(func(t *tracked) bool {
		if t == nil {
			return false
		}
		targetHost, rawHost, port, appName, curOb := a.stats.routeAndHost(t)
		proto := t.protocol
		if proto == "" {
			proto = "tcp"
		}
		dstIP := ""
		if net.ParseIP(rawHost) != nil {
			dstIP = rawHost
		}
		if proto == "udp" {
			newOb, _ := a.planUDPIP(targetHost, dstIP, port, appName)
			if newOb == "" {
				return curOb != obBlock && curOb != ""
			}
			return newOb != curOb
		}
		order, _ := a.router.planForProto(proto, targetHost, dstIP, port, appName)
		if len(order) == 0 || order[0] == obBlock {
			// Если новый маршрут блокирует трафик (пустой order / block),
			// обязательно закрываем активное соединение!
			return curOb != obBlock && curOb != ""
		}
		return order[0] != curOb
	})
	if closed > 0 {
		logf("info", "Правила обновлены: сброшено активных сессий со старым маршрутом: %d", closed)
	}
	return closed
}

func (a *App) state() map[string]any {
	return a.stateCompact(false)
}

func (a *App) stateCompact(compact bool) map[string]any {
	a.cfg.mu.Lock()
	mode := a.cfg.Routing.Mode
	bypassLAN := a.cfg.Routing.BypassLAN
	blockQUIC := a.cfg.Routing.BlockQUIC
	killSwitch := a.cfg.Routing.KillSwitch
	blockSTUN := a.cfg.Routing.BlockSTUN
	fakeIP := a.cfg.Tun.FakeIP
	singleCountry := a.cfg.Psiphon.SingleProcessCountries
	dnsOn := a.cfg.DNS.Enabled
	localDNSAddr := a.cfg.DNS.LocalAddr
	warpOn := a.cfg.Warp.Enabled
	uiMode := a.cfg.General.UIMode
	uiTheme := a.cfg.General.UITheme
	favCountries := append([]string(nil), a.cfg.Psiphon.FavoriteCountries...)
	cfgErr := a.cfg.corruptErr
	cfgBackup := a.cfg.corruptBackup
	a.cfg.mu.Unlock()
	listen, ui := a.listenAddr(), a.uiAddr()
	a.mu.Lock()
	sys := a.sysOn
	shareOn := a.shareLn != nil
	localDNSOn := a.dnsUDP != nil
	a.mu.Unlock()

	var logs []logLine
	if !compact {
		logs = theLog.snapshot()
		if len(logs) > 300 {
			logs = logs[len(logs)-300:]
		}
	}
	learned := a.router.learnedList()
	learnedCount := len(learned)
	if compact {
		learned = nil
	}
	return map[string]any{
		"version": version, "mode": mode, "listen": listen, "ui": ui, "sysproxy": sys,
		"share_on": shareOn, "dns_on": dnsOn, "local_dns_on": localDNSOn, "local_dns_addr": localDNSAddr,
		"warp_on": warpOn, "bypass_lan": bypassLAN, "block_quic": blockQUIC,
		"kill_switch": killSwitch, "block_stun": blockSTUN, "fake_ip": fakeIP,
		"single_process_countries": singleCountry, "fakeip_count": theFakeIP.count(), "ui_mode": uiMode, "ui_theme": uiTheme,
		"psiphon": a.psi.view(), "psiphon_slots": a.psi.slots(), "warp": a.warp.view(),
		"stats": a.stats.snapshot(), "history": a.stats.history(),
		"log": logs, "learned": learned, "learned_count": learnedCount,
		"mem": memView(), "net": a.net.view(), "panics": panicsCaught.Load(), "crash_restarts": crashRestarts,
		"udp": map[string]any{"mode": a.udpMode(), "sessions": udpStats.sessions.Load(), "flows": udpStats.flows.Load(), "quic_desync_sent": quicDesyncSent.Load()},
		"tun": a.tun.view(), "obfs": a.obfsView(),
		"countries": a.countries.Status(), "favorite_countries": favCountries,
		"config_error": cfgErr, "config_backup": cfgBackup,
		"probe_running": a.isProbeRunning(),
		"paused":        a.IsPaused(), "pause_remaining_sec": a.PauseRemainingSec(), "pause_until": a.pauseUntil.Load(),
	}
}

func (a *App) isProbeRunning() bool {
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	return a.probeRunning
}

// processesView returns the unified status of all main processes and services
// for the Main Menu / Process Control Center.
func (a *App) processesView() map[string]any {
	a.cfg.mu.Lock()
	dnsOn := a.cfg.DNS.Enabled
	warpOn := a.cfg.Warp.Enabled
	bypassLAN := a.cfg.Routing.BypassLAN
	blockQUIC := a.cfg.Routing.BlockQUIC
	mode := a.cfg.Routing.Mode
	a.cfg.mu.Unlock()
	a.mu.Lock()
	sysOn := a.sysOn
	shareOn := a.shareLn != nil
	a.mu.Unlock()

	dpiT.mu.Lock()
	dpiTestRun := dpiT.running
	dpiT.mu.Unlock()

	return map[string]any{
		"ok":            true,
		"psiphon":       a.psi.view(),
		"psiphon_on":    a.psi.running(),
		"warp":          a.warp.view(),
		"warp_on":       warpOn,
		"tun":           a.tun.view(),
		"sysproxy_on":   sysOn,
		"share":         a.shareInfo(),
		"share_on":      shareOn,
		"dns_on":        dnsOn,
		"dpi_mode":      a.dpiMode(),
		"obfs":          a.obfsView(),
		"udp_mode":      a.udpMode(),
		"routing_mode":  mode,
		"bypass_lan":    bypassLAN,
		"block_quic":    blockQUIC,
		"countries":     a.countries.Status(),
		"lists":         a.lists.Status(),
		"probe_running": a.isProbeRunning(),
		"dpitest_run":   dpiTestRun,
		"mem":           memView(),
	}
}

// ---- DPI auto-probe (separate process, see probe.go) ----

func (a *App) startProbe() error {
	a.probeMu.Lock()
	if a.probeRunning {
		a.probeMu.Unlock()
		return errors.New("подбор уже идёт")
	}
	a.probeRunning = true
	a.probeResults = nil
	ctx, cancel := context.WithCancel(a.ctx)
	a.probeCancel = cancel
	a.probeMu.Unlock()

	fail := func(err error) error {
		a.probeMu.Lock()
		a.probeRunning = false
		a.probeMu.Unlock()
		cancel()
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	a.cfg.mu.Lock()
	region := strings.ToUpper(a.cfg.Psiphon.Country)
	a.cfg.mu.Unlock()
	cmd := exec.CommandContext(ctx, exe, "--probe", "--probe-dir", filepath.Join(a.dataDir, "probe"), "--probe-region", region)
	hideConsole(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fail(err)
	}
	if err := cmd.Start(); err != nil {
		return fail(err)
	}
	logf("info", "Подбор обхода: проверяю варианты (до 8 минут)")
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			var r probeResult
			if json.Unmarshal(sc.Bytes(), &r) != nil {
				continue
			}
			a.probeMu.Lock()
			a.probeResults = append(a.probeResults, r)
			a.probeMu.Unlock()
			if r.OK {
				logf("info", "Подбор: «%s» — работает, %d мс, %d КБ/с", r.Name, r.ConnectMs, r.Kbps)
			} else if r.Name != "" {
				logf("info", "Подбор: «%s» — нет (%s)", r.Name, r.Note)
			}
		}
		if err := sc.Err(); err != nil {
			logf("warn", "Подбор: результаты прочитаны не полностью: %v", err)
		}
		_ = cmd.Wait()
		a.probeMu.Lock()
		a.probeRunning = false
		a.probeCancel = nil
		a.probeMu.Unlock()
		cancel()
		logf("info", "Подбор обхода завершён")
	}()
	return nil
}

func (a *App) stopProbe() {
	a.probeMu.Lock()
	if a.probeCancel != nil {
		a.probeCancel()
	}
	a.probeMu.Unlock()
}

func (a *App) probeState() map[string]any {
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	res := append([]probeResult(nil), a.probeResults...)
	if res == nil {
		res = []probeResult{}
	}
	best := ""
	bestScore := -1.0
	for _, r := range res {
		if !r.OK {
			continue
		}
		score := float64(r.Kbps) + 100000.0/float64(r.ConnectMs+1)
		if score > bestScore {
			best, bestScore = r.ID, score
		}
	}
	return map[string]any{"running": a.probeRunning, "results": res, "best": best, "total": len(psiDPIStrategies())}
}

// applyProbe turns a probe result into settings: a DPI mode, or a protocol
// strategy moved to the top of the list.
func (a *App) applyProbe(id string) error {
	a.probeMu.Lock()
	var found *probeResult
	for i := range a.probeResults {
		if a.probeResults[i].ID == id && a.probeResults[i].OK {
			found = &a.probeResults[i]
		}
	}
	a.probeMu.Unlock()
	if found == nil {
		return errors.New("нет такого рабочего варианта")
	}
	c := a.cfg
	c.mu.Lock()
	if found.Protos == "" {
		c.Psiphon.DPI = found.DPI
	} else {
		list := []string{found.Protos}
		for _, s := range c.Psiphon.Strategies {
			if s != found.Protos {
				list = append(list, s)
			}
		}
		c.Psiphon.Strategies = list
	}
	c.mu.Unlock()
	_ = c.save()
	_ = os.Remove(a.psi.file("psiroute-last"))
	logf("info", "Применён вариант «%s»", found.Name)
	go a.psi.Restart()
	return nil
}
