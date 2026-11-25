package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONCode(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

func (a *App) serveUI(ln net.Listener) {
	srv := &http.Server{Handler: a.routes(), ReadHeaderTimeout: 10 * time.Second}
	safeGo("App.serveUI", func() {
		<-a.ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	_ = srv.Serve(ln)
}

func isAllowedLocalHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func isAllowedOrigin(r *http.Request) bool {
	if sfs := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); sfs == "cross-site" {
		return false
	}
	if orig := r.Header.Get("Origin"); orig != "" && orig != "null" {
		u, err := url.Parse(orig)
		if err != nil || !isAllowedLocalHost(u.Host) {
			return false
		}
	}
	return true
}

func (a *App) routes() http.Handler {
	// Direction 3 RAM optimization: do not pre-allocate a duplicate 150 KB HTML buffer
	// at startup when the user only uses the native Gio GUI; build it on demand.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		// Block DNS-rebinding and cross-site requests: only accept requests addressed to localhost.
		if !isAllowedLocalHost(r.Host) || !isAllowedOrigin(r) {
			http.Error(w, "доступ запрещён", http.StatusForbidden)
			return
		}
		switch {
		case r.URL.Path == "/api/ping":
			_, _ = w.Write([]byte("psiroute " + version))
		case strings.HasPrefix(r.URL.Path, "/api/"):
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Psiroute")), []byte(a.token)) != 1 {
				writeErr(w, http.StatusForbidden, "неверный токен")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
			defer func() {
				if v := recover(); v != nil {
					reportPanic("интерфейс "+r.URL.Path, v)
					writeErr(w, 500, "внутренняя ошибка (записана в журнал)")
				}
			}()
			a.api(w, r)
		case r.URL.Path == "/proxy.pac":
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(browserPAC(a.listenAddr())))
		case r.URL.Path == "/" || r.URL.Path == "/index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
			indexHTML, err := readCompressedAsset("ui/index.html.gz")
			if err != nil {
				http.Error(w, "UI asset unavailable", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(bytes.ReplaceAll(indexHTML, []byte("__PSIROUTE_TOKEN__"), []byte(a.token)))
		default:
			http.NotFound(w, r)
		}
	})
}

func (a *App) restartIfRunning() bool {
	if a.psi.running() {
		safeGo("App.restartIfRunning", a.psi.Restart)
		return true
	}
	return false
}

func (a *App) api(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/")
	if r.Method != http.MethodGet && (p == "rules" || strings.HasPrefix(p, "rules/") || p == "conns/quick-rule") {
		a.rulesWriteMu.Lock()
		defer a.rulesWriteMu.Unlock()
	}

	q := r.URL.Query()
	post := r.Method == http.MethodPost
	ok := map[string]any{"ok": true}
	tail := func(prefix string) string { return strings.TrimPrefix(p, prefix) }

	if p == "config/ack-corrupt" && post {
		a.cfg.ackCorruptError() // the user has seen the warning about the damaged config
		writeJSON(w, ok)
		return
	}
	if strings.HasPrefix(p, "profiles") && a.profilesAPI(w, r, p) {
		return
	}
	if p == "apps" {
		a.appsAPI(w, r)
		return
	}
	if p == "lists" || strings.HasPrefix(p, "lists/") {
		a.listsAPI(w, r, p)
		return
	}

	switch {
	case p == "leaktest" && post:
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		writeJSON(w, a.RunLeakTest(ctx))
	case p == "selftest" && post:
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		checks := a.selftest(ctx)
		writeJSON(w, map[string]any{"checks": checks, "text": formatChecks(checks)})
	case p == "report" && post:
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		path, err := a.makeReport(ctx)
		if err != nil {
			writeErr(w, 500, "отчёт не сохранён: "+err.Error())
			return
		}
		if q.Get("reveal") != "0" {
			revealFile(path)
		}
		writeJSON(w, map[string]any{"ok": true, "path": path})
	case p == "state":
		writeJSON(w, a.stateCompact(q.Get("compact") == "1"))
	case p == "fsm":
		writeJSON(w, a.fsm.View())
	case p == "stack/reset" && post:
		a.ResetStack()
		writeJSON(w, ok)
	case p == "clean-chain/verify" && post:
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		writeJSON(w, a.cleanChain.Verify(ctx))
	case p == "psi/blocked-countries":
		if post {
			var b struct {
				Country string   `json:"country"`
				CC      string   `json:"cc"`
				Blocked []string `json:"blocked"`
			}
			if json.NewDecoder(r.Body).Decode(&b) != nil {
				writeErr(w, 400, "ошибка в данных запроса")
				return
			}
			a.cfg.mu.Lock()
			if b.Blocked != nil {
				a.cfg.Psiphon.BlockedCountries = normalizeFavoriteCountries(b.Blocked)
			} else {
				cc := strings.ToUpper(strings.TrimSpace(b.Country))
				if cc == "" {
					cc = strings.ToUpper(strings.TrimSpace(b.CC))
				}
				if len(cc) == 2 && cc != "AUTO" {
					cur := append([]string(nil), a.cfg.Psiphon.BlockedCountries...)
					idx := slices.Index(cur, cc)
					if idx >= 0 {
						cur = append(cur[:idx], cur[idx+1:]...)
					} else {
						cur = append(cur, cc)
					}
					a.cfg.Psiphon.BlockedCountries = normalizeFavoriteCountries(cur)
				}
			}
			blk := append([]string(nil), a.cfg.Psiphon.BlockedCountries...)
			curEgress := ""
			if a.psi != nil {
				v := a.psi.view()
				curEgress, _ = v["egress"].(string)
			}
			pinned := strings.TrimSpace(a.cfg.Psiphon.Country)
			a.cfg.mu.Unlock()
			if !a.saveOrFail(w, "App.api") {
				return
			}
			rotated := false
			if pinned == "" && curEgress != "" && slices.Contains(blk, strings.ToUpper(curEgress)) && a.psi != nil && a.psi.running() {
				a.psi.NewNode()
				rotated = true
			}
			writeJSON(w, map[string]any{"ok": true, "blocked_countries": blk, "rotated": rotated})
			return
		}
		a.cfg.mu.Lock()
		blk := append([]string(nil), a.cfg.Psiphon.BlockedCountries...)
		a.cfg.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true, "blocked_countries": blk})
	case p == "clean-chain/toggle" && post:
		var b struct {
			Enabled   *bool `json:"enabled"`
			AutoChain *bool `json:"auto_chain"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Enabled != nil {
			a.cfg.setKey("clean_chain.enabled", *b.Enabled)
			if !*b.Enabled && a.cleanChain != nil {
				a.cleanChain.Close()
			}
		}
		if b.AutoChain != nil {
			a.cfg.setKey("clean_chain.auto_chain", *b.AutoChain)
		}
		if !a.saveOrFail(w, "App.api") {
			return
		}
		a.onRulesChanged()
		a.syncWFPKillSwitch()
		a.tun.refresh()
		writeJSON(w, map[string]any{"ok": true, "clean_chain": a.cleanChain.View()})
	case p == "processes" && !post:
		writeJSON(w, a.processesView())
	case p == "processes" && post:
		a.processesAPI(w, r)
	case p == "psi/info":
		writeJSON(w, a.psi.info())

	case p == "settings" && !post:
		writeJSON(w, map[string]any{"values": a.cfg.values(), "autostart": autostartEnabled(), "config_path": a.cfgPath})
	case p == "settings":
		var m map[string]any
		if json.NewDecoder(r.Body).Decode(&m) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		restart := false
		for k, v := range m {
			if k == "tun.enabled" {
				if err := a.setTun(toBool(v)); err != nil {
					writeJSON(w, map[string]any{"ok": false, "error": tunErrText(err), "need_admin": err == errNeedAdmin})
					return
				}
				continue
			}
			if k == "general.system_proxy" {
				if err := a.setSysProxy(toBool(v)); err != nil {
					writeErr(w, 500, err.Error())
					return
				}
				continue
			}
			if k == "dns.local_server" {
				if err := a.setLocalDNS(toBool(v)); err != nil {
					writeErr(w, 500, err.Error())
					return
				}
				continue
			}
			if a.cfg.setKey(k, v) {
				restart = true
			}
		}
		if !a.saveOrFail(w, "App.api") {
			return
		}
		a.onRulesChanged()
		restarted := restart && a.restartIfRunning()
		writeJSON(w, map[string]any{"ok": true, "restarted": restarted})

	case p == "psi/strategies":
		var b struct {
			Strategies []string `json:"strategies"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		ids := []string{}
		for _, id := range b.Strategies {
			if _, okk := strategyByID(id); okk {
				ids = append(ids, id)
			}
		}
		a.cfg.mu.Lock()
		a.cfg.Psiphon.Strategies = ids
		a.cfg.mu.Unlock()
		if !a.saveOrFail(w, "App.api") {
			return
		}
		writeJSON(w, map[string]any{"ok": true, "restarted": a.restartIfRunning()})
	case p == "psi/favorites":
		if post {
			var b struct {
				Country   string   `json:"country"`
				CC        string   `json:"cc"`
				Favorites []string `json:"favorites"`
			}
			if json.NewDecoder(r.Body).Decode(&b) != nil {
				writeErr(w, 400, "ошибка в данных запроса")
				return
			}
			a.cfg.mu.Lock()
			if b.Favorites != nil {
				a.cfg.Psiphon.FavoriteCountries = normalizeFavoriteCountries(b.Favorites)
			} else {
				cc := strings.ToUpper(strings.TrimSpace(b.Country))
				if cc == "" {
					cc = strings.ToUpper(strings.TrimSpace(b.CC))
				}
				if len(cc) == 2 && cc != "AUTO" {
					cur := append([]string(nil), a.cfg.Psiphon.FavoriteCountries...)
					idx := slices.Index(cur, cc)
					if idx >= 0 {
						cur = append(cur[:idx], cur[idx+1:]...)
					} else {
						cur = append(cur, cc)
					}
					a.cfg.Psiphon.FavoriteCountries = normalizeFavoriteCountries(cur)
				}
			}
			favs := append([]string(nil), a.cfg.Psiphon.FavoriteCountries...)
			a.cfg.mu.Unlock()
			if !a.saveOrFail(w, "App.api") {
				return
			}
			writeJSON(w, map[string]any{"ok": true, "favorite_countries": favs})
			return
		}
		a.cfg.mu.Lock()
		favs := append([]string(nil), a.cfg.Psiphon.FavoriteCountries...)
		a.cfg.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true, "favorite_countries": favs})
	case p == "stats/reset" && post:
		a.stats.ResetTotals()
		logf("info", "Счётчики трафика сброшены пользователем")
		writeJSON(w, map[string]any{"ok": true, "stats": a.stats.snapshot()})
	case p == "psi/reset-order" && post:
		a.psi.ResetStrategyMemory()
		logf("info", "Рейтинг стратегий Psiphon сброшен — приоритет прямых DPI-методов восстановлен")
		writeJSON(w, map[string]any{"ok": true, "restarted": a.restartIfRunning()})
	case p == "psi/region":
		var b struct {
			Region string `json:"region"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		reg := strings.ToUpper(strings.TrimSpace(b.Region))
		if reg == "AUTO" {
			reg = ""
		}
		a.cfg.mu.Lock()
		a.cfg.Psiphon.Country = reg
		a.cfg.mu.Unlock()
		if !a.saveOrFail(w, "App.api") {
			return
		}
		if reg == "" {
			logf("info", "Страна выхода: любая (быстрейшая)")
		} else {
			logf("info", "Страна выхода: %s", reg)
		}
		writeJSON(w, map[string]any{"ok": true, "restarted": a.restartIfRunning()})
	case p == "psi/speedtest":
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		writeJSON(w, a.psi.SpeedTest(ctx))
	case p == "psi/probe":
		if post {
			if err := a.startProbe(); err != nil {
				writeErr(w, 409, err.Error())
				return
			}
		}
		writeJSON(w, a.probeState())
	case p == "psi/probe/stop":
		a.stopProbe()
		writeJSON(w, ok)
	case p == "psi/probe/apply":
		if err := a.applyProbe(q.Get("id")); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, ok)

	case strings.HasPrefix(p, "psiphon/"):
		switch tail("psiphon/") {
		case "stats":
			writeJSON(w, a.psi.statsView())
			return
		case "state":
			writeJSON(w, a.psi.connectionStateView())
			return
		case "action":
			if !post {
				writeErr(w, 405, "нужен POST-запрос")
				return
			}
			var act struct {
				Action string `json:"action"`
			}
			if json.NewDecoder(r.Body).Decode(&act) != nil {
				writeErr(w, 400, "ошибка в данных запроса")
				return
			}
			switch act.Action {
			case "use_warp":
				a.cfg.setKey("warp.enabled", true)
				if !a.saveOrFail(w, "App.api") {
					return
				}
				a.warp.Want()
				writeJSON(w, map[string]any{"ok": true, "action": "use_warp"})
			case "retry_patient":
				a.cfg.setKey("psiphon.preset", PresetPatient)
				if !a.saveOrFail(w, "App.api") {
					return
				}
				if a.psi.running() {
					safeGo("App.api", a.psi.Restart)
				}
				writeJSON(w, map[string]any{"ok": true, "action": "retry_patient", "preset": PresetPatient})
			case "run_diagnostics":
				rep := a.psi.RunPreflight(r.Context(), true)
				writeJSON(w, map[string]any{"ok": true, "action": "run_diagnostics", "preflight": rep})
			case "import_servers", "use_worker":
				writeJSON(w, map[string]any{"ok": true, "action": act.Action, "ui_prompt": true})
			default:
				writeErr(w, 400, "неизвестное действие подключения")
			}
			return
		case "server-entries":
			if !post {
				writeErr(w, 405, "нужен POST-запрос")
				return
			}
			var b struct {
				Data   string `json:"data"`
				Source string `json:"source"`
			}
			if json.NewDecoder(r.Body).Decode(&b) != nil {
				writeErr(w, 400, "ошибка в данных запроса")
				return
			}
			added, dup, bad, err := a.psi.importServerEntriesDetailed(b.Data, b.Source)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			// Audit A-04: the trust warning is shown on the FIRST import from a source.
			isNewSource := a.psi.noteSeedSource(b.Source)
			warn := ""
			if isNewSource {
				warn = seedTrustWarning
			}
			writeJSON(w, SeedImportResult{
				OK:           true,
				Imported:     added + dup,
				Added:        added,
				Duplicates:   dup,
				Invalid:      bad,
				Source:       b.Source,
				TrustWarning: warn,
				NewSource:    isNewSource,
				SeedHealth:   a.psi.SeedHealth(),
			})
			return
		case "start":
			a.ConnectVPN()
		case "stop":
			a.DisconnectVPN()
		case "restart":
			safeGo("App.api#2", a.psi.Restart)
		case "next":
			if left := a.psi.Next(); left > 0 {
				writeJSON(w, map[string]any{"ok": true, "wait": left})
				return
			}
		case "newnode":
			if left := a.psi.NewNode(); left > 0 {
				writeJSON(w, map[string]any{"ok": true, "wait": left})
				return
			}
		default:
			writeErr(w, 404, "неизвестное действие")
			return
		}
		writeJSON(w, ok)

	case strings.HasPrefix(p, "warp/"):
		switch tail("warp/") {
		case "on":
			restarted := a.cfg.setKey("warp.enabled", true) && a.restartIfRunning()
			if !a.saveOrFail(w, "App.api") {
				return
			}
			a.warp.Want()
			writeJSON(w, map[string]any{"ok": true, "restarted": restarted})
			return
		case "off":
			restarted := a.cfg.setKey("warp.enabled", false) && a.restartIfRunning()
			if !a.saveOrFail(w, "App.api") {
				return
			}
			writeJSON(w, map[string]any{"ok": true, "restarted": restarted})
			return
		case "reconnect":
			a.warp.Reconnect()
			writeJSON(w, ok)
			return
		default:
			writeErr(w, 404, "неизвестное действие WARP")
			return
		}

	case strings.HasPrefix(p, "countries/"):
		switch tail("countries/") {
		case "stop-all":
			a.countries.StopAll()
			logf("info", "Все фоновые процессы стран остановлены")
			writeJSON(w, ok)
		case "stop":
			cc := q.Get("country")
			a.countries.StopCountry(cc)
			writeJSON(w, ok)
		default:
			writeErr(w, 404, "неизвестное действие")
		}

	case strings.HasPrefix(p, "autostart/"):
		if err := setAutostart(tail("autostart/") == "on"); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "autostart": refreshAutostartCache(), "warning": autostartWarning()})
	case strings.HasPrefix(p, "mode/"):
		m := tail("mode/")
		if m != "psiphon" && m != "rules" && m != "auto" {
			writeErr(w, 400, "неизвестный режим")
			return
		}
		a.cfg.mu.Lock()
		a.cfg.Routing.Mode = m
		a.cfg.mu.Unlock()
		if !a.saveOrFail(w, "App.api") {
			return
		}
		a.onRulesChanged()
		logf("info", "Режим маршрутизации: %s", m)
		writeJSON(w, ok)
	case strings.HasPrefix(p, "sysproxy/"):
		if err := a.setSysProxy(tail("sysproxy/") == "on"); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, ok)
	case p == "tun/elevate" && post:
		if isElevated() {
			if err := a.setTun(true); err != nil {
				writeErr(w, 500, tunErrText(err))
				return
			}
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		if err := a.relaunchForTun(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "restarting": true})
		safeGo("App.api#3", func() { time.Sleep(700 * time.Millisecond); a.cancel() })
	case strings.HasPrefix(p, "tun/") && post:
		on := tail("tun/") == "on"
		if err := a.setTun(on); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": tunErrText(err), "need_admin": err == errNeedAdmin})
			return
		}
		writeJSON(w, ok)
	case p == "browser/info":
		writeJSON(w, map[string]any{"ok": true, "list": browserList()})
	case p == "browser/open" && post:
		var body struct {
			Browser string `json:"browser"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, "неверный запрос")
			return
		}
		if err := a.openBrowser(body.Browser); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	case p == "dpi/test" && post:
		var b struct {
			Sites []string `json:"sites"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if len(b.Sites) == 0 {
			b.Sites = a.dpiSites()
		}
		if err := a.dpiTestStart(b.Sites); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		writeJSON(w, a.dpiTestView())
	case p == "dpi/test":
		writeJSON(w, a.dpiTestView())
	case p == "dpi/test/stop" && post:
		dpiTestStop()
		writeJSON(w, map[string]any{"ok": true})
	case p == "dpi/mode" && post:
		var b struct {
			Mode string `json:"mode"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		if err := a.dpiSetMode(b.Mode); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "mode": a.dpiMode()})
	case p == "obfs/reset" && post:
		obfs.reset()
		writeJSON(w, map[string]any{"ok": true})
	case p == "quit":
		if a.stats != nil {
			a.stats.Flush()
		}
		writeJSON(w, ok)
		safeGo("App.api#4", func() { time.Sleep(300 * time.Millisecond); a.cancel() })
	case p == "reload":
		a.reloadConfig()
		writeJSON(w, ok)
	case p == "dns/clear":
		theDNS.clear()
		logf("info", "Кэш DNS очищен")
		writeJSON(w, ok)

	case p == "learned/forget":
		a.router.forget(q.Get("host"))
		writeJSON(w, ok)
	case p == "learned/clear":
		a.router.clearLearned()
		writeJSON(w, ok)

	case p == "diagnose":
		host := strings.TrimSpace(q.Get("host"))
		if host == "" {
			writeErr(w, 400, "укажите сайт")
			return
		}
		port, _ := strconv.Atoi(q.Get("port"))
		if port == 0 {
			port = 443
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		writeJSON(w, a.diagnose(ctx, cleanHost(host), port))
	case p == "route":
		host := cleanHost(q.Get("host"))
		port, _ := strconv.Atoi(q.Get("port"))
		if port == 0 {
			port = 443
		}
		app := strings.TrimSpace(q.Get("app"))
		proto := strings.TrimSpace(q.Get("proto"))
		exp := a.router.ExplainRoute(proto, host, "", port, app)
		writeJSON(w, map[string]any{
			"host":        host,
			"port":        port,
			"proto":       proto,
			"app":         app,
			"outbound":    exp.Outbound,
			"chain":       exp.Chain,
			"rule":        exp.Rule,
			"stage":       exp.Stage,
			"stage_title": exp.StageTitle,
			"badge":       exp.Badge,
			"learned":     exp.Learned,
			"pipeline":    routingPipelineStages,
		})

	case p == "pause" && post:
		var req struct {
			Minutes int `json:"minutes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if qm := q.Get("minutes"); qm != "" {
			req.Minutes, _ = strconv.Atoi(qm)
		}
		a.SetPause(req.Minutes)
		writeJSON(w, map[string]any{
			"ok":                  true,
			"paused":              a.IsPaused(),
			"pause_remaining_sec": a.PauseRemainingSec(),
		})

	case p == "repair" && post:
		// Быстрое действие «Починить соединение»: сбрасывает статистику ошибок DPI (auto-tune),
		// очищает кэш DNS/маршрутов и перезапускает активный каскад WARP + Psiphon.
		obfs.reset()
		theDNS.clear()
		a.router.InvalidateRules()
		a.cfg.mu.Lock()
		warpOn := a.cfg.Warp.Enabled
		a.cfg.mu.Unlock()
		if warpOn && a.warp != nil {
			safeGo("App.api#5", a.warp.Reconnect)
		}
		if a.psi != nil {
			safeGo("App.api#6", a.psi.Restart)
		}
		logf("info", "Запущено быстрое восстановление соединения (DPI auto-tune + переподключение)")
		writeJSON(w, ok)

	case p == "rules" && !post:
		listSt, countrySt := a.lists.Status(), a.countries.Status()
		a.cfg.mu.Lock()
		hidden := append([]string(nil), a.cfg.Lists.Hidden...)
		resp := map[string]any{
			"default":      a.cfg.Routing.Default,
			"auto_chain":   a.cfg.Routing.Chain,
			"bypass_lan":   a.cfg.Routing.BypassLAN,
			"block_quic":   a.cfg.Routing.BlockQUIC,
			"rules":        a.cfg.Routing.Rules,
			"outbounds":    ruleOutbounds(),
			"presets":      listPresets,
			"catalog":      listCatalog,
			"trusted":      allTrustedListHosts(),
			"hidden_lists": hidden,
			"lists":        listSt,
			"countries":    countrySt,
		}
		a.cfg.mu.Unlock()
		writeJSON(w, resp)
	case p == "rules":
		var b struct {
			Default   string   `json:"default"`
			Chain     []string `json:"auto_chain"`
			BypassLAN *bool    `json:"bypass_lan,omitempty"`
			BlockQUIC *bool    `json:"block_quic,omitempty"`
			Rules     []Rule   `json:"rules"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		for _, ru := range b.Rules {
			if err := checkRule(ru); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
		}
		a.cfg.mu.Lock()
		rollback := a.snapshotRuleSettingsLocked()
		if b.Default != "" {
			a.cfg.Routing.Default = b.Default
		}
		if len(b.Chain) > 0 {
			a.cfg.Routing.Chain = b.Chain
		}
		if b.BypassLAN != nil {
			a.cfg.Routing.BypassLAN = *b.BypassLAN
		}
		if b.BlockQUIC != nil {
			a.cfg.Routing.BlockQUIC = *b.BlockQUIC
		}
		if b.Rules == nil {
			b.Rules = []Rule{}
		}
		a.cfg.Routing.Rules = b.Rules
		if err := a.cfg.saveLocked(); err != nil {
			rollback()
			a.cfg.mu.Unlock()
			writeErr(w, 500, "не удалось сохранить правила: "+err.Error())
			return
		}
		a.cfg.mu.Unlock()
		a.onRulesChanged()
		a.lists.Refresh()
		writeJSON(w, ok)
	case p == "rules/toggle" && post:
		var b struct {
			Index    int   `json:"index"`
			Disabled *bool `json:"disabled,omitempty"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		a.cfg.mu.Lock()
		rollback := a.snapshotRuleSettingsLocked()
		if b.Index < 0 || b.Index >= len(a.cfg.Routing.Rules) {
			a.cfg.mu.Unlock()
			writeErr(w, 400, "правило не найдено")
			return
		}
		if b.Disabled != nil {
			a.cfg.Routing.Rules[b.Index].Disabled = *b.Disabled
		} else {
			a.cfg.Routing.Rules[b.Index].Disabled = !a.cfg.Routing.Rules[b.Index].Disabled
		}
		disabled := a.cfg.Routing.Rules[b.Index].Disabled
		if err := a.cfg.saveLocked(); err != nil {
			rollback()
			a.cfg.mu.Unlock()
			writeErr(w, 500, "не удалось сохранить правила: "+err.Error())
			return
		}
		a.cfg.mu.Unlock()
		a.onRulesChanged()
		writeJSON(w, map[string]any{"ok": true, "disabled": disabled})
	case p == "rules/delete" && post:
		var b struct {
			Index int `json:"index"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		a.cfg.mu.Lock()
		rollback := a.snapshotRuleSettingsLocked()
		if b.Index < 0 || b.Index >= len(a.cfg.Routing.Rules) {
			a.cfg.mu.Unlock()
			writeErr(w, 400, "правило не найдено")
			return
		}
		name := a.cfg.Routing.Rules[b.Index].Name
		a.cfg.Routing.Rules = append(a.cfg.Routing.Rules[:b.Index], a.cfg.Routing.Rules[b.Index+1:]...)
		if err := a.cfg.saveLocked(); err != nil {
			rollback()
			a.cfg.mu.Unlock()
			writeErr(w, 500, "не удалось сохранить правила: "+err.Error())
			return
		}
		a.cfg.mu.Unlock()
		a.onRulesChanged()
		logf("info", "Правило удалено: %s", name)
		writeJSON(w, ok)
	case p == "rules/move" && post:
		var b struct {
			Index int `json:"index"`
			Dir   int `json:"dir"` // -1 = up, +1 = down
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		a.cfg.mu.Lock()
		rollback := a.snapshotRuleSettingsLocked()
		n := len(a.cfg.Routing.Rules)
		target := b.Index + b.Dir
		if b.Index >= 0 && b.Index < n && target >= 0 && target < n {
			a.cfg.Routing.Rules[b.Index], a.cfg.Routing.Rules[target] = a.cfg.Routing.Rules[target], a.cfg.Routing.Rules[b.Index]
		}
		if err := a.cfg.saveLocked(); err != nil {
			rollback()
			a.cfg.mu.Unlock()
			writeErr(w, 500, "не удалось сохранить правила: "+err.Error())
			return
		}
		a.cfg.mu.Unlock()
		a.onRulesChanged()
		writeJSON(w, ok)
	case p == "rules/preset" && post:
		var b struct {
			Preset   string `json:"preset"`
			Outbound string `json:"outbound"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		if err := a.addQuickRulePreset(b.Preset, b.Outbound); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, ok)
	case p == "rules/add":
		a.rulesAddAPI(w, r)
	case p == "rules/batch" && post:
		a.rulesBatchAPI(w, r)
	case p == "rules/export":
		a.rulesExportAPI(w, r)
	case p == "conns/recent":
		writeJSON(w, map[string]any{"ok": true, "recent": a.stats.recentList()})
	case (p == "conns/quick-rule" || p == "rules/from-conn") && post:
		a.quickConnRuleAPI(w, r)

	case p == "share":
		writeJSON(w, a.shareInfo())
	case strings.HasPrefix(p, "share/"):
		if err := a.setShare(tail("share/") == "on"); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, a.shareInfo())
	default:
		writeErr(w, 404, "неизвестный запрос")
	}
}

// listsAPI handles all /api/lists* endpoints:
//   - GET /api/lists
//   - POST /api/lists (add by URL or text, or preview)
//   - POST /api/lists/preview
//   - POST /api/lists/import
//   - POST /api/lists/restore-builtins (or /api/lists/unhide)
//   - POST /api/lists/refresh
//   - GET/POST /api/lists/test
//   - GET/POST /api/lists/local, POST /api/lists/local/delete
//   - PUT /api/lists/{id}
//   - DELETE /api/lists/{id}
//   - POST /api/lists/{id}/refresh
//   - GET /api/lists/{id}/content
func (a *App) listsAPI(w http.ResponseWriter, r *http.Request, p string) {
	q := r.URL.Query()
	switch {
	case p == "lists" && r.Method == http.MethodGet:
		a.cfg.mu.Lock()
		hidden := append([]string(nil), a.cfg.Lists.Hidden...)
		custom := append([]CustomList(nil), a.cfg.Lists.Custom...)
		a.cfg.mu.Unlock()
		writeJSON(w, map[string]any{
			"ok":      true,
			"lists":   a.lists.Status(),
			"custom":  custom,
			"hidden":  hidden,
			"catalog": listCatalog,
			"presets": listPresets,
			"trusted": allTrustedListHosts(),
		})

	case (p == "lists" || p == "lists/import") && r.Method == http.MethodPost:
		var b struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			Title         string `json:"title"`
			Type          string `json:"type"`
			URL           string `json:"url"`
			Content       string `json:"content"`
			Category      string `json:"category"`
			Enabled       *bool  `json:"enabled,omitempty"`
			IntervalHours int    `json:"interval_hours,omitempty"`
			ConfirmTrust  bool   `json:"confirm_trust,omitempty"`
			PreviewOnly   bool   `json:"preview,omitempty"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		if b.PreviewOnly || q.Get("preview") == "1" {
			writeJSON(w, a.lists.PreviewList(b.Content))
			return
		}
		id := b.ID
		if id == "" {
			id = b.Name
		}
		title := b.Title
		if title == "" {
			title = b.Name
		}
		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
		defer cancel()
		res, err := a.lists.UpsertCustomList(ctx, id, title, b.Type, b.URL, b.Content, b.Category, b.Enabled, b.IntervalHours, b.ConfirmTrust)
		if err != nil {
			var untrusted *ErrUntrustedListHost
			if errors.As(err, &untrusted) && res != nil {
				writeJSONCode(w, http.StatusConflict, res)
				return
			}
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, res)

	case p == "lists/preview" && r.Method == http.MethodPost:
		var b struct {
			Content string `json:"content"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		writeJSON(w, a.lists.PreviewList(b.Content))

	case (p == "lists/restore-builtins" || p == "lists/unhide") && r.Method == http.MethodPost:
		writeJSON(w, a.lists.RestoreBuiltinLists())

	case p == "lists/refresh":
		a.lists.Refresh()
		logf("info", "Запущено обновление списков адресов")
		writeJSON(w, map[string]any{"ok": true})

	case p == "lists/test":
		target := q.Get("host")
		if r.Method == http.MethodPost && target == "" {
			var b struct {
				Host string `json:"host"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			target = b.Host
		}
		target = cleanHost(target)
		if target == "" {
			writeErr(w, 400, "укажите домен или IP для проверки по спискам")
			return
		}
		writeJSON(w, a.lists.TestHost(target))

	case p == "lists/local" && r.Method == http.MethodGet:
		txt, err := a.lists.GetListContent(q.Get("name"))
		if err != nil {
			writeErr(w, 404, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "name": q.Get("name"), "content": txt})

	case p == "lists/local" && r.Method == http.MethodPost:
		var b struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		res, err := a.lists.SaveLocalList(b.Name, b.Content)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, res)

	case p == "lists/local/delete" && r.Method == http.MethodPost:
		var b struct {
			Name            string `json:"name"`
			RemoveFromRules bool   `json:"remove_from_rules,omitempty"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "ошибка в данных запроса")
			return
		}
		res, code, err := a.lists.DeleteList(b.Name, b.RemoveFromRules)
		if err != nil {
			if res != nil {
				writeJSONCode(w, code, res)
				return
			}
			writeErr(w, code, err.Error())
			return
		}
		writeJSON(w, res)

	case strings.HasPrefix(p, "lists/"):
		rest := strings.TrimPrefix(p, "lists/")
		if rest == "" {
			writeErr(w, 404, "не указан идентификатор списка")
			return
		}
		if idPart, ok := strings.CutSuffix(rest, "/refresh"); ok && r.Method == http.MethodPost {
			id, _ := url.PathUnescape(idPart)
			ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
			defer cancel()
			res, err := a.lists.RefreshOne(ctx, id)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			writeJSON(w, res)
			return
		}
		if idPart, ok := strings.CutSuffix(rest, "/content"); ok && r.Method == http.MethodGet {
			id, _ := url.PathUnescape(idPart)
			txt, err := a.lists.GetListContent(id)
			if err != nil {
				writeErr(w, 404, err.Error())
				return
			}
			writeJSON(w, map[string]any{"ok": true, "id": id, "content": txt})
			return
		}
		if idPart, ok := strings.CutSuffix(rest, "/delete"); ok && r.Method == http.MethodPost {
			id, _ := url.PathUnescape(idPart)
			var b struct {
				RemoveFromRules bool `json:"remove_from_rules,omitempty"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			force := b.RemoveFromRules || q.Get("remove_from_rules") == "1" || q.Get("force") == "1"
			res, code, err := a.lists.DeleteList(id, force)
			if err != nil {
				if res != nil {
					writeJSONCode(w, code, res)
					return
				}
				writeErr(w, code, err.Error())
				return
			}
			writeJSON(w, res)
			return
		}

		id, _ := url.PathUnescape(rest)
		switch r.Method {
		case http.MethodDelete:
			var b struct {
				RemoveFromRules bool `json:"remove_from_rules,omitempty"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			force := b.RemoveFromRules || q.Get("remove_from_rules") == "1" || q.Get("force") == "1"
			res, code, err := a.lists.DeleteList(id, force)
			if err != nil {
				if res != nil {
					writeJSONCode(w, code, res)
					return
				}
				writeErr(w, code, err.Error())
				return
			}
			writeJSON(w, res)

		case http.MethodPut, http.MethodPost:
			var b struct {
				Title         string `json:"title"`
				Name          string `json:"name"`
				Type          string `json:"type"`
				URL           string `json:"url"`
				Content       string `json:"content"`
				Category      string `json:"category"`
				Enabled       *bool  `json:"enabled,omitempty"`
				Hidden        *bool  `json:"hidden,omitempty"`
				IntervalHours int    `json:"interval_hours,omitempty"`
				ConfirmTrust  bool   `json:"confirm_trust,omitempty"`
			}
			if json.NewDecoder(r.Body).Decode(&b) != nil {
				writeErr(w, 400, "ошибка в данных запроса")
				return
			}
			// Check if toggling hidden state on a built-in list
			for _, meta := range listCatalog {
				if strings.EqualFold(meta.ID, id) {
					hide := false
					if b.Hidden != nil {
						hide = *b.Hidden
					} else if b.Enabled != nil {
						hide = !*b.Enabled
					}
					a.cfg.mu.Lock()
					idx := slices.IndexFunc(a.cfg.Lists.Hidden, func(x string) bool { return strings.EqualFold(x, meta.ID) })
					if hide && idx < 0 {
						a.cfg.Lists.Hidden = append(a.cfg.Lists.Hidden, meta.ID)
					} else if !hide && idx >= 0 {
						a.cfg.Lists.Hidden = append(a.cfg.Lists.Hidden[:idx], a.cfg.Lists.Hidden[idx+1:]...)
					}
					syncListRegistryLocked(a.cfg)
					a.cfg.mu.Unlock()
					if !a.saveOrFail(w, "App.listsAPI") {
						return
					}
					writeJSON(w, map[string]any{"ok": true, "id": meta.ID, "hidden": hide, "enabled": !hide})
					return
				}
			}
			title := b.Title
			if title == "" {
				title = b.Name
			}
			// Inherit existing fields when omitted on PUT
			a.cfg.mu.Lock()
			for _, cl := range a.cfg.Lists.Custom {
				if strings.EqualFold(cl.ID, id) {
					if title == "" {
						title = cl.Title
					}
					if b.Type == "" {
						b.Type = cl.Type
					}
					if b.URL == "" {
						b.URL = cl.URL
					}
					if b.Category == "" {
						b.Category = cl.Category
					}
					if b.IntervalHours <= 0 {
						b.IntervalHours = cl.IntervalHours
					}
					if b.Enabled == nil {
						en := cl.Enabled
						b.Enabled = &en
					}
					break
				}
			}
			a.cfg.mu.Unlock()
			ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
			defer cancel()
			res, err := a.lists.UpsertCustomList(ctx, id, title, b.Type, b.URL, b.Content, b.Category, b.Enabled, b.IntervalHours, b.ConfirmTrust)
			if err != nil {
				var untrusted *ErrUntrustedListHost
				if errors.As(err, &untrusted) && res != nil {
					writeJSONCode(w, http.StatusConflict, res)
					return
				}
				writeErr(w, 400, err.Error())
				return
			}
			writeJSON(w, res)

		default:
			writeErr(w, 405, "метод не поддерживается")
		}

	default:
		writeErr(w, 404, "неизвестный запрос к спискам")
	}
}

// rulesAddAPI handles POST /api/rules/add with Smart Token Classification
// and optional in-place rule editing (when index >= 0).
func (a *App) rulesAddAPI(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var body struct {
		Index        *int     `json:"index,omitempty"`
		Tokens       string   `json:"tokens,omitempty"`
		Hosts        []string `json:"hosts"`
		Domains      []string `json:"domains,omitempty"`
		Keywords     []string `json:"keywords,omitempty"`
		CIDR         []string `json:"cidr,omitempty"`
		Lists        []string `json:"lists,omitempty"`
		Outbound     string   `json:"outbound"`
		Name         string   `json:"name"`
		Apps         []string `json:"apps,omitempty"`
		Proto        string   `json:"proto,omitempty"`
		Ports        []int    `json:"ports,omitempty"`
		PortRanges   []string `json:"port_ranges,omitempty"`
		Always       *bool    `json:"always,omitempty"`
		Disabled     bool     `json:"disabled,omitempty"`
		Smart        bool     `json:"smart,omitempty"`
		ExactDomains []string `json:"exact_domains,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ob := q.Get("outbound")
	if ob == "" {
		ob = body.Outbound
	}
	if ob == "" {
		ob = obPsiphon
	}

	var hosts []string
	var cidr []string
	var lists []string
	var keywords []string
	var apps []string
	var ports []int
	var portRanges []string
	proto := strings.ToLower(strings.TrimSpace(body.Proto))

	addUnique := func(dst *[]string, val string) {
		if val != "" && !slices.Contains(*dst, val) {
			*dst = append(*dst, val)
		}
	}

	if h := cleanHost(q.Get("host")); h != "" {
		addUnique(&hosts, h)
	}

	rawTokens := append([]string(nil), body.Hosts...)
	rawTokens = append(rawTokens, body.Domains...)
	for _, domain := range body.ExactDomains {
		addUnique(&hosts, strings.TrimSpace(domain))
	}
	if strings.TrimSpace(body.Tokens) != "" {
		rawTokens = append(rawTokens, body.Tokens)
	}
	for _, raw := range rawTokens {
		for _, tok := range splitRuleInput(raw) {
			classifySmartRuleToken(tok, &hosts, &cidr, &lists, &keywords, &apps, &ports, &portRanges, &proto)
		}
	}
	for _, kw := range body.Keywords {
		if kw = strings.TrimSpace(kw); kw != "" {
			addUnique(&keywords, kw)
		}
	}
	for _, c := range body.CIDR {
		if c = strings.TrimSpace(c); c != "" {
			addUnique(&cidr, c)
		}
	}
	for _, l := range body.Lists {
		if l = strings.TrimSpace(l); l != "" {
			addUnique(&lists, l)
		}
	}
	for _, ap := range body.Apps {
		if ap = strings.TrimSpace(ap); ap != "" {
			addUnique(&apps, ap)
		}
	}
	for _, p := range body.Ports {
		if p > 0 && p < 65536 && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	for _, pr := range body.PortRanges {
		if pr = strings.TrimSpace(pr); pr != "" {
			addUnique(&portRanges, pr)
		}
	}

	if len(hosts) == 0 && len(cidr) == 0 && len(lists) == 0 && len(keywords) == 0 && len(apps) == 0 && len(ports) == 0 && len(portRanges) == 0 {
		writeErr(w, 400, "укажите сайт, список, подсеть или программу")
		return
	}

	name := strings.TrimSpace(body.Name)
	if name == "" {
		switch {
		case len(lists) > 0 && len(hosts) == 0:
			name = "Список: " + strings.Join(lists, ", ")
		case len(hosts) > 0:
			name = strings.Join(hosts, ", ")
			if len(name) > 48 {
				name = hosts[0] + " (+" + strconv.Itoa(len(hosts)-1) + ")"
			}
		case len(cidr) > 0:
			name = "Подсеть: " + strings.Join(cidr, ", ")
		case len(apps) > 0:
			name = strings.Join(apps, ", ")
		default:
			name = "Правило"
		}
	}

	alwaysVal := true
	if body.Always != nil {
		alwaysVal = *body.Always
	}
	newRule := Rule{
		Name: name, Outbound: ob, Domains: hosts, Keywords: keywords,
		CIDR: cidr, Lists: lists, Apps: apps, Proto: proto,
		Ports: ports, PortRanges: portRanges, Always: alwaysVal, Disabled: body.Disabled,
	}
	if err := checkRule(newRule); err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	a.cfg.mu.Lock()
	rollback := a.snapshotRuleSettingsLocked()
	if body.Index != nil && *body.Index >= 0 && *body.Index < len(a.cfg.Routing.Rules) {
		a.cfg.Routing.Rules[*body.Index] = newRule
	} else {
		updated := false
		if len(hosts) == 1 && len(cidr) == 0 && len(lists) == 0 && len(keywords) == 0 && len(apps) == 0 && len(ports) == 0 && len(portRanges) == 0 && proto == "" {
			for i := range a.cfg.Routing.Rules {
				ru := &a.cfg.Routing.Rules[i]
				if len(ru.Domains) == 1 && cleanHostKey(ru.Domains[0]) == hosts[0] && len(ru.Apps) == 0 && len(ru.Ports) == 0 && len(ru.PortRanges) == 0 && len(ru.Lists) == 0 && len(ru.CIDR) == 0 && ru.Proto == "" {
					ru.Outbound = ob
					ru.Disabled = false
					updated = true
					break
				}
			}
		}
		if !updated {
			a.cfg.Routing.Rules = append(a.cfg.Routing.Rules, newRule)
		}
	}
	if err := a.cfg.saveLocked(); err != nil {
		rollback()
		a.cfg.mu.Unlock()
		writeErr(w, 500, "не удалось сохранить правила: "+err.Error())
		return
	}
	a.cfg.mu.Unlock()
	if len(lists) > 0 {
		a.lists.Refresh()
	}
	for _, h := range hosts {
		a.router.forget(strings.TrimPrefix(h, "!"))
	}
	a.onRulesChanged()
	logf("info", "Правило: %s → %s", name, ob)
	writeJSON(w, map[string]any{"ok": true, "rule": newRule})
}

// classifySmartRuleToken auto-detects whether a user-entered token is a list
// preset, custom list, CIDR subnet, port/range, executable app, keyword, or domain.
func classifySmartRuleToken(tok string, hosts, cidr, lists, keywords, apps *[]string, ports *[]int, portRanges *[]string, proto *string) {
	addUnique := func(dst *[]string, val string) {
		if val != "" && !slices.Contains(*dst, val) {
			*dst = append(*dst, val)
		}
	}
	low := strings.ToLower(strings.TrimSpace(tok))
	switch low {
	case "tcp", "proto:tcp":
		*proto = "tcp"
		return
	case "udp", "proto:udp":
		*proto = "udp"
		return
	}
	if rest, ok := strings.CutPrefix(low, "tcp:"); ok {
		*proto = "tcp"
		tok, low = rest, rest
	} else if rest, ok := strings.CutPrefix(low, "udp:"); ok {
		*proto = "udp"
		tok, low = rest, rest
	}
	if rest, ok := strings.CutPrefix(low, "list:"); ok {
		addUnique(lists, strings.TrimSpace(rest))
		return
	}
	if rest, ok := strings.CutPrefix(low, "!list:"); ok {
		addUnique(lists, "!"+strings.TrimSpace(rest))
		return
	}
	if rest, ok := strings.CutPrefix(low, "kw:"); ok {
		addUnique(keywords, strings.TrimSpace(rest))
		return
	}
	if rest, ok := strings.CutPrefix(low, "keyword:"); ok {
		addUnique(keywords, strings.TrimSpace(rest))
		return
	}
	if rest, ok := strings.CutPrefix(low, "port:"); ok {
		rest = strings.TrimSpace(rest)
		if p, err := strconv.Atoi(rest); err == nil && p >= 1 && p <= 65535 {
			if !slices.Contains(*ports, p) {
				*ports = append(*ports, p)
			}
		} else if _, _, ok := parsePortRange(rest); ok {
			addUnique(portRanges, rest)
		}
		return
	}
	if rest, ok := strings.CutPrefix(low, "cidr:"); ok {
		addUnique(cidr, strings.TrimSpace(rest))
		return
	}
	if rest, ok := strings.CutPrefix(low, "ip:"); ok {
		addUnique(cidr, strings.TrimSpace(rest))
		return
	}
	if rest, ok := strings.CutPrefix(tok, "domain:"); ok {
		addUnique(hosts, strings.TrimSpace(rest))
		return
	}
	if rest, ok := strings.CutPrefix(low, "country:"); ok {
		cc := strings.TrimSpace(rest)
		if cc == "ru" {
			addUnique(lists, "ru-gov-banks")
		}
		addUnique(hosts, "country:"+cc)
		return
	}
	if rest, ok := strings.CutPrefix(low, "geoip:"); ok {
		cc := strings.TrimSpace(rest)
		if cc == "ru" {
			addUnique(lists, "ru-gov-banks")
		}
		addUnique(hosts, "country:"+cc)
		return
	}
	if strings.HasPrefix(low, "regexp:") {
		addUnique(hosts, strings.TrimSpace(tok))
		return
	}
	if rest, ok := strings.CutPrefix(tok, "app:"); ok {
		addUnique(apps, strings.TrimSpace(rest))
		return
	}
	neg := ""
	clean := tok
	if strings.HasPrefix(clean, "!") {
		neg = "!"
		clean = strings.TrimSpace(clean[1:])
	}
	cleanLow := strings.ToLower(clean)
	_, isPreset := listPresets[cleanLow]
	listRegMu.RLock()
	_, isCustom := customListURLMap[cleanLow]
	listRegMu.RUnlock()
	if isPreset || isCustom || strings.HasPrefix(cleanLow, "local:") {
		addUnique(lists, neg+cleanLow)
		return
	}
	if strings.HasSuffix(cleanLow, ".exe") {
		addUnique(apps, neg+clean)
		return
	}
	if _, err := netip.ParsePrefix(clean); err == nil {
		addUnique(cidr, neg+clean)
		return
	}
	if ip, err := netip.ParseAddr(clean); err == nil {
		ip = ip.Unmap()
		addUnique(cidr, neg+netip.PrefixFrom(ip, ip.BitLen()).String())
		return
	}
	if neg == "" {
		if p, err := strconv.Atoi(clean); err == nil && p >= 1 && p <= 65535 {
			if !slices.Contains(*ports, p) {
				*ports = append(*ports, p)
			}
			return
		}
		if _, _, ok := parsePortRange(clean); ok {
			addUnique(portRanges, clean)
			return
		}
	}
	if strings.HasPrefix(cleanLow, "exact:") || strings.HasPrefix(cleanLow, "full:") {
		addUnique(hosts, neg+cleanLow)
		return
	}
	if h := cleanHost(clean); h != "" {
		addUnique(hosts, neg+h)
	}
}

// addQuickRulePreset adds or updates a curated 1-click service routing rule.
func (a *App) addQuickRulePreset(preset, ob string) error {
	if ob == "" {
		ob = obPsiphon
	}
	var newRules []Rule
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "youtube":
		newRules = []Rule{
			{
				Name: "YouTube: блок QUIC (UDP 443)", Outbound: obBlock, Proto: "udp", Ports: []int{443},
				Lists: []string{"youtube"}, Domains: []string{"youtube.com", "googlevideo.com", "ytimg.com"},
			},
			{
				Name: "YouTube и Google Video", Outbound: ob,
				Lists:   []string{"youtube"},
				Domains: []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com"},
			},
		}
	case "discord", "discord-voice":
		newRules = []Rule{
			{
				Name: "Discord (чат, голос и медиа)", Outbound: ob,
				Lists:   []string{"discord"},
				Domains: []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"},
				Apps:    []string{"Discord.exe"},
				Always:  true,
			},
		}
	case "telegram":
		newRules = []Rule{
			{
				Name: "Telegram (домены и подсети)", Outbound: ob,
				Lists:   []string{"telegram-ip"},
				Domains: telegramDomains,
				Apps:    []string{"Telegram.exe"},
				Always:  true,
			},
		}
	case "ai", "ai-services":
		newRules = []Rule{
			{
				Name: "ИИ-сервисы (ChatGPT, Claude, Gemini)", Outbound: ob,
				Lists:   []string{"ai-services"},
				Domains: []string{"openai.com", "chatgpt.com", "claude.ai", "anthropic.com", "gemini.google.com", "perplexity.ai", "cursor.com"},
			},
		}
	case "meta", "instagram":
		newRules = []Rule{
			{
				Name: "Instagram, Facebook и Meta", Outbound: ob,
				Lists:   []string{"meta-instagram", "twitter-x"},
				Domains: []string{"instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "threads.net", "x.com", "twitter.com", "t.co"},
			},
		}
	case "ru-direct":
		newRules = []Rule{
			{
				Name: "РФ: Госуслуги, банки и .RU напрямую", Outbound: obDirect,
				Lists:   []string{"ru-gov-banks"},
				Domains: []string{"ru", "xn--p1ai", "su", "vk.com", "yandex.net", "yastatic.net", "ozon.ru", "wildberries.ru"},
				Always:  true,
			},
		}
	case "steam", "gaming":
		newRules = []Rule{
			{
				Name: "Steam, Epic Games и лаунчеры", Outbound: ob,
				Lists:   []string{"gaming-steam-epic"},
				Domains: []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "epicgames.com", "battle.net"},
			},
		}
	case "blocked", "ru-blocked":
		newRules = []Rule{
			{
				Name: "Заблокированные домены и подсети РФ", Outbound: ob,
				Lists: []string{"ru-blocked", "antifilter-community", "antifilter-ip"},
			},
		}
	case "ads-block":
		newRules = []Rule{
			{
				Name: "Блокировка рекламы и трекеров", Outbound: obBlock,
				Lists:   []string{"ads-trackers"},
				Domains: []string{"doubleclick.net", "googlesyndication.com", "googleadservices.com", "adnxs.com"},
				Always:  true,
			},
		}
	default:
		return errors.New("неизвестный шаблон правила: " + preset)
	}

	a.cfg.mu.Lock()
	rollback := a.snapshotRuleSettingsLocked()
	rules := a.cfg.Routing.Rules
	for _, nr := range newRules {
		idx := slices.IndexFunc(rules, func(x Rule) bool { return strings.EqualFold(x.Name, nr.Name) })
		if idx >= 0 {
			rules[idx] = nr
		} else {
			rules = append([]Rule{nr}, rules...)
		}
	}
	a.cfg.Routing.Rules = rules
	if err := a.cfg.saveLocked(); err != nil {
		rollback()
		a.cfg.mu.Unlock()
		return err
	}
	a.cfg.mu.Unlock()
	a.onRulesChanged()
	a.lists.Refresh()
	logf("info", "Добавлен шаблон правил «%s» → %s", preset, ob)
	return nil
}

// processesAPI handles POST /api/processes for controlling any core process or
// service from the Main Menu / Process Control Center.
func (a *App) processesAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Process string `json:"process"`
		Service string `json:"service"`
		Action  string `json:"action"`
		Value   string `json:"value,omitempty"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, 400, "ошибка в данных запроса")
		return
	}
	proc := req.Process
	if proc == "" {
		proc = req.Service
	}
	switch proc {
	case "psiphon":
		switch req.Action {
		case "start":
			a.ConnectVPN()
		case "stop":
			a.DisconnectVPN()
		case "restart":
			safeGo("App.processesAPI", a.psi.Restart)
		case "newnode":
			if left := a.psi.NewNode(); left > 0 {
				writeJSON(w, map[string]any{"ok": true, "wait": left})
				return
			}
		case "next":
			if left := a.psi.Next(); left > 0 {
				writeJSON(w, map[string]any{"ok": true, "wait": left})
				return
			}
		default:
			writeErr(w, 400, "неизвестное действие Psiphon")
			return
		}
	case "warp":
		switch req.Action {
		case "enable", "on":
			restarted := a.cfg.setKey("warp.enabled", true) && a.restartIfRunning()
			if !a.saveOrFail(w, "App.processesAPI") {
				return
			}
			a.warp.Want()
			writeJSON(w, map[string]any{"ok": true, "restarted": restarted})
			return
		case "disable", "off":
			restarted := a.cfg.setKey("warp.enabled", false) && a.restartIfRunning()
			if !a.saveOrFail(w, "App.processesAPI") {
				return
			}
			writeJSON(w, map[string]any{"ok": true, "restarted": restarted})
			return
		case "reconnect":
			a.warp.Reconnect()
		default:
			writeErr(w, 400, "неизвестное действие WARP")
			return
		}
	case "tun":
		switch req.Action {
		case "enable", "on":
			if err := a.setTun(true); err != nil {
				writeJSON(w, map[string]any{"ok": false, "error": tunErrText(err), "need_admin": err == errNeedAdmin})
				return
			}
		case "disable", "off":
			_ = a.setTun(false)
		default:
			writeErr(w, 400, "неизвестное действие TUN")
			return
		}
	case "sysproxy":
		on := req.Action == "enable" || req.Action == "on"
		if err := a.setSysProxy(on); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	case "share":
		on := req.Action == "enable" || req.Action == "on"
		if err := a.setShare(on); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	case "dns":
		switch req.Action {
		case "enable", "on":
			a.cfg.setKey("dns.enabled", true)
			if !a.saveOrFail(w, "App.processesAPI") {
				return
			}
		case "disable", "off":
			a.cfg.setKey("dns.enabled", false)
			if !a.saveOrFail(w, "App.processesAPI") {
				return
			}
		case "clear":
			theDNS.clear()
			logf("info", "Кэш DNS очищен")
		default:
			writeErr(w, 400, "неизвестное действие DNS")
			return
		}
	case "countries":
		switch req.Action {
		case "stop_all":
			a.countries.StopAll()
			logf("info", "Все фоновые процессы стран остановлены")
		case "stop":
			a.countries.StopCountry(req.Value)
		default:
			writeErr(w, 400, "неизвестное действие стран")
			return
		}
	case "lists":
		if req.Action == "refresh" {
			a.lists.Refresh()
			logf("info", "Запущено обновление списков адресов")
		}
	case "probe":
		switch req.Action {
		case "start":
			if err := a.startProbe(); err != nil {
				writeErr(w, 409, err.Error())
				return
			}
		case "stop":
			a.stopProbe()
		default:
			writeErr(w, 400, "неизвестное действие автоподбора")
			return
		}
	case "dpitest":
		switch req.Action {
		case "start":
			if err := a.dpiTestStart(a.dpiSites()); err != nil {
				writeErr(w, 409, err.Error())
				return
			}
		case "stop":
			dpiTestStop()
		default:
			writeErr(w, 400, "неизвестное действие теста DPI")
			return
		}
	case "routing":
		switch req.Action {
		case "bypass_lan":
			a.cfg.setKey("routing.bypass_lan", req.Value == "true" || req.Value == "1" || req.Value == "on")
			if !a.saveOrFail(w, "App.processesAPI") {
				return
			}
		case "block_quic":
			a.cfg.setKey("routing.block_quic", req.Value == "true" || req.Value == "1" || req.Value == "on")
			if !a.saveOrFail(w, "App.processesAPI") {
				return
			}
		case "clear_learned":
			a.router.clearLearned()
		default:
			writeErr(w, 400, "неизвестное действие маршрутизации")
			return
		}
	default:
		writeErr(w, 400, "неизвестный процесс: "+proc)
		return
	}
	writeJSON(w, a.processesView())
}

// cleanHost accepts "https://site.com/path", "site.com:443" or "site.com".
func cleanHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.Trim(s, "[]")
}

// ruleOutbounds fills the route dropdowns: the usual outbounds plus
// "psiphon:CC" for common exit countries and any country already used in the rules.
func ruleOutbounds() []string {
	out := []string{obPsiphon, obDirect, obDesync, obWarp, obCleanIP, obProxy, obBlock, obAuto}
	for _, cc := range countryChoices {
		out = append(out, obPsiphon+":"+cc)
	}
	return out
}

// rulesBatchAPI imports multiple lines of rules/tokens from clipboard or text file.
func (a *App) rulesBatchAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text     string `json:"text"`
		Outbound string `json:"outbound"`
		Name     string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		writeErr(w, 400, "ошибка в данных запроса")
		return
	}
	ob := strings.TrimSpace(b.Outbound)
	if ob == "" || strings.EqualFold(ob, "tunnel") {
		ob = obPsiphon
	}
	if !validOutbound(ob) {
		writeErr(w, 400, "недопустимый маршрут: "+ob)
		return
	}
	var hosts, cidr, lists, keywords, apps, portRanges []string
	var ports []int
	proto := ""
	for _, line := range strings.FieldsFunc(b.Text, func(c rune) bool { return c == '\n' || c == '\r' || c == ',' || c == ';' }) {
		tok := sanitizeRuleToken(line)
		if tok == "" {
			continue
		}
		classifySmartRuleToken(tok, &hosts, &cidr, &lists, &keywords, &apps, &ports, &portRanges, &proto)
	}
	totalItems := len(hosts) + len(cidr) + len(lists) + len(keywords) + len(apps) + len(ports) + len(portRanges)
	if totalItems == 0 {
		writeErr(w, 400, "не найдено ни одного корректного домена, IP, списка, порта или процесса")
		return
	}
	name := strings.TrimSpace(b.Name)
	if name == "" {
		name = "Пакетный импорт (" + strconv.Itoa(totalItems) + ")"
	}
	nr := Rule{
		Name: name, Outbound: ob, Domains: hosts, CIDR: cidr,
		Lists: lists, Keywords: keywords, Apps: apps, Ports: ports, PortRanges: portRanges, Proto: proto, Always: true,
	}
	if err := checkRule(nr); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	a.cfg.mu.Lock()
	rollback := a.snapshotRuleSettingsLocked()
	a.cfg.Routing.Rules = append([]Rule{nr}, a.cfg.Routing.Rules...)
	if err := a.cfg.saveLocked(); err != nil {
		rollback()
		a.cfg.mu.Unlock()
		writeErr(w, 500, "не удалось сохранить правила: "+err.Error())
		return
	}
	a.cfg.mu.Unlock()
	for _, h := range hosts {
		a.router.forget(strings.TrimPrefix(h, "!"))
	}
	a.onRulesChanged()
	if len(lists) > 0 {
		a.lists.Refresh()
	}
	writeJSON(w, map[string]any{"ok": true, "rule": nr, "count": totalItems})
}

// rulesExportAPI exports all active rules as human-readable text lines and JSON.
func (a *App) rulesExportAPI(w http.ResponseWriter, r *http.Request) {
	a.cfg.mu.Lock()
	rules := append([]Rule(nil), a.cfg.Routing.Rules...)
	a.cfg.mu.Unlock()
	var lines []string
	for _, ru := range rules {
		lines = append(lines, "# "+ru.Name+" -> "+ru.Outbound)
		for _, l := range ru.Lists {
			lines = append(lines, "list:"+l)
		}
		lines = append(lines, ru.Domains...)
		lines = append(lines, ru.CIDR...)
		for _, ap := range ru.Apps {
			lines = append(lines, "app:"+ap)
		}
	}
	writeJSON(w, map[string]any{"ok": true, "text": strings.Join(lines, "\n"), "rules": rules})
}

// quickConnRuleAPI creates a 1-click routing rule directly from a live or recent connection row.
func (a *App) quickConnRuleAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Host     string `json:"host"`
		App      string `json:"app"`
		Outbound string `json:"outbound"`
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		writeErr(w, 400, "ошибка в данных запроса")
		return
	}
	ob := strings.TrimSpace(b.Outbound)
	if ob == "" || strings.EqualFold(ob, "tunnel") {
		ob = obPsiphon
	}
	if !validOutbound(ob) {
		writeErr(w, 400, "недопустимый маршрут: "+ob)
		return
	}
	if b.App != "" && b.Host == "" {
		if err := a.SetAppRoute(b.App, ob); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	h := sanitizeRuleToken(b.Host)
	if h == "" {
		writeErr(w, 400, "укажите хост или приложение")
		return
	}
	var hosts, cidr, lists, keywords, apps, portRanges []string
	var ports []int
	proto := ""
	classifySmartRuleToken(h, &hosts, &cidr, &lists, &keywords, &apps, &ports, &portRanges, &proto)
	nr := Rule{
		Name:       h + " → " + ob,
		Outbound:   ob,
		Domains:    hosts,
		CIDR:       cidr,
		Lists:      lists,
		Keywords:   keywords,
		Apps:       apps,
		Ports:      ports,
		PortRanges: portRanges,
		Proto:      proto,
		Always:     true,
	}
	if err := checkRule(nr); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	a.cfg.mu.Lock()
	rollback := a.snapshotRuleSettingsLocked()
	a.cfg.Routing.Rules = append([]Rule{nr}, a.cfg.Routing.Rules...)
	if err := a.cfg.saveLocked(); err != nil {
		rollback()
		a.cfg.mu.Unlock()
		writeErr(w, 500, "не удалось сохранить правила: "+err.Error())
		return
	}
	a.cfg.mu.Unlock()
	for _, d := range hosts {
		a.router.forget(d)
	}
	a.onRulesChanged()
	writeJSON(w, map[string]any{"ok": true, "rule": nr})
}

// snapshotRuleSettingsLocked is called under cfg.mu; rollback runs before unlock.
func (a *App) snapshotRuleSettingsLocked() func() {
	old := a.cfg.Routing
	old.Rules = cloneRules(old.Rules)
	old.Chain = append([]string(nil), old.Chain...)
	return func() { a.cfg.Routing = old }
}
