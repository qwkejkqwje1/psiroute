package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// The report (1.0.7): one zip with everything needed to understand a
// problem — journal, crash logs, settings without passwords, the current
// state and a fresh self-test. Never the WARP identity (its private key).

var secretKey = regexp.MustCompile(`(?i)pass|token|secret|private|auth|client_id`)

func redactJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if s, ok := x.(string); ok && s != "" && secretKey.MatchString(k) {
				t[k] = "***"
				continue
			}
			t[k] = redactJSON(x)
		}
	case []any:
		for i, x := range t {
			t[i] = redactJSON(x)
		}
	case string:
		return redactURL(t)
	}
	return v
}

// redactURL hides user:password in proxy URLs (socks5://user:pass@host).
func redactURL(s string) string {
	if !strings.Contains(s, "://") || !strings.Contains(s, "@") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = url.User("***")
	return u.String()
}

func redactSettings(b []byte) []byte {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return []byte("(не удалось разобрать: " + err.Error() + ")")
	}
	out, _ := json.MarshalIndent(redactJSON(v), "", "  ")
	return out
}

// reportDirFor сохраняет диагностические отчёты строго внутри filepath.Join(dataDir, "reports")
// без обращения к системной папке Загрузки на диске C:.
var reportDirFor = func(dataDir string) string {
	d := filepath.Join(dataDir, "reports")
	if err := os.MkdirAll(d, 0o700); err == nil {
		return d
	}
	return dataDir
}

const reportReadme = "Отчёт Psiroute\r\n\r\n" +
	"selftest.txt  — самопроверка на момент отчёта\r\n" +
	"state.json    — состояние: Psiphon, WARP, TUN, обход DPI, память, сеть\r\n" +
	"settings.json — настройки; пароли и токены заменены на ***\r\n" +
	"psiroute.log  — журнал (psiroute.log.1 — предыдущий)\r\n" +
	"crash.log     — если программа падала\r\n\r\n" +
	"Ключ WARP (warp-identity.json) в отчёт не попадает. В журнале есть адреса\r\n" +
	"сайтов, куда ходили программы, — посмотрите его, прежде чем пересылать.\r\n"

func (a *App) makeReport(ctx context.Context) (string, error) {
	checks := a.selftest(ctx)
	path := filepath.Join(reportDirFor(a.dataDir), "psiroute-report-"+time.Now().Format("2006-01-02-150405")+".zip")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	zw := zip.NewWriter(f)
	add := func(name string, b []byte) {
		if err != nil {
			return
		}
		var w io.Writer
		if w, err = zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()}); err == nil {
			_, err = w.Write(b)
		}
	}
	add("README.txt", []byte(reportReadme))
	add("selftest.txt", []byte(formatChecks(checks)))
	add("state.json", a.reportState())
	if b, e := os.ReadFile(a.cfgPath); e == nil {
		add("settings.json", redactSettings(b))
	}
	for _, n := range []string{"psiroute.log.1", "psiroute.log", "crash.log.1", "crash.log"} {
		if b, e := os.ReadFile(filepath.Join(a.dataDir, n)); e == nil {
			add(n, b)
		}
	}
	if theLog.filePath() == "" { // no log file: at least the recent journal
		var sb strings.Builder
		for _, l := range theLog.snapshot() {
			sb.WriteString(l.Time + " " + l.Level + " " + l.Msg + "\r\n")
		}
		add("journal.txt", []byte(sb.String()))
	}
	if e := zw.Close(); err == nil {
		err = e
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	logf("info", "Отчёт сохранён: %s", path)
	return path, nil
}

func (a *App) reportState() []byte {
	a.mu.Lock()
	ui, listen, sys := a.uiActual, a.listenActual, a.sysOn
	a.mu.Unlock()
	st := map[string]any{
		"version": version, "os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(),
		"time": time.Now().Format(time.RFC3339), "ui": ui, "listen": listen, "system_proxy": sys,
		"psiphon": a.psi.view(), "psiphon_timeline": a.psi.tl().Events(), "psiphon_counters": a.psi.tl().Counters(), "psiphon_preflight": a.psi.lastPreflightReport(),
		"warp": a.warp.view(), "tun": a.tun.view(), "obfs": a.obfsView(),
		"memory": memView(), "net": a.net.view(),
		"panics": panicsCaught.Load(), "crash_restarts": crashRestarts,
		"udp": map[string]any{"mode": a.udpMode(), "sessions": udpStats.sessions.Load(), "flows": udpStats.flows.Load()},
	}
	if !a.started.IsZero() {
		st["uptime"] = humanDur(time.Since(a.started))
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	return b
}
