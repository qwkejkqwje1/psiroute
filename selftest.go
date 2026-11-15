package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Self-test (1.0.7): the button in Settings, "psiroute --selftest" and the
// report. Each line is ok, warn (works, but worth knowing), fail or info.

type check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail | info
	Detail string `json:"detail"`
}

// selftestTarget answers GET /generate_204 with 204 (tests point it at a
// local server).
var selftestTarget = "www.gstatic.com:80"

func (a *App) selftest(ctx context.Context) []check {
	out := []check{{"Psiroute", "info", fmt.Sprintf("%s, %s/%s, %s", version, runtime.GOOS, runtime.GOARCH, runtime.Version())}}
	out = append(out, platformChecks(a)...)
	out = append(out, a.portChecks()...)
	tests := []func(context.Context) []check{a.checkProxy, a.checkDNS, a.checkPsiphon, a.checkWarp, a.checkUDP, a.checkTun}
	res := make([][]check, len(tests))
	var wg sync.WaitGroup
	for i, f := range tests {
		wg.Add(1)
		goSafe("самопроверка", func() {
			defer wg.Done()
			res[i] = f(ctx)
		})
	}
	wg.Wait()
	for _, r := range res {
		out = append(out, r...)
	}
	return append(out, a.healthChecks()...)
}

func (a *App) checkTun(context.Context) []check {
	v := a.tun.view()
	on, _ := v["on"].(bool)
	st, _ := v["state"].(string)
	text, _ := v["text"].(string)
	switch {
	case on:
		return []check{{"Режим TUN", "ok", text}}
	case st == "error" || st == "starting":
		return []check{{"Режим TUN", "warn", text}}
	case a.cfg.tunWanted():
		return []check{{"Режим TUN", "warn", text}}
	default:
		return []check{{"Режим TUN", "info", text}}
	}
}

func (a *App) portChecks() []check {
	a.mu.Lock()
	ui, listen := a.uiActual, a.listenActual
	a.mu.Unlock()
	a.cfg.mu.Lock()
	wantL, wantU := a.cfg.General.Listen, a.cfg.General.UI
	a.cfg.mu.Unlock()
	var out []check
	pc := func(name, want, got string) {
		switch {
		case got == "":
			out = append(out, check{name, "fail", "не открыт"})
		case got == want:
			out = append(out, check{name, "ok", got})
		default:
			d := got + " — " + want + " занят"
			if o := portOwner(want); o != "" {
				d += " (" + o + ")"
			}
			out = append(out, check{name, "warn", d})
		}
	}
	pc("Порт прокси", wantL, listen)
	pc("Интерфейс", wantU, ui)
	return out
}

// socksConnect opens a SOCKS5 CONNECT through a proxy (no password).
func socksConnect(ctx context.Context, proxy, target string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	host, ps, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(ps)
	req := append([]byte{5, 1, 0, 5, 1, 0}, socksAddr(host, port)...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	if err := socksReadReply(c, 2); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// socksReadReply reads the method answer (if methodBytes) and the reply.
func socksReadReply(c io.Reader, methodBytes int) error {
	if methodBytes > 0 {
		m := make([]byte, methodBytes)
		if _, err := io.ReadFull(c, m); err != nil {
			return err
		}
		if m[1] != 0 {
			return errors.New("SOCKS5: прокси просит пароль")
		}
	}
	_, _, err := socksReadAddrReply(c)
	return err
}

func socksReadAddrReply(c io.Reader) (net.IP, int, error) {
	r := make([]byte, 4)
	if _, err := io.ReadFull(c, r); err != nil {
		return nil, 0, err
	}
	if r[1] != 0 {
		return nil, 0, fmt.Errorf("SOCKS5: отказ (код %d)", r[1])
	}
	n := 4
	switch r[3] {
	case 4:
		n = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return nil, 0, err
		}
		n = int(l[0])
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, 0, err
	}
	var ip net.IP
	if r[3] != 3 {
		ip = net.IP(b[:n])
	}
	return ip, int(b[n])<<8 | int(b[n+1]), nil
}

func (a *App) checkProxy(ctx context.Context) []check {
	a.mu.Lock()
	listen := a.listenActual
	a.mu.Unlock()
	if listen == "" {
		return []check{{"Интернет через прокси", "fail", "прокси не запущен"}}
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := httpCheck(ctx, func(ctx context.Context) (net.Conn, error) { return socksConnect(ctx, listen, selftestTarget) })
	if err != nil {
		return []check{{"Интернет через прокси", "fail", short(err.Error(), 160)}}
	}
	out := []check{{"Интернет через прокси", "ok", fmt.Sprintf("работает, %d мс", time.Since(start).Milliseconds())}}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		out[0] = check{"Интернет через прокси", "warn", fmt.Sprintf("ответ %d — возможно, портал авторизации (Wi-Fi в кафе, гостинице)", resp.StatusCode)}
	}
	out = append(out, clockCheck(resp.Header.Get("Date"))...)
	return out
}

// httpCheck sends GET /generate_204 over a connection from dial.
func httpCheck(ctx context.Context, dial func(context.Context) (net.Conn, error)) (*http.Response, error) {
	c, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	host, _, _ := net.SplitHostPort(selftestTarget)
	if _, err := fmt.Fprintf(c, "GET /generate_204 HTTP/1.1\r\nHost: %s\r\nUser-Agent: Psiroute-selftest\r\nConnection: close\r\n\r\n", host); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return resp, nil
}

func clockCheck(date string) []check {
	t, err := http.ParseTime(date)
	if date == "" || err != nil {
		return nil
	}
	skew := time.Since(t)
	switch {
	case skew > 2*time.Minute:
		return []check{{"Часы", "warn", "часы компьютера спешат на " + humanDur(skew) + " — из-за этого не подключаются сайты и Psiphon"}}
	case skew < -2*time.Minute:
		return []check{{"Часы", "warn", "часы компьютера отстают на " + humanDur(-skew) + " — из-за этого не подключаются сайты и Psiphon"}}
	}
	return []check{{"Часы", "ok", "точные"}}
}

func (a *App) checkDNS(ctx context.Context) []check {
	host, _, _ := net.SplitHostPort(selftestTarget)
	if net.ParseIP(host) != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	_, sysErr := net.DefaultResolver.LookupHost(ctx, host)
	_, dohErr := resolve(ctx, host, true)
	switch {
	case sysErr == nil && dohErr == nil:
		return []check{{"DNS", "ok", "системный и DNS over HTTPS отвечают"}}
	case sysErr != nil && dohErr == nil:
		return []check{{"DNS", "warn", "системный DNS не отвечает, Psiroute обходится DNS over HTTPS"}}
	case sysErr == nil:
		return []check{{"DNS", "ok", "системный отвечает; DNS over HTTPS недоступен: " + short(dohErr.Error(), 100)}}
	}
	return []check{{"DNS", "fail", "ни системный DNS, ни DNS over HTTPS не отвечают — сети нет?"}}
}

func (a *App) checkPsiphon(ctx context.Context) []check {
	if !a.psi.running() {
		return []check{{"Psiphon", "info", "выключен"}}
	}
	v := a.psi.view()
	st, _ := v["state"].(string)
	if st != "connected" {
		d := st
		if e, _ := v["last_error"].(string); e != "" {
			d += ": " + e
		}
		return []check{{"Psiphon", "warn", d}}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ms, err := a.psi.ping(ctx)
	d := fmt.Sprintf("подключён «%v», выход %v", v["strategy_title"], v["egress_region"])
	if err != nil {
		return []check{{"Psiphon", "fail", d + ", но туннель не пропускает данные: " + short(err.Error(), 100)}}
	}
	return []check{{"Psiphon", "ok", fmt.Sprintf("%s, отклик %d мс", d, ms)}}
}

func (a *App) checkWarp(context.Context) []check {
	v := a.warp.view()
	st, _ := v["state"].(string)
	text, _ := v["text"].(string)
	switch st {
	case "connected":
		return []check{{"WARP", "ok", text}}
	case "off", "idle", "external":
		return []check{{"WARP", "info", text}}
	case "connecting":
		return []check{{"WARP", "info", "подключается: " + text}}
	}
	return []check{{"WARP", "warn", text}}
}

// udpProbe sends one datagram through a SOCKS5 UDP ASSOCIATE and returns
// the first answer.
func udpProbe(ctx context.Context, proxy, dst string, payload []byte) ([]byte, error) {
	var d net.Dialer
	ctl, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	defer ctl.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = ctl.SetDeadline(dl)
	}
	if _, err := ctl.Write([]byte{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	m := make([]byte, 2)
	if _, err := io.ReadFull(ctl, m); err != nil {
		return nil, err
	}
	ip, port, err := socksReadAddrReply(ctl)
	if err != nil {
		return nil, err
	}
	if ip == nil || ip.IsUnspecified() {
		h, _, _ := net.SplitHostPort(proxy)
		ip = net.ParseIP(h)
	}
	u, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, err
	}
	defer u.Close()
	host, ps, _ := net.SplitHostPort(dst)
	dp, _ := strconv.Atoi(ps)
	pkt := append(append([]byte{0, 0, 0}, socksAddr(host, dp)...), payload...)
	buf := make([]byte, 64<<10)
	for try := 0; try < 4 && ctx.Err() == nil; try++ {
		if _, err := u.Write(pkt); err != nil {
			return nil, err
		}
		_ = u.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := u.Read(buf)
		if err != nil {
			continue
		}
		if _, _, data, ok := parseSocksUDP(buf[:n]); ok {
			return data, nil
		}
	}
	return nil, errors.New("нет ответа")
}

var udpCheckDst = "1.1.1.1:53"

func (a *App) checkUDP(ctx context.Context) []check {
	if a.udpMode() == "off" {
		return []check{{"UDP", "info", "выключен в настройках"}}
	}
	a.mu.Lock()
	listen := a.listenActual
	a.mu.Unlock()
	var out []check
	ob, _ := a.planUDP("1.1.1.1", 53, "")
	ctx1, cancel := context.WithTimeout(ctx, 20*time.Second)
	resp, err := udpProbe(ctx1, listen, udpCheckDst, dnsQuery(0x5053, "www.gstatic.com", 1))
	cancel()
	if err == nil {
		_, err = dnsAnswers(resp)
	}
	if err != nil {
		out = append(out, check{"UDP через прокси", "fail", obTitle(ob) + ": " + short(err.Error(), 120)})
	} else {
		out = append(out, check{"UDP через прокси", "ok", "работает (DNS-запрос " + obTitle(ob) + ")"})
	}
	if a.psi.running() && a.psi.cur.Load() != nil {
		ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := a.udpgwProbe(ctx2)
		cancel()
		if err != nil {
			out = append(out, check{"UDP через Psiphon", "warn", "сервер не пропустил UDP: " + short(err.Error(), 100) + " — звонки и игры через Psiphon не пойдут, DNS — пойдёт"})
		} else {
			out = append(out, check{"UDP через Psiphon", "ok", "udpgw отвечает"})
		}
	}
	return out
}

// udpgwProbe: one DNS query to 1.1.1.1 through the Psiphon server's udpgw.
func (a *App) udpgwProbe(ctx context.Context) error {
	c, err := a.psi.Dial(ctx, "tcp", udpgwServer)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(udpgwEncode(udpgwFlagRebind, 1, net.IPv4(1, 1, 1, 1), 53, dnsQuery(0x5054, "www.gstatic.com", 1))); err != nil {
		return err
	}
	_, _, _, _, data, err := udpgwRead(c, make([]byte, 64<<10))
	if err != nil {
		return err
	}
	_, err = dnsAnswers(data)
	return err
}

func obTitle(ob string) string {
	switch ob {
	case obDirect:
		return "напрямую"
	case obPsiphon:
		return "через Psiphon"
	case obWarp:
		return "через WARP"
	}
	return ob
}

func (a *App) healthChecks() []check {
	m := memView()
	out := []check{{"Память", "info", memLine(m)}}
	crash := "не было"
	st := "ok"
	if n := panicsCaught.Load(); n > 0 {
		crash, st = fmt.Sprintf("перехвачено сбоев: %d (подробности в psiroute.log)", n), "warn"
	}
	if crashRestarts > 0 {
		crash, st = fmt.Sprintf("%s; перезапусков после сбоя: %d", crash, crashRestarts), "warn"
	}
	if h := crashHeadline(crashLogPath(a.dataDir)); h != "" {
		crash += "; в crash.log: " + h
	}
	out = append(out, check{"Сбои", st, crash})
	if v := a.net.view(); v != nil {
		d := fmt.Sprintf("адрес %v, смен сети: %v, пробуждений: %v", v["ip"], v["changes"], v["resumes"])
		if l, ok := v["last"].(string); ok {
			d += "; последнее: " + l
		}
		out = append(out, check{"Сеть", "info", d})
	}
	return out
}

func memLine(m memSnap) string {
	s := "всего " + mbText(m.Total) + ": ядро " + mbText(m.App)
	if m.Window > 0 {
		s += ", окно " + mbText(m.Window)
	}
	if m.Workers > 0 {
		s += ", помощники " + mbText(m.Workers)
	}
	if m.Watchdog > 0 {
		s += ", сторож " + mbText(m.Watchdog)
	}
	return s
}

var checkMarks = map[string]string{"ok": "✓", "warn": "!", "fail": "✗", "info": "·"}

func formatChecks(cs []check) string {
	var b strings.Builder
	for _, c := range cs {
		fmt.Fprintf(&b, "%s %s: %s\r\n", checkMarks[c.Status], c.Name, c.Detail)
	}
	return b.String()
}

func checksFailed(cs []check) bool {
	for _, c := range cs {
		if c.Status == "fail" {
			return true
		}
	}
	return false
}

// offlineSelftest: Psiroute is not running; check what can be checked.
func offlineSelftest(dir string) []check {
	out := []check{{"Psiroute", "info", fmt.Sprintf("%s, %s/%s, %s — не запущен", version, runtime.GOOS, runtime.GOARCH, runtime.Version())}}
	out = append(out, platformChecks(nil)...)
	cfg := loadConfig(filepath.Join(dir, "psiroute.json"))
	for _, p := range [][2]string{{"Порт прокси", cfg.General.Listen}, {"Интерфейс", cfg.General.UI}} {
		ln, err := net.Listen("tcp", p[1])
		if err == nil {
			ln.Close()
			out = append(out, check{p[0], "ok", p[1] + " свободен"})
			continue
		}
		d := p[1] + " занят"
		if o := portOwner(p[1]); o != "" {
			d += " (" + o + ")"
		}
		out = append(out, check{p[0], "warn", d + " — Psiroute возьмёт соседний"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := httpCheck(ctx, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", selftestTarget)
	})
	if err != nil {
		out = append(out, check{"Интернет напрямую", "warn", short(err.Error(), 140)})
	} else {
		out = append(out, check{"Интернет напрямую", "ok", "работает"})
		out = append(out, clockCheck(resp.Header.Get("Date"))...)
	}
	if h := crashHeadline(crashLogPath(dir)); h != "" {
		out = append(out, check{"Сбои", "warn", "в crash.log: " + h})
	}
	return out
}

// runSelftestCLI: "psiroute --selftest". Asks the running Psiroute when
// there is one (it can test the tunnels), otherwise tests offline.
func runSelftestCLI(dir string) int {
	var checks []check
	if addr := readInstanceLine(dir, 0); addr != "" && isPsirouteAt(addr) {
		var err error
		if checks, err = remoteSelftest(addr, readInstanceLine(dir, 1)); err != nil {
			checks = append(offlineSelftest(dir), check{"Связь с Psiroute", "warn", short(err.Error(), 120)})
		}
	} else {
		checks = offlineSelftest(dir)
	}
	text := "Самопроверка Psiroute, " + time.Now().Format("02.01.2006 15:04:05") + "\r\n\r\n" + formatChecks(checks)
	path := filepath.Join(dir, "psiroute-selftest.txt")
	_ = os.WriteFile(path, []byte("\ufeff"+text), 0o600)
	if _, err := os.Stdout.Stat(); err == nil {
		fmt.Print(text)
	} else {
		openWithDefault(path) // no console (the Windows build is a GUI program)
	}
	if checksFailed(checks) {
		return 1
	}
	return 0
}

func remoteSelftest(addr, token string) ([]check, error) {
	req, err := http.NewRequest("POST", "http://"+addr+"/api/selftest", bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Psiroute", token)
	cl := &http.Client{Timeout: 100 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ответ %d", resp.StatusCode)
	}
	var v struct {
		Checks []check `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return v.Checks, nil
}
