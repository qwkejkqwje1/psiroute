package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// netWatch notices that the computer woke up or changed networks (another
// Wi-Fi, a cable, a VPN, a phone hotspot) and recovers at once, instead of
// waiting for health checks to fail one by one: DNS cache cleared, idle
// connections dropped, WARP starts a fresh UDP flow, Psiphon checks its
// tunnel and switches its per-network strategy profile if the network
// fingerprint changed.

type netWatch struct {
	a           *App
	every       time.Duration
	probe       func() string
	fingerprint func() string
	now         func() time.Time
	kick        chan string

	onEvent func(kind, text string) // tests; nil: a.recoverNetwork

	mu            sync.Mutex
	ip            string
	netKey        string
	changes       int
	resumes       int
	lastEvent     time.Time
	lastText      string
	lastResume    time.Time
	asleepAt      time.Time
	captivePortal bool
	captiveURL    string
	captiveHost   string
}

func newNetWatch(a *App) *netWatch {
	w := &netWatch{
		a:           a,
		every:       5 * time.Second,
		probe:       primaryIP,
		fingerprint: detectNetworkFingerprint,
		now:         time.Now,
		kick:        make(chan string, 4),
	}
	w.ip = w.probe()
	w.netKey = w.fingerprint()
	return w
}

// Kick: the system says something changed ("net" or "resume").
func (w *netWatch) Kick(why string) {
	if w == nil {
		return
	}
	select {
	case w.kick <- why:
	default:
	}
}

// suspended: the system goes to sleep.
func (w *netWatch) suspended() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.asleepAt = w.now()
	w.mu.Unlock()
	logf("info", "Компьютер засыпает")
}

// currentNetKey returns the current network fingerprint key (gateway/subnet +
// adapter name/MAC hash) used for per-network Psiphon strategy memory and NetworkID.
func (w *netWatch) currentNetKey() string {
	if w == nil {
		return "net-default"
	}
	w.mu.Lock()
	k := w.netKey
	fn := w.fingerprint
	w.mu.Unlock()
	if k != "" {
		return k
	}
	if fn != nil {
		if nk := fn(); nk != "" {
			w.mu.Lock()
			w.netKey = nk
			w.mu.Unlock()
			return nk
		}
	}
	return "net-default"
}

func (w *netWatch) run(ctx context.Context) {
	w.mu.Lock()
	w.ip = w.probe()
	if w.fingerprint != nil {
		w.netKey = w.fingerprint()
	}
	w.mu.Unlock()
	goSafe("слежение за сетью", func() { platformNetNotify(ctx, w) })
	t := time.NewTicker(w.every)
	defer t.Stop()
	last := w.now()
	for {
		select {
		case <-ctx.Done():
			return
		case why := <-w.kick:
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			now := w.now()
			w.step(why, 0)
			last = now
		case <-t.C:
			now := w.now()
			w.step("", now.Sub(last))
			last = now
		}
	}
}

// step compares the network with what it was. gap: time since the last
// tick; much longer than the tick interval means the computer slept.
func (w *netWatch) step(why string, gap time.Duration) {
	ip := w.probe()
	var nk string
	if w.fingerprint != nil {
		nk = w.fingerprint()
	}
	now := w.now()
	w.mu.Lock()
	old := w.ip
	oldKey := w.netKey
	w.ip = ip
	if nk != "" {
		w.netKey = nk
	}
	kind, text := "", ""
	switch {
	case ip != "" && ip != old:
		kind = "net"
		if old == "" {
			text = "сеть появилась (" + ip + ")"
		} else {
			text = "сменилась сеть (" + old + " → " + ip + ")"
		}
		w.changes++
	case nk != "" && oldKey != "" && nk != oldKey && ip != "":
		kind = "net"
		text = "сменился сетевой профиль (" + oldKey + " → " + nk + ")"
		w.changes++
	case why == "resume" || gap > 30*time.Second:
		if now.Sub(w.lastResume) < time.Minute {
			break // Windows sends several resume messages; the tick sees the gap too
		}
		kind, text = "resume", "компьютер проснулся"
		if !w.asleepAt.IsZero() {
			text += " (спал " + humanDur(now.Sub(w.asleepAt)) + ")"
		} else if gap > 0 {
			text += " (спал " + humanDur(gap) + ")"
		}
		w.lastResume, w.asleepAt = now, time.Time{}
		w.resumes++
	case ip == "" && old != "":
		w.mu.Unlock()
		logf("warn", "Сеть пропала — жду, когда появится")
		return
	}
	if kind != "" {
		w.lastEvent, w.lastText = now, text
	}
	w.mu.Unlock()
	if kind == "" {
		return
	}
	if w.onEvent != nil {
		w.onEvent(kind, text)
		return
	}
	w.a.recoverNetwork(kind, text)
}

func (w *netWatch) view() map[string]any {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	m := map[string]any{
		"ip":             w.ip,
		"net_key":        w.netKey,
		"changes":        w.changes,
		"resumes":        w.resumes,
		"captive_portal": w.captivePortal,
		"captive_url":    w.captiveURL,
		"captive_host":   w.captiveHost,
	}
	if !w.lastEvent.IsZero() {
		m["last"] = w.lastText
		m["lastAt"] = w.lastEvent.Unix()
	}
	return m
}

// primaryIP: the local address of the route to the internet (no packet is
// sent: a UDP "connect" only picks the route).
func primaryIP() string {
	for _, t := range [][2]string{{"udp4", "8.8.8.8:53"}, {"udp6", "[2001:4860:4860::8888]:53"}} {
		c, err := net.Dial(t[0], t[1])
		if err != nil {
			continue
		}
		ip := c.LocalAddr().(*net.UDPAddr).IP.String()
		_ = c.Close()
		return ip
	}
	return ""
}

// detectNetworkFingerprint computes a stable network key from the active
// outbound interface name, hardware MAC, and IPv4/IPv6 subnet prefix (which
// uniquely identifies the router/gateway subnet + adapter).
func detectNetworkFingerprint() string {
	ipStr := primaryIP()
	if ipStr == "" {
		return "net-offline"
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "net-default"
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, aerr := iface.Addrs()
			if aerr != nil {
				continue
			}
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok || !ipNet.IP.Equal(ip) {
					continue
				}
				subnet := ipNet.IP.Mask(ipNet.Mask).String()
				raw := strings.ToLower(strings.TrimSpace(iface.Name)) + "|" + iface.HardwareAddr.String() + "|" + subnet
				sum := sha256.Sum256([]byte(raw))
				cleanName := sanitizeNetAdapterName(iface.Name)
				return "net-" + cleanName + "-" + hex.EncodeToString(sum[:6])
			}
		}
	}
	// Fallback: hash the /24 subnet of the local IP
	var parts []string
	if v4 := ip.To4(); v4 != nil {
		parts = append(parts, net.IPv4(v4[0], v4[1], v4[2], 0).String())
	} else {
		parts = append(parts, ip.String())
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "net-" + hex.EncodeToString(sum[:6])
}

func sanitizeNetAdapterName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		if b.Len() >= 10 {
			break
		}
	}
	if b.Len() == 0 {
		return "if"
	}
	return b.String()
}

// theNetWatch: for the tray window procedure (WM_POWERBROADCAST).
var theNetWatch *netWatch

var errNetChange = errors.New("сеть сменилась")

// recoverNetwork: what to redo after a network change or sleep.

// isCaptiveHost проверяет, является ли хост страницей авторизации публичного Wi-Fi (Captive Portal).
func (w *netWatch) isCaptiveHost(host string) bool {
	if w == nil || host == "" {
		return false
	}
	h := cleanHostKey(host)
	if h == "connectivitycheck.gstatic.com" || h == "www.msftconnecttest.com" || h == "captive.apple.com" || h == "detectportal.firefox.com" {
		return true
	}
	w.mu.Lock()
	cp := w.captivePortal
	ch := w.captiveHost
	w.mu.Unlock()
	return cp && ch != "" && (h == ch || strings.HasSuffix(h, "."+ch))
}

// setCaptivePortalState позволяет обновить или протестировать состояние Captive Portal.
func (w *netWatch) setCaptivePortalState(active bool, portalURL string) {
	if w == nil {
		return
	}
	var host string
	if active && portalURL != "" {
		if u, err := url.Parse(portalURL); err == nil {
			host = cleanHostKey(u.Hostname())
		}
	}
	w.mu.Lock()
	w.captivePortal = active && host != ""
	w.captiveURL = portalURL
	w.captiveHost = host
	w.mu.Unlock()
}

const captiveConnectivityURL = "http://connectivitycheck.gstatic.com/generate_204"

// captivePortalResponse classifies only our fixed no-content probe. It never
// follows links from HTML or treats arbitrary web pages as portal evidence.
func captivePortalResponse(resp *http.Response) (bool, string) {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.String() != captiveConnectivityURL {
		return false, ""
	}
	base := resp.Request.URL
	if (resp.StatusCode >= 300 && resp.StatusCode < 400) || resp.StatusCode == http.StatusNetworkAuthenticationRequired {
		raw := strings.TrimSpace(resp.Header.Get("Location"))
		if raw == "" {
			return false, ""
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return false, ""
		}
		target := base.ResolveReference(ref)
		if (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil || target.Opaque != "" {
			return false, ""
		}
		if port := target.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return false, ""
			}
		}
		target.Fragment = ""
		return true, target.String()
	}
	if resp.StatusCode == http.StatusOK && resp.Body != nil {
		media := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
		if media != "text/html" {
			return false, ""
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return false, ""
		}
		prefix := strings.ToLower(strings.TrimSpace(string(body)))
		if strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html") {
			return true, captiveConnectivityURL
		}
	}
	return false, ""
}

// detectCaptivePortal checks our known no-content endpoint without following
// redirects. HTML interception is evidence of changed probe content, not DPI.
func (w *netWatch) detectCaptivePortal(ctx context.Context) (bool, string) {
	if w == nil || isRunningTests() {
		return false, ""
	}
	cl := &http.Client{
		Timeout: 3500 * time.Millisecond,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: dialDirect,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", captiveConnectivityURL, nil)
	if err != nil {
		return false, ""
	}
	resp, err := cl.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	defer cl.CloseIdleConnections()
	if resp.StatusCode == http.StatusNoContent {
		w.setCaptivePortalState(false, "")
		return false, ""
	}
	if active, location := captivePortalResponse(resp); active {
		w.setCaptivePortalState(true, location)
		logf("warn", "Проверка подключения перехвачена: %s", location)
		return true, location
	}
	return false, ""
}

func (a *App) recoverNetwork(kind, text string) {
	if a.net != nil {
		go a.net.detectCaptivePortal(a.ctx)
	}
	logf("info", "%s — проверяю связь", upperFirst(text))
	theDNS.clear()
	a.dohReset()
	a.tun.refresh()
	if kind == "net" {
		obfs.reset() // another network, other DPI: learn the methods again
		a.countries.StopAll()
		if t := a.warp.cur.Load(); t != nil {
			if err := t.refresh(); err != nil {
				logf("warn", "WARP: не удалось переоткрыть туннель: %v", err)
			}
		}
	}
	if a.psi.running() {
		a.psi.send("check")
	}
}

func upperFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}
