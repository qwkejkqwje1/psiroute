package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"strings"

	"rsc.io/qr"
)

// LAN share: lets a phone / TV / second PC use this Psiphon connection.

func randomPass(n int) string {
	const abc = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = abc[int(b[i])%len(abc)]
	}
	return string(b)
}

func lanIP() string {
	c, err := net.Dial("udp", "192.168.0.1:9")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func (a *App) setShare(on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !on {
		if a.shareLn != nil {
			a.shareLn.Close()
			a.shareLn = nil
		}
		a.cfg.mu.Lock()
		a.cfg.Share.Enabled = false
		a.cfg.mu.Unlock()
		_ = a.cfg.save()
		logf("info", "Раздача в сеть выключена")
		return nil
	}
	if a.shareLn != nil {
		return nil
	}
	a.cfg.mu.Lock()
	if a.cfg.Share.Password == "" {
		a.cfg.Share.Password = randomPass(10)
	}
	if a.cfg.Share.User == "" {
		a.cfg.Share.User = "psiroute"
	}
	port, user, pass, free := a.cfg.Share.Port, a.cfg.Share.User, a.cfg.Share.Password, a.cfg.Share.NoPwdLAN
	a.cfg.mu.Unlock()
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("порт %d занят: %w", port, err)
	}
	a.shareLn = ln
	a.cfg.mu.Lock()
	a.cfg.Share.Enabled = true
	a.cfg.mu.Unlock()
	_ = a.cfg.save()
	go a.serveProxy(ln, &proxyAuth{user: user, pass: pass, lanFree: free})
	logf("info", "Раздача в сеть: %s:%d", lanIP(), port)
	return nil
}

func (a *App) shareInfo() map[string]any {
	a.mu.Lock()
	enabled := a.shareLn != nil
	a.mu.Unlock()
	a.cfg.mu.Lock()
	port, user, pass, free := a.cfg.Share.Port, a.cfg.Share.User, a.cfg.Share.Password, a.cfg.Share.NoPwdLAN
	a.cfg.mu.Unlock()
	ip := lanIP()
	cred := url.UserPassword(user, pass).String()
	socks := fmt.Sprintf("socks5://%s@%s:%d", cred, ip, port)
	httpURL := fmt.Sprintf("http://%s@%s:%d", cred, ip, port)
	tg := fmt.Sprintf("https://t.me/socks?server=%s&port=%d&user=%s&pass=%s", ip, port, url.QueryEscape(user), url.QueryEscape(pass))
	return map[string]any{"enabled": enabled, "port": port, "ip": ip, "user": user, "password": pass,
		"socks": socks, "http": httpURL, "qr": qrSVG(socks), "qr_tg": qrSVG(tg), "no_password_in_lan": free}
}

func qrSVG(text string) string {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return ""
	}
	const m = 2
	n := code.Size + 2*m
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&sb, "M%d %dh1v1h-1z", x+m, y+m)
			}
		}
	}
	sb.WriteString(`"/></svg>`)
	return sb.String()
}
