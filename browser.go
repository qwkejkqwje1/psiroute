package main

// Browser helpers: a PAC file for "automatic proxy configuration" and a
// one-click launch of a Chromium-based browser in its own profile with the
// local SOCKS5 proxy (no DNS and WebRTC leaks, the system proxy is not needed).

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type browserKind struct {
	id, name string
	win      []string // relative to Program Files / LocalAppData
	unix     []string // names in PATH or absolute paths (macOS)
}

var browserKinds = []browserKind{
	{"chrome", "Chrome", []string{`Google\Chrome\Application\chrome.exe`},
		[]string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}},
	{"edge", "Edge", []string{`Microsoft\Edge\Application\msedge.exe`},
		[]string{"microsoft-edge", "microsoft-edge-stable", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"}},
	{"yandex", "Яндекс Браузер", []string{`Yandex\YandexBrowser\Application\browser.exe`},
		[]string{"yandex-browser", "yandex-browser-stable"}},
	{"brave", "Brave", []string{`BraveSoftware\Brave-Browser\Application\brave.exe`},
		[]string{"brave-browser", "brave", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"}},
}

func (k browserKind) find() string {
	if runtime.GOOS == "windows" {
		for _, env := range []string{"ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LOCALAPPDATA"} {
			root := os.Getenv(env)
			if root == "" {
				continue
			}
			for _, rel := range k.win {
				p := filepath.Join(root, rel)
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					return p
				}
			}
		}
		return ""
	}
	for _, n := range k.unix {
		if filepath.IsAbs(n) {
			if _, err := os.Stat(n); err == nil {
				return n
			}
			continue
		}
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// browserHostPort turns the proxy listen address into what a browser should
// use: 0.0.0.0 / :: / empty become 127.0.0.1.
func browserHostPort(listen string) (host, hostport string) {
	h, p, err := net.SplitHostPort(listen)
	if err != nil {
		h, p = "127.0.0.1", "1080"
	}
	if ip := net.ParseIP(h); h == "" || (ip != nil && ip.IsUnspecified()) {
		h = "127.0.0.1"
	}
	return h, net.JoinHostPort(h, p)
}

// browserPAC: everything through the local SOCKS5 port (names are resolved by
// the proxy), the local network goes direct. PROXY is the fallback for engines
// without SOCKS support (WinHTTP); there is no DIRECT fallback on purpose.
func browserPAC(listen string) string {
	_, hp := browserHostPort(listen)
	return `// Psiroute: everything via the local proxy, local network direct.
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host == "localhost" || shExpMatch(host, "*.local") ||
      shExpMatch(host, "127.*") || shExpMatch(host, "10.*") || shExpMatch(host, "192.168.*") ||
      shExpMatch(host, "169.254.*") || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host) ||
      host == "::1" || host == "[::1]")
    return "DIRECT";
  return "SOCKS5 ` + hp + `; PROXY ` + hp + `";
}
`
}

// browserList: browsers found on this computer, for the buttons in the UI.
func browserList() []map[string]string {
	out := []map[string]string{}
	for _, k := range browserKinds {
		if k.find() != "" {
			out = append(out, map[string]string{"id": k.id, "name": k.name})
		}
	}
	return out
}

// openBrowser starts the browser in a separate profile (works even when the
// usual window of the same browser is already open) with the proxy forced.
func (a *App) openBrowser(id string) error {
	for _, k := range browserKinds {
		if k.id != id {
			continue
		}
		exe := k.find()
		if exe == "" {
			return fmt.Errorf("%s не найден на этом компьютере", k.name)
		}
		host, hp := browserHostPort(a.listenAddr())
		prof := filepath.Join(a.dataDir, "browser", k.id)
		if err := os.MkdirAll(prof, 0o700); err != nil {
			return fmt.Errorf("папка профиля браузера: %w", err)
		}
		cmd := exec.Command(exe,
			"--proxy-server=socks5://"+hp,
			"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE "+host,
			"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
			"--user-data-dir="+prof,
			"--no-first-run", "--no-default-browser-check")
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("не удалось запустить %s: %w", k.name, err)
		}
		safeGo("App.openBrowser", func() { _ = cmd.Wait() })
		logf("info", "Открыт %s через прокси %s (отдельный профиль)", k.name, hp)
		return nil
	}
	return fmt.Errorf("неизвестный браузер %q", id)
}
