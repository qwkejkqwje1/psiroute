//go:build windows

package main

import (
	"net/url"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowTitle also identifies the window: the core finds it by its title to
// bring it to the front and to close it on exit.
const windowTitle = "Psiroute v" + version + " — Psiphon VPN"

var procMessageBox = dtUser32.NewProc("MessageBoxW")

var (
	nativeModes     = []string{"psiphon", "rules", "auto"}
	nativeModeNames = []string{"Весь трафик (Psiphon)", "Умный режим (по правилам)", "Авто-обход (Direct → DPI → Psiphon)"}

	nativeCountries = []string{
		"", "DE", "NL", "FI", "SE", "FR", "GB", "US", "CA", "PL", "AT", "CH", "JP", "SG",
		"IT", "ES", "CZ", "NO", "DK", "BE", "IE", "EE", "LV", "LT", "RO", "BG", "HU", "TR",
	}
	nativeCountryNames = []string{
		"Авто (быстрейшая)", "Германия (DE)", "Нидерланды (NL)", "Финляндия (FI)", "Швеция (SE)",
		"Франция (FR)", "Великобритания (GB)", "США (US)", "Канада (CA)", "Польша (PL)",
		"Австрия (AT)", "Швейцария (CH)", "Япония (JP)", "Сингапур (SG)",
		"Италия (IT)", "Испания (ES)", "Чехия (CZ)", "Норвегия (NO)", "Дания (DK)",
		"Бельгия (BE)", "Ирландия (IE)", "Эстония (EE)", "Латвия (LV)", "Литва (LT)",
		"Румыния (RO)", "Болгария (BG)", "Венгрия (HU)", "Турция (TR)",
	}

	nativeDPIModes = []string{"auto", "off", "tlsrec", "split", "double", "multirec", "chunk"}
	nativeDPINames = []string{"Авто (подбор)", "Выключен", "2 TLS-записи (tlsrec)", "Разрез TCP (split)", "Записи + разрез (double)", "Много записей (multirec)", "Мелкие куски (chunk)"}

	nativeRuleObs     = []string{"psiphon", "direct", "direct-dpi", "warp", "clean-ip", "block", "auto", "psiphon:DE", "psiphon:NL", "psiphon:FI", "psiphon:US", "psiphon:GB", "psiphon:FR"}
	nativeRuleObNames = []string{"Psiphon", "Напрямую (direct)", "DPI-обход (direct-dpi)", "Через WARP", "Clean-IP (WARP→VPN→WARP)", "Блокировать (block)", "Авто-подбор (auto)", "Psiphon: Германия (DE)", "Psiphon: Нидерланды (NL)", "Psiphon: Финляндия (FI)", "Psiphon: США (US)", "Psiphon: Великобритания (GB)", "Psiphon: Франция (FR)"}

	nativeProfileIDs   = []string{"discord-youtube", "gaming-discord-youtube", "except-ru", "blocked-only", "telegram"}
	nativeProfileNames = []string{"Discord + YouTube через Psiphon", "Игры + Discord (голос) + YouTube", "Всё, кроме российских сайтов", "Только заблокированное через Psiphon", "Только Telegram"}
)

// runWindowProcess is the "psiroute --window" process: a modern, hardware-
// accelerated Gio (gioui.org) vector UI window (<8 MB RAM, zero WebView2 /
// Chromium processes). If the user configured general.ui_mode = "browser", it
// opens the UI in the default browser instead and exits with exitNoWebView.
func runWindowProcess(dataDir, uiURL string, parentPID int) {
	if h := findAppWindow(); h != 0 {
		focusWindow(h) // already open
		return
	}
	cfg := loadConfig(readConfigPath(dataDir))
	if cfg.General.UIMode == "app" {
		openAppWindow(uiURL, dataDir)
		os.Exit(exitNoWebView)
	}
	if cfg.General.UIMode == "browser" {
		openBrowser(uiURL)
		os.Exit(exitNoWebView)
	}
	runGioWindow(dataDir, uiURL, parentPID)
}

func readConfigPath(dataDir string) string {
	return dataDir + `\psiroute.json`
}

func resolveAPIConfig(dataDir, uiURL string) (apiBase, token string) {
	addr := readInstanceLine(dataDir, 0)
	token = readInstanceLine(dataDir, 1)
	if addr != "" {
		apiBase = "http://" + addr
	} else if u, err := url.Parse(uiURL); err == nil && u.Host != "" {
		apiBase = "http://" + u.Host
	} else {
		apiBase = "http://127.0.0.1:9090"
	}
	return apiBase, token
}



func openBrowser(url string) {
	if !isHTTPURL(url) {
		logf("warn", "Ссылка не открыта: разрешены только http и https")
		return
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// openAppWindow launches the Aether Flow Dark UI as a standalone frameless
// desktop app window (--app=URL) using Edge or Chrome with a strictly portable
// profile inside dataDir\tmp\app-ui (zero files written to C:).
func openAppWindow(uiURL, dataDir string) {
	profDir := dataDir + `\tmp\app-ui`
	_ = os.MkdirAll(profDir, 0o700)
	candidates := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}
	for _, bin := range candidates {
		if _, err := os.Stat(bin); err == nil {
			cmd := exec.Command(bin,
				"--app="+uiURL,
				"--window-size=1280,820",
				"--user-data-dir="+profDir,
				"--no-first-run",
				"--no-default-browser-check",
			)
			if cmd.Start() == nil {
				return
			}
		}
	}
	openBrowser(uiURL)
}

// showFatal shows a startup error: the GUI build has no console to print to.
func showFatal(msg string) {
	t, _ := windows.UTF16PtrFromString("Psiroute")
	m, _ := windows.UTF16PtrFromString(msg)
	procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10) // MB_ICONERROR
}
