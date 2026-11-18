//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Desktop integration on Windows. The core process keeps a tray icon with a
// complete hierarchical menu to control all processes; the window is a
// lightweight Native Gio GPU-accelerated GUI ("psiroute --window").

var (
	dtUser32   = windows.NewLazySystemDLL("user32.dll")
	dtShell32  = windows.NewLazySystemDLL("shell32.dll")
	dtKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	dtShellNotifyIconW            = dtShell32.NewProc("Shell_NotifyIconW")
	dtRegisterClassExW            = dtUser32.NewProc("RegisterClassExW")
	dtCreateWindowExW             = dtUser32.NewProc("CreateWindowExW")
	dtDefWindowProcW              = dtUser32.NewProc("DefWindowProcW")
	dtGetMessageW                 = dtUser32.NewProc("GetMessageW")
	dtTranslateMessage            = dtUser32.NewProc("TranslateMessage")
	dtDispatchMessageW            = dtUser32.NewProc("DispatchMessageW")
	dtPostMessageW                = dtUser32.NewProc("PostMessageW")
	dtSendMessageW                = dtUser32.NewProc("SendMessageW")
	dtPostQuitMessage             = dtUser32.NewProc("PostQuitMessage")
	dtDestroyWindow               = dtUser32.NewProc("DestroyWindow")
	dtCreatePopupMenu             = dtUser32.NewProc("CreatePopupMenu")
	dtAppendMenuW                 = dtUser32.NewProc("AppendMenuW")
	dtSetMenuDefaultItem          = dtUser32.NewProc("SetMenuDefaultItem")
	dtTrackPopupMenu              = dtUser32.NewProc("TrackPopupMenu")
	dtDestroyMenu                 = dtUser32.NewProc("DestroyMenu")
	dtGetCursorPos                = dtUser32.NewProc("GetCursorPos")
	dtSetForegroundWindow         = dtUser32.NewProc("SetForegroundWindow")
	dtAllowSetForegroundWindow    = dtUser32.NewProc("AllowSetForegroundWindow")
	dtRegisterWindowMessageW      = dtUser32.NewProc("RegisterWindowMessageW")
	dtChangeWindowMessageFilterEx = dtUser32.NewProc("ChangeWindowMessageFilterEx")
	dtGetSystemMetrics            = dtUser32.NewProc("GetSystemMetrics")
	dtCreateIconFromResourceEx    = dtUser32.NewProc("CreateIconFromResourceEx")
	dtDestroyIcon                 = dtUser32.NewProc("DestroyIcon")
	dtFindWindowW                 = dtUser32.NewProc("FindWindowW")
	dtShowWindow                  = dtUser32.NewProc("ShowWindow")
	dtIsIconic                    = dtUser32.NewProc("IsIconic")
	dtGetWindowThreadProcessId    = dtUser32.NewProc("GetWindowThreadProcessId")
	dtGetModuleHandleW            = dtKernel32.NewProc("GetModuleHandleW")
	dtGetProcessMemoryInfo        = dtKernel32.NewProc("K32GetProcessMemoryInfo")
)

const (
	wmNull            = 0x0000
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmContextMenu     = 0x007b
	wmSetIcon         = 0x0080
	wmLButtonUp       = 0x0202
	wmRButtonUp       = 0x0205
	wmTrayCallback    = 0x8001 // WM_APP+1
	wmTrayRefresh     = 0x8002
	wmTrayClose       = 0x8003
	ninBalloonClick   = 0x0405 // NIN_BALLOONUSERCLICK

	nimAdd     = 0
	nimModify  = 1
	nimDelete  = 2
	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04
	nifInfo    = 0x10
	niifInfo   = 0x01

	mfString    = 0x0000
	mfChecked   = 0x0008
	mfPopup     = 0x0010
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020
	tpmNoNotify    = 0x0080
	tpmReturnCmd   = 0x0100

	swShow    = 5
	swRestore = 9

	smCxSmIcon = 49

	processVMRead       = 0x0010
	processQueryLimited = 0x1000
	createNoWindow      = 0x08000000

	exitNoWebView = 3 // the window process opened the browser instead
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

// notifyIconData is NOTIFYICONDATAW (976 bytes on amd64, 956 on 386).
type notifyIconData struct {
	Size             uint32
	Wnd              uintptr
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             uintptr
	Tip              [128]uint16
	State            uint32
	StateMask        uint32
	Info             [256]uint16
	TimeoutOrVersion uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GUIDItem         [16]byte
	BalloonIcon      uintptr
}

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
	Private uint32
}

func wstr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("")
	}
	return p
}

// copyW copies s into a fixed UTF-16 buffer, cut to fit, zero-terminated.
func copyW(dst []uint16, s string) {
	u := utf16.Encode([]rune(s))
	if len(u) > len(dst)-1 {
		u = u[:len(dst)-1]
	}
	dst[copy(dst, u)] = 0
}

// ---- tray icon ----

type trayItem struct {
	id         int
	text       string
	sep, check bool
	bold       bool
	children   []trayItem
}

type tray struct {
	menu      func() []trayItem
	onClick   func()
	onCommand func(id int)
	onEnd     func()

	hwnd       uintptr
	taskbarMsg uintptr
	icons      map[uint32]uintptr // by colour; tray thread only
	added      atomic.Bool        // the icon is in the notification area
	endOnce    sync.Once
	done       chan struct{}

	mu               sync.Mutex
	state, tip       string
	balTitle, balMsg string
}

var (
	theTray  *tray // the window procedure gets no user data; one tray per process
	trayProc uintptr
)

func (t *tray) start() {
	t.icons = map[uint32]uintptr{}
	t.done = make(chan struct{})
	ready := make(chan struct{})
	go t.run(ready)
	<-ready
}

// run owns the tray window: it lives on one locked OS thread with its own
// message loop, separate from everything else in the core.
func (t *tray) run(ready chan struct{}) {
	runtime.LockOSThread()
	defer close(t.done)
	inst, _, _ := dtGetModuleHandleW.Call(0)
	cls := wstr("PsirouteTray")
	if trayProc == 0 {
		trayProc = syscall.NewCallback(trayWndProc)
	}
	wc := wndClassEx{WndProc: trayProc, Instance: inst, ClassName: cls}
	wc.Size = uint32(unsafe.Sizeof(wc))
	dtRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	theTray = t
	// A hidden top-level window (not message-only): only those receive
	// TaskbarCreated and the end-of-session messages.
	h, _, _ := dtCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(wstr("Psiroute"))),
		0, 0, 0, 0, 0, 0, 0, inst, 0)
	if h == 0 {
		close(ready)
		return
	}
	t.hwnd = h
	t.taskbarMsg, _, _ = dtRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(wstr("TaskbarCreated"))))
	if t.taskbarMsg != 0 {
		dtChangeWindowMessageFilterEx.Call(h, t.taskbarMsg, 1, 0) // MSGFLT_ALLOW, for an elevated run
	}
	t.apply()
	close(ready)
	var m winMsg
	for {
		r, _, _ := dtGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		dtTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		dtDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	for _, ic := range t.icons {
		dtDestroyIcon.Call(ic)
	}
}

// iconBrand is the colour of the window icon (used only here, hence not in icon.go).
const iconBrand = 0x2783de

const wmPowerBroadcast = 0x0218

func trayWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	if t := theTray; t != nil && hwnd == t.hwnd {
		switch msg {
		case wmTrayCallback:
			switch lp & 0xffff {
			case wmLButtonUp, ninBalloonClick:
				goSafe("щелчок по значку", t.onClick)
			case wmRButtonUp, wmContextMenu:
				t.showMenu()
			}
			return 0
		case wmTrayRefresh:
			t.apply()
			return 0
		case wmPowerBroadcast:
			switch wp {
			case 4: // PBT_APMSUSPEND
				theNetWatch.suspended()
			case 7, 0x12: // PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC
				theNetWatch.Kick("resume")
			}
			return 1
		case wmTrayClose:
			t.remove()
			dtDestroyWindow.Call(hwnd)
			return 0
		case wmDestroy:
			dtPostQuitMessage.Call(0)
			return 0
		case wmQueryEndSession:
			return 1
		case wmEndSession:
			if wp != 0 {
				t.endOnce.Do(t.onEnd)
			}
			return 0
		}
		if t.taskbarMsg != 0 && msg == t.taskbarMsg {
			t.added.Store(false) // Explorer restarted: the icon is gone
			t.apply()
			return 0
		}
	}
	r, _, _ := dtDefWindowProcW.Call(hwnd, msg, wp, lp)
	return r
}

func buildPopupMenu(items []trayItem) uintptr {
	m, _, _ := dtCreatePopupMenu.Call()
	if m == 0 {
		return 0
	}
	for _, it := range items {
		if it.sep {
			dtAppendMenuW.Call(m, mfSeparator, 0, 0)
			continue
		}
		if len(it.children) > 0 {
			sub := buildPopupMenu(it.children)
			if sub != 0 {
				dtAppendMenuW.Call(m, mfPopup, sub, uintptr(unsafe.Pointer(wstr(it.text))))
			}
			continue
		}
		f := uintptr(mfString)
		if it.check {
			f |= mfChecked
		}
		dtAppendMenuW.Call(m, f, uintptr(it.id), uintptr(unsafe.Pointer(wstr(it.text))))
		if it.bold {
			dtSetMenuDefaultItem.Call(m, uintptr(it.id), 0)
		}
	}
	return m
}

func (t *tray) showMenu() {
	m := buildPopupMenu(t.menu())
	if m == 0 {
		return
	}
	defer dtDestroyMenu.Call(m)
	var pt struct{ X, Y int32 }
	dtGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	dtSetForegroundWindow.Call(t.hwnd) // otherwise the menu stays open after a click elsewhere
	cmd, _, _ := dtTrackPopupMenu.Call(m, tpmRightButton|tpmBottomAlign|tpmNoNotify|tpmReturnCmd,
		uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	dtPostMessageW.Call(t.hwnd, wmNull, 0, 0)
	if cmd != 0 {
		go t.onCommand(int(cmd))
	}
}

// apply puts the current icon, tooltip and pending balloon into the
// notification area (tray thread). It adds the icon when it is not there:
// at autostart the taskbar may not exist yet, and Explorer can restart.
func (t *tray) apply() {
	if t.hwnd == 0 {
		return
	}
	t.mu.Lock()
	state, tip, title, msg := t.state, t.tip, t.balTitle, t.balMsg
	t.mu.Unlock()
	if tip == "" {
		tip = "Psiroute"
	}
	nid := notifyIconData{Wnd: t.hwnd, ID: 1, Flags: nifMessage | nifIcon | nifTip, CallbackMessage: wmTrayCallback, Icon: t.icon(state)}
	nid.Size = uint32(unsafe.Sizeof(nid))
	copyW(nid.Tip[:], tip)
	if msg != "" {
		nid.Flags |= nifInfo
		nid.InfoFlags = niifInfo
		copyW(nid.InfoTitle[:], title)
		copyW(nid.Info[:], msg)
	}
	first, second := uintptr(nimAdd), uintptr(nimModify)
	if t.added.Load() {
		first, second = nimModify, nimAdd
	}
	r, _, _ := dtShellNotifyIconW.Call(first, uintptr(unsafe.Pointer(&nid)))
	if r == 0 {
		r, _, _ = dtShellNotifyIconW.Call(second, uintptr(unsafe.Pointer(&nid)))
	}
	t.added.Store(r != 0)
	if r != 0 && msg != "" {
		t.mu.Lock()
		if t.balMsg == msg {
			t.balTitle, t.balMsg = "", ""
		}
		t.mu.Unlock()
	}
}

func (t *tray) remove() {
	if !t.added.Load() {
		return
	}
	nid := notifyIconData{Wnd: t.hwnd, ID: 1}
	nid.Size = uint32(unsafe.Sizeof(nid))
	dtShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	t.added.Store(false)
}

func (t *tray) icon(state string) uintptr {
	c := iconColor(state)
	if h, ok := t.icons[c]; ok {
		return h
	}
	h := makeHIcon(trayIconSize(), c)
	if h != 0 {
		t.icons[c] = h
	}
	return h
}

// set updates the state colour and the tooltip (any goroutine).
func (t *tray) set(state, tip string) {
	t.mu.Lock()
	changed := state != t.state || tip != t.tip
	t.state, t.tip = state, tip
	t.mu.Unlock()
	if changed || !t.added.Load() {
		t.post(wmTrayRefresh)
	}
}

func (t *tray) balloon(title, msg string) {
	t.mu.Lock()
	t.balTitle, t.balMsg = title, msg
	t.mu.Unlock()
	t.post(wmTrayRefresh)
}

func (t *tray) post(msg uintptr) {
	if t.hwnd != 0 {
		dtPostMessageW.Call(t.hwnd, msg, 0, 0)
	}
}

func (t *tray) stop() {
	if t.hwnd == 0 {
		return
	}
	t.post(wmTrayClose)
	select {
	case <-t.done:
	case <-time.After(2 * time.Second):
	}
}

// trayIconSize: the icon is drawn at 32 px at least; the notification area
// scales it to its own size (16 px at 100 %, 24 at 150 %, 32 at 200 %).
func trayIconSize() int {
	if s, _, _ := dtGetSystemMetrics.Call(smCxSmIcon); int(s) > 32 {
		return int(s)
	}
	return 32
}

func makeHIcon(size int, rgb uint32) uintptr {
	img := iconImage(size, rgb)
	h, _, _ := dtCreateIconFromResourceEx.Call(uintptr(unsafe.Pointer(&img[0])), uintptr(len(img)),
		1, 0x00030000, uintptr(size), uintptr(size), 0)
	return h
}

func makeHIconFlag(size int, rgb uint32, cc string) uintptr {
	img := iconFlagImage(size, rgb, cc)
	h, _, _ := dtCreateIconFromResourceEx.Call(uintptr(unsafe.Pointer(&img[0])), uintptr(len(img)),
		1, 0x00030000, uintptr(size), uintptr(size), 0)
	return h
}

// ---- the core's desktop side: tray + window process ----

const (
	menuOpen = 1 + iota
	menuOpenWeb
	menuConnect
	menuPause5
	menuPause15
	menuPauseResume
	menuNewNode
	menuNextStrat
	menuRestartPsi
	menuSysProxy
	menuTun
	menuWarpToggle
	menuWarpReconn
	menuShareToggle
	menuDoHToggle
	menuModePsiphon
	menuModeRules
	menuModeAuto
	menuBypassLAN
	menuBlockQUIC
	menuDPIModeAuto
	menuDPIModeOff
	menuDPIModeTLSRec
	menuDPIModeSplit
	menuDPIModeDouble
	menuDPIModeMultiRec
	menuDPIModeChunk
	menuDPIReset
	menuProbeToggle
	menuDPITestToggle
	menuStopCountries
	menuRefreshLists
	menuClearDNS
	menuClearLearned
	menuReloadCfg
	menuMakeReport
	menuQuit
	menuCountryBase = 200
)

type desktop struct {
	a   *App
	dir string
	t   *tray
	mu  sync.Mutex
	win *exec.Cmd // the window process we started, while it runs
}

// runDesktop shows the tray icon (and the window, unless started for
// autostart) and returns when Psiroute is quitting.
func runDesktop(ctx context.Context, a *App, dir string, openNow bool) {
	d := &desktop{a: a, dir: dir}
	d.t = &tray{menu: d.menu, onClick: d.openWindow, onCommand: d.command, onEnd: d.endSession}
	d.t.start()
	d.refresh()
	if openNow {
		d.openWindow()
	}
	go d.watch(ctx)
	<-ctx.Done()
	d.closeWindows()
	d.t.stop()
}

func (d *desktop) watch(ctx context.Context) {
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			d.refresh()
		}
	}
}

func trayStateText(st string) string {
	switch st {
	case "connected":
		return "подключено"
	case "connecting":
		return "подключение…"
	case "reconnecting":
		return "переподключение…"
	case "error":
		return "ошибка подключения"
	}
	return "отключено"
}

// refresh: icon colour by Psiphon state; tooltip with the exit country and
// the memory in use.
func (d *desktop) refresh() {
	v := d.a.psi.view()
	st, _ := v["state"].(string)
	tip := "Psiroute " + version + ": " + trayStateText(st)
	if r, _ := v["egress_region"].(string); st == "connected" && r != "" {
		tip += ", " + r
	}
	if tv := d.a.tun.view(); tv["on"] == true {
		tip += " · TUN"
	}
	m := memView()
	tip += "\nПамять: " + mbText(m.App+m.Workers)
	if m.Window > 0 {
		tip += " + окно " + mbText(m.Window)
	}
	d.t.set(st, tip)
}

func (d *desktop) menu() []trayItem {
	d.a.mu.Lock()
	sys := d.a.sysOn
	shareOn := d.a.shareLn != nil
	d.a.mu.Unlock()

	d.a.cfg.mu.Lock()
	mode := d.a.cfg.Routing.Mode
	bypassLAN := d.a.cfg.Routing.BypassLAN
	blockQUIC := d.a.cfg.Routing.BlockQUIC
	warpOn := d.a.cfg.Warp.Enabled
	dnsOn := d.a.cfg.DNS.Enabled
	curCountry := strings.ToUpper(d.a.cfg.Psiphon.Country)
	d.a.cfg.mu.Unlock()

	tv := d.a.tun.view()
	tunOn, _ := tv["on"].(bool)
	dpiMode := d.a.dpiMode()

	conn := "Подключить Psiphon"
	if d.a.psi.running() {
		conn = "Отключить Psiphon"
	}

	var countryItems []trayItem
	for i, cc := range nativeCountries {
		countryItems = append(countryItems, trayItem{
			id:    menuCountryBase + i,
			text:  nativeCountryNames[i],
			check: curCountry == cc,
		})
	}

	probeTxt := "Запустить автоподбор обхода Psiphon"
	if d.a.isProbeRunning() {
		probeTxt = "Остановить автоподбор обхода Psiphon"
	}

	return []trayItem{
		{id: menuOpen, text: "Открыть окно Psiroute (Нативный UI)", bold: true},
		{id: menuOpenWeb, text: "Открыть веб-панель в браузере"},
		{sep: true},
		{id: menuConnect, text: conn},
		{id: menuPause5, text: "Пауза защиты на 5 минут", check: d.a.IsPaused() && d.a.PauseRemainingSec() <= 300},
		{id: menuPause15, text: "Пауза защиты на 15 минут", check: d.a.IsPaused() && d.a.PauseRemainingSec() > 300},
		{id: menuPauseResume, text: "Возобновить защиту сейчас", check: !d.a.IsPaused()},
		{id: menuNewNode, text: "Сменить узел Psiphon"},
		{id: menuNextStrat, text: "Следующий способ подключения"},
		{sep: true},
		{id: menuSysProxy, text: "Системный прокси Windows", check: sys},
		{id: menuTun, text: "Режим TUN (весь ПК)", check: tunOn},
		{id: menuWarpToggle, text: "Cloudflare WARP (подложка)", check: warpOn},
		{id: menuShareToggle, text: "Раздача в LAN (Телефон / ТВ)", check: shareOn},
		{sep: true},
		{text: "Режим маршрутизации", children: []trayItem{
			{id: menuModePsiphon, text: "Весь трафик через Psiphon", check: mode == "psiphon"},
			{id: menuModeRules, text: "Умный режим (по правилам)", check: mode == "rules"},
			{id: menuModeAuto, text: "Авто-обход (Direct → DPI → Psiphon)", check: mode == "auto"},
			{sep: true},
			{id: menuBypassLAN, text: "Локальная сеть всегда напрямую (Bypass LAN)", check: bypassLAN},
			{id: menuBlockQUIC, text: "Блокировать QUIC (UDP 443) для браузеров", check: blockQUIC},
		}},
		{text: "Страна выхода Psiphon", children: countryItems},
		{text: "Обход DPI и тесты", children: []trayItem{
			{id: menuDPIModeAuto, text: "Авто (запоминание и повтор)", check: dpiMode == "auto"},
			{id: menuDPIModeOff, text: "Выключен", check: dpiMode == "off"},
			{id: menuDPIModeTLSRec, text: "2 TLS-записи (tlsrec)", check: dpiMode == "tlsrec"},
			{id: menuDPIModeSplit, text: "Разрез TCP (split)", check: dpiMode == "split"},
			{id: menuDPIModeDouble, text: "Записи + разрез (double)", check: dpiMode == "double"},
			{id: menuDPIModeMultiRec, text: "Много записей (multirec)", check: dpiMode == "multirec"},
			{id: menuDPIModeChunk, text: "Мелкие куски (chunk)", check: dpiMode == "chunk"},
			{sep: true},
			{id: menuDPIReset, text: "Сбросить статистику DPI"},
			{id: menuProbeToggle, text: probeTxt},
			{id: menuDPITestToggle, text: "Запустить тест методов DPI"},
		}},
		{text: "Процессы и обслуживание", children: []trayItem{
			{id: menuRestartPsi, text: "Перезапустить Psiphon"},
			{id: menuWarpReconn, text: "Переоткрыть поток WARP"},
			{id: menuDoHToggle, text: "Шифрованный DNS (DoH)", check: dnsOn},
			{id: menuStopCountries, text: "Остановить фоновые процессы стран"},
			{id: menuRefreshLists, text: "Обновить списки доменов"},
			{sep: true},
			{id: menuClearDNS, text: "Очистить кэш DNS"},
			{id: menuClearLearned, text: "Забыть выученные маршруты"},
			{id: menuReloadCfg, text: "Перечитать настройки (psiroute.json)"},
			{id: menuMakeReport, text: "Сохранить диагностический отчёт (.zip)"},
		}},
		{sep: true},
		{id: menuQuit, text: "Выход"},
	}
}

func (d *desktop) command(id int) {
	if id >= menuCountryBase && id < menuCountryBase+len(nativeCountries) {
		reg := nativeCountries[id-menuCountryBase]
		d.a.cfg.mu.Lock()
		d.a.cfg.Psiphon.Country = reg
		d.a.cfg.mu.Unlock()
		_ = d.a.cfg.save()
		d.a.restartIfRunning()
		d.refresh()
		return
	}
	switch id {
	case menuOpen:
		d.openWindow()
	case menuOpenWeb:
		openBrowser(d.a.uiURL())
	case menuConnect:
		if d.a.psi.running() {
			d.a.psi.Stop()
		} else {
			d.a.psi.Start()
		}
	case menuPause5:
		d.a.SetPause(5)
	case menuPause15:
		d.a.SetPause(15)
	case menuPauseResume:
		d.a.SetPause(0)
	case menuNewNode:
		d.a.psi.NewNode()
	case menuNextStrat:
		d.a.psi.Next()
	case menuRestartPsi:
		go d.a.psi.Restart()
	case menuSysProxy:
		d.a.mu.Lock()
		on := !d.a.sysOn
		d.a.mu.Unlock()
		if err := d.a.setSysProxy(on); err != nil {
			logf("warn", "Системный прокси: %v", err)
		}
	case menuTun:
		tv := d.a.tun.view()
		on, _ := tv["on"].(bool)
		if !on && !isElevated() {
			if err := d.a.relaunchForTun(); err == nil {
				time.Sleep(500 * time.Millisecond)
				d.a.cancel()
				return
			}
		} else if err := d.a.setTun(!on); err != nil {
			logf("warn", "Режим TUN: %s", tunErrText(err))
		}
	case menuWarpToggle:
		d.a.cfg.mu.Lock()
		on := !d.a.cfg.Warp.Enabled
		d.a.cfg.mu.Unlock()
		restarted := d.a.cfg.setKey("warp.enabled", on) && d.a.restartIfRunning()
		_ = d.a.cfg.save()
		if on && !restarted {
			d.a.warp.Want()
		}
	case menuWarpReconn:
		d.a.warp.Reconnect()
	case menuShareToggle:
		d.a.mu.Lock()
		on := d.a.shareLn == nil
		d.a.mu.Unlock()
		_ = d.a.setShare(on)
	case menuDoHToggle:
		d.a.cfg.mu.Lock()
		on := !d.a.cfg.DNS.Enabled
		d.a.cfg.mu.Unlock()
		d.a.cfg.setKey("dns.enabled", on)
		_ = d.a.cfg.save()
	case menuModePsiphon:
		d.a.cfg.mu.Lock()
		d.a.cfg.Routing.Mode = "psiphon"
		d.a.cfg.mu.Unlock()
		_ = d.a.cfg.save()
	case menuModeRules:
		d.a.cfg.mu.Lock()
		d.a.cfg.Routing.Mode = "rules"
		d.a.cfg.mu.Unlock()
		_ = d.a.cfg.save()
	case menuModeAuto:
		d.a.cfg.mu.Lock()
		d.a.cfg.Routing.Mode = "auto"
		d.a.cfg.mu.Unlock()
		_ = d.a.cfg.save()
	case menuBypassLAN:
		d.a.cfg.mu.Lock()
		on := !d.a.cfg.Routing.BypassLAN
		d.a.cfg.mu.Unlock()
		d.a.cfg.setKey("routing.bypass_lan", on)
		_ = d.a.cfg.save()
	case menuBlockQUIC:
		d.a.cfg.mu.Lock()
		on := !d.a.cfg.Routing.BlockQUIC
		d.a.cfg.mu.Unlock()
		d.a.cfg.setKey("routing.block_quic", on)
		_ = d.a.cfg.save()
	case menuDPIModeAuto:
		_ = d.a.dpiSetMode("auto")
	case menuDPIModeOff:
		_ = d.a.dpiSetMode("off")
	case menuDPIModeTLSRec:
		_ = d.a.dpiSetMode("tlsrec")
	case menuDPIModeSplit:
		_ = d.a.dpiSetMode("split")
	case menuDPIModeDouble:
		_ = d.a.dpiSetMode("double")
	case menuDPIModeMultiRec:
		_ = d.a.dpiSetMode("multirec")
	case menuDPIModeChunk:
		_ = d.a.dpiSetMode("chunk")
	case menuDPIReset:
		obfs.reset()
	case menuProbeToggle:
		if d.a.isProbeRunning() {
			d.a.stopProbe()
		} else {
			_ = d.a.startProbe()
		}
	case menuDPITestToggle:
		_ = d.a.dpiTestStart(d.a.dpiSites())
	case menuStopCountries:
		d.a.countries.StopAll()
	case menuRefreshLists:
		d.a.lists.Refresh()
	case menuClearDNS:
		theDNS.clear()
	case menuClearLearned:
		d.a.router.clearLearned()
	case menuReloadCfg:
		d.a.reloadConfig()
	case menuMakeReport:
		go func() {
			ctx, cancel := context.WithTimeout(d.a.ctx, 90*time.Second)
			defer cancel()
			if path, err := d.a.makeReport(ctx); err == nil {
				revealFile(path)
			}
		}()
	case menuQuit:
		d.a.cancel()
		return
	}
	d.refresh()
}

// endSession: Windows is shutting down or the user is logging off, and the
// process will be killed right after. The one thing that must not be left
// behind is the system proxy pointing at a port nobody listens on. The
// setting itself stays on and is applied again at the next start.
func (d *desktop) endSession() {
	d.a.mu.Lock()
	sys := d.a.sysOn
	d.a.mu.Unlock()
	if sys {
		_ = setSystemProxy(d.a.listenAddr(), false)
	}
	d.a.router.flush()
}

// openWindow brings the window to the front, or starts the window process.
func (d *desktop) openWindow() {
	if h := findAppWindow(); h != 0 {
		focusWindow(h)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.win != nil {
		return // still starting
	}
	url := d.a.uiURL()
	exe, err := os.Executable()
	if err != nil {
		openBrowser(url)
		return
	}
	cmd := exec.Command(exe, "--window", url, "--parent", strconv.Itoa(os.Getpid()))
	// No console for a console build. Not HideWindow: that would also hide
	// the window itself (its first ShowWindow takes the STARTUPINFO value).
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		logf("warn", "Окно не открылось (%v) — открываю интерфейс в браузере", err)
		openBrowser(url)
		return
	}
	dtAllowSetForegroundWindow.Call(uintptr(cmd.Process.Pid))
	d.win = cmd
	go func() {
		_ = cmd.Wait()
		d.mu.Lock()
		d.win = nil
		d.mu.Unlock()
		d.windowClosed(cmd.ProcessState.ExitCode())
	}()
}

func (d *desktop) windowClosed(code int) {
	if d.a.ctx.Err() != nil || code == exitNoWebView {
		return
	}
	if !d.t.added.Load() {
		// No tray icon to bring the window back from: closing the window
		// quits, as before 1.0.6.
		d.a.cancel()
		return
	}
	marker := filepath.Join(d.dir, "psiroute.tray")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	_ = os.WriteFile(marker, []byte("1"), 0o600)
	d.t.balloon("Psiroute работает в фоне",
		"Окно закрыто, Psiphon продолжает работать в трее. Открыть — щелчок по значку, все процессы и выход — правой кнопкой.")
}

// closeWindows closes every Psiroute window (also one opened by a second
// launch) when the core quits.
func (d *desktop) closeWindows() {
	for i := 0; i < 10; i++ {
		h := findAppWindow()
		if h == 0 {
			break
		}
		dtPostMessageW.Call(h, wmClose, 0, 0)
		time.Sleep(150 * time.Millisecond)
	}
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		d.mu.Lock()
		c := d.win
		d.mu.Unlock()
		if c == nil {
			return
		}
	}
	d.mu.Lock()
	if d.win != nil && d.win.Process != nil {
		_ = d.win.Process.Kill()
	}
	d.mu.Unlock()
}

// ---- windows of the window process ----

func findAppWindow() uintptr {
	h, _, _ := dtFindWindowW.Call(0, uintptr(unsafe.Pointer(wstr(windowTitle))))
	return h
}

func focusWindow(h uintptr) {
	if r, _, _ := dtIsIconic.Call(h); r != 0 {
		dtShowWindow.Call(h, swRestore)
	} else {
		dtShowWindow.Call(h, swShow)
	}
	dtSetForegroundWindow.Call(h)
}

// setWindowIcon gives our window (title bar, taskbar, Alt+Tab) the drawn icon.
func setWindowIcon() {
	setWindowIconState("", "")
}

func setWindowIconState(state, cc string) {
	h := findAppWindow()
	if h == 0 {
		return
	}
	var pid uint32
	dtGetWindowThreadProcessId.Call(h, uintptr(unsafe.Pointer(&pid)))
	if pid != uint32(os.Getpid()) {
		return
	}
	var big, small uintptr
	if state == "connected" && cc != "" && cc != "auto" {
		col := iconColor("connected")
		big = makeHIconFlag(48, col, cc)
		small = makeHIconFlag(trayIconSize(), col, cc)
	} else {
		col := uint32(iconBrand)
		if state == "connected" {
			col = iconColor("connected")
		}
		big = makeHIcon(48, col)
		small = makeHIcon(trayIconSize(), col)
	}
	if big != 0 {
		dtSendMessageW.Call(h, wmSetIcon, 1, big) // ICON_BIG
	}
	if small != 0 {
		dtSendMessageW.Call(h, wmSetIcon, 0, small) // ICON_SMALL
	}
}

// ---- memory of the process tree ----

// processMemoryCounters is PROCESS_MEMORY_COUNTERS_EX2. Windows versions
// without the _EX2 part leave PrivateWorkingSetSize at zero or reject the
// size; then the private commit (_EX) is used.
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
	PrivateWorkingSetSize      uintptr
	SharedCommitUsage          uint64
}

// processMemory: the private working set, Task Manager's "Memory" column.
func processMemory(pid uint32) (uint64, bool) {
	h, err := syscall.OpenProcess(processQueryLimited|processVMRead, false, pid)
	if err != nil {
		if h, err = syscall.OpenProcess(processQueryLimited, false, pid); err != nil {
			return 0, false
		}
	}
	defer syscall.CloseHandle(h)
	var c processMemoryCounters
	c.CB = uint32(unsafe.Sizeof(c))
	r, _, _ := dtGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.CB))
	if r == 0 {
		c = processMemoryCounters{}
		c.CB = uint32(unsafe.Offsetof(c.PrivateWorkingSetSize))
		if r, _, _ = dtGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.CB)); r == 0 {
			return 0, false
		}
	}
	if c.PrivateWorkingSetSize > 0 {
		return uint64(c.PrivateWorkingSetSize), true
	}
	return uint64(c.PrivateUsage), true
}

// procTreeMemory: this process, the window (wherever it was started from),
// and our other child processes.
func procTreeMemory() memSnap {
	var s memSnap
	self := uint32(os.Getpid())
	s.App, _ = processMemory(self)
	if watchdogPID > 0 {
		s.Watchdog, _ = processMemory(uint32(watchdogPID))
	}
	var winPID uint32
	if h := findAppWindow(); h != 0 {
		dtGetWindowThreadProcessId.Call(h, uintptr(unsafe.Pointer(&winPID)))
	}
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return s
	}
	defer syscall.CloseHandle(snap)
	kids := map[uint32][]uint32{}
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err := syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		if e.ProcessID != 0 && e.ProcessID != e.ParentProcessID {
			kids[e.ParentProcessID] = append(kids[e.ParentProcessID], e.ProcessID)
		}
	}
	seen := map[uint32]bool{self: true}
	var tree func(pid uint32) (int, uint64)
	tree = func(pid uint32) (n int, b uint64) {
		if seen[pid] {
			return 0, 0
		}
		seen[pid] = true
		n = 1
		b, _ = processMemory(pid)
		for _, k := range kids[pid] {
			kn, kb := tree(k)
			n += kn
			b += kb
		}
		return n, b
	}
	if winPID != 0 {
		s.WindowN, s.Window = tree(winPID)
	}
	for _, k := range kids[self] {
		n, b := tree(k)
		s.WorkersN += n
		s.Workers += b
	}
	return s
}
