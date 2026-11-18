//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gioui.org/app"
	"gioui.org/font"
	"gioui.org/font/opentype"
	"gioui.org/io/event"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

type gioUI struct {
	w            *app.Window
	th           *material.Theme
	pal          gioPalette
	apiBase      string
	token        string
	dataDir      string
	narrowWindow bool

	mu           sync.Mutex
	state        map[string]any
	apps         []map[string]any
	presets      []map[string]any
	rulesData    map[string]any
	diagRes      map[string]any
	psiStatsData map[string]any
	statusToast       string
	toastErr          bool
	toastUntil        time.Time
	pendingTheme      string
	pendingEditorText map[*widget.Editor]string
	powerBusy         atomic.Bool

	// Navigation tabs (5 разделов):
	// 0=Главная, 1=Маршруты, 2=Потоки (активна только при клике), 3=Сеть, 4=Журнал и Система
	tab                 int
	navBtns             [5]widget.Clickable
	subTabs             [5]int
	subTabBtns          [5][3]widget.Clickable
	rulesTemplatesOpen  bool
	streamsPaused       bool
	streamRuleForApp    bool
	streamSearchEditor  widget.Editor
	recentStreams       []map[string]any
	frozenLiveStreams   []map[string]any
	frozenRecentStreams []map[string]any
	cachedLogs          []map[string]any
	logLevelFilter      int
	lastIconState       string
	lastIconCC          string
	webBtn     widget.Clickable
	quitBtn    widget.Clickable
	keyTag     bool

	// Scroll lists
	mainList        widget.List
	appList         widget.List
	ruleList        widget.List
	connList        widget.List
	logList         widget.List
	rulesPageList   widget.List
	dpiPageList     widget.List
	devicesPageList widget.List
	diagPageList    widget.List
	setPageList     widget.List

	// Home & Process controls
	powerBtn        widget.Clickable
	newNodeBtn      widget.Clickable
	moreMenuBtn     widget.Clickable
	homeMenuOpen    bool
	allCountriesBtn widget.Clickable
	nextStratBtn    widget.Clickable
	restartPsiBtn   widget.Clickable
	speedTestBtn    widget.Clickable
	modeBtns        [3]widget.Clickable
	sysProxyBtn     widget.Clickable
	tunBtn          widget.Clickable
	tunAdminBtn     widget.Clickable
	warpBtn         widget.Clickable
	warpReconnBtn   widget.Clickable
	shareBtn        widget.Clickable
	dohBtn          widget.Clickable
	localDNSBtn     widget.Clickable
	fakeIPBtn       widget.Clickable
	bypassLANBtn    widget.Clickable
	blockQUICBtn    widget.Clickable
	killSwitchBtn   widget.Clickable
	blockSTUNBtn    widget.Clickable
	singleProcBtn   widget.Clickable
	stopCountryBtn  widget.Clickable
	refreshListBtn  widget.Clickable
	clearDNSBtn     widget.Clickable
	clearLearnBtn   widget.Clickable
	probeBtn        widget.Clickable
	dpiTestBtn      widget.Clickable
	selftestBtn     widget.Clickable
	reportBtn       widget.Clickable
	shareQuickBtn   widget.Clickable

	// App routing (Split Tunneling)
	appTabFilter  int // 0=Running & Active, 1=Popular Catalog
	appTabBtns    [2]widget.Clickable
	appRefreshBtn widget.Clickable
	appSearch     widget.Editor
	lastAppQ      string
	appActionBtns map[string]*widget.Clickable

	// Home Dashboard («Командный центр» 1040x680 без прокрутки)
	connectingStart  time.Time
	pipeCaptureBtn   widget.Clickable
	pipeWarpBtn      widget.Clickable
	pipePsiBtn       widget.Clickable
	pipePopup        int // 0=none, 1=capture selector, 2=country selector
	captureModeBtns  [3]widget.Clickable
	tunBannerBtn     widget.Clickable
	repairConnBtn    widget.Clickable
	pause5Btn        widget.Clickable
	pause15Btn       widget.Clickable
	pauseResumeBtn   widget.Clickable
	captiveOpenBtn   widget.Clickable
	privacyBtn       widget.Clickable
	privacyMode      bool
	homeRuleEditor   widget.Editor
	homeRuleOb       string
	homeRuleObBtns   [5]widget.Clickable
	homeRuleAddBtn   widget.Clickable
	homeCheckBtn     widget.Clickable
	homeRoutePreview string
	lastHomeQuery    string
	lastHomeCheckAt  time.Time
	themeToggleBtn   widget.Clickable
	liveAppBtns      [4]widget.Clickable
	liveAppNames     [4]string
	liveAppRoutes    [4]string
	liveAppHosts     [4]string
	liveAppAlerts    [4]bool
	resetStatsBtn    widget.Clickable

	// Rules Constructor
	ruleFilterEditor      widget.Editor
	batchRuleEditor       widget.Editor
	batchImportBtn        widget.Clickable
	ruleNameEditor        widget.Editor
	hostEditor            widget.Editor
	selectedRuleOb        string
	selectedProto         string
	ruleAlways            bool
	editingRuleIdx        int
	ruleObBtns            [10]widget.Clickable
	ruleProtoBtns         [3]widget.Clickable
	ruleAlwaysBtn         widget.Clickable
	ruleCancelBtn         widget.Clickable
	checkRouteBtn         widget.Clickable
	lastRuleCheckQuery    string
	lastRuleCheckAt       time.Time
	ruleInspectorPreview  string
	ruleInspectorConflict string
	addRuleBtn            widget.Clickable
	presetRuleBtns        [8]widget.Clickable
	listPickBtns          [12]widget.Clickable
	listUseBtns           map[string]*widget.Clickable
	profileBtns           [5]widget.Clickable
	undoProfileBtn        widget.Clickable
	ruleToggleBtns        map[int]*widget.Clickable
	ruleDeleteBtns        map[int]*widget.Clickable
	ruleEditBtns          map[int]*widget.Clickable
	editingRuleOriginal   map[string]any
	ruleUpBtns            map[int]*widget.Clickable
	ruleDownBtns          map[int]*widget.Clickable

	// Lists Manager (Stage 1 & Stage 3)
	listActionBtns         map[string]*widget.Clickable
	listSearchEditor       widget.Editor
	listGroupFilter        int // 0=Все, 1=Мои, 2=Встроенные, 3=Скрытые
	listGroupBtns          [4]widget.Clickable
	listRestoreBuiltinBtn  widget.Clickable
	listNewBtn             widget.Clickable
	listFormOpen           bool
	listEditID             string
	listSourceMode         int // 0=Text, 1=URL, 2=File
	listSourceModeBtns     [3]widget.Clickable
	listIDEditor           widget.Editor
	listTitleEditor        widget.Editor
	listURLEditor          widget.Editor
	listFilePathEditor     widget.Editor
	listLoadFileBtn        widget.Clickable
	listContentEditor      widget.Editor // multiline editor (SingleLine = false)
	listPreviewBtn         widget.Clickable
	listSaveBtn            widget.Clickable
	listCancelBtn          widget.Clickable
	listPreviewData        map[string]any
	listDeleteConfirmID    string
	listDeleteConfirmTitle string
	listDeleteUsedRules    []string
	listDeleteForceBtn     widget.Clickable
	listDeleteCancelBtn    widget.Clickable
	listTrustConfirmHost   string
	listTrustApproveBtn    widget.Clickable
	listTrustCancelBtn     widget.Clickable

	// Countries, DPI & WARP Mask
	countryBtns    [28]widget.Clickable
	favCountryBtns [28]widget.Clickable
	favStarBtns    [28]widget.Clickable
	dpiModeBtns  [7]widget.Clickable
	warpMaskBtns [5]widget.Clickable

	// Diagnostics, Psiphon Stats & Server Entries Import
	diagEditor          widget.Editor
	diagRunBtn          widget.Clickable
	diagConnFilter      int
	diagFilterBtns      [3]widget.Clickable
	serverEntriesEditor widget.Editor
	importEntriesBtn    widget.Clickable
	connPsiBtns         map[string]*widget.Clickable

	// Clipboard, Editor Focus/Paste & LAN Share
	copyBtns  map[string]*widget.Clickable
	pasteBtns map[string]*widget.Clickable
	focusBtns map[string]*widget.Clickable
	copiedKey string
	copiedAt  time.Time
	shareInfo map[string]any
}

var navTitles = [5]string{
	"Главная",
	"Маршруты",
	"Потоки",
	"Сеть",
	"Журнал",
}

var navHints = [5]string{
	"Командный центр: питание (с флагом страны), схема захвата, глобальный сценарий и живой омнибокс",
	"Умные маршруты по 4 уровням приоритета ядра, раздельное туннелирование программ (.exe) и каталог списков",
	"Живые потоки и подключения (вкладка активна только когда открыта) — назначение правил в 1 клик",
	"Выбор страны выхода Psiphon, авто-тюнинг обхода DPI, параметры Cloudflare WARP и раздача в LAN",
	"Полноэкранный живой журнал событий (без обрезки), настройки DNS/FakeIP и глубокая диагностика",
}

// loadWindowsSystemFonts загружает системные шрифты Windows (Segoe UI / Consolas) напрямую с диска,
// избавляя бинарник от встраивания пакета gioui.org/font/gofont (~1.8 МБ экономии .exe и ОЗУ).
func loadWindowsSystemFonts() []font.FontFace {
	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = `C:\Windows`
	}
	fontDir := filepath.Join(winDir, "Fonts")
	candidates := []struct {
		file    string
		weight  font.Weight
		style   font.Style
		variant string
	}{
		{"segoeui.ttf", font.Normal, font.Regular, ""},
		{"seguisb.ttf", font.SemiBold, font.Regular, ""},
		{"segoeuib.ttf", font.Bold, font.Regular, ""},
		{"consola.ttf", font.Normal, font.Regular, "Mono"},
		{"arial.ttf", font.Normal, font.Regular, ""},
	}
	var collection []font.FontFace
	for _, c := range candidates {
		b, err := os.ReadFile(filepath.Join(fontDir, c.file))
		if err != nil || len(b) == 0 {
			continue
		}
		faces, err := opentype.ParseCollection(b)
		if err != nil {
			continue
		}
		for _, f := range faces {
			f.Font.Weight = c.weight
			f.Font.Style = c.style
			collection = append(collection, f)
			// Дублируем дескриптор шрифта для Typeface "Go" и "Go Mono", которые использует material.NewTheme()
			alias := f
			if c.variant == "Mono" {
				alias.Font.Typeface = "Go Mono"
			} else {
				alias.Font.Typeface = "Go"
			}
			collection = append(collection, alias)
		}
	}
	return collection
}

var guiHTTP = &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{
	Proxy:               nil,
	MaxIdleConns:        2,
	MaxIdleConnsPerHost: 2,
	IdleConnTimeout:     30 * time.Second,
	DisableCompression:  true,
}}

var guiHidden atomic.Bool

func runGioWindow(dataDir, uiURL string, parentPID int) {
	apiBase, token := resolveAPIConfig(dataDir, uiURL)
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(loadWindowsSystemFonts()))

	ui := &gioUI{
		th:             th,
		pal:            paletteFor(true),
		apiBase:        apiBase,
		token:          token,
		dataDir:        dataDir,
		homeRuleOb:     obPsiphon,
		selectedRuleOb: obPsiphon,
		ruleAlways:     true,
		editingRuleIdx: -1,
		pendingEditorText: map[*widget.Editor]string{},
		appActionBtns:     map[string]*widget.Clickable{},
		listUseBtns:    map[string]*widget.Clickable{},
		listActionBtns: map[string]*widget.Clickable{},
		ruleToggleBtns: map[int]*widget.Clickable{},
		ruleDeleteBtns: map[int]*widget.Clickable{},
		ruleEditBtns:   map[int]*widget.Clickable{},
		ruleUpBtns:     map[int]*widget.Clickable{},
		ruleDownBtns:   map[int]*widget.Clickable{},
		connPsiBtns:    map[string]*widget.Clickable{},
		copyBtns:       map[string]*widget.Clickable{},
		pasteBtns:      map[string]*widget.Clickable{},
		focusBtns:      map[string]*widget.Clickable{},
	}
	ui.mainList.List.Axis = layout.Vertical
	ui.rulesPageList.List.Axis = layout.Vertical
	ui.dpiPageList.List.Axis = layout.Vertical
	ui.devicesPageList.List.Axis = layout.Vertical
	ui.diagPageList.List.Axis = layout.Vertical
	ui.setPageList.List.Axis = layout.Vertical
	ui.appList.List.Axis = layout.Vertical
	ui.ruleList.List.Axis = layout.Vertical
	ui.connList.List.Axis = layout.Vertical
	ui.logList.List.Axis = layout.Vertical

	ui.ruleNameEditor.SingleLine = true
	ui.homeRuleEditor.SingleLine = true
	ui.ruleFilterEditor.SingleLine = true
	ui.batchRuleEditor.SingleLine = false
	ui.appSearch.SingleLine = true
	ui.hostEditor.SingleLine = true
	ui.hostEditor.SetText("youtube.com")
	ui.diagEditor.SingleLine = true
	ui.diagEditor.SetText("www.youtube.com")
	ui.serverEntriesEditor.SingleLine = true
	ui.streamSearchEditor.SingleLine = true

	// Lists editors: multiline for listContentEditor, single-line for metadata
	ui.listSearchEditor.SingleLine = true
	ui.listIDEditor.SingleLine = true
	ui.listTitleEditor.SingleLine = true
	ui.listURLEditor.SingleLine = true
	ui.listFilePathEditor.SingleLine = true
	ui.listContentEditor.SingleLine = false

	go func() {
		w := new(app.Window)
		w.Option(
			app.Title(windowTitle),
			app.Size(unit.Dp(1080), unit.Dp(700)),
			app.MinSize(unit.Dp(960), unit.Dp(640)),
		)
		ui.w = w
		setWindowIcon()

		if parentPID > 0 {
			if p, err := os.FindProcess(parentPID); err == nil {
				go func() {
					_, _ = p.Wait()
					os.Exit(0)
				}()
			}
		}

		stopPoll := make(chan struct{})
		go ui.pollLoop(stopPoll)

		defer func() {
			if r := recover(); r != nil {
				msg := fmt.Sprintf("panic в окне Gio: %v\n%s\n", r, debug.Stack())
				_ = os.WriteFile(filepath.Join(dataDir, "window-crash.log"), []byte(msg), 0o600)
			}
		}()

		var ops op.Ops
		for {
			switch e := w.Event().(type) {
			case app.DestroyEvent:
				close(stopPoll)
				os.Exit(0)
				return
			case app.ConfigEvent:
				minimized := e.Config.Mode == app.Minimized
				wasHidden := guiHidden.Swap(minimized)
				if minimized && !wasHidden {
					go ReleaseGUIMemory()
				}
			case app.FrameEvent:
				ops.Reset()
				gtx := app.NewContext(&ops, e)
				func() {
					defer func() {
						if r := recover(); r != nil {
							msg := fmt.Sprintf("panic в FrameEvent: %v\n%s\n", r, debug.Stack())
							_ = os.WriteFile(filepath.Join(dataDir, "window-crash.log"), []byte(msg), 0o600)
							ui.setToast(fmt.Sprintf("Ошибка отрисовки: %v", r), true)
						}
					}()
					ui.Layout(gtx)
				}()
				e.Frame(gtx.Ops)
			}
		}
	}()
	app.Main()
}

func (ui *gioUI) pollLoop(stop <-chan struct{}) {
	ui.fetchAll(true)
	tk := time.NewTicker(1200 * time.Millisecond)
	defer tk.Stop()
	tick := 0
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			tick++
			if guiHidden.Load() && tick%8 != 0 {
				continue
			}
			ui.fetchAll(tick%4 == 0)
		}
	}
}

func (ui *gioUI) fetchAll(full bool) {
	ui.mu.Lock()
	curTab := ui.tab
	streamsPaused := ui.streamsPaused
	ui.mu.Unlock()
	statePath := "/api/state?compact=1"
	if full || curTab == 4 {
		statePath = "/api/state"
	}
	st, err := ui.apiCall("GET", statePath, nil)
	if err == nil && st != nil {
		ui.mu.Lock()
		newLogs := toMapSlice(st["log"])
		if len(newLogs) > 0 {
			ui.cachedLogs = newLogs
		} else if len(ui.cachedLogs) > 0 {
			st["log"] = ui.cachedLogs
		}
		ui.state = st
		if thm, ok := st["ui_theme"].(string); ok && thm != "" {
			ui.pendingTheme = thm
		}
		psiMap, _ := st["psiphon"].(map[string]any)
		pState, _ := psiMap["state"].(string)
		cc, _ := psiMap["egress_region"].(string)
		if cc == "" {
			cc, _ = psiMap["region"].(string)
		}
		iconChanged := pState != ui.lastIconState || cc != ui.lastIconCC
		ui.lastIconState = pState
		ui.lastIconCC = cc
		ui.mu.Unlock()
		if iconChanged {
			setWindowIconState(pState, cc)
		}
	}
	ui.mu.Lock()
	tab := ui.tab
	haveApps, haveRules, havePsiStats := ui.apps != nil, ui.rulesData != nil, ui.psiStatsData != nil
	ui.mu.Unlock()

	if tab == 0 || tab == 1 || (full && !haveApps) {
		if ap, err := ui.apiCall("GET", "/api/apps", nil); err == nil && ap != nil {
			ui.mu.Lock()
			ui.apps = toMapSlice(ap["apps"])
			ui.presets = toMapSlice(ap["presets"])
			ui.mu.Unlock()
		}
	}
	if tab == 1 || (full && !haveRules) {
		if rl, err := ui.apiCall("GET", "/api/rules", nil); err == nil && rl != nil {
			ui.mu.Lock()
			ui.rulesData = rl
			ui.mu.Unlock()
		}
	}
	// Вкладка «Потоки» (tab == 2) запрашивает расширенный список потоков ТОЛЬКО когда она открыта!
	if tab == 2 && !streamsPaused {
		if rc, err := ui.apiCall("GET", "/api/conns/recent", nil); err == nil && rc != nil {
			ui.mu.Lock()
			ui.recentStreams = toMapSlice(rc["recent"])
			ui.mu.Unlock()
		}
	}
	if tab == 4 || (full && !havePsiStats) {
		if ps, err := ui.apiCall("GET", "/api/psiphon/stats", nil); err == nil && ps != nil {
			ui.mu.Lock()
			ui.psiStatsData = ps
			ui.mu.Unlock()
		}
	}
	ui.mu.Lock()
	haveShare := ui.shareInfo != nil
	shareOnNow, _ := ui.state["share_on"].(bool)
	if haveShare {
		if en, _ := ui.shareInfo["enabled"].(bool); en != shareOnNow {
			haveShare = false
		}
	}
	ui.mu.Unlock()
	if (tab == 3 || tab == 4) && (full || !haveShare) {
		if sh, err := ui.apiCall("GET", "/api/share", nil); err == nil && sh != nil {
			ui.mu.Lock()
			ui.shareInfo = sh
			ui.mu.Unlock()
		}
	}
	if ui.w != nil && !guiHidden.Load() {
		ui.w.Invalidate()
	}
}

func toMapSlice(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func (ui *gioUI) apiCall(method, path string, body any) (map[string]any, error) {
	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = json.Marshal(body)
	}
	doOnce := func() (*http.Response, error) {
		ui.mu.Lock()
		base, tok := ui.apiBase, ui.token
		ui.mu.Unlock()
		var rd io.Reader
		if bodyBytes != nil {
			rd = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequest(method, base+path, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Psiroute", tok)
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return guiHTTP.Do(req)
	}
	resp, err := doOnce()
	if err != nil || (resp != nil && resp.StatusCode == http.StatusForbidden) {
		if resp != nil {
			resp.Body.Close()
		}
		// Перечитываем актуальный адрес и токен из psiroute.instance (на случай перезапуска ядра или UAC-эскалации)
		ui.mu.Lock()
		curBase := ui.apiBase
		ui.mu.Unlock()
		if newBase, newTok := resolveAPIConfig(ui.dataDir, curBase); newTok != "" {
			ui.mu.Lock()
			ui.apiBase = newBase
			ui.token = newTok
			ui.mu.Unlock()
			resp, err = doOnce()
		}
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (ui *gioUI) doAsync(toastMsg string, fn func() (map[string]any, error)) {
	if toastMsg != "" {
		ui.setToast(toastMsg, false)
	}
	go func() {
		res, err := fn()
		if err != nil {
			ui.setToast("Ошибка: "+err.Error(), true)
		} else if res != nil {
			if ok, _ := res["ok"].(bool); !ok {
				if errMsg, _ := res["error"].(string); errMsg != "" {
					ui.setToast(errMsg, true)
				}
			}
		}
		ui.fetchAll(true)
	}()
}

func (ui *gioUI) setToast(msg string, isErr bool) {
	ui.mu.Lock()
	ui.statusToast = msg
	ui.toastErr = isErr
	ui.toastUntil = time.Now().Add(4 * time.Second)
	ui.mu.Unlock()
	if ui.w != nil {
		ui.w.Invalidate()
	}
}

func (ui *gioUI) queueEditorText(ed *widget.Editor, txt string) {
	if ed == nil {
		return
	}
	ui.mu.Lock()
	if ui.pendingEditorText == nil {
		ui.pendingEditorText = map[*widget.Editor]string{}
	}
	ui.pendingEditorText[ed] = txt
	ui.mu.Unlock()
	if ui.w != nil {
		ui.w.Invalidate()
	}
}

func (ui *gioUI) applyPendingUIUpdates() {
	ui.mu.Lock()
	thm := ui.pendingTheme
	ui.pendingTheme = ""
	var edUpdates map[*widget.Editor]string
	if len(ui.pendingEditorText) > 0 {
		edUpdates = ui.pendingEditorText
		ui.pendingEditorText = map[*widget.Editor]string{}
	}
	ui.mu.Unlock()
	if thm != "" && thm != ui.pal.themeID {
		ui.pal = paletteByTheme(thm)
	}
	for ed, txt := range edUpdates {
		ed.SetText(txt)
	}
}

func (ui *gioUI) togglePower(pState string) {
	if !ui.powerBusy.CompareAndSwap(false, true) {
		return
	}
	act := "stop"
	toastStart := "Отключаю VPN-соединение…"
	toastDone := "VPN-соединение отключено"
	if pState == "stopped" || pState == "error" || pState == "" {
		act = "start"
		toastStart = "Подключаюсь к Psiphon VPN…"
		toastDone = ""
	}
	ui.setToast(toastStart, false)
	go func() {
		defer ui.powerBusy.Store(false)
		res, err := ui.apiCall("POST", "/api/psiphon/"+act, nil)
		if err != nil {
			ui.setToast("Ошибка: "+err.Error(), true)
		} else if res != nil {
			if ok, _ := res["ok"].(bool); !ok {
				if errMsg, _ := res["error"].(string); errMsg != "" {
					ui.setToast(errMsg, true)
				}
			} else if toastDone != "" {
				ui.setToast(toastDone, false)
			}
		}
		ui.fetchAll(true)
	}()
}

func (ui *gioUI) appBtn(key string) *widget.Clickable {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	if len(ui.appActionBtns) > 600 {
		for k := range ui.appActionBtns {
			if strings.HasPrefix(k, "strm|") {
				delete(ui.appActionBtns, k)
			}
		}
	}
	b := ui.appActionBtns[key]
	if b == nil {
		b = new(widget.Clickable)
		ui.appActionBtns[key] = b
	}
	return b
}

// ---------- Keyboard Shortcuts & Event Handling ----------

func (ui *gioUI) anyEditorFocused(gtx layout.Context) bool {
	editors := []*widget.Editor{
		&ui.homeRuleEditor,
		&ui.ruleNameEditor,
		&ui.hostEditor,
		&ui.ruleFilterEditor,
		&ui.batchRuleEditor,
		&ui.appSearch,
		&ui.listSearchEditor,
		&ui.listIDEditor,
		&ui.listTitleEditor,
		&ui.listURLEditor,
		&ui.listFilePathEditor,
		&ui.listContentEditor,
		&ui.diagEditor,
		&ui.serverEntriesEditor,
		&ui.streamSearchEditor,
	}
	for _, ed := range editors {
		if gtx.Focused(ed) {
			return true
		}
	}
	return false
}

// handleHotkeys обрабатывает только явные именованные шорткаты с модификатором Ctrl
// ПОСЛЕ отрисовки дерева виджетов (Раздел 1.1 ТЗ), чтобы не перехватывать ввод букв,
// Backspace и буфер обмена Ctrl+C / Ctrl+V / Ctrl+X / Ctrl+A внутри widget.Editor.
func (ui *gioUI) handleHotkeys(gtx layout.Context, pState string) {
	pass := pointer.PassOp{}.Push(gtx.Ops)
	event.Op(gtx.Ops, &ui.keyTag)
	pass.Pop()
	for {
		ev, ok := gtx.Event(
			key.Filter{Name: key.NameReturn, Required: key.ModCtrl},
			key.Filter{Name: key.NameEnter, Required: key.ModCtrl},
			key.Filter{Name: "F", Required: key.ModCtrl},
			key.Filter{Name: "1", Required: key.ModCtrl},
			key.Filter{Name: "2", Required: key.ModCtrl},
			key.Filter{Name: "3", Required: key.ModCtrl},
			key.Filter{Name: "4", Required: key.ModCtrl},
			key.Filter{Name: "5", Required: key.ModCtrl},
		)
		if !ok {
			break
		}
		ke, ok := ev.(key.Event)
		if !ok || ke.State != key.Press || !ke.Modifiers.Contain(key.ModCtrl) {
			continue
		}
		switch ke.Name {
		case "1", "2", "3", "4", "5":
			idx := int(ke.Name[0] - '1')
			if idx >= 0 && idx < len(navTitles) {
				ui.tab = idx
				go ui.fetchAll(true)
			}
		case key.NameReturn, key.NameEnter:
			ui.togglePower(pState)
		case "F", "f":
			switch ui.tab {
			case 0:
				gtx.Execute(key.FocusCmd{Tag: &ui.homeRuleEditor})
			case 1:
				switch ui.subTabs[1] {
				case 1:
					gtx.Execute(key.FocusCmd{Tag: &ui.appSearch})
				case 2:
					gtx.Execute(key.FocusCmd{Tag: &ui.listSearchEditor})
				default:
					gtx.Execute(key.FocusCmd{Tag: &ui.ruleFilterEditor})
				}
			case 2:
				gtx.Execute(key.FocusCmd{Tag: &ui.streamSearchEditor})
			case 4:
				if ui.subTabs[4] == 2 {
					gtx.Execute(key.FocusCmd{Tag: &ui.diagEditor})
				}
			}
		}
	}
}

func (ui *gioUI) submitListForm(confirmTrust bool) {
	id := strings.TrimSpace(ui.listIDEditor.Text())
	if id == "" && ui.listEditID != "" {
		id = ui.listEditID
	}
	title := strings.TrimSpace(ui.listTitleEditor.Text())
	rawURL := strings.TrimSpace(ui.listURLEditor.Text())
	content := ui.listContentEditor.Text()
	typ := "local"
	if ui.listSourceMode == 1 {
		typ = "url"
	}
	body := map[string]any{
		"id":            id,
		"title":         title,
		"type":          typ,
		"url":           rawURL,
		"content":       content,
		"confirm_trust": confirmTrust,
	}
	go func() {
		method := "POST"
		path := "/api/lists"
		if ui.listEditID != "" {
			method = "PUT"
			path = "/api/lists/" + url.PathEscape(ui.listEditID)
		}
		res, err := ui.apiCall(method, path, body)
		if res != nil && res["need_confirm_trust"] == true {
			host, _ := res["untrusted_host"].(string)
			ui.mu.Lock()
			ui.listTrustConfirmHost = host
			ui.mu.Unlock()
			if ui.w != nil {
				ui.w.Invalidate()
			}
			return
		}
		if err != nil {
			ui.setToast("Ошибка: "+err.Error(), true)
			return
		}
		if ok, _ := res["ok"].(bool); !ok {
			if em, _ := res["error"].(string); em != "" {
				ui.setToast(em, true)
				return
			}
		}
		ui.mu.Lock()
		ui.listFormOpen = false
		ui.listEditID = ""
		ui.listPreviewData = nil
		ui.listTrustConfirmHost = ""
		ui.mu.Unlock()
		ui.queueEditorText(&ui.listIDEditor, "")
		ui.queueEditorText(&ui.listTitleEditor, "")
		ui.queueEditorText(&ui.listURLEditor, "")
		ui.queueEditorText(&ui.listContentEditor, "")
		ui.setToast("Список сохранён", false)
		ui.fetchAll(true)
	}()
}

func (ui *gioUI) handleEvents(gtx layout.Context) {
	ui.mu.Lock()
	st := ui.state
	ui.mu.Unlock()
	psi, _ := st["psiphon"].(map[string]any)
	pState, _ := psi["state"].(string)

	for i := range ui.navBtns {
		if ui.navBtns[i].Clicked(gtx) {
			ui.tab = i
			ui.pipePopup = 0
			go ui.fetchAll(true)
		}
	}
	for tIdx := range ui.subTabBtns {
		for sIdx := range ui.subTabBtns[tIdx] {
			if ui.subTabBtns[tIdx][sIdx].Clicked(gtx) {
				ui.subTabs[tIdx] = sIdx
				go ui.fetchAll(true)
			}
		}
	}
	if ui.allCountriesBtn.Clicked(gtx) {
		ui.tab = 3
		ui.subTabs[3] = 0
		ui.pipePopup = 0
		go ui.fetchAll(true)
	}
	if ui.pipeCaptureBtn.Clicked(gtx) {
		if ui.pipePopup == 1 {
			ui.pipePopup = 0
		} else {
			ui.pipePopup = 1
		}
	}
	if ui.pipeWarpBtn.Clicked(gtx) {
		ui.pipePopup = 0
		on, _ := st["warp_on"].(bool)
		act := "on"
		if on {
			act = "off"
		}
		ui.doAsync("Подложка Cloudflare WARP: "+act, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/warp/"+act, nil)
		})
	}
	if ui.pipePsiBtn.Clicked(gtx) {
		if ui.pipePopup == 2 {
			ui.pipePopup = 0
		} else {
			ui.pipePopup = 2
		}
	}
	// Кнопки выбора режима перехвата трафика из визуального пайплайна (Весь ПК [TUN] / Только браузеры / Ручной прокси).
	// ВАЖНО (Аудит 2): переключение способа захвата меняет ТОЛЬКО состояние TUN и Системного прокси
	// и НИКОГДА не сбрасывает выбранный пользователем глобальный сценарий Routing.Mode (например, "rules").
	if ui.captureModeBtns[0].Clicked(gtx) || ui.tunBannerBtn.Clicked(gtx) {
		ui.pipePopup = 0
		ui.doAsync("Перехват: Весь ПК (режим TUN)", func() (map[string]any, error) {
			_, _ = ui.apiCall("POST", "/api/sysproxy/off", nil)
			return ui.apiCall("POST", "/api/tun/on", map[string]any{})
		})
	}
	if ui.captureModeBtns[1].Clicked(gtx) {
		ui.pipePopup = 0
		ui.doAsync("Перехват: Только браузеры (Системный прокси)", func() (map[string]any, error) {
			_, _ = ui.apiCall("POST", "/api/tun/off", map[string]any{})
			return ui.apiCall("POST", "/api/sysproxy/on", nil)
		})
	}
	if ui.captureModeBtns[2].Clicked(gtx) {
		ui.pipePopup = 0
		ui.doAsync("Перехват: Ручной прокси 127.0.0.1:1080", func() (map[string]any, error) {
			_, _ = ui.apiCall("POST", "/api/tun/off", map[string]any{})
			return ui.apiCall("POST", "/api/sysproxy/off", nil)
		})
	}
	if ui.repairConnBtn.Clicked(gtx) {
		ui.pipePopup = 0
		ui.doAsync("Починка соединения: авто-тюнинг DPI + переподключение…", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/repair", map[string]any{})
		})
	}
	if ui.pause5Btn.Clicked(gtx) {
		ui.doAsync("Защита поставлена на паузу на 5 минут", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/pause", map[string]any{"minutes": 5})
		})
	}
	if ui.pause15Btn.Clicked(gtx) {
		ui.doAsync("Защита поставлена на паузу на 15 минут", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/pause", map[string]any{"minutes": 15})
		})
	}
	if ui.pauseResumeBtn.Clicked(gtx) {
		ui.doAsync("Пауза снята — защита возобновлена", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/pause", map[string]any{"minutes": 0})
		})
	}
	if ui.themeToggleBtn.Clicked(gtx) {
		nextTheme := "cyber-amber"
		title := "Cyber-Amber (Терминал СССР)"
		if ui.pal.themeID == "cyber-amber" {
			nextTheme = "obsidian"
			title = "Tactical Glass (Obsidian Dark)"
		}
		ui.pal = paletteByTheme(nextTheme)
		ui.doAsync("Тема оформления: "+title, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"general.ui_theme": nextTheme})
		})
	}
	if ui.privacyBtn.Clicked(gtx) {
		ui.privacyMode = !ui.privacyMode
		if ui.privacyMode {
			ui.setToast("Чистый экран: IP и домены скрыты в подписях и логах. Поля ввода остаются видимыми", false)
		} else {
			ui.setToast("Режим «Чистый экран» выключен", false)
		}
	}
	if ui.captiveOpenBtn.Clicked(gtx) {
		if netMap, ok := st["net"].(map[string]any); ok {
			if cURL, _ := netMap["captive_url"].(string); cURL != "" {
				openBrowser(cURL)
			}
		}
	}
	// Клик по элементу в нижней полосе Главной:
	//   - ТСПУ-дроп -> добавляет точечное правило для домена (host -> psiphon), не трогая весь браузер .exe
	//   - Активный процесс -> циклически переключает его маршрут
	for i := range ui.liveAppBtns {
		if ui.liveAppBtns[i].Clicked(gtx) {
			exe := ui.liveAppNames[i]
			cur := ui.liveAppRoutes[i]
			host := ui.liveAppHosts[i]
			isAlert := ui.liveAppAlerts[i]
			if isAlert && host != "" {
				ui.doAsync(fmt.Sprintf("Правило %s → Psiphon VPN", host), func() (map[string]any, error) {
					return ui.apiCall("POST", "/api/rules/add", map[string]any{"tokens": host, "outbound": obPsiphon, "always": true})
				})
			} else if exe != "" {
				nextOb := obPsiphon
				switch cur {
				case "", obAuto:
					nextOb = obPsiphon
				case obPsiphon:
					nextOb = obWarp
				case obWarp:
					nextOb = obDesync
				case obDesync:
					nextOb = obDirect
				default:
					nextOb = ""
				}
				lbl := routeShortRu(nextOb)
				if nextOb == "" {
					lbl = "По общим правилам"
				}
				ui.doAsync(fmt.Sprintf("%s → %s", exe, lbl), func() (map[string]any, error) {
					return ui.apiCall("POST", "/api/apps", map[string]any{"exe": exe, "outbound": nextOb})
				})
			}
		}
	}
	if ui.moreMenuBtn.Clicked(gtx) {
		ui.homeMenuOpen = !ui.homeMenuOpen
	}
	if ui.webBtn.Clicked(gtx) {
		openBrowser(ui.apiBase + "/")
	}
	if ui.quitBtn.Clicked(gtx) {
		go func() {
			_, _ = ui.apiCall("POST", "/api/quit", nil)
			os.Exit(0)
		}()
	}

	if ui.powerBtn.Clicked(gtx) {
		ui.togglePower(pState)
	}
	if ui.newNodeBtn.Clicked(gtx) {
		ui.doAsync("Меняю сервер Psiphon…", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psiphon/newnode", nil)
		})
	}
	if ui.nextStratBtn.Clicked(gtx) {
		ui.homeMenuOpen = false
		ui.doAsync("Пробую следующий способ подключения…", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psiphon/next", nil)
		})
	}
	if ui.restartPsiBtn.Clicked(gtx) {
		ui.homeMenuOpen = false
		ui.doAsync("Перезапуск Psiphon…", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/psiphon/restart", nil)
		})
	}
	if ui.speedTestBtn.Clicked(gtx) {
		ui.homeMenuOpen = false
		ui.doAsync("Замеряю скорость туннеля (до 10 с)…", func() (map[string]any, error) {
			res, err := ui.apiCall("POST", "/api/psi/speedtest", nil)
			if err == nil && res["ok"] == true {
				ui.setToast(fmt.Sprintf("Скорость: %.0f КБ/с, пинг %.0f мс (%v)", res["kbps"], res["ms"], res["region"]), false)
			}
			return res, err
		})
	}

	homeObs := [5]string{obDirect, obDesync, obWarp, obPsiphon, obBlock}
	for i := range ui.homeRuleObBtns {
		if ui.homeRuleObBtns[i].Clicked(gtx) {
			ui.homeRuleOb = homeObs[i]
		}
	}
	if ui.homeCheckBtn.Clicked(gtx) {
		raw := strings.TrimSpace(ui.homeRuleEditor.Text())
		if raw != "" {
			q := "/api/route?host=" + url.QueryEscape(raw) + "&port=443"
			if strings.HasSuffix(strings.ToLower(raw), ".exe") || !strings.Contains(raw, ".") {
				exe := raw
				if !strings.HasSuffix(strings.ToLower(exe), ".exe") {
					exe += ".exe"
				}
				q = "/api/route?host=example.com&port=443&app=" + url.QueryEscape(exe)
			}
			go func() {
				res, err := ui.apiCall("GET", q, nil)
				if err == nil && res != nil {
					badge, _ := res["badge"].(string)
					conflict, _ := res["conflict"].(string)
					msg := "Текущий маршрут: " + badge
					if conflict != "" {
						msg += "  ⚠ " + conflict
					}
					ui.mu.Lock()
					ui.homeRoutePreview = msg
					ui.mu.Unlock()
					if ui.w != nil {
						ui.w.Invalidate()
					}
				}
			}()
		}
	}
	if ui.homeRuleAddBtn.Clicked(gtx) {
		raw := strings.TrimSpace(ui.homeRuleEditor.Text())
		ob := ui.homeRuleOb
		if ob == "" {
			ob = obPsiphon
		}
		if raw != "" {
			ui.homeRuleEditor.SetText("")
			ui.lastHomeQuery = ""
			ui.mu.Lock()
			ui.homeRoutePreview = ""
			ui.mu.Unlock()
			lower := strings.ToLower(raw)
			if strings.HasSuffix(lower, ".exe") || (!strings.Contains(lower, ".") && !strings.Contains(lower, ":") && !strings.Contains(lower, "/")) {
				exe := raw
				if !strings.HasSuffix(lower, ".exe") {
					exe += ".exe"
				}
				ui.doAsync(fmt.Sprintf("Маршрут программы %s → %s (Приоритет 3)", exe, routeShortRu(ob)), func() (map[string]any, error) {
					return ui.apiCall("POST", "/api/apps", map[string]any{"exe": exe, "outbound": ob})
				})
			} else {
				ui.doAsync(fmt.Sprintf("Личное правило %s → %s (Приоритет 2)", raw, routeShortRu(ob)), func() (map[string]any, error) {
					return ui.apiCall("POST", "/api/rules/add", map[string]any{"tokens": raw, "outbound": ob, "always": true})
				})
			}
		}
	}

	modes := [3]string{"psiphon", "rules", "auto"}
	for i := range ui.modeBtns {
		if ui.modeBtns[i].Clicked(gtx) {
			m := modes[i]
			ui.doAsync("Режим маршрутизации: "+m, func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/mode/"+m, nil)
			})
		}
	}

	// Включение/выключение Системного прокси и TUN изменяет только режим перехвата трафика,
	// не затрагивая Routing.Mode.
	if ui.sysProxyBtn.Clicked(gtx) {
		on, _ := st["sysproxy"].(bool)
		act := "on"
		if on {
			act = "off"
		}
		ui.doAsync("Системный прокси: "+act, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/sysproxy/"+act, nil)
		})
	}
	if ui.tunBtn.Clicked(gtx) {
		tunMap, _ := st["tun"].(map[string]any)
		on, _ := tunMap["on"].(bool)
		act := "on"
		if on {
			act = "off"
		}
		ui.doAsync("Режим TUN: "+act, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/tun/"+act, map[string]any{})
		})
	}
	if ui.tunAdminBtn.Clicked(gtx) {
		ui.doAsync("Перезапуск от имени администратора для включения TUN…", func() (map[string]any, error) {
			res, err := ui.apiCall("POST", "/api/tun/elevate", map[string]any{})
			if err == nil && res != nil && res["restarting"] == true {
				go func() {
					time.Sleep(300 * time.Millisecond)
					os.Exit(0)
				}()
			}
			return res, err
		})
	}
	if ui.resetStatsBtn.Clicked(gtx) {
		ui.doAsync("Счётчики трафика сброшены", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/stats/reset", map[string]any{})
		})
	}
	if ui.warpBtn.Clicked(gtx) {
		on, _ := st["warp_on"].(bool)
		act := "on"
		if on {
			act = "off"
		}
		ui.doAsync("Cloudflare WARP: "+act, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/warp/"+act, nil)
		})
	}
	if ui.warpReconnBtn.Clicked(gtx) {
		ui.doAsync("WARP: открыт новый UDP-поток", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/warp/reconnect", nil)
		})
	}
	shareA := ui.shareBtn.Clicked(gtx)
	shareB := ui.shareQuickBtn.Clicked(gtx)
	if shareA || shareB {
		on, _ := st["share_on"].(bool)
		act := "on"
		if on {
			act = "off"
		}
		ui.doAsync("Раздача в LAN: "+act, func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/share/"+act, nil)
		})
	}
	if ui.dohBtn.Clicked(gtx) {
		on, _ := st["dns_on"].(bool)
		ui.doAsync("Шифрованный DNS (DoH): "+onOffRu(!on), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"dns.enabled": !on})
		})
	}
	if ui.localDNSBtn.Clicked(gtx) {
		on, _ := st["local_dns_on"].(bool)
		ui.doAsync("Локальный DNS 127.0.0.1:5353: "+onOffRu(!on), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"dns.local_server": !on})
		})
	}
	if ui.fakeIPBtn.Clicked(gtx) {
		on, _ := st["fake_ip"].(bool)
		ui.doAsync("FakeIP (198.18.0.0/15): "+onOffRu(!on), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"tun.fake_ip": !on})
		})
	}
	if ui.bypassLANBtn.Clicked(gtx) {
		on, _ := st["bypass_lan"].(bool)
		ui.doAsync("Обход LAN напрямую: "+onOffRu(!on), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.bypass_lan": !on})
		})
	}
	if ui.blockQUICBtn.Clicked(gtx) {
		on, _ := st["block_quic"].(bool)
		ui.doAsync("Блокировка QUIC (UDP 443): "+onOffRu(!on), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.block_quic": !on})
		})
	}
	if ui.killSwitchBtn.Clicked(gtx) {
		on, _ := st["kill_switch"].(bool)
		ui.doAsync("Kill Switch: "+onOffRu(!on), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.kill_switch": !on})
		})
	}
	if ui.blockSTUNBtn.Clicked(gtx) {
		on, _ := st["block_stun"].(bool)
		ui.doAsync("Защита WebRTC/STUN: "+onOffRu(!on), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"routing.block_stun": !on})
		})
	}
	if ui.singleProcBtn.Clicked(gtx) {
		on, _ := st["single_process_countries"].(bool)
		ui.doAsync("Горячее переключение стран в 1 процессе: "+onOffRu(!on), func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/settings", map[string]any{"psiphon.single_process_countries": !on})
		})
	}
	if ui.stopCountryBtn.Clicked(gtx) {
		ui.doAsync("Фоновые процессы стран остановлены", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/countries/stop-all", nil)
		})
	}
	if ui.clearDNSBtn.Clicked(gtx) {
		ui.doAsync("Кэш DNS, FakeIP и ECH очищен", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/dns/clear", nil)
		})
	}
	if ui.clearLearnBtn.Clicked(gtx) {
		ui.doAsync("Выученные маршруты сброшены", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/learned/clear", nil)
		})
	}
	if ui.refreshListBtn.Clicked(gtx) {
		ui.doAsync("Запущено обновление списков доменов и подсетей", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/lists/refresh", nil)
		})
	}
	if ui.probeBtn.Clicked(gtx) {
		ui.homeMenuOpen = false
		pr, _ := st["probe_running"].(bool)
		if pr {
			ui.doAsync("Автоподбор остановлен", func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/psi/probe/stop", nil)
			})
		} else {
			ui.doAsync("Автоподбор обхода Psiphon запущен", func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/psi/probe", map[string]any{})
			})
		}
	}
	if ui.dpiTestBtn.Clicked(gtx) {
		ui.doAsync("Тест методов DPI запущен", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/dpi/test", map[string]any{})
		})
	}
	if ui.selftestBtn.Clicked(gtx) {
		ui.doAsync("Выполняется самопроверка…", func() (map[string]any, error) {
			res, err := ui.apiCall("POST", "/api/selftest", nil)
			if err == nil {
				ui.setToast("Самопроверка успешно завершена", false)
			}
			return res, err
		})
	}
	if ui.reportBtn.Clicked(gtx) {
		ui.doAsync("Собираю диагностический отчёт в папку reports…", func() (map[string]any, error) {
			res, err := ui.apiCall("POST", "/api/report", nil)
			if err == nil && res["ok"] == true {
				ui.setToast(fmt.Sprintf("Отчёт сохранён: %v", res["path"]), false)
			}
			return res, err
		})
	}

	// Lists Manager events
	for i := range ui.listGroupBtns {
		if ui.listGroupBtns[i].Clicked(gtx) {
			ui.listGroupFilter = i
		}
	}
	for i := range ui.listSourceModeBtns {
		if ui.listSourceModeBtns[i].Clicked(gtx) {
			ui.listSourceMode = i
		}
	}
	if ui.listNewBtn.Clicked(gtx) {
		ui.listFormOpen = !ui.listFormOpen
		ui.listEditID = ""
		ui.listPreviewData = nil
	}
	if ui.listCancelBtn.Clicked(gtx) {
		ui.listFormOpen = false
		ui.listEditID = ""
		ui.listPreviewData = nil
	}
	if ui.listLoadFileBtn.Clicked(gtx) {
		ui.loadFileIntoListEditor()
	}
	if ui.listPreviewBtn.Clicked(gtx) {
		content := ui.listContentEditor.Text()
		go func() {
			res, err := ui.apiCall("POST", "/api/lists/preview", map[string]any{"content": content})
			if err == nil && res != nil {
				ui.mu.Lock()
				ui.listPreviewData = res
				ui.mu.Unlock()
				if ui.w != nil {
					ui.w.Invalidate()
				}
			}
		}()
	}
	if ui.listSaveBtn.Clicked(gtx) {
		ui.submitListForm(false)
	}
	if ui.listTrustApproveBtn.Clicked(gtx) {
		ui.submitListForm(true)
	}
	if ui.listTrustCancelBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.listTrustConfirmHost = ""
		ui.mu.Unlock()
	}
	if ui.listDeleteForceBtn.Clicked(gtx) {
		ui.mu.Lock()
		delID := ui.listDeleteConfirmID
		delTitle := ui.listDeleteConfirmTitle
		ui.listDeleteConfirmID = ""
		ui.listDeleteConfirmTitle = ""
		ui.listDeleteUsedRules = nil
		ui.mu.Unlock()
		if delID != "" {
			ui.doAsync("Список «"+orDefault(delTitle, delID)+"» убран из правил и удалён", func() (map[string]any, error) {
				return ui.apiCall("DELETE", "/api/lists/"+url.PathEscape(delID)+"?remove_from_rules=1", map[string]any{"remove_from_rules": true})
			})
		}
	}
	if ui.listDeleteCancelBtn.Clicked(gtx) {
		ui.mu.Lock()
		ui.listDeleteConfirmID = ""
		ui.listDeleteConfirmTitle = ""
		ui.listDeleteUsedRules = nil
		ui.mu.Unlock()
	}
	if ui.listRestoreBuiltinBtn.Clicked(gtx) {
		ui.listGroupFilter = 0
		ui.doAsync("Все встроенные списки восстановлены", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/lists/restore-builtins", map[string]any{})
		})
	}

	// App filter tabs
	for i := range ui.appTabBtns {
		if ui.appTabBtns[i].Clicked(gtx) {
			ui.appTabFilter = i
		}
	}
	if ui.appRefreshBtn.Clicked(gtx) {
		go ui.fetchAll(true)
	}

	// Rule builder events (dynamically includes user's favorite countries)
	obChoices := ui.dynamicRuleObChoices()
	for i := range ui.ruleObBtns {
		if i < len(obChoices) && ui.ruleObBtns[i].Clicked(gtx) {
			ui.selectedRuleOb = obChoices[i].id
		}
	}
	protoIDs := [3]string{"", "tcp", "udp"}
	for i := range ui.ruleProtoBtns {
		if ui.ruleProtoBtns[i].Clicked(gtx) {
			ui.selectedProto = protoIDs[i]
		}
	}
	if ui.ruleAlwaysBtn.Clicked(gtx) {
		ui.ruleAlways = !ui.ruleAlways
	}
	if ui.ruleCancelBtn.Clicked(gtx) {
		ui.editingRuleIdx = -1
		ui.ruleAlways = true
		ui.ruleNameEditor.SetText("")
	}
	for i := range ui.listPickBtns {
		if ui.listPickBtns[i].Clicked(gtx) {
			tok := "list:" + ruleQuickListIDs[i].id
			cur := strings.TrimSpace(ui.hostEditor.Text())
			if cur == "" {
				ui.hostEditor.SetText(tok)
			} else if !strings.Contains(strings.ToLower(cur), strings.ToLower(tok)) {
				ui.hostEditor.SetText(cur + ", " + tok)
			}
		}
	}
	for i := range ui.presetRuleBtns {
		if ui.presetRuleBtns[i].Clicked(gtx) {
			pr := rulePresetChoices[i]
			ob := ui.selectedRuleOb
			ui.doAsync("Добавлен шаблон «"+pr.title+"»", func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/rules/preset", map[string]any{"preset": pr.id, "outbound": ob})
			})
		}
	}
	if ui.checkRouteBtn.Clicked(gtx) {
		raw := strings.TrimSpace(ui.hostEditor.Text())
		if idx := strings.IndexAny(raw, ", "); idx > 0 {
			raw = strings.TrimSpace(raw[:idx])
		}
		if raw != "" {
			target := raw
			ui.doAsync("", func() (map[string]any, error) {
				q := "/api/route?host=" + url.QueryEscape(target) + "&port=443"
				if strings.HasSuffix(strings.ToLower(target), ".exe") {
					q = "/api/route?host=example.com&port=443&app=" + url.QueryEscape(target)
				}
				res, err := ui.apiCall("GET", q, nil)
				if err == nil && res != nil {
					badge, _ := res["badge"].(string)
					if badge != "" {
						ui.setToast(fmt.Sprintf("Почему так пошло (%s): %s", target, badge), false)
					} else {
						ui.setToast(fmt.Sprintf("Маршрут для %s → %v (правило: %v)", target, res["outbound"], res["rule"]), false)
					}
				}
				return res, err
			})
		}
	}
	if ui.addRuleBtn.Clicked(gtx) {
		target := strings.TrimSpace(ui.hostEditor.Text())
		name := strings.TrimSpace(ui.ruleNameEditor.Text())
		ob := ui.selectedRuleOb
		proto := ui.selectedProto
		alw := ui.ruleAlways
		editIdx := ui.editingRuleIdx
		original := ui.editingRuleOriginal
		if editIdx < 0 {
			original = nil
		}
		if target != "" {
			ui.editingRuleIdx = -1
			ui.ruleAlways = true
			ui.ruleNameEditor.SetText("")
			ui.hostEditor.SetText("")
			ui.lastRuleCheckQuery = ""
			ui.doAsync(fmt.Sprintf("Правило сохранено → %s", ob), func() (map[string]any, error) {
				body := ruleEditRequest(original, target, name, ob, proto, alw)
				if editIdx >= 0 {
					body["index"] = editIdx
				}
				return ui.apiCall("POST", "/api/rules/add", body)
			})
		}
	}
	if ui.batchImportBtn.Clicked(gtx) {
		rawBatch := strings.TrimSpace(ui.batchRuleEditor.Text())
		ob := ui.selectedRuleOb
		if ob == "" {
			ob = obPsiphon
		}
		if rawBatch != "" {
			ui.batchRuleEditor.SetText("")
			ui.doAsync("Пакетный импорт правил выполнен → "+ob, func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/rules/batch", map[string]any{
					"text":     rawBatch,
					"outbound": ob,
				})
			})
		}
	}
	for i := range ui.profileBtns {
		if i < len(builtinProfiles) && ui.profileBtns[i].Clicked(gtx) {
			pid := builtinProfiles[i].ID
			pname := builtinProfiles[i].Name
			ui.doAsync("Применён профиль «"+pname+"»", func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/profiles/import", map[string]any{"builtin": pid, "merge": false})
			})
		}
	}
	if ui.undoProfileBtn.Clicked(gtx) {
		ui.doAsync("Импорт профиля отменён, прежние правила восстановлены", func() (map[string]any, error) {
			return ui.apiCall("POST", "/api/profiles/undo", map[string]any{})
		})
	}

	// Countries, DPI & WARP Mask events
	for i := range ui.countryBtns {
		clicked := ui.countryBtns[i].Clicked(gtx) || ui.favCountryBtns[i].Clicked(gtx)
		if i < len(nativeCountries) && clicked {
			ui.pipePopup = 0
			reg := nativeCountries[i]
			ui.doAsync("Страна выхода: "+nativeCountryNames[i], func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/psi/region", map[string]any{"region": reg})
			})
		}
	}
	for i := range ui.favStarBtns {
		if i < len(nativeCountries) && ui.favStarBtns[i].Clicked(gtx) {
			cc := nativeCountries[i]
			if cc != "" && cc != "auto" {
				ui.doAsync("Избранные страны обновлены ("+cc+")", func() (map[string]any, error) {
					return ui.apiCall("POST", "/api/psi/favorites", map[string]any{"country": cc})
				})
			}
		}
	}
	for i := range ui.dpiModeBtns {
		if i < len(nativeDPIModes) && ui.dpiModeBtns[i].Clicked(gtx) {
			dm := nativeDPIModes[i]
			ui.doAsync("Метод DPI: "+nativeDPINames[i], func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/dpi/mode", map[string]any{"mode": dm})
			})
		}
	}
	maskIDs := [5]string{"auto", "quic", "masque", "bwg", "dns"}
	for i := range ui.warpMaskBtns {
		if ui.warpMaskBtns[i].Clicked(gtx) {
			mid := maskIDs[i]
			ui.doAsync("Маскировка WARP: "+mid, func() (map[string]any, error) {
				return ui.apiCall("POST", "/api/settings", map[string]any{"warp.mask": mid})
			})
		}
	}

	// Site Diagnostics & Server Entries Import
	if ui.diagRunBtn.Clicked(gtx) {
		h := strings.TrimSpace(ui.diagEditor.Text())
		if h != "" {
			ui.doAsync("Диагностика сайта "+h+"…", func() (map[string]any, error) {
				res, err := ui.apiCall("POST", "/api/diagnose?host="+url.QueryEscape(h)+"&port=443", nil)
				if err == nil && res != nil {
					ui.mu.Lock()
					ui.diagRes = res
					ui.mu.Unlock()
					ui.setToast(fmt.Sprintf("Диагностика %s завершена: лучший маршрут — %v", h, res["best"]), false)
				}
				return res, err
			})
		}
	}
	if ui.importEntriesBtn.Clicked(gtx) {
		raw := strings.TrimSpace(ui.serverEntriesEditor.Text())
		if raw != "" {
			ui.doAsync("Проверяю и импортирую записи серверов Psiphon…", func() (map[string]any, error) {
				res, err := ui.apiCall("POST", "/api/psiphon/server-entries", map[string]any{"data": raw})
				if err == nil && res != nil && res["ok"] == true {
					ui.queueEditorText(&ui.serverEntriesEditor, "")
					addF, _ := res["added"].(float64)
					dupF, _ := res["duplicates"].(float64)
					badF, _ := res["invalid"].(float64)
					ui.setToast(fmt.Sprintf("Импорт серверов: добавлено %.0f, дубликатов %.0f, отброшено %.0f", addF, dupF, badF), false)
				}
				return res, err
			})
		}
	}
}
