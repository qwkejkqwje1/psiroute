package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// Split Tunneling / Application Routing Manager (1.1.0+).
//
// Allows routing individual programs through Psiphon VPN, WARP, DPI-bypass,
// Direct (bypassing VPN), or Blocking them — either by picking from the live
// list of running processes on the computer or from a built-in catalog of
// popular browsers, messengers, voice apps and games.

type appPreset struct {
	Exe      string `json:"exe"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Rec      string `json:"recommended"` // recommended outbound
}

var popularApps = []appPreset{
	{Exe: "Discord.exe", Title: "Discord (чат и голос)", Category: "Мессенджеры и звонки", Rec: obPsiphon},
	{Exe: "Telegram.exe", Title: "Telegram Desktop", Category: "Мессенджеры и звонки", Rec: obPsiphon},
	{Exe: "WhatsApp.exe", Title: "WhatsApp Desktop", Category: "Мессенджеры и звонки", Rec: obPsiphon},
	{Exe: "Signal.exe", Title: "Signal", Category: "Мессенджеры и звонки", Rec: obPsiphon},
	{Exe: "Zoom.exe", Title: "Zoom Workplace", Category: "Мессенджеры и звонки", Rec: obDirect},
	{Exe: "chrome.exe", Title: "Google Chrome", Category: "Браузеры", Rec: obAuto},
	{Exe: "msedge.exe", Title: "Microsoft Edge", Category: "Браузеры", Rec: obAuto},
	{Exe: "firefox.exe", Title: "Mozilla Firefox", Category: "Браузеры", Rec: obAuto},
	{Exe: "browser.exe", Title: "Яндекс Браузер", Category: "Браузеры", Rec: obDirect},
	{Exe: "brave.exe", Title: "Brave Browser", Category: "Браузеры", Rec: obPsiphon},
	{Exe: "opera.exe", Title: "Opera / Opera GX", Category: "Браузеры", Rec: obPsiphon},
	{Exe: "Spotify.exe", Title: "Spotify", Category: "Музыка и медиа", Rec: obPsiphon},
	{Exe: "obs64.exe", Title: "OBS Studio (стриминг)", Category: "Музыка и медиа", Rec: obDirect},
	{Exe: "steam.exe", Title: "Steam Client", Category: "Игры и лаунчеры", Rec: obDirect},
	{Exe: "EpicGamesLauncher.exe", Title: "Epic Games Launcher", Category: "Игры и лаунчеры", Rec: obDirect},
	{Exe: "Battle.net.exe", Title: "Battle.net", Category: "Игры и лаунчеры", Rec: obDirect},
	{Exe: "RobloxPlayerBeta.exe", Title: "Roblox", Category: "Игры и лаунчеры", Rec: obDirect},
	{Exe: "cs2.exe", Title: "Counter-Strike 2", Category: "Игры и лаунчеры", Rec: obDirect},
	{Exe: "dota2.exe", Title: "Dota 2", Category: "Игры и лаунчеры", Rec: obDirect},
	{Exe: "valorant.exe", Title: "VALORANT", Category: "Игры и лаунчеры", Rec: obDirect},
	{Exe: "GenshinImpact.exe", Title: "Genshin Impact", Category: "Игры и лаунчеры", Rec: obDirect},
	{Exe: "qbittorrent.exe", Title: "qBittorrent (торренты)", Category: "Загрузки и P2P", Rec: obDirect},
	{Exe: "uTorrent.exe", Title: "uTorrent", Category: "Загрузки и P2P", Rec: obDirect},
	{Exe: "Code.exe", Title: "Visual Studio Code", Category: "Разработка и ИИ", Rec: obPsiphon},
	{Exe: "Cursor.exe", Title: "Cursor IDE", Category: "Разработка и ИИ", Rec: obPsiphon},
}

// systemNoiseProcs are Windows background/system processes hidden from the
// user-facing application picker so the list stays clean and relevant.
var systemNoiseProcs = map[string]bool{
	"system": true, "registry": true, "smss": true, "csrss": true, "wininit": true,
	"services": true, "lsass": true, "svchost": true, "fontdrvhost": true, "winlogon": true,
	"dwm": true, "conhost": true, "sihost": true, "taskhostw": true, "runtimebroker": true,
	"searchhost": true, "startmenuexperiencehost": true, "shellexperiencehost": true,
	"ctfmon": true, "dllhost": true, "wmiprvse": true, "spoolsv": true, "audiodg": true,
	"securityhealthservice": true, "securityhealthsystray": true, "msmpeng": true, "nissrv": true,
	"smartscreen": true, "applicationframehost": true, "systemsettings": true, "textinputhost": true,
	"widgetservice": true, "widgets": true, "searchindexer": true, "dashost": true, "lsaiso": true,
	"memory compression": true, "idle": true, "psiroute": true,
}

func isNoiseProc(name string) bool {
	n := normAppName(name)
	if n == "" || systemNoiseProcs[n] {
		return true
	}
	if tunSelfExe != "" && n == normAppName(tunSelfExe) {
		return true
	}
	return false
}

func presetForApp(exe string) (appPreset, bool) {
	n := normAppName(exe)
	for _, p := range popularApps {
		if normAppName(p.Exe) == n {
			return p, true
		}
	}
	return appPreset{}, false
}

// appCurrentRoute inspects Config.Routing.Rules and Config.Tun.Exclude to
// report how connections from exe are currently routed.
func (a *App) appCurrentRoute(exe string) string {
	n := normAppName(exe)
	if n == "" {
		return ""
	}
	a.cfg.mu.Lock()
	defer a.cfg.mu.Unlock()
	for _, ru := range a.cfg.Routing.Rules {
		if ru.Disabled || len(ru.Domains) > 0 || len(ru.Keywords) > 0 || len(ru.CIDR) > 0 || len(ru.Lists) > 0 || len(ru.Ports) > 0 || len(ru.PortRanges) > 0 {
			continue
		}
		for _, ap := range ru.Apps {
			if !strings.HasPrefix(strings.TrimSpace(ap), "!") && normAppName(ap) == n {
				return ru.Outbound
			}
		}
	}
	if tunAppMatch(exe, a.cfg.Tun.Exclude) {
		return "tun-exclude"
	}
	return ""
}

// SetAppRoute configures or removes a per-application routing rule (Split
// Tunneling). Outbound values:
//   - "psiphon", "direct", "direct-dpi", "warp", "block", "auto", "psiphon:XX"
//   - "tun-exclude": always direct + added to TUN excluded apps
//   - "default" or "": removes per-app overrides so general rules apply
func (a *App) SetAppRoute(exe, outbound string) error {
	exe = strings.TrimSpace(exe)
	if i := strings.LastIndexAny(exe, `\/`); i >= 0 {
		exe = exe[i+1:]
	}
	n := normAppName(exe)
	if n == "" {
		return errors.New("укажите имя программы (например Discord.exe)")
	}
	if !strings.HasSuffix(strings.ToLower(exe), ".exe") && !strings.Contains(exe, ".") {
		exe = exe + ".exe"
	}
	outbound = strings.TrimSpace(outbound)
	if outbound == "default" {
		outbound = ""
	}
	if outbound != "" && outbound != "tun-exclude" && !validOutbound(outbound) {
		return errors.New("неизвестный маршрут: " + outbound)
	}

	a.cfg.mu.Lock()
	// 1. Remove exe from existing pure app rules
	var kept []Rule
	for _, ru := range a.cfg.Routing.Rules {
		isPureAppRule := len(ru.Domains) == 0 && len(ru.Keywords) == 0 && len(ru.CIDR) == 0 && len(ru.Lists) == 0 && len(ru.Ports) == 0 && len(ru.PortRanges) == 0 && ru.Proto == ""
		if isPureAppRule && len(ru.Apps) > 0 {
			var remApps []string
			for _, ap := range ru.Apps {
				if strings.HasPrefix(strings.TrimSpace(ap), "!") || normAppName(ap) != n {
					remApps = append(remApps, ap)
				}
			}
			if len(remApps) == 0 {
				continue
			}
			ru.Apps = remApps
		}
		kept = append(kept, ru)
	}
	// 2. Remove from Tun.Exclude unless outbound is "tun-exclude" or "direct"
	var cleanEx []string
	for _, ex := range a.cfg.Tun.Exclude {
		if normAppName(ex) != n {
			cleanEx = append(cleanEx, ex)
		}
	}
	a.cfg.Tun.Exclude = cleanEx

	if outbound == "tun-exclude" {
		a.cfg.Tun.Exclude = append(a.cfg.Tun.Exclude, exe)
		ruleName := "Приложение: " + exe
		if pr, ok := presetForApp(exe); ok {
			ruleName = pr.Title + " (" + exe + ")"
		}
		kept = append([]Rule{{Name: ruleName, Outbound: obDirect, Apps: []string{exe}, Always: true}}, kept...)
	} else if outbound != "" {
		if outbound == obDirect && a.cfg.Tun.Enabled && !slices.Contains(a.cfg.Tun.Exclude, exe) {
			a.cfg.Tun.Exclude = append(a.cfg.Tun.Exclude, exe)
		}
		ruleName := "Приложение: " + exe
		if pr, ok := presetForApp(exe); ok {
			ruleName = pr.Title + " (" + exe + ")"
		}
		kept = append([]Rule{{Name: ruleName, Outbound: outbound, Apps: []string{exe}, Always: true}}, kept...)
	}
	a.cfg.Routing.Rules = kept
	a.cfg.mu.Unlock()
	_ = a.cfg.save()
	a.onRulesChanged()
	if outbound == "" {
		logf("info", "Маршрут для %s сброшен (применяются общие правила)", exe)
	} else {
		logf("info", "Маршрут для программы %s → %s", exe, outbound)
	}
	return nil
}

// appsView returns the combined list of running processes, active network apps,
// configured per-app rules, and the popular app catalog. Includes both
// ("apps"/"presets", "app"/"route") for Gio UI and ("running"/"catalog",
// "exe"/"outbound") aliases for Web UI and API tests.
func (a *App) appsView() map[string]any {
	osProcs := listRunningProcesses()
	snap := a.stats.snapshot()
	statApps, _ := snap["apps"].([]map[string]any)

	type entry struct {
		exe      string
		title    string
		category string
		running  bool
		pids     int
		conns    int
		bytes    int64
		route    string
	}
	byNorm := map[string]*entry{}
	getOrMake := func(rawExe string) *entry {
		n := normAppName(rawExe)
		if n == "" {
			return nil
		}
		if e := byNorm[n]; e != nil {
			return e
		}
		exe := rawExe
		if !strings.Contains(exe, ".") {
			exe += ".exe"
		}
		title, cat := exe, "Запущенные программы"
		if pr, ok := presetForApp(exe); ok {
			exe, title, cat = pr.Exe, pr.Title, pr.Category
		}
		e := &entry{exe: exe, title: title, category: cat, route: a.appCurrentRoute(exe)}
		byNorm[n] = e
		return e
	}

	for _, p := range osProcs {
		if isNoiseProc(p.Name) {
			continue
		}
		if e := getOrMake(p.Name); e != nil {
			e.running = true
			e.pids += p.Count
		}
	}
	for _, sa := range statApps {
		appName, _ := sa["app"].(string)
		if appName == "" || appName == "—" || isNoiseProc(appName) {
			continue
		}
		if strings.Count(appName, ".") == 3 && !strings.HasSuffix(strings.ToLower(appName), ".exe") {
			continue
		}
		if e := getOrMake(appName); e != nil {
			c, _ := sa["conns"].(int)
			u, _ := sa["up"].(int64)
			d, _ := sa["down"].(int64)
			e.conns += c
			e.bytes += u + d
		}
	}
	var configured []string
	a.cfg.mu.Lock()
	for _, ru := range a.cfg.Routing.Rules {
		for _, ap := range ru.Apps {
			if ap = strings.TrimSpace(ap); ap != "" && !strings.HasPrefix(ap, "!") {
				configured = append(configured, ap)
			}
		}
	}
	configured = append(configured, a.cfg.Tun.Exclude...)
	a.cfg.mu.Unlock()
	for _, ap := range configured {
		if ap != "" && !isNoiseProc(ap) {
			_ = getOrMake(ap)
		}
	}

	list := make([]map[string]any, 0, len(byNorm))
	for _, e := range byNorm {
		list = append(list, map[string]any{
			"app":      e.exe,
			"exe":      e.exe,
			"title":    e.title,
			"category": e.category,
			"running":  e.running,
			"pids":     e.pids,
			"conns":    e.conns,
			"bytes":    e.bytes,
			"route":    e.route,
			"outbound": e.route,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		ri, rj := list[i]["route"].(string) != "", list[j]["route"].(string) != ""
		if ri != rj {
			return ri
		}
		bi, bj := list[i]["bytes"].(int64), list[j]["bytes"].(int64)
		if bi != bj {
			return bi > bj
		}
		runI, runJ := list[i]["running"].(bool), list[j]["running"].(bool)
		if runI != runJ {
			return runI
		}
		return strings.ToLower(list[i]["title"].(string)) < strings.ToLower(list[j]["title"].(string))
	})

	presets := make([]map[string]any, 0, len(popularApps))
	for _, p := range popularApps {
		rt := a.appCurrentRoute(p.Exe)
		_, isRun := byNorm[normAppName(p.Exe)]
		presets = append(presets, map[string]any{
			"app":         p.Exe,
			"exe":         p.Exe,
			"title":       p.Title,
			"category":    p.Category,
			"recommended": p.Rec,
			"running":     isRun,
			"route":       rt,
			"outbound":    rt,
		})
	}
	return map[string]any{
		"ok":      true,
		"apps":    list,
		"running": list,
		"presets": presets,
		"catalog": presets,
	}
}

func (a *App) appsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, a.appsView())
		return
	}
	var req struct {
		App      string `json:"app"`
		Exe      string `json:"exe"`
		Outbound string `json:"outbound"`
		Route    string `json:"route"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, 400, "ошибка в данных запроса")
		return
	}
	target := req.App
	if target == "" {
		target = req.Exe
	}
	ob := req.Outbound
	if ob == "" && req.Route != "" {
		ob = req.Route
	}
	if err := a.SetAppRoute(target, ob); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, a.appsView())
}

// nextAppCountry cycles the "Страна" button of a program:
// (any) → psiphon:DE → psiphon:NL → … → psiphon:SG → psiphon (no country).
func nextAppCountry(route string) string {
	if cur, ok := strings.CutPrefix(route, obPsiphon+":"); ok {
		for i, cc := range countryChoices {
			if cc == cur {
				if i+1 < len(countryChoices) {
					return obPsiphon + ":" + countryChoices[i+1]
				}
				return obPsiphon
			}
		}
	}
	return obPsiphon + ":" + countryChoices[0]
}
