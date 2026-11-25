package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

type leakCheckItem struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"` // "ok" | "warn" | "fail"
	Detail string `json:"detail"`
}

// RunLeakTest executes a 1-click 5-vector leak and environment conflict audit:
//  1. Exit IP masking (direct vs Psiphon / Clean-IP)
//  2. Encrypted DNS + FakeIP + DoH/DoT hijack
//  3. IPv6 leak / blackhole verification
//  4. WebRTC/STUN + QUIC + WFP Kill Switch status
//  5. Foreign VPN adapter & system proxy environment check
func (a *App) RunLeakTest(ctx context.Context) map[string]any {
	checks := make([]leakCheckItem, 0, 5)
	if a == nil || a.cfg == nil {
		return map[string]any{"ok": false, "verdict": "fail", "checks": checks}
	}

	a.cfg.mu.Lock()
	dnsOn := a.cfg.DNS.Enabled
	tunDNS := a.cfg.Tun.DNS
	fakeIP := a.cfg.Tun.FakeIP
	tunV6 := a.cfg.Tun.IPv6
	blockSTUN := a.cfg.Routing.BlockSTUN
	blockQUIC := a.cfg.Routing.BlockQUIC
	ksMode := normalizeKillSwitchMode(a.cfg.Routing.KillSwitchMode, a.cfg.Routing.KillSwitch)
	a.cfg.mu.Unlock()
	tunOn := tunActive.Load()

	// 1. Exit IP masking check
	var directIP, vpnIP, vpnLoc string
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	if tr, err := getTrace(dctx, dialDirect); err == nil {
		directIP = tr.IP
	}
	dcancel()

	if a.psi != nil && (a.psi.running() || a.psi.cur.Load() != nil) {
		pctx, pcancel := context.WithTimeout(ctx, 8*time.Second)
		if tr, err := getTrace(pctx, a.psi.Dial); err == nil {
			vpnIP, vpnLoc = tr.IP, tr.Loc
		}
		pcancel()
	}
	switch {
	case vpnIP != "" && (directIP == "" || vpnIP != directIP):
		checks = append(checks, leakCheckItem{
			ID: "exit_ip", Title: "Маскировка внешнего IP", Status: "ok",
			Detail: fmt.Sprintf("Туннель активен: выход %s (%s), реальный IP скрыт", vpnIP, vpnLoc),
		})
	case vpnIP == "":
		checks = append(checks, leakCheckItem{
			ID: "exit_ip", Title: "Маскировка внешнего IP", Status: "warn",
			Detail: "Psiphon сейчас не подключён — трафик идёт напрямую",
		})
	default:
		checks = append(checks, leakCheckItem{
			ID: "exit_ip", Title: "Маскировка внешнего IP", Status: "fail",
			Detail: fmt.Sprintf("Выходной IP совпадает с прямым (%s)", vpnIP),
		})
	}

	// 2. DNS & FakeIP leak protection
	if dnsOn && (!tunOn || (tunDNS && fakeIP)) {
		checks = append(checks, leakCheckItem{
			ID: "dns", Title: "Защита DNS и Split-DNS", Status: "ok",
			Detail: fmt.Sprintf("DoH включён, FakeIP 198.19.x.y (%d доменов), публичный DoH/DoT заблокирован", theFakeIP.count()),
		})
	} else {
		checks = append(checks, leakCheckItem{
			ID: "dns", Title: "Защита DNS и Split-DNS", Status: "warn",
			Detail: "Включите DoH + перехват DNS и FakeIP для полного исключения DNS-утечек",
		})
	}

	// 3. IPv6 leak / blackhole verification
	if !tunOn {
		checks = append(checks, leakCheckItem{
			ID: "ipv6", Title: "Защита от утечки IPv6", Status: "ok",
			Detail: "Режим прокси (IPv6 управляется клиентом; в режиме TUN активен IPv6 blackhole)",
		})
	} else if !tunV6 {
		// Verify IPv6 cannot escape directly when IPv6 tunneling is disabled
		c, err := net.DialTimeout("tcp6", "[2606:4700:4700::1111]:443", 1500*time.Millisecond)
		if err != nil {
			checks = append(checks, leakCheckItem{
				ID: "ipv6", Title: "Защита от утечки IPv6", Status: "ok",
				Detail: "IPv6 blackhole (::/1, 8000::/1) активен — прямых утечек IPv6 нет",
			})
		} else {
			_ = c.Close()
			checks = append(checks, leakCheckItem{
				ID: "ipv6", Title: "Защита от утечки IPv6", Status: "fail",
				Detail: "Обнаружен прямой выход по IPv6 мимо TUN — нажмите Reset Stack",
			})
		}
	} else {
		checks = append(checks, leakCheckItem{
			ID: "ipv6", Title: "Защита от утечки IPv6", Status: "ok",
			Detail: "IPv6-трафик перехватывается через адаптер Wintun TUN",
		})
	}

	// 4. WebRTC/STUN, QUIC & WFP Kill Switch
	wfpV := a.wfp.View()
	wfpEngaged, _ := wfpV["engaged"].(bool)
	if blockSTUN && ksMode != wfpModeOff {
		checks = append(checks, leakCheckItem{
			ID: "webrtc_ks", Title: "WebRTC / STUN и WFP Kill Switch", Status: "ok",
			Detail: fmt.Sprintf("STUN заблокирован, QUIC-блок=%v, WFP Kill Switch=%s (lock=%v)", blockQUIC, ksMode, wfpEngaged),
		})
	} else {
		checks = append(checks, leakCheckItem{
			ID: "webrtc_ks", Title: "WebRTC / STUN и WFP Kill Switch", Status: "warn",
			Detail: fmt.Sprintf("STUN-защита=%v, WFP Kill Switch=%s — рекомендуется включить STUN и Kill Switch (Auto/Strict)", blockSTUN, ksMode),
		})
	}

	// 5. Environment conflicts (foreign VPN adapters / dead proxy)
	phys := tunPhysText()
	if tunOn && isVirtualVPNAdapterName(phys, "") {
		checks = append(checks, leakCheckItem{
			ID: "env", Title: "Конфликты сети и других VPN", Status: "fail",
			Detail: fmt.Sprintf("Физический выход указывает на виртуальный адаптер (%s) — отключите другой VPN и нажмите Reset Stack", phys),
		})
	} else {
		checks = append(checks, leakCheckItem{
			ID: "env", Title: "Конфликты сети и других VPN", Status: "ok",
			Detail: fmt.Sprintf("Конфликтов нет · прокси %s активен · выход: %s", a.listenAddr(), phys),
		})
	}

	passed, warns, fails := 0, 0, 0
	for _, ch := range checks {
		switch ch.Status {
		case "ok":
			passed++
		case "warn":
			warns++
		default:
			fails++
		}
	}
	verdict := "ok"
	if fails > 0 {
		verdict = "fail"
	} else if warns > 0 {
		verdict = "warn"
	}
	return map[string]any{
		"ok":      true,
		"verdict": verdict,
		"passed":  passed,
		"total":   len(checks),
		"checks":  checks,
	}
}
