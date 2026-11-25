package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WFP Kill Switch modes (3 modes per TZ):
//   - "off":    no OS-level firewall blocking
//   - "auto":   activates OS-level WFP block automatically when VPN/TUN drops unexpectedly
//   - "strict": permanent OS-level WFP block allowing only loopback, LAN (RFC1918),
//     Wintun interface, and psiroute.exe itself
const (
	wfpModeOff    = "off"
	wfpModeAuto   = "auto"
	wfpModeStrict = "strict"
)

func normalizeKillSwitchMode(mode string, legacyBool bool) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case wfpModeStrict:
		return wfpModeStrict
	case wfpModeAuto:
		return wfpModeAuto
	case wfpModeOff:
		return wfpModeOff
	default:
		if legacyBool {
			return wfpModeAuto
		}
		return wfpModeOff
	}
}

type wfpBackend interface {
	Apply(exePath string, strict bool) error
	Clear() error
}

// wfpKillSwitch manages OS-level Windows Filtering Platform (via Windows Firewall
// WFP engine) rules and crash-recovery orphan cleanup.
type wfpKillSwitch struct {
	mu      sync.Mutex
	dataDir string
	mode    string
	engaged bool
	lastErr string
	since   int64
	backend wfpBackend
}

func newWFPKillSwitch(dataDir string) *wfpKillSwitch {
	return &wfpKillSwitch{
		dataDir: dataDir,
		mode:    wfpModeOff,
		backend: defaultWFPBackend(),
	}
}

func (k *wfpKillSwitch) lockPath() string {
	if k == nil || k.dataDir == "" {
		return ""
	}
	return filepath.Join(k.dataDir, "psiroute-wfp.lock")
}

// CleanupOrphans removes any leftover PsiRoute WFP Kill Switch rules after an
// unexpected crash or power loss.
func (k *wfpKillSwitch) CleanupOrphans() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	lp := k.lockPath()
	hadLock := false
	if lp != "" {
		if _, err := os.Stat(lp); err == nil {
			hadLock = true
		}
	}
	if k.backend != nil {
		if err := k.backend.Clear(); err != nil && hadLock {
			logf("warn", "WFP Kill Switch: не удалось очистить сиротские фильтры: %v", err)
		} else if hadLock {
			logf("info", "WFP Kill Switch: очищены сиротские фильтры после аварийного завершения")
		}
	}
	if lp != "" {
		_ = os.Remove(lp)
	}
	k.engaged = false
	k.lastErr = ""
}

// Sync updates OS-level WFP filters according to the configured mode and current
// tunnel health (vpnUp, userStopped, tunOn).
func (k *wfpKillSwitch) Sync(mode string, vpnUp, userStopped, tunOn bool) {
	if k == nil {
		return
	}
	mode = normalizeKillSwitchMode(mode, false)
	wantEngage := false
	switch mode {
	case wfpModeStrict:
		wantEngage = !userStopped
	case wfpModeAuto:
		// Engage OS-level block when TUN is active and VPN dropped unexpectedly
		wantEngage = tunOn && !vpnUp && !userStopped
	default:
		wantEngage = false
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	k.mode = mode
	if wantEngage == k.engaged {
		return
	}
	if k.backend == nil {
		k.engaged = wantEngage
		return
	}
	if wantEngage {
		exe, _ := os.Executable()
		if err := k.backend.Apply(exe, mode == wfpModeStrict); err != nil {
			k.lastErr = err.Error()
			logf("warn", "WFP Kill Switch (%s): ошибка активации: %v", mode, err)
			return
		}
		k.engaged = true
		k.lastErr = ""
		k.since = time.Now().Unix()
		if lp := k.lockPath(); lp != "" {
			_ = os.WriteFile(lp, []byte(mode+"\n"), 0o600)
		}
		logf("warn", "WFP Kill Switch (%s): системная блокировка утечек АКТИВИРОВАНА", mode)
		return
	}

	if err := k.backend.Clear(); err != nil {
		k.lastErr = err.Error()
		logf("warn", "WFP Kill Switch: ошибка снятия фильтров: %v", err)
		return
	}
	k.engaged = false
	k.lastErr = ""
	k.since = 0
	if lp := k.lockPath(); lp != "" {
		_ = os.Remove(lp)
	}
	logf("info", "WFP Kill Switch: системная блокировка снята")
}

func (k *wfpKillSwitch) Close() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.engaged && k.backend != nil {
		_ = k.backend.Clear()
	}
	k.engaged = false
	if lp := k.lockPath(); lp != "" {
		_ = os.Remove(lp)
	}
}

func (k *wfpKillSwitch) View() map[string]any {
	if k == nil {
		return map[string]any{"mode": wfpModeOff, "engaged": false, "supported": false}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return map[string]any{
		"mode":      k.mode,
		"engaged":   k.engaged,
		"since":     k.since,
		"error":     k.lastErr,
		"supported": wfpSupported,
	}
}
