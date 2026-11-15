//go:build windows

package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

var (
	procIsUserAnAdmin    = dtShell32.NewProc("IsUserAnAdmin")
	procAllowSetFg       = dtUser32.NewProc("AllowSetForegroundWindow")
	procNotifyAddrChange = iphlpapi.NewProc("NotifyAddrChange")
)

const webview2GUID = `{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

// windowsVersion from the registry (RtlGetVersion is not needed for this;
// ProductName still says "Windows 10" on Windows 11, the build tells).
func windowsVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuild")
	disp, _, _ := k.GetStringValue("DisplayVersion")
	ubr, _, _ := k.GetIntegerValue("UBR")
	if b, _ := strconv.Atoi(build); b >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	if name == "" {
		name = "Windows"
	}
	if disp != "" {
		name += " " + disp
	}
	if build != "" {
		name += " (сборка " + build
		if ubr > 0 {
			name += "." + strconv.FormatUint(ubr, 10)
		}
		name += ")"
	}
	return name
}

func webview2Version() string {
	for _, p := range []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + webview2GUID},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webview2GUID},
		{registry.CURRENT_USER, `Software\Microsoft\EdgeUpdate\Clients\` + webview2GUID},
	} {
		k, err := registry.OpenKey(p.root, p.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetStringValue("pv")
		k.Close()
		if err == nil && v != "" && v != "0.0.0.0" {
			return v
		}
	}
	return ""
}

func autostartCommand() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("Psiroute")
	return v
}

func platformChecks(a *App) []check {
	out := []check{{"Windows", "info", windowsVersion()}}
	if procIsUserAnAdmin.Find() == nil {
		if r, _, _ := procIsUserAnAdmin.Call(); r != 0 {
			out = append(out, check{"Права", "info", "запущен от имени администратора (доступен режим TUN)"})
		} else if a != nil && a.cfg.tunWanted() {
			out = append(out, check{"Права", "warn", "обычный пользователь — для режима TUN нужен запуск от администратора"})
		}
	}
	out = append(out, check{"Графический интерфейс", "ok", "нативное окно Win32 (без WebView2, экономия ~120–150 МБ ОЗУ)"})
	if cmd := autostartCommand(); cmd == "" {
		out = append(out, check{"Автозапуск", "info", "выключен"})
	} else if exe, err := os.Executable(); err == nil && !strings.Contains(strings.ToLower(cmd), strings.ToLower(exe)) {
		out = append(out, check{"Автозапуск", "warn", "указывает на другой файл (" + cmd + ") — выключите и включите его в настройках"})
	} else {
		out = append(out, check{"Автозапуск", "ok", "включён"})
	}
	if a != nil {
		a.mu.Lock()
		on, listen := a.sysOn, a.listenActual
		a.mu.Unlock()
		owned := listen != "" && systemProxyOwnedBy(listen)
		switch {
		case on && owned:
			out = append(out, check{"Системный прокси", "ok", "указывает на Psiroute (" + listen + ")"})
		case on:
			out = append(out, check{"Системный прокси", "warn", "включён в Psiroute, но в Windows другие настройки — их сменила другая программа"})
		case owned:
			out = append(out, check{"Системный прокси", "warn", "Windows указывает на Psiroute, хотя в Psiroute он выключен"})
		default:
			out = append(out, check{"Системный прокси", "info", "выключен"})
		}
	}
	return out
}

// portOwner: which program holds a local TCP port.
func portOwner(addr string) string {
	_, ps, err := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(ps)
	if err != nil || port == 0 {
		return ""
	}
	pid := loadTCPTable()[port]
	if pid == 0 {
		return ""
	}
	if n := procName(pid); n != "" {
		return n + ", PID " + strconv.Itoa(int(pid))
	}
	return "PID " + strconv.Itoa(int(pid))
}

// revealFile opens Explorer with the file selected (sanitizing path quotes).
func revealFile(path string) {
	clean := strings.ReplaceAll(filepath.Clean(path), `"`, "")
	if clean == "" {
		return
	}
	cmd := exec.Command("explorer.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `explorer.exe /select,"` + clean + `"`}
	_ = cmd.Start()
}

func openWithDefault(path string) {
	clean := strings.ReplaceAll(filepath.Clean(path), `"`, "")
	if clean != "" {
		_ = exec.Command("notepad.exe", clean).Start()
	}
}

// allowForeground lets a child process (the restarted core, the window)
// bring its window to the front.
func allowForeground(pid int) {
	if procAllowSetFg.Find() == nil {
		_, _, _ = procAllowSetFg.Call(uintptr(pid))
	}
}

// platformNetNotify: NotifyAddrChange blocks until an IPv4 address changes.
func platformNetNotify(ctx context.Context, w *netWatch) {
	if procNotifyAddrChange.Find() != nil {
		return
	}
	for ctx.Err() == nil {
		r, _, _ := procNotifyAddrChange.Call(0, 0)
		if ctx.Err() != nil {
			return
		}
		if r != 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		w.Kick("net")
	}
}
