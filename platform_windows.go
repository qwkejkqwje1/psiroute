//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	wininet                 = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption   = wininet.NewProc("InternetSetOptionW")
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	user32Clip              = windows.NewLazySystemDLL("user32.dll")
	procOpenClipboard       = user32Clip.NewProc("OpenClipboard")
	procCloseClipboard      = user32Clip.NewProc("CloseClipboard")
	procEmptyClipboard      = user32Clip.NewProc("EmptyClipboard")
	procGetClipboardData    = user32Clip.NewProc("GetClipboardData")
	procSetClipboardData    = user32Clip.NewProc("SetClipboardData")
	kernel32Clip            = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalAlloc         = kernel32Clip.NewProc("GlobalAlloc")
	procGlobalFree          = kernel32Clip.NewProc("GlobalFree")
	procGlobalLock          = kernel32Clip.NewProc("GlobalLock")
	procGlobalUnlock        = kernel32Clip.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

// setPlatformSocketTTL sets IP_TTL (4) and IPV6_UNICAST_HOPS (4) on a Windows socket handle.
func setPlatformSocketTTL(fd uintptr, ttl int) {
	h := windows.Handle(fd)
	_ = windows.SetsockoptInt(h, windows.IPPROTO_IP, 4, ttl)
	_ = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, 4, ttl)
}

func uintptrToPtr(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

var (
	sysProxyMu      sync.Mutex
	sysProxyMockFn  func(addr string, on bool) error
	autostartMockFn func(on bool) error
)

func isRunningTests() bool {
	if len(os.Args) > 0 {
		base := strings.ToLower(filepath.Base(os.Args[0]))
		if strings.HasSuffix(base, ".test.exe") || strings.HasSuffix(base, ".test") {
			return true
		}
	}
	return false
}

// writeClipboardText записывает текст в системный буфер обмена Windows напрямую через Win32 API,
// гарантируя работу копирования даже когда clipboard.WriteCmd в Gio теряет фокус окна (Раздел 1.2 ТЗ).
func writeClipboardText(val string) bool {
	if val == "" {
		return false
	}
	u16, err := syscall.UTF16FromString(val)
	if err != nil {
		return false
	}
	r, _, _ := procOpenClipboard.Call(0)
	if r == 0 {
		return false
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()

	byteLen := uintptr(len(u16) * 2)
	hMem, _, _ := procGlobalAlloc.Call(gmemMoveable, byteLen)
	if hMem == 0 {
		return false
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return false
	}
	dst := unsafe.Slice((*uint16)(uintptrToPtr(ptr)), len(u16))
	copy(dst, u16)
	procGlobalUnlock.Call(hMem)

	if res, _, _ := procSetClipboardData.Call(cfUnicodeText, hMem); res == 0 {
		procGlobalFree.Call(hMem)
		return false
	}
	return true
}

// readClipboardText читает текст из системного буфера обмена Windows через Win32 GetClipboardData(CF_UNICODETEXT),
// чтобы кнопка «Вставить» и Ctrl+V работали независимо от раскладки клавиатуры в Gio (Раздел 1.2 ТЗ).
func readClipboardText() string {
	r, _, _ := procOpenClipboard.Call(0)
	if r == 0 {
		return ""
	}
	defer procCloseClipboard.Call()
	hMem, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if hMem == 0 {
		return ""
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return ""
	}
	defer procGlobalUnlock.Call(hMem)
	return windows.UTF16PtrToString((*uint16)(uintptrToPtr(ptr)))
}

const (
	inetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	runKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
)

const savedKey = `Software\Psiroute\SavedProxy`

// setSystemProxy points Windows (and every app that follows system settings)
// at the local proxy port. The user's previous proxy settings are saved on
// enable and restored on disable (they used to be overwritten and lost).
func setSystemProxy(addr string, on bool) error {
	sysProxyMu.Lock()
	mock := sysProxyMockFn
	sysProxyMu.Unlock()
	if mock != nil {
		return mock(addr, on)
	}
	if isRunningTests() {
		// Ни при каких условиях не изменяем системный прокси реального Windows во время тестов!
		return nil
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if on {
		saveUserProxy(k, addr)
		if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
			return err
		}
		_ = k.SetStringValue("ProxyServer", addr)
		_ = k.SetStringValue("ProxyOverride", "<local>;localhost;127.*;[::1];10.*;172.16.*;192.168.*")
	} else if !restoreUserProxy(k) {
		if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
			return err
		}
	}
	procInternetSetOption.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	procInternetSetOption.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
	return nil
}

// saveUserProxy remembers the current settings unless they are already ours
// (or already saved), so repeated enables never save our own values.
func saveUserProxy(k registry.Key, ours string) {
	if sk, err := registry.OpenKey(registry.CURRENT_USER, savedKey, registry.QUERY_VALUE); err == nil {
		sk.Close()
		return
	}
	en, _, _ := k.GetIntegerValue("ProxyEnable")
	srv, _, _ := k.GetStringValue("ProxyServer")
	ov, _, _ := k.GetStringValue("ProxyOverride")
	if isOurProxy(srv, ours) {
		return
	}
	sk, _, err := registry.CreateKey(registry.CURRENT_USER, savedKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer sk.Close()
	_ = sk.SetDWordValue("ProxyEnable", uint32(en))
	_ = sk.SetStringValue("ProxyServer", srv)
	_ = sk.SetStringValue("ProxyOverride", ov)
}

func restoreUserProxy(k registry.Key) bool {
	sk, err := registry.OpenKey(registry.CURRENT_USER, savedKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	en, _, _ := sk.GetIntegerValue("ProxyEnable")
	srv, _, _ := sk.GetStringValue("ProxyServer")
	ov, _, _ := sk.GetStringValue("ProxyOverride")
	sk.Close()
	_ = k.SetDWordValue("ProxyEnable", uint32(en))
	if srv == "" {
		_ = k.DeleteValue("ProxyServer")
	} else {
		_ = k.SetStringValue("ProxyServer", srv)
	}
	if ov == "" {
		_ = k.DeleteValue("ProxyOverride")
	} else {
		_ = k.SetStringValue("ProxyOverride", ov)
	}
	_ = registry.DeleteKey(registry.CURRENT_USER, savedKey)
	return true
}

// isOurProxy reports whether a ProxyServer value points at one of our addrs.
func isOurProxy(srv string, ours ...string) bool {
	for _, o := range ours {
		if o != "" && (srv == o || strings.Contains(srv, "="+o)) {
			return true
		}
	}
	return false
}

// systemProxyOwnedBy reports an enabled system proxy pointing at us.
func systemProxyOwnedBy(addrs ...string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	en, _, _ := k.GetIntegerValue("ProxyEnable")
	srv, _, _ := k.GetStringValue("ProxyServer")
	return en == 1 && isOurProxy(srv, addrs...)
}

const schtasksAutostartName = "PsiRoute Autostart"

func autostartTaskExists() bool {
	if isRunningTests() {
		return false
	}
	cmd := exec.Command("schtasks.exe", "/Query", "/TN", schtasksAutostartName)
	hideConsole(cmd)
	return cmd.Run() == nil
}

func autostartEnabled() bool {
	if autostartTaskExists() {
		return true
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("Psiroute")
	return err == nil
}

// setAutostart регистрирует чистый автозапуск без всплывающих окон UAC:
// если программа запущена с правами администратора (для режима TUN), создаётся задание
// в Планировщике заданий Windows (Task Scheduler) с флагом /RL HIGHEST (Run with highest privileges),
// а также запись в реестре HKCU\...\Run в качестве резерва.
func setAutostart(on bool) error {
	sysProxyMu.Lock()
	mock := autostartMockFn
	sysProxyMu.Unlock()
	if mock != nil {
		return mock(on)
	}
	if isRunningTests() {
		return nil
	}
	if !on {
		delCmd := exec.Command("schtasks.exe", "/Delete", "/TN", schtasksAutostartName, "/F")
		hideConsole(delCmd)
		_ = delCmd.Run()
	} else if isElevated() {
		if exe, err := os.Executable(); err == nil {
			tr := fmt.Sprintf(`"%s" --minimized`, exe)
			createCmd := exec.Command("schtasks.exe", "/Create", "/TN", schtasksAutostartName, "/TR", tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
			hideConsole(createCmd)
			if createCmd.Run() == nil {
				logf("info", "Автозапуск зарегистрирован через Планировщик заданий Windows (RL HIGHEST, без окон UAC)")
			}
		}
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if on {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		return k.SetStringValue("Psiroute", "\""+exe+"\" --minimized")
	}
	if err := k.DeleteValue("Psiroute"); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

// installBackgroundService регистрирует сетевое ядро PsiRoute как системное задание/службу
// с наивысшими привилегиями (NT AUTHORITY\SYSTEM / RL HIGHEST), чтобы режим TUN работал без запросов UAC.
func installBackgroundService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tr := fmt.Sprintf(`"%s" --minimized`, exe)
	cmd := exec.Command("schtasks.exe", "/Create", "/TN", schtasksAutostartName, "/TR", tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
	hideConsole(cmd)
	return cmd.Run()
}

func uninstallBackgroundService() error {
	cmd := exec.Command("schtasks.exe", "/Delete", "/TN", schtasksAutostartName, "/F")
	hideConsole(cmd)
	return cmd.Run()
}

func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

type pidName struct {
	name string
	exp  time.Time
}

var pidNames sync.Map // uint32 -> pidName; entries expire, PIDs get reused

// appForConn finds which program opened a local connection (by its source
// port in the TCP table). LAN-share clients are shown by IP.
func appForConn(remote net.Addr) string {
	ta, ok := remote.(*net.TCPAddr)
	if !ok {
		return ""
	}
	if !ta.IP.IsLoopback() {
		return ta.IP.String()
	}
	if ta.IP.To4() == nil {
		return "" // IPv6 loopback: the IPv4 table does not have it
	}
	pid := pidForPort(ta.Port)
	if pid == 0 {
		return ""
	}
	if v, ok := pidNames.Load(pid); ok && time.Now().Before(v.(pidName).exp) {
		return v.(pidName).name
	}
	name := procName(pid)
	pidNames.Store(pid, pidName{name, time.Now().Add(time.Minute)})
	return name
}

// The TCP table is fetched at most every 500 ms and shared by all new
// connections (it was fetched once per connection before).
var tcpTab struct {
	mu   sync.Mutex
	at   time.Time
	map_ map[int]uint32
}

func pidForPort(port int) uint32 {
	tcpTab.mu.Lock()
	defer tcpTab.mu.Unlock()
	if pid, ok := tcpTab.map_[port]; ok && time.Since(tcpTab.at) < 500*time.Millisecond {
		return pid
	}
	tcpTab.map_ = loadTCPTable()
	tcpTab.at = time.Now()
	return tcpTab.map_[port]
}

func loadTCPTable() map[int]uint32 {
	m := map[int]uint32{}
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0) // AF_INET, TCP_TABLE_OWNER_PID_ALL
	if size == 0 {
		return m
	}
	buf := make([]byte, size+4096)
	size = uint32(len(buf))
	r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0)
	if r != 0 {
		return m
	}
	n := int(binary.LittleEndian.Uint32(buf[0:4]))
	for i := 0; i < n; i++ {
		off := 4 + i*24 // MIB_TCPROW_OWNER_PID
		if off+24 > len(buf) {
			break
		}
		lp := int(buf[off+8])<<8 | int(buf[off+9])
		m[lp] = binary.LittleEndian.Uint32(buf[off+20:])
	}
	return m
}

func procName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return filepath.Base(windows.UTF16ToString(buf[:n]))
}

type runningProc struct {
	Name  string
	Count int
}

// listRunningProcesses enumerates active processes on Windows via Toolhelp32.
func listRunningProcesses() []runningProc {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	counts := map[string]int{}
	names := map[string]string{}
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err := syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		exe := windows.UTF16ToString(e.ExeFile[:])
		if exe == "" {
			continue
		}
		key := strings.ToLower(exe)
		counts[key]++
		if _, ok := names[key]; !ok {
			names[key] = exe
		}
	}
	out := make([]runningProc, 0, len(counts))
	for k, c := range counts {
		out = append(out, runningProc{Name: names[k], Count: c})
	}
	return out
}
