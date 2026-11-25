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

func isOurProxy(srv string, ours ...string) bool {
	for _, o := range ours {
		if o != "" && (srv == o || strings.Contains(srv, "="+o)) {
			return true
		}
	}
	return false
}

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

// exeDirUserWritable reports whether ordinary users (Users, Everyone,
// Authenticated Users) have a write-type allow ACE on path. SIDs are used, not
// names, so it works on every Windows language.
func exeDirUserWritable(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return true, nil // a NULL DACL gives everyone full access
	}
	var sids []*windows.SID
	for _, str := range []string{"S-1-5-32-545", "S-1-1-0", "S-1-5-11"} {
		if sid, serr := windows.StringToSid(str); serr == nil {
			sids = append(sids, sid)
		}
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if gerr := windows.GetAce(dacl, i, &ace); gerr != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != 0 { // 0 = ACCESS_ALLOWED_ACE_TYPE
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, u := range sids {
			if sid.Equals(u) && aceMaskAllowsWrite(uint32(ace.Mask)) {
				return true, nil
			}
		}
	}
	return false, nil
}

// exeLocationUserWritable checks the folder of the exe and the exe itself.
func exeLocationUserWritable(exe string) (bool, error) {
	var firstErr error
	for _, p := range []string{filepath.Dir(exe), exe} {
		w, err := exeDirUserWritable(p)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if w {
			return true, nil
		}
	}
	return false, firstErr
}

func deleteAutostartTask() {
	delCmd := exec.Command("schtasks.exe", "/Delete", "/TN", schtasksAutostartName, "/F")
	hideConsole(delCmd)
	_ = delCmd.Run()
}

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
		deleteAutostartTask()
		setAutostartWarning("")
		return deleteRunValue()
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	writable, werr := exeLocationUserWritable(exe)
	plan := planAutostart(isElevated(), writable, werr, autostartTaskExists())
	if plan.RemoveTask {
		deleteAutostartTask()
	}
	if plan.UseTask {
		tr := fmt.Sprintf(`"%s" --minimized`, exe)
		createCmd := exec.Command("schtasks.exe", "/Create", "/TN", schtasksAutostartName, "/TR", tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
		hideConsole(createCmd)
		if cerr := createCmd.Run(); cerr == nil {
			logf("info", "Автозапуск зарегистрирован через Планировщик заданий Windows (RL HIGHEST, без окон UAC; папка программы защищена от записи)")
		} else {
			// The task could not be created: fall back to the plain Run value.
			logf("warn", "Задача автозапуска не создана (%v), использую обычный автозапуск без повышенных прав", cerr)
			plan.UseRunKey, plan.RemoveRunKey = true, false
		}
	}
	if plan.RemoveRunKey {
		if derr := deleteRunValue(); derr != nil {
			logf("warn", "Не удалось убрать запись автозапуска из реестра: %v", derr)
		}
	}
	setAutostartWarning(plan.Warning)
	if plan.Warning != "" {
		logf("warn", "%s", plan.Warning)
	}
	if plan.UseRunKey {
		return setRunValue(exe)
	}
	return nil
}

func deleteRunValue() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue("Psiroute"); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

func setRunValue(exe string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("Psiroute", "\""+exe+"\" --minimized")
}

func installBackgroundService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if writable, werr := exeLocationUserWritable(exe); writable || werr != nil {
		return fmt.Errorf("%s", autostartWarnWritable)
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

// appForConn определяет процесс локального подключения по порту источника в таблице TCP Windows
// (включая IPv6 loopback и мгновенное обновление кэша, если сокет открылся меньше 500 мс назад — Баг 4).
func appForConn(remote net.Addr) string {
	ta, ok := remote.(*net.TCPAddr)
	if !ok {
		return ""
	}
	if !ta.IP.IsLoopback() {
		return ta.IP.String()
	}
	var pid uint32
	if ta.IP.To4() == nil {
		pid = ownerPID("tcp", true, uint16(ta.Port))
	} else {
		pid = pidForPort(ta.Port)
		if pid == 0 {
			pid = ownerPID("tcp", false, uint16(ta.Port))
		}
	}
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

var tcpTab struct {
	mu   sync.Mutex
	at   time.Time
	map_ map[int]uint32
}

func pidForPort(port int) uint32 {
	tcpTab.mu.Lock()
	defer tcpTab.mu.Unlock()
	if pid, ok := tcpTab.map_[port]; ok && pid != 0 && time.Since(tcpTab.at) < 500*time.Millisecond {
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

// clearDeadLoopbackProxy checks if Windows System Proxy is still pointing to a
// closed localhost port left behind by another VPN (e.g. Clash 127.0.0.1:7890,
// v2rayN 127.0.0.1:10808). If unreachable, disables ProxyEnable so TUN traffic
// is not blackholed by a dead local proxy.
func clearDeadLoopbackProxy(ourAddrs ...string) string {
	if isRunningTests() {
		return ""
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	en, _, _ := k.GetIntegerValue("ProxyEnable")
	srv, _, _ := k.GetStringValue("ProxyServer")
	if en != 1 || srv == "" || isOurProxy(srv, ourAddrs...) {
		return ""
	}
	// Extract host:port (supports "127.0.0.1:7890" or "http=127.0.0.1:7890;https=...")
	target := strings.TrimSpace(srv)
	if i := strings.IndexByte(target, ';'); i >= 0 {
		target = target[:i]
	}
	if i := strings.IndexByte(target, '='); i >= 0 {
		target = target[i+1:]
	}
	target = strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
	host, port, err := net.SplitHostPort(target)
	if err != nil || port == "" {
		return ""
	}
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h != "127.0.0.1" && h != "localhost" && h != "::1" {
		return ""
	}
	c, derr := net.DialTimeout("tcp", net.JoinHostPort(host, port), 150*time.Millisecond)
	if derr == nil {
		_ = c.Close()
		return "" // Another local proxy is actively listening; do not touch it.
	}
	_ = k.SetDWordValue("ProxyEnable", 0)
	procInternetSetOption.Call(0, 39, 0, 0)
	procInternetSetOption.Call(0, 37, 0, 0)
	return srv
}
