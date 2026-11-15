//go:build !windows

package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

var errWindowsOnly = errors.New("доступно только в Windows")

func setSystemProxy(addr string, on bool) error { return errWindowsOnly }
func systemProxyOwnedBy(addrs ...string) bool   { return false }
func autostartEnabled() bool                    { return false }
func setAutostart(on bool) error                { return errWindowsOnly }
func hideConsole(cmd *exec.Cmd)                 {}
func writeClipboardText(val string) bool        { return false }
func readClipboardText() string                 { return "" }

func setPlatformSocketTTL(fd uintptr, ttl int) {
	_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
}

func appForConn(remote net.Addr) string {
	if ta, ok := remote.(*net.TCPAddr); ok && !ta.IP.IsLoopback() {
		return ta.IP.String()
	}
	return ""
}

type runningProc struct {
	Name  string
	Count int
}

// listRunningProcesses scans /proc on Linux (or returns empty on other Unix)
// for user applications.
func listRunningProcesses() []runningProc {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	counts := map[string]int{}
	names := map[string]string{}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		nm := ent.Name()
		if nm[0] < '0' || nm[0] > '9' {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", nm, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(b))
		if comm == "" {
			continue
		}
		key := strings.ToLower(comm)
		counts[key]++
		if _, ok := names[key]; !ok {
			names[key] = comm
		}
	}
	out := make([]runningProc, 0, len(counts))
	for k, c := range counts {
		out = append(out, runningProc{Name: names[k], Count: c})
	}
	return out
}

func installBackgroundService() error   { return errTunUnsupported }
func uninstallBackgroundService() error { return errTunUnsupported }

func isRunningTests() bool {
	if len(os.Args) == 0 {
		return false
	}
	base := strings.ToLower(filepath.Base(os.Args[0]))
	return strings.HasSuffix(base, ".test.exe") || strings.HasSuffix(base, ".test")
}
