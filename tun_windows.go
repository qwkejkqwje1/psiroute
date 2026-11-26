//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tunSupported = true

const (
	tunIPUnicastIf   = 31 // IP_UNICAST_IF
	tunIPv6UnicastIf = 31 // IPV6_UNICAST_IF

	wintunURL    = "https://www.wintun.net/builds/wintun-0.14.1.zip"
	wintunSHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
)

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

var (
	tunDnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = tunDnsapi.NewProc("DnsFlushResolverCache")
)

// flushWindowsDNSCache сбрасывает системный DNS-кэш Windows (аналог ipconfig /flushdns без окна консоли),
// чтобы браузеры сразу забывали отравленные провайдером IP-адреса заглушек и получали FakeIP (198.18.x.y).
func flushWindowsDNSCache() {
	if procDnsFlushResolverCache.Find() == nil {
		_, _, _ = procDnsFlushResolverCache.Call()
	}
}

// ---------- adapter ----------

func openTunDevice(a *App, mtu int, v6 bool) (tunDevice, error) {
	if err := ensureWintun(a); err != nil {
		return nil, err
	}
	tun.WintunTunnelType = "Psiroute"
	dev, err := tun.CreateTUN("Psiroute", mtu)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать адаптер Wintun: %w", err)
	}
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		_ = dev.Close()
		return nil, errors.New("wintun: неизвестный тип адаптера")
	}
	if err := setupAdapter(winipcfg.LUID(nt.LUID()), mtu, v6); err != nil {
		_ = dev.Close()
		return nil, err
	}
	safeGo("openTunDevice", func() {
		for range dev.Events() {
		}
	})
	return dev, nil
}

// setTunAdapterMTU dynamically adjusts NLMTU on the active Wintun interface
// when the cascade state (TUN -> WARP -> Psiphon) changes, without tearing
// down routes or active connections.
func setTunAdapterMTU(dev tunDevice, mtu int, v6 bool) error {
	nt, ok := dev.(*tun.NativeTun)
	if !ok || nt == nil {
		return fmt.Errorf("TUN: unsupported adapter type %T", dev)
	}
	luid := winipcfg.LUID(nt.LUID())
	fams := []winipcfg.AddressFamily{windows.AF_INET}
	if v6 {
		fams = append(fams, windows.AF_INET6)
	}
	for _, f := range fams {
		ipi, err := luid.IPInterface(f)
		if err != nil {
			return fmt.Errorf("TUN: read IP interface family %d: %w", f, err)
		}
		if ipi.NLMTU == uint32(mtu) {
			continue
		}
		ipi.NLMTU = uint32(mtu)
		if err := ipi.Set(); err != nil {
			return err
		}
	}
	return nil
}

// setupAdapter: addresses, DNS, and two /1 routes per family - they win over
// the default route without touching it, and vanish with the adapter.
func setupAdapter(luid winipcfg.LUID, mtu int, v6 bool) error {
	// Always assign IPv6 address and capture ::/1 + 8000::/1 on the Wintun adapter:
	// when v6 == false, tun.go drops all IPv6 packets (blackhole), preventing native
	// ISP IPv6 leaks bypassing the IPv4 tunnel.
	addrs := []netip.Prefix{netip.PrefixFrom(tunAddr4, 30), netip.PrefixFrom(tunAddr6, 126)}
	if err := luid.SetIPAddresses(addrs); err != nil {
		if v6 {
			return fmt.Errorf("адрес адаптера TUN: %w", err)
		}
		// Host IPv6 stack may be disabled globally; fall back to IPv4-only address.
		if err4 := luid.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(tunAddr4, 30)}); err4 != nil {
			return fmt.Errorf("адрес адаптера TUN: %w", err4)
		}
	}
	for _, r := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := luid.AddRoute(netip.MustParsePrefix(r), netip.IPv4Unspecified(), 0); err != nil {
			return fmt.Errorf("маршрут %s: %w", r, err)
		}
	}
	for _, r := range []string{"::/1", "8000::/1"} {
		if err := luid.AddRoute(netip.MustParsePrefix(r), netip.IPv6Unspecified(), 0); err != nil {
			if v6 {
				return fmt.Errorf("маршрут %s: %w", r, err)
			}
			logf("debug", "TUN: IPv6 blackhole %s пропущен: %v", r, err)
		}
	}
	flushWindowsDNSCache()
	if err := luid.SetDNS(windows.AF_INET, []netip.Addr{tunDNS4}, nil); err != nil {
		logf("warn", "TUN: DNS адаптера: %v", err)
	}
	fams := []winipcfg.AddressFamily{windows.AF_INET}
	if v6 {
		if err := luid.SetDNS(windows.AF_INET6, []netip.Addr{tunDNS6}, nil); err != nil {
			logf("warn", "TUN: DNS IPv6 адаптера: %v", err)
		}
		fams = append(fams, windows.AF_INET6)
	}
	for _, f := range fams {
		ipi, err := luid.IPInterface(f)
		if err != nil {
			continue
		}
		ipi.UseAutomaticMetric = false
		ipi.Metric = 1
		ipi.NLMTU = uint32(mtu)
		if f == windows.AF_INET {
			ipi.SitePrefixLength = 0
		}
		if err := ipi.Set(); err != nil {
			logf("warn", "TUN: метрика адаптера: %v", err)
		}
	}
	return nil
}

// ensureWintun puts wintun.dll next to psiroute.exe (downloads the signed
// official build from wintun.net once, checking its SHA-256).
func ensureWintun(a *App) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")
	tmpDst := ""
	if a != nil && a.dataDir != "" {
		tmpDir := filepath.Join(a.dataDir, "tmp")
		_ = os.MkdirAll(tmpDir, 0o700)
		tmpDst = filepath.Join(tmpDir, "wintun.dll")
	}
	for _, cand := range []string{dst, tmpDst} {
		if cand == "" {
			continue
		}
		if st, err := os.Stat(cand); err == nil && st.Size() > 32768 {
			if cand != dst {
				if b, rerr := os.ReadFile(cand); rerr == nil {
					_ = os.WriteFile(dst, b, 0o644)
				}
			}
			if abs, aerr := filepath.Abs(cand); aerr == nil {
				_, _ = windows.LoadLibraryEx(abs, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
			}
			return nil
		}
	}
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "x86", "arm": "arm"}[runtime.GOARCH]
	logf("info", "TUN: скачиваю драйвер Wintun с wintun.net…")
	var lastErr error
	type namedDial struct {
		name string
		dial func(ctx context.Context, network, addr string) (net.Conn, error)
	}
	dials := []namedDial{
		{"direct", tunDialBound},
		{"desync", dialDesync},
	}
	if a != nil && a.warp != nil && a.warp.builtin() {
		dials = append(dials, namedDial{"warp", a.warp.Dial})
	}
	if a != nil && a.psi != nil && a.psi.cur.Load() != nil {
		dials = append(dials, namedDial{"psiphon", a.psi.Dial})
	}
	for _, d := range dials {
		data, err := downloadWintun(d.dial, arch)
		if err == nil {
			saved := false
			if tmpDst != "" {
				if werr := writeFileAtomic(tmpDst, data, 0o644); werr == nil {
					saved = true
					if abs, aerr := filepath.Abs(tmpDst); aerr == nil {
						_, _ = windows.LoadLibraryEx(abs, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
					}
				}
			}
			if werr := writeFileAtomic(dst, data, 0o644); werr == nil {
				saved = true
			}
			if saved {
				logf("info", "TUN: wintun.dll сохранён в рабочей папке и рядом с psiroute.exe")
				return nil
			}
		}
		lastErr = err
	}
	return fmt.Errorf("нет wintun.dll (%v). Скачайте архив с https://www.wintun.net и положите wintun\\bin\\%s\\wintun.dll рядом с psiroute.exe", lastErr, arch)
}

func downloadWintun(dial func(ctx context.Context, network, addr string) (net.Conn, error), arch string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cl := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: dial, ForceAttemptHTTP2: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wintunURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	z, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(z); hex.EncodeToString(sum[:]) != wintunSHA256 {
		return nil, errors.New("контрольная сумма архива не совпала")
	}
	zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if strings.EqualFold(f.Name, "wintun/bin/"+arch+"/wintun.dll") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, 8<<20))
		}
	}
	return nil, errors.New("в архиве нет wintun.dll для " + arch)
}

// ---------- the real adapter ----------

// refreshPhys finds the adapter of the system default route (our /1 routes
// are skipped because their prefix is not 0).
func refreshPhys() error {
	i4, n4 := tunBestDefault(windows.AF_INET)
	i6, n6 := tunBestDefault(windows.AF_INET6)
	if i4 == 0 && i6 == 0 {
		return errors.New("не найден сетевой адаптер с выходом в интернет")
	}
	physIdx4.Store(i4)
	physIdx6.Store(i6)
	if n4 == "" {
		n4 = n6
	}
	physAlias.Store(n4)
	return nil
}

func tunBestDefault(family winipcfg.AddressFamily) (uint32, string) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, ""
	}
	// Pass 1: strictly prefer real physical NICs (skip virtual/VPN/TUN/TAP adapters left by other VPNs).
	// Pass 2: fallback to any non-Psiroute default route if no physical adapter matched.
	for pass := 0; pass < 2; pass++ {
		best, bestMetric, name := uint32(0), uint32(math.MaxUint32), ""
		for i := range rows {
			r := &rows[i]
			if r.DestinationPrefix.PrefixLength != 0 {
				continue
			}
			ifr, err := r.InterfaceLUID.Interface()
			if err != nil || ifr.OperStatus != winipcfg.IfOperStatusUp {
				continue
			}
			alias := ifr.Alias()
			desc := ifr.Description()
			if strings.EqualFold(alias, "Psiroute") {
				continue
			}
			if pass == 0 {
				if ifr.Type == winipcfg.IfTypeTunnel || ifr.Type == winipcfg.IfTypeSoftwareLoopback || ifr.Type == winipcfg.IfTypePropVirtual || isVirtualVPNAdapterName(alias, desc) {
					continue
				}
			}
			m := r.Metric
			if ipi, err := r.InterfaceLUID.IPInterface(family); err == nil {
				m += ipi.Metric
			}
			if m < bestMetric {
				best, bestMetric, name = r.InterfaceIndex, m, alias
			}
		}
		if best != 0 {
			return best, name
		}
	}
	return 0, ""
}

func tunHtonl(v uint32) uint32 { return v>>24 | v>>8&0xff00 | v<<8&0xff0000 | v<<24 }

// bindPhys pins a socket to the real adapter (IP_UNICAST_IF), so it never
// goes back into TUN. Errors for the other address family are ignored.
func bindPhys(network, address string, c syscall.RawConn) error {
	i4, i6 := physIdx4.Load(), physIdx6.Load()
	if i4 == 0 && i6 == 0 {
		_ = refreshPhys()
		i4, i6 = physIdx4.Load(), physIdx6.Load()
	}
	return c.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if i4 != 0 && !strings.HasSuffix(network, "6") {
			_ = windows.SetsockoptInt(h, windows.IPPROTO_IP, tunIPUnicastIf, int(tunHtonl(i4)))
		}
		if i6 != 0 && !strings.HasSuffix(network, "4") {
			_ = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, tunIPv6UnicastIf, int(i6))
		}
	})
}

// disableUDPConnResetFD disables ICMP PORT_UNREACHABLE / NET_UNREACHABLE errors
// (WSAECONNRESET / WSAENETRESET) on unconnected Windows UDP sockets.
func disableUDPConnResetFD(fd uintptr) {
	const sioUDPNetReset = 0x9800000F // SIO_UDP_NETRESET
	h := windows.Handle(fd)
	var ret, flag uint32
	sz := uint32(unsafe.Sizeof(flag))
	_ = windows.WSAIoctl(h, windows.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&flag)), sz, nil, 0, &ret, nil, 0)
	ret, flag = 0, 0
	_ = windows.WSAIoctl(h, sioUDPNetReset, (*byte)(unsafe.Pointer(&flag)), sz, nil, 0, &ret, nil, 0)
}

func disableUDPConnResetRaw(c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		disableUDPConnResetFD(fd)
	})
}

// bindPhysSocketFD pins a raw OS socket FD (TCP or UDP) to the active physical
// adapter using IP_UNICAST_IF / IPV6_UNICAST_IF when TUN is active.
func bindPhysSocketFD(fd int) (string, error) {
	i4, i6 := physIdx4.Load(), physIdx6.Load()
	if i4 == 0 && i6 == 0 {
		_ = refreshPhys()
		i4, i6 = physIdx4.Load(), physIdx6.Load()
	}
	if i4 == 0 && i6 == 0 {
		return "", errors.New("физический сетевой адаптер не найден")
	}
	h := windows.Handle(fd)
	var err4, err6 error
	ok := false
	if i4 != 0 {
		err4 = windows.SetsockoptInt(h, windows.IPPROTO_IP, tunIPUnicastIf, int(tunHtonl(i4)))
		if err4 == nil {
			ok = true
		}
	}
	if i6 != 0 {
		err6 = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, tunIPv6UnicastIf, int(i6))
		if err6 == nil {
			ok = true
		}
	}
	if !ok {
		if err4 != nil {
			return "", err4
		}
		return "", err6
	}
	if alias, _ := physAlias.Load().(string); alias != "" {
		return alias, nil
	}
	return fmt.Sprintf("if#%d", i4), nil
}

// physDNSServers returns DNS server IPs configured on the physical adapter
// (excluding loopback and Wintun's own DNS addresses).
func physDNSServers() []string {
	i4, i6 := physIdx4.Load(), physIdx6.Load()
	if i4 == 0 && i6 == 0 {
		_ = refreshPhys()
		i4, i6 = physIdx4.Load(), physIdx6.Load()
	}
	seen := map[string]bool{}
	var out []string
	for _, idx := range []uint32{i4, i6} {
		if idx == 0 {
			continue
		}
		luid, err := winipcfg.LUIDFromIndex(idx)
		if err != nil {
			continue
		}
		ips, err := luid.DNS()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip == tunDNS4 || ip == tunDNS6 {
				continue
			}
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// ---------- which process owns a flow ----------

var (
	tunIphlp        = windows.NewLazySystemDLL("iphlpapi.dll")
	procTunTCPTable = tunIphlp.NewProc("GetExtendedTcpTable")
	procTunUDPTable = tunIphlp.NewProc("GetExtendedUdpTable")
)

func tunOwnerTable(proc *windows.LazyProc, af, class uint32) []byte {
	size := uint32(32 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
		switch r {
		case 0:
			return buf
		case 122: // ERROR_INSUFFICIENT_BUFFER
			size += 8 << 10
		default:
			return nil
		}
	}
	return nil
}

func tunScan(buf []byte, rowSize, portOff, pidOff int, port uint16) uint32 {
	if len(buf) < 4 {
		return 0
	}
	n := int(binary.LittleEndian.Uint32(buf))
	for i := 0; i < n; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		p := uint16(buf[off+portOff])<<8 | uint16(buf[off+portOff+1])
		if p != port {
			continue
		}
		if pid := binary.LittleEndian.Uint32(buf[off+pidOff:]); pid != 0 {
			return pid
		}
	}
	return 0
}

// ownerPID looks up the local port in the TCP/UDP owner tables; dual-stack
// sockets live in the IPv6 table, so both families are checked.
func ownerPID(proto string, v6 bool, port uint16) uint32 {
	for _, six := range []bool{v6, !v6} {
		var pid uint32
		switch {
		case proto == "tcp" && six:
			pid = tunScan(tunOwnerTable(procTunTCPTable, windows.AF_INET6, 5), 56, 20, 52, port)
		case proto == "tcp":
			pid = tunScan(tunOwnerTable(procTunTCPTable, windows.AF_INET, 5), 24, 8, 20, port)
		case six:
			pid = tunScan(tunOwnerTable(procTunUDPTable, windows.AF_INET6, 1), 28, 20, 24, port)
		default:
			pid = tunScan(tunOwnerTable(procTunUDPTable, windows.AF_INET, 1), 12, 4, 8, port)
		}
		if pid != 0 {
			return pid
		}
	}
	return 0
}

func tunProcName(pid uint32) string {
	switch pid {
	case 0:
		return ""
	case 4:
		return "System"
	}
	return procName(pid)
}

// ---------- elevation ----------

func relaunchElevated(waitPID int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	args, _ := windows.UTF16PtrFromString(fmt.Sprintf("--wait-pid=%d", waitPID))
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err := windows.ShellExecute(0, verb, file, args, cwd, windows.SW_SHOWNORMAL); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errors.New("запуск от администратора отменён")
		}
		return err
	}
	return nil
}

// waitForPID: the elevated copy waits until the old one has exited.
func waitForPID(pid int) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err == nil {
		_, _ = windows.WaitForSingleObject(h, 20000)
		_ = windows.CloseHandle(h)
	}
	time.Sleep(500 * time.Millisecond)
}
