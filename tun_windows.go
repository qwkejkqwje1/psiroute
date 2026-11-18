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
	go func() {
		for range dev.Events() {
		}
	}()
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
	addrs := []netip.Prefix{netip.PrefixFrom(tunAddr4, 30)}
	if v6 {
		addrs = append(addrs, netip.PrefixFrom(tunAddr6, 126))
	}
	if err := luid.SetIPAddresses(addrs); err != nil {
		return fmt.Errorf("адрес адаптера TUN: %w", err)
	}
	routes := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if v6 {
		routes = append(routes, "::/1", "8000::/1")
	}
	for _, r := range routes {
		p := netip.MustParsePrefix(r)
		hop := netip.IPv4Unspecified()
		if p.Addr().Is6() {
			hop = netip.IPv6Unspecified()
		}
		if err := luid.AddRoute(p, hop, 0); err != nil {
			return fmt.Errorf("маршрут %s: %w", r, err)
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
	dials := []func(ctx context.Context, network, addr string) (net.Conn, error){tunDialBound}
	if a.psi.running() {
		dials = append(dials, a.psi.Dial)
	}
	for _, d := range dials {
		data, err := downloadWintun(d, arch)
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
	cl := &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{DialContext: dial, ForceAttemptHTTP2: true}}
	resp, err := cl.Get(wintunURL)
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
		if strings.EqualFold(alias, "Psiroute") {
			continue
		}
		m := r.Metric
		if ipi, err := r.InterfaceLUID.IPInterface(family); err == nil {
			m += ipi.Metric
		}
		if m < bestMetric {
			best, bestMetric, name = r.InterfaceIndex, m, alias
		}
	}
	return best, name
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
