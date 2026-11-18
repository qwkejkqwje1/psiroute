package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// One local port speaks both SOCKS5 and HTTP (CONNECT and plain requests).
// The same handler serves the LAN share port, with authentication and
// brute-force rate limiting.

func readFull(c net.Conn, b []byte) (int, error) { return io.ReadFull(c, b) }

// readLine reads one line byte by byte so nothing after it is consumed.
func readLine(c net.Conn) (string, error) {
	var sb []byte
	one := make([]byte, 1)
	for len(sb) < 8192 {
		if _, err := c.Read(one); err != nil {
			return string(sb), err
		}
		sb = append(sb, one[0])
		if one[0] == '\n' {
			return string(sb), nil
		}
	}
	return string(sb), errors.New("слишком длинная строка")
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func basicAuth(u *url.Userinfo) string {
	p, _ := u.Password()
	return base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + p))
}

type proxyAuth struct {
	user, pass string
	lanFree    bool
}

// authFailTracker rate-limits failed password attempts per client IP on the
// LAN share port to prevent brute-force attacks over local networks.
type authFailEntry struct {
	fails int
	until time.Time
	last  time.Time
}

var authLimiter struct {
	mu sync.Mutex
	m  map[string]*authFailEntry
}

const (
	authMaxFails = 5
	authLockout  = time.Minute
)

func remoteIPKey(a net.Addr) string {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP.String()
	}
	h, _, err := net.SplitHostPort(a.String())
	if err == nil {
		return h
	}
	return a.String()
}

func authBlocked(a net.Addr) bool {
	ip := remoteIPKey(a)
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return false
	}
	authLimiter.mu.Lock()
	defer authLimiter.mu.Unlock()
	e := authLimiter.m[ip]
	if e == nil {
		return false
	}
	if !e.until.IsZero() && time.Now().Before(e.until) {
		return true
	}
	if time.Since(e.last) > authLockout {
		delete(authLimiter.m, ip)
	}
	return false
}

func authRecord(a net.Addr, ok bool) {
	ip := remoteIPKey(a)
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return
	}
	authLimiter.mu.Lock()
	defer authLimiter.mu.Unlock()
	if ok {
		delete(authLimiter.m, ip)
		return
	}
	if authLimiter.m == nil {
		authLimiter.m = map[string]*authFailEntry{}
	}
	now := time.Now()
	if len(authLimiter.m) > 1024 {
		for k, v := range authLimiter.m {
			if now.Sub(v.last) > 5*time.Minute {
				delete(authLimiter.m, k)
			}
		}
	}
	e := authLimiter.m[ip]
	if e == nil || now.Sub(e.last) > authLockout {
		e = &authFailEntry{}
		authLimiter.m[ip] = e
	}
	e.fails++
	e.last = now
	if e.fails >= authMaxFails {
		e.until = now.Add(authLockout)
		logf("warn", "Раздача в LAN: IP %s временно заблокирован после %d неверных попыток пароля", ip, e.fails)
	}
}

func isPrivateAddr(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	return ta.IP.IsLoopback() || ta.IP.IsPrivate() || ta.IP.IsLinkLocalUnicast()
}

func isLoopbackAddr(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	return ok && ta.IP.IsLoopback()
}

// isSelfUI blocks proxy connections directed at Psiroute's own Web UI port so
// neither websites nor LAN clients can read the UI page or steal the API token.
func (a *App) isSelfUI(host string, port int) bool {
	a.mu.Lock()
	ui := a.uiActual
	a.mu.Unlock()
	if ui == "" {
		return false
	}
	_, uiPortStr, err := net.SplitHostPort(ui)
	if err != nil || atoiSafe(uiPortStr) != port {
		return false
	}
	h := cleanHostKey(host)
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" || h == "::" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return true
	}
	return false
}

// isForbiddenLANPivot blocks non-loopback LAN share clients from connecting to
// loopback or link-local services on the host computer.
func isForbiddenLANPivot(auth *proxyAuth, remote net.Addr, host string) bool {
	if auth == nil || isLoopbackAddr(remote) {
		return false
	}
	h := cleanHostKey(host)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func (s *Stats) setSNI(t *tracked, sni string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.sni = sni
	newKey := displayHost(t)
	if newKey != "" && newKey != t.key {
		if old := s.byHost[t.key]; old != nil {
			old.conns--
			if old.conns <= 0 && old.up == 0 && old.down == 0 {
				delete(s.byHost, t.key)
			}
		}
		t.key = newKey
		bump(s.byHost, t.key, 1, 0, 0).outbound = t.outbound
	}
}

func (s *Stats) getSNI(t *tracked) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return t.sni
}

func (a *App) serveProxy(ln net.Listener, auth *proxyAuth) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if a.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go a.handleConn(c, auth)
	}
}

func (a *App) handleConn(c net.Conn, auth *proxyAuth) {
	defer c.Close()
	defer recoverLog("соединение прокси")
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if auth != nil && authBlocked(c.RemoteAddr()) {
		return
	}
	br := bufio.NewReaderSize(c, 8<<10)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	needAuth := auth != nil && !(auth.lanFree && isPrivateAddr(c.RemoteAddr()))
	if first[0] == 5 {
		host, port, cmd, err := socksHandshake(c, br, needAuth, auth)
		if err != nil {
			return
		}
		if cmd == 3 {
			a.udpAssociate(c, br)
			return
		}
		if a.isSelfUI(host, port) || isForbiddenLANPivot(auth, c.RemoteAddr(), host) {
			_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		a.tunnel(c, br, host, port, func(up net.Conn, err error) error {
			if err != nil {
				_, _ = c.Write([]byte{5, socksErrCode(err), 0, 1, 0, 0, 0, 0, 0, 0})
				return err
			}
			_, werr := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			return werr
		})
		return
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if needAuth {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth.user+":"+auth.pass))
		if !eqConst(req.Header.Get("Proxy-Authorization"), want) {
			authRecord(c.RemoteAddr(), false)
			_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"psiroute\"\r\nContent-Length: 0\r\n\r\n")
			return
		}
		authRecord(c.RemoteAddr(), true)
	}
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	if req.Method == http.MethodConnect {
		host, portStr, err := net.SplitHostPort(req.Host)
		if err != nil {
			host, portStr = req.Host, "443"
		}
		port := atoiSafe(portStr)
		if a.isSelfUI(host, port) || isForbiddenLANPivot(auth, c.RemoteAddr(), host) {
			_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			return
		}
		a.tunnel(c, br, host, port, func(up net.Conn, err error) error {
			if err != nil {
				if errors.Is(err, errBlocked) {
					_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					return err
				}
				_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
				return err
			}
			_, werr := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
			return werr
		})
		return
	}
	if req.URL.Host == "" {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n")
		return
	}
	host := req.URL.Hostname()
	port := atoiSafe(req.URL.Port())
	if port == 0 {
		port = 80
	}
	if a.isSelfUI(host, port) || isForbiddenLANPivot(auth, c.RemoteAddr(), host) {
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	req.Close = true
	req.Header.Set("Connection", "close")
	a.tunnel(c, br, host, port, func(up net.Conn, err error) error {
		if err != nil {
			if errors.Is(err, errBlocked) {
				_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
				return err
			}
			_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return err
		}
		return req.Write(up)
	})
}

func socksHandshake(c net.Conn, br *bufio.Reader, needAuth bool, auth *proxyAuth) (string, int, byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		return "", 0, 0, err
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return "", 0, 0, err
	}
	want := byte(0)
	if needAuth {
		want = 2
	}
	if !bytes.Contains(methods, []byte{want}) {
		_, _ = c.Write([]byte{5, 0xff})
		return "", 0, 0, errors.New("socks: нет подходящего метода")
	}
	if _, err := c.Write([]byte{5, want}); err != nil {
		return "", 0, 0, err
	}
	if needAuth {
		v := make([]byte, 2)
		if _, err := io.ReadFull(br, v); err != nil {
			return "", 0, 0, err
		}
		u := make([]byte, v[1])
		if _, err := io.ReadFull(br, u); err != nil {
			return "", 0, 0, err
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(br, pl); err != nil {
			return "", 0, 0, err
		}
		p := make([]byte, pl[0])
		if _, err := io.ReadFull(br, p); err != nil {
			return "", 0, 0, err
		}
		if okU, okP := eqConst(string(u), auth.user), eqConst(string(p), auth.pass); !okU || !okP {
			authRecord(c.RemoteAddr(), false)
			_, _ = c.Write([]byte{1, 1})
			return "", 0, 0, errors.New("socks: неверный пароль")
		}
		authRecord(c.RemoteAddr(), true)
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return "", 0, 0, err
		}
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return "", 0, 0, err
	}
	if req[1] != 1 && req[1] != 3 { // CONNECT, UDP ASSOCIATE
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", 0, 0, errors.New("socks: поддерживаются CONNECT и UDP ASSOCIATE")
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", 0, 0, err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return "", 0, 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(br, b); err != nil {
			return "", 0, 0, err
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", 0, 0, err
		}
		host = net.IP(b).String()
	default:
		return "", 0, 0, errors.New("socks: неизвестный тип адреса")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return "", 0, 0, err
	}
	return host, int(pb[0])<<8 | int(pb[1]), req[1], nil
}

// socksErrCode maps a dial error to a SOCKS5 reply code (RFC 1928).
func socksErrCode(err error) byte {
	switch {
	case errors.Is(err, errBlocked):
		return 2 // connection not allowed by ruleset
	case isTimeout(err):
		return 4 // host unreachable
	case errors.Is(err, syscall.ECONNREFUSED):
		return 5
	case strings.Contains(err.Error(), "no such host"), strings.Contains(err.Error(), "DNS"):
		return 4
	}
	return 1 // general failure
}

// directAddrs resolves a host for direct outbounds, through DoH when enabled.
// It returns up to 3 addresses so a dead first IP does not fail the site.
func (a *App) directAddrs(ctx context.Context, host string, port int) ([]string, error) {
	a.cfg.mu.Lock()
	doh := a.cfg.DNS.Enabled
	a.cfg.mu.Unlock()
	ips, err := resolve(ctx, host, doh)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS: нет адресов для %s", host)
	}
	if len(ips) > 3 {
		ips = ips[:3]
	}
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = net.JoinHostPort(ip, strconv.Itoa(port))
	}
	return out, nil
}

func isEarlySNIPort(port int) bool {
	switch port {
	case 80, 443, 8080, 8443, 2053, 2083, 2087, 2096:
		return true
	}
	return false
}

// sniffBufferedConn вычитывает первые байты TLS ClientHello / HTTP Host из буферизованного
// клиентского соединения с коротким дедлайном (до 250 мс) и возвращает новый *bufio.Reader,
// который сначала отдаёт вычитанный буфер, а затем продолжает чтение из исходного потока.
func sniffBufferedConn(c net.Conn, br *bufio.Reader, wait time.Duration) (*bufio.Reader, string) {
	if n := br.Buffered(); n > 0 {
		peek, _ := br.Peek(n)
		return br, sniffHost(peek)
	}
	var buf []byte
	tmpPtr := getSmallBuf()
	tmp := *tmpPtr
	_ = c.SetReadDeadline(time.Now().Add(wait))
	for len(buf) < len(tmp) {
		n, err := br.Read(tmp[:len(tmp)-len(buf)])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil || !sniffWantMore(buf) {
			break
		}
	}
	putSmallBuf(tmpPtr)
	_ = c.SetReadDeadline(time.Time{})
	host := sniffHost(buf)
	if len(buf) > 0 {
		br = bufio.NewReaderSize(io.MultiReader(bytes.NewReader(buf), br), 8<<10)
		_, _ = br.Peek(min(len(buf), 8<<10))
	}
	return br, host
}

// tunnel dials the destination using the router plan and relays data.
func (a *App) tunnel(c net.Conn, br *bufio.Reader, host string, port int, reply func(up net.Conn, err error) error) {
	a.tunnelApp(c, br, host, port, appForConn(c.RemoteAddr()), reply)
}

func (a *App) tunnelApp(c net.Conn, br *bufio.Reader, host string, port int, app string, reply func(up net.Conn, err error) error) {
	a.tunnelAppAddr(c, br, host, "", port, app, reply)
}

func (a *App) tunnelAppAddr(c net.Conn, br *bufio.Reader, host, dstIP string, port int, app string, reply func(up net.Conn, err error) error) {
	fromProxy := dstIP == "" && !isFakeIPStr(host)
	if fdom := theFakeIP.LookupString(host); fdom != "" {
		host = fdom
		if isFakeIPStr(dstIP) {
			dstIP = ""
		}
	} else if addr, err := netip.ParseAddr(cleanHostKey(host)); err == nil {
		if dstIP == "" {
			dstIP = addr.Unmap().String()
		}
		if rev := theRevDNS.get(addr); rev != "" {
			host = rev
		}
	}

	repliedEarly := false
	// Находка 10: Если клиент (например, Discord или браузер с DoH) стучится по сырому публичному IP
	// на TLS/HTTP порт (443, 80, 8443 и т.д.), а домен ещё неизвестен в theFakeIP / theRevDNS,
	// прямое подключение к заблокированной ТСПУ подсети (162.159.x.x и др.) зависнет на TCP SYN blackhole
	// до того, как клиент пришлёт ClientHello.
	// Чтобы исключить двойное ожидание 550 мс между tun.go (300 мс) и proxy.go (250 мс):
	// - если br.Buffered() > 0 (соединение пришло из tun.go после e.sniff), мгновенно без ожидания
	//   читаем уже буферизованные байты через br.Peek(br.Buffered()) и извлекаем sniffHost(peek);
	// - только когда br.Buffered() == 0 и fromProxy == true (соединение пришло напрямую в SOCKS5/HTTP прокси),
	//   подтверждаем рукопожатие и запускаем sniffBufferedConn(c, br, 250*time.Millisecond).
	if addr, err := netip.ParseAddr(cleanHostKey(host)); err == nil && !addr.IsLoopback() && isEarlySNIPort(port) {
		preOrder, _, preStage := a.router.planForProtoWithStage("tcp", host, dstIP, port, app)
		if len(preOrder) == 0 || preOrder[0] != obBlock {
			// Если для этого IP ещё нет точного CIDR/App правила (Stage 7 или Auto), читаем SNI до dial
			if preStage >= 6 || (len(preOrder) > 0 && preOrder[0] == obDirect) {
				var sni string
				if buffered := br.Buffered(); buffered > 0 {
					peek, _ := br.Peek(buffered)
					sni = sniffHost(peek)
				} else if fromProxy {
					if err := reply(nil, nil); err != nil {
						return
					}
					repliedEarly = true
					br, sni = sniffBufferedConn(c, br, 250*time.Millisecond)
				}
				if sni != "" {
					theRevDNS.put(net.IP(addr.AsSlice()), sni, 10*time.Minute)
					host = sni
				}
			}
		}
	}

	order, rule := a.router.planForProto("tcp", host, dstIP, port, app)
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	var up net.Conn
	var ob string
	var lastErr error
	var resolved []string // resolved once, shared by direct and direct-dpi
	var resolveErr error
	for i, o := range order {
		if o == obBlock {
			lastErr = errBlocked
			break
		}
		addrs := []string{net.JoinHostPort(host, strconv.Itoa(port))}
		if o == obDirect || o == obDesync {
			if resolved == nil && resolveErr == nil {
				resolved, resolveErr = a.directAddrs(ctx, host, port)
				if resolveErr != nil && dstIP != "" {
					resolved, resolveErr = []string{net.JoinHostPort(dstIP, strconv.Itoa(port))}, nil
				}
				// Если провайдер заблокировал все прямые DNS-серверы, а соединение пришло по FakeIP (dstIP == ""),
				// пробуем получить реальный IP через активный туннель (Psiphon/WARP) и подключиться к нему напрямую.
				if resolveErr != nil && dstIP == "" && net.ParseIP(host) == nil {
					for _, tunOb := range []string{obWarp, obPsiphon} {
						if tunOb == obWarp && (a.warp == nil || !a.warp.connected()) {
							continue
						}
						if tunOb == obPsiphon && (a.psi == nil || !a.psi.running()) {
							continue
						}
						tctx, tcancel := context.WithTimeout(ctx, 3*time.Second)
						tip, terr := a.tunnelLookup(tctx, tunOb, host)
						tcancel()
						if terr == nil && tip != nil && !isFakeIPStr(tip.String()) {
							theRevDNS.put(tip, cleanHostKey(host), 10*time.Minute)
							resolved = []string{net.JoinHostPort(tip.String(), strconv.Itoa(port))}
							resolveErr = nil
							break
						}
					}
				}
			}
			if resolveErr != nil {
				lastErr = resolveErr
				continue
			}
			addrs = resolved
		}
		dctx := ctx
		var dcancel context.CancelFunc = func() {}
		if i < len(order)-1 && o != obPsiphon {
			dctx, dcancel = context.WithTimeout(ctx, 7*time.Second)
		}
		dial := a.router.dialer(o)
		if o == obDesync {
			origDial := dial
			domainKey := cleanHostKey(host)
			dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := origDial(ctx, network, addr)
				if err == nil && conn != nil {
					if oc, ok := conn.(*obfsConn); ok && domainKey != "" && net.ParseIP(domainKey) == nil {
						oc.host = domainKey
					}
				}
				return conn, err
			}
		}
		up, lastErr = dialHappyEyeballs(dctx, dial, addrs)
		dcancel()
		if lastErr == nil {
			ob = o
			break
		}
	}
	cancel()
	if up == nil {
		last := obDirect
		if len(order) > 0 {
			last = order[len(order)-1]
		}
		t := a.stats.open(app, host, "", port, last, rule)
		if lastErr == nil {
			lastErr = errors.New("нет маршрута")
		}
		a.stats.close(t, lastErr)
		if !repliedEarly {
			_ = reply(nil, lastErr)
		}
		return
	}
	if ob != order[0] {
		rule = "запасной (" + order[0] + " не ответил)"
		a.router.remember(host, ob, order[0]+" не подключился", true)
	}
	t := a.stats.open(app, host, "", port, ob, rule)
	cc := &countConn{Conn: up, s: a.stats, t: t}
	defer func() { _ = cc.Close() }()
	if !repliedEarly {
		if err := reply(cc, nil); err != nil {
			a.stats.close(t, err)
			return
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	started := time.Now()
	err, clientFirst := a.relay(c, br, cc, t)
	a.stats.close(t, err)
	elapsed := time.Since(started)
	downB, upB := t.down.Load(), t.up.Load()
	blocked := isConnReset(err) || (!clientFirst && err == nil)
	blackhole16K := is16KBBlackholeBlock(downB, upB, elapsed, err, clientFirst)
	if (ob == obDirect || ob == obDesync) && (port == 443 || blackhole16K) && upB > 0 && elapsed < 30*time.Second && ((blocked && downB == 0) || blackhole16K) {
		next := obPsiphon
		reason := fmt.Sprintf("%s: соединение прервано до ответа", ob)
		if blackhole16K {
			a.cfg.mu.Lock()
			if a.cfg.Warp.Enabled {
				next = obWarp
			}
			a.cfg.mu.Unlock()
			reason = fmt.Sprintf("прерывание передачи после %d Б", downB)
		} else if ob == obDirect {
			a.cfg.mu.Lock()
			if a.cfg.Desync.Enabled {
				next = obDesync
			}
			a.cfg.mu.Unlock()
		}
		a.router.remember(host, next, reason, true)
		if sni := a.stats.getSNI(t); sni != "" && sni != host {
			a.router.remember(sni, next, reason, true)
		}
		logf("warn", "%s: обнаружена %s через %s → запоминаю маршрут %s", host, reason, ob, next)
	}
}

// relay copies both directions using pooled 32 KB buffers and supports race-free
// dynamic upstream handoff if TLS SNI inspection changes the route on raw-IP connections.
func (a *App) relay(c net.Conn, br *bufio.Reader, up net.Conn, t *tracked) (error, bool) {
	if t != nil {
		t.addCloser(c)
		t.addCloser(up)
	}
	var upMu sync.Mutex
	activeUp := up
	getUp := func() net.Conn {
		upMu.Lock()
		u := activeUp
		upMu.Unlock()
		return u
	}
	defer func() {
		if u := getUp(); u != nil && u != up {
			_ = u.Close()
		}
	}()
	switchedUpCh := make(chan net.Conn, 1)

	type res struct {
		client bool
		err    error
	}
	errc := make(chan res, 2)
	go func() {
		bufPtr := getRelayBuf()
		defer putRelayBuf(bufPtr)
		buf := *bufPtr
		first := true
		curUp := up
		for {
			n, err := br.Read(buf)
			if n > 0 {
				if first {
					first = false
					// P2P must not escape the selected tunnel through an implicit
					// direct connection. Explicit direct routes remain usable.
					if isBitTorrentTCP(buf[:n]) && t != nil {
						_, _, _, _, curOb := a.stats.routeAndHost(t)
						if curOb == obPsiphon || isCountryOb(curOb) {
							errc <- res{false, errBlocked}
							_ = curUp.Close()
							return
						}
					}
					if s := sniffHost(buf[:n]); s != "" {
						a.stats.setSNI(t, s)
						_, host, port, app, curOb := a.stats.routeAndHost(t)
						if ip := net.ParseIP(host); ip != nil {
							theRevDNS.put(ip, s, 10*time.Minute)
							if ord, newRule := a.router.planForProto("tcp", s, host, port, app); len(ord) > 0 {
								if ord[0] == obBlock {
									_ = curUp.Close()
									errc <- res{false, errBlocked}
									return
								}
								// Переподключаем апстрим, если маршрут по домену s отличается от curOb,
								// ЛИБО если соединение изначально было открыто по сырому (возможно отравленному ТСПУ) IP
								// внутрь туннеля (Psiphon/WARP) — чтобы туннель открыл соединение именно по доменному имени s:port!
								needTunnelDomainRebind := host != s && (ord[0] == obPsiphon || isCountryOb(ord[0]) || ord[0] == obWarp)
								if ord[0] != curOb || needTunnelDomainRebind {
									rctx, rcancel := context.WithTimeout(a.ctx, 15*time.Second)
									var newConn net.Conn
									var chosenOb string
									var lastErr error
									var resolved []string
									var resolveErr error
									rawHostAddr := net.JoinHostPort(host, strconv.Itoa(port))
									domainAddr := net.JoinHostPort(s, strconv.Itoa(port))
									for i, o := range ord {
										if o == obBlock {
											lastErr = errBlocked
											break
										}
										dctx := rctx
										var dcancel context.CancelFunc = func() {}
										if i < len(ord)-1 && o != obPsiphon {
											dctx, dcancel = context.WithTimeout(rctx, 7*time.Second)
										}
										dial := a.router.dialer(o)
										switch o {
										case obDirect:
											if resolved == nil && resolveErr == nil {
												resolved, resolveErr = a.directAddrs(dctx, s, port)
												if resolveErr != nil || len(resolved) == 0 {
													resolved, resolveErr = []string{rawHostAddr}, nil
												} else if host != "" && !slices.Contains(resolved, rawHostAddr) {
													resolved = append(resolved, rawHostAddr)
												}
											}
											newConn, lastErr = dialHappyEyeballs(dctx, dial, resolved)
										case obDesync:
											if resolved == nil && resolveErr == nil {
												resolved, resolveErr = a.directAddrs(dctx, s, port)
												if resolveErr != nil || len(resolved) == 0 {
													resolved, resolveErr = []string{rawHostAddr}, nil
												} else if host != "" && !slices.Contains(resolved, rawHostAddr) {
													resolved = append(resolved, rawHostAddr)
												}
											}
											// Сохраняем ключ домена s в obfsConn, чтобы dialObfs кэшировал стратегию
											// обхода DPI по домену s (psiroute-obfs.json), а при ошибке directAddrs
											// откатываемся на s:port и сырой host:port.
											desyncDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
												conn, err := dial(ctx, network, addr)
												if err == nil && conn != nil {
													if oc, ok := conn.(*obfsConn); ok {
														oc.host = cleanHostKey(s)
													}
												}
												return conn, err
											}
											newConn, lastErr = dialHappyEyeballs(dctx, desyncDial, resolved)
											if lastErr != nil {
												newConn, lastErr = desyncDial(dctx, "tcp", domainAddr)
											}
										default:
											newConn, lastErr = dial(dctx, "tcp", domainAddr)
										}
										dcancel()
										if lastErr == nil && newConn != nil {
											chosenOb = o
											break
										}
									}
									rcancel()
									if newConn != nil && lastErr == nil {
										if chosenOb != ord[0] {
											newRule = "запасной (" + ord[0] + " не ответил)"
											a.router.remember(s, chosenOb, ord[0]+" не подключился", true)
										}
										a.stats.setRoute(t, chosenOb, newRule)
										newCounted := &countConn{Conn: newConn, s: a.stats, t: t}
										t.addCloser(newCounted)
										upMu.Lock()
										activeUp = newCounted
										upMu.Unlock()
										select {
										case switchedUpCh <- newCounted:
										default:
										}
										_ = curUp.Close()
										curUp = newCounted
									} else {
										_ = curUp.Close()
										if lastErr == nil {
											lastErr = errors.New("нет маршрута")
										}
										errc <- res{false, lastErr}
										return
									}
								}
							}
						}
					}
				}
				if _, werr := curUp.Write(buf[:n]); werr != nil {
					errc <- res{false, werr}
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				errc <- res{true, err}
				return
			}
		}
	}()
	go func() {
		bufPtr := getRelayBuf()
		defer putRelayBuf(bufPtr)
		_, err := io.CopyBuffer(c, up, *bufPtr)
		select {
		case newUp := <-switchedUpCh:
			_, err = io.CopyBuffer(c, newUp, *bufPtr)
		default:
		}
		errc <- res{false, err}
	}()
	r1 := <-errc
	curUp := getUp()
	if r1.client {
		if cw, ok := curUp.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	} else if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if curUp != nil {
		_ = curUp.SetDeadline(time.Now().Add(5 * time.Second))
	}
	r2 := <-errc
	for _, r := range []res{r1, r2} {
		if r.err != nil && !errors.Is(r.err, net.ErrClosed) && !isTimeout(r.err) {
			return r.err, r1.client
		}
	}
	return nil, r1.client
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isConnReset reports a TCP reset / abort, the typical DPI injection.
func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	var en syscall.Errno
	if errors.As(err, &en) && (en == 10054 || en == 10053) {
		return true
	}
	return false
}

// eqConst compares secrets in constant time.
func eqConst(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// dialHappyEyeballs dials addrs with a 250ms staggered race (RFC 8305 style)
// so a blackholed first CDN IP does not stall connection establishment for 7s.
func dialHappyEyeballs(ctx context.Context, dial dialFunc, addrs []string) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("нет адресов")
	}
	if len(addrs) == 1 {
		return dial(ctx, "tcp", addrs[0])
	}
	type res struct {
		c   net.Conn
		err error
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan res, len(addrs))
	launch := func(addr string) {
		go func() {
			c, err := dial(rctx, "tcp", addr)
			ch <- res{c, err}
		}()
	}
	launch(addrs[0])
	started := 1
	var lastErr error
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	for finished := 0; finished < started; {
		select {
		case r := <-ch:
			finished++
			if r.err == nil && r.c != nil {
				cancel()
				rem := started - finished
				if rem > 0 {
					go func(n int) {
						for range n {
							if x := <-ch; x.c != nil {
								_ = x.c.Close()
							}
						}
					}(rem)
				}
				return r.c, nil
			}
			lastErr = r.err
			if started < len(addrs) && ctx.Err() == nil {
				launch(addrs[started])
				started++
				timer.Reset(250 * time.Millisecond)
			}
		case <-timer.C:
			if started < len(addrs) && ctx.Err() == nil {
				launch(addrs[started])
				started++
				if started < len(addrs) {
					timer.Reset(250 * time.Millisecond)
				}
			}
		}
	}
	return nil, lastErr
}

// is16KBBlackholeBlock identifies an interrupted transfer in a size window.
// This is a recovery hint, not evidence of DPI; normal EOF is not a failure.
func is16KBBlackholeBlock(downBytes, upBytes int64, elapsed time.Duration, err error, clientClosedFirst bool) bool {
	if upBytes <= 0 || downBytes < 14*1024 || downBytes > 36*1024 || elapsed > 30*time.Second {
		return false
	}
	return !clientClosedFirst && (isConnReset(err) || isTimeout(err))
}

// isBitTorrentTCP определяет сигнатуру протокола BitTorrent (\x13BitTorrent protocol)
// и обращения к HTTP-трекерам (/announce?info_hash=, /scrape?info_hash=).
func isBitTorrentTCP(b []byte) bool {
	if len(b) >= 20 && b[0] == 19 && string(b[1:20]) == "BitTorrent protocol" {
		return true
	}
	if len(b) >= 24 && (bytes.HasPrefix(b, []byte("GET /announce?")) || bytes.HasPrefix(b, []byte("GET /scrape?"))) {
		if bytes.Contains(b[:min(len(b), 256)], []byte("info_hash=")) {
			return true
		}
	}
	return false
}

// isBitTorrentUDP определяет UDP-пакеты BitTorrent DHT (bencoded d1:ad2:id20:, d1:rd2:id20:),
// UDP-трекеров (connection_id 0x0000041727101980) и uTP.
func isBitTorrentUDP(b []byte) bool {
	if len(b) < 16 {
		return false
	}
	// BitTorrent DHT (KRPC bencoded)
	if b[0] == 'd' && b[len(b)-1] == 'e' {
		if bytes.Contains(b[:min(len(b), 64)], []byte("2:id20:")) ||
			bytes.Contains(b[:min(len(b), 64)], []byte("1:q9:find_node")) ||
			bytes.Contains(b[:min(len(b), 64)], []byte("1:q9:get_peers")) ||
			bytes.Contains(b[:min(len(b), 64)], []byte("1:q13:announce_peer")) {
			return true
		}
	}
	// BitTorrent UDP Tracker Connect magic constant 0x0000041727101980
	if len(b) >= 16 && b[0] == 0x00 && b[1] == 0x00 && b[2] == 0x04 && b[3] == 0x17 &&
		b[4] == 0x27 && b[5] == 0x10 && b[6] == 0x19 && b[7] == 0x80 {
		return true
	}
	return false
}
