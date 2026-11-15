package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	obPsiphon = "psiphon"
	obDirect  = "direct"
	obDesync  = "direct-dpi"
	obWarp    = "warp"
	obProxy   = "proxy"
	obBlock   = "block"
	obAuto    = "auto"
)

const (
	learnedMax = 2000               // TZ §4.4: cap the learned table
	learnedTTL = 7 * 24 * time.Hour // TZ §4.4: expire entries not used for 7 days
)

var errBlocked = errors.New("соединение заблокировано правилом")

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// learned is a host for which auto-mode found a working outbound.
type learned struct {
	Host     string `json:"host"`
	Outbound string `json:"outbound"`
	Reason   string `json:"reason"`
	Hits     int    `json:"hits"`
	Updated  int64  `json:"updated"`
}

// prefixCache avoids re-parsing CIDR strings on every connection and uses
// value-type netip.Prefix without net.IP heap boxing.
var prefixCache struct {
	mu sync.RWMutex
	m  map[string]netip.Prefix
}

func parsePrefixCached(c string) (netip.Prefix, bool) {
	c = strings.TrimSpace(c)
	c = strings.TrimPrefix(strings.ToLower(c), "cidr:")
	c = strings.TrimPrefix(c, "ip:")
	c = strings.TrimSpace(c)
	if c == "" {
		return netip.Prefix{}, false
	}
	prefixCache.mu.RLock()
	if prefixCache.m != nil {
		if p, ok := prefixCache.m[c]; ok {
			prefixCache.mu.RUnlock()
			return p, p.IsValid()
		}
	}
	prefixCache.mu.RUnlock()

	var pfx netip.Prefix
	if p, err := netip.ParsePrefix(c); err == nil {
		pfx = p.Masked()
	} else if a, err := netip.ParseAddr(c); err == nil {
		a = a.Unmap()
		pfx = netip.PrefixFrom(a, a.BitLen())
	}
	prefixCache.mu.Lock()
	if prefixCache.m == nil || len(prefixCache.m) > 8192 {
		prefixCache.m = map[string]netip.Prefix{}
	}
	prefixCache.m[c] = pfx
	prefixCache.mu.Unlock()
	return pfx, pfx.IsValid()
}

// regexpCache compiles "regexp:..." patterns once and caches them.
var regexpCache struct {
	mu sync.RWMutex
	m  map[string]*regexp.Regexp
}

func compileRuleRegexp(pat string) *regexp.Regexp {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return nil
	}
	regexpCache.mu.RLock()
	if regexpCache.m != nil {
		if re, ok := regexpCache.m[pat]; ok {
			regexpCache.mu.RUnlock()
			return re
		}
	}
	regexpCache.mu.RUnlock()
	re, err := regexp.Compile(pat)
	if err != nil {
		re = nil
	}
	regexpCache.mu.Lock()
	if regexpCache.m == nil || len(regexpCache.m) > 2048 {
		regexpCache.m = map[string]*regexp.Regexp{}
	}
	regexpCache.m[pat] = re
	regexpCache.mu.Unlock()
	return re
}

// cidrCache avoids re-parsing CIDR strings on every connection.
var cidrCache struct {
	mu sync.RWMutex
	m  map[string]*net.IPNet
}

func parseCIDRCached(c string) *net.IPNet {
	c = strings.TrimSpace(c)
	if c == "" {
		return nil
	}
	cidrCache.mu.RLock()
	if cidrCache.m != nil {
		if n, ok := cidrCache.m[c]; ok {
			cidrCache.mu.RUnlock()
			return n
		}
	}
	cidrCache.mu.RUnlock()

	_, ipnet, err := net.ParseCIDR(c)
	if err != nil {
		if ip := net.ParseIP(c); ip != nil {
			bits := 128
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
				bits = 32
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
	}
	cidrCache.mu.Lock()
	if cidrCache.m == nil {
		cidrCache.m = map[string]*net.IPNet{}
	}
	if len(cidrCache.m) > 8192 {
		cidrCache.m = map[string]*net.IPNet{}
	}
	cidrCache.m[c] = ipnet
	cidrCache.mu.Unlock()
	return ipnet
}

type routeCacheEntry struct {
	order []string
	rule  string
	stage int
}

// RouteStageInfo описывает один из 7 неизменных уровней конвейера маршрутизации (Top-to-Bottom Pipeline).
type RouteStageInfo struct {
	Stage   int    `json:"stage"`
	Title   string `json:"title"`
	Example string `json:"example"`
	Summary string `json:"summary"`
}

var routingPipelineStages = []RouteStageInfo{
	{Stage: 1, Title: "Системные и LAN", Example: "127.0.0.0/8, 192.168.0.0/16, psiroute.exe", Summary: "Всегда Direct (защита от петель и потери доступа к роутеру)"},
	{Stage: 2, Title: "Правила для программ", Example: "cs2.exe → Direct, Discord.exe → WARP", Summary: "Явный маршрут процесса перекрывает списки доменов"},
	{Stage: 3, Title: "Личные правила пользователя", Example: "mybank.ru → Direct, work.com → psiphon:DE", Summary: "Точные домены, IP и порты из Быстрого правила и редактора"},
	{Stage: 4, Title: "Белый список РФ / Исключения", Example: "ru-gov-banks (*.ru, *.рф, Госуслуги, банки)", Summary: "Всегда Direct в Умном обходе без капч и лишнего пинга"},
	{Stage: 5, Title: "Подключённые списки (Пресеты)", Example: "youtube → direct-dpi, ai-services → psiphon", Summary: "Массовые списки заблокированных сервисов и подсетей"},
	{Stage: 6, Title: "Выученные маршруты (Auto-learn)", Example: "psiroute-learned.json", Summary: "Автоматически найденные обходы после сброса ТСПУ (только в Умном обходе)"},
	{Stage: 7, Title: "Маршрут по умолчанию", Example: "Direct / По правилам / Psiphon", Summary: "Базовый выход выбранного глобального сценария"},
}

// RouteExplanation возвращает полную диагностику («Почему так пошло?») для любого домена/IP/программы.
type RouteExplanation struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Proto      string   `json:"proto"`
	App        string   `json:"app,omitempty"`
	Outbound   string   `json:"outbound"`
	Chain      []string `json:"chain"`
	Rule       string   `json:"rule"`
	Stage      int      `json:"stage"`
	StageTitle string   `json:"stage_title"`
	Badge      string   `json:"badge"`
	Learned    string   `json:"learned"`
}

func stageTitleFor(stage int) string {
	for _, s := range routingPipelineStages {
		if s.Stage == stage {
			return fmt.Sprintf("%d · %s", s.Stage, s.Title)
		}
	}
	return "7 · Маршрут по умолчанию"
}

func outboundShortTitle(ob string) string {
	switch {
	case ob == obDirect || ob == "tun-exclude":
		return "Direct"
	case ob == obDesync:
		return "DPI"
	case ob == obWarp:
		return "WARP"
	case ob == obBlock:
		return "Block"
	case ob == obPsiphon:
		return "Psiphon"
	case strings.HasPrefix(ob, obPsiphon+":"):
		return "Psiphon:" + strings.ToUpper(strings.TrimPrefix(ob, obPsiphon+":"))
	case ob == obAuto:
		return "Auto"
	}
	return ob
}

func formatRouteBadge(ob string, stage int, ruleName, app string) string {
	obName := outboundShortTitle(ob)
	switch stage {
	case 1:
		return fmt.Sprintf("%s (1 · Локальная сеть)", obName)
	case 2:
		if app != "" {
			return fmt.Sprintf("%s (2 · Программа: %s)", obName, app)
		}
		return fmt.Sprintf("%s (2 · %s)", obName, ruleName)
	case 3:
		return fmt.Sprintf("%s (3 · Личное правило: %s)", obName, ruleName)
	case 4:
		return fmt.Sprintf("%s (4 · Белый список РФ)", obName)
	case 5:
		return fmt.Sprintf("%s (5 · Список: %s)", obName, ruleName)
	case 6:
		return fmt.Sprintf("%s (6 · Выучено после сброса ТСПУ)", obName)
	default:
		return fmt.Sprintf("%s (7 · По умолчанию: %s)", obName, ruleName)
	}
}

// rulePriorityTier относит правило к уровню конвейера (2..5):
//
//	2 — явное правило для программы; proto/ports/domain/list уточняют совпадение
//	3 — личное правило пользователя (точные домены/IP/порты без внешних списков)
//	4 — правило Белого списка РФ / исключений (ru-gov-banks / ru -> direct)
//	5 — правило на основе подключённых списков (Lists)
func rulePriorityTier(ru Rule) int {
	hasPosApp := false
	for _, a := range ru.Apps {
		a = strings.TrimSpace(a)
		if a != "" && !strings.HasPrefix(a, "!") {
			hasPosApp = true
			break
		}
	}
	if hasPosApp {
		return 2
	}
	if len(ru.Lists) == 0 {
		return 3
	}
	if ru.Outbound == obDirect {
		for _, l := range ru.Lists {
			l = strings.ToLower(strings.TrimSpace(l))
			if l == "ru" || l == "ru-gov-banks" {
				return 4
			}
		}
	}
	return 5
}

// serviceCompanionDomains связывает основные домены популярных сервисов с их техническими
// и медиа-доменами (Раздел 2.3 ТЗ), чтобы пользовательское правило для youtube.com, discord.com
// или telegram.org автоматически маршрутизировало видеопотоки, статику и голосовые шлюзы.
var serviceCompanionDomains = map[string][]string{
	"youtube.com":   {"googlevideo.com", "ytimg.com", "ggpht.com", "youtu.be", "youtubei.googleapis.com", "youtube-nocookie.com"},
	"youtu.be":      {"youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "youtubei.googleapis.com"},
	"discord.com":   {"discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"},
	"discord.gg":    {"discord.com", "discordapp.com", "discordapp.net", "discord.media"},
	"telegram.org":  {"t.me", "telegram.me", "tdesktop.com", "telesco.pe", "cdn-telegram.org"},
	"t.me":          {"telegram.org", "telegram.me", "tdesktop.com", "telesco.pe", "cdn-telegram.org"},
	"instagram.com": {"cdninstagram.com", "fbcdn.net"},
	"openai.com":    {"chatgpt.com", "oaistatic.com", "oaiusercontent.com"},
	"chatgpt.com":   {"openai.com", "oaistatic.com", "oaiusercontent.com"},
}

type Router struct {
	a               *App
	file            string
	mu              sync.Mutex
	seen            map[string]*learned
	cacheMu         sync.RWMutex
	routeCache      map[string]routeCacheEntry
	rulesGeneration uint64
	saveT           *time.Timer
	savePen         bool
}

// InvalidateRules сбрасывает кэш маршрутных решений (routeCache) при любом изменении правил или режима.
func (r *Router) InvalidateRules() {
	if r == nil {
		return
	}
	r.cacheMu.Lock()
	r.routeCache = map[string]routeCacheEntry{}
	r.rulesGeneration++
	r.cacheMu.Unlock()
}

func newRouter(a *App, file string) *Router {
	r := &Router{a: a, file: file, seen: map[string]*learned{}}
	if b, err := os.ReadFile(file); err == nil {
		var list []*learned
		if json.Unmarshal(b, &list) == nil {
			cut := time.Now().Add(-learnedTTL).Unix()
			for _, x := range list {
				h := cleanHostKey(x.Host)
				if h != "" && x.Updated >= cut {
					x.Host = h
					r.seen[h] = x
				}
			}
		}
	}
	return r
}

// cleanHostKey normalizes a host for rule and learned-map lookups: lowercase,
// no trailing dot (FQDN form), no IPv6 brackets.
func cleanHostKey(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.Trim(h, "[]")
	return strings.TrimSuffix(h, ".")
}

// hostMatches checks exact match or subdomain ("youtube.com" matches
// "www.youtube.com" and "youtube.com"; "*.googlevideo.com" matches too).
// Prefix "exact:" or "full:" matches only the exact hostname without subdomains.
func hostMatches(host, pattern string) bool {
	host = cleanHostKey(host)
	rawPat := strings.TrimSpace(pattern)
	lowerPat := strings.ToLower(rawPat)
	if rest, ok := strings.CutPrefix(lowerPat, "regexp:"); ok {
		if host == "" {
			return false
		}
		origRest := strings.TrimSpace(rawPat[len("regexp:"):])
		if origRest == "" {
			origRest = rest
		}
		if re := compileRuleRegexp(origRest); re != nil {
			return re.MatchString(host)
		}
		return false
	}
	if rest, ok := strings.CutPrefix(lowerPat, "keyword:"); ok {
		rest = strings.TrimSpace(rest)
		return host != "" && rest != "" && strings.Contains(host, rest)
	}
	if rest, ok := strings.CutPrefix(lowerPat, "exact:"); ok {
		return host != "" && host == cleanHostKey(rest)
	}
	if rest, ok := strings.CutPrefix(lowerPat, "full:"); ok {
		return host != "" && host == cleanHostKey(rest)
	}
	if rest, ok := strings.CutPrefix(lowerPat, "domain:"); ok {
		lowerPat = strings.TrimSpace(rest)
	}
	if rest, ok := strings.CutPrefix(lowerPat, "country:"); ok {
		cc := strings.TrimSpace(rest)
		if cc == "ru" {
			return strings.HasSuffix(host, ".ru") || strings.HasSuffix(host, ".su") || strings.HasSuffix(host, ".рф") || strings.HasSuffix(host, ".xn--p1ai")
		}
		return cc != "" && strings.HasSuffix(host, "."+cc)
	}
	if strings.Contains(lowerPat, "://") || strings.ContainsAny(lowerPat, "/?#") {
		lowerPat = cleanHost(lowerPat)
		if strings.HasPrefix(lowerPat, "www.") && strings.Count(lowerPat, ".") >= 2 {
			lowerPat = strings.TrimPrefix(lowerPat, "www.")
		}
	}
	pattern = cleanHostKey(strings.TrimPrefix(lowerPat, "*."))
	pattern = strings.TrimPrefix(pattern, ".")
	if host == "" || pattern == "" {
		return false
	}
	if _, err1 := netip.ParseAddr(host); err1 == nil {
		return host == pattern
	}
	if _, err2 := netip.ParseAddr(pattern); err2 == nil {
		return host == pattern
	}
	if host == pattern || strings.HasSuffix(host, "."+pattern) {
		return true
	}
	if extras, ok := serviceCompanionDomains[pattern]; ok {
		for _, ex := range extras {
			if host == ex || strings.HasSuffix(host, "."+ex) {
				return true
			}
		}
	}
	return false
}

func normAppName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSuffix(s, ".exe")
}

func normAppFullPath(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, "/", `\`)
	return s
}

func singleAppMatch(pat, app string) bool {
	if pat == "" || app == "" {
		return false
	}
	if strings.ContainsAny(pat, `\/`) && strings.ContainsAny(app, `\/`) {
		if normAppFullPath(pat) == normAppFullPath(app) {
			return true
		}
	}
	w := normAppName(pat)
	a := normAppName(app)
	return w != "" && a != "" && a == w
}

// appMatches: the connection's program matches one of the rule's names
// ("telegram.exe", "Telegram", and full path "C:\...\Telegram.exe" all match case-insensitively).
// Supports negation with "!" prefix (e.g. "!steam.exe" matches everything except steam.exe).
func appMatches(list []string, app string) bool {
	hasPos := false
	posMatch := false
	for _, x := range list {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if strings.HasPrefix(x, "!") {
			if singleAppMatch(x[1:], app) {
				return false
			}
			continue
		}
		hasPos = true
		if singleAppMatch(x, app) {
			posMatch = true
		}
	}
	if hasPos {
		return posMatch
	}
	return true
}

// parsePortRange parses "80", "50000-65535", or "3478:3480".
func parsePortRange(s string) (lo, hi int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	sep := strings.IndexAny(s, "-:")
	if sep < 0 {
		p, err := strconv.Atoi(s)
		if err != nil || p < 1 || p > 65535 {
			return 0, 0, false
		}
		return p, p, true
	}
	p1, err1 := strconv.Atoi(strings.TrimSpace(s[:sep]))
	p2, err2 := strconv.Atoi(strings.TrimSpace(s[sep+1:]))
	if err1 != nil || err2 != nil || p1 < 1 || p2 < 1 || p1 > 65535 || p2 > 65535 || p1 > p2 {
		return 0, 0, false
	}
	return p1, p2, true
}

func portMatchesRule(ru Rule, port int) bool {
	if len(ru.Ports) == 0 && len(ru.PortRanges) == 0 {
		return true
	}
	if slices.Contains(ru.Ports, port) {
		return true
	}
	for _, pr := range ru.PortRanges {
		if lo, hi, ok := parsePortRange(pr); ok && port >= lo && port <= hi {
			return true
		}
	}
	return false
}

func protoMatchesRule(ruProto, proto string) bool {
	rp := strings.ToLower(strings.TrimSpace(ruProto))
	if rp == "" || rp == "any" || rp == "all" || rp == "tcp+udp" {
		return true
	}
	if proto == "" {
		return true
	}
	return rp == strings.ToLower(proto)
}

func isPrivateOrLANHost(host string, ips []net.IP) bool {
	h := cleanHostKey(host)
	if h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".lan") || strings.HasSuffix(h, ".home") || strings.HasSuffix(h, ".internal") {
		return true
	}
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			a = a.Unmap()
			if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || tunInternal(a) {
				return true
			}
		}
	}
	return false
}

func (r *Router) matchRule(host string, port int) (outbound, ruleName string) {
	ob, name, _ := r.matchRuleFullWithStage("", host, "", port, "", false)
	return ob, name
}

func (r *Router) matchRuleFor(host string, port int, app string, onlyAlways bool) (outbound, ruleName string) {
	ob, name, _ := r.matchRuleFullWithStage("", host, "", port, app, onlyAlways)
	return ob, name
}

func (r *Router) matchRuleFull(proto, host, dstIP string, port int, app string, onlyAlways bool) (outbound, ruleName string) {
	ob, name, _ := r.matchRuleFullWithStage(proto, host, dstIP, port, app, onlyAlways)
	return ob, name
}

// matchRuleFullWithStage evaluates rules strictly along the Top-to-Bottom Priority Pipeline:
// Tier 2 (Per-App Rules) -> Tier 3 (Personal Rules) -> Tier 4 (RU Whitelist) -> Tier 5 (Preset Lists).
func (r *Router) matchRuleFullWithStage(proto, host, dstIP string, port int, app string, onlyAlways bool) (outbound, ruleName string, stage int) {
	host = cleanHostKey(host)
	r.a.cfg.mu.Lock()
	rules := append([]Rule(nil), r.a.cfg.Routing.Rules...)
	r.a.cfg.mu.Unlock()

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
		if a, ok := netip.AddrFromSlice(ip); ok {
			if fdom := theFakeIP.Lookup(a); fdom != "" {
				host = cleanHostKey(fdom)
			} else if rev := theRevDNS.get(a); rev != "" {
				host = cleanHostKey(rev)
			}
		}
	} else if host != "" {
		ips = theDNS.cachedIPs(host)
	}
	if dstIP != "" {
		if dip := net.ParseIP(cleanHostKey(dstIP)); dip != nil {
			found := false
			for _, existing := range ips {
				if existing.Equal(dip) {
					found = true
					break
				}
			}
			if !found {
				ips = append(ips, dip)
			}
		}
	}
	var netipAddrs []netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			netipAddrs = append(netipAddrs, a.Unmap())
		}
	}

	evalOneRule := func(ru Rule) (string, string, bool) {
		if ru.Disabled {
			return "", "", false
		}
		if onlyAlways && !ru.Always {
			return "", "", false
		}
		if !protoMatchesRule(ru.Proto, proto) {
			return "", "", false
		}
		if len(ru.Apps) > 0 && !appMatches(ru.Apps, app) {
			return "", "", false
		}
		if !portMatchesRule(ru, port) {
			return "", "", false
		}

		excluded := false
		hasPosCond := false
		posMatched := false

		for _, d := range ru.Domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if strings.HasPrefix(d, "!") {
				if hostMatches(host, d[1:]) {
					excluded = true
					break
				}
				continue
			}
			hasPosCond = true
			if hostMatches(host, d) {
				posMatched = true
			}
		}
		if excluded {
			return "", "", false
		}

		for _, kw := range ru.Keywords {
			kw = strings.ToLower(strings.TrimSpace(kw))
			if kw == "" {
				continue
			}
			if strings.HasPrefix(kw, "!") {
				neg := strings.TrimSpace(kw[1:])
				if neg != "" && host != "" && strings.Contains(host, neg) {
					excluded = true
					break
				}
				continue
			}
			hasPosCond = true
			if host != "" && strings.Contains(host, kw) {
				posMatched = true
			}
		}
		if excluded {
			return "", "", false
		}

		for _, c := range ru.CIDR {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if strings.HasPrefix(c, "!") {
				if pfx, ok := parsePrefixCached(c[1:]); ok {
					for _, a := range netipAddrs {
						if pfx.Contains(a) {
							excluded = true
							break
						}
					}
				}
				if excluded {
					break
				}
				continue
			}
			hasPosCond = true
			if !posMatched && len(netipAddrs) > 0 {
				if pfx, ok := parsePrefixCached(c); ok {
					for _, a := range netipAddrs {
						if pfx.Contains(a) {
							posMatched = true
							break
						}
					}
				}
			}
		}
		if excluded {
			return "", "", false
		}

		if len(ru.Lists) > 0 && r.a.lists != nil {
			listPos, listHasPos, listNeg := r.a.lists.EvalLists(ru.Lists, host, netipAddrs)
			if listNeg {
				return "", "", false
			}
			if listHasPos {
				hasPosCond = true
				if listPos {
					posMatched = true
				}
			}
		}

		ob := ru.Outbound
		if strings.EqualFold(ob, "tunnel") {
			ob = obPsiphon
		}
		if hasPosCond {
			if posMatched {
				return ob, ru.Name, true
			}
			return "", "", false
		}
		if len(ru.Ports) > 0 || len(ru.PortRanges) > 0 || len(ru.Apps) > 0 || ru.Proto != "" {
			return ob, ru.Name, true
		}
		return "", "", false
	}

	for tier := 2; tier <= 5; tier++ {
		for _, ru := range rules {
			if rulePriorityTier(ru) != tier {
				continue
			}
			if ob, name, ok := evalOneRule(ru); ok {
				return ob, name, tier
			}
		}
	}
	return "", "", 0
}

// isVPNUp reports whether the given VPN outbound is currently connected or
// configured with an active upstream, used when KillSwitch is enabled.
func (r *Router) isVPNUp(ob string) bool {
	switch {
	case ob == obPsiphon || isCountryOb(ob):
		return r.a.psi != nil && (r.a.psi.running() || r.a.psi.cur.Load() != nil)
	case ob == obWarp:
		return r.a.warp != nil && (r.a.warp.connected() || !r.a.warp.builtin())
	case ob == obProxy:
		r.a.cfg.mu.Lock()
		ok := r.a.cfg.Proxy.Enabled && r.a.cfg.Proxy.Upstream != ""
		r.a.cfg.mu.Unlock()
		return ok
	}
	return false
}

// plan returns the ordered list of outbounds to try for host:port and a human
// description of why. The first working one wins.
func (r *Router) plan(host string, port int) (order []string, rule string) {
	return r.planForProto("", host, "", port, "")
}

func (r *Router) planFor(host string, port int, app string) (order []string, rule string) {
	return r.planForProto("", host, "", port, app)
}

func (r *Router) planForIP(host, dstIP string, port int, app string) (order []string, rule string) {
	return r.planForProto("", host, dstIP, port, app)
}

func (r *Router) planForProto(proto, host, dstIP string, port int, app string) (order []string, rule string) {
	order, rule, _ = r.planForProtoWithStage(proto, host, dstIP, port, app)
	return order, rule
}

// ExplainRoute возвращает детальную расшифровку решения маршрутизатора по 7-уровневому конвейеру.
func (r *Router) ExplainRoute(proto, host, dstIP string, port int, app string) RouteExplanation {
	cleanH := cleanHostKey(host)
	if port == 0 {
		port = 443
	}
	order, rule, stage := r.planForProtoWithStage(proto, host, dstIP, port, app)
	first := obDirect
	if len(order) > 0 {
		first = order[0]
	}
	return RouteExplanation{
		Host:       cleanH,
		Port:       port,
		Proto:      proto,
		App:        app,
		Outbound:   first,
		Chain:      order,
		Rule:       rule,
		Stage:      stage,
		StageTitle: stageTitleFor(stage),
		Badge:      formatRouteBadge(first, stage, rule, app),
		Learned:    r.learnedFor(cleanH),
	}
}

func (r *Router) planForProtoWithStage(proto, host, dstIP string, port int, app string) (order []string, rule string, stage int) {
	r.cacheMu.RLock()
	generation := r.rulesGeneration
	r.cacheMu.RUnlock()
	cleanH := cleanHostKey(host)
	if a, err := netip.ParseAddr(cleanH); err == nil && isFakeIP(a) {
		if fdom := theFakeIP.Lookup(a); fdom != "" {
			cleanH = fdom
			host = fdom
		}
	}
	var checkIPs []net.IP
	if ip := net.ParseIP(cleanH); ip != nil {
		checkIPs = append(checkIPs, ip)
	}
	if dstIP != "" {
		if dip := net.ParseIP(cleanHostKey(dstIP)); dip != nil {
			checkIPs = append(checkIPs, dip)
		}
	}

	r.a.cfg.mu.Lock()
	mode := r.a.cfg.Routing.Mode
	def := r.a.cfg.Routing.Default
	failover := r.a.cfg.Routing.Failover
	learn := r.a.cfg.Routing.Learn
	bypassLAN := r.a.cfg.Routing.BypassLAN
	killSwitch := r.a.cfg.Routing.KillSwitch
	blockSTUN := r.a.cfg.Routing.BlockSTUN
	chain := append([]string(nil), r.a.cfg.Routing.Chain...)
	desyncOn := r.a.cfg.Desync.Enabled
	rulesLen := len(r.a.cfg.Routing.Rules)
	r.a.cfg.mu.Unlock()

	cacheKey := fmt.Sprintf("%d|%s|%s|%s|%d|%s|%s|%s|%t|%t|%t|%d",
		generation, proto, cleanH, dstIP, port, normAppFullPath(app), mode, def, failover, bypassLAN, blockSTUN, rulesLen)
	if !killSwitch && mode != "auto" && len(theDNS.cachedIPs(cleanH)) == 0 {
		if addr, err := netip.ParseAddr(cleanH); err != nil || theRevDNS.get(addr) == "" {
			r.cacheMu.RLock()
			if ent, ok := r.routeCache[cacheKey]; ok && len(ent.order) > 0 {
				r.cacheMu.RUnlock()
				st := ent.stage
				if st == 0 {
					st = 7
				}
				return slices.Clone(ent.order), ent.rule, st
			}
			r.cacheMu.RUnlock()
		}
	}

	// Если включён «Таймер паузы» (на 5 / 15 минут), временно пускаем весь трафик напрямую
	if r.a != nil && r.a.IsPaused() {
		return []string{obDirect}, "пауза защиты", 1
	}

	// Приоритет 1 (Высший): Системные, LAN (127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8, psiroute.exe) и Captive Portal Wi-Fi
	if app != "" && normAppName(app) == "psiroute" {
		return []string{obDirect}, "локальная сеть", 1
	}
	if bypassLAN && isPrivateOrLANHost(cleanH, checkIPs) {
		return []string{obDirect}, "локальная сеть", 1
	}
	if r.a.net != nil && r.a.net.isCaptiveHost(cleanH) {
		return []string{obDirect}, "авторизация Wi-Fi (Captive Portal)", 1
	}

	// Защита от утечки WebRTC / STUN на UDP портах 3478, 5349, 19302 и доменах stun.*
	if blockSTUN && (proto == "udp" || proto == "") {
		if port == 3478 || port == 5349 || port == 19302 || strings.HasPrefix(cleanH, "stun.") || strings.Contains(cleanH, ".stun.") {
			return []string{obBlock}, "защита от утечки WebRTC/STUN", 1
		}
	}

	buildAutoChain := func() ([]string, int) {
		if learn && mode == "auto" {
			if l := r.learnedFor(cleanH); l != "" {
				return []string{l}, 6
			}
		}
		out := []string{}
		for _, c := range chain {
			if c == obDesync && !desyncOn {
				continue
			}
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
		if len(out) == 0 {
			out = []string{obPsiphon}
		}
		return out, 7
	}

	// Приоритеты 2..5: Правила программ (2) -> Личные правила (3) -> Белый список РФ (4) -> Пресеты списков (5)
	matchedOb, matchedName, matchedStage := r.matchRuleFullWithStage(proto, host, dstIP, port, app, false)

	// Приоритет 4 (в режиме «Умный обход»): автоматический Белый список РФ (.ru, .рф, Госуслуги, банки)
	if (matchedOb == "" || matchedStage == 5) && mode == "auto" && r.a.lists != nil && r.a.lists.MatchRUWhitelist(cleanH) {
		return []string{obDirect}, "Белый список РФ", 4
	}

	if matchedOb == "" {
		matchedStage = 7
		switch mode {
		case "psiphon":
			if killSwitch && !r.isVPNUp(obPsiphon) {
				return []string{obBlock}, "Kill Switch: Psiphon отключён", 7
			}
			return []string{obPsiphon}, "всё через Psiphon", 7
		case "rules":
			if def == "" {
				def = obPsiphon
			}
			matchedOb, matchedName = def, "по умолчанию"
		case "auto":
			matchedOb, matchedName = obAuto, "автоподбор"
		default:
			if killSwitch && !r.isVPNUp(obPsiphon) {
				return []string{obBlock}, "Kill Switch: Psiphon отключён", 7
			}
			return []string{obPsiphon}, "всё через Psiphon", 7
		}
	}

	if matchedOb == obBlock {
		return []string{obBlock}, matchedName, matchedStage
	}

	applyFailover := func(out []string) ([]string, string) {
		if killSwitch {
			var vpnOut []string
			for _, o := range out {
				if o == obBlock {
					return []string{obBlock}, matchedName
				}
				if (o == obPsiphon || isCountryOb(o) || o == obWarp || o == obProxy) && r.isVPNUp(o) {
					vpnOut = append(vpnOut, o)
				}
			}
			if len(vpnOut) == 0 {
				return []string{obBlock}, "Kill Switch: VPN отключён (" + matchedName + ")"
			}
			return vpnOut, matchedName
		}
		if failover && !slices.Contains(out, obPsiphon) && !slices.ContainsFunc(out, isCountryOb) {
			out = append(out, obPsiphon)
		}
		return out, matchedName
	}

	var finalOrder []string
	var finalRule string
	if matchedOb == obAuto {
		autoChain, autoStage := buildAutoChain()
		if matchedStage == 7 {
			matchedStage = autoStage
		}
		finalOrder, finalRule = applyFailover(autoChain)
	} else {
		finalOrder, finalRule = applyFailover([]string{matchedOb})
	}
	if matchedOb != obAuto && !killSwitch && len(theDNS.cachedIPs(cleanH)) == 0 {
		r.cacheMu.Lock()
		if r.routeCache == nil || len(r.routeCache) >= 4096 {
			r.routeCache = map[string]routeCacheEntry{}
		}
		r.routeCache[cacheKey] = routeCacheEntry{order: slices.Clone(finalOrder), rule: finalRule, stage: matchedStage}
		r.cacheMu.Unlock()
	}
	return finalOrder, finalRule, matchedStage
}

func (r *Router) learnedFor(host string) string {
	host = cleanHostKey(host)
	if host == "" {
		return ""
	}
	now := time.Now().Unix()
	cut := now - int64(learnedTTL/time.Second)
	r.mu.Lock()
	defer r.mu.Unlock()
	for h := host; ; {
		if x, ok := r.seen[h]; ok {
			if x.Updated < cut {
				delete(r.seen, h)
				r.scheduleSaveLocked()
			} else {
				x.Hits++
				x.Updated = now
				return x.Outbound
			}
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return ""
		}
		h = h[i+1:]
	}
}

// remember records that outbound worked (or failed) for host.
func (r *Router) remember(host, outbound, reason string, ok bool) {
	host = cleanHostKey(host)
	if host == "" {
		return
	}
	r.a.cfg.mu.Lock()
	learn := r.a.cfg.Routing.Learn
	r.a.cfg.mu.Unlock()
	if !learn {
		return
	}
	r.mu.Lock()
	if !ok {
		delete(r.seen, host)
		r.scheduleSaveLocked()
		r.mu.Unlock()
		r.InvalidateRules()
		return
	}
	if _, exists := r.seen[host]; !exists && len(r.seen) >= learnedMax {
		r.evictLocked()
	}
	x := r.seen[host]
	if x == nil {
		x = &learned{Host: strings.Clone(host)}
		r.seen[x.Host] = x
	}
	changed := x.Outbound != outbound
	x.Outbound = outbound
	x.Reason = reason
	x.Updated = time.Now().Unix()
	r.scheduleSaveLocked()
	r.mu.Unlock()
	r.InvalidateRules()
	if changed {
		logf("info", "Запомнен маршрут: %s → %s (%s)", host, outbound, reason)
	}
}

func (r *Router) evictLocked() {
	cut := time.Now().Add(-learnedTTL).Unix()
	for k, x := range r.seen {
		if x.Updated < cut {
			delete(r.seen, k)
		}
	}
	for len(r.seen) >= learnedMax {
		var oldestKey string
		var oldestAt int64 = 1<<62 - 1
		for k, x := range r.seen {
			if x.Updated < oldestAt {
				oldestAt = x.Updated
				oldestKey = k
			}
		}
		if oldestKey == "" {
			break
		}
		delete(r.seen, oldestKey)
	}
}

func (r *Router) forget(host string) {
	host = cleanHostKey(host)
	r.mu.Lock()
	for k := range r.seen {
		if k == host || (host != "" && strings.HasSuffix(k, "."+host)) {
			delete(r.seen, k)
		}
	}
	r.scheduleSaveLocked()
	r.mu.Unlock()
	r.InvalidateRules()
}

func (r *Router) clearLearned() {
	r.mu.Lock()
	r.seen = map[string]*learned{}
	r.scheduleSaveLocked()
	r.mu.Unlock()
	r.InvalidateRules()
	logf("info", "Выученные маршруты сброшены")
}

func (r *Router) learnedList() []map[string]any {
	cut := time.Now().Add(-learnedTTL).Unix()
	r.mu.Lock()
	list := make([]*learned, 0, len(r.seen))
	for k, x := range r.seen {
		if x.Updated < cut {
			delete(r.seen, k)
			continue
		}
		cp := *x
		list = append(list, &cp)
	}
	r.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Updated > list[j].Updated })
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		out = append(out, map[string]any{
			"host": x.Host, "outbound": x.Outbound, "reason": x.Reason,
			"hits": x.Hits, "updated": x.Updated,
		})
	}
	return out
}

func (r *Router) scheduleSaveLocked() {
	if r.file == "" {
		return
	}
	r.savePen = true
	if r.saveT != nil {
		return
	}
	r.saveT = time.AfterFunc(2*time.Second, func() {
		r.mu.Lock()
		r.saveT = nil
		if !r.savePen {
			r.mu.Unlock()
			return
		}
		b := r.marshalLocked()
		r.savePen = false
		r.mu.Unlock()
		r.writeFile(b)
	})
}

func (r *Router) flush() {
	r.mu.Lock()
	if r.saveT != nil {
		r.saveT.Stop()
		r.saveT = nil
	}
	if !r.savePen {
		r.mu.Unlock()
		return
	}
	b := r.marshalLocked()
	r.savePen = false
	r.mu.Unlock()
	r.writeFile(b)
}

func (r *Router) marshalLocked() []byte {
	list := make([]*learned, 0, len(r.seen))
	for _, x := range r.seen {
		list = append(list, x)
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	return b
}

func (r *Router) writeFile(b []byte) {
	if r.file == "" || b == nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(r.file), 0o700)
	tmp := r.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, r.file)
	}
}

// ---- outbound dialers ----

func (r *Router) dialer(outbound string) dialFunc {
	if cc, ok := countryOf(outbound); ok {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return r.a.countries.Dial(ctx, cc, addr)
		}
	}
	switch outbound {
	case obBlock:
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errBlocked
		}
	case obDirect:
		return dialDirect
	case obDesync:
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			r.a.cfg.mu.Lock()
			on, method := r.a.cfg.Desync.Enabled, r.a.cfg.Desync.Method
			r.a.cfg.mu.Unlock()
			if !on {
				return dialDirect(ctx, network, addr)
			}
			return dialObfs(ctx, network, addr, method)
		}
	case obWarp:
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			r.a.cfg.mu.Lock()
			on, engine, socks := r.a.cfg.Warp.Enabled, r.a.cfg.Warp.Engine, r.a.cfg.Warp.Socks
			r.a.cfg.mu.Unlock()
			if !on {
				return nil, errors.New("WARP выключен в настройках")
			}
			if engine != "socks" {
				return r.a.warp.Dial(ctx, network, addr)
			}
			return dialSocks5(ctx, strings.TrimPrefix(socks, "socks5://"), addr, "", "")
		}
	case obProxy:
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			r.a.cfg.mu.Lock()
			on, up := r.a.cfg.Proxy.Enabled, r.a.cfg.Proxy.Upstream
			r.a.cfg.mu.Unlock()
			if !on || up == "" {
				return nil, errors.New("внешний прокси не настроен")
			}
			return dialUpstream(ctx, up, addr)
		}
	default:
		// Priority 6: Use DialBalanced so when Psiphon.Parallel >= 2 and a 2nd
		// tunnel slot is active, downloads balance across both tunnels.
		return r.a.psi.DialBalanced
	}
}

func dialUpstream(ctx context.Context, upstream, addr string) (net.Conn, error) {
	if !strings.Contains(upstream, "://") {
		upstream = "socks5://" + upstream
	}
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("неверный адрес прокси: %s", upstream)
	}
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	switch u.Scheme {
	case "socks5", "socks5h", "socks":
		return dialSocks5(ctx, u.Host, addr, user, pass)
	case "http":
		return dialHTTPConnect(ctx, u.Host, addr, u.User)
	default:
		return nil, fmt.Errorf("протокол %s не поддерживается (нужен socks5:// или http://)", u.Scheme)
	}
}

func dialSocks5(ctx context.Context, proxyAddr, targetAddr, user, pass string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("неверный порт: %s", portStr)
	}
	c, err := dialDirect(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if user != "" {
		_, _ = c.Write([]byte{5, 2, 0, 2})
	} else {
		_, _ = c.Write([]byte{5, 1, 0})
	}
	rep := make([]byte, 2)
	if _, err := readFull(c, rep); err != nil || rep[0] != 5 {
		return nil, fmt.Errorf("SOCKS5 %s: нет ответа", proxyAddr)
	}
	if rep[1] == 2 {
		if len(user) > 255 || len(pass) > 255 {
			return nil, errors.New("SOCKS5: слишком длинный логин или пароль")
		}
		b := append([]byte{1, byte(len(user))}, user...)
		b = append(b, byte(len(pass)))
		b = append(b, pass...)
		_, _ = c.Write(b)
		if _, err := readFull(c, rep); err != nil || rep[1] != 0 {
			return nil, errors.New("SOCKS5: неверный логин или пароль")
		}
	} else if rep[1] != 0 {
		return nil, errors.New("SOCKS5: сервер отклонил подключение")
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 1)
			req = append(req, ip4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("слишком длинное имя хоста")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := readFull(c, hdr); err != nil {
		return nil, err
	}
	if hdr[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 %s → %s: код ошибки %d", proxyAddr, targetAddr, hdr[1])
	}
	skip := 0
	switch hdr[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		l := make([]byte, 1)
		if _, err := readFull(c, l); err != nil {
			return nil, err
		}
		skip = int(l[0]) + 2
	default:
		return nil, fmt.Errorf("SOCKS5: неизвестный тип адреса %d в ответе", hdr[3])
	}
	if _, err := readFull(c, make([]byte, skip)); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}

type bufConn struct {
	net.Conn
	r io.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func dialHTTPConnect(ctx context.Context, proxyAddr, targetAddr string, user *url.Userinfo) (net.Conn, error) {
	c, err := dialDirect(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	req := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n"
	if user != nil {
		req += "Proxy-Authorization: Basic " + basicAuth(user) + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(status, " 200 ") {
		return nil, fmt.Errorf("HTTP-прокси: %s", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}
