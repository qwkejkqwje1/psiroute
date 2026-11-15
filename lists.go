package main

// Modernized Subscriptions & Domain/IP Lists Engine (2.0).
//
// Key features:
//  1. Zero-Copy Streaming Parser: reads lines via bufio.Scanner / json.Decoder
//     directly from io.Reader without allocating 32 MB rawBytes in heap.
//  2. O(log N) Binary-Search IPv4 & IPv6 Interval Trees: CIDR subnets are
//     converted into sorted, merged [start, end] ranges.
//  3. User Custom Lists Registry (lists.custom), Hidden Built-ins (lists.hidden),
//     and User-Approved HTTPS Hosts (lists.trusted_hosts) with SSRF protection.
//  4. Full CRUD REST API: GET/POST /api/lists, PUT/DELETE /api/lists/{id},
//     POST /api/lists/{id}/refresh, GET /api/lists/{id}/content, preview & import.
//  5. Safe Rule Integrity: deleting a list used in rules returns the list of
//     affected rules and optionally strips it cleanly without leaving broken links.
//  6. Extended Formats: plain, hosts, AdBlock, Clash, sing-box JSON, and v2fly
//     (domain:, full:, keyword:, include: expansion, regexp: skipped with warning).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	listUpdateEvery = 12 * time.Hour
	listMaxBytes    = 32 << 20
	listMaxDomains  = 500000
	listMaxPrefixes = 300000
)

type listPresetMeta struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	About    string `json:"about"`
	URL      string `json:"url"`
	Kind     string `json:"kind"` // "domains" | "ips" | "mixed"
}

var listCatalog = []listPresetMeta{
	{
		ID:       "youtube",
		Title:    "YouTube и Google Video",
		Category: "Медиа и соцсети",
		About:    "Все домены YouTube, видеопотоки googlevideo.com, превью ytimg и ggpht",
		URL:      "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/youtube",
		Kind:     "domains",
	},
	{
		ID:       "discord",
		Title:    "Discord (чат, голос и CDN)",
		Category: "Мессенджеры и звонки",
		About:    "Все домены Discord, голосовые серверы discord.media и CDN discordapp",
		URL:      "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/discord",
		Kind:     "domains",
	},
	{
		ID:       "telegram-ip",
		Title:    "Telegram (официальные IP и домены)",
		Category: "Мессенджеры и звонки",
		About:    "Официальные подсети дата-центров Telegram (AS62041/AS62014) и веб-домены",
		URL:      "https://antifilter.download/list/allyouneed.lst",
		Kind:     "mixed",
	},
	{
		ID:       "meta-instagram",
		Title:    "Instagram, Facebook, WhatsApp, Threads",
		Category: "Медиа и соцсети",
		About:    "Домены и CDN Instagram, Facebook, Threads и медиасерверов Meta",
		URL:      "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/instagram",
		Kind:     "domains",
	},
	{
		ID:       "twitter-x",
		Title:    "X (Twitter) и t.co",
		Category: "Медиа и соцсети",
		About:    "Домены x.com, twitter.com, twimg.com, t.co и видеопотоки",
		URL:      "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/twitter",
		Kind:     "domains",
	},
	{
		ID:       "ai-services",
		Title:    "ИИ-сервисы (ChatGPT, Claude, Gemini, Copilot)",
		Category: "Разработка и ИИ",
		About:    "OpenAI/ChatGPT, Anthropic Claude, Google Gemini, Perplexity, Midjourney, Cursor",
		URL:      "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai",
		Kind:     "domains",
	},
	{
		ID:       "gaming-steam-epic",
		Title:    "Игры и лаунчеры (Steam, Epic, Battle.net)",
		Category: "Игры",
		About:    "Серверы загрузки и авторизации Steam, Epic Games, Battle.net, Riot, EA",
		URL:      "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/steam",
		Kind:     "domains",
	},
	{
		ID:       "ru-gov-banks",
		Title:    "РФ: Госуслуги, банки и маркетплейсы",
		Category: "Прямой маршрут / Исключения",
		About:    "Российские банки, Госуслуги, Яндекс, ВК, Ozon, Wildberries (для правил Напрямую или исключения !ru-gov-banks)",
		URL:      "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-ru",
		Kind:     "domains",
	},
	{
		ID:       "ads-trackers",
		Title:    "Реклама, телеметрия и трекеры",
		Category: "Блокировка",
		About:    "Популярные рекламные сети и трекеры (рекомендуется маршрут «Блок»)",
		URL:      "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-ads",
		Kind:     "domains",
	},
	{
		ID:       "ru-blocked",
		Title:    "Реестр заблокированных доменов РФ",
		Category: "Антизапрет и реестры",
		About:    "Полный автоматически обновляемый список заблокированных доменов",
		URL:      "https://reestr.rublacklist.net/api/v3/domains/",
		Kind:     "domains",
	},
	{
		ID:       "antifilter-community",
		Title:    "Antifilter Community (домены)",
		Category: "Антизапрет и реестры",
		About:    "Сообщество Antifilter: домены, требующие маршрутизации через VPN",
		URL:      "https://community.antifilter.download/list/domains.lst",
		Kind:     "domains",
	},
	{
		ID:       "antifilter-ip",
		Title:    "Antifilter IP (заблокированные подсети)",
		Category: "Антизапрет и реестры",
		About:    "Список заблокированных IPv4-адресов и CIDR-подсетей Antifilter",
		URL:      "https://antifilter.download/list/ip.lst",
		Kind:     "ips",
	},
}

// Built-in presets map for backward compatibility with /api/rules.
var listPresets = map[string]string{
	"ru-blocked":           "https://reestr.rublacklist.net/api/v3/domains/",
	"blocked":              "https://reestr.rublacklist.net/api/v3/domains/",
	"antifilter-community": "https://community.antifilter.download/list/domains.lst",
	"antifilter-ip":        "https://antifilter.download/list/ip.lst",
	"telegram-ip":          "https://antifilter.download/list/allyouneed.lst",
	"telegram":             "https://antifilter.download/list/allyouneed.lst",
	"youtube":              "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/youtube",
	"discord":              "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/discord",
	"meta-instagram":       "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/instagram",
	"meta":                 "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/instagram",
	"twitter-x":            "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/twitter",
	"ai-services":          "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai",
	"ai":                   "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai",
	"gaming-steam-epic":    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/steam",
	"steam":                "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/steam",
	"ru-gov-banks":         "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-ru",
	"ru":                   "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-ru",
	"ads-trackers":         "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-ads",
	"google":               "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/google",
	"twitch":               "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/twitch",
	"spotify":              "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/spotify",
	"github":               "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/github",
}

// Built-in instant seed lists so rules using popular presets and v2fly
// "include:" directives work immediately at startup.

// Remote lists may be fetched from these built-in hosts and any host added by
// the user to lists.trusted_hosts.
var listTrustedHosts = []string{
	"raw.githubusercontent.com",
	"gist.githubusercontent.com",
	"antifilter.download",
	"reestr.rublacklist.net",
	"cdn.jsdelivr.net",
}

// Dynamic registry synced from Config so resolveListURL works everywhere.
var (
	listRegMu         sync.RWMutex
	customListURLMap  = map[string]string{} // lower(id) -> resolved URL or local:...
	extraTrustedHosts = map[string]bool{}   // lower(host) -> true
)

func syncListRegistryFromConfig(c *Config) {
	if c == nil {
		return
	}
	c.mu.Lock()
	syncListRegistryLocked(c)
	c.mu.Unlock()
}

func syncListRegistryLocked(c *Config) {
	if c == nil {
		return
	}
	listRegMu.Lock()
	defer listRegMu.Unlock()
	customListURLMap = make(map[string]string, len(c.Lists.Custom))
	for _, cl := range c.Lists.Custom {
		id := strings.ToLower(strings.TrimSpace(cl.ID))
		if id != "" && cl.URL != "" {
			customListURLMap[id] = cl.URL
		}
	}
	extraTrustedHosts = make(map[string]bool, len(c.Lists.TrustedHosts))
	for _, h := range c.Lists.TrustedHosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h != "" {
			extraTrustedHosts[h] = true
		}
	}
}

func isTrustedListHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, ok := range listTrustedHosts {
		if h == ok || strings.HasSuffix(h, "."+ok) {
			return true
		}
	}
	listRegMu.RLock()
	defer listRegMu.RUnlock()
	for ok := range extraTrustedHosts {
		if h == ok || strings.HasSuffix(h, "."+ok) {
			return true
		}
	}
	return false
}

func allTrustedListHosts() []string {
	out := append([]string(nil), listTrustedHosts...)
	listRegMu.RLock()
	for h := range extraTrustedHosts {
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	listRegMu.RUnlock()
	sort.Strings(out)
	return out
}

// validLocalListName checks that a local list filename is safe (no path
// traversal "..", no slashes, no leading/trailing dots, only [a-z0-9._-]).
func validLocalListName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// isBlockedSSRFAddr returns true if ip is loopback, private, link-local,
// multicast, unspecified, CGNAT (100.64.0.0/10) or benchmark (198.18.0.0/15).
func isBlockedSSRFAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.Is4() {
		b := ip.As4()
		// 100.64.0.0/10 (Carrier-Grade NAT)
		if b[0] == 100 && (b[1]&0xC0) == 64 {
			return true
		}
		// 198.18.0.0/15 (FakeIP / RFC 2544 benchmark)
		if b[0] == 198 && (b[1] == 18 || b[1] == 19) {
			return true
		}
		// 169.254.0.0/16 (cloud metadata / link-local)
		if b[0] == 169 && b[1] == 254 {
			return true
		}
	}
	return false
}

// ErrUntrustedListHost is returned when a remote list URL uses an HTTPS host
// that is valid and safe (not SSRF) but not yet in the trusted hosts list.
type ErrUntrustedListHost struct {
	Host string
	URL  string
}

func (e *ErrUntrustedListHost) Error() string {
	return fmt.Sprintf("список с %s не разрешён (подтвердите доверие к хосту %s; сейчас разрешены: %s)", e.Host, e.Host, strings.Join(allTrustedListHosts(), ", "))
}

// validateRemoteListURL validates scheme, hostname, SSRF constraints, and trust.
func validateRemoteListURL(raw string, allowUntrusted bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("список «%s»: нужна ссылка https://", raw)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".internal") {
		return nil, fmt.Errorf("список «%s»: локальные и внутренние адреса запрещены (SSRF)", raw)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if isBlockedSSRFAddr(ip) {
			return nil, fmt.Errorf("список «%s»: частные и локальные IP-адреса запрещены (SSRF)", raw)
		}
	}
	if !allowUntrusted && !isTrustedListHost(host) {
		return nil, &ErrUntrustedListHost{Host: host, URL: u.String()}
	}
	return u, nil
}

// splitListNegation strips an optional "!" prefix from a list reference.
func splitListNegation(s string) (name string, neg bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "!") {
		return strings.TrimSpace(s[1:]), true
	}
	return s, false
}

// resolveListURL turns a preset name, custom list ID, local list name, or
// https URL into the canonical URL/key to fetch. Leading "!" (exclusion) is
// allowed and stripped.
func resolveListURL(s string) (string, error) {
	s, _ = splitListNegation(s)
	s = strings.TrimPrefix(s, "list:")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("пустое имя списка")
	}
	low := strings.ToLower(s)
	if u, ok := listPresets[low]; ok {
		return u, nil
	}
	listRegMu.RLock()
	cu, isCustom := customListURLMap[low]
	listRegMu.RUnlock()
	if isCustom && cu != "" {
		return cu, nil
	}
	// Support local user lists stored in the lists directory ("local:my.lst" or "local:user-my.lst")
	if rest, ok := strings.CutPrefix(low, "local:"); ok {
		rest = strings.TrimSpace(rest)
		if !validLocalListName(rest) {
			return "", errors.New("некорректное имя локального списка")
		}
		return "local:" + rest, nil
	}
	if !strings.Contains(s, "://") {
		names := make([]string, 0, len(listPresets))
		for k := range listPresets {
			names = append(names, k)
		}
		sort.Strings(names)
		return "", fmt.Errorf("неизвестный список «%s» (готовые: %s)", s, strings.Join(names, ", "))
	}
	u, err := validateRemoteListURL(s, false)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// ipv4Range represents an inclusive IPv4 interval [start, end] in host byte order.
type ipv4Range struct {
	start uint32
	end   uint32
}

// ipv6Range represents an inclusive IPv6 interval [start, end].
type ipv6Range struct {
	start [16]byte
	end   [16]byte
}

type listMetaCache struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	Updated      int64  `json:"updated,omitempty"`
}

// flatDomainIndex хранит отсортированные домены в едином непрерывном буфере байт (blob)
// и таблице смещений (offs длины N+1). Структура не содержит указателей на строки,
// поэтому сборщик мусора Go (GC) полностью пропускает сканирование сотен тысяч доменов,
// сокращая потребление ОЗУ списков с ~18 МБ до ~1.8 МБ.
type flatDomainIndex struct {
	blob []byte
	offs []uint32
}

func buildFlatDomainIndex(sorted []string) flatDomainIndex {
	if len(sorted) == 0 {
		return flatDomainIndex{}
	}
	total := 0
	for _, s := range sorted {
		total += len(s)
	}
	blob := make([]byte, 0, total)
	offs := make([]uint32, 0, len(sorted)+1)
	for _, s := range sorted {
		offs = append(offs, uint32(len(blob)))
		blob = append(blob, s...)
	}
	offs = append(offs, uint32(len(blob)))
	return flatDomainIndex{blob: blob, offs: offs}
}

func (f *flatDomainIndex) Len() int {
	if f == nil || len(f.offs) <= 1 {
		return 0
	}
	return len(f.offs) - 1
}

func (f *flatDomainIndex) Contains(target string) bool {
	n := f.Len()
	if n == 0 || target == "" {
		return false
	}
	lo, hi := 0, n-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		start, end := f.offs[mid], f.offs[mid+1]
		cur := string(f.blob[start:end])
		if cur == target {
			return true
		}
		if cur < target {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return false
}

// listData stores domains in pointer-free flatDomainIndex buffers and IPv4/IPv6 CIDRs
// in merged interval trees, plus parse diagnostics for preview.
type listData struct {
	domains       flatDomainIndex // pointer-free sorted suffix domains (O(log N) binary search, 0 GC pointers)
	exact         flatDomainIndex // pointer-free sorted exact domains ("DOMAIN,..." or "full:...")
	keywords      []string        // substring match ("DOMAIN-KEYWORD,..." or "keyword:...")
	v4Ranges      []ipv4Range     // sorted, merged IPv4 intervals for O(log N) lookup
	v6Ranges      []ipv6Range     // sorted, merged IPv6 intervals for O(log N) lookup
	includes      []string        // v2fly "include:..." directives encountered
	skippedLines  int             // malformed or unrecognized non-empty lines skipped
	regexpSkipped int             // "regexp:..." rules skipped with warning
	etag          string
	lastModified  string
	updated       time.Time
	sizeBytes     int
	builtin       bool
	err           string
}

func (d *listData) domainCount() int {
	if d == nil {
		return 0
	}
	return d.domains.Len() + d.exact.Len() + len(d.keywords)
}

func (d *listData) subnetCount() int {
	if d == nil {
		return 0
	}
	return len(d.v4Ranges) + len(d.v6Ranges)
}

func (d *listData) warnings() []string {
	if d == nil {
		return nil
	}
	var w []string
	if d.regexpSkipped > 0 {
		w = append(w, fmt.Sprintf("пропущено правил regexp: %d (регулярные выражения в списках не поддерживаются)", d.regexpSkipped))
	}
	if d.skippedLines > 0 {
		w = append(w, fmt.Sprintf("отброшено нераспознанных строк: %d", d.skippedLines))
	}
	return w
}

type Lists struct {
	app *App
	dir string

	mu       sync.RWMutex
	data     map[string]*listData // resolved URL -> parsed list
	seeds    map[string]*listData // resolved URL -> built-in seed fallback
	updating bool
	wake     chan struct{}

	// Optional HTTP transport override for offline unit tests.
	testTransport http.RoundTripper
}

func newLists(app *App, dir string) *Lists {
	l := &Lists{
		app:   app,
		dir:   dir,
		data:  map[string]*listData{},
		seeds: map[string]*listData{},
		wake:  make(chan struct{}, 1),
	}
	if app != nil && app.cfg != nil {
		syncListRegistryFromConfig(app.cfg)
	}
	for _, id := range builtinSeedNames() {
		raw, _ := builtinSeed(id)
		if u, err := resolveListURL(id); err == nil {
			sd := parseListWithIncludes(strings.NewReader(raw), l.resolveIncludeReader, 0)
			sd.builtin = true
			sd.sizeBytes = len(raw)
			l.seeds[u] = sd
		}
	}
	return l
}

// resolveRemoteIncludeReader разрешает директиву include: только для встроенных (builtin)
// списков при разборе внешних списков, скачанных по URL (Баг №1: запрет чтения локальных файлов с диска).
func (l *Lists) resolveRemoteIncludeReader(name string) io.ReadCloser {
	cleanName := strings.ToLower(strings.TrimSpace(name))
	if cleanName == "" {
		return nil
	}
	if raw, ok := builtinSeed(cleanName); ok {
		return io.NopCloser(strings.NewReader(raw))
	}
	return nil
}

// resolveIncludeReader разрешает директиву include: для локальных списков
// со строгой валидацией имени и проверкой префикса filepath.Abs (защита от Path Traversal — Баг №1).
func (l *Lists) resolveIncludeReader(name string) io.ReadCloser {
	cleanName := strings.ToLower(strings.TrimSpace(name))
	if cleanName == "" {
		return nil
	}
	if raw, ok := builtinSeed(cleanName); ok {
		return io.NopCloser(strings.NewReader(raw))
	}
	// Запрещаем любые разделители путей, "..", двоеточия и скрытые имена
	if strings.ContainsAny(cleanName, `/\:*?"<>|`) || strings.Contains(cleanName, "..") || strings.HasPrefix(cleanName, ".") {
		return nil
	}
	if l != nil && l.dir != "" {
		absListDir, err := filepath.Abs(l.dir)
		if err != nil {
			return nil
		}
		absPrefix := absListDir
		if !strings.HasSuffix(absPrefix, string(filepath.Separator)) {
			absPrefix += string(filepath.Separator)
		}
		for _, fileCand := range []string{
			cleanName + ".lst",
			"user-" + cleanName + ".lst",
			cleanName,
		} {
			if !validLocalListName(fileCand) {
				continue
			}
			fullCand := filepath.Join(l.dir, fileCand)
			absTarget, err := filepath.Abs(fullCand)
			if err != nil || !strings.HasPrefix(absTarget, absPrefix) {
				continue
			}
			if f, err := os.Open(absTarget); err == nil {
				return f
			}
		}
		if u, err := resolveListURL(cleanName); err == nil && !strings.HasPrefix(u, "local:") {
			cacheCand := listCacheFile(l.dir, u)
			if absCache, err := filepath.Abs(cacheCand); err == nil && strings.HasPrefix(absCache, absPrefix) {
				if f, err := os.Open(absCache); err == nil {
					return f
				}
			}
		}
	}
	return nil
}

func (l *Lists) Start(ctx context.Context) {
	_ = os.MkdirAll(l.dir, 0o700)
	l.discoverDiskLocalLists()
	l.loadCached()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		l.updateAll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-l.wake:
				l.updateAll(ctx)
			case <-t.C:
				l.updateAll(ctx)
			}
		}
	}()
}

// discoverDiskLocalLists registers any existing user-*.lst files in l.dir into
// cfg.Lists.Custom if they are not already registered.
func (l *Lists) discoverDiskLocalLists() {
	if l == nil || l.dir == "" || l.app == nil || l.app.cfg == nil {
		return
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	c := l.app.cfg
	c.mu.Lock()
	changed := false
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		nm := ent.Name()
		if !strings.HasPrefix(nm, "user-") || (!strings.HasSuffix(nm, ".lst") && !strings.HasSuffix(nm, ".txt")) {
			continue
		}
		key := "local:" + nm
		baseID := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(nm, "user-"), ".lst"), ".txt")
		exists := false
		for _, cl := range c.Lists.Custom {
			if strings.EqualFold(cl.ID, baseID) || strings.EqualFold(cl.URL, key) {
				exists = true
				break
			}
		}
		if !exists && baseID != "" {
			c.Lists.Custom = append(c.Lists.Custom, CustomList{
				ID:            baseID,
				Title:         baseID,
				Type:          "local",
				URL:           key,
				Category:      "Мои списки",
				Enabled:       true,
				IntervalHours: 12,
			})
			changed = true
		}
	}
	if changed {
		syncListRegistryLocked(c)
	}
	c.mu.Unlock()
}

// Refresh triggers an immediate check of all lists used in the rules and custom registry.
func (l *Lists) Refresh() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *Lists) neededURLs() []string {
	if l == nil || l.app == nil || l.app.cfg == nil {
		return nil
	}
	l.app.cfg.mu.Lock()
	syncListRegistryLocked(l.app.cfg)
	rules := append([]Rule(nil), l.app.cfg.Routing.Rules...)
	customs := append([]CustomList(nil), l.app.cfg.Lists.Custom...)
	hidden := append([]string(nil), l.app.cfg.Lists.Hidden...)
	l.app.cfg.mu.Unlock()

	hiddenSet := map[string]bool{}
	for _, h := range hidden {
		hiddenSet[strings.ToLower(strings.TrimSpace(h))] = true
	}

	seen := map[string]bool{}
	var out []string
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		for _, s := range r.Lists {
			name, _ := splitListNegation(s)
			low := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "list:"))
			if hiddenSet[low] {
				continue
			}
			u, err := resolveListURL(s)
			if err != nil {
				continue
			}
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	for _, cl := range customs {
		if !cl.Enabled || cl.URL == "" {
			continue
		}
		if !seen[cl.URL] {
			seen[cl.URL] = true
			out = append(out, cl.URL)
		}
	}
	return out
}

func listCacheFile(dir, u string) string {
	if rest, ok := strings.CutPrefix(u, "local:"); ok {
		return filepath.Join(dir, rest)
	}
	h := sha256.Sum256([]byte(u))
	return filepath.Join(dir, hex.EncodeToString(h[:8])+".lst")
}

func (l *Lists) loadCached() {
	urls := l.neededURLs()
	for _, m := range listCatalog {
		if !slices.Contains(urls, m.URL) {
			urls = append(urls, m.URL)
		}
	}
	for _, u := range urls {
		f := listCacheFile(l.dir, u)
		st, err := os.Stat(f)
		if err != nil {
			continue
		}
		rc, err := os.Open(f)
		if err != nil {
			continue
		}
		d := parseListWithIncludes(rc, l.resolveIncludeReader, 0)
		_ = rc.Close()
		d.updated = st.ModTime()
		d.sizeBytes = int(st.Size())
		l.mu.Lock()
		l.data[u] = d
		l.mu.Unlock()
	}
}

func (l *Lists) customIntervalForURL(u string) time.Duration {
	if l == nil || l.app == nil || l.app.cfg == nil {
		return listUpdateEvery
	}
	l.app.cfg.mu.Lock()
	defer l.app.cfg.mu.Unlock()
	for _, cl := range l.app.cfg.Lists.Custom {
		if cl.URL == u && cl.IntervalHours > 0 {
			return time.Duration(cl.IntervalHours) * time.Hour
		}
	}
	return listUpdateEvery
}

func (l *Lists) updateAll(ctx context.Context) {
	l.mu.Lock()
	if l.updating {
		l.mu.Unlock()
		return
	}
	l.updating = true
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.updating = false
		l.mu.Unlock()
	}()

	urls := l.neededURLs()
	updatedAny := false
	for _, u := range urls {
		if ctx.Err() != nil {
			return
		}
		if strings.HasPrefix(u, "local:") {
			f := listCacheFile(l.dir, u)
			if st, err := os.Stat(f); err == nil {
				if rc, err := os.Open(f); err == nil {
					d := parseListWithIncludes(rc, l.resolveIncludeReader, 0)
					_ = rc.Close()
					d.updated = st.ModTime()
					d.sizeBytes = int(st.Size())
					l.mu.Lock()
					l.data[u] = d
					l.mu.Unlock()
				}
			}
			continue
		}
		l.mu.RLock()
		cur := l.data[u]
		l.mu.RUnlock()
		interval := l.customIntervalForURL(u)
		if cur != nil && !cur.builtin && time.Since(cur.updated) < interval {
			continue
		}
		l.fetchOne(ctx, u)
		updatedAny = true
	}
	if updatedAny {
		runtime.GC()
	}
}

// wrapSSRFDial protects direct connections from connecting to loopback/private IPs.
func wrapSSRFDial(base dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip, perr := netip.ParseAddr(host); perr == nil {
			if isBlockedSSRFAddr(ip) {
				return nil, errors.New("соединение с внутренним адресом запрещено (SSRF)")
			}
			return base(ctx, network, addr)
		}
		// Баг №6: строгая политика fail-closed — при ошибке DNS-резолвинга или пустом ответе
		// соединение немедленно отклоняется без передачи неразрешённого хоста в базовый диалер.
		ips, rerr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if rerr != nil {
			return nil, fmt.Errorf("ssrf guard: ошибка DNS-резолвинга для %s: %w", host, rerr)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("ssrf guard: DNS не вернул IP-адресов для %s", host)
		}
		for _, ip := range ips {
			if isBlockedSSRFAddr(ip) {
				return nil, fmt.Errorf("домен %s указывает на внутренний IP %s (SSRF)", host, ip)
			}
		}
		return base(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
}

func (l *Lists) fetchOne(ctx context.Context, u string) {
	if _, err := validateRemoteListURL(u, false); err != nil {
		l.mu.Lock()
		l.data[u] = &listData{err: err.Error()}
		l.mu.Unlock()
		return
	}
	f := listCacheFile(l.dir, u)
	var dials []dialFunc
	if l.testTransport != nil {
		dials = []dialFunc{nil}
	} else {
		dials = []dialFunc{wrapSSRFDial(l.app.router.dialer(obDesync)), wrapSSRFDial(dialDirect)}
		if l.app.psi != nil && l.app.psi.running() {
			dials = append([]dialFunc{l.app.psi.Dial}, dials...)
		}
	}
	var lastErr error
	for _, d := range dials {
		fctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		tr := l.testTransport
		if tr == nil {
			tr = &http.Transport{
				Proxy:             nil,
				DialContext:       d,
				DisableKeepAlives: true,
			}
		}
		cl := &http.Client{
			Timeout:   45 * time.Second,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("слишком много перенаправлений")
				}
				if _, err := validateRemoteListURL(req.URL.String(), false); err != nil {
					return fmt.Errorf("перенаправление отклонено: %w", err)
				}
				return nil
			},
		}
		req, err := http.NewRequestWithContext(fctx, "GET", u, nil)
		if err != nil {
			cancel()
			lastErr = err
			break
		}
		metaPath := f + ".meta.json"
		var prevMeta listMetaCache
		if mb, merr := os.ReadFile(metaPath); merr == nil {
			_ = json.Unmarshal(mb, &prevMeta)
		}
		if _, stErr := os.Stat(f); stErr == nil {
			if prevMeta.ETag != "" {
				req.Header.Set("If-None-Match", prevMeta.ETag)
			}
			if prevMeta.LastModified != "" {
				req.Header.Set("If-Modified-Since", prevMeta.LastModified)
			}
		}
		resp, err := cl.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			cancel()
			l.mu.Lock()
			if cur := l.data[u]; cur != nil {
				cur.updated = time.Now()
				cur.err = ""
			}
			l.mu.Unlock()
			logf("info", "Список актуален (304 Not Modified): %s", presetNameOrURL(u))
			return
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			cancel()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		newETag := strings.TrimSpace(resp.Header.Get("ETag"))
		newLastMod := strings.TrimSpace(resp.Header.Get("Last-Modified"))
		_ = os.MkdirAll(l.dir, 0o700)
		tmp := f + ".tmp"
		tf, ferr := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if ferr != nil {
			resp.Body.Close()
			cancel()
			lastErr = ferr
			continue
		}
		written, cerr := io.Copy(tf, io.LimitReader(resp.Body, listMaxBytes+1))
		_ = tf.Sync()
		_ = tf.Close()
		resp.Body.Close()
		cancel()
		if written > listMaxBytes {
			_ = os.Remove(tmp)
			lastErr = errors.New("размер списка превышает лимит 32 МБ")
			continue
		}
		if cerr != nil || written == 0 {
			_ = os.Remove(tmp)
			lastErr = errors.New("пустой или оборванный ответ")
			continue
		}
		rc, oerr := os.Open(tmp)
		if oerr != nil {
			_ = os.Remove(tmp)
			lastErr = oerr
			continue
		}
		parsed := parseListWithIncludes(rc, l.resolveRemoteIncludeReader, 0)
		_ = rc.Close()
		if parsed.domainCount() == 0 && parsed.subnetCount() == 0 {
			_ = os.Remove(tmp)
			lastErr = errors.New("список пуст или не распознан")
			continue
		}
		if err := os.Rename(tmp, f); err != nil {
			_ = os.Remove(tmp)
			lastErr = err
			continue
		}
		parsed.updated = time.Now()
		parsed.sizeBytes = int(written)
		parsed.etag = newETag
		parsed.lastModified = newLastMod
		if newETag != "" || newLastMod != "" {
			if mb, merr := json.Marshal(listMetaCache{ETag: newETag, LastModified: newLastMod, Updated: parsed.updated.Unix()}); merr == nil {
				_ = writeFileAtomic(metaPath, mb, 0o600)
			}
		}
		l.mu.Lock()
		l.data[u] = parsed
		l.mu.Unlock()
		if l.app != nil && l.app.router != nil {
			l.app.router.InvalidateRules()
		}
		if parsed.regexpSkipped > 0 {
			logf("warn", "Список %s: пропущено %d правил regexp (не поддерживаются)", presetNameOrURL(u), parsed.regexpSkipped)
		}
		logf("info", "Список обновлён: %s (доменов: %d, диапазонов IP: %d)", presetNameOrURL(u), parsed.domainCount(), parsed.subnetCount())
		return
	}
	l.mu.Lock()
	if l.data[u] == nil {
		if seed := l.seeds[u]; seed != nil {
			cp := *seed
			if lastErr != nil {
				cp.err = "используется встроенная база (" + lastErr.Error() + ")"
			}
			l.data[u] = &cp
		} else {
			l.data[u] = &listData{err: errText(lastErr)}
		}
	} else if lastErr != nil {
		l.data[u].err = lastErr.Error()
	}
	l.mu.Unlock()
	if lastErr != nil {
		logf("warn", "Список %s не обновлён: %v", presetNameOrURL(u), lastErr)
	}
}

func presetNameOrURL(u string) string {
	for _, m := range listCatalog {
		if m.URL == u {
			return m.ID + " (" + m.Title + ")"
		}
	}
	return u
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func sanitizeListID(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "local:")
	raw = strings.TrimPrefix(raw, "list:")
	raw = strings.TrimPrefix(raw, "user-")
	raw = strings.TrimSuffix(raw, ".lst")
	raw = strings.TrimSuffix(raw, ".txt")
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' || r == '.' {
			b.WriteByte('-')
		}
	}
	res := strings.Trim(b.String(), "-_")
	if len(res) > 48 {
		res = res[:48]
	}
	return res
}

// PreviewList parses raw list text and returns a preview summary (domains,
// subnets, skipped lines, regexp warnings) without saving.
func (l *Lists) PreviewList(content string) map[string]any {
	var inc func(string) io.ReadCloser
	if l != nil {
		inc = l.resolveIncludeReader
	}
	d := parseListWithIncludes(strings.NewReader(content), inc, 0)
	return map[string]any{
		"ok":             true,
		"domains":        d.domainCount(),
		"suffixes":       d.domains.Len(),
		"exact":          d.exact.Len(),
		"keywords":       len(d.keywords),
		"subnets":        d.subnetCount(),
		"cidrs":          d.subnetCount(),
		"skipped_lines":  d.skippedLines,
		"regexp_skipped": d.regexpSkipped,
		"includes":       d.includes,
		"warnings":       d.warnings(),
	}
}

// SaveLocalList writes a user-managed custom list to the lists directory,
// registers it in cfg.Lists.Custom, and parses it into memory.
func (l *Lists) SaveLocalList(name, content string) (map[string]any, error) {
	if len(content) > listMaxBytes {
		return nil, errors.New("размер списка превышает 32 МБ")
	}
	rawName := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(name), "local:"))
	if rawName == "" {
		return nil, errors.New("укажите название локального списка")
	}
	var clean strings.Builder
	for _, r := range rawName {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			clean.WriteRune(r)
		}
	}
	fname := strings.Trim(clean.String(), ".")
	if fname == "" {
		return nil, errors.New("недопустимое имя списка (используйте латиницу, цифры и дефис)")
	}
	if !strings.HasSuffix(fname, ".lst") && !strings.HasSuffix(fname, ".txt") {
		fname += ".lst"
	}
	if !validLocalListName(fname) {
		return nil, errors.New("некорректное имя локального списка")
	}
	d := parseListWithIncludes(strings.NewReader(content), l.resolveIncludeReader, 0)
	if d.domainCount() == 0 && d.subnetCount() == 0 {
		return nil, errors.New("в списке не найдено ни одного корректного домена или IP/подсети")
	}
	key := "local:" + fname
	path := listCacheFile(l.dir, key)
	if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
		return nil, err
	}
	d.updated = time.Now()
	d.sizeBytes = len(content)
	l.mu.Lock()
	l.data[key] = d
	l.mu.Unlock()

	baseID := sanitizeListID(fname)
	if baseID == "" {
		baseID = fname
	}
	if l.app != nil && l.app.cfg != nil {
		c := l.app.cfg
		c.mu.Lock()
		found := false
		for i := range c.Lists.Custom {
			if strings.EqualFold(c.Lists.Custom[i].ID, baseID) || c.Lists.Custom[i].URL == key {
				c.Lists.Custom[i].URL = key
				c.Lists.Custom[i].Type = "local"
				c.Lists.Custom[i].Enabled = true
				found = true
				break
			}
		}
		if !found {
			c.Lists.Custom = append(c.Lists.Custom, CustomList{
				ID:            baseID,
				Title:         strings.TrimSpace(name),
				Type:          "local",
				URL:           key,
				Category:      "Мои списки",
				Enabled:       true,
				IntervalHours: 12,
			})
		}
		syncListRegistryLocked(c)
		c.mu.Unlock()
		_ = c.save()
		l.app.onRulesChanged()
	}

	return map[string]any{
		"ok":             true,
		"id":             key,
		"custom_id":      baseID,
		"domains":        d.domainCount(),
		"subnets":        d.subnetCount(),
		"cidrs":          d.subnetCount(),
		"skipped_lines":  d.skippedLines,
		"regexp_skipped": d.regexpSkipped,
		"warnings":       d.warnings(),
	}, nil
}

// UpsertCustomList creates or updates a custom list (local or remote URL).
func (l *Lists) UpsertCustomList(ctx context.Context, id, title, typ, rawURL, content, category string, enabled *bool, intervalHours int, confirmTrust bool) (map[string]any, error) {
	if l == nil || l.app == nil || l.app.cfg == nil {
		return nil, errors.New("подсистема списков не инициализирована")
	}
	typ = strings.ToLower(strings.TrimSpace(typ))
	if typ == "" {
		if strings.TrimSpace(content) != "" || strings.HasPrefix(strings.ToLower(rawURL), "local:") {
			typ = "local"
		} else {
			typ = "url"
		}
	}
	if typ != "local" && typ != "url" {
		return nil, errors.New("неизвестный тип списка: укажите local или url")
	}
	cleanID := sanitizeListID(id)
	if cleanID == "" {
		cleanID = sanitizeListID(title)
	}
	if cleanID == "" && typ == "url" {
		if u, err := url.Parse(rawURL); err == nil {
			cleanID = sanitizeListID(u.Hostname() + "-" + filepath.Base(u.Path))
		}
	}
	if cleanID == "" {
		return nil, errors.New("укажите идентификатор или название списка (латиницей/цифрами)")
	}
	// Prevent colliding with built-in catalog IDs when creating a custom list
	for _, b := range listCatalog {
		if strings.EqualFold(b.ID, cleanID) {
			cleanID = "custom-" + cleanID
			break
		}
	}
	if strings.TrimSpace(title) == "" {
		title = cleanID
	}
	if strings.TrimSpace(category) == "" {
		category = "Мои списки"
	}
	if intervalHours <= 0 {
		intervalHours = 12
	}
	en := true
	if enabled != nil {
		en = *enabled
	}

	c := l.app.cfg
	var resolvedKey string
	var parsed *listData

	if typ == "local" {
		fname := "user-" + cleanID + ".lst"
		resolvedKey = "local:" + fname
		path := listCacheFile(l.dir, resolvedKey)
		if strings.TrimSpace(content) == "" {
			// If updating metadata only (rename/toggle) without passing new content, read existing file
			if existingBytes, err := os.ReadFile(path); err == nil {
				content = string(existingBytes)
			}
		}
		if len(content) > listMaxBytes {
			return nil, errors.New("размер списка превышает 32 МБ")
		}
		parsed = parseListWithIncludes(strings.NewReader(content), l.resolveIncludeReader, 0)
		if parsed.domainCount() == 0 && parsed.subnetCount() == 0 {
			return nil, errors.New("в списке не найдено ни одного корректного домена или подсети")
		}
		if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
			return nil, err
		}
		parsed.updated = time.Now()
		parsed.sizeBytes = len(content)
		l.mu.Lock()
		l.data[resolvedKey] = parsed
		l.mu.Unlock()
	} else {
		u, err := validateRemoteListURL(rawURL, confirmTrust)
		if err != nil {
			var untrusted *ErrUntrustedListHost
			if errors.As(err, &untrusted) {
				return map[string]any{
					"ok":                 false,
					"need_confirm_trust": true,
					"untrusted_host":     untrusted.Host,
					"error":              untrusted.Error(),
				}, err
			}
			return nil, err
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if confirmTrust && !isTrustedListHost(host) {
			c.mu.Lock()
			if !slices.Contains(c.Lists.TrustedHosts, host) {
				c.Lists.TrustedHosts = append(c.Lists.TrustedHosts, host)
			}
			syncListRegistryLocked(c)
			c.mu.Unlock()
			logf("info", "Хост %s добавлен в доверенные источники списков", host)
		}
		resolvedKey = u.String()
	}

	entry := CustomList{
		ID:            cleanID,
		Title:         strings.TrimSpace(title),
		Type:          typ,
		URL:           resolvedKey,
		Category:      strings.TrimSpace(category),
		Enabled:       en,
		IntervalHours: intervalHours,
	}

	c.mu.Lock()
	updated := false
	for i := range c.Lists.Custom {
		if strings.EqualFold(c.Lists.Custom[i].ID, cleanID) || strings.EqualFold(c.Lists.Custom[i].ID, id) {
			c.Lists.Custom[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		c.Lists.Custom = append(c.Lists.Custom, entry)
	}
	syncListRegistryLocked(c)
	c.mu.Unlock()
	_ = c.save()
	l.app.onRulesChanged()

	if typ == "url" && en {
		l.fetchOne(ctx, resolvedKey)
		l.mu.RLock()
		parsed = l.data[resolvedKey]
		l.mu.RUnlock()
	}

	res := map[string]any{
		"ok":   true,
		"id":   cleanID,
		"url":  resolvedKey,
		"type": typ,
		"item": entry,
	}
	if parsed != nil {
		res["domains"] = parsed.domainCount()
		res["subnets"] = parsed.subnetCount()
		res["cidrs"] = parsed.subnetCount()
		res["skipped_lines"] = parsed.skippedLines
		res["regexp_skipped"] = parsed.regexpSkipped
		res["warnings"] = parsed.warnings()
		if parsed.err != "" {
			res["fetch_error"] = parsed.err
		}
	}
	return res, nil
}

// RulesUsingList returns the names of all routing rules that reference listID.
func (l *Lists) RulesUsingList(listID string) []string {
	if l == nil || l.app == nil || l.app.cfg == nil {
		return nil
	}
	target := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(listID), "list:"))
	targetURL, _ := resolveListURL(target)

	l.app.cfg.mu.Lock()
	defer l.app.cfg.mu.Unlock()
	var used []string
	for i, r := range l.app.cfg.Routing.Rules {
		for _, ref := range r.Lists {
			name, _ := splitListNegation(ref)
			clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "list:"))
			refURL, _ := resolveListURL(clean)
			if clean == target || (targetURL != "" && refURL == targetURL) || "local:"+target == clean || "local:user-"+target+".lst" == clean {
				nm := strings.TrimSpace(r.Name)
				if nm == "" {
					nm = fmt.Sprintf("Правило #%d", i+1)
				}
				if !slices.Contains(used, nm) {
					used = append(used, nm)
				}
			}
		}
	}
	return used
}

// removeListFromRulesLocked removes all references to target / targetURL from
// c.Routing.Rules and drops rules that had only this list and no other criteria.
func removeListFromRulesLocked(c *Config, target, targetURL string) int {
	removedRefs := 0
	keptRules := make([]Rule, 0, len(c.Routing.Rules))
	for _, r := range c.Routing.Rules {
		if len(r.Lists) == 0 {
			keptRules = append(keptRules, r)
			continue
		}
		var newLists []string
		for _, ref := range r.Lists {
			name, _ := splitListNegation(ref)
			clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "list:"))
			refURL, _ := resolveListURL(clean)
			if clean == target || (targetURL != "" && refURL == targetURL) || "local:"+target == clean || "local:user-"+target+".lst" == clean {
				removedRefs++
				continue
			}
			newLists = append(newLists, ref)
		}
		r.Lists = newLists
		if len(r.Lists) == 0 && len(r.Domains) == 0 && len(r.Keywords) == 0 && len(r.CIDR) == 0 && len(r.Apps) == 0 && len(r.Ports) == 0 && len(r.PortRanges) == 0 {
			continue
		}
		keptRules = append(keptRules, r)
	}
	c.Routing.Rules = keptRules
	return removedRefs
}

// DeleteList deletes a custom/local list or hides a built-in list. If the list
// is referenced by rules and removeFromRules is false, it returns HTTP 409 info
// with used_in_rules without modifying rules.
func (l *Lists) DeleteList(id string, removeFromRules bool) (map[string]any, int, error) {
	if l == nil || l.app == nil || l.app.cfg == nil {
		return nil, 500, errors.New("подсистема списков не инициализирована")
	}
	clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(id), "list:"))
	if clean == "" {
		return nil, 400, errors.New("укажите идентификатор списка")
	}
	used := l.RulesUsingList(clean)
	if len(used) > 0 && !removeFromRules {
		return map[string]any{
			"ok":            false,
			"in_use":        true,
			"used_in_rules": used,
			"error":         fmt.Sprintf("Список «%s» используется в правилах (%s). Убрать его из правил и удалить?", id, strings.Join(used, ", ")),
		}, http.StatusConflict, errors.New("список используется в правилах")
	}

	targetURL, _ := resolveListURL(clean)
	c := l.app.cfg
	c.mu.Lock()
	if removeFromRules && len(used) > 0 {
		removeListFromRulesLocked(c, clean, targetURL)
	}

	// Check if built-in catalog preset -> hide instead of deleting from code
	isBuiltin := false
	for _, b := range listCatalog {
		if strings.EqualFold(b.ID, clean) {
			isBuiltin = true
			if !slices.ContainsFunc(c.Lists.Hidden, func(x string) bool { return strings.EqualFold(x, b.ID) }) {
				c.Lists.Hidden = append(c.Lists.Hidden, b.ID)
			}
			break
		}
	}

	var removedURL string
	if !isBuiltin {
		idx := slices.IndexFunc(c.Lists.Custom, func(cl CustomList) bool {
			return strings.EqualFold(cl.ID, clean) || strings.EqualFold(cl.URL, clean) || strings.EqualFold(cl.URL, "local:"+clean)
		})
		if idx >= 0 {
			removedURL = c.Lists.Custom[idx].URL
			c.Lists.Custom = append(c.Lists.Custom[:idx], c.Lists.Custom[idx+1:]...)
		} else if strings.HasPrefix(clean, "local:") {
			removedURL = clean
		} else {
			cand := "local:" + clean
			if !strings.HasSuffix(cand, ".lst") && !strings.HasSuffix(cand, ".txt") {
				cand += ".lst"
			}
			if _, err := os.Stat(listCacheFile(l.dir, cand)); err == nil {
				removedURL = cand
			} else {
				c.mu.Unlock()
				return nil, http.StatusNotFound, fmt.Errorf("список «%s» не найден", id)
			}
		}
	}
	syncListRegistryLocked(c)
	c.mu.Unlock()
	_ = c.save()
	l.app.onRulesChanged()

	if removedURL != "" {
		f := listCacheFile(l.dir, removedURL)
		_ = os.Remove(f)
		_ = os.Remove(f + ".meta.json")
		l.mu.Lock()
		delete(l.data, removedURL)
		l.mu.Unlock()
	}

	return map[string]any{
		"ok":                 true,
		"id":                 clean,
		"hidden_builtin":     isBuiltin,
		"removed_from_rules": used,
	}, http.StatusOK, nil
}

// RestoreBuiltinLists clears lists.hidden so all built-in lists are visible again.
func (l *Lists) RestoreBuiltinLists() map[string]any {
	if l == nil || l.app == nil || l.app.cfg == nil {
		return map[string]any{"ok": false}
	}
	c := l.app.cfg
	c.mu.Lock()
	restored := len(c.Lists.Hidden)
	c.Lists.Hidden = nil
	syncListRegistryLocked(c)
	c.mu.Unlock()
	_ = c.save()
	l.app.onRulesChanged()
	return map[string]any{"ok": true, "restored": restored}
}

// RefreshOne triggers an immediate update/reload of a single list by ID or URL.
func (l *Lists) RefreshOne(ctx context.Context, id string) (map[string]any, error) {
	u, err := resolveListURL(id)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(u, "local:") {
		f := listCacheFile(l.dir, u)
		rc, err := os.Open(f)
		if err != nil {
			return nil, fmt.Errorf("файл локального списка не найден: %w", err)
		}
		st, _ := rc.Stat()
		d := parseListWithIncludes(rc, l.resolveIncludeReader, 0)
		_ = rc.Close()
		if st != nil {
			d.updated = st.ModTime()
			d.sizeBytes = int(st.Size())
		} else {
			d.updated = time.Now()
		}
		l.mu.Lock()
		l.data[u] = d
		l.mu.Unlock()
		return map[string]any{"ok": true, "id": id, "url": u, "domains": d.domainCount(), "subnets": d.subnetCount()}, nil
	}
	l.fetchOne(ctx, u)
	l.mu.RLock()
	d := l.data[u]
	l.mu.RUnlock()
	if d != nil && d.err != "" && d.domainCount() == 0 && d.subnetCount() == 0 {
		return nil, errors.New(d.err)
	}
	doms, subs := 0, 0
	if d != nil {
		doms, subs = d.domainCount(), d.subnetCount()
	}
	return map[string]any{"ok": true, "id": id, "url": u, "domains": doms, "subnets": subs}, nil
}

// GetListContent returns the raw text content of a local, cached, or seed list.
func (l *Lists) GetListContent(id string) (string, error) {
	clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(id), "list:"))
	if clean == "" {
		return "", errors.New("укажите идентификатор списка")
	}
	u, err := resolveListURL(clean)
	if err != nil {
		// Try local:<id>.lst fallback
		cand := clean
		if !strings.HasSuffix(cand, ".lst") && !strings.HasSuffix(cand, ".txt") {
			cand += ".lst"
		}
		if validLocalListName(cand) {
			u = "local:" + cand
		} else {
			return "", err
		}
	}
	f := listCacheFile(l.dir, u)
	if b, rerr := os.ReadFile(f); rerr == nil {
		return string(b), nil
	}
	if raw, ok := builtinSeed(clean); ok {
		return raw, nil
	}
	for k, presetURL := range listPresets {
		if presetURL == u {
			if raw, ok := builtinSeed(k); ok {
				return raw, nil
			}
		}
	}
	return "", fmt.Errorf("содержимое списка «%s» ещё не загружено", id)
}

// Status for the UI: returns built-in catalog lists, custom lists (local + URL),
// and any extra lists referenced in rules, with rule usage and deletable flags.
func (l *Lists) Status() []map[string]any {
	needed := map[string]bool{}
	for _, u := range l.neededURLs() {
		needed[u] = true
	}
	var customs []CustomList
	hiddenSet := map[string]bool{}
	if l != nil && l.app != nil && l.app.cfg != nil {
		l.app.cfg.mu.Lock()
		customs = append([]CustomList(nil), l.app.cfg.Lists.Custom...)
		for _, h := range l.app.cfg.Lists.Hidden {
			hiddenSet[strings.ToLower(strings.TrimSpace(h))] = true
		}
		l.app.cfg.mu.Unlock()
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	seen := map[string]bool{}
	var out []map[string]any

	buildEntry := func(id, title, category, about, kind, typ, u string, isCustom, isBuiltin, isHidden, enabled bool, intervalHours int) map[string]any {
		d := l.data[u]
		if d == nil {
			d = l.seeds[u]
		}
		usedBy := l.RulesUsingList(id)
		if len(usedBy) == 0 && u != id {
			usedBy = l.RulesUsingList(u)
		}
		m := map[string]any{
			"id":             id,
			"title":          title,
			"category":       category,
			"about":          about,
			"kind":           kind,
			"type":           typ,
			"url":            u,
			"custom":         isCustom,
			"local":          strings.HasPrefix(u, "local:"),
			"builtin_preset": isBuiltin,
			"hidden":         isHidden,
			"enabled":        enabled,
			"interval_hours": intervalHours,
			"active":         needed[u] || len(usedBy) > 0,
			"used_in_rules":  usedBy,
			"deletable":      len(usedBy) == 0,
			"domains":        0,
			"subnets":        0,
			"cidrs":          0,
			"updated":        int64(0),
			"error":          "",
		}
		if d != nil {
			m["domains"] = d.domainCount()
			m["suffixes"] = d.domains.Len()
			m["exact"] = d.exact.Len()
			m["keywords"] = len(d.keywords)
			m["subnets"] = d.subnetCount()
			m["cidrs"] = d.subnetCount()
			m["builtin"] = d.builtin
			m["size_bytes"] = d.sizeBytes
			m["skipped_lines"] = d.skippedLines
			m["regexp_skipped"] = d.regexpSkipped
			if !d.updated.IsZero() {
				m["updated"] = d.updated.Unix()
			}
			if d.err != "" {
				m["error"] = d.err
			}
		}
		return m
	}

	// 1. User custom lists (from config.Lists.Custom)
	for _, cl := range customs {
		if cl.URL == "" {
			continue
		}
		seen[cl.URL] = true
		seen[strings.ToLower(cl.ID)] = true
		cat := cl.Category
		if cat == "" {
			cat = "Мои списки"
		}
		iv := cl.IntervalHours
		if iv <= 0 {
			iv = 12
		}
		out = append(out, buildEntry(cl.ID, cl.Title, cat, cl.About, "mixed", cl.Type, cl.URL, true, false, false, cl.Enabled, iv))
	}

	// 2. Any in-memory local lists not yet in customs (e.g. created via SaveLocalList on a bare Lists struct)
	for u := range l.data {
		if strings.HasPrefix(u, "local:") && !seen[u] {
			seen[u] = true
			name := strings.TrimPrefix(u, "local:")
			out = append(out, buildEntry(u, name, "Мои списки", "Локальный пользовательский список", "mixed", "local", u, true, false, false, true, 12))
		}
	}

	// 3. Built-in catalog presets
	for _, meta := range listCatalog {
		if seen[meta.URL] || seen[strings.ToLower(meta.ID)] {
			continue
		}
		seen[meta.URL] = true
		seen[strings.ToLower(meta.ID)] = true
		hid := hiddenSet[strings.ToLower(meta.ID)]
		out = append(out, buildEntry(meta.ID, meta.Title, meta.Category, meta.About, meta.Kind, "builtin", meta.URL, false, true, hid, !hid, 12))
	}

	// 4. Any other direct URLs referenced in rules
	for _, u := range l.neededURLs() {
		if seen[u] {
			continue
		}
		seen[u] = true
		typ := "url"
		if strings.HasPrefix(u, "local:") {
			typ = "local"
		}
		out = append(out, buildEntry(u, u, "Пользовательские списки", "", "mixed", typ, u, true, false, false, true, 12))
	}
	return out
}

// TestHost checks a domain or IP against all loaded and seed lists and returns
// matching list IDs and details for the UI diagnostic tool.
func (l *Lists) TestHost(target string) map[string]any {
	target = cleanHostKey(target)
	ip, _ := netip.ParseAddr(target)
	var matches []map[string]any

	l.mu.RLock()
	defer l.mu.RUnlock()

	checkOne := func(id, title, u string, d *listData) {
		if d == nil {
			return
		}
		if d.match(target, ip) {
			matches = append(matches, map[string]any{
				"id":    id,
				"title": title,
				"url":   u,
			})
		}
	}
	seen := map[string]bool{}
	for _, m := range listCatalog {
		seen[m.URL] = true
		d := l.data[m.URL]
		if d == nil {
			d = l.seeds[m.URL]
		}
		checkOne(m.ID, m.Title, m.URL, d)
	}
	if l.app != nil && l.app.cfg != nil {
		l.app.cfg.mu.Lock()
		customs := append([]CustomList(nil), l.app.cfg.Lists.Custom...)
		l.app.cfg.mu.Unlock()
		for _, cl := range customs {
			seen[cl.URL] = true
			checkOne(cl.ID, cl.Title, cl.URL, l.data[cl.URL])
		}
	}
	for u, d := range l.data {
		if !seen[u] {
			checkOne(u, u, u, d)
		}
	}
	matchedIDs := make([]string, 0, len(matches))
	for _, m := range matches {
		if id, ok := m["id"].(string); ok {
			matchedIDs = append(matchedIDs, id)
		}
	}
	return map[string]any{
		"ok":      true,
		"target":  target,
		"matches": matches,
		"matched": matchedIDs,
	}
}

func (l *Lists) getListDataLocked(u string) *listData {
	if d := l.data[u]; d != nil && (d.domainCount() > 0 || d.subnetCount() > 0) {
		return d
	}
	return l.seeds[u]
}

// EvalLists evaluates positive and negated ("!list") list references in a rule.
func (l *Lists) EvalLists(listNames []string, host string, ips []netip.Addr) (posMatch, hasPos, negMatch bool) {
	if l == nil || len(listNames) == 0 {
		return false, false, false
	}
	host = cleanHostKey(host)
	if len(ips) == 0 {
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{ip.Unmap()}
		}
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, raw := range listNames {
		name, neg := splitListNegation(raw)
		if name == "" {
			continue
		}
		u, err := resolveListURL(name)
		if err != nil {
			continue
		}
		if !neg {
			hasPos = true
		}
		d := l.getListDataLocked(u)
		if d == nil {
			continue
		}
		matched := false
		if len(ips) == 0 {
			matched = d.match(host, netip.Addr{})
		} else {
			for _, ip := range ips {
				if d.match(host, ip) {
					matched = true
					break
				}
			}
		}
		if matched {
			if neg {
				return posMatch, hasPos, true
			}
			posMatch = true
		}
	}
	return posMatch, hasPos, false
}

// Match reports whether host (domain or IP) is in any of the named lists,
// respecting "!list" exclusions.
func (l *Lists) Match(listNames []string, host string) bool {
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(cleanHostKey(host)); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	}
	return l.MatchIPs(listNames, host, ips)
}

// MatchIPs reports whether host or any of the pre-resolved/packet IPs is in any
// of the named lists (and not excluded by a "!list" entry).
func (l *Lists) MatchIPs(listNames []string, host string, ips []netip.Addr) bool {
	posMatch, hasPos, negMatch := l.EvalLists(listNames, host, ips)
	if negMatch {
		return false
	}
	if hasPos {
		return posMatch
	}
	return true
}

func (d *listData) match(host string, ip netip.Addr) bool {
	if d == nil {
		return false
	}
	if ip.IsValid() {
		ip = ip.Unmap()
		if ip.Is4() {
			if matchIPv4Ranges(d.v4Ranges, ipv4ToUint32(ip)) {
				return true
			}
		} else if ip.Is6() {
			if matchIPv6Ranges(d.v6Ranges, ip.As16()) {
				return true
			}
		}
	}
	if host == "" {
		return false
	}
	if d.exact.Contains(host) {
		return true
	}
	for _, kw := range d.keywords {
		if strings.Contains(host, kw) {
			return true
		}
	}
	if d.domains.Len() == 0 {
		return false
	}
	for h := host; ; {
		if d.domains.Contains(h) {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
}

// ---------- Binary-Search IPv4 & IPv6 Range Helpers ----------

func ipv4ToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func prefixToIPv4Range(p netip.Prefix) ipv4Range {
	p = p.Masked()
	start := ipv4ToUint32(p.Addr())
	bits := p.Bits()
	if bits >= 32 {
		return ipv4Range{start: start, end: start}
	}
	if bits <= 0 {
		return ipv4Range{start: 0, end: 0xFFFFFFFF}
	}
	mask := uint32(0xFFFFFFFF) >> uint(bits)
	return ipv4Range{start: start, end: start | mask}
}

func prefixToIPv6Range(p netip.Prefix) ipv6Range {
	p = p.Masked()
	start := p.Addr().As16()
	end := start
	bits := p.Bits()
	for i := bits; i < 128; i++ {
		end[i/8] |= 1 << uint(7-(i%8))
	}
	return ipv6Range{start: start, end: end}
}

func mergeIPv4Ranges(in []ipv4Range) []ipv4Range {
	if len(in) <= 1 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].start != in[j].start {
			return in[i].start < in[j].start
		}
		return in[i].end < in[j].end
	})
	out := in[:0]
	cur := in[0]
	for _, r := range in[1:] {
		if r.start <= cur.end || (cur.end < 0xFFFFFFFF && r.start == cur.end+1) {
			if r.end > cur.end {
				cur.end = r.end
			}
		} else {
			out = append(out, cur)
			cur = r
		}
	}
	out = append(out, cur)
	return slices.Clip(out)
}

func cmp16(a, b [16]byte) int {
	return bytes.Compare(a[:], b[:])
}

func mergeIPv6Ranges(in []ipv6Range) []ipv6Range {
	if len(in) <= 1 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if c := cmp16(in[i].start, in[j].start); c != 0 {
			return c < 0
		}
		return cmp16(in[i].end, in[j].end) < 0
	})
	out := in[:0]
	cur := in[0]
	for _, r := range in[1:] {
		if cmp16(r.start, cur.end) <= 0 {
			if cmp16(r.end, cur.end) > 0 {
				cur.end = r.end
			}
		} else {
			out = append(out, cur)
			cur = r
		}
	}
	out = append(out, cur)
	return slices.Clip(out)
}

func matchIPv4Ranges(ranges []ipv4Range, ip uint32) bool {
	lo, hi := 0, len(ranges)-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		r := ranges[mid]
		if ip < r.start {
			hi = mid - 1
		} else if ip > r.end {
			lo = mid + 1
		} else {
			return true
		}
	}
	return false
}

func matchIPv6Ranges(ranges []ipv6Range, ip [16]byte) bool {
	lo, hi := 0, len(ranges)-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		r := ranges[mid]
		if cmp16(ip, r.start) < 0 {
			hi = mid - 1
		} else if cmp16(ip, r.end) > 0 {
			lo = mid + 1
		} else {
			return true
		}
	}
	return false
}

// ---------- Zero-Copy Streaming List Parser with Include & Preview ----------

func parseList(r io.Reader) *listData {
	return parseListWithIncludes(r, func(name string) io.ReadCloser {
		name = strings.ToLower(strings.TrimSpace(name))
		if raw, ok := builtinSeed(name); ok {
			return io.NopCloser(strings.NewReader(raw))
		}
		return nil
	}, 0)
}

func parseListWithIncludes(r io.Reader, includeResolver func(string) io.ReadCloser, depth int) *listData {
	d := &listData{}
	domSet := map[string]struct{}{}
	exactSet := map[string]struct{}{}
	kwSeen := map[string]struct{}{}
	incSeen := map[string]bool{}
	var v4Raw []ipv4Range
	var v6Raw []ipv6Range

	addSuffix := func(s string) bool {
		if len(domSet) >= listMaxDomains {
			return true
		}
		if h := cleanListDomain(s); h != "" {
			domSet[strings.Clone(h)] = struct{}{}
			return true
		}
		return false
	}
	addExact := func(s string) bool {
		if len(exactSet) >= listMaxDomains {
			return true
		}
		if h := cleanListDomain(s); h != "" {
			exactSet[strings.Clone(h)] = struct{}{}
			return true
		}
		return false
	}
	addKeyword := func(s string) bool {
		s = strings.ToLower(strings.TrimSpace(s))
		if len(s) < 3 || len(s) > 128 {
			return false
		}
		if _, ok := kwSeen[s]; !ok && len(d.keywords) < 10000 {
			kwClone := strings.Clone(s)
			kwSeen[kwClone] = struct{}{}
			d.keywords = append(d.keywords, kwClone)
		}
		return true
	}
	addPrefix := func(p netip.Prefix) {
		if len(v4Raw)+len(v6Raw) >= listMaxPrefixes {
			return
		}
		if p.Addr().Is4() {
			v4Raw = append(v4Raw, prefixToIPv4Range(p))
		} else if p.Addr().Is6() {
			v6Raw = append(v6Raw, prefixToIPv6Range(p))
		}
	}
	addCIDROrIP := func(s string) bool {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			addPrefix(p)
			return true
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			ip = ip.Unmap()
			addPrefix(netip.PrefixFrom(ip, ip.BitLen()))
			return true
		}
		return false
	}

	var parseStream func(rd io.Reader, curDepth int)
	parseStream = func(rd io.Reader, curDepth int) {
		br := bufio.NewReaderSize(io.LimitReader(rd, listMaxBytes), 32<<10)
		var firstByte byte
		for {
			b, err := br.Peek(1)
			if err != nil {
				break
			}
			if b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n' || b[0] == 0xEF || b[0] == 0xBB || b[0] == 0xBF {
				_, _ = br.ReadByte()
				continue
			}
			firstByte = b[0]
			break
		}

		if firstByte == '{' {
			var sb struct {
				Rules []struct {
					Domain        []string `json:"domain"`
					DomainSuffix  []string `json:"domain_suffix"`
					DomainKeyword []string `json:"domain_keyword"`
					DomainRegex   []string `json:"domain_regex"`
					IPCIDR        []string `json:"ip_cidr"`
				} `json:"rules"`
			}
			if json.NewDecoder(br).Decode(&sb) == nil && len(sb.Rules) > 0 {
				for _, ru := range sb.Rules {
					for _, x := range ru.Domain {
						if !addExact(x) {
							d.skippedLines++
						}
					}
					for _, x := range ru.DomainSuffix {
						if !addSuffix(x) {
							d.skippedLines++
						}
					}
					for _, x := range ru.DomainKeyword {
						if !addKeyword(x) {
							d.skippedLines++
						}
					}
					d.regexpSkipped += len(ru.DomainRegex)
					for _, x := range ru.IPCIDR {
						if !addCIDROrIP(x) {
							d.skippedLines++
						}
					}
				}
				return
			}
		}

		sc := bufio.NewScanner(br)
		sc.Buffer(make([]byte, 64<<10), 2<<20)
		for sc.Scan() {
			line := sc.Text()
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if line == "" || line == "payload:" || line == "[" || line == "]" {
				continue
			}
			// JSON array elements on one or many lines: ["a.com","b.com"]
			if strings.HasPrefix(line, "[") || strings.HasSuffix(line, `",`) || strings.HasPrefix(line, `"`) {
				for _, part := range strings.Split(line, ",") {
					part = strings.Trim(part, "[]\" \t")
					if part == "" {
						continue
					}
					if !addCIDROrIP(part) && !addSuffix(part) {
						d.skippedLines++
					}
				}
				continue
			}
			// Clash YAML list item: - '+.youtube.com' or - DOMAIN-SUFFIX,youtube.com
			if strings.HasPrefix(line, "-") {
				line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
				line = strings.Trim(line, `'"`)
			}
			// Clash rule format: TYPE,VALUE[,POLICY...]
			if strings.Contains(line, ",") {
				parts := strings.Split(line, ",")
				if len(parts) >= 2 {
					kind := strings.ToUpper(strings.TrimSpace(parts[0]))
					val := strings.TrimSpace(parts[1])
					switch kind {
					case "DOMAIN-SUFFIX", "HOST-SUFFIX":
						if !addSuffix(val) {
							d.skippedLines++
						}
						continue
					case "DOMAIN", "HOST":
						if !addExact(val) {
							d.skippedLines++
						}
						continue
					case "DOMAIN-KEYWORD", "HOST-KEYWORD":
						if !addKeyword(val) {
							d.skippedLines++
						}
						continue
					case "IP-CIDR", "IP-CIDR6", "IP6-CIDR":
						if !addCIDROrIP(val) {
							d.skippedLines++
						}
						continue
					case "DOMAIN-REGEX", "URL-REGEX":
						d.regexpSkipped++
						continue
					}
				}
			}
			// v2ray / xray format: regexp:..., include:..., full:..., keyword:..., domain:...
			lowLine := strings.ToLower(line)
			if strings.HasPrefix(lowLine, "regexp:") {
				d.regexpSkipped++
				continue
			}
			if rest, ok := strings.CutPrefix(lowLine, "include:"); ok {
				incName := strings.TrimSpace(rest)
				if i := strings.IndexAny(incName, " \t@"); i >= 0 {
					incName = incName[:i]
				}
				if incName != "" && !incSeen[incName] {
					incSeen[incName] = true
					d.includes = append(d.includes, incName)
					if curDepth < 4 && includeResolver != nil {
						if irc := includeResolver(incName); irc != nil {
							parseStream(irc, curDepth+1)
							_ = irc.Close()
						}
					}
				}
				continue
			}
			if rest, ok := strings.CutPrefix(lowLine, "full:"); ok {
				if i := strings.IndexAny(rest, " \t@"); i >= 0 {
					rest = rest[:i]
				}
				if !addExact(rest) {
					d.skippedLines++
				}
				continue
			}
			if rest, ok := strings.CutPrefix(lowLine, "keyword:"); ok {
				if i := strings.IndexAny(rest, " \t@"); i >= 0 {
					rest = rest[:i]
				}
				if !addKeyword(rest) {
					d.skippedLines++
				}
				continue
			}
			if rest, ok := strings.CutPrefix(lowLine, "domain:"); ok {
				line = rest
			}
			// hosts file format: "0.0.0.0 example.com" or "127.0.0.1 example.com"
			if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") || strings.HasPrefix(line, "0.0.0.0\t") || strings.HasPrefix(line, "127.0.0.1\t") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] != "localhost" && fields[1] != "0.0.0.0" {
					if !addSuffix(fields[1]) {
						d.skippedLines++
					}
				}
				continue
			}
			if i := strings.IndexAny(line, " \t@"); i >= 0 {
				// If there's whitespace not from a valid hosts/v2fly attribute, check if it's "@attr"
				if line[i] == '@' || strings.HasPrefix(strings.TrimSpace(line[i:]), "@") {
					line = line[:i]
				} else {
					d.skippedLines++
					continue
				}
			}
			if addCIDROrIP(line) {
				continue
			}
			if !addSuffix(line) {
				d.skippedLines++
			}
		}
	}

	parseStream(r, depth)
	d.finalize(domSet, exactSet, v4Raw, v6Raw)
	return d
}

// finalize merges IPv4/IPv6 CIDR ranges and removes redundant subdomain entries
// that are already covered by a parent domain suffix in d.domains.
func (d *listData) finalize(domSet, exactSet map[string]struct{}, v4Raw []ipv4Range, v6Raw []ipv6Range) {
	if len(v4Raw) > 0 {
		d.v4Ranges = mergeIPv4Ranges(v4Raw)
	}
	if len(v6Raw) > 0 {
		d.v6Ranges = mergeIPv6Ranges(v6Raw)
	}
	if len(domSet) > 1 {
		for h := range domSet {
			for rem := h; ; {
				i := strings.IndexByte(rem, '.')
				if i < 0 {
					break
				}
				rem = rem[i+1:]
				if _, parentExists := domSet[rem]; parentExists {
					delete(domSet, h)
					break
				}
			}
		}
	}
	if len(exactSet) > 0 && len(domSet) > 0 {
		for h := range exactSet {
			for rem := h; ; {
				if _, covered := domSet[rem]; covered {
					delete(exactSet, h)
					break
				}
				i := strings.IndexByte(rem, '.')
				if i < 0 {
					break
				}
				rem = rem[i+1:]
			}
		}
	}
	if len(domSet) > 0 {
		sortedDom := make([]string, 0, len(domSet))
		for h := range domSet {
			sortedDom = append(sortedDom, h)
		}
		sort.Strings(sortedDom)
		d.domains = buildFlatDomainIndex(sortedDom)
	}
	if len(exactSet) > 0 {
		sortedExact := make([]string, 0, len(exactSet))
		for h := range exactSet {
			sortedExact = append(sortedExact, h)
		}
		sort.Strings(sortedExact)
		d.exact = buildFlatDomainIndex(sortedExact)
	}

	// MatchRUWhitelist checks whether host belongs to Russian national TLDs (.ru, .рф, .su, .xn--p1ai)
	// or the built-in ru-gov-banks / ru lists (Priority 4 in the Top-to-Bottom routing pipeline).
}

func (l *Lists) MatchRUWhitelist(host string) bool {
	host = cleanHostKey(host)
	if host == "" {
		return false
	}
	if strings.HasSuffix(host, ".ru") || strings.HasSuffix(host, ".su") || strings.HasSuffix(host, ".рф") || strings.HasSuffix(host, ".xn--p1ai") {
		return true
	}
	if l == nil {
		return false
	}
	pos, _, _ := l.EvalLists([]string{"ru-gov-banks", "ru"}, host, nil)
	return pos
}

// sanitizeRuleToken cleans user-pasted URLs (https://site.com/path -> site.com),
// strips comments (#...), and trims spaces.
func sanitizeRuleToken(raw string) string {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	neg := ""
	if strings.HasPrefix(raw, "!") {
		neg = "!"
		raw = strings.TrimSpace(raw[1:])
	}
	lower := strings.ToLower(raw)
	for _, pfx := range []string{"domain:", "full:", "exact:", "keyword:", "regexp:", "cidr:", "ip:", "app:", "country:", "geoip:", "list:", "port:", "proto:"} {
		if strings.HasPrefix(lower, pfx) {
			val := strings.TrimSpace(raw[len(pfx):])
			if pfx == "domain:" || pfx == "full:" || pfx == "exact:" {
				val = stripURLToHost(val)
			}
			return neg + pfx + val
		}
	}
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if !strings.Contains(lower, ".lst") && !strings.Contains(lower, ".txt") && !isTrustedListURL(raw) {
			return neg + stripURLToHost(raw)
		}
	}
	return neg + raw
}

func isTrustedListURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && isTrustedListHost(u.Hostname())
}

func stripURLToHost(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	return strings.Trim(s, "[] ")
}

func cleanListDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimSuffix(s, "^")
	s = strings.TrimPrefix(s, "+.")
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(s, ".")
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_') {
			return ""
		}
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	return s
}
