package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var defaultFavoriteCountries = []string{"DE", "NL", "US", "FI", "GB"}

func normalizeFavoriteCountries(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, cc := range in {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if len(cc) != 2 || cc == "AUTO" {
			continue
		}
		if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			continue
		}
		if !seen[cc] {
			seen[cc] = true
			out = append(out, cc)
		}
	}
	return out
}

// CustomList describes a user-created remote (URL) or local domain/IP list
// persisted in psiroute.json under lists.custom.
type CustomList struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Type          string `json:"type"` // "url" | "local"
	URL           string `json:"url"`  // https://... or local:<file>.lst
	Category      string `json:"category,omitempty"`
	About         string `json:"about,omitempty"`
	Enabled       bool   `json:"enabled"`
	IntervalHours int    `json:"interval_hours,omitempty"` // update interval in hours (default 12)
}

// Config is persisted to psiroute.json next to the data directory. It is kept
// deliberately flat-ish so the UI can read and write individual keys by a
// dotted path ("psiphon.parallel", "desync.enabled", ...).
const currentConfigSchemaVersion = 2

type Config struct {
	SchemaVersion int `json:"schema_version,omitempty"`
	Psiphon       struct {
		Parallel               int      `json:"parallel"`                           // tunnels tried in parallel (TunnelPoolSize)
		Standby                bool     `json:"standby"`                            // keep a spare tunnel warm
		HealthIntervalS        int      `json:"health_interval_secs"`               // health check period
		MinSpeedKBps           int      `json:"min_speed_kbps"`                     // rotate if slower (0 = off)
		DPI                    string   `json:"dpi"`                                // "" std | off | hello | light | strong | auto
		Country                string   `json:"country"`                            // egress region, "" = auto
		FavoriteCountries      []string `json:"favorite_countries,omitempty"`       // user's favorite exit countries
		BlockedCountries       []string `json:"blocked_countries,omitempty"`        // country blacklist excluded from Auto egress
		Via                    string   `json:"via"`                                // auto | direct | warp | proxy
		Strategies             []string `json:"strategies"`                         // enabled strategy ids, order = priority
		SingleProcessCountries bool     `json:"single_process_countries,omitempty"` // hot-switch exit country in main process (saves 20-25 MB RAM per country)
		Preset                 string   `json:"preset,omitempty"`                   // fast | balanced | patient
		MirrorURL              string   `json:"mirror_url,omitempty"`               // optional user-controlled HTTPS mirror for server entries (off by default)
		PropagationChannelID   string   `json:"propagation_channel_id,omitempty"`   // optional 16-hex official Psiphon PropagationChannelId
		SponsorID              string   `json:"sponsor_id,omitempty"`               // optional 16-hex official Psiphon SponsorId
		ClientPlatform         string   `json:"client_platform,omitempty"`          // optional Psiphon ClientPlatform string
	} `json:"psiphon"`
	Desync struct {
		Enabled   bool     `json:"enabled"`    // split TLS ClientHello on direct connections
		Method    string   `json:"method"`     // auto | tlsrec | split | double | multirec | chunk
		TestSites []string `json:"test_sites"` // sites for the DPI test panel
	} `json:"desync"`
	Warp struct {
		Enabled  bool   `json:"enabled"`
		Engine   string `json:"engine"`   // builtin (in-process, the default) | socks (external)
		Socks    string `json:"socks"`    // external WARP SOCKS5, e.g. 127.0.0.1:18181
		Mask     string `json:"mask"`     // built-in: handshake masking auto | quic | masque | bwg | dns | off
		Endpoint string `json:"endpoint"` // built-in: Cloudflare endpoint ip:port, "" = auto
	} `json:"warp"`
	CleanChain struct {
		Enabled   bool `json:"enabled"`    // WARP -> VPN -> WARP clean exit IP cascade
		AutoChain bool `json:"auto_chain"` // bypass EntryWarp automatically when direct VPN works
	} `json:"clean_chain"`
	Proxy struct {
		Enabled  bool   `json:"enabled"`
		Upstream string `json:"upstream"` // external upstream, e.g. socks5://127.0.0.1:1081 or http://...
	} `json:"proxy"`
	DNS struct {
		Enabled     bool   `json:"enabled"`                // encrypted DNS (DoH) for name resolution
		LocalServer bool   `json:"local_server,omitempty"` // run local DNS server (DoH + FakeIP)
		LocalAddr   string `json:"local_addr,omitempty"`   // default 127.0.0.1:5353
	} `json:"dns"`
	Routing struct {
		Mode       string   `json:"mode"`                  // psiphon | rules | auto
		Failover   bool     `json:"failover"`              // fall back to Psiphon when a non-direct route fails
		Learn      bool     `json:"learn"`                 // remember the working route per host
		BypassLAN  bool     `json:"bypass_lan,omitempty"`  // keep private/LAN addresses direct in all modes
		BlockQUIC  bool     `json:"block_quic,omitempty"`  // drop UDP:443 (QUIC) on non-direct routes so browsers use TCP+DPI
		KillSwitch     bool     `json:"kill_switch,omitempty"`      // block VPN traffic when Psiphon is disconnected
		KillSwitchMode string   `json:"kill_switch_mode,omitempty"` // off | auto | strict (WFP Kill Switch)
		BlockSTUN  bool     `json:"block_stun,omitempty"`  // block STUN/WebRTC UDP ports (3478, 5349, 19302) on direct routes
		Default    string   `json:"default"`               // default outbound in rules mode
		Rules      []Rule   `json:"rules"`
		Chain      []string `json:"auto_chain"` // outbound order tried in auto mode
	} `json:"routing"`
	Lists struct {
		Custom       []CustomList `json:"custom,omitempty"`        // user-defined local and remote lists
		Hidden       []string     `json:"hidden,omitempty"`        // hidden built-in preset IDs
		TrustedHosts []string     `json:"trusted_hosts,omitempty"` // user-approved HTTPS hosts for remote lists
	} `json:"lists,omitempty"`
	UDP struct {
		Mode string `json:"mode"` // route | direct | psiphon | off
	} `json:"udp"`
	Share struct {
		Enabled  bool   `json:"enabled"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		NoPwdLAN bool   `json:"no_password_in_lan"`
	} `json:"share"`
	General struct {
		WatchConfig bool   `json:"watch_config"`          // reload psiroute.json when it changes
		SystemProxy bool   `json:"system_proxy"`          // set the OS proxy to us on start
		Autostart   bool   `json:"autostart"`             // launch with the OS
		Autoconnect bool   `json:"autoconnect,omitempty"` // connect tunnel automatically on start
		Listen      string `json:"listen"`                // proxy address, e.g. 127.0.0.1:1080
		UI          string `json:"ui"`                    // web UI address, e.g. 127.0.0.1:9090
		NoWeb       bool   `json:"no_web,omitempty"`      // disable web UI listener when headless/CLI
		UIMode      string `json:"ui_mode,omitempty"`     // gio (modern Gio UI, default) | browser
		UITheme     string `json:"ui_theme,omitempty"`    // obsidian (Tactical Glass, default) | cyber (Cyber-Amber / Soviet Terminal HUD)
		LogLevel    string `json:"log_level,omitempty"`   // debug | info | warn | error
		LogFile     string `json:"log_file,omitempty"`    // optional custom log file path
		MemLimitMB  int    `json:"mem_limit_mb,omitempty"`
		Profile     string `json:"profile,omitempty"`
	} `json:"general"`
	Tun struct {
		Enabled bool     `json:"enabled"`
		MTU     int      `json:"mtu"`
		DNS     bool     `json:"dns_hijack"`
		FakeIP  bool     `json:"fake_ip"`
		IPv6    bool     `json:"ipv6"`
		Exclude []string `json:"exclude_apps"`
	} `json:"tun"`

	mu            sync.Mutex `json:"-"`
	path          string     `json:"-"`
	corruptErr    string     `json:"-"`
	corruptBackup string     `json:"-"`
	corruptLogged bool       `json:"-"`
	lastSavedMod  time.Time  `json:"-"`
}

func (c *Config) corruptError() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.corruptErr
}

func (c *Config) corruptBackupPath() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.corruptBackup
}

// isSelfSaveModTime проверяет, совпадает ли время модификации файла на диске с последним
// сохранением из самой программы (Находка 11: защита от ложного срабатывания reloadConfig в loop()).
func (c *Config) isSelfSaveModTime(mod time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.lastSavedMod.IsZero() && !mod.After(c.lastSavedMod)
}

// Rule is one routing rule matched by host, keyword, CIDR, port/port-range,
// protocol, or application. Prefixing a domain, keyword, CIDR or app with "!"
// negates (excludes) it.
type Rule struct {
	Name       string   `json:"name"`
	Outbound   string   `json:"outbound"`
	Domains    []string `json:"domains"`
	Keywords   []string `json:"keywords"`
	CIDR       []string `json:"cidr"`
	Ports      []int    `json:"ports"`
	PortRanges []string `json:"port_ranges,omitempty"`
	Proto      string   `json:"proto,omitempty"`
	Lists      []string `json:"lists,omitempty"`
	Apps       []string `json:"apps,omitempty"`
	Always     bool     `json:"always,omitempty"`
	Disabled   bool     `json:"disabled,omitempty"`
}

func defaultConfig() *Config {
	c := &Config{SchemaVersion: currentConfigSchemaVersion}
	c.Psiphon.Parallel = 2
	c.Psiphon.Standby = true
	c.Psiphon.SingleProcessCountries = true
	c.Psiphon.HealthIntervalS = 30
	c.Psiphon.MinSpeedKBps = 0
	c.Psiphon.Via = "auto"
	c.Psiphon.Preset = PresetBalanced
	c.Psiphon.FavoriteCountries = append([]string(nil), defaultFavoriteCountries...)
	c.Psiphon.Strategies = []string{"via-warp", "auto", "conduit", "meek", "tls", "ossh", "quic", "direct-dpi", "desync-meek", "desync-ossh"}
	c.Desync.Enabled = true
	c.Desync.Method = "auto"
	c.Warp.Enabled = false
	c.Warp.Socks = "127.0.0.1:40000"
	c.Warp.Engine = "builtin"
	c.Warp.Mask = "auto"
	c.CleanChain.Enabled = false
	c.CleanChain.AutoChain = true
	c.Routing.KillSwitchMode = wfpModeOff
	c.Proxy.Enabled = false
	c.DNS.Enabled = true
	c.DNS.LocalAddr = "127.0.0.1:5353"
	c.UDP.Mode = "route"
	c.Routing.Mode = "psiphon"
	c.Routing.Failover = true
	c.Routing.Learn = true
	c.Routing.Default = obDirect
	c.Routing.Chain = []string{"direct", "direct-dpi", "psiphon"}
	c.Share.Port = 1081
	c.Share.User = "psiroute"
	c.Share.NoPwdLAN = false
	c.General.WatchConfig = true
	c.General.Listen = "127.0.0.1:1080"
	c.General.UI = "127.0.0.1:9090"
	c.General.UIMode = "gio"
	c.General.UITheme = "obsidian"
	c.Tun.MTU = 1500
	c.Tun.DNS = true
	c.Tun.FakeIP = true
	c.Tun.IPv6 = true
	return c
}

// loadConfigStrict reads psiroute.json and returns an explicit syntax/read error (used by --test-config).
func loadConfigStrict(path string) (*Config, error) {
	c := defaultConfig()
	c.path = path
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл конфигурации: %w", err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, fmt.Errorf("ошибка синтаксиса config.json: файл пуст")
	}
	if uerr := json.Unmarshal(b, c); uerr != nil {
		return nil, fmt.Errorf("ошибка синтаксиса config.json: %w", uerr)
	}
	c.postLoadDefaults()
	return c, nil
}

// loadConfig reads psiroute.json, filling missing fields with defaults.
// Баг №3: при ошибке парсинга JSON сохраняет резервную копию повреждённого файла
// (.corrupt.<timestamp>), пишет критическую ошибку в лог и не перезаписывает файл дефолтами.
func loadConfig(path string) *Config {
	c := defaultConfig()
	c.path = path
	b, err := os.ReadFile(path)
	if err == nil {
		var rawMeta struct {
			SchemaVersion int `json:"schema_version"`
		}
		_ = json.Unmarshal(b, &rawMeta)
		if uerr := json.Unmarshal(b, c); uerr != nil {
			backupPath := fmt.Sprintf("%s.corrupt.%s", path, time.Now().Format("20060102-150405"))
			backupErr := writeFileAtomic(backupPath, b, 0o600)
			c = defaultConfig()
			c.path = path
			c.corruptErr = fmt.Sprintf("Ошибка синтаксиса %s: %v (сохранена резервная копия %s)", filepath.Base(path), uerr, filepath.Base(backupPath))
			if backupErr != nil {
				c.corruptErr = fmt.Sprintf("Ошибка синтаксиса %s: %v; резервная копия не сохранена: %v", filepath.Base(path), uerr, backupErr)
			} else {
				c.corruptBackup = backupPath
			}
			logf("error", "%s", c.corruptErr)
		} else if rawMeta.SchemaVersion < currentConfigSchemaVersion {
			bakPath := path + ".bak"
			if err := writeFileAtomic(bakPath, b, 0o600); err != nil {
				c.postLoadDefaults()
				c.corruptErr = fmt.Sprintf("Миграция конфигурации не сохранена: резервная копия не создана: %v", err)
				logf("error", "%s", c.corruptErr)
				return c
			}
			c.corruptBackup = bakPath
			c.SchemaVersion = currentConfigSchemaVersion
			c.postLoadDefaults()
			if err := c.save(); err != nil {
				c.corruptErr = fmt.Sprintf("Миграция конфигурации не сохранена: %v (резервная копия: %s)", err, filepath.Base(bakPath))
				logf("error", "%s", c.corruptErr)
				return c
			}
			logf("info", "Конфигурация мигрирована до схемы v%d (резервная копия: %s)", currentConfigSchemaVersion, filepath.Base(bakPath))
			return c
		}
	}
	c.postLoadDefaults()
	return c
}

func (c *Config) postLoadDefaults() {
	if c.Psiphon.FavoriteCountries == nil {
		c.Psiphon.FavoriteCountries = append([]string(nil), defaultFavoriteCountries...)
	} else {
		c.Psiphon.FavoriteCountries = normalizeFavoriteCountries(c.Psiphon.FavoriteCountries)
	}
	if c.Desync.Method == "" {
		c.Desync.Method = "auto"
	}
	if c.DNS.LocalAddr == "" {
		c.DNS.LocalAddr = "127.0.0.1:5353"
	}
	if c.General.Listen == "" {
		c.General.Listen = "127.0.0.1:1080"
	}
	if c.General.UI == "" {
		c.General.UI = "127.0.0.1:9090"
	}
	if c.General.UIMode != "browser" {
		c.General.UIMode = "gio"
	}
	if c.General.UITheme == "" {
		c.General.UITheme = "obsidian"
	}
	if c.General.LogLevel == "" {
		c.General.LogLevel = "info"
	}
	c.migrateLegacy()
	c.applyEnvOverrides()
	syncListRegistryFromConfig(c)
}

// migrateLegacy normalizes older config formats (v1.0..v1.5) without losing user rules.
func (c *Config) migrateLegacy() {
	if c.SchemaVersion < currentConfigSchemaVersion {
		c.SchemaVersion = currentConfigSchemaVersion
	}
	if strings.EqualFold(c.Routing.Default, "tunnel") {
		c.Routing.Default = obPsiphon
	} else if strings.EqualFold(c.Routing.Default, "desync") {
		c.Routing.Default = obDesync
	}
	for i := range c.Routing.Rules {
		ru := &c.Routing.Rules[i]
		if strings.EqualFold(ru.Outbound, "tunnel") {
			ru.Outbound = obPsiphon
		} else if strings.EqualFold(ru.Outbound, "desync") {
			ru.Outbound = obDesync
		}
		for j, d := range ru.Domains {
			ru.Domains[j] = sanitizeRuleToken(d)
		}
	}
	for i := range c.Lists.Custom {
		cl := &c.Lists.Custom[i]
		if cl.IntervalHours <= 0 {
			cl.IntervalHours = 12
		}
		if cl.Type == "" {
			if strings.HasPrefix(strings.ToLower(cl.URL), "local:") {
				cl.Type = "local"
			} else {
				cl.Type = "url"
			}
		}
	}
}

// applyEnvOverrides applies PSIROUTE_* environment variables over config.json values.
func (c *Config) applyEnvOverrides() {
	if v := strings.TrimSpace(os.Getenv("PSIROUTE_LISTEN")); v != "" {
		c.General.Listen = v
	}
	if v := strings.TrimSpace(os.Getenv("PSIROUTE_WEB_ADDR")); v != "" {
		c.General.UI = v
	}
	if v := strings.TrimSpace(os.Getenv("PSIROUTE_NO_WEB")); v == "1" || strings.EqualFold(v, "true") {
		c.General.NoWeb = true
	}
	if v := strings.TrimSpace(os.Getenv("PSIROUTE_AUTOCONNECT")); v != "" {
		c.General.Autoconnect = v == "1" || strings.EqualFold(v, "true")
	}
	if v := strings.TrimSpace(os.Getenv("PSIROUTE_LOG_LEVEL")); v != "" {
		c.General.LogLevel = strings.ToLower(v)
	}
	if v := strings.TrimSpace(os.Getenv("PSIROUTE_LOG_FILE")); v != "" {
		c.General.LogFile = v
	}
	if v := strings.TrimSpace(os.Getenv("PSIROUTE_PROFILE")); v != "" {
		c.General.Profile = v
	}
	if v := strings.TrimSpace(os.Getenv("PSIROUTE_MEM_LIMIT")); v != "" {
		if mb, err := strconv.Atoi(v); err == nil && mb > 0 {
			c.General.MemLimitMB = mb
		}
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("PSIROUTE_MODE"))); v != "" {
		c.applyModeOverride(v)
	}
}

func (c *Config) applyModeOverride(m string) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "tun":
		c.Tun.Enabled = true
	case "proxy":
		c.Tun.Enabled = false
	case "psiphon", "rules", "auto":
		c.Routing.Mode = strings.ToLower(strings.TrimSpace(m))
	case "split":
		c.Routing.Mode = "rules"
	}
}

type cliOverrides struct {
	Profile     string
	Mode        string
	Listen      string
	WebAddr     string
	NoWeb       bool
	Autoconnect bool
	LogLevel    string
	LogFile     string
	MemLimitMB  int
}

var activeCLIOverrides cliOverrides

func (c *Config) applyCLIOverrides(ov cliOverrides) {
	if ov.Listen != "" {
		c.General.Listen = ov.Listen
	}
	if ov.WebAddr != "" {
		c.General.UI = ov.WebAddr
	}
	if ov.NoWeb {
		c.General.NoWeb = true
	}
	if ov.Autoconnect {
		c.General.Autoconnect = true
	}
	if ov.LogLevel != "" {
		c.General.LogLevel = strings.ToLower(ov.LogLevel)
	}
	if ov.LogFile != "" {
		c.General.LogFile = ov.LogFile
	}
	if ov.MemLimitMB > 0 {
		c.General.MemLimitMB = ov.MemLimitMB
	}
	if ov.Mode != "" {
		c.applyModeOverride(ov.Mode)
	}
	if ov.Profile != "" {
		c.General.Profile = ov.Profile
		for _, p := range builtinProfiles {
			if strings.EqualFold(p.ID, ov.Profile) || strings.EqualFold(p.Name, ov.Profile) {
				c.Routing.Mode = p.Mode
				c.Routing.Default = p.Default
				if len(p.Chain) > 0 {
					c.Routing.Chain = append([]string(nil), p.Chain...)
				}
				c.Routing.Rules = cloneRules(p.Rules)
				break
			}
		}
	}
}

// ValidateConfig checks config syntax, listen addresses, rules, regexes, CIDRs, and lists.
func ValidateConfig(c *Config) []string {
	syncListRegistryFromConfig(c)
	var errs []string
	if _, _, err := net.SplitHostPort(c.General.Listen); err != nil {
		errs = append(errs, fmt.Sprintf("general.listen (%q): %v", c.General.Listen, err))
	}
	if !c.General.NoWeb {
		if _, _, err := net.SplitHostPort(c.General.UI); err != nil {
			errs = append(errs, fmt.Sprintf("general.ui (%q): %v", c.General.UI, err))
		}
	}
	if c.Tun.MTU != 0 && (c.Tun.MTU < 1280 || c.Tun.MTU > 9000) {
		errs = append(errs, fmt.Sprintf("tun.mtu (%d): должен быть в диапазоне 1280..9000", c.Tun.MTU))
	}
	for i, ru := range c.Routing.Rules {
		rLabel := fmt.Sprintf("правило #%d (%s)", i+1, ru.Name)
		for _, d := range ru.Domains {
			raw := strings.TrimPrefix(strings.TrimSpace(d), "!")
			if rest, ok := strings.CutPrefix(strings.ToLower(raw), "regexp:"); ok {
				orig := strings.TrimSpace(raw[len("regexp:"):])
				if orig == "" {
					orig = rest
				}
				if _, err := regexp.Compile(orig); err != nil {
					errs = append(errs, fmt.Sprintf("%s: некорректное регулярное выражение %q: %v", rLabel, d, err))
				}
			}
		}
		for _, cidr := range ru.CIDR {
			raw := strings.TrimPrefix(strings.TrimSpace(cidr), "!")
			if _, ok := parsePrefixCached(raw); !ok {
				errs = append(errs, fmt.Sprintf("%s: некорректный IP/CIDR %q", rLabel, cidr))
			}
		}
		for _, pr := range ru.PortRanges {
			if _, _, ok := parsePortRange(pr); !ok {
				errs = append(errs, fmt.Sprintf("%s: некорректный диапазон портов %q", rLabel, pr))
			}
		}
		for _, lst := range ru.Lists {
			if _, err := resolveListURL(lst); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", rLabel, err))
			}
		}
	}
	return errs
}

// writeFileAtomic writes b to path via a temporary file in the same directory
// and renames it atomically so a power loss never leaves a truncated file.
func writeFileAtomic(path string, b []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	if serr != nil {
		_ = os.Remove(tmp)
		return serr
	}
	if cerr != nil {
		_ = os.Remove(tmp)
		return cerr
	}
	return os.Rename(tmp, path)
}

// saveOrReport saves the config and, if the write fails, writes the reason to
// the log (audit A-10). The error is returned so API handlers can show it.
func (c *Config) saveOrReport(where string) error {
	err := c.save()
	if err != nil {
		logf("error", "Не удалось сохранить настройки (%s): %v", where, err)
	}
	return err
}

// saveErrText is the user-facing text for a failed settings write.
func saveErrText(err error) string {
	return fmt.Sprintf("Настройки не сохранены на диск: %v. Изменение действует только до перезапуска. Проверьте свободное место и права на папку с настройками Psiroute", err)
}

// saveFailed wraps a failed settings write into an error with the user-facing text.
func saveFailed(err error) error { return errors.New(saveErrText(err)) }

// saveOrFail is used by API handlers: on a failed write it answers 500 with a
// human text and returns false, so the UI never shows "saved" after a failure.
func (a *App) saveOrFail(w http.ResponseWriter, where string) bool {
	if err := a.cfg.saveOrReport(where); err != nil {
		writeErr(w, http.StatusInternalServerError, saveErrText(err))
		return false
	}
	return true
}

func (c *Config) save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

// ackCorruptError clears the damaged-config warning after the user confirmed it (A-17).
func (c *Config) ackCorruptError() {
	c.mu.Lock()
	c.corruptErr = ""
	c.corruptLogged = false
	c.mu.Unlock()
}

func (c *Config) saveLocked() error {
	// A-17: a save must not silently drop the warning. It stays visible until the
	// user confirms it; meanwhile the journal says the program runs on defaults.
	if c.corruptErr != "" && !c.corruptLogged {
		c.corruptLogged = true
		logf("warn", "Конфигурация была повреждена, работа идёт на настройках по умолчанию (%s). Предупреждение остаётся в интерфейсе, пока вы его не подтвердите", c.corruptErr)
	}
	syncListRegistryLocked(c)
	p := c.path
	if p == "" {
		return nil
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(p, b, 0o600); err != nil {
		return err
	}
	if st, err := os.Stat(p); err == nil {
		c.lastSavedMod = st.ModTime()
	} else {
		c.lastSavedMod = time.Now()
	}
	return nil
}

// values returns the flat key/value map the settings UI binds to.
func (c *Config) values() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	uiMode := c.General.UIMode
	if uiMode == "" || uiMode == "native" {
		uiMode = "gio"
	}
	return map[string]any{
		"psiphon.parallel":                 c.Psiphon.Parallel,
		"psiphon.standby":                  c.Psiphon.Standby,
		"psiphon.health_interval_secs":     c.Psiphon.HealthIntervalS,
		"psiphon.min_speed_kbps":           c.Psiphon.MinSpeedKBps,
		"psiphon.dpi":                      c.Psiphon.DPI,
		"psiphon.single_process_countries": c.Psiphon.SingleProcessCountries,
		"psiphon.preset":                   normalizePreset(c.Psiphon.Preset),
		"psiphon.mirror_url":               c.Psiphon.MirrorURL,
		"psiphon.propagation_channel_id":   c.Psiphon.PropagationChannelID,
		"psiphon.sponsor_id":               c.Psiphon.SponsorID,
		"psiphon.client_platform":          c.Psiphon.ClientPlatform,
		"desync.enabled":                   c.Desync.Enabled,
		"desync.method":                    c.Desync.Method,
		"warp.enabled":                     c.Warp.Enabled,
		"warp.socks":                       c.Warp.Socks,
		"warp.engine":                      c.Warp.Engine,
		"warp.mask":                        c.Warp.Mask,
		"warp.endpoint":                    c.Warp.Endpoint,
		"proxy.enabled":                    c.Proxy.Enabled,
		"proxy.upstream":                   c.Proxy.Upstream,
		"dns.enabled":                      c.DNS.Enabled,
		"dns.local_server":                 c.DNS.LocalServer,
		"dns.local_addr":                   c.DNS.LocalAddr,
		"udp.mode":                         c.UDP.Mode,
		"tun.enabled":                      c.Tun.Enabled,
		"tun.mtu":                          c.Tun.MTU,
		"tun.dns_hijack":                   c.Tun.DNS,
		"tun.fake_ip":                      c.Tun.FakeIP,
		"tun.ipv6":                         c.Tun.IPv6,
		"tun.exclude_apps":                 strings.Join(c.Tun.Exclude, ", "),
		"routing.failover":                 c.Routing.Failover,
		"routing.learn":                    c.Routing.Learn,
		"routing.bypass_lan":               c.Routing.BypassLAN,
		"routing.block_quic":               c.Routing.BlockQUIC,
		"routing.kill_switch":              c.Routing.KillSwitch,
		"routing.kill_switch_mode":         normalizeKillSwitchMode(c.Routing.KillSwitchMode, c.Routing.KillSwitch),
		"clean_chain.enabled":              c.CleanChain.Enabled,
		"clean_chain.auto_chain":           c.CleanChain.AutoChain,
		"routing.block_stun":               c.Routing.BlockSTUN,
		"general.watch_config":             c.General.WatchConfig,
		"general.system_proxy":             c.General.SystemProxy,
		"general.ui_mode":                  uiMode,
	}
}

// setKey updates one dotted key. It returns true when the change requires the
// Psiphon engine to restart to take effect.
func (c *Config) setKey(key string, v any) (restart bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch key {
	case "psiphon.parallel":
		c.Psiphon.Parallel = toInt(v)
		restart = true
	case "psiphon.standby":
		c.Psiphon.Standby = toBool(v)
		restart = true
	case "psiphon.health_interval_secs":
		c.Psiphon.HealthIntervalS = toInt(v)
	case "psiphon.min_speed_kbps":
		c.Psiphon.MinSpeedKBps = toInt(v)
	case "psiphon.dpi":
		c.Psiphon.DPI = toStr(v)
		restart = true
	case "psiphon.single_process_countries":
		c.Psiphon.SingleProcessCountries = toBool(v)
	case "psiphon.preset":
		c.Psiphon.Preset = normalizePreset(toStr(v))
		restart = true
	case "psiphon.mirror_url":
		if norm, err := validateUserMirrorURL(toStr(v)); err == nil {
			c.Psiphon.MirrorURL = norm
		}
	case "psiphon.propagation_channel_id":
		s := strings.ToUpper(strings.TrimSpace(toStr(v)))
		if s == "" || validateHexID16(s) == nil {
			c.Psiphon.PropagationChannelID = s
			restart = true
		}
	case "psiphon.sponsor_id":
		s := strings.ToUpper(strings.TrimSpace(toStr(v)))
		if s == "" || validateHexID16(s) == nil {
			c.Psiphon.SponsorID = s
			restart = true
		}
	case "psiphon.client_platform":
		c.Psiphon.ClientPlatform = strings.TrimSpace(toStr(v))
		restart = true
	case "psiphon.blocked_countries":
		switch arr := v.(type) {
		case []string:
			c.Psiphon.BlockedCountries = normalizeFavoriteCountries(arr)
		case []any:
			tmp := make([]string, 0, len(arr))
			for _, it := range arr {
				if s, ok := it.(string); ok {
					tmp = append(tmp, s)
				}
			}
			c.Psiphon.BlockedCountries = normalizeFavoriteCountries(tmp)
		}
	case "psiphon.favorite_countries":
		switch arr := v.(type) {
		case []string:
			c.Psiphon.FavoriteCountries = normalizeFavoriteCountries(arr)
		case []any:
			tmp := make([]string, 0, len(arr))
			for _, it := range arr {
				if s, ok := it.(string); ok {
					tmp = append(tmp, s)
				}
			}
			c.Psiphon.FavoriteCountries = normalizeFavoriteCountries(tmp)
		}
	case "desync.enabled":
		c.Desync.Enabled = toBool(v)
	case "desync.method":
		c.Desync.Method = "auto"
		if m := toStr(v); obfsByID(m) != nil {
			c.Desync.Method = m
		}
	case "warp.enabled":
		c.Warp.Enabled = toBool(v)
		if c.Warp.Enabled && !slices.Contains(c.Psiphon.Strategies, "via-warp") {
			// Keep via-warp as automatic fallback AFTER direct-dpi / conduit / meek / tls
			c.Psiphon.Strategies = append(c.Psiphon.Strategies, "via-warp")
		}
		restart = true
	case "warp.engine":
		c.Warp.Engine = toStr(v)
		restart = true
	case "warp.mask":
		c.Warp.Mask = toStr(v)
	case "warp.endpoint":
		c.Warp.Endpoint = strings.TrimSpace(toStr(v))
	case "warp.socks":
		c.Warp.Socks = toStr(v)
		restart = true
	case "proxy.enabled":
		c.Proxy.Enabled = toBool(v)
		restart = true
	case "proxy.upstream":
		c.Proxy.Upstream = toStr(v)
		restart = true
	case "dns.enabled":
		c.DNS.Enabled = toBool(v)
	case "dns.local_server":
		c.DNS.LocalServer = toBool(v)
	case "dns.local_addr":
		if s := strings.TrimSpace(toStr(v)); s != "" {
			c.DNS.LocalAddr = s
		}
	case "udp.mode":
		switch m := toStr(v); m {
		case "route", "direct", "psiphon", "off":
			c.UDP.Mode = m
		}
	case "tun.enabled":
		c.Tun.Enabled = toBool(v)
	case "tun.mtu":
		if n := toInt(v); n >= 1280 && n <= 9000 {
			c.Tun.MTU = n
		}
	case "tun.dns_hijack":
		c.Tun.DNS = toBool(v)
	case "tun.fake_ip":
		c.Tun.FakeIP = toBool(v)
	case "tun.ipv6":
		c.Tun.IPv6 = toBool(v)
	case "tun.exclude_apps":
		c.Tun.Exclude = tunSplitApps(toStr(v))
	case "routing.failover":
		c.Routing.Failover = toBool(v)
	case "routing.learn":
		c.Routing.Learn = toBool(v)
	case "routing.bypass_lan":
		c.Routing.BypassLAN = toBool(v)
	case "routing.block_quic":
		c.Routing.BlockQUIC = toBool(v)
	case "routing.kill_switch":
		c.Routing.KillSwitch = toBool(v)
	case "routing.kill_switch_mode":
		m := normalizeKillSwitchMode(toStr(v), false)
		c.Routing.KillSwitchMode = m
		c.Routing.KillSwitch = m != wfpModeOff
	case "clean_chain.enabled":
		c.CleanChain.Enabled = toBool(v)
	case "clean_chain.auto_chain":
		c.CleanChain.AutoChain = toBool(v)
	case "routing.block_stun":
		c.Routing.BlockSTUN = toBool(v)
	case "general.watch_config":
		c.General.WatchConfig = toBool(v)
	case "general.system_proxy":
		c.General.SystemProxy = toBool(v)
	case "general.ui_mode":
		switch m := toStr(v); m {
		case "gio", "native", "browser":
			if m == "native" {
				m = "gio"
			}
			c.General.UIMode = m
		default:
			c.General.UIMode = "gio"
		}
	case "general.ui_theme":
		switch m := strings.ToLower(strings.TrimSpace(toStr(v))); m {
		case "cyber", "amber", "soviet":
			c.General.UITheme = "cyber"
		default:
			c.General.UITheme = "obsidian"
		}
	}
	return restart
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

func toBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	}
	return false
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// isCountryBlocked reports whether 2-letter country code cc is in the user blacklist.
func (c *Config) isCountryBlocked(cc string) bool {
	if c == nil {
		return false
	}
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.Psiphon.BlockedCountries, cc)
}
