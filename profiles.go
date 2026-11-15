package main

// Profiles (1.1): a portable set of routing settings — mode, default route,
// auto chain and rules. A profile can be exported to a file or a short code
// (psiroute://profile/...), shared, previewed and imported back, either
// replacing the current rules or adding to them. The previous rules are
// saved before every import so the last import can be undone.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	profileFormat     = 1
	profileCodeScheme = "psiroute://profile/"
	profileMaxRules   = 500
	profileMaxBytes   = 1 << 20
	profileMaxName    = 80
)

// Profile is the exported routing settings. Fields absent in a profile keep
// the user's current values on import.
type Profile struct {
	Format  int      `json:"format"`
	Name    string   `json:"name"`
	About   string   `json:"about,omitempty"`
	Mode    string   `json:"mode,omitempty"`
	Default string   `json:"default,omitempty"`
	Chain   []string `json:"auto_chain,omitempty"`
	Rules   []Rule   `json:"rules"`
}

// builtinProfile is a ready-made profile shipped with the program.
type builtinProfile struct {
	ID string
	Profile
}

var telegramDomains = []string{"telegram.org", "t.me", "telegram.me", "tdesktop.com", "telesco.pe", "cdn-telegram.org"}

var builtinProfiles = []builtinProfile{
	{ID: "discord-youtube", Profile: Profile{
		Format: profileFormat, Name: "Discord + YouTube через Psiphon",
		About: "Discord и YouTube идут через Psiphon, все остальные сайты — напрямую.",
		Mode:  "rules", Default: obDirect,
		Rules: []Rule{
			{Name: "YouTube", Outbound: obPsiphon, Lists: []string{"youtube"},
				Domains: []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com"}},
			{Name: "Discord", Outbound: obPsiphon, Lists: []string{"discord"},
				Domains: []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"}},
		},
	}},
	{ID: "gaming-discord-youtube", Profile: Profile{
		Format: profileFormat, Name: "Игры + Discord (голос) + YouTube",
		About: "Блокирует QUIC (UDP 443) для YouTube (чтобы работал TCP с DPI-обходом), ведёт голос Discord (UDP 50000-65535) через Psiphon, а игры и российские сайты — напрямую.",
		Mode:  "rules", Default: obDirect,
		Rules: []Rule{
			{Name: "YouTube: блок QUIC (переход на TCP)", Outbound: obBlock, Proto: "udp", Ports: []int{443}, Lists: []string{"youtube"},
				Domains: []string{"youtube.com", "googlevideo.com", "ytimg.com"}},
			{Name: "YouTube (DPI / Psiphon)", Outbound: obAuto, Lists: []string{"youtube"},
				Domains: []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com"}},
			{Name: "Discord и голос", Outbound: obPsiphon, Lists: []string{"discord"}, PortRanges: []string{"443", "50000-65535"},
				Domains: []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"}, Apps: []string{"Discord.exe"}},
			{Name: "Игры и лаунчеры напрямую", Outbound: obDirect, Always: true,
				Apps: []string{"steam.exe", "cs2.exe", "dota2.exe", "EpicGamesLauncher.exe"}},
		},
	}},
	{ID: "except-ru", Profile: Profile{
		Format: profileFormat, Name: "Всё, кроме российских сайтов",
		About: "Российские сайты (.ru, .рф, .su и крупные сервисы на других доменах) идут напрямую, всё остальное — через Psiphon.",
		Mode:  "rules", Default: obPsiphon,
		Rules: []Rule{
			{Name: "Российские домены", Outbound: obDirect, Domains: []string{"ru", "xn--p1ai", "su"}},
			{Name: "Российские сервисы", Outbound: obDirect,
				Domains: []string{"vk.com", "vk.me", "userapi.com", "vkuser.net", "vk-cdn.net", "mycdn.me", "yandex.net", "yastatic.net", "yandex.com", "mradx.net", "avito.st", "wbstatic.net"}},
		},
	}},
	{ID: "blocked-only", Profile: Profile{
		Format: profileFormat, Name: "Только заблокированное через Psiphon",
		About: "Сайты из списков блокировок и Telegram идут через Psiphon, остальное — напрямую. Списки обновляются сами.",
		Mode:  "rules", Default: obDirect,
		Rules: []Rule{
			{Name: "Заблокированные сайты", Outbound: obPsiphon, Lists: []string{"ru-blocked", "antifilter-community"}},
			{Name: "Telegram", Outbound: obPsiphon, Lists: []string{"telegram-ip"}, Domains: telegramDomains},
		},
	}},
	{ID: "telegram", Profile: Profile{
		Format: profileFormat, Name: "Только Telegram",
		About: "Через Psiphon идёт только Telegram, всё остальное — напрямую.",
		Mode:  "rules", Default: obDirect,
		Rules: []Rule{
			{Name: "Telegram", Outbound: obPsiphon, Lists: []string{"telegram-ip"}, Domains: telegramDomains},
		},
	}},
}

func builtinByID(id string) (Profile, bool) {
	for _, b := range builtinProfiles {
		if b.ID == id {
			p := b.Profile
			p.Chain = slices.Clone(p.Chain)
			p.Rules = cloneRules(p.Rules)
			return p, true
		}
	}
	return Profile{}, false
}

// builtinProfileList is what the UI shows in the "ready profiles" list.
func builtinProfileList() []map[string]any {
	out := make([]map[string]any, 0, len(builtinProfiles))
	for _, b := range builtinProfiles {
		out = append(out, map[string]any{"id": b.ID, "name": b.Name, "about": b.About, "rules": len(b.Rules)})
	}
	return out
}

func cloneRules(in []Rule) []Rule {
	out := make([]Rule, 0, len(in))
	for _, r := range in {
		r.Domains = slices.Clone(r.Domains)
		r.Keywords = slices.Clone(r.Keywords)
		r.CIDR = slices.Clone(r.CIDR)
		r.Ports = slices.Clone(r.Ports)
		r.PortRanges = slices.Clone(r.PortRanges)
		r.Lists = slices.Clone(r.Lists)
		r.Apps = slices.Clone(r.Apps)
		out = append(out, r)
	}
	return out
}

// currentProfile exports the current routing settings.
func currentProfile(c *Config, name string) Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := Profile{
		Format:  profileFormat,
		Name:    strings.TrimSpace(name),
		Mode:    c.Routing.Mode,
		Default: c.Routing.Default,
		Chain:   slices.Clone(c.Routing.Chain),
		Rules:   cloneRules(c.Routing.Rules),
	}
	if p.Name == "" {
		p.Name = "Мой профиль"
	}
	return p
}

// encodeProfileCode packs a profile into a short text code that can be sent
// in a messenger: psiroute://profile/<base64url(gzip(json))>.
func encodeProfileCode(p Profile) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(b); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return profileCodeScheme + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

var errBadProfileCode = errors.New("код профиля повреждён или скопирован не полностью")

// decodeProfile accepts a profile code, profile JSON or a whole
// psiroute.json (its routing section is taken) and validates the result.
func decodeProfile(data string) (Profile, error) {
	var p Profile
	if len(data) > 2*profileMaxBytes {
		return p, errors.New("профиль слишком большой")
	}
	s := strings.TrimSpace(strings.TrimPrefix(data, "\ufeff"))
	if s == "" {
		return p, errors.New("вставьте код профиля или выберите файл")
	}
	var raw []byte
	if strings.HasPrefix(s, "{") {
		raw = []byte(s)
	} else {
		code := strings.TrimPrefix(s, profileCodeScheme)
		code = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, code)
		code = strings.TrimRight(code, "=")
		z, err := base64.RawURLEncoding.DecodeString(code)
		if err != nil {
			z, err = base64.RawStdEncoding.DecodeString(code)
		}
		if err != nil || len(z) == 0 {
			return p, errBadProfileCode
		}
		zr, err := gzip.NewReader(bytes.NewReader(z))
		if err != nil {
			return p, errBadProfileCode
		}
		defer zr.Close()
		raw, err = io.ReadAll(io.LimitReader(zr, profileMaxBytes+1))
		if err != nil {
			return p, errBadProfileCode
		}
	}
	if len(raw) > profileMaxBytes {
		return p, errors.New("профиль слишком большой")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, errors.New("в профиле ошибка: " + err.Error())
	}
	if p.Rules == nil && p.Format == 0 {
		// not a profile: maybe a whole psiroute.json from another computer
		var cf struct {
			Routing struct {
				Mode    string   `json:"mode"`
				Default string   `json:"default"`
				Chain   []string `json:"auto_chain"`
				Rules   []Rule   `json:"rules"`
			} `json:"routing"`
		}
		if json.Unmarshal(raw, &cf) == nil && cf.Routing.Rules != nil {
			p = Profile{Format: profileFormat, Name: "Правила из psiroute.json", Mode: cf.Routing.Mode,
				Default: cf.Routing.Default, Chain: cf.Routing.Chain, Rules: cf.Routing.Rules}
		} else {
			return p, errors.New("это не профиль Psiroute: в нём нет правил")
		}
	}
	if err := validateProfile(&p); err != nil {
		return p, err
	}
	return p, nil
}

// validOutbound: the routes a rule may use (see ruleOutbounds).
func validOutbound(ob string) bool {
	switch ob {
	case obPsiphon, obDirect, obDesync, obWarp, obProxy, obBlock, obAuto:
		return true
	}
	return isCountryOb(ob)
}

// checkRule validates one rule the same way the rule editor does.
func checkRule(ru Rule) error {
	name := ru.Name
	if name == "" {
		name = "без названия"
	}
	if ru.Outbound == "" {
		return errors.New("у правила «" + name + "» не указан маршрут")
	}
	if strings.HasPrefix(ru.Outbound, obPsiphon+":") && !isCountryOb(ru.Outbound) {
		return errors.New("у правила «" + name + "» неверная страна: нужен код из двух букв, например psiphon:DE")
	}
	if !validOutbound(ru.Outbound) {
		return errors.New("у правила «" + name + "» неизвестный маршрут «" + ru.Outbound + "»")
	}
	switch strings.ToLower(strings.TrimSpace(ru.Proto)) {
	case "", "any", "all", "tcp", "udp":
	default:
		return errors.New("у правила «" + name + "» неверный протокол «" + ru.Proto + "» (допустимы tcp, udp или пусто)")
	}
	for _, pr := range ru.PortRanges {
		if strings.TrimSpace(pr) != "" {
			if _, _, ok := parsePortRange(pr); !ok {
				return errors.New("у правила «" + name + "» неверный диапазон портов «" + pr + "»")
			}
		}
	}
	for _, l := range ru.Lists {
		if _, err := resolveListURL(l); err != nil {
			return errors.New("правило «" + name + "»: " + err.Error())
		}
	}
	return nil
}

// validateProfile checks a profile from an untrusted source. Lists may only
// come from the trusted hosts (resolveListURL), so a shared profile cannot
// pull a list from an arbitrary server.
func validateProfile(p *Profile) error {
	if p.Format == 0 {
		p.Format = profileFormat // written by hand
	}
	if p.Format > profileFormat {
		return fmt.Errorf("профиль создан более новой версией Psiroute (формат %d) — обновите программу", p.Format)
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "Без названия"
	}
	if r := []rune(p.Name); len(r) > profileMaxName {
		p.Name = string(r[:profileMaxName])
	}
	switch p.Mode {
	case "", "psiphon", "rules", "auto":
	default:
		return fmt.Errorf("неизвестный режим «%s»", p.Mode)
	}
	if p.Default != "" && !validOutbound(p.Default) {
		return fmt.Errorf("неизвестный маршрут по умолчанию «%s»", p.Default)
	}
	for _, ob := range p.Chain {
		if !validOutbound(ob) || ob == obAuto {
			return fmt.Errorf("неверный маршрут «%s» в цепочке автоподбора", ob)
		}
	}
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	if len(p.Rules) > profileMaxRules {
		return fmt.Errorf("в профиле слишком много правил: %d (не больше %d)", len(p.Rules), profileMaxRules)
	}
	for _, ru := range p.Rules {
		if err := checkRule(ru); err != nil {
			return err
		}
	}
	return nil
}

// profileResult describes what an import changed.
type profileResult struct {
	Name     string `json:"name"`
	Added    int    `json:"added"`
	Replaced int    `json:"replaced"`
	Mode     string `json:"mode"`
	Merged   bool   `json:"merged"`
}

// applyProfile replaces the routing settings with the profile, or with
// merge adds its rules to the current ones (a rule with the same name is
// replaced, the mode and the default route stay).
func applyProfile(c *Config, p Profile, merge bool) profileResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := profileResult{Name: p.Name, Merged: merge}
	if !merge {
		c.Routing.Rules = cloneRules(p.Rules)
		res.Added = len(p.Rules)
		if p.Mode != "" {
			c.Routing.Mode = p.Mode
		}
		if p.Default != "" {
			c.Routing.Default = p.Default
		}
		if len(p.Chain) > 0 {
			c.Routing.Chain = slices.Clone(p.Chain)
		}
		res.Mode = c.Routing.Mode
		return res
	}
	rules := cloneRules(c.Routing.Rules)
	for _, r := range cloneRules(p.Rules) {
		i := -1
		if r.Name != "" {
			i = slices.IndexFunc(rules, func(x Rule) bool { return strings.EqualFold(x.Name, r.Name) })
		}
		if i >= 0 {
			rules[i] = r
			res.Replaced++
		} else {
			rules = append(rules, r)
			res.Added++
		}
	}
	c.Routing.Rules = rules
	res.Mode = c.Routing.Mode
	return res
}

// profileSummary is a one-line description for the import preview.
func profileSummary(p Profile) string {
	modes := map[string]string{"psiphon": "весь трафик через Psiphon", "rules": "по правилам", "auto": "автоподбор"}
	s := fmt.Sprintf("«%s»: правил — %d", p.Name, len(p.Rules))
	if m, ok := modes[p.Mode]; ok {
		s += ", режим — " + m
	}
	if p.Default != "" {
		s += ", остальное — " + p.Default
	}
	return s
}

// ---------- undo of the last import ----------

func (a *App) profileUndoPath() string {
	return filepath.Join(filepath.Dir(a.cfgPath), "psiroute-undo-profile.json")
}

func (a *App) hasProfileUndo() bool {
	_, err := os.Stat(a.profileUndoPath())
	return err == nil
}

func (a *App) saveProfileUndo() error {
	b, err := json.MarshalIndent(currentProfile(a.cfg, "До импорта"), "", "  ")
	if err != nil {
		return err
	}
	path := a.profileUndoPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// undoProfile restores the rules saved before the last import.
func (a *App) undoProfile() (profileResult, error) {
	b, err := os.ReadFile(a.profileUndoPath())
	if err != nil {
		return profileResult{}, errors.New("нечего отменять")
	}
	p, err := decodeProfile(string(b))
	if err != nil {
		return profileResult{}, err
	}
	res := applyProfile(a.cfg, p, false)
	_ = a.cfg.save()
	_ = os.Remove(a.profileUndoPath())
	a.onRulesChanged()
	a.lists.Refresh()
	logf("info", "Импорт профиля отменён: правила возвращены (%d)", res.Added)
	return res, nil
}

// ---------- API ----------

// profileRequest is the body of profiles/preview and profiles/import:
// either a built-in profile id or pasted data (code, JSON, file contents).
type profileRequest struct {
	Builtin string `json:"builtin"`
	Data    string `json:"data"`
	Merge   bool   `json:"merge"`
}

func readProfileRequest(r *http.Request) (profileRequest, Profile, error) {
	var req profileRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		return req, Profile{}, errors.New("ошибка в данных запроса")
	}
	if req.Builtin != "" {
		p, ok := builtinByID(req.Builtin)
		if !ok {
			return req, p, errors.New("нет такого готового профиля")
		}
		return req, p, nil
	}
	p, err := decodeProfile(req.Data)
	return req, p, err
}

// profilesAPI handles /api/profiles*. It returns false for other paths.
func (a *App) profilesAPI(w http.ResponseWriter, r *http.Request, p string) bool {
	post := r.Method == http.MethodPost
	switch {
	case p == "profiles" && !post:
		writeJSON(w, map[string]any{"builtin": builtinProfileList(), "undo": a.hasProfileUndo()})
	case p == "profiles/export":
		var b struct {
			Name string `json:"name"`
		}
		if post {
			_ = json.NewDecoder(r.Body).Decode(&b)
		} else {
			b.Name = r.URL.Query().Get("name")
		}
		prof := currentProfile(a.cfg, b.Name)
		code, err := encodeProfileCode(prof)
		if err != nil {
			writeErr(w, 500, "профиль не сохранён: "+err.Error())
			return true
		}
		writeJSON(w, map[string]any{"ok": true, "profile": prof, "code": code})
	case p == "profiles/preview" && post:
		_, prof, err := readProfileRequest(r)
		if err != nil {
			writeErr(w, 400, err.Error())
			return true
		}
		writeJSON(w, map[string]any{"ok": true, "profile": prof, "summary": profileSummary(prof)})
	case p == "profiles/import" && post:
		req, prof, err := readProfileRequest(r)
		if err != nil {
			writeErr(w, 400, err.Error())
			return true
		}
		if err := a.saveProfileUndo(); err != nil {
			logf("warn", "Профиль: не удалось сохранить копию правил для отмены: %v", err)
		}
		res := applyProfile(a.cfg, prof, req.Merge)
		_ = a.cfg.save()
		a.onRulesChanged()
		a.lists.Refresh()
		if req.Merge {
			logf("info", "Профиль «%s» добавлен к правилам: новых %d, заменено %d", res.Name, res.Added, res.Replaced)
		} else {
			logf("info", "Профиль «%s» применён: правил %d, режим %s", res.Name, res.Added, res.Mode)
		}
		writeJSON(w, map[string]any{"ok": true, "result": res, "undo": a.hasProfileUndo()})
	case p == "profiles/undo" && post:
		res, err := a.undoProfile()
		if err != nil {
			writeErr(w, 400, err.Error())
			return true
		}
		writeJSON(w, map[string]any{"ok": true, "result": res, "undo": false})
	default:
		return false
	}
	return true
}
