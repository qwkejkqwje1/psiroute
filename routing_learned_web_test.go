package main

// Section-2 autotests from the builder's 1.0.3 test list (forwarded by Amy
// 08.11.2026): routing corners, learned TTL/eviction, config robustness,
// stats caps, log ring, and the 1.0.3 web fixes (403, /api/rules outbounds,
// /api/route fields, empty-outbound rejection).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- routing: matchRule ----------

func TestMatchRuleDomains(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Rules = []Rule{{Name: "vk", Domains: []string{"vk.com"}, Outbound: obPsiphon}}
	})
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"vk.com", true}, {"m.vk.com", true}, {"deep.m.vk.com", true},
		{"notvk.com", false}, {"badvk.com", false}, {"vk.com.evil.test", false},
		{"VK.COM.", true}, // case + trailing dot are normalized
	} {
		ob, _ := a.router.matchRule(tc.host, 443)
		if (ob != "") != tc.want {
			t.Errorf("matchRule(%q) = %q, want match=%v", tc.host, ob, tc.want)
		}
	}
}

func TestMatchRuleKeywordCIDRPortFirstWins(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Rules = []Rule{
			{Name: "икс-порт", Domains: []string{"x.com"}, Ports: []int{443}, Outbound: obWarp},
			{Name: "икс", Domains: []string{"x.com"}, Outbound: obDirect},
			{Name: "видео", Keywords: []string{"ViDeO"}, Outbound: obProxy},
			{Name: "телега", CIDR: []string{"91.108.0.0/16"}, Outbound: obPsiphon},
			{Name: "почта", Ports: []int{25}, Outbound: obDirect},
		}
	})
	check := func(host string, port int, want string) {
		t.Helper()
		if ob, _ := a.router.matchRule(host, port); ob != want {
			t.Errorf("matchRule(%q,%d) = %q, want %q", host, port, ob, want)
		}
	}
	check("x.com", 443, obWarp)          // ports AND domains; first rule wins
	check("x.com", 80, obDirect)         // port misses the first rule, domain rule applies
	check("my-VIDEO.test", 443, obProxy) // keyword is case-insensitive
	check("91.108.4.4", 443, obPsiphon)  // inside the CIDR
	check("91.109.4.4", 443, "")         // outside the CIDR
	check("anything.test", 25, obDirect) // a ports-only rule matches by port
	check("anything.test", 26, "")
}

// ---------- learned: TTL and eviction ----------

func TestLearnedTTLExpiry(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) { c.Routing.Learn = true })
	r := a.router
	r.mu.Lock()
	r.seen["old.test"] = &learned{Host: "old.test", Outbound: obDirect,
		Updated: time.Now().Add(-learnedTTL - time.Hour).Unix()}
	r.seen["fresh.test"] = &learned{Host: "fresh.test", Outbound: obWarp, Updated: time.Now().Unix()}
	r.mu.Unlock()
	if got := r.learnedFor("old.test"); got != "" {
		t.Fatalf("stale entry must expire, got %q", got)
	}
	r.mu.Lock()
	_, still := r.seen["old.test"]
	r.mu.Unlock()
	if still {
		t.Fatal("expired entry must be deleted")
	}
	if got := r.learnedFor("fresh.test"); got != obWarp {
		t.Fatalf("fresh entry = %q", got)
	}
}

func TestLearnedEvictOldest(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) { c.Routing.Learn = true })
	r := a.router
	base := time.Now().Add(-time.Hour).Unix()
	r.mu.Lock()
	for i := 0; i < learnedMax; i++ {
		h := fmt.Sprintf("h%04d.test", i)
		r.seen[h] = &learned{Host: h, Outbound: obDirect, Updated: base + int64(i)}
	}
	r.mu.Unlock()
	r.remember("new.test", obWarp, "r", true)
	r.mu.Lock()
	n := len(r.seen)
	_, hasOldest := r.seen["h0000.test"]
	_, hasNew := r.seen["new.test"]
	_, hasSecond := r.seen["h0001.test"]
	r.mu.Unlock()
	if n != learnedMax || hasOldest || !hasNew || !hasSecond {
		t.Fatalf("evict: n=%d oldest=%v new=%v second=%v (cap %d)", n, hasOldest, hasNew, hasSecond, learnedMax)
	}
}

// ---------- host key cleaning ----------

func TestCleanHostKeyAndHost(t *testing.T) {
	for in, want := range map[string]string{
		"EXAMPLE.com.":   "example.com",
		"  spaced.test ": "spaced.test",
		"[2001:DB8::1]":  "2001:db8::1",
		"plain.test":     "plain.test",
	} {
		if got := cleanHostKey(in); got != want {
			t.Errorf("cleanHostKey(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"EXAMPLE.com:443": "example.com",
		"[::1]:443":       "::1",
		"host.test":       "host.test",
		"10.0.0.1:1080":   "10.0.0.1",
	} {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------- config robustness ----------

func TestLoadConfigBrokenUnknownRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")

	// Broken JSON falls back to defaults without crashing, records corruptError & backup,
	// while loadConfigStrict returns an explicit syntax error (Баг №3).
	_ = os.WriteFile(p, []byte("{broken json"), 0o600)
	if _, strictErr := loadConfigStrict(p); strictErr == nil {
		t.Fatal("loadConfigStrict must fail on invalid JSON")
	}
	c := loadConfig(p)
	if c.General.Listen != "127.0.0.1:1080" || c.General.UI != "127.0.0.1:9090" {
		t.Fatalf("broken config: listen=%q ui=%q", c.General.Listen, c.General.UI)
	}
	if c.corruptError() == "" || c.corruptBackupPath() == "" {
		t.Fatal("expected corruptError and corruptBackupPath to be recorded on broken JSON")
	}
	// Unknown fields are ignored, known ones apply.
	_ = os.WriteFile(p, []byte(`{"general":{"listen":"127.0.0.1:7777"},"brand_new_field":{"x":1}}`), 0o600)
	c2 := loadConfig(p)
	if c2.General.Listen != "127.0.0.1:7777" {
		t.Fatalf("known field lost: %q", c2.General.Listen)
	}
	// Save + reload round-trip preserves the values view.
	c2.path = p
	if err := c2.save(); err != nil {
		t.Fatal(err)
	}
	c3 := loadConfig(p)
	if fmt.Sprint(c3.values()) != fmt.Sprint(c2.values()) {
		t.Fatalf("roundtrip mismatch:\n%v\n%v", c2.values(), c3.values())
	}
}

// ---------- stats caps ----------

func TestStatsTickCapAndLiveOrder(t *testing.T) {
	s := newStats("")
	ids := []int64{}
	for i := 0; i < 3; i++ {
		tr := s.open("app", fmt.Sprintf("h%d.test", i), "", 443, obDirect, "")
		s.add(tr, int64(10*(i+1)), int64(i+1))
		ids = append(ids, tr.id)
	}
	for i := 0; i < 130; i++ {
		s.tick()
	}
	snap := s.snapshot()
	hist, _ := snap["speed"].(map[string]any)["history"].([][2]int64)
	if len(hist) > 120 {
		t.Fatalf("speed history = %d points, cap is 120", len(hist))
	}
	live, _ := snap["live"].([]map[string]any)
	if len(live) != 3 {
		t.Fatalf("live = %d", len(live))
	}
	for i := 1; i < len(live); i++ {
		if live[i-1]["id"].(int64) <= live[i]["id"].(int64) {
			t.Fatalf("live not sorted by id desc: %v", live)
		}
	}
	tot := snap["total"].(map[string]any)
	if tot["up"] != int64(60) || tot["down"] != int64(6) {
		t.Fatalf("totals = %v, want up=60 down=6", tot)
	}
}

func TestStatsHistoryCap30(t *testing.T) {
	s := newStats("")
	s.mu.Lock()
	for i := 0; i < 35; i++ {
		day := fmt.Sprintf("2026-01-%02d", i+1)
		s.days[day] = &[2]int64{int64(i), int64(i)}
	}
	s.mu.Unlock()
	h := s.history()
	if len(h) != 30 {
		t.Fatalf("history = %d days, cap is 30", len(h))
	}
	if h[0]["date"] != "2026-01-35" || h[29]["date"] != "2026-01-06" {
		t.Fatalf("history must be newest-first trimmed: %v ... %v", h[0]["date"], h[29]["date"])
	}
}

// ---------- log ring ----------

func TestLogRing800(t *testing.T) {
	l := &Logger{max: 800}
	for i := 0; i < 1000; i++ {
		l.add("info", fmt.Sprintf("m%d", i))
	}
	snap := l.snapshot()
	if len(snap) != 800 {
		t.Fatalf("ring = %d lines, want 800", len(snap))
	}
	if snap[0].Msg != "m200" || snap[799].Msg != "m999" {
		t.Fatalf("ring order wrong: first=%q last=%q", snap[0].Msg, snap[799].Msg)
	}
}

// ---------- web: 1.0.3 fixes ----------

func apiCall(t *testing.T, a *App, method, path string, token bool, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = "127.0.0.1" // httptest defaults to example.com, which the Host guard rejects
	req.RemoteAddr = "127.0.0.1:5555"
	if token {
		req.Header.Set("X-Psiroute", a.token)
	}
	rec := httptest.NewRecorder()
	a.routes().ServeHTTP(rec, req)
	return rec
}

func TestWebTokenForbidden403(t *testing.T) {
	a := testApp(t)
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"no header", ""},
		{"wrong token", "deadbeef"},
	} {
		req := httptest.NewRequest("GET", "/api/state", nil)
		req.Host = "127.0.0.1"
		req.RemoteAddr = "127.0.0.1:5555"
		if tc.token != "" {
			req.Header.Set("X-Psiroute", tc.token)
		}
		rec := httptest.NewRecorder()
		a.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: code = %d, want 403", tc.name, rec.Code)
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m["ok"] != false {
			t.Fatalf("%s: body = %q, want JSON {ok:false}", tc.name, rec.Body.String())
		}
	}
}

func TestWebRulesOutbounds(t *testing.T) {
	a := testApp(t)
	rec := apiCall(t, a, "GET", "/api/rules", true, "")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	obs, _ := m["outbounds"].([]any)
	joined := fmt.Sprint(obs)
	for _, want := range []string{"psiphon", "direct", "direct-dpi", "warp", "proxy", "block", "auto"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("outbounds %v misses %q", obs, want)
		}
	}
}

func TestWebRouteFields(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obPsiphon
		c.Routing.Learn = true
	})
	a.router.remember("vk.com", obDirect, "r", true)
	rec := apiCall(t, a, "GET", "/api/route?host=vk.com&port=443", true, "")
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["host"] != "vk.com" || m["port"] != float64(443) {
		t.Fatalf("route fields: %v (host/port must be present, no undefined)", m)
	}
	chain, _ := m["chain"].([]any)
	if len(chain) == 0 {
		t.Fatalf("chain must not be empty: %v", m)
	}
	if _, ok := m["learned"]; !ok {
		t.Fatalf("learned field missing: %v", m)
	}
}

func TestWebRulesEmptyOutboundRejected(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Rules = []Rule{{Name: "keep", Domains: []string{"keep.test"}, Outbound: obDirect}}
	})
	body := `{"rules":[{"name":"bad","domains":["bad.test"],"outbound":""}]}`
	rec := apiCall(t, a, "POST", "/api/rules", true, body)
	if rec.Code != 400 {
		t.Fatalf("empty outbound save: code = %d, want 400", rec.Code)
	}
	a.cfg.mu.Lock()
	n := len(a.cfg.Routing.Rules)
	name := ""
	if n > 0 {
		name = a.cfg.Routing.Rules[0].Name
	}
	a.cfg.mu.Unlock()
	if n != 1 || name != "keep" {
		t.Fatalf("rules changed after rejected save: %v", a.cfg.Routing.Rules)
	}
}


func TestServiceCompanionDomainsAndFavoritesAndTrafficStats(t *testing.T) {
	a := testApp(t)
	// 1. Companion domains & URL normalization: rule with https://www.youtube.com/watch?v=1 matches googlevideo.com and ytimg.com
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "psiphon"
		c.Routing.Rules = []Rule{
			{Name: "YouTube Direct Test", Domains: []string{"https://www.youtube.com/watch?v=123"}, Outbound: obDirect},
		}
	})
	for _, h := range []string{"youtube.com", "www.youtube.com", "rr2---sn-abc.googlevideo.com", "i.ytimg.com", "youtu.be"} {
		order, rule := a.router.plan(h, 443)
		if len(order) == 0 || order[0] != obDirect || rule != "YouTube Direct Test" {
			t.Fatalf("companion domain match failed for %s: order=%v rule=%q", h, order, rule)
		}
	}

	// 2. Favorite countries API (POST /api/psi/favorites)
	recFav := apiCall(t, a, "POST", "/api/psi/favorites", true, `{"country":"JP"}`)
	if recFav.Code != http.StatusOK || !strings.Contains(recFav.Body.String(), `"JP"`) {
		t.Fatalf("POST /api/psi/favorites failed: %d %s", recFav.Code, recFav.Body.String())
	}

	// 3. Persistent lifetime traffic stats & POST /api/stats/reset
	tr := a.stats.open("chrome.exe", "youtube.com", "", 443, obPsiphon, "YouTube")
	a.stats.add(tr, 2048, 8192)
	a.stats.close(tr, nil)
	a.stats.Flush()

	reloadedStats := newStats(filepath.Join(a.dataDir, "psiroute-days.json"))
	if reloadedStats.lifeDown.Load() < 8192 || reloadedStats.lifeUp.Load() < 2048 {
		t.Fatalf("expected lifetime traffic persisted in traffic_stats.json, got down=%d up=%d",
			reloadedStats.lifeDown.Load(), reloadedStats.lifeUp.Load())
	}

	recReset := apiCall(t, a, "POST", "/api/stats/reset", true, `{}`)
	if recReset.Code != http.StatusOK || a.stats.totDown.Load() != 0 || a.stats.lifeDown.Load() != 0 {
		t.Fatalf("POST /api/stats/reset failed: code=%d down=%d lifeDown=%d",
			recReset.Code, a.stats.totDown.Load(), a.stats.lifeDown.Load())
	}
}
