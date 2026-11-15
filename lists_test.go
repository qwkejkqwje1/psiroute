package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseListAndMatch(t *testing.T) {
	d := parseList(strings.NewReader("# comment\nYouTube.com\n*.googlevideo.com\n.ytimg.com\n91.108.4.0/22\n149.154.167.50\nbad line here\nfoo // x\n\n2001:67c:4e8::/48\n"))
	cases := map[string]bool{
		"youtube.com": true, "www.youtube.com": true, "r1.googlevideo.com": true, "i.ytimg.com": true,
		"notyoutube.com": false, "com": false, "bad": false,
	}
	for h, want := range cases {
		if got := (&Lists{data: map[string]*listData{"u": d}}).dataMatch("u", h); got != want {
			t.Errorf("%s: got %v want %v", h, got, want)
		}
	}
	l := &Lists{data: map[string]*listData{}}
	u, _ := resolveListURL("telegram-ip")
	l.data[u] = d
	for ip, want := range map[string]bool{"91.108.5.1": true, "91.108.8.1": false, "149.154.167.50": true, "2001:67c:4e8::1": true} {
		if got := l.Match([]string{"telegram-ip"}, ip); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
}

func (l *Lists) dataMatch(u, host string) bool {
	return l.data[u].match(host, parseAddrOrZero(host))
}

func TestResolveListURL(t *testing.T) {
	for _, ok := range []string{
		"ru-blocked", "RU-BLOCKED",
		"local:my.lst", "local:user-custom.txt",
		"https://raw.githubusercontent.com/a/b/main/x.lst",
		"https://antifilter.download/list/ip.lst",
	} {
		if _, err := resolveListURL(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"local:../secret.lst",
		"local:a/b.lst",
		"local:.hidden",
		"http://raw.githubusercontent.com/x",
		"https://evil.example/list",
		"https://127.0.0.1/list.txt",
		"https://192.168.1.1/list.txt",
		"https://localhost/list.txt",
		"https://raw.githubusercontent.com.evil.ru/x",
		"file:///etc/passwd",
		"unknown-preset",
	} {
		if _, err := resolveListURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCountryOutbound(t *testing.T) {
	for in, want := range map[string]string{"psiphon:DE": "DE", "psiphon:nl": "NL"} {
		if cc, ok := countryOf(in); !ok || cc != want {
			t.Errorf("%s -> %s %v", in, cc, ok)
		}
	}
	for _, bad := range []string{"psiphon", "psiphon:", "psiphon:DEU", "psiphon:1E", "direct:DE"} {
		if _, ok := countryOf(bad); ok {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestRuleWithListAndCountry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := NewApp(ctx, cancel, "", t.TempDir())
	a.cfg.Routing.Mode = "rules"
	a.cfg.Routing.Failover = true
	a.cfg.Routing.Default = obDirect
	a.cfg.Routing.Rules = []Rule{{Name: "через Германию", Outbound: "psiphon:DE", Lists: []string{"youtube"}}}
	u, _ := resolveListURL("youtube")
	a.lists.data[u] = parseList(strings.NewReader("youtube.com\ngooglevideo.com\n"))
	order, rule := a.router.plan("rr3.googlevideo.com", 443)
	if len(order) != 1 || order[0] != "psiphon:DE" || rule != "через Германию" {
		t.Fatalf("order=%v rule=%q", order, rule)
	}
	order, _ = a.router.plan("vk.com", 443)
	if order[0] != obDirect {
		t.Fatalf("vk.com: %v", order)
	}
	_ = time.Second
}

func TestLocalListSaveMatchDeleteAndRuleProtection(t *testing.T) {
	a := testApp(t)
	res, err := a.lists.SaveLocalList("my-work", "corp.example.com\nfull:exact.corp.test\n10.20.30.0/24\nregexp:^skip\\.me$\ninvalid_line\n")
	if err != nil {
		t.Fatalf("SaveLocalList: %v", err)
	}
	id, _ := res["id"].(string)
	if id != "local:my-work.lst" {
		t.Fatalf("id = %q, want local:my-work.lst", id)
	}
	if _, err := resolveListURL(id); err != nil {
		t.Fatalf("resolveListURL(%q) failed: %v", id, err)
	}
	if !a.lists.Match([]string{id}, "sub.corp.example.com") {
		t.Fatal("expected sub.corp.example.com to match local list")
	}
	if !a.lists.Match([]string{id}, "exact.corp.test") || a.lists.Match([]string{id}, "sub.exact.corp.test") {
		t.Fatal("exact domain match failed")
	}
	if !a.lists.Match([]string{id}, "10.20.30.55") {
		t.Fatal("subnet match failed")
	}

	// Attach list to a rule and verify deletion is blocked without removeFromRules
	setCfg(a, func(c *Config) {
		c.Routing.Rules = []Rule{{Name: "Рабочая сеть", Outbound: obDirect, Lists: []string{"my-work"}}}
	})
	delRes, code, derr := a.lists.DeleteList("my-work", false)
	if derr == nil || code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when deleting list in use, got code=%d err=%v", code, derr)
	}
	used, _ := delRes["used_in_rules"].([]string)
	if len(used) != 1 || used[0] != "Рабочая сеть" {
		t.Fatalf("used_in_rules = %v, want [Рабочая сеть]", used)
	}

	// Delete with removeFromRules=true cleans up rule and removes list
	_, code2, derr2 := a.lists.DeleteList("my-work", true)
	if derr2 != nil || code2 != http.StatusOK {
		t.Fatalf("DeleteList with removeFromRules=true failed: code=%d err=%v", code2, derr2)
	}
	a.cfg.mu.Lock()
	leftRules := len(a.cfg.Routing.Rules)
	a.cfg.mu.Unlock()
	if leftRules != 0 {
		t.Fatalf("expected empty rule to be removed cleanly, got %d rules", leftRules)
	}
}

func TestV2FlyIncludePreviewAndHiddenBuiltins(t *testing.T) {
	a := testApp(t)
	pv := a.lists.PreviewList("include:yandex\nfull:only.example.org\nregexp:^ads\\..*$\nbad token here\n192.0.2.0/24\n")
	if pv["domains"].(int) < 5 || pv["subnets"].(int) != 1 || pv["regexp_skipped"].(int) != 1 || pv["skipped_lines"].(int) != 1 {
		t.Fatalf("PreviewList unexpected result: %+v", pv)
	}

	// Hide built-in list "youtube" via DELETE /api/lists/youtube, then restore via /api/lists/restore-builtins
	rec := apiCall(t, a, "DELETE", "/api/lists/youtube", true, `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/lists/youtube status=%d: %s", rec.Code, rec.Body.String())
	}
	a.cfg.mu.Lock()
	hidCount := len(a.cfg.Lists.Hidden)
	a.cfg.mu.Unlock()
	if hidCount != 1 {
		t.Fatalf("expected 1 hidden built-in list, got %d", hidCount)
	}

	rec2 := apiCall(t, a, "POST", "/api/lists/restore-builtins", true, `{}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("restore-builtins status=%d", rec2.Code)
	}
	a.cfg.mu.Lock()
	hidAfter := len(a.cfg.Lists.Hidden)
	a.cfg.mu.Unlock()
	if hidAfter != 0 {
		t.Fatalf("expected 0 hidden lists after restore, got %d", hidAfter)
	}
}

func TestCustomRemoteListTrustAndFakeTransport(t *testing.T) {
	a := testApp(t)
	a.lists.testTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.Header().Set("ETag", `"v1"`)
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.WriteString("custom1.example.com\ncustom2.example.org\n198.51.100.0/24\n")
		return rec.Result(), nil
	})

	// 1. Without confirm_trust, custom host is rejected with 409 + need_confirm_trust
	rec := apiCall(t, a, "POST", "/api/lists", true, `{"id":"corp-url","title":"Corp List","type":"url","url":"https://lists.corp-example.org/rules.txt"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("untrusted host should return 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. With confirm_trust=true, host is added to trusted_hosts and fetched via fake transport
	rec2 := apiCall(t, a, "POST", "/api/lists", true, `{"id":"corp-url","title":"Corp List","type":"url","url":"https://lists.corp-example.org/rules.txt","confirm_trust":true}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("confirmed host POST /api/lists status=%d: %s", rec2.Code, rec2.Body.String())
	}
	if !a.lists.Match([]string{"corp-url"}, "sub.custom1.example.com") {
		t.Fatal("expected sub.custom1.example.com to match fetched custom URL list")
	}

	// 3. Content endpoint returns downloaded list text
	rec3 := apiCall(t, a, "GET", "/api/lists/corp-url/content", true, "")
	if rec3.Code != http.StatusOK || !strings.Contains(rec3.Body.String(), "custom1.example.com") {
		t.Fatalf("GET /api/lists/corp-url/content failed: %d %s", rec3.Code, rec3.Body.String())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func parseAddrOrZero(s string) (a netip.Addr) {
	a, _ = netip.ParseAddr(s)
	return a
}

func TestIncludePathTraversalBlockedAndSSRFGuardFailClosed(t *testing.T) {
	a := testApp(t)
	// Баг №1: попытки выйти за пределы dataDir/lists через include:../ или поддиректории блокируются
	for _, badInc := range []string{
		"../psiroute.json",
		"../../Windows/win.ini",
		"../../etc/passwd",
		"sub/nested.lst",
		`C:\Windows\win.ini`,
	} {
		if rc := a.lists.resolveIncludeReader(badInc); rc != nil {
			_ = rc.Close()
			t.Fatalf("Path Traversal include:%s was NOT blocked!", badInc)
		}
	}
	// Удалённый список не имеет права подключать локальные файлы с диска через include:
	_, _ = a.lists.SaveLocalList("secret-local", "internal.corp.local\n")
	if rc := a.lists.resolveRemoteIncludeReader("secret-local"); rc != nil {
		_ = rc.Close()
		t.Fatal("remote list include resolver must not read local disk lists")
	}
	if rc := a.lists.resolveRemoteIncludeReader("yandex"); rc == nil {
		t.Fatal("remote list include resolver should allow built-in seeds")
	} else {
		_ = rc.Close()
	}

	// Баг №6: wrapSSRFDial обязан блокировать соединение (fail-closed), если DNS-резолвинг не удался
	baseCalled := false
	guarded := wrapSSRFDial(func(ctx context.Context, network, addr string) ( 	net.Conn, error) {
		baseCalled = true
		return nil, nil
	})
	_, err := guarded(context.Background(), "tcp", "nonexistent-domain-for-ssrf-test.invalid:443")
	if err == nil || baseCalled {
		t.Fatalf("wrapSSRFDial must fail-closed on DNS error: err=%v baseCalled=%v", err, baseCalled)
	}
}


func TestFlatDomainIndexPointerFreeAndBinarySearch(t *testing.T) {
	idx := buildFlatDomainIndex([]string{"discord.com", "openai.com", "youtube.com"})
	if idx.Len() != 3 {
		t.Fatalf("expected Len() = 3, got %d", idx.Len())
	}
	for _, hit := range []string{"discord.com", "openai.com", "youtube.com"} {
		if !idx.Contains(hit) {
			t.Fatalf("expected %q in flatDomainIndex", hit)
		}
	}
	for _, miss := range []string{"", "a.com", "middle.org", "zzz.net"} {
		if idx.Contains(miss) {
			t.Fatalf("unexpected match for %q in flatDomainIndex", miss)
		}
	}
	a := testApp(t)
	if !a.lists.MatchRUWhitelist("gosuslugi.ru") || !a.lists.MatchRUWhitelist("sberbank.ru") {
		t.Fatal("expected Russian domains to match MatchRUWhitelist")
	}
	if a.lists.MatchRUWhitelist("youtube.com") {
		t.Fatal("did not expect youtube.com to match MatchRUWhitelist")
	}
}
