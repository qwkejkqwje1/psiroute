package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAppRuleConditionsTakePriorityOverDomain(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			a := testApp(t)
			setCfg(a, func(c *Config) {
				c.Routing.Mode = "rules"
				c.Routing.BypassLAN = false
				c.Routing.Failover = false
				c.Routing.Rules = []Rule{
					{Name: "domain", Domains: []string{"service.example"}, Outbound: obPsiphon, Always: true},
					{Name: "app restricted", Apps: []string{"browser.exe"}, Proto: proto, Ports: []int{8443}, Domains: []string{"service.example"}, Outbound: obDirect, Always: true},
				}
			})
			for _, tc := range []struct {
				host, app, protocol string
				port, stage         int
				name                string
			}{
				{"service.example", "browser.exe", proto, 8443, 2, "app restricted"},
				{"service.example", "browser.exe", proto, 443, 3, "domain"},
				{"service.example", "other.exe", proto, 8443, 3, "domain"},
			} {
				got := a.router.ExplainRoute(tc.protocol, tc.host, "", tc.port, tc.app)
				if got.Stage != tc.stage || got.Rule != tc.name {
					t.Fatalf("%+v: %+v", tc, got)
				}
			}
		})
	}
}

func TestStrictRUTierBeforePresetAndLearned(t *testing.T) {
	a := testApp(t)
	url, _ := resolveListURL("ai-services")
	a.lists.data[url] = parseList(strings.NewReader("openai.com\n"))
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "auto"
		c.Routing.Learn = true
		c.Routing.BypassLAN = false
		c.Routing.Failover = false
		c.Routing.Rules = []Rule{{Name: "preset", Lists: []string{"ai-services"}, Outbound: obPsiphon, Always: true}}
	})
	// 1. In auto mode, unmatched .ru domain hits automatic RU Whitelist (Stage 4) instead of learned route.
	a.router.remember("service.ru", obPsiphon, "old learned", true)
	got := a.router.ExplainRoute("tcp", "service.ru", "", 443, "browser.exe")
	if got.Stage != 4 || got.Outbound != obDirect {
		t.Fatalf("RU lost to learned: %+v", got)
	}
	// 2. If user explicitly adds a domain rule for service.ru, personal domain tier (Stage 3) wins over RU Whitelist.
	setCfg(a, func(c *Config) {
		c.Routing.Rules = append(c.Routing.Rules, Rule{Name: "explicit", Domains: []string{"service.ru"}, Outbound: obPsiphon, Always: true})
	})
	a.onRulesChanged()
	got = a.router.ExplainRoute("tcp", "service.ru", "", 443, "browser.exe")
	if got.Stage != 3 || got.Rule != "explicit" {
		t.Fatalf("RU overrode personal rule: %+v", got)
	}
}

func TestManualAutoOutboundDoesNotUseLearnedRoute(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Learn = true
		c.Routing.BypassLAN = false
		c.Routing.Failover = false
		c.Routing.Default = obAuto
		c.Routing.Chain = []string{obPsiphon}
	})
	a.router.remember("manual.example", obDirect, "learned", true)
	got := a.router.ExplainRoute("tcp", "manual.example", "", 443, "")
	if got.Stage != 7 || got.Outbound != obPsiphon {
		t.Fatalf("manual used learned: %+v", got)
	}
}

// TestRulesModeDefaultDirectAndNoFailoverToVPN verifies Audit 2 fix:
// in "rules" mode, unmatched traffic goes via obDirect ("по умолчанию (мимо VPN)")
// even when Config.Routing.Default is "" or obPsiphon, and Failover never appends obPsiphon.
func TestRulesModeDefaultDirectAndNoFailoverToVPN(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Default = obPsiphon
		c.Routing.Failover = true
		c.Routing.BypassLAN = false
		c.Routing.Rules = []Rule{
			{Name: "Only YouTube DPI", Domains: []string{"youtube.com"}, Outbound: obDesync, Always: true},
		}
	})

	// 1. Unmatched site in "rules" mode must go to obDirect ("по умолчанию (мимо VPN)") without obPsiphon failover
	ordUnmatched, nameUnmatched, stageUnmatched := a.router.planForProtoWithStage("tcp", "gosuslugi.ru", "", 443, "chrome.exe")
	if len(ordUnmatched) != 1 || ordUnmatched[0] != obDirect || nameUnmatched != "по умолчанию (мимо VPN)" || stageUnmatched != 7 {
		t.Fatalf("expected unmatched in rules mode to be [direct] ('по умолчанию (мимо VPN)', stage 7), got %v (%q, stage %d)", ordUnmatched, nameUnmatched, stageUnmatched)
	}

	// 2. Matched non-VPN rule (obDesync) in "rules" mode must NOT have obPsiphon appended by Failover
	ordMatched, nameMatched, stageMatched := a.router.planForProtoWithStage("tcp", "www.youtube.com", "", 443, "chrome.exe")
	if len(ordMatched) != 1 || ordMatched[0] != obDesync || nameMatched != "Only YouTube DPI" || stageMatched != 3 {
		t.Fatalf("expected matched DPI rule in rules mode to stay [direct-dpi] without psiphon failover, got %v (%q, stage %d)", ordMatched, nameMatched, stageMatched)
	}
}

// classifyRuleJSONMapForTest mirrors gui_rules.go classifyRuleMapGroup(r map[string]any)
// so the 4 UI priority groups can be verified on all build targets alongside RuleGroupTier and rulePriorityTier.
func classifyRuleJSONMapForTest(r map[string]any) int {
	strSlice := func(v any) []string {
		arr, ok := v.([]any)
		if !ok {
			return nil
		}
		var out []string
		for _, it := range arr {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	intSlice := func(v any) []int {
		arr, ok := v.([]any)
		if !ok {
			return nil
		}
		var out []int
		for _, it := range arr {
			if n, ok := it.(float64); ok {
				out = append(out, int(n))
			}
		}
		return out
	}
	hasPosApp := false
	for _, a := range strSlice(r["apps"]) {
		a = strings.TrimSpace(a)
		if a != "" && !strings.HasPrefix(a, "!") {
			hasPosApp = true
			break
		}
	}
	hasTarget := len(strSlice(r["domains"])) > 0 ||
		len(strSlice(r["keywords"])) > 0 ||
		len(strSlice(r["cidr"])) > 0 ||
		len(strSlice(r["ips"])) > 0 ||
		len(intSlice(r["ports"])) > 0 ||
		len(strSlice(r["port_ranges"])) > 0
	hasLists := len(strSlice(r["lists"])) > 0
	proto, _ := r["proto"].(string)

	if hasPosApp && (hasTarget || hasLists || strings.TrimSpace(proto) != "") {
		return 1
	}
	ob, _ := r["outbound"].(string)
	if !hasPosApp && ob == obDirect {
		isRU := false
		for _, l := range strSlice(r["lists"]) {
			l = strings.ToLower(strings.TrimSpace(l))
			if l == "ru" || l == "ru-gov-banks" {
				isRU = true
			}
		}
		doms := strSlice(r["domains"])
		if len(doms) > 0 && len(strSlice(r["apps"])) == 0 && len(strSlice(r["cidr"])) == 0 && len(intSlice(r["ports"])) == 0 && len(strSlice(r["port_ranges"])) == 0 {
			for _, d := range doms {
				d = strings.ToLower(strings.TrimSpace(d))
				if d == "ru" || d == ".ru" || d == "*.ru" || d == "xn--p1ai" || d == "su" || d == "рф" || d == "country:ru" {
					isRU = true
				}
			}
		}
		if isRU {
			return 4
		}
	}
	if !hasPosApp && (hasTarget || !hasLists) {
		return 2
	}
	if hasPosApp {
		return 3
	}
	return 4
}

// TestGUIRulesGroupsMatchRouterPriorityTiers verifies Audit 2 Item 1 & 3:
// the 4 UI rule groups in gui_rules.go (1..4) align with rulePriorityTier (2..6) in router.go
// and execute in the exact promised priority order regardless of JSON slice position.
func TestGUIRulesGroupsMatchRouterPriorityTiers(t *testing.T) {
	cases := []struct {
		name      string
		rule      Rule
		wantGroup int
		wantTiers []int // acceptable internal tier(s) in router.go (2..6, or 1..5 before renumbering)
		wantStage int
	}{
		{
			name:      "Group 1 / Tier 2: Combo App + Domain/Port",
			rule:      Rule{Name: "Chrome YouTube", Apps: []string{"chrome.exe"}, Domains: []string{"youtube.com"}, Outbound: "psiphon:NL", Always: true},
			wantGroup: 1,
			wantTiers: []int{2, 1},
			wantStage: 2,
		},
		{
			name:      "Group 1 / Tier 2: Combo App + UDP PortRange (Voice)",
			rule:      Rule{Name: "Telegram Voice UDP", Apps: []string{"Telegram.exe"}, Proto: "udp", PortRanges: []string{"50000-65535"}, Outbound: obWarp, Always: true},
			wantGroup: 1,
			wantTiers: []int{2, 1},
			wantStage: 2,
		},
		{
			name:      "Group 2 / Tier 3: Personal Domain inside all browsers",
			rule:      Rule{Name: "Personal Site", Domains: []string{"chatgpt.com"}, Outbound: obPsiphon, Always: true},
			wantGroup: 2,
			wantTiers: []int{3, 2},
			wantStage: 3,
		},
		{
			name:      "Group 3 / Tier 4: Pure App Rule",
			rule:      Rule{Name: "Browser Direct", Apps: []string{"chrome.exe"}, Outbound: obDirect, Always: true},
			wantGroup: 3,
			wantTiers: []int{4, 3},
			wantStage: 2,
		},
		{
			name:      "Group 4 / Tier 5: RU Whitelist List Rule",
			rule:      Rule{Name: "RU Gov Banks", Lists: []string{"ru-gov-banks"}, Outbound: obDirect, Always: true},
			wantGroup: 4,
			wantTiers: []int{5, 4},
			wantStage: 4,
		},
		{
			name:      "Group 4 / Tier 6: Bulk Service List Rule",
			rule:      Rule{Name: "Blocked List", Lists: []string{"ru-blocked"}, Outbound: obPsiphon, Always: true},
			wantGroup: 4,
			wantTiers: []int{6, 4},
			wantStage: 5,
		},
	}

	var prevTier int
	for i, tc := range cases {
		raw, err := json.Marshal(tc.rule)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		gotMapGroup := classifyRuleJSONMapForTest(m)
		if gotMapGroup != tc.wantGroup {
			t.Fatalf("%s: classifyRuleMapGroup = %d, want %d", tc.name, gotMapGroup, tc.wantGroup)
		}
		if gotGroup := RuleGroupTier(tc.rule); gotGroup != tc.wantGroup {
			t.Fatalf("%s: RuleGroupTier = %d, want %d", tc.name, gotGroup, tc.wantGroup)
		}
		gotTier := rulePriorityTier(tc.rule)
		tierOK := false
		for _, wt := range tc.wantTiers {
			if gotTier == wt {
				tierOK = true
				break
			}
		}
		if !tierOK {
			t.Fatalf("%s: rulePriorityTier = %d, want one of %v", tc.name, gotTier, tc.wantTiers)
		}
		if i > 0 && gotTier < prevTier {
			t.Fatalf("%s: priority tier decreased from %d to %d", tc.name, prevTier, gotTier)
		}
		prevTier = gotTier
		if gotStage := rulePipelineStage(tc.rule, gotTier); gotStage != tc.wantStage {
			t.Fatalf("%s: rulePipelineStage = %d, want %d", tc.name, gotStage, tc.wantStage)
		}
	}
}
