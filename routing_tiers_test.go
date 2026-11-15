package main

import (
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
					{Name: "domain", Domains: []string{"service.example"}, Outbound: obPsiphon},
					{Name: "app restricted", Apps: []string{"browser.exe"}, Proto: proto, Ports: []int{8443}, Domains: []string{"service.example"}, Outbound: obDirect},
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
	a.lists.data[url] = parseList(strings.NewReader("service.ru\n"))
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "auto"
		c.Routing.Learn = true
		c.Routing.BypassLAN = false
		c.Routing.Failover = false
		c.Routing.Rules = []Rule{{Name: "preset", Lists: []string{"ai-services"}, Outbound: obPsiphon}}
	})
	a.router.remember("service.ru", obPsiphon, "old learned", true)
	got := a.router.ExplainRoute("tcp", "service.ru", "", 443, "browser.exe")
	if got.Stage != 4 || got.Outbound != obDirect {
		t.Fatalf("RU lost to learned: %+v", got)
	}
	setCfg(a, func(c *Config) {
		c.Routing.Rules = append(c.Routing.Rules, Rule{Name: "explicit", Domains: []string{"service.ru"}, Outbound: obPsiphon})
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
