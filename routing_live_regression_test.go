package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestSNIFailedRouteChangeDoesNotSendToOldDirect(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.BypassLAN = false
		c.Routing.Failover = false
		c.Proxy.Enabled = false
		c.Routing.Rules = []Rule{{Name: "protected", Domains: []string{"protected.example"}, Outbound: obProxy}}
	})
	hello := clientHello(t, "protected.example")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	upstream, remote := net.Pipe()
	defer upstream.Close()
	defer remote.Close()
	tracked := a.stats.open("test", "203.0.113.10", "", 443, obDirect, "initial IP")
	done := make(chan error, 1)
	go func() { err, _ := a.relay(server, bufio.NewReader(server), upstream, tracked); done <- err }()
	go func() { client.Write(hello) }()
	remote.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 4096)
	n, _ := remote.Read(b)
	if n != 0 {
		t.Fatalf("leaked %d ClientHello bytes to old route", n)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("route switch failure stalled")
	}
}

func TestUDPFlowAppliesChangedProtocolRule(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.BypassLAN = false
		c.Routing.Failover = false
		c.UDP.Mode = "route"
		c.Routing.Rules = []Rule{{Name: "udp", Domains: []string{"flow.example"}, Proto: "udp", Outbound: obDirect}}
	})
	s := &udpSession{a: a, flows: map[string]*udpFlow{}, failed: map[string]time.Time{}, byAddr: map[string]*udpFlow{}}
	old := &udpFlow{key: "flow.example:9000", host: "flow.example", port: 9000, ob: obDirect, t: a.stats.openProto("udp", "test", "flow.example", "", 9000, obDirect, "old")}
	s.flows[old.key] = old
	setCfg(a, func(c *Config) { c.Routing.Rules[0].Outbound = obBlock })
	a.onRulesChanged()
	if got := s.flow("flow.example", 9000); got != nil {
		t.Fatal("blocked UDP rule reused old direct flow")
	}
}

func TestEditorRoundtripPreservesTypedConditions(t *testing.T) {
	a := testApp(t)
	original := Rule{Name: "complex", Outbound: obDirect, Disabled: true, Domains: []string{"youtube", "regexp:^x{1,3}\\.example$"}, Keywords: []string{"video,part;#fragment"}, CIDR: []string{"203.0.113.0/24"}, Apps: []string{"!notepad", "browser"}, Ports: []int{443}, PortRanges: []string{"1000-2000"}}
	raw, _ := json.Marshal(original)
	var mapped map[string]any
	json.Unmarshal(raw, &mapped)
	body := ruleEditRequest(mapped, ruleEditableTokens(mapped), "renamed", obDirect, "", true)
	raw, _ = json.Marshal(body)
	response := apiCall(t, a, "POST", "/api/rules/add", true, string(raw))
	if response.Code != 200 {
		t.Fatalf("save: %d %s", response.Code, response.Body.String())
	}
	got := a.cfg.Routing.Rules[len(a.cfg.Routing.Rules)-1]
	original.Name = "renamed"
	original.Always = true
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("lost rule conditions:\ngot %#v\nwant %#v", got, original)
	}
	body = ruleEditRequest(mapped, ruleEditableTokens(mapped)+", domain:extra.example", "renamed", obDirect, "", true)
	raw, _ = json.Marshal(body)
	response = apiCall(t, a, "POST", "/api/rules/add", true, string(raw))
	if response.Code != 200 {
		t.Fatalf("modified save: %s", response.Body.String())
	}
	got = a.cfg.Routing.Rules[len(a.cfg.Routing.Rules)-1]
	original.Domains = append(original.Domains, "extra.example")
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("editing target lost typed conditions: got %#v want %#v", got, original)
	}

}
func TestRuleSaveFailureRestoresActiveRule(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.BypassLAN = false
		c.Routing.Mode = "rules"
		c.Routing.Rules = []Rule{{Name: "protected", Domains: []string{"secure.example"}, Outbound: obBlock}}
	})
	a.cfg.path = filepath.Join(t.TempDir(), "missing", "config.json")
	// A regular file cannot be used as a parent directory.
	blockedParent := filepath.Join(t.TempDir(), "parent")
	os.WriteFile(blockedParent, []byte("x"), 0600)
	a.cfg.path = filepath.Join(blockedParent, "config.json")
	response := apiCall(t, a, "POST", "/api/rules/toggle", true, `{"index":0,"disabled":true}`)
	if response.Code != 500 {
		t.Fatalf("false save success %d", response.Code)
	}
	route := a.router.ExplainRoute("tcp", "secure.example", "", 443, "")
	if route.Outbound != obBlock || a.cfg.Routing.Rules[0].Disabled {
		t.Fatal("failed save changed active policy")
	}
}

func TestTUNUDPClosesOnProtocolRuleChange(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.BypassLAN = false
		c.Routing.Failover = false
		c.Routing.Rules = []Rule{{Name: "block UDP", Domains: []string{"tun.example"}, Proto: "udp", Outbound: obBlock}}
	})
	c, client := net.Pipe()
	defer client.Close()
	up, remote := net.Pipe()
	defer remote.Close()
	tracked := a.stats.openProto("udp", "test", "tun.example", "", 9000, obDirect, "old")
	e := &tunEngine{a: a, ctx: a.ctx}
	// Force closure before relay registers its sockets to exercise the race.
	a.onRulesChanged()
	done := make(chan struct{})
	go func() { e.udpRelay(c, up, tracked, false); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old TUN UDP sockets survived rule change")
	}
}

func TestSmartDomainsAPICompatibility(t *testing.T) {
	a := testApp(t)
	response := apiCall(t, a, "POST", "/api/rules/add", true, `{"name":"legacy smart domains","outbound":"direct","domains":["youtube","203.0.113.0/24"]}`)
	if response.Code != 200 {
		t.Fatalf("save %s", response.Body.String())
	}
	got := a.cfg.Routing.Rules[len(a.cfg.Routing.Rules)-1]
	if len(got.Lists) != 1 || got.Lists[0] != "youtube" || len(got.CIDR) != 1 || got.CIDR[0] != "203.0.113.0/24" {
		t.Fatalf("legacy smart fields changed: %#v", got)
	}
}
func TestConcurrentConfigSavesProduceCurrentCompleteConfig(t *testing.T) {
	a := testApp(t)
	a.cfg.path = filepath.Join(t.TempDir(), "config.json")
	errors := make(chan error, 32)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			a.cfg.mu.Lock()
			a.cfg.Routing.Default = fmt.Sprintf("route-%d", i)
			a.cfg.mu.Unlock()
			errors <- a.cfg.save()
		}(i)
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent save failed: %v", err)
		}
	}
	raw, err := os.ReadFile(a.cfg.path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Config
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Routing.Default != a.cfg.Routing.Default {
		t.Fatal("last persisted snapshot is stale")
	}
}
