package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- 1.1: routing profiles ----------

func sampleProfile() Profile {
	return Profile{
		Format: profileFormat, Name: "Тест", Mode: "rules", Default: obDirect,
		Chain: []string{obDirect, obDesync, obPsiphon},
		Rules: []Rule{
			{Name: "YouTube", Outbound: obPsiphon, Domains: []string{"youtube.com"}, Lists: []string{"youtube"}, Ports: []int{443}},
			{Name: "Германия", Outbound: "psiphon:DE", CIDR: []string{"91.108.0.0/16"}, Apps: []string{"Telegram.exe"}, Always: true},
		},
	}
}

func sameJSON(t *testing.T, want, got any) {
	t.Helper()
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Fatalf("не совпало:\nждали %s\nполучили %s", a, b)
	}
}

func TestProfileCodeRoundTrip(t *testing.T) {
	p := sampleProfile()
	code, err := encodeProfileCode(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, profileCodeScheme) {
		t.Fatalf("код без префикса: %s", code)
	}
	// a messenger may wrap a long code and add spaces around it
	cut := len(profileCodeScheme) + 5
	wrapped := "  " + code[:cut] + "\n" + code[cut:] + "\r\n"
	got, err := decodeProfile(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, p, got)
	// the code without the psiroute://profile/ prefix works too
	got2, err := decodeProfile(strings.TrimPrefix(code, profileCodeScheme))
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, p, got2)
}

func TestProfileDecodeJSONAndConfigFile(t *testing.T) {
	b, _ := json.Marshal(sampleProfile())
	got, err := decodeProfile("\ufeff" + string(b))
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, sampleProfile(), got)

	cfg := `{"psiphon":{"parallel":2},"routing":{"mode":"rules","default":"psiphon","rules":[{"name":"банк","outbound":"direct","domains":["sberbank.ru"]}]}}`
	got, err = decodeProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Name != "банк" || got.Default != obPsiphon || got.Mode != "rules" {
		t.Fatalf("правила из psiroute.json не взяты: %+v", got)
	}

	// hand-written profile without format and name
	got, err = decodeProfile(`{"rules":[{"outbound":"psiphon","domains":["x.com"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != profileFormat || got.Name == "" {
		t.Fatalf("формат и имя не заполнены: %+v", got)
	}
}

func TestProfileRejectsBadInput(t *testing.T) {
	bad := map[string]string{
		"пусто":              "   ",
		"мусор":              "psiroute://profile/!!!",
		"не gzip":            profileCodeScheme + "aGVsbG8",
		"не профиль":        `{"hello":1}`,
		"новый формат":      `{"format":99,"rules":[]}`,
		"нет маршрута":     `{"rules":[{"name":"a","domains":["x.com"]}]}`,
		"чужой маршрут":    `{"rules":[{"name":"a","outbound":"evil"}]}`,
		"плохая страна":    `{"rules":[{"name":"a","outbound":"psiphon:GER"}]}`,
		"чужой список":     `{"rules":[{"name":"a","outbound":"psiphon","lists":["https://evil.example/x.lst"]}]}`,
		"список по http":   `{"rules":[{"name":"a","outbound":"psiphon","lists":["http://raw.githubusercontent.com/a/b"]}]}`,
		"неизвестный режим": `{"mode":"tor","rules":[]}`,
		"auto в цепочке":   `{"auto_chain":["direct","auto"],"rules":[]}`,
	}
	for name, data := range bad {
		if _, err := decodeProfile(data); err == nil {
			t.Errorf("%s: профиль принят, а должен быть отклонён", name)
		}
	}
	// too many rules
	many := Profile{Rules: make([]Rule, profileMaxRules+1)}
	for i := range many.Rules {
		many.Rules[i] = Rule{Name: "r", Outbound: obDirect}
	}
	if err := validateProfile(&many); err == nil {
		t.Error("профиль с лишними правилами принят")
	}
}

func TestBuiltinProfilesValid(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range builtinProfiles {
		if seen[b.ID] {
			t.Errorf("повтор id %s", b.ID)
		}
		seen[b.ID] = true
		p, ok := builtinByID(b.ID)
		if !ok {
			t.Fatalf("%s не найден", b.ID)
		}
		if err := validateProfile(&p); err != nil {
			t.Errorf("%s: %v", b.ID, err)
		}
		// builtinByID returns a copy: changing it must not touch the original
		if len(p.Rules) > 0 && len(p.Rules[0].Domains) > 0 {
			p.Rules[0].Domains[0] = "changed.example"
			if b.Rules[0].Domains[0] == "changed.example" {
				t.Errorf("%s: готовый профиль изменён через копию", b.ID)
			}
		}
	}
	if _, ok := builtinByID("nope"); ok {
		t.Error("несуществующий профиль найден")
	}
}

func TestApplyProfileReplaceAndMerge(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "psiphon"
		c.Routing.Default = obPsiphon
		c.Routing.Rules = []Rule{{Name: "банк", Outbound: obDirect, Domains: []string{"sberbank.ru"}}, {Name: "YouTube", Outbound: obDirect}}
	})

	// merge: same name is replaced, new rule is added, mode stays
	res := applyProfile(app.cfg, sampleProfile(), true)
	if res.Added != 1 || res.Replaced != 1 || res.Mode != "psiphon" {
		t.Fatalf("слияние: %+v", res)
	}
	cur := currentProfile(app.cfg, "")
	if len(cur.Rules) != 3 || cur.Rules[1].Outbound != obPsiphon || cur.Rules[0].Name != "банк" || cur.Default != obPsiphon {
		t.Fatalf("после слияния: %+v", cur)
	}

	// replace: rules, mode, default and chain come from the profile
	res = applyProfile(app.cfg, sampleProfile(), false)
	if res.Added != 2 || res.Mode != "rules" {
		t.Fatalf("замена: %+v", res)
	}
	cur = currentProfile(app.cfg, "x")
	sameJSON(t, sampleProfile().Rules, cur.Rules)
	if cur.Default != obDirect || len(cur.Chain) != 3 {
		t.Fatalf("после замены: %+v", cur)
	}

	// the exported profile does not share slices with the config
	cur.Rules[0].Domains[0] = "changed.example"
	if currentProfile(app.cfg, "").Rules[0].Domains[0] == "changed.example" {
		t.Fatal("экспорт делит память с настройками")
	}
}

func profileCall(t *testing.T, app *App, method, path, body string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	app.api(rec, req)
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("%s: ответ не JSON: %s", path, rec.Body.String())
	}
	return m
}

func TestProfilesAPIImportExportUndo(t *testing.T) {
	app := testApp(t)
	setCfg(app, func(c *Config) {
		c.Routing.Mode = "psiphon"
		c.Routing.Rules = []Rule{{Name: "банк", Outbound: obDirect, Domains: []string{"sberbank.ru"}}}
	})

	m := profileCall(t, app, "GET", "/api/profiles", "")
	if l, _ := m["builtin"].([]any); len(l) != len(builtinProfiles) || m["undo"] != false {
		t.Fatalf("список профилей: %v", m)
	}

	m = profileCall(t, app, "POST", "/api/profiles/export", `{"name":"Дом"}`)
	code, _ := m["code"].(string)
	if !strings.HasPrefix(code, profileCodeScheme) {
		t.Fatalf("экспорт: %v", m)
	}

	// preview does not change anything
	data, _ := json.Marshal(map[string]any{"data": `{"name":"Новый","mode":"rules","rules":[{"name":"x","outbound":"psiphon","domains":["x.com"]}]}`})
	m = profileCall(t, app, "POST", "/api/profiles/preview", string(data))
	if m["ok"] != true || !strings.Contains(m["summary"].(string), "Новый") {
		t.Fatalf("предпросмотр: %v", m)
	}
	if r := currentProfile(app.cfg, "").Rules; len(r) != 1 || r[0].Name != "банк" {
		t.Fatal("предпросмотр изменил правила")
	}

	// import replaces and allows undo
	m = profileCall(t, app, "POST", "/api/profiles/import", string(data))
	if m["ok"] != true || m["undo"] != true {
		t.Fatalf("импорт: %v", m)
	}
	if cur := currentProfile(app.cfg, ""); len(cur.Rules) != 1 || cur.Rules[0].Name != "x" || cur.Mode != "rules" {
		t.Fatalf("после импорта: %+v", cur)
	}

	// a broken profile changes nothing
	m = profileCall(t, app, "POST", "/api/profiles/import", `{"data":"psiroute://profile/broken"}`)
	if m["ok"] != false {
		t.Fatalf("битый профиль принят: %v", m)
	}

	m = profileCall(t, app, "POST", "/api/profiles/undo", "")
	if m["ok"] != true {
		t.Fatalf("отмена: %v", m)
	}
	if cur := currentProfile(app.cfg, ""); len(cur.Rules) != 1 || cur.Rules[0].Name != "банк" || cur.Mode != "psiphon" {
		t.Fatalf("после отмены: %+v", cur)
	}
	if m = profileCall(t, app, "POST", "/api/profiles/undo", ""); m["ok"] != false {
		t.Fatal("вторая отмена прошла")
	}

	// the exported code imports back into the same rules
	data, _ = json.Marshal(map[string]any{"data": code})
	if m = profileCall(t, app, "POST", "/api/profiles/import", string(data)); m["ok"] != true {
		t.Fatalf("импорт кода: %v", m)
	}
	if cur := currentProfile(app.cfg, ""); len(cur.Rules) != 1 || cur.Rules[0].Domains[0] != "sberbank.ru" {
		t.Fatalf("после импорта кода: %+v", cur)
	}
}
