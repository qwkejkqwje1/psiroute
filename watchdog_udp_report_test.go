package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- safe.go ----------

func TestCatchPanic(t *testing.T) {
	before := panicsCaught.Load()
	if !catchPanic("тест", func() { panic("boom") }) {
		t.Fatal("panic not reported")
	}
	if catchPanic("тест", func() {}) {
		t.Fatal("no panic, but reported")
	}
	if panicsCaught.Load() != before+1 {
		t.Fatalf("panicsCaught = %d, want %d", panicsCaught.Load(), before+1)
	}
	done := make(chan struct{})
	goSafe("тест", func() { defer close(done); panic("in goroutine") })
	<-done
}

func TestFindCrash(t *testing.T) {
	dir := t.TempDir()
	if c := findCrash(dir); c.unseen {
		t.Fatal("no crash.log, but unseen")
	}
	body := "goroutine 1 [running]:\npanic: boom\n\ngoroutine 5:\nmain.x()\n"
	if err := os.WriteFile(crashLogPath(dir), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c := findCrash(dir)
	if !c.unseen || !strings.Contains(c.Headline, "boom") {
		t.Fatalf("findCrash = %+v", c)
	}
	c.markSeen(dir)
	if findCrash(dir).unseen {
		t.Fatal("still unseen after markSeen")
	}
}

// ---------- log.go ----------

func TestLogFileRotation(t *testing.T) {
	l := &Logger{max: 50}
	p := filepath.Join(t.TempDir(), "psiroute.log")
	l.add("info", "до открытия файла")
	if err := l.openFile(p); err != nil {
		t.Fatal(err)
	}
	if l.filePath() != p {
		t.Fatalf("filePath = %q", l.filePath())
	}
	msg := strings.Repeat("x", 1000)
	for i := 0; i < 1300; i++ { // ~1.3 MB > logFileMax
		l.add("info", msg)
	}
	l.closeFile()
	if l.filePath() != "" {
		t.Fatal("filePath after close")
	}
	st1, err := os.Stat(p + ".1")
	if err != nil {
		t.Fatalf("no rotated file: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st1.Size() > logFileMax || st.Size() > logFileMax {
		t.Fatalf("sizes %d / %d exceed %d", st1.Size(), st.Size(), logFileMax)
	}
	b, _ := os.ReadFile(p + ".1")
	if !strings.Contains(string(b), "до открытия файла") {
		t.Fatal("lines logged before openFile are missing")
	}
	if len(l.snapshot()) != 50 {
		t.Fatalf("ring size = %d", len(l.snapshot()))
	}
}

// ---------- watchdog.go ----------

func TestIsCrashExit(t *testing.T) {
	for code, want := range map[int]bool{0: false, 1: false, -1: false, 2: true, int(int32(-1073741819)): true} {
		if got := isCrashExit(code); got != want {
			t.Errorf("isCrashExit(%#x) = %v, want %v", code, got, want)
		}
	}
}

func TestCoreArgs(t *testing.T) {
	if got := coreArgs([]string{"--minimized", "--core", "--restarts=2"}, 0); !reflect.DeepEqual(got, []string{"--core", "--minimized"}) {
		t.Errorf("coreArgs = %q", got)
	}
	want := []string{"--core", "--config=x.json", "--restarts=1", "--minimized"}
	if got := coreArgs([]string{"--config=x.json"}, 1); !reflect.DeepEqual(got, want) {
		t.Errorf("coreArgs = %q, want %q", got, want)
	}
}

func fakeWatchdog(codes []int) (*watchdog, *[]string, *int, *int) {
	var calls []string
	crashes, gaveUp := 0, 0
	now := time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC)
	i := 0
	w := &watchdog{
		run: func(args []string) (int, error) {
			calls = append(calls, strings.Join(args, " "))
			c := codes[len(codes)-1]
			if i < len(codes) {
				c = codes[i]
			}
			i++
			now = now.Add(time.Minute)
			return c, nil
		},
		sleep:   func(time.Duration) {},
		now:     func() time.Time { return now },
		onCrash: func(int) { crashes++ },
		giveUp:  func(int) { gaveUp++ },
	}
	return w, &calls, &crashes, &gaveUp
}

func TestWatchdogRestartsAfterCrash(t *testing.T) {
	w, calls, crashes, gaveUp := fakeWatchdog([]int{2, 0})
	code, ran := w.loop()
	if !ran || code != 0 {
		t.Fatalf("loop = %d, %v", code, ran)
	}
	if len(*calls) != 2 || *crashes != 1 || *gaveUp != 0 {
		t.Fatalf("calls %q, crashes %d, gaveUp %d", *calls, *crashes, *gaveUp)
	}
	if !strings.Contains((*calls)[1], "--restarts=1") {
		t.Fatalf("second start without --restarts: %q", (*calls)[1])
	}
}

func TestWatchdogGivesUp(t *testing.T) {
	w, calls, _, gaveUp := fakeWatchdog([]int{2})
	_, ran := w.loop()
	if !ran || *gaveUp != 1 {
		t.Fatalf("ran %v, gaveUp %d", ran, *gaveUp)
	}
	if len(*calls) > maxCrashRestarts+1 {
		t.Fatalf("%d starts, limit %d", len(*calls), maxCrashRestarts+1)
	}
}

func TestWatchdogNormalExit(t *testing.T) {
	w, calls, crashes, _ := fakeWatchdog([]int{1})
	if code, ran := w.loop(); !ran || code != 1 || len(*calls) != 1 || *crashes != 0 {
		t.Fatalf("code %d ran %v calls %d crashes %d", code, ran, len(*calls), *crashes)
	}
}

func TestWatchdogCannotStart(t *testing.T) {
	w := &watchdog{run: func([]string) (int, error) { return 0, os.ErrNotExist }, sleep: func(time.Duration) {}, now: time.Now,
		onCrash: func(int) {}, giveUp: func(int) {}}
	if _, ran := w.loop(); ran {
		t.Fatal("ran = true although the core could not start")
	}
}

// ---------- app.go: instance file ----------

func TestReadInstanceLine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(instanceFile(dir), []byte("127.0.0.1:9090\r\ntok123\n127.0.0.1:1082"), 0o600); err != nil {
		t.Fatal(err)
	}
	if readInstance(dir) != "127.0.0.1:9090" || readInstanceLine(dir, 1) != "tok123" || readInstanceLine(dir, 2) != "127.0.0.1:1082" || readInstanceLine(dir, 5) != "" {
		t.Fatalf("got %q %q %q", readInstance(dir), readInstanceLine(dir, 1), readInstanceLine(dir, 2))
	}
	// 1.0.6 and older wrote only the UI address
	_ = os.WriteFile(instanceFile(dir), []byte("127.0.0.1:9091"), 0o600)
	if readInstance(dir) != "127.0.0.1:9091" || readInstanceLine(dir, 2) != "" {
		t.Fatal("old format")
	}
}

// ---------- report.go ----------

func TestRedactSettings(t *testing.T) {
	in := `{"proxy":{"upstream":"socks5://user:secretpw@10.0.0.1:1080"},"share":{"password":"hunter2","enabled":true},"general":{"api_token":"abc"},"routing":{"mode":"rules"}}`
	out := string(redactSettings([]byte(in)))
	for _, bad := range []string{"secretpw", "hunter2", "\"abc\""} {
		if strings.Contains(out, bad) {
			t.Errorf("secret %s left in %s", bad, out)
		}
	}
	if !strings.Contains(out, "\"rules\"") || !strings.Contains(out, "10.0.0.1:1080") {
		t.Errorf("too much removed: %s", out)
	}
}

func TestMakeReport(t *testing.T) {
	a := testApp(t)
	out := t.TempDir()
	old := reportDirFor
	reportDirFor = func(string) string { return out }
	t.Cleanup(func() { reportDirFor = old })
	setCfg(a, func(c *Config) { c.Share.Password = "topsecret" })
	if err := a.cfg.save(); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(a.dataDir, "warp-identity.json"), []byte(`{"private_key":"KEYKEYKEY"}`), 0o600)
	_ = os.WriteFile(crashLogPath(a.dataDir), []byte("panic: test\n"), 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, err := a.makeReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		rc, _ := f.Open()
		var b bytes.Buffer
		_, _ = b.ReadFrom(rc)
		rc.Close()
		if strings.Contains(b.String(), "topsecret") || strings.Contains(b.String(), "KEYKEYKEY") {
			t.Errorf("%s contains a secret", f.Name)
		}
	}
	for _, n := range []string{"README.txt", "selftest.txt", "state.json", "settings.json", "crash.log"} {
		if !names[n] {
			t.Errorf("no %s in the report (%v)", n, names)
		}
	}
	if names["warp-identity.json"] {
		t.Error("WARP key in the report")
	}
}

// ---------- selftest.go ----------

func TestFormatChecks(t *testing.T) {
	cs := []check{{"А", "ok", "да"}, {"Б", "warn", "так себе"}}
	if checksFailed(cs) {
		t.Fatal("warn counted as failure")
	}
	if s := formatChecks(cs); !strings.Contains(s, "✓") || !strings.Contains(s, "так себе") {
		t.Fatalf("formatChecks = %q", s)
	}
	if !checksFailed(append(cs, check{"В", "fail", "нет"})) {
		t.Fatal("fail not counted")
	}
}

func TestOfflineSelftest(t *testing.T) {
	if cs := offlineSelftest(t.TempDir()); len(cs) == 0 {
		t.Fatal("no checks")
	}
}

// ---------- netwatch.go ----------

func TestNetWatchStep(t *testing.T) {
	a := testApp(t)
	w := newNetWatch(a)
	ip := "192.168.1.5"
	now := time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC)
	w.probe = func() string { return ip }
	w.now = func() time.Time { return now }
	var mu sync.Mutex
	var events []string
	w.onEvent = func(kind, text string) { mu.Lock(); events = append(events, kind); mu.Unlock() }
	w.ip = ip

	w.step("", 5*time.Second) // nothing changed
	ip = "10.0.0.7"
	w.step("", 5*time.Second) // network changed
	w.step("resume", 0)       // woke up
	now = now.Add(10 * time.Second)
	w.step("resume", 0) // duplicate resume message: ignored
	now = now.Add(5 * time.Minute)
	w.step("", 40*time.Second) // a gap in ticks: slept again
	ip = ""
	w.step("", 5*time.Second) // network gone: wait, no recovery
	want := []string{"net", "resume", "resume"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %q, want %q", events, want)
	}
	v := w.view()
	if v["changes"] != 1 || v["resumes"] != 2 {
		t.Fatalf("view = %v", v)
	}
}

func TestNetWatchNil(t *testing.T) {
	var w *netWatch
	w.Kick("resume")
	w.suspended()
	if w.view() != nil {
		t.Fatal("nil view")
	}
}

// ---------- config.go: udp.mode ----------

func TestUDPModeSetting(t *testing.T) {
	a := testApp(t)
	if a.udpMode() != "route" {
		t.Fatalf("default udp mode %q", a.udpMode())
	}
	a.cfg.setKey("udp.mode", "off")
	a.cfg.setKey("udp.mode", "nonsense") // ignored
	if a.udpMode() != "off" || a.cfg.values()["udp.mode"] != "off" {
		t.Fatalf("udp mode %q", a.udpMode())
	}
}

// ---------- router.go: per-program and «always» rules ----------

func TestAppMatches(t *testing.T) {
	list := []string{"Telegram.exe", "chrome"}
	for app, want := range map[string]bool{
		"telegram.exe": true, "Telegram": true, `C:\Users\u\AppData\Roaming\Telegram Desktop\Telegram.exe`: true,
		"chrome.exe": true, "firefox.exe": false, "": false,
	} {
		if got := appMatches(list, app); got != want {
			t.Errorf("appMatches(%q) = %v, want %v", app, got, want)
		}
	}
}

func TestAppRules(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) {
		c.Routing.Mode = "rules"
		c.Routing.Rules = []Rule{
			{Name: "Telegram напрямую", Outbound: obDirect, Apps: []string{"Telegram.exe"}},
			{Name: "Игра", Outbound: obDirect, Apps: []string{"game.exe"}, Ports: []int{27015}, Always: true},
		}
	})
	if ob, name := a.router.matchRuleFor("example.com", 443, "Telegram.exe", false); ob != obDirect || name != "Telegram напрямую" {
		t.Fatalf("Telegram: %q %q", ob, name)
	}
	if ob, _ := a.router.matchRuleFor("example.com", 443, "chrome.exe", false); ob != "" {
		t.Fatalf("chrome matched an app rule: %q", ob)
	}
	if ob, _ := a.router.matchRule("example.com", 443); ob != "" {
		t.Fatalf("unknown program matched an app rule: %q", ob)
	}
	if ob, _ := a.router.matchRuleFor("x.com", 443, "game.exe", false); ob != "" {
		t.Fatal("port condition ignored")
	}
	// Раздел 2.1 ТЗ: пользовательские правила (где !Disabled) проверяются первыми во всех режимах, включая «psiphon»
	setCfg(a, func(c *Config) { c.Routing.Mode = "psiphon" })
	order, rule := a.router.planFor("1.2.3.4", 27015, "game.exe")
	if len(order) == 0 || order[0] != obDirect || rule != "Игра" {
		t.Fatalf("always rule in psiphon mode: %v %q", order, rule)
	}
	order, rule = a.router.planFor("example.com", 443, "Telegram.exe")
	if len(order) == 0 || order[0] != obDirect || rule != "Telegram напрямую" {
		t.Fatalf("user rule must have priority in psiphon mode: %v %q", order, rule)
	}
	order, _ = a.router.planFor("example.com", 443, "chrome.exe")
	if len(order) == 0 || order[0] != obPsiphon {
		t.Fatalf("unmatched app in psiphon mode must default to psiphon: %v", order)
	}
	if o1, _ := a.router.plan("example.com", 443); !reflect.DeepEqual(o1, order) {
		t.Fatalf("plan and planFor differ: %v vs %v", o1, order)
	}
}

// ---------- dnsmsg.go ----------

func TestDNSMessages(t *testing.T) {
	q := dnsQuery(0x1234, "example.com.", 1)
	if binary.BigEndian.Uint16(q) != 0x1234 || !bytes.Contains(q, []byte("\x07example\x03com\x00")) {
		t.Fatalf("query % x", q)
	}
	resp := append([]byte(nil), q...)
	resp[2], resp[3] = 0x81, 0x80
	resp[7] = 1 // ANCOUNT
	resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34)
	ips, err := dnsAnswers(resp)
	if err != nil || len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("answers %v %v", ips, err)
	}
	resp[3] = 0x83 // NXDOMAIN
	if _, err := dnsAnswers(resp); err == nil {
		t.Fatal("NXDOMAIN without error")
	}
	if _, err := dnsAnswers([]byte{1, 2}); err == nil {
		t.Fatal("short message without error")
	}
}

// ---------- udp.go ----------

func TestSocksUDPHeader(t *testing.T) {
	for _, c := range []struct {
		host string
		port int
	}{{"1.2.3.4", 53}, {"2001:db8::1", 443}, {"example.com", 3478}} {
		pkt := append(append([]byte{0, 0, 0}, socksAddr(c.host, c.port)...), "data"...)
		h, p, d, ok := parseSocksUDP(pkt)
		if !ok || h != c.host || p != c.port || string(d) != "data" {
			t.Errorf("%s:%d -> %q %d %q %v", c.host, c.port, h, p, d, ok)
		}
	}
	for _, bad := range [][]byte{{0, 0, 1, 1, 1, 2, 3, 4, 0, 53}, {0, 0, 0, 9}, {0, 0, 0, 1, 1, 2, 3, 4, 0, 0}, {0, 0, 0, 3, 0}} {
		if _, _, _, ok := parseSocksUDP(bad); ok {
			t.Errorf("accepted % x", bad)
		}
	}
}

func TestUDPGWFraming(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(udpgwKeepalive())
	buf.Write(udpgwEncode(0, 7, net.ParseIP("8.8.8.8"), 53, []byte("q4")))
	buf.Write(udpgwEncode(udpgwFlagDNS, 9, net.ParseIP("2001:db8::2"), 443, []byte("q6")))
	rb := make([]byte, udpgwMaxData+64)
	fl, id, ip, port, data, err := udpgwRead(&buf, rb)
	if err != nil || id != 7 || ip.String() != "8.8.8.8" || port != 53 || string(data) != "q4" || fl&udpgwFlagIPv6 != 0 {
		t.Fatalf("v4: %d %d %v %d %q %v", fl, id, ip, port, data, err)
	}
	fl, id, ip, port, data, err = udpgwRead(&buf, rb)
	if err != nil || id != 9 || ip.String() != "2001:db8::2" || port != 443 || string(data) != "q6" || fl&udpgwFlagIPv6 == 0 || fl&udpgwFlagDNS == 0 {
		t.Fatalf("v6: %d %d %v %d %q %v", fl, id, ip, port, data, err)
	}
	if _, _, _, _, _, err := udpgwRead(bytes.NewReader([]byte{1, 0, 0}), rb); err == nil {
		t.Fatal("bad length accepted")
	}
}

// UDP ASSOCIATE end to end: client -> Psiroute (direct) -> local echo.
func TestUDPAssociateDirect(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) { c.UDP.Mode = "direct" })

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(append([]byte("echo:"), b[:n]...), from)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go a.handleConn(c, nil)
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := ioReadFull(c, rep[:2]); err != nil || rep[1] != 0 {
		t.Fatalf("method reply % x %v", rep[:2], err)
	}
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if _, err := ioReadFull(c, rep); err != nil || rep[1] != 0 || rep[3] != 1 {
		t.Fatalf("associate reply % x %v", rep, err)
	}
	bnd := &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:]))}

	u, err := net.DialUDP("udp", nil, bnd)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	eport := echo.LocalAddr().(*net.UDPAddr).Port
	pkt := append(append([]byte{0, 0, 0}, socksAddr("127.0.0.1", eport)...), "hello"...)
	_ = u.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := u.Write(pkt); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2048)
	n, err := u.Read(b)
	if err != nil {
		t.Fatalf("no UDP reply: %v", err)
	}
	h, p, d, ok := parseSocksUDP(b[:n])
	if !ok || h != "127.0.0.1" || p != eport || string(d) != "echo:hello" {
		t.Fatalf("reply %q %d %q %v", h, p, d, ok)
	}
}

func TestUDPAssociateOff(t *testing.T) {
	a := testApp(t)
	setCfg(a, func(c *Config) { c.UDP.Mode = "off" })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			a.handleConn(c, nil)
		}
	}()
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	_ = cl.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = cl.Write([]byte{5, 1, 0})
	rep := make([]byte, 10)
	if _, err := ioReadFull(cl, rep[:2]); err != nil {
		t.Fatal(err)
	}
	_, _ = cl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if _, err := ioReadFull(cl, rep); err != nil || rep[1] != 7 {
		t.Fatalf("reply % x %v, want code 7", rep, err)
	}
}

func ioReadFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
