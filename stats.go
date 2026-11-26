package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tracked is one proxied connection, live or recently closed.
type tracked struct {
	protocol  string
	id        int64
	app       string
	host      string
	sni       string
	key       string // byHost key fixed at open, so open/close hit one entry
	port      int
	outbound  string
	rule      string
	err       string
	start     time.Time
	end       time.Time
	up        atomic.Int64
	down      atomic.Int64
	chanCode  atomic.Int32
	closersMu sync.Mutex
	forced    bool
	closers   []io.Closer
}

func outboundChanCode(ob string) int32 {
	switch normStatsChannel(ob) {
	case obPsiphon:
		return 1
	case obWarp:
		return 2
	case obProxy:
		return 3
	default:
		return 0
	}
}

func chanKeyFromCode(code int32) string {
	switch code {
	case 1:
		return obPsiphon
	case 2:
		return obWarp
	case 3:
		return obProxy
	default:
		return obDirect
	}
}

func (t *tracked) addCloser(c io.Closer) {
	if t == nil || c == nil {
		return
	}
	t.closersMu.Lock()
	if t.forced {
		t.closersMu.Unlock()
		_ = c.Close()
		return
	}
	t.closers = append(t.closers, c)
	t.closersMu.Unlock()
}

func (t *tracked) forceClose() {
	if t == nil {
		return
	}
	t.closersMu.Lock()
	t.forced = true
	list := append([]io.Closer(nil), t.closers...)
	t.closers = nil
	t.closersMu.Unlock()
	for _, c := range list {
		_ = c.Close()
	}
}

func (t *tracked) view() map[string]any {
	end := t.end
	if end.IsZero() {
		end = time.Now()
	}
	proto := t.protocol
	if proto == "" {
		proto = "tcp"
	}
	m := map[string]any{
		"id": t.id, "proto": proto, "app": t.app, "host": t.host, "sni": t.sni, "port": t.port,
		"outbound": t.outbound, "rule": t.rule, "up": t.up.Load(), "down": t.down.Load(),
		"age": int64(end.Sub(t.start).Seconds()),
	}
	if t.err != "" {
		m["error"] = t.err
	}
	return m
}

type agg struct {
	conns    int
	up, down int64
	outbound string
}

// Stats counts traffic per connection, outbound, application, host and day.
type recentConn struct {
	Time     string `json:"time"`
	Proto    string `json:"proto,omitempty"`
	App      string `json:"app"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Outbound string `json:"outbound"`
	Rule     string `json:"rule"`
	Hits     int    `json:"hits"`
	Up       int64  `json:"up"`
	Down     int64  `json:"down"`
	Error    string `json:"error,omitempty"`
}

// channelTrafficCounters хранит атомарные счётчики сессии и за всё время по каналам (psiphon, warp, direct, proxy).
type channelTrafficCounters struct {
	sessionUp    atomic.Int64
	sessionDown  atomic.Int64
	lifetimeUp   atomic.Int64
	lifetimeDown atomic.Int64
}

// persistedTrafficStats сохраняется в filepath.Join(dataDir, "traffic_stats.json")
// каждые 30 секунд и при корректном выходе из программы.
type persistedTrafficStats struct {
	LifetimeUp   int64               `json:"lifetime_up"`
	LifetimeDown int64               `json:"lifetime_down"`
	PsiphonBytes int64               `json:"psiphon_bytes"`
	WarpBytes    int64               `json:"warp_bytes"`
	DirectBytes  int64               `json:"direct_bytes"`
	Channels     map[string][2]int64 `json:"channels,omitempty"`
	UpdatedAt    int64               `json:"updated_at"`
}

type Stats struct {
	mu       sync.Mutex
	nextID   int64
	live     map[int64]*tracked
	closed   []*tracked
	recent   []recentConn
	byOb     map[string]*agg
	byApp    map[string]*agg
	byHost   map[string]*agg
	totUp    atomic.Int64 // SessionUpBytes
	totDown  atomic.Int64 // SessionDownBytes
	lifeUp   atomic.Int64 // LifetimeUpBytes
	lifeDown atomic.Int64 // LifetimeDownBytes
	chans    map[string]*channelTrafficCounters
	lastUp   int64
	lastDown int64
	spUp     int64
	spDown   int64
	hist     [][2]int64
	days     map[string]*[2]int64
	dayFile  string
	statFile string
	ticks    int
}

func normStatsChannel(ob string) string {
	ob = strings.ToLower(strings.TrimSpace(ob))
	switch {
	case strings.HasPrefix(ob, "psiphon"):
		return obPsiphon
	case ob == obWarp:
		return obWarp
	case ob == obProxy:
		return obProxy
	default:
		return obDirect
	}
}

func newStats(dayFile string) *Stats {
	statFile := ""
	if dayFile != "" {
		statFile = filepath.Join(filepath.Dir(dayFile), "traffic_stats.json")
	}
	s := &Stats{
		live:     map[int64]*tracked{},
		byOb:     map[string]*agg{},
		byApp:    map[string]*agg{},
		byHost:   map[string]*agg{},
		days:     map[string]*[2]int64{},
		dayFile:  dayFile,
		statFile: statFile,
		chans: map[string]*channelTrafficCounters{
			obPsiphon: {},
			obWarp:    {},
			obDirect:  {},
			obProxy:   {},
		},
	}
	if b, err := os.ReadFile(dayFile); err == nil {
		var d map[string][2]int64
		if json.Unmarshal(b, &d) == nil {
			for k, v := range d {
				v := v
				s.days[k] = &v
			}
		}
	}
	s.loadPersistedTraffic()
	return s
}

func (s *Stats) loadPersistedTraffic() {
	if s.statFile != "" {
		if b, err := os.ReadFile(s.statFile); err == nil {
			var st persistedTrafficStats
			if json.Unmarshal(b, &st) == nil {
				if st.LifetimeUp > 0 {
					s.lifeUp.Store(st.LifetimeUp)
				}
				if st.LifetimeDown > 0 {
					s.lifeDown.Store(st.LifetimeDown)
				}
				for k, pair := range st.Channels {
					ck := normStatsChannel(k)
					if cc, ok := s.chans[ck]; ok {
						cc.lifetimeUp.Store(pair[0])
						cc.lifetimeDown.Store(pair[1])
					}
				}
				return
			}
		}
	}
	var sumU, sumD int64
	for _, v := range s.days {
		if v != nil {
			sumU += v[0]
			sumD += v[1]
		}
	}
	if sumU > 0 || sumD > 0 {
		s.lifeUp.Store(sumU)
		s.lifeDown.Store(sumD)
	}
}

// closeAffectedSessions принудительно закрывает активные TCP/UDP сессии, чей маршрут
// изменился после редактирования правил или смены маршрута приложения.
func (s *Stats) closeAffectedSessions(shouldClose func(t *tracked) bool) int {
	if s == nil || shouldClose == nil {
		return 0
	}
	s.mu.Lock()
	list := make([]*tracked, 0, len(s.live))
	for _, t := range s.live {
		list = append(list, t)
	}
	s.mu.Unlock()
	closed := 0
	for _, t := range list {
		if shouldClose(t) {
			t.forceClose()
			closed++
		}
	}
	return closed
}

func bump(m map[string]*agg, k string, conns int, up, down int64) *agg {
	if k == "" {
		k = "—"
	}
	a := m[k]
	if a == nil {
		a = &agg{}
		m[k] = a
	}
	a.conns += conns
	a.up += up
	a.down += down
	return a
}

func (s *Stats) open(app, host, sni string, port int, outbound, rule string) *tracked {
	return s.openProto("tcp", app, host, sni, port, outbound, rule)
}

func (s *Stats) openProto(proto, app, host, sni string, port int, outbound, rule string) *tracked {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	t := &tracked{protocol: proto, id: s.nextID, app: app, host: host, sni: sni, port: port, outbound: outbound, rule: rule, start: time.Now()}
	t.chanCode.Store(outboundChanCode(outbound))
	s.live[t.id] = t
	bump(s.byOb, outbound, 1, 0, 0)
	bump(s.byApp, app, 1, 0, 0)
	t.key = displayHost(t)
	if len(s.byHost) > 5000 { // long sessions: do not grow without bound
		s.byHost = map[string]*agg{}
	}
	bump(s.byHost, t.key, 1, 0, 0).outbound = outbound
	// Record in unique recent connections ring buffer (max 150 entries)
	s.upsertRecentLocked(t, "", true, 0, 0, "")
	return t
}

func (s *Stats) upsertRecentLocked(t *tracked, prevKey string, newHit bool, addUp, addDown int64, errStr string) {
	if t == nil || t.key == "" || t.key == "—" {
		return
	}
	nowStr := t.start.Format("15:04:05")
	proto := t.protocol
	if proto == "" {
		proto = "tcp"
	}
	foundIdx := -1
	for i := range s.recent {
		if (s.recent[i].Host == t.key || (prevKey != "" && s.recent[i].Host == prevKey)) && s.recent[i].App == t.app {
			foundIdx = i
			break
		}
	}
	if foundIdx >= 0 {
		rc := s.recent[foundIdx]
		rc.Host = t.key
		rc.Proto = proto
		rc.Port = t.port
		rc.Outbound = t.outbound
		rc.Rule = t.rule
		if newHit {
			rc.Time = nowStr
			rc.Hits++
		}
		if addUp > 0 {
			rc.Up += addUp
		}
		if addDown > 0 {
			rc.Down += addDown
		}
		if errStr != "" {
			rc.Error = errStr
		}
		if newHit {
			copy(s.recent[1:foundIdx+1], s.recent[0:foundIdx])
			s.recent[0] = rc
		} else {
			s.recent[foundIdx] = rc
		}
		return
	}
	hits := 1
	if !newHit {
		hits = 1
	}
	rc := recentConn{
		Time:     nowStr,
		Proto:    proto,
		App:      t.app,
		Host:     t.key,
		Port:     t.port,
		Outbound: t.outbound,
		Rule:     t.rule,
		Hits:     hits,
		Up:       addUp,
		Down:     addDown,
		Error:    errStr,
	}
	s.recent = append([]recentConn{rc}, s.recent...)
	if len(s.recent) > 150 {
		s.recent = s.recent[:150]
	}
}

func displayHost(t *tracked) string {
	if t.sni != "" {
		return t.sni
	}
	return t.host
}

func (s *Stats) close(t *tracked, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.live[t.id]; !ok {
		return
	}
	delete(s.live, t.id)
	t.end = time.Now()
	t.closersMu.Lock()
	t.closers = nil
	t.closersMu.Unlock()
	if err != nil {
		t.err = short(err.Error(), 160)
	}
	up, down := t.up.Load(), t.down.Load()
	bump(s.byOb, t.outbound, 0, up, down)
	bump(s.byApp, t.app, 0, up, down)
	bump(s.byHost, t.key, 0, up, down)
	s.upsertRecentLocked(t, "", false, up, down, t.err)
	s.closed = append(s.closed, t)
	if len(s.closed) > 300 {
		s.closed = s.closed[len(s.closed)-300:]
	}
}

func (s *Stats) setRoute(t *tracked, outbound, rule string) {
	if s == nil || t == nil {
		return
	}
	s.mu.Lock()
	t.outbound = outbound
	t.rule = rule
	t.chanCode.Store(outboundChanCode(outbound))
	s.upsertRecentLocked(t, "", false, 0, 0, "")
	s.mu.Unlock()
}

func (s *Stats) routeAndHost(t *tracked) (targetHost, host string, port int, app, outbound string) {
	if s == nil || t == nil {
		return "", "", 0, "", ""
	}
	s.mu.Lock()
	targetHost = t.sni
	if targetHost == "" {
		targetHost = t.host
	}
	host = t.host
	port = t.port
	app = t.app
	outbound = t.outbound
	s.mu.Unlock()
	return
}

func (s *Stats) add(t *tracked, up, down int64) {
	ck := obDirect
	if t != nil {
		ck = chanKeyFromCode(t.chanCode.Load())
	}
	cc := s.chans[ck]
	if up > 0 {
		if t != nil {
			t.up.Add(up)
		}
		s.totUp.Add(up)
		s.lifeUp.Add(up)
		if cc != nil {
			cc.sessionUp.Add(up)
			cc.lifetimeUp.Add(up)
		}
	}
	if down > 0 {
		if t != nil {
			t.down.Add(down)
		}
		s.totDown.Add(down)
		s.lifeDown.Add(down)
		if cc != nil {
			cc.sessionDown.Add(down)
			cc.lifetimeDown.Add(down)
		}
	}
}

// tick runs once a second: speed, speed history, per-day totals.
func (s *Stats) tick() {
	up, down := s.totUp.Load(), s.totDown.Load()
	s.mu.Lock()
	s.spUp, s.spDown = up-s.lastUp, down-s.lastDown
	s.lastUp, s.lastDown = up, down
	s.hist = append(s.hist, [2]int64{s.spUp, s.spDown})
	if len(s.hist) > 120 {
		s.hist = s.hist[len(s.hist)-120:]
	}
	day := time.Now().Format("2006-01-02")
	d := s.days[day]
	if d == nil {
		d = &[2]int64{}
		s.days[day] = d
	}
	d[0] += s.spUp
	d[1] += s.spDown
	s.ticks++
	save := s.ticks%30 == 0
	var snap map[string][2]int64
	if save {
		snap = map[string][2]int64{}
		for k, v := range s.days {
			snap[k] = *v
		}
	}
	s.mu.Unlock()
	if save {
		s.persistToDisk(snap)
	}
}

func (s *Stats) persistToDisk(daySnap map[string][2]int64) {
	if s == nil {
		return
	}
	if daySnap == nil && s.dayFile != "" {
		up, down := s.totUp.Load(), s.totDown.Load()
		s.mu.Lock()
		du, dd := up-s.lastUp, down-s.lastDown
		if du > 0 || dd > 0 {
			s.lastUp, s.lastDown = up, down
			day := time.Now().Format("2006-01-02")
			d := s.days[day]
			if d == nil {
				d = &[2]int64{}
				s.days[day] = d
			}
			d[0] += du
			d[1] += dd
		}
		daySnap = map[string][2]int64{}
		for k, v := range s.days {
			if v != nil {
				daySnap[k] = *v
			}
		}
		s.mu.Unlock()
	}
	if s.dayFile != "" && daySnap != nil {
		if b, err := json.Marshal(daySnap); err == nil {
			_ = writeFileAtomic(s.dayFile, b, 0o600)
		}
	}
	if s.statFile != "" {
		chMap := make(map[string][2]int64, len(s.chans))
		for k, cc := range s.chans {
			chMap[k] = [2]int64{cc.lifetimeUp.Load(), cc.lifetimeDown.Load()}
		}
		psiBytes := chMap[obPsiphon][0] + chMap[obPsiphon][1]
		warpBytes := chMap[obWarp][0] + chMap[obWarp][1]
		dirBytes := chMap[obDirect][0] + chMap[obDirect][1]
		st := persistedTrafficStats{
			LifetimeUp:   s.lifeUp.Load(),
			LifetimeDown: s.lifeDown.Load(),
			PsiphonBytes: psiBytes,
			WarpBytes:    warpBytes,
			DirectBytes:  dirBytes,
			Channels:     chMap,
			UpdatedAt:    time.Now().Unix(),
		}
		if b, err := json.MarshalIndent(st, "", "  "); err == nil {
			_ = writeFileAtomic(s.statFile, b, 0o600)
		}
	}
}

// Flush немедленно сохраняет накопленную статистику трафика на диск при выходе.
func (s *Stats) Flush() {
	if s == nil {
		return
	}
	s.persistToDisk(nil)
}

// ResetTotals обнуляет счётчики трафика за сессию, за всё время и по каналам (POST /api/stats/reset).
func (s *Stats) ResetTotals() {
	if s == nil {
		return
	}
	s.totUp.Store(0)
	s.totDown.Store(0)
	s.lifeUp.Store(0)
	s.lifeDown.Store(0)
	for _, cc := range s.chans {
		cc.sessionUp.Store(0)
		cc.sessionDown.Store(0)
		cc.lifetimeUp.Store(0)
		cc.lifetimeDown.Store(0)
	}
	s.mu.Lock()
	s.lastUp = 0
	s.lastDown = 0
	s.spUp = 0
	s.spDown = 0
	s.byOb = map[string]*agg{}
	s.byApp = map[string]*agg{}
	s.byHost = map[string]*agg{}
	s.days = map[string]*[2]int64{}
	s.mu.Unlock()
	s.persistToDisk(map[string][2]int64{})
}

func aggList(m map[string]*agg, key string, live map[string]int64) []map[string]any {
	out := make([]map[string]any, 0, len(m))
	for k, a := range m {
		x := map[string]any{key: k, "conns": a.conns, "up": a.up + live[k+"\x00u"], "down": a.down + live[k+"\x00d"]}
		if a.outbound != "" {
			x["outbound"] = a.outbound
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["up"].(int64)+out[i]["down"].(int64) > out[j]["up"].(int64)+out[j]["down"].(int64)
	})
	return out
}

// snapshot is the "stats" object of /api/state.
func (s *Stats) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	liveOb, liveApp, liveHost := map[string]int64{}, map[string]int64{}, map[string]int64{}
	live := make([]map[string]any, 0, len(s.live))
	for _, t := range s.live {
		u, d := t.up.Load(), t.down.Load()
		for _, p := range []struct {
			m map[string]int64
			k string
		}{{liveOb, t.outbound}, {liveApp, t.app}, {liveHost, displayHost(t)}} {
			k := p.k
			if k == "" {
				k = "—"
			}
			p.m[k+"\x00u"] += u
			p.m[k+"\x00d"] += d
		}
		live = append(live, t.view())
	}
	sort.Slice(live, func(i, j int) bool { return live[i]["id"].(int64) > live[j]["id"].(int64) })
	closed := make([]map[string]any, 0, len(s.closed))
	for i := len(s.closed) - 1; i >= 0; i-- {
		closed = append(closed, s.closed[i].view())
	}
	hist := make([][2]int64, len(s.hist))
	copy(hist, s.hist)
	sessUp, sessDown := s.totUp.Load(), s.totDown.Load()
	lifeUp, lifeDown := s.lifeUp.Load(), s.lifeDown.Load()
	if lifeUp < sessUp {
		lifeUp = sessUp
	}
	if lifeDown < sessDown {
		lifeDown = sessDown
	}
	channels := map[string]map[string]int64{}
	for k, cc := range s.chans {
		su, sd := cc.sessionUp.Load(), cc.sessionDown.Load()
		lu, ld := cc.lifetimeUp.Load(), cc.lifetimeDown.Load()
		channels[k] = map[string]int64{
			"session_up":    su,
			"session_down":  sd,
			"session_bytes": su + sd,
			"lifetime_up":   lu,
			"lifetime_down": ld,
			"total_bytes":   lu + ld,
		}
	}
	return map[string]any{
		"total":     map[string]any{"up": sessUp, "down": sessDown, "live": len(s.live)},
		"session":   map[string]any{"up": sessUp, "down": sessDown, "total": sessUp + sessDown},
		"lifetime":  map[string]any{"up": lifeUp, "down": lifeDown, "total": lifeUp + lifeDown},
		"channels":  channels,
		"speed":     map[string]any{"up": s.spUp, "down": s.spDown, "history": hist},
		"outbounds": aggList(s.byOb, "outbound", liveOb),
		"apps":      aggList(s.byApp, "app", liveApp),
		"hosts":     aggList(s.byHost, "host", liveHost),
		"live":      live,
		"closed":    closed,
		"recent":    append([]recentConn(nil), s.recent...),
	}
}

// fmtBytes форматирует байты в КБ / МБ / ГБ / ТБ с авто-переключением единиц.
func fmtBytes(b int64) string {
	if b < 0 {
		b = 0
	}
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
		tb = 1024 * gb
	)
	switch {
	case b >= tb:
		return fmt.Sprintf("%.2f ТБ", float64(b)/float64(tb))
	case b >= gb:
		return fmt.Sprintf("%.2f ГБ", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f МБ", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.0f КБ", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d Б", b)
	}
}

func (s *Stats) recentList() []recentConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]recentConn(nil), s.recent...)
	// Add live active byte counts on matching recent entries so paused/recent views reflect live traffic too.
	liveTotals := make(map[string][2]int64, len(s.live))
	for _, t := range s.live {
		k := t.app + "\x00" + t.key
		prev := liveTotals[k]
		prev[0] += t.up.Load()
		prev[1] += t.down.Load()
		liveTotals[k] = prev
	}
	for i := range out {
		k := out[i].App + "\x00" + out[i].Host
		if add, ok := liveTotals[k]; ok {
			out[i].Up += add[0]
			out[i].Down += add[1]
		}
	}
	return out
}

// connsList returns unified stream rows (live flows first, then recent history) for Web UI /api/conns/recent.
func (s *Stats) connsList() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	liveKeys := make(map[string]struct{}, len(s.live))
	liveRows := make([]map[string]any, 0, len(s.live))
	for _, t := range s.live {
		u, d := t.up.Load(), t.down.Load()
		proto := t.protocol
		if proto == "" {
			proto = "tcp"
		}
		h := displayHost(t)
		liveKeys[t.app+"\x00"+h] = struct{}{}
		liveRows = append(liveRows, map[string]any{
			"id":       t.id,
			"live":     true,
			"app":      t.app,
			"host":     h,
			"sni":      t.sni,
			"port":     t.port,
			"proto":    proto,
			"outbound": t.outbound,
			"rule":     t.rule,
			"rx":       d,
			"tx":       u,
			"down":     d,
			"up":       u,
			"err":      t.err,
			"time":     t.start.Format("15:04:05"),
		})
	}
	sort.Slice(liveRows, func(i, j int) bool { return liveRows[i]["id"].(int64) > liveRows[j]["id"].(int64) })
	out := make([]map[string]any, 0, len(liveRows)+len(s.recent))
	out = append(out, liveRows...)
	for _, rc := range s.recent {
		if _, isLive := liveKeys[rc.App+"\x00"+rc.Host]; isLive {
			continue
		}
		proto := rc.Proto
		if proto == "" {
			proto = "tcp"
		}
		out = append(out, map[string]any{
			"live":     false,
			"app":      rc.App,
			"host":     rc.Host,
			"port":     rc.Port,
			"proto":    proto,
			"outbound": rc.Outbound,
			"rule":     rc.Rule,
			"hits":     rc.Hits,
			"rx":       rc.Down,
			"tx":       rc.Up,
			"down":     rc.Down,
			"up":       rc.Up,
			"err":      rc.Error,
			"time":     rc.Time,
		})
	}
	return out
}

// history is per-day totals, newest first.
func (s *Stats) history() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.days))
	for k, v := range s.days {
		out = append(out, map[string]any{"date": k, "total": map[string]any{"up": v[0], "down": v[1]}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["date"].(string) > out[j]["date"].(string) })
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

// countConn counts bytes of a proxied connection.
type countConn struct {
	net.Conn
	s *Stats
	t *tracked
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.s.add(c.t, 0, int64(n))
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.s.add(c.t, int64(n), 0)
	return n, err
}

func (c *countConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
