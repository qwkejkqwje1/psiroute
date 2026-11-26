package main

// Obfuscation of direct connections (outbound direct-dpi), adaptive per-site
// method selection, and background DPI auto-tuning (Priority 3).
//
//   - Five ways to cut the first bytes so a DPI box can't read the host name:
//     TLS records, TCP segments, both, many records, tiny pieces. The cut
//     points are random every time, so there is no fixed signature.
//   - Plain HTTP: mixed-case "Host" header name and a cut inside the name.
//   - "auto": the method that worked for a site is remembered, the others are
//     ranked by their recent success rate.
//   - Background Auto-Tune (Priority 3): monitors a sliding window of recent
//     outcomes and consecutive failures on the active method. If the error
//     rate rises above threshold (or consecutive failures occur), obfsBook
//     automatically switches to the highest-rated healthy method and triggers
//     a lightweight background probe without requiring manual user action.
//   - If the connection is reset, closed or silently dropped before the server
//     answered the ClientHello, a fresh connection is opened with the next
//     method and the same ClientHello is sent again - the program never
//     notices. A resend is safe: the server has not answered, and nothing but
//     the ClientHello was sent.
//   - Psiphon: psiphon.dpi = "auto" rotates the fragmentation modes between
//     connection attempts and keeps the one that connected.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

type obfsMethod struct {
	id, title string
	cut       func(b []byte) [][]byte // segments to write; one segment = not applicable
	delay     time.Duration           // pause between segments
}

var obfsMethods = []obfsMethod{
	{"tlsrec", "две TLS-записи", obfsTLSRec, 3 * time.Millisecond},
	{"split", "разрез TCP", obfsSplit, 3 * time.Millisecond},
	{"double", "TLS-записи + разрез TCP", obfsDouble, 3 * time.Millisecond},
	{"multirec", "много TLS-записей", obfsMultiRec, 2 * time.Millisecond},
	{"chunk", "мелкие TCP-куски", obfsChunk, time.Millisecond},
}

func obfsByID(id string) *obfsMethod {
	for i := range obfsMethods {
		if obfsMethods[i].id == id {
			return &obfsMethods[i]
		}
	}
	return nil
}

// ---------- cutting ----------

// obfsHello splits a TLS record holding a ClientHello into the record header,
// the handshake body and the bytes after the record; sni/n locate the host
// name inside body (sni < 0 when there is none).
func obfsHello(b []byte) (hdr, body, rest []byte, sni, n int, ok bool) {
	if len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return
	}
	recLen := int(b[3])<<8 | int(b[4])
	if recLen < 8 || 5+recLen > len(b) {
		return
	}
	body = b[5 : 5+recLen]
	sni, n = findSNI(body)
	return b[:5], body, b[5+recLen:], sni, n, true
}

func obfsIsHello(b []byte) bool {
	_, _, _, _, _, ok := obfsHello(b)
	return ok
}

// obfsHelloNeed: how many bytes the first TLS record needs, to wait for a
// ClientHello that arrived in several pieces (big post-quantum hellos);
// len(b) when it is not TLS.
func obfsHelloNeed(b []byte) int {
	if len(b) == 0 || b[0] != 0x16 {
		return len(b)
	}
	if len(b) < 5 {
		return 5
	}
	if b[1] != 0x03 {
		return len(b)
	}
	return 5 + (int(b[3])<<8 | int(b[4]))
}

// obfsCut: a random cut strictly inside the host name, or 2 bytes into the
// body when there is no name.
func obfsCut(sni, n int) int {
	if sni > 0 && n > 1 {
		return sni + 1 + rand.IntN(n-1)
	}
	return 2
}

// obfsRecords re-frames a handshake body as several TLS records cut at the
// given ascending offsets (fresh slices).
func obfsRecords(hdr, body []byte, cuts ...int) [][]byte {
	out := make([][]byte, 0, len(cuts)+1)
	prev := 0
	for _, c := range append(cuts, len(body)) {
		if c <= prev || c > len(body) {
			continue
		}
		part := body[prev:c]
		r := make([]byte, 0, 5+len(part))
		r = append(r, 0x16, hdr[1], hdr[2], byte(len(part)>>8), byte(len(part)))
		out = append(out, append(r, part...))
		prev = c
	}
	return out
}

func obfsTail(segs [][]byte, rest []byte) [][]byte {
	if len(rest) > 0 && len(segs) > 0 {
		segs[len(segs)-1] = append(segs[len(segs)-1], rest...)
	}
	return segs
}

// tlsrec: two TLS records cut inside the name, each in its own TCP segment.
func obfsTLSRec(b []byte) [][]byte {
	hdr, body, rest, sni, n, ok := obfsHello(b)
	if !ok {
		return [][]byte{b}
	}
	return obfsTail(obfsRecords(hdr, body, obfsCut(sni, n)), rest)
}

// split: one TLS record, two TCP segments cut inside the name (for servers
// and boxes that dislike a fragmented ClientHello).
func obfsSplit(b []byte) [][]byte {
	_, _, _, sni, n, ok := obfsHello(b)
	if !ok {
		return [][]byte{b}
	}
	k := 5 + obfsCut(sni, n)
	return [][]byte{b[:k], b[k:]}
}

// double: two TLS records, and the second record's header with 1-3 bytes goes
// alone - against DPI that glues records but looks at single packets.
func obfsDouble(b []byte) [][]byte {
	hdr, body, rest, sni, n, ok := obfsHello(b)
	if !ok {
		return [][]byte{b}
	}
	recs := obfsTail(obfsRecords(hdr, body, obfsCut(sni, n)), rest)
	if len(recs) < 2 {
		return recs
	}
	second := recs[1]
	k := 5 + 1 + rand.IntN(3)
	if k >= len(second) {
		return recs
	}
	return [][]byte{recs[0], second[:k], second[k:]}
}

// multirec: 4-5 TLS records: a random cut before the name, at its start,
// inside it and at its end.
func obfsMultiRec(b []byte) [][]byte {
	hdr, body, rest, sni, n, ok := obfsHello(b)
	if !ok {
		return [][]byte{b}
	}
	var cuts []int
	if sni > 1 && n > 1 {
		cuts = []int{1 + rand.IntN(sni-1), sni, obfsCut(sni, n), sni + n}
	} else {
		q := len(body) / 4
		cuts = []int{q, 2 * q, 3 * q}
	}
	sort.Ints(cuts)
	return obfsTail(obfsRecords(hdr, body, cuts...), rest)
}

// chunk: the record header and the host name go out in 1-3 byte TCP pieces,
// the bytes between them in one piece.
func obfsChunk(b []byte) [][]byte {
	_, _, _, sni, n, ok := obfsHello(b)
	if !ok {
		return [][]byte{b}
	}
	var out [][]byte
	p := 0
	piece := func(to, max int) {
		if to > len(b) {
			to = len(b)
		}
		for p < to {
			sz := 1 + rand.IntN(max)
			if p+sz > to {
				sz = to - p
			}
			out = append(out, b[p:p+sz])
			p += sz
		}
	}
	if sni > 0 && n > 0 {
		piece(5, 2) // not even recognisable as TLS from the first packet
		if a := 5 + sni - 2; a > p {
			out = append(out, b[p:a])
			p = a
		}
		piece(5+sni+n+2, 3)
	} else {
		piece(64, 8)
	}
	if p < len(b) {
		out = append(out, b[p:])
	}
	return out
}

var obfsHTTPMethods = [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT ")}

func obfsLooksHTTP(b []byte) bool {
	for _, m := range obfsHTTPMethods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

// obfsIndexHost finds "\r\nhost:" in b using ASCII case-insensitive matching
// so multi-byte UTF-8 sequences before the header cannot shift byte offsets.
func obfsIndexHost(b []byte) int {
	const pat = "\r\nhost:"
	for i := 0; i+len(pat) <= len(b); i++ {
		if b[i] != '\r' || b[i+1] != '\n' || b[i+6] != ':' {
			continue
		}
		if (b[i+2]|0x20) == 'h' && (b[i+3]|0x20) == 'o' && (b[i+4]|0x20) == 's' && (b[i+5]|0x20) == 't' {
			return i
		}
	}
	return -1
}

// obfsHTTP: plain HTTP - a mixed-case "Host" header name (case-insensitive by
// the standard, many DPI boxes match it literally) and a cut inside the name.
func obfsHTTP(b []byte) [][]byte {
	lim := b
	if len(lim) > 8192 {
		lim = lim[:8192]
	}
	i := obfsIndexHost(lim)
	if i < 0 {
		return [][]byte{b}
	}
	out := append([]byte(nil), b...)
	copy(out[i+2:], "hoSt")
	v := i + 7
	for v < len(out) && (out[v] == ' ' || out[v] == '\t') {
		v++
	}
	e := v
	for e < len(out) && out[e] != '\r' && out[e] != '\n' {
		e++
	}
	cut := i + 4
	if e-v > 1 {
		cut = v + 1 + rand.IntN(e-v-1)
	}
	return [][]byte{out[:cut], out[cut:]}
}

// ---------- what works: per site, overall, and background auto-tune ----------

const (
	obfsSiteTTL           = 12 * time.Hour
	obfsMaxTries          = 3 // methods per connection
	obfsAutoTuneWindow    = 10
	obfsAutoTuneThreshold = 0.50 // 50%+ error rate in sliding window triggers auto-tune
	obfsAutoTuneMinTries  = 4    // minimum recent tries before error rate triggers switch
	obfsAutoTuneConsec    = 3    // 3 consecutive failures trigger immediate switch
	obfsAutoTuneCooldown  = 2 * time.Minute
)

type obfsScore struct {
	Ok   float64 `json:"ok"`
	Fail float64 `json:"fail"`
}

type obfsSite struct {
	method string
	exp    time.Time
}

type obfsWindowStat struct {
	outcomes    []bool
	consecFails int
}

type obfsBook struct {
	mu               sync.Mutex
	sites            map[string]obfsSite
	score            map[string]*obfsScore
	window           map[string]*obfsWindowStat
	saved            int64 // connections rescued by a resend with another method
	autoTunedMethod  string
	autoTuneSwitches int64
	lastAutoTune     time.Time
	onAutoTune       func(failedMethod, nextMethod string)
	file             string
	saveTimer        *time.Timer
}

type obfsPersist struct {
	Sites map[string]struct {
		Method string `json:"method"`
		Exp    int64  `json:"exp"`
	} `json:"sites"`
	Score            map[string]*obfsScore `json:"score"`
	Saved            int64                 `json:"saved"`
	AutoTunedMethod  string                `json:"auto_tuned_method,omitempty"`
	AutoTuneSwitches int64                 `json:"auto_tune_switches,omitempty"`
}

func (b *obfsBook) loadFile(path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.file = path
	b.initLocked()
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var p obfsPersist
	if json.Unmarshal(raw, &p) != nil {
		return
	}
	now := time.Now()
	for h, st := range p.Sites {
		exp := time.Unix(st.Exp, 0)
		if now.Before(exp) && obfsByID(st.Method) != nil {
			b.sites[h] = obfsSite{method: st.Method, exp: exp}
		}
	}
	for id, sc := range p.Score {
		if sc != nil && obfsByID(id) != nil {
			b.score[id] = &obfsScore{Ok: sc.Ok, Fail: sc.Fail}
		}
	}
	b.saved = p.Saved
	if obfsByID(p.AutoTunedMethod) != nil {
		b.autoTunedMethod = p.AutoTunedMethod
	}
	b.autoTuneSwitches = p.AutoTuneSwitches
}

func (b *obfsBook) scheduleSaveLocked() {
	if b.file == "" || b.saveTimer != nil {
		return
	}
	b.saveTimer = time.AfterFunc(3*time.Second, func() {
		b.mu.Lock()
		b.saveTimer = nil
		path := b.file
		p := obfsPersist{
			Sites: make(map[string]struct {
				Method string `json:"method"`
				Exp    int64  `json:"exp"`
			}, len(b.sites)),
			Score:            make(map[string]*obfsScore, len(b.score)),
			Saved:            b.saved,
			AutoTunedMethod:  b.autoTunedMethod,
			AutoTuneSwitches: b.autoTuneSwitches,
		}
		now := time.Now()
		for k, v := range b.sites {
			if now.Before(v.exp) {
				p.Sites[k] = struct {
					Method string `json:"method"`
					Exp    int64  `json:"exp"`
				}{Method: v.method, Exp: v.exp.Unix()}
			}
		}
		for k, v := range b.score {
			if v != nil {
				cp := *v
				p.Score[k] = &cp
			}
		}
		b.mu.Unlock()
		if raw, err := json.Marshal(p); err == nil {
			_ = writeFileAtomic(path, raw, 0o600)
		}
	})
}

var obfs = &obfsBook{}

// obfsFirstByte: no answer to the ClientHello for this long = dropped silently.
var obfsFirstByte = 6 * time.Second

func (b *obfsBook) initLocked() {
	if b.sites == nil {
		b.sites = map[string]obfsSite{}
	}
	if b.score == nil {
		b.score = map[string]*obfsScore{}
	}
	if b.window == nil {
		b.window = map[string]*obfsWindowStat{}
	}
}

// isMethodDegradedLocked checks whether method id has experienced a spike in
// failure rate or consecutive failures warranting an automatic method switch.
func (b *obfsBook) isMethodDegradedLocked(id string) (bool, float64) {
	if w := b.window[id]; w != nil {
		if w.consecFails >= obfsAutoTuneConsec {
			return true, 1.0
		}
		if len(w.outcomes) >= obfsAutoTuneMinTries {
			fails := 0
			for _, ok := range w.outcomes {
				if !ok {
					fails++
				}
			}
			rate := float64(fails) / float64(len(w.outcomes))
			if rate >= obfsAutoTuneThreshold {
				return true, rate
			}
		}
	}
	if sc := b.score[id]; sc != nil && sc.Ok+sc.Fail >= 4 {
		rate := sc.Fail / (sc.Ok + sc.Fail)
		if rate >= obfsAutoTuneThreshold {
			return true, rate
		}
	}
	return false, 0
}

// bestHealthyLocked returns the highest-scoring DPI method other than excludeID.
func (b *obfsBook) bestHealthyLocked(excludeID string) string {
	bestID := ""
	bestRate := -1.0
	for _, m := range obfsMethods {
		if m.id == excludeID {
			continue
		}
		r := 0.5
		if s := b.score[m.id]; s != nil {
			r = (s.Ok + 1) / (s.Ok + s.Fail + 2)
		}
		if deg, _ := b.isMethodDegradedLocked(m.id); deg {
			r *= 0.5
		}
		if r > bestRate {
			bestRate = r
			bestID = m.id
		}
	}
	return bestID
}

// rankedIDsLocked returns all method IDs sorted by empirical success score.
func (b *obfsBook) rankedIDsLocked(host string) []string {
	ids := make([]string, 0, len(obfsMethods))
	rate := make(map[string]float64, len(obfsMethods))
	for _, m := range obfsMethods {
		ids = append(ids, m.id)
		rate[m.id] = 0.5
		if s := b.score[m.id]; s != nil {
			rate[m.id] = (s.Ok + 1) / (s.Ok + s.Fail + 2)
		}
	}
	sort.SliceStable(ids, func(i, j int) bool { return rate[ids[i]] > rate[ids[j]] })
	if b.autoTunedMethod != "" {
		if deg, _ := b.isMethodDegradedLocked(b.autoTunedMethod); !deg {
			for i, id := range ids {
				if id == b.autoTunedMethod {
					copy(ids[1:i+1], ids[:i])
					ids[0] = id
					break
				}
			}
		}
	}
	if s, ok := b.sites[host]; ok && time.Now().Before(s.exp) {
		if deg, _ := b.isMethodDegradedLocked(s.method); !deg {
			for i, id := range ids {
				if id == s.method {
					copy(ids[1:i+1], ids[:i])
					ids[0] = id
					break
				}
			}
		}
	}
	return ids
}

// order: methods to try for host, best first. A specific method is used alone
// while healthy; if its error rate spikes (Priority 3 auto-tune), fallback
// methods are unlocked automatically with the healthier method first.
func (b *obfsBook) order(host, forced string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initLocked()
	if m := obfsByID(forced); m != nil {
		if deg, _ := b.isMethodDegradedLocked(m.id); !deg {
			return []string{m.id}
		}
		// Forced method has degraded: auto-tune unlocks ranked alternatives
		return b.rankedIDsLocked(host)
	}
	return b.rankedIDsLocked(host)
}

func (b *obfsBook) result(host, id string, ok bool) {
	var hook func(failedMethod, nextMethod string)
	var switchedTo string

	b.mu.Lock()
	b.initLocked()
	s := b.score[id]
	if s == nil {
		s = &obfsScore{}
		b.score[id] = s
	}
	// old results fade, so new DPI rules or another network show up quickly
	s.Ok *= 0.98
	s.Fail *= 0.98
	w := b.window[id]
	if w == nil {
		w = &obfsWindowStat{}
		b.window[id] = w
	}
	w.outcomes = append(w.outcomes, ok)
	if len(w.outcomes) > obfsAutoTuneWindow {
		w.outcomes = w.outcomes[len(w.outcomes)-obfsAutoTuneWindow:]
	}
	now := time.Now()
	if ok {
		s.Ok++
		w.consecFails = 0
		if host != "" {
			b.sites[host] = obfsSite{id, now.Add(obfsSiteTTL)}
		}
	} else {
		s.Fail++
		w.consecFails++
		if st, found := b.sites[host]; found && st.method == id {
			delete(b.sites, host)
		}
		// Check if background DPI auto-tune should switch away from failing method.
		// Hysteresis: the very first switch fires immediately, whereas subsequent
		// switches strictly respect obfsAutoTuneCooldown (no bypass for current method)
		// and never bounce to an already-degraded alternative.
		if deg, failRate := b.isMethodDegradedLocked(id); deg {
			alt := b.bestHealthyLocked(id)
			altDeg := alt == ""
			if !altDeg {
				altDeg, _ = b.isMethodDegradedLocked(alt)
			}
			cooldownOK := b.lastAutoTune.IsZero() || now.Sub(b.lastAutoTune) >= obfsAutoTuneCooldown
			if alt != "" && alt != id && !altDeg && cooldownOK {
				b.autoTunedMethod = alt
				b.autoTuneSwitches++
				b.lastAutoTune = now
				// Reset hysteresis window on the newly selected method alt so it starts clean,
				// while keeping failed method id marked degraded so forced orders unlock fallback.
				if aw := b.window[alt]; aw != nil {
					aw.consecFails = 0
					aw.outcomes = nil
				}
				switchedTo = alt
				hook = b.onAutoTune
				if mOld, mNew := obfsByID(id), obfsByID(alt); mOld != nil && mNew != nil {
					logf("info", "DPI авто-тюнинг: на методе «%s» вырос процент ошибок (%d%%), автоматическая смена на «%s»",
						mOld.title, int(failRate*100+0.5), mNew.title)
				}
			}
		}
	}
	if len(b.sites) > 5000 {
		for k, v := range b.sites {
			if now.After(v.exp) {
				delete(b.sites, k)
			}
		}
		if len(b.sites) > 5000 {
			b.sites = map[string]obfsSite{}
		}
	}
	b.scheduleSaveLocked()
	b.mu.Unlock()

	if hook != nil && switchedTo != "" {
		hook(id, switchedTo)
	}
}

func (b *obfsBook) setAutoTunedMethod(id string) {
	if obfsByID(id) == nil {
		return
	}
	b.mu.Lock()
	b.initLocked()
	if b.autoTunedMethod != id {
		b.autoTunedMethod = id
		b.autoTuneSwitches++
		b.lastAutoTune = time.Now()
		b.scheduleSaveLocked()
	}
	if w := b.window[id]; w != nil {
		w.consecFails = 0
	}
	b.mu.Unlock()
}

func (b *obfsBook) currentAutoTuned() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.autoTunedMethod
}

func (b *obfsBook) rescued() {
	b.mu.Lock()
	b.saved++
	b.mu.Unlock()
}

func (b *obfsBook) reset() {
	b.mu.Lock()
	b.sites, b.score, b.window, b.saved = nil, nil, nil, 0
	b.autoTunedMethod, b.autoTuneSwitches, b.lastAutoTune = "", 0, time.Time{}
	b.mu.Unlock()
}

func (b *obfsBook) view() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	list := make([]map[string]any, 0, len(obfsMethods))
	for _, m := range obfsMethods {
		var ok, fail float64
		if s := b.score[m.id]; s != nil {
			ok, fail = s.Ok, s.Fail
		}
		deg, _ := b.isMethodDegradedLocked(m.id)
		row := map[string]any{
			"id":       m.id,
			"title":    m.title,
			"ok":       int(ok + 0.5),
			"fail":     int(fail + 0.5),
			"degraded": deg,
		}
		if ok+fail >= 1 {
			row["rate"] = int(ok/(ok+fail)*100 + 0.5)
		}
		list = append(list, row)
	}
	return map[string]any{
		"methods":            list,
		"sites":              len(b.sites),
		"saved":              b.saved,
		"auto_tuned_method":  b.autoTunedMethod,
		"auto_tune_switches": b.autoTuneSwitches,
	}
}

// obfsView: the state for the UI.
func (a *App) obfsView() map[string]any {
	v := obfs.view()
	a.cfg.mu.Lock()
	dpi, method := a.cfg.Psiphon.DPI, a.cfg.Desync.Method
	a.cfg.mu.Unlock()
	v["method"] = method
	v["mode"] = a.dpiMode()
	if dpi == "auto" && a.psi != nil {
		v["psi_dpi"] = psiDPINames[a.psi.dpiAuto.current()]
	}
	return v
}

// ---------- the connection ----------

type obfsConn struct {
	network, addr, forced string

	mu       sync.Mutex
	c        net.Conn
	buf      []byte // first bytes, collected until the ClientHello is whole
	flushT   *time.Timer
	sent     bool   // the first bytes are out
	hello    []byte // ClientHello for a resend; nil when a resend is no longer safe
	host     string
	order    []string
	idx      int  // order[idx] is in use
	applied  bool // a TLS ClientHello went out with order[idx]
	judged   bool // the result of order[idx] is recorded
	answered bool
	closed   bool
	fbArmed  bool
	rd, wd   time.Time // deadlines set by the program
}

func obfsDialRaw(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: directControl}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return c, nil
}

// dialObfs: a direct connection with DPI obfuscation; method is "auto" or an id.
func dialObfs(ctx context.Context, network, addr, method string) (net.Conn, error) {
	c, err := obfsDialRaw(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &obfsConn{network: network, addr: addr, forced: method, c: c}, nil
}

// dialDesync: the automatic choice (DoH and other internal users).
func dialDesync(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialObfs(ctx, network, addr, "auto")
}

func (o *obfsConn) canRetryLocked() bool {
	return !o.answered && o.hello != nil && o.idx+1 < len(o.order) && o.idx+1 < obfsMaxTries
}

func (o *obfsConn) armFirstByteLocked() {
	if !o.canRetryLocked() {
		return
	}
	t := time.Now().Add(obfsFirstByte)
	if o.rd.IsZero() || o.rd.After(t) {
		o.fbArmed = true
		_ = o.c.SetReadDeadline(t)
	}
}

func (o *obfsConn) Write(b []byte) (int, error) {
	o.mu.Lock()
	if o.sent || o.closed {
		if !o.answered {
			o.hello = nil // more data before the answer: a resend is no longer safe
		}
		c := o.c
		o.mu.Unlock()
		return c.Write(b)
	}
	defer o.mu.Unlock()
	o.buf = append(o.buf, b...)
	if need := obfsHelloNeed(o.buf); need > len(o.buf) && need <= 5+16<<10 {
		if o.flushT == nil {
			o.flushT = time.AfterFunc(150*time.Millisecond, o.flushLate)
		}
		return len(b), nil
	}
	if o.flushT != nil {
		o.flushT.Stop()
	}
	if err := o.first(); err != nil {
		if o.applied && o.hello != nil {
			if !o.judged {
				o.judged = true
				obfs.result(o.host, o.order[o.idx], false)
			}
			if o.retryLocked() == nil {
				return len(b), nil
			}
		}
		return 0, err
	}
	return len(b), nil
}

// flushLate: the rest of the ClientHello never came - send what there is.
func (o *obfsConn) flushLate() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.sent && !o.closed && len(o.buf) > 0 {
		_ = o.first() // a Read reports the failure
	}
}

// first sends the collected first bytes (o.mu held).
func (o *obfsConn) first() error {
	b := o.buf
	o.buf, o.sent = nil, true
	if obfsIsHello(b) {
		o.host = parseSNI(b)
		if o.host == "" {
			o.host, _, _ = net.SplitHostPort(o.addr)
		}
		o.order = obfs.order(o.host, o.forced)
		o.hello, o.applied = b, true
	}
	if err := o.send(o.c, b); err != nil {
		return err
	}
	o.armFirstByteLocked()
	return nil
}

// send writes the first bytes to c with the method in use (o.mu held).
func (o *obfsConn) send(c net.Conn, b []byte) error {
	segs, delay := [][]byte{b}, time.Duration(0)
	switch {
	case o.applied:
		if m := obfsByID(o.order[o.idx]); m != nil {
			segs, delay = m.cut(b), m.delay
		}
	case obfsLooksHTTP(b):
		segs, delay = obfsHTTP(b), 3*time.Millisecond
	}
	for i, s := range segs {
		if i > 0 && delay > 0 {
			time.Sleep(delay)
		}
		if _, err := c.Write(s); err != nil {
			return err
		}
	}
	return nil
}

// retryLocked: a fresh connection with the next method and the same
// ClientHello. Called with o.mu held; releases it while dialing.
func (o *obfsConn) retryLocked() error {
	for o.canRetryLocked() {
		prev, next, hello := o.order[o.idx], o.order[o.idx+1], o.hello
		o.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		c, err := obfsDialRaw(ctx, o.network, o.addr)
		cancel()
		o.mu.Lock()
		if err == nil && (o.closed || o.hello == nil) {
			_ = c.Close()
			err = net.ErrClosed
		}
		if err != nil {
			o.hello = nil
			return err
		}
		o.idx++
		o.judged = false
		o.fbArmed = false
		if !o.wd.IsZero() {
			_ = c.SetWriteDeadline(o.wd)
		}
		if !o.rd.IsZero() {
			_ = c.SetReadDeadline(o.rd)
		}
		if err := o.send(c, hello); err != nil {
			o.judged = true
			obfs.result(o.host, next, false)
			_ = c.Close()
			continue
		}
		old := o.c
		o.c = c
		o.armFirstByteLocked()
		_ = old.Close()
		logf("info", "%s: DPI-обход «%s» не прошёл, повторяю с «%s»", o.host, obfsByID(prev).title, obfsByID(next).title)
		return nil
	}
	o.hello = nil
	return errors.New("способы обхода закончились")
}

func (o *obfsConn) Read(p []byte) (int, error) {
	for {
		o.mu.Lock()
		c := o.c
		if o.answered || o.closed {
			o.mu.Unlock()
			return c.Read(p)
		}
		o.armFirstByteLocked()
		o.mu.Unlock()

		n, err := c.Read(p)

		o.mu.Lock()
		if !o.closed && o.c != c && n == 0 {
			// Write already replaced o.c during a retry; read from the new socket.
			o.mu.Unlock()
			continue
		}
		wasArmed := o.fbArmed
		if o.fbArmed {
			o.fbArmed = false
			_ = o.c.SetReadDeadline(o.rd)
		}
		if n > 0 {
			if !o.answered {
				o.answered, o.hello = true, nil
				if o.applied && !o.judged {
					o.judged = true
					obfs.result(o.host, o.order[o.idx], true)
					if o.idx > 0 {
						obfs.rescued()
					}
				}
			}
			o.mu.Unlock()
			return n, err
		}
		if err == nil || o.closed || !o.applied {
			o.mu.Unlock()
			return n, err
		}
		ours := wasArmed && isTimeout(err) && (o.rd.IsZero() || time.Now().Before(o.rd))
		if !ours && !isConnReset(err) && !errors.Is(err, io.EOF) {
			o.mu.Unlock()
			return n, err
		}
		if !o.judged {
			o.judged = true
			obfs.result(o.host, o.order[o.idx], false)
		}
		if o.hello != nil && o.retryLocked() == nil {
			o.mu.Unlock()
			continue
		}
		o.mu.Unlock()
		if ours {
			continue // no methods left: our own timer must not end the connection
		}
		return n, err
	}
}

func (o *obfsConn) Close() error {
	o.mu.Lock()
	o.closed = true
	if o.flushT != nil {
		o.flushT.Stop()
	}
	c := o.c
	o.mu.Unlock()
	return c.Close()
}

func (o *obfsConn) CloseWrite() error {
	o.mu.Lock()
	if !o.sent && len(o.buf) > 0 {
		_ = o.first()
	}
	o.hello = nil
	c := o.c
	o.mu.Unlock()
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (o *obfsConn) cur() net.Conn {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.c
}

func (o *obfsConn) underlyingConn() net.Conn { return o.cur() }

func (o *obfsConn) LocalAddr() net.Addr  { return o.cur().LocalAddr() }
func (o *obfsConn) RemoteAddr() net.Addr { return o.cur().RemoteAddr() }

func (o *obfsConn) SetDeadline(t time.Time) error {
	o.mu.Lock()
	o.rd, o.wd = t, t
	o.fbArmed = false
	c := o.c
	o.mu.Unlock()
	return c.SetDeadline(t)
}

func (o *obfsConn) SetReadDeadline(t time.Time) error {
	o.mu.Lock()
	o.rd = t
	o.fbArmed = false
	c := o.c
	o.mu.Unlock()
	return c.SetReadDeadline(t)
}

func (o *obfsConn) SetWriteDeadline(t time.Time) error {
	o.mu.Lock()
	o.wd = t
	c := o.c
	o.mu.Unlock()
	return c.SetWriteDeadline(t)
}

// ---------- Psiphon: psiphon.dpi = "auto" ----------

var psiDPIRotation = []string{"", "hello", "light", "strong", "off"}

type psiDPIAuto struct {
	mu    sync.Mutex
	idx   int
	tried bool
	ok    bool
}

// next: the fragmentation mode for the next attempt. A mode that connected is
// kept (one more chance after the tunnel drops); one that failed gives way.
func (a *psiDPIAuto) next() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.ok:
		a.ok = false
	case a.tried:
		prev := psiDPIRotation[a.idx]
		a.idx = (a.idx + 1) % len(psiDPIRotation)
		logf("info", "Psiphon: обход DPI «%s» не помог, пробую «%s»", psiDPINames[prev], psiDPINames[psiDPIRotation[a.idx]])
	}
	a.tried = true
	return psiDPIRotation[a.idx]
}

func (a *psiDPIAuto) good() {
	a.mu.Lock()
	a.ok = true
	a.mu.Unlock()
}

func (a *psiDPIAuto) current() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return psiDPIRotation[a.idx]
}
