package main

// Per-network strategy memory, scoring, and first-round protocol race (2.0).
//
// Key improvements over 1.5.0:
//  1. Per-Network Strategy Memory (psiroute-strategies.json, atomic write):
//     stores attempts, successes, median connection time (ms), median tunnel
//     lifetime (s), and last success timestamp keyed by network fingerprint
//     (gateway/subnet + adapter hash).
//  2. Score-Based Strategy Ordering: ranks enabled strategies for the active
//     network by empirical success rate, median tunnel lifetime, connect speed,
//     and recency rather than a single global psiroute-last file.
//  3. First-Round Parallel Protocol Race: tries the top-scoring strategy for
//     this network with a short window (18 s) first; if it does not connect,
//     combines the protocol sets of the remaining direct strategies into one
//     Controller (LimitTunnelProtocols union, 35 s) so tunnel-core races them
//     concurrently and connects within <= 60 seconds.

import (
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	holdOK                   = 3 * time.Minute  // tunnels held this long: the method is remembered
	shortLife                = 2 * time.Minute  // tunnels lost sooner were cut by the network
	unstableFor              = 6 * time.Hour    // a method cut twice in a row goes last this long
	cmdGap                   = 20 * time.Second // button presses closer than this are not passed on
	bestStrategyShortTimeout = 20                // Эшелон 1: 6–8 с на быстрый прямой протокол (OSSH/TLS/QUIC)
	combinedRaceTimeout      = 35               // Эшелон 1–2: параллельная гонка протоколов (<= 30 с суммарно)
	tspuEchelonTimeout       = 35               // Эшелон 2: резистентные к ТСПУ транспорты (Meek CDN + Conduit + Desync)
	maxStatSamples           = 15               // rolling window for median calculation
)

// strategyNetStats holds empirical performance metrics for one strategy on one network.
type strategyNetStats struct {
	Attempts           int   `json:"attempts"`
	Successes          int   `json:"successes"`
	ConnectMsSamples   []int `json:"connect_ms_samples,omitempty"`
	MedianConnectMs    int   `json:"median_connect_ms"`
	LifetimeSecSamples []int `json:"lifetime_sec_samples,omitempty"`
	MedianLifetimeSec  int   `json:"median_lifetime_sec"`
	LastSuccessUnix    int64 `json:"last_success_unix,omitempty"`
	UnstableUntil      int64 `json:"unstable_until,omitempty"`
}

// strategyMemoryFile is persisted atomically to psiroute-strategies.json.
type strategyMemoryFile struct {
	Networks map[string]map[string]*strategyNetStats `json:"networks"`
}

// attemptTimeout is the time one method gets before the next one is tried:
// the first round goes over all methods quickly, later rounds give more.
func attemptTimeout(round int) int { return []int{35, 75, 150}[min(max(round, 0), 2)] }

// userCmd passes a button press (next method, new node) on to the engine
// unless the previous press or the start of the attempt was less than
// cmdGap ago.
func (p *Psi) userCmd(c string) int {
	p.mu.Lock()
	since := min(time.Since(p.cmdAt), time.Since(p.attemptAt))
	if p.cancel != nil && since < cmdGap {
		p.mu.Unlock()
		return int((cmdGap - since + time.Second - 1) / time.Second)
	}
	p.cmdAt = time.Now()
	p.mu.Unlock()
	p.send(c)
	return 0
}

// warpUp: the built-in WARP tunnel is up.
func (p *Psi) warpUp() bool { return p.app != nil && p.app.warp.connected() }

// currentNetKey returns the active network fingerprint key.
func (p *Psi) currentNetKey() string {
	if p != nil && p.netKeyFunc != nil {
		if k := p.netKeyFunc(); k != "" {
			return k
		}
	}
	if p != nil && p.app != nil && p.app.net != nil {
		if k := p.app.net.currentNetKey(); k != "" {
			return k
		}
	}
	return "net-default"
}

// lastGood is the method whose tunnels last held for holdOK (legacy fallback).
func (p *Psi) lastGood() string {
	b, _ := os.ReadFile(p.file("psiroute-last"))
	return strings.TrimSpace(string(b))
}

func (p *Psi) stratMemLocked() *strategyMemoryFile {
	if p.stratMem == nil {
		p.stratMem = &strategyMemoryFile{Networks: map[string]map[string]*strategyNetStats{}}
		if b, err := os.ReadFile(p.file("psiroute-strategies.json")); err == nil {
			var loaded strategyMemoryFile
			if json.Unmarshal(b, &loaded) == nil && loaded.Networks != nil {
				p.stratMem = &loaded
			}
		}
	}
	if p.stratMem.Networks == nil {
		p.stratMem.Networks = map[string]map[string]*strategyNetStats{}
	}
	return p.stratMem
}

func (p *Psi) netStatsLocked(netKey, id string, create bool) *strategyNetStats {
	if netKey == "" {
		netKey = "net-default"
	}
	mem := p.stratMemLocked()
	nm := mem.Networks[netKey]
	if nm == nil {
		if !create {
			return nil
		}
		nm = map[string]*strategyNetStats{}
		mem.Networks[netKey] = nm
	}
	st := nm[id]
	if st == nil && create {
		st = &strategyNetStats{}
		nm[id] = st
	}
	return st
}

func (p *Psi) saveStratMemLocked() {
	if p.stratMem == nil || p.dataDir == "" {
		return
	}
	b, err := json.MarshalIndent(p.stratMem, "", "  ")
	if err != nil {
		return
	}
	_ = writeFileAtomic(p.file("psiroute-strategies.json"), b, 0o600)
}

func medianInt(samples []int) int {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]int(nil), samples...)
	sort.Ints(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[mid]
	}
	return (cp[mid-1] + cp[mid]) / 2
}

func appendSample(samples []int, v int) []int {
	samples = append(samples, v)
	if len(samples) > maxStatSamples {
		samples = samples[len(samples)-maxStatSamples:]
	}
	return samples
}

// recordStrategyAttempt increments the attempt counter for strategy id on netKey.
func (p *Psi) recordStrategyAttempt(netKey, id string) {
	if id == "" || id == "race-direct" || id == "desync-direct" {
		return
	}
	p.mu.Lock()
	st := p.netStatsLocked(netKey, id, true)
	st.Attempts++
	p.saveStratMemLocked()
	p.mu.Unlock()
}

// recordStrategySuccess records a successful connection and its connect latency.
func (p *Psi) recordStrategySuccess(netKey, id string, connectMs int) {
	if id == "" || id == "race-direct" || id == "desync-direct" {
		return
	}
	now := time.Now().Unix()
	p.mu.Lock()
	st := p.netStatsLocked(netKey, id, true)
	if st.Attempts < st.Successes+1 {
		st.Attempts = st.Successes + 1
	}
	st.Successes++
	st.LastSuccessUnix = now
	if connectMs > 0 {
		st.ConnectMsSamples = appendSample(st.ConnectMsSamples, connectMs)
		st.MedianConnectMs = medianInt(st.ConnectMsSamples)
	}
	p.saveStratMemLocked()
	p.mu.Unlock()
}

// recordStrategyLifetime records how long a connected tunnel lived before dropping.
func (p *Psi) recordStrategyLifetime(netKey, id string, life time.Duration) {
	if id == "" || id == "race-direct" || id == "desync-direct" {
		return
	}
	sec := int(life.Seconds())
	if sec <= 0 {
		return
	}
	p.mu.Lock()
	st := p.netStatsLocked(netKey, id, true)
	st.LifetimeSecSamples = appendSample(st.LifetimeSecSamples, sec)
	st.MedianLifetimeSec = medianInt(st.LifetimeSecSamples)
	p.saveStratMemLocked()
	p.mu.Unlock()
}

// scoreStrategyLocked computes the priority score of strategy id on netKey.
func (p *Psi) scoreStrategyLocked(netKey, id string, baseIdx int, lastGlobal string, now time.Time) float64 {
	// Base priority from config order so untried strategies preserve user order.
	score := 50.0 - float64(baseIdx)*1.5
	if id == lastGlobal {
		score += 8.0
	}
	st := p.netStatsLocked(netKey, id, false)
	if st == nil || st.Attempts == 0 {
		return score
	}
	// Laplace-smoothed success ratio in [0..100]
	ratio := float64(st.Successes+1) / float64(st.Attempts+2)
	score += ratio * 60.0
	if st.Successes > 0 {
		score += 20.0
	}
	// Bonus for long-lived tunnels (up to +35)
	if st.MedianLifetimeSec > 0 {
		score += min(35.0, float64(st.MedianLifetimeSec)/10.0)
	}
	// Bonus for fast connection (up to +15)
	if st.MedianConnectMs > 0 {
		if st.MedianConnectMs < 15000 {
			score += float64(15000-st.MedianConnectMs) / 1000.0
		} else {
			score -= min(15.0, float64(st.MedianConnectMs-15000)/2000.0)
		}
	}
	// Recency bonus if succeeded within the last 24h
	if st.LastSuccessUnix > 0 {
		ageHours := now.Sub(time.Unix(st.LastSuccessUnix, 0)).Hours()
		if ageHours >= 0 && ageHours < 24 {
			score += (24.0 - ageHours) * 0.8
		}
	}
	// Penalty if repeated attempts failed without a single success
	if st.Successes == 0 && st.Attempts >= 2 {
		score -= float64(st.Attempts) * 12.0
	}
	if st.UnstableUntil > now.Unix() {
		score -= 200.0
	}
	return score
}

// order puts the best methods for the current network first and methods whose
// tunnels kept dying soon after connecting last.
func (p *Psi) order(list []strategyDef, last string) []strategyDef {
	return p.orderForNetwork(p.currentNetKey(), list, last)
}

func (p *Psi) orderForNetwork(netKey string, list []strategyDef, last string) []strategyDef {
	now := time.Now()
	p.mu.Lock()
	type scored struct {
		def      strategyDef
		score    float64
		unstable bool
		idx      int
	}
	items := make([]scored, 0, len(list))
	for i, s := range list {
		un := p.isUnstableForNetLocked(netKey, s.ID, now)
		sc := p.scoreStrategyLocked(netKey, s.ID, i, last, now)
		items = append(items, scored{def: s, score: sc, unstable: un, idx: i})
	}
	p.mu.Unlock()

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].unstable != items[j].unstable {
			return !items[i].unstable
		}
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].idx < items[j].idx
	})
	out := make([]strategyDef, 0, len(items))
	for _, it := range items {
		out = append(out, it.def)
	}
	return out
}

// combinedDirectRaceStrategy merges the tunnel protocols of multiple direct
// strategies into a single strategyDef so tunnel-core races them in parallel.
func combinedDirectRaceStrategy(directs []strategyDef) (strategyDef, []string) {
	var protos []string
	var titles []string
	for _, s := range directs {
		titles = append(titles, s.Title)
		if s.Protos == "" {
			// "auto" allows all protocols; collect all known protocol sets
			for _, set := range psiProtoSets {
				for _, pr := range set {
					if !slices.Contains(protos, pr) {
						protos = append(protos, pr)
					}
				}
			}
			continue
		}
		for _, pr := range psiProtoSets[s.Protos] {
			if !slices.Contains(protos, pr) {
				protos = append(protos, pr)
			}
		}
	}
	title := "Параллельная гонка протоколов"
	if len(titles) > 0 && len(titles) <= 3 {
		title += " (" + strings.Join(titles, " + ") + ")"
	}
	return strategyDef{
		ID:           "race-direct",
		Title:        title,
		Transport:    "direct",
		Protos:       "race",
		CustomProtos: protos,
		Upstream:     "None",
	}, protos
}

// buildRoundZeroPlan constructs the fast first-round sequence:
//  1. Top strategy for this network with a short window (18 s).
//  2. Combined parallel race of all remaining direct strategies in one Controller (35 s).
//  3. Any remaining separate-transport strategies (via-warp, via-proxy).
// Total time to reach a working direct strategy in a restricted network is <= 53 s (< 60 s).
func (p *Psi) buildRoundZeroPlan(ordered []strategyDef) []strategyDef {
	if len(ordered) <= 1 {
		return ordered
	}
	first := ordered[0]
	var restDirect []strategyDef
	var separateTransport []strategyDef
	for _, s := range ordered[1:] {
		if s.Transport == "direct" {
			restDirect = append(restDirect, s)
		} else {
			separateTransport = append(separateTransport, s)
		}
	}
	plan := []strategyDef{first}
	if len(restDirect) == 1 {
		plan = append(plan, restDirect[0])
	} else if len(restDirect) > 1 {
		raceStrat, _ := combinedDirectRaceStrategy(restDirect)
		plan = append(plan, raceStrat)
	}
	// Эшелон 2 (Раздел 3.2 ТЗ): резистентные к ТСПУ транспорты (Meek-HTTPS с CDN-фронтованием,
	// Conduit/Conjure и локальный TCP Desync -> Psiphon) без зависимости от WARP.
	var tspuProtos []string
	for _, k := range []string{"meek", "conduit", "tls"} {
		for _, pr := range psiProtoSets[k] {
			if !slices.Contains(tspuProtos, pr) {
				tspuProtos = append(tspuProtos, pr)
			}
		}
	}
	if len(tspuProtos) > 0 {
		plan = append(plan, strategyDef{
			ID:           "desync-direct",
			Title:        "Прямой + локальный Desync (Анти-ТСПУ)",
			Transport:    "desync",
			Protos:       "tls",
			CustomProtos: tspuProtos,
			DPI:          "strong",
			Upstream:     "Desync",
		})
	}
	plan = append(plan, separateTransport...)
	return plan
}

func (p *Psi) unstableLocked() map[string]int64 {
	if p.unstable == nil {
		p.unstable = map[string]int64{}
		if b, err := os.ReadFile(p.file("psiroute-unstable.json")); err == nil {
			var m map[string]int64
			if json.Unmarshal(b, &m) == nil && m != nil {
				p.unstable = m
			}
		}
	}
	return p.unstable
}

func (p *Psi) isUnstableForNetLocked(netKey, id string, now time.Time) bool {
	if st := p.netStatsLocked(netKey, id, false); st != nil && st.UnstableUntil > now.Unix() {
		return true
	}
	return p.unstableLocked()[id] > now.Unix()
}

func (p *Psi) isUnstable(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isUnstableForNetLocked(p.currentNetKey(), id, time.Now())
}

// markUnstable sends a method to the end of the list for unstableFor (on)
// or takes it back (off); stored per-network and in legacy file.
func (p *Psi) markUnstable(id string, on bool) {
	netKey := p.currentNetKey()
	p.mu.Lock()
	m := p.unstableLocked()
	now := time.Now()
	for k, until := range m {
		if until <= now.Unix() {
			delete(m, k)
		}
	}
	st := p.netStatsLocked(netKey, id, true)
	if on {
		until := now.Add(unstableFor).Unix()
		m[id] = until
		st.UnstableUntil = until
	} else {
		delete(m, id)
		st.UnstableUntil = 0
	}
	p.saveStratMemLocked()
	b, _ := json.Marshal(m)
	p.mu.Unlock()
	if p.dataDir != "" {
		_ = writeFileAtomic(p.file("psiroute-unstable.json"), b, 0o600)
	}
}
