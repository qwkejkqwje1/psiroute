package main

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// Connection timeline and baseline observability counters (Step 0).
// Records structured, secret-masked connection lifecycle events around
// Psi.run / attemptOnce / onNotice without altering connection behavior.

const defaultTimelineCapacity = 128

// connTimelineEvent is one structured step in the Psiphon connection lifecycle.
type connTimelineEvent struct {
	Seq        int64    `json:"seq"`
	Timestamp  string   `json:"ts"`
	Stage      string   `json:"stage"`
	Carrier    string   `json:"carrier,omitempty"`
	StrategyID string   `json:"strategy_id,omitempty"`
	Protocols  []string `json:"protocols,omitempty"`
	Attempt    int      `json:"attempt,omitempty"`
	DurationMs int64    `json:"duration_ms,omitempty"`
	Outcome    string   `json:"outcome,omitempty"`
	DiagCode   string   `json:"diag_code,omitempty"`
	Detail     string   `json:"detail,omitempty"`
}

// connCountersSnapshot is a race-free snapshot of connection metrics.
type connCountersSnapshot struct {
	AttemptsByCarrier  map[string]int `json:"attempts_by_carrier"`
	AttemptsByProtocol map[string]int `json:"attempts_by_protocol"`
	SuccessesByCarrier map[string]int `json:"successes_by_carrier"`
	MedianConnectMs    int            `json:"median_connect_ms"`
	TotalHoldSec       int64          `json:"total_hold_sec"`
	Stall16KBEvents    int64          `json:"stall_16kb_events"`
}

// connTimeline stores a bounded ring of timeline events and connection counters.
type connTimeline struct {
	mu                 sync.Mutex
	maxEntries         int
	nextSeq            int64
	events             []connTimelineEvent
	attemptsByCarrier  map[string]int
	attemptsByProtocol map[string]int
	successesByCarrier map[string]int
	connectMsSamples   []int
	totalHoldSec       int64
	stall16KBEvents    int64
}

func newConnTimeline(maxEntries int) *connTimeline {
	if maxEntries <= 0 {
		maxEntries = defaultTimelineCapacity
	}
	return &connTimeline{
		maxEntries:         maxEntries,
		events:             make([]connTimelineEvent, 0, min(maxEntries, 32)),
		attemptsByCarrier:  map[string]int{},
		attemptsByProtocol: map[string]int{},
		successesByCarrier: map[string]int{},
	}
}

func (tl *connTimeline) Record(ev connTimelineEvent) {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.nextSeq++
	ev.Seq = tl.nextSeq
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if len(ev.Protocols) > 0 {
		ev.Protocols = append([]string(nil), ev.Protocols...)
	}
	if ev.Detail != "" {
		ev.Detail = maskTimelineSecrets(cleanPsiErr(ev.Detail))
	}
	if len(tl.events) >= tl.maxEntries {
		copy(tl.events, tl.events[1:])
		tl.events[len(tl.events)-1] = ev
	} else {
		tl.events = append(tl.events, ev)
	}
}

func (tl *connTimeline) RecordAttempt(carrier string, protocols []string) {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if carrier == "" {
		carrier = "unknown"
	}
	tl.attemptsByCarrier[carrier]++
	if len(protocols) == 0 {
		tl.attemptsByProtocol["all"]++
		return
	}
	for _, pr := range protocols {
		if pr != "" {
			tl.attemptsByProtocol[pr]++
		}
	}
}

func (tl *connTimeline) RecordConnect(carrier, proto string, connectMs int) {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if carrier == "" {
		carrier = "unknown"
	}
	tl.successesByCarrier[carrier]++
	if connectMs > 0 {
		tl.connectMsSamples = appendSample(tl.connectMsSamples, connectMs)
	}
	if proto != "" {
		tl.attemptsByProtocol[proto]++
	}
}

func (tl *connTimeline) RecordHold(dur time.Duration) {
	if tl == nil || dur <= 0 {
		return
	}
	sec := int64(dur / time.Second)
	if sec <= 0 {
		return
	}
	tl.mu.Lock()
	tl.totalHoldSec += sec
	tl.mu.Unlock()
}

func (tl *connTimeline) RecordStall16KB() {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	tl.stall16KBEvents++
	tl.mu.Unlock()
}

func (tl *connTimeline) Events() []connTimelineEvent {
	if tl == nil {
		return []connTimelineEvent{}
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	out := make([]connTimelineEvent, len(tl.events))
	for i, ev := range tl.events {
		if len(ev.Protocols) > 0 {
			ev.Protocols = append([]string(nil), ev.Protocols...)
		}
		out[i] = ev
	}
	return out
}

func (tl *connTimeline) Counters() connCountersSnapshot {
	snap := connCountersSnapshot{
		AttemptsByCarrier:  map[string]int{},
		AttemptsByProtocol: map[string]int{},
		SuccessesByCarrier: map[string]int{},
	}
	if tl == nil {
		return snap
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	for k, v := range tl.attemptsByCarrier {
		snap.AttemptsByCarrier[k] = v
	}
	for k, v := range tl.attemptsByProtocol {
		snap.AttemptsByProtocol[k] = v
	}
	for k, v := range tl.successesByCarrier {
		snap.SuccessesByCarrier[k] = v
	}
	snap.MedianConnectMs = medianInt(tl.connectMsSamples)
	snap.TotalHoldSec = tl.totalHoldSec
	snap.Stall16KBEvents = tl.stall16KBEvents
	return snap
}

func (tl *connTimeline) Reset() {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.events = tl.events[:0]
	tl.attemptsByCarrier = map[string]int{}
	tl.attemptsByProtocol = map[string]int{}
	tl.successesByCarrier = map[string]int{}
	tl.connectMsSamples = nil
	tl.totalHoldSec = 0
	tl.stall16KBEvents = 0
}

var (
	tlUUIDRe     = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	tlLongHexRe  = regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`)
	tlKVSecretRe = regexp.MustCompile(`(?i)\b(token|secret|password|pass|key|auth|signature|sig)\s*([=:])\s*([^\s,;'"&]+)`)
	tlURLCredRe  = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^\s/@:]+:[^\s/@]+)@`)
)

// maskTimelineSecrets strips credentials, UUIDs, server-entry hex blobs, keys,
// and tokens from strings before they enter the timeline or diagnostic reports.
func maskTimelineSecrets(s string) string {
	if s == "" {
		return ""
	}
	s = tlURLCredRe.ReplaceAllString(s, "${1}***@")
	s = redactURL(s)
	s = tlUUIDRe.ReplaceAllString(s, "<uuid>")
	s = tlKVSecretRe.ReplaceAllString(s, "${1}${2}***")
	s = tlLongHexRe.ReplaceAllString(s, "<redacted-hex>")
	return strings.TrimSpace(s)
}

func carrierNameForStrategy(s strategyDef) string {
	switch s.Transport {
	case "desync":
		return "direct+dpi"
	case "direct", "warp", "proxy", "worker":
		return s.Transport
	default:
		if s.Transport != "" {
			return s.Transport
		}
		return "direct"
	}
}

func protocolsForStrategy(s strategyDef) []string {
	if len(s.CustomProtos) > 0 {
		return append([]string(nil), s.CustomProtos...)
	}
	if set := psiProtoSets[s.Protos]; len(set) > 0 {
		return append([]string(nil), set...)
	}
	return []string{"all"}
}
