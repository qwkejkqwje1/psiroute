package main

import (
	"context"
	"net"
	"sync"
	"time"
)

// CoreState represents the strict finite state machine (FSM) states of the
// PsiRoute networking core.
type CoreState string

const (
	CoreIdle          CoreState = "idle"
	CoreBootstrapping CoreState = "bootstrapping"
	CoreConnecting    CoreState = "connecting"
	CoreConnected     CoreState = "connected"
	CoreDegraded      CoreState = "degraded"
	CoreReconnecting  CoreState = "reconnecting"
	CoreStopping      CoreState = "stopping"
)

// StartupStage tracks the 4-step launch pipeline displayed in the Overview panel:
// Bootstrap → Obfs → Tunnel → Check → Ready.
type StartupStage string

const (
	StageNone      StartupStage = "none"
	StageBootstrap StartupStage = "bootstrap"
	StageObfs      StartupStage = "obfs"
	StageTunnel    StartupStage = "tunnel"
	StageCheck     StartupStage = "check"
	StageReady     StartupStage = "ready"
)

// CoreFSMSnapshot is an immutable state snapshot published to UI subscribers.
type CoreFSMSnapshot struct {
	State      CoreState    `json:"state"`
	Stage      StartupStage `json:"stage"`
	StageIndex int          `json:"stage_index"` // 0=none, 1=bootstrap, 2=obfs, 3=tunnel, 4=check, 5=ready
	Reason     string       `json:"reason,omitempty"`
	Since      int64        `json:"since"`
	Seq        uint64       `json:"seq"`
}

func stageIndexFor(st StartupStage) int {
	switch st {
	case StageBootstrap:
		return 1
	case StageObfs:
		return 2
	case StageTunnel:
		return 3
	case StageCheck:
		return 4
	case StageReady:
		return 5
	default:
		return 0
	}
}

// validCoreTransitions defines the allowed FSM state transitions to prevent
// out-of-order races across Psiphon, WARP, Clean-IP cascade, and UI actions.
var validCoreTransitions = map[CoreState]map[CoreState]bool{
	CoreIdle: {
		CoreIdle:          true,
		CoreBootstrapping: true,
		CoreConnecting:    true,
		CoreStopping:      true,
	},
	CoreBootstrapping: {
		CoreBootstrapping: true,
		CoreConnecting:    true,
		CoreConnected:     true,
		CoreDegraded:      true,
		CoreReconnecting:  true,
		CoreStopping:      true,
		CoreIdle:          true,
	},
	CoreConnecting: {
		CoreConnecting:    true,
		CoreBootstrapping: true,
		CoreConnected:     true,
		CoreDegraded:      true,
		CoreReconnecting:  true,
		CoreStopping:      true,
		CoreIdle:          true,
	},
	CoreConnected: {
		CoreConnected:    true,
		CoreDegraded:     true,
		CoreReconnecting: true,
		CoreStopping:     true,
		CoreIdle:         true,
	},
	CoreDegraded: {
		CoreDegraded:      true,
		CoreConnected:     true,
		CoreReconnecting:  true,
		CoreBootstrapping: true,
		CoreStopping:      true,
		CoreIdle:          true,
	},
	CoreReconnecting: {
		CoreReconnecting:  true,
		CoreBootstrapping: true,
		CoreConnecting:    true,
		CoreConnected:     true,
		CoreDegraded:      true,
		CoreStopping:      true,
		CoreIdle:          true,
	},
	CoreStopping: {
		CoreStopping: true,
		CoreIdle:     true,
	},
}

// CoreFSM coordinates the lifecycle of the networking core and notifies UI
// subscribers whenever the state or startup stage changes.
type CoreFSM struct {
	mu     sync.RWMutex
	snap   CoreFSMSnapshot
	nextID uint64
	subs   map[uint64]chan CoreFSMSnapshot
}

func newCoreFSM() *CoreFSM {
	return &CoreFSM{
		snap: CoreFSMSnapshot{
			State: CoreIdle,
			Stage: StageNone,
			Since: time.Now().Unix(),
		},
		subs: make(map[uint64]chan CoreFSMSnapshot),
	}
}

// Transition attempts to move the FSM to next state. Invalid transitions are
// rejected (returns false) to guard against stale goroutine callbacks.
func (f *CoreFSM) Transition(next CoreState, stage StartupStage, reason string) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	allowed := validCoreTransitions[f.snap.State][next]
	if !allowed {
		f.mu.Unlock()
		return false
	}
	if stage == "" {
		stage = defaultStageForState(next)
	}
	if f.snap.State == next && f.snap.Stage == stage && f.snap.Reason == reason {
		f.mu.Unlock()
		return true
	}
	now := time.Now().Unix()
	since := f.snap.Since
	if f.snap.State != next || since == 0 {
		since = now
	}
	f.snap = CoreFSMSnapshot{
		State:      next,
		Stage:      stage,
		StageIndex: stageIndexFor(stage),
		Reason:     reason,
		Since:      since,
		Seq:        f.snap.Seq + 1,
	}
	snap := f.snap
	for _, ch := range f.subs {
		select {
		case ch <- snap:
		default:
			// Drop stale frame if subscriber is slow and push newest.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- snap:
			default:
			}
		}
	}
	f.mu.Unlock()
	return true
}

func defaultStageForState(st CoreState) StartupStage {
	switch st {
	case CoreBootstrapping:
		return StageBootstrap
	case CoreConnecting, CoreReconnecting:
		return StageTunnel
	case CoreConnected:
		return StageReady
	case CoreDegraded:
		return StageCheck
	default:
		return StageNone
	}
}

func (f *CoreFSM) Snapshot() CoreFSMSnapshot {
	if f == nil {
		return CoreFSMSnapshot{State: CoreIdle, Stage: StageNone}
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.snap
}

func (f *CoreFSM) State() CoreState {
	return f.Snapshot().State
}

func (f *CoreFSM) Subscribe() (uint64, <-chan CoreFSMSnapshot) {
	ch := make(chan CoreFSMSnapshot, 4)
	if f == nil {
		close(ch)
		return 0, ch
	}
	f.mu.Lock()
	f.nextID++
	id := f.nextID
	f.subs[id] = ch
	ch <- f.snap
	f.mu.Unlock()
	return id, ch
}

func (f *CoreFSM) Unsubscribe(id uint64) {
	if f == nil || id == 0 {
		return
	}
	f.mu.Lock()
	if ch, ok := f.subs[id]; ok {
		delete(f.subs, id)
		close(ch)
	}
	f.mu.Unlock()
}

func (f *CoreFSM) View() map[string]any {
	s := f.Snapshot()
	return map[string]any{
		"state":       string(s.State),
		"stage":       string(s.Stage),
		"stage_index": s.StageIndex,
		"reason":      s.Reason,
		"since":       s.Since,
		"seq":         s.Seq,
	}
}

// ChainDialer is the unified transport interface for direct, Psiphon, WARP,
// and cascaded Clean-IP (WARP -> VPN -> WARP) outbound hops.
type ChainDialer interface {
	Name() string
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	Healthy() bool
}

type chainDialerAdapter struct {
	name    string
	dialFn  func(ctx context.Context, network, addr string) (net.Conn, error)
	checkFn func() bool
}

func newChainDialer(name string, dialFn func(ctx context.Context, network, addr string) (net.Conn, error), checkFn func() bool) ChainDialer {
	return &chainDialerAdapter{name: name, dialFn: dialFn, checkFn: checkFn}
}

func (d *chainDialerAdapter) Name() string { return d.name }

func (d *chainDialerAdapter) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialFn(ctx, network, addr)
}

func (d *chainDialerAdapter) Healthy() bool {
	if d.checkFn == nil {
		return true
	}
	return d.checkFn()
}
