package main

import (
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"sync"
	"time"
)

// setupMemory runs in every psiroute process: the core, the window, the
// country workers and the DPI probe.
func setupMemory() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(40) // aggressive GC for short-lived network buffers
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		// Soft memory limit keeps the Go runtime from hoarding virtual/physical pages
		// during large list downloads or high-concurrency bursts (48 MiB for core).
		limit := int64(48 << 20)
		for _, a := range os.Args[1:] {
			if a == "--window" || a == "-window" {
				limit = 24 << 20 // 24 MiB for Gio UI window process
				break
			}
			if a == "--psi-worker" || a == "--probe" {
				limit = 24 << 20 // 24 MiB for helper workers
				break
			}
		}
		debug.SetMemoryLimit(limit)
	}
	go memTrimmer()
}

// ReleaseGUIMemory forces a GC cycle and returns unused heap pages to the OS
// immediately when the GUI window is minimized to tray or closed.
func ReleaseGUIMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}

// memTrimmer gives freed heap pages back to the system and periodically prunes
// expired entries from in-memory caches (DNS, DoH wire cache, Reverse DNS,
// FakeIP, ECH, and LAN auth rate-limiter).
func memTrimmer() {
	s := []metrics.Sample{{Name: "/memory/classes/heap/free:bytes"}}
	tk := time.NewTicker(15 * time.Second)
	defer tk.Stop()
	ticks := 0
	for range tk.C {
		ticks++
		if ticks%2 == 0 {
			pruneAllCaches()
		}
		metrics.Read(s)
		if s[0].Value.Kind() == metrics.KindUint64 && s[0].Value.Uint64() >= 4<<20 {
			debug.FreeOSMemory()
		}
	}
}

// pruneAllCaches evicts expired entries from all global lookup caches so they
// do not retain stale heap objects during long sessions.
func pruneAllCaches() {
	if theDNS != nil {
		theDNS.prune()
	}
	if theDoHWire != nil {
		theDoHWire.prune()
	}
	if theRevDNS != nil {
		theRevDNS.prune()
	}
	if theFakeIP != nil {
		theFakeIP.prune()
	}
	if theECHCache != nil {
		theECHCache.prune()
	}
}

// goMemory: what the Go runtime holds from the system (heap, stacks, its
// own structures), minus what it has already given back.
func goMemory() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 || s[1].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	if s[0].Value.Uint64() < s[1].Value.Uint64() {
		return 0
	}
	return s[0].Value.Uint64() - s[1].Value.Uint64()
}

// memSnap: where Psiroute's memory goes. On Windows the sizes are private
// working sets, the "Memory" column of Task Manager.
type memSnap struct {
	App      uint64 `json:"app"`       // the core process
	Go       uint64 `json:"go"`        // of it, held by the Go runtime
	Workers  uint64 `json:"workers"`   // helper processes: countries, DPI probe
	WorkersN int    `json:"workers_n"` //
	Window   uint64 `json:"window"`    // the window process
	WindowN  int    `json:"window_n"`  //
	Watchdog uint64 `json:"watchdog"`  // the crash watchdog (parent process)
	Total    uint64 `json:"total"`
}

var memCache struct {
	sync.Mutex
	at   time.Time
	snap memSnap
}

// memView is cached for 2 s: the UI asks every second, the tray every 2 s.
func memView() memSnap {
	memCache.Lock()
	defer memCache.Unlock()
	if !memCache.at.IsZero() && time.Since(memCache.at) < 2*time.Second {
		return memCache.snap
	}
	s := procTreeMemory()
	s.Go = goMemory()
	if s.App == 0 {
		s.App = s.Go // no OS figure on this platform
	}
	s.Total = s.App + s.Workers + s.Window + s.Watchdog
	memCache.at, memCache.snap = time.Now(), s
	return s
}

func mbText(b uint64) string {
	return strconv.FormatUint((b+1<<19)>>20, 10) + " МБ"
}

// SetCustomMemoryLimitMB sets the soft GOMEMLIMIT in megabytes when specified
// via --mem-limit, PSIROUTE_MEM_LIMIT, or config.json.
func SetCustomMemoryLimitMB(mb int) {
	if mb >= 16 && mb <= 16384 {
		debug.SetMemoryLimit(int64(mb) << 20)
	}
}
