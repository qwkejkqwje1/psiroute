package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Crash safety (1.0.7).
//
// A panic in one connection or background task used to end the whole
// program, and with the system proxy on, the internet stopped working until
// the next start. Now our goroutines recover: the panic and its stack go to
// psiroute.log and only that connection or task is lost (loops start again).
//
// What cannot be recovered (a panic inside a library goroutine, a fatal
// runtime error) is written by the Go runtime to crash.log, and the watchdog
// process (watchdog.go) turns the system proxy off and restarts the core.

var panicsCaught atomic.Int64

func reportPanic(where string, r any) {
	panicsCaught.Add(1)
	logf("error", "Сбой в «%s» перехвачен, Psiroute продолжает работу: %v", where, r)
	theLog.raw(fmt.Sprintf("panic в «%s»: %v\n%s", where, r, debug.Stack()))
}

// recoverLog must be deferred directly: defer recoverLog("where").
func recoverLog(where string) {
	if r := recover(); r != nil {
		reportPanic(where, r)
	}
}

// catchPanic runs f and reports whether it panicked.
func catchPanic(where string, f func()) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			reportPanic(where, r)
		}
	}()
	f()
	return false
}

// safeGo runs f in a goroutine that survives a panic: the panic and its stack
// go to the log (reportPanic) and only this task is lost. Every background
// launch in the program goes through it (audit A-06).
func safeGo(name string, f func()) {
	go func() {
		defer recoverLog(name)
		f()
	}()
}

// safeGoReply runs fn in a panic-recovered goroutine and guarantees exactly one
// reply reaches ch (falling back to panicVal on panic/Goexit) so waiting
// callers never hang indefinitely.
func safeGoReply[T any](name string, ch chan<- T, panicVal func(r any) T, fn func() T) {
	go func() {
		sent := false
		defer func() {
			if rec := recover(); rec != nil {
				reportPanic(name, rec)
				if !sent && ch != nil {
					ch <- panicVal(rec)
					sent = true
				}
			} else if !sent && ch != nil {
				ch <- panicVal("не получен ответ")
				sent = true
			}
		}()
		v := fn()
		if ch != nil {
			ch <- v
		}
		sent = true
	}()
}

// goSafe is the older name of safeGo, kept for existing call sites.
func goSafe(where string, f func()) { safeGo(where, f) }

const (
	loopMaxCrashes   = 5                // crashes per window before the component is marked failed
	loopCrashWindow  = time.Minute      // sliding window for the counter
	loopBackoffStart = 500 * time.Millisecond
	loopBackoffMax   = 30 * time.Second
)

// loopCrashTracker counts crashes of one long-lived component inside a sliding
// window. It is separate from the goroutine so tests can drive it with a fake
// clock.
type loopCrashTracker struct {
	times []time.Time
}

// note records a crash at now and reports how many crashes lie inside the
// window (including this one).
func (t *loopCrashTracker) note(now time.Time) int {
	keep := t.times[:0]
	for _, x := range t.times {
		if now.Sub(x) < loopCrashWindow {
			keep = append(keep, x)
		}
	}
	t.times = append(keep, now)
	return len(t.times)
}

// loopBackoff is the pause before restart number n (1 = first crash).
func loopBackoff(n int) time.Duration {
	d := loopBackoffStart
	for i := 1; i < n; i++ {
		d *= 2
		if d >= loopBackoffMax {
			return loopBackoffMax
		}
	}
	return d
}

var failedComponents sync.Map // name -> time.Time when marked failed

// componentFailed reports whether a long-lived component was switched off
// after too many crashes.
func componentFailed(name string) bool {
	_, ok := failedComponents.Load(name)
	return ok
}

// failedComponentNames lists components marked failed, sorted.
func failedComponentNames() []string {
	var out []string
	failedComponents.Range(func(k, _ any) bool {
		out = append(out, k.(string))
		return true
	})
	sort.Strings(out)
	return out
}

// runLoopSupervised runs f until it returns without a panic, ctx ends, or the
// component fails (loopMaxCrashes crashes inside loopCrashWindow). Between
// crashes it waits with exponential backoff. sleep is injectable for tests.
// It returns true if the component was marked failed.
func runLoopSupervised(ctx context.Context, name string, f func(), now func() time.Time, sleep func(context.Context, time.Duration)) (failed bool) {
	var tr loopCrashTracker
	crashes := 0
	for {
		if !catchPanic(name, f) || ctx.Err() != nil {
			return false
		}
		crashes++
		if n := tr.note(now()); n >= loopMaxCrashes {
			failedComponents.Store(name, now())
			logf("error", "Компонент «%s» остановлен: %d сбоев за минуту. Остальные функции Psiroute работают; перезапустите программу, а если сбой повторяется — отправьте psiroute.log разработчику", name, n)
			return true
		}
		d := loopBackoff(crashes)
		logf("warn", "Компонент «%s» перезапустится через %s (сбой %d из %d за минуту)", name, d, tr.note2(), loopMaxCrashes)
		sleep(ctx, d)
		if ctx.Err() != nil {
			return false
		}
	}
}

// note2 is the current number of crashes in the window, without adding one.
func (t *loopCrashTracker) note2() int { return len(t.times) }

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// safeLoop starts a long-lived loop in a goroutine and restarts it after a
// panic with backoff; after loopMaxCrashes crashes in a minute the component
// is marked failed and the process keeps living.
func safeLoop(ctx context.Context, name string, f func()) {
	go func() {
		defer recoverLog(name)
		runLoopSupervised(ctx, name, f, time.Now, sleepCtx)
	}()
}

// goLoop is the older name of safeLoop, kept for existing call sites.
func goLoop(ctx context.Context, where string, f func()) { safeLoop(ctx, where, f) }

func crashLogPath(dir string) string { return filepath.Join(dir, "crash.log") }

// setupCrashOutput makes the runtime append fatal panics and errors to
// crash.log; above 256 KB the old file becomes crash.log.1.
func setupCrashOutput(dir string) {
	p := crashLogPath(dir)
	if st, err := os.Stat(p); err == nil && st.Size() > 256<<10 {
		_ = os.Remove(p + ".1")
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	_ = f.Close() // SetCrashOutput keeps its own copy of the descriptor
}

// crashInfo is a crash.log entry the user has not been told about yet.
type crashInfo struct {
	At       time.Time
	Headline string
	unseen   bool
	stamp    int64
}

func crashSeenPath(dir string) string { return filepath.Join(dir, "psiroute.crashseen") }

// findCrash looks at crash.log without changing anything: the mark is set
// by markSeen only in the process that really starts (not in a second launch).
func findCrash(dir string) crashInfo {
	st, err := os.Stat(crashLogPath(dir))
	if err != nil || st.Size() == 0 {
		return crashInfo{}
	}
	b, _ := os.ReadFile(crashSeenPath(dir))
	seen, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	c := crashInfo{At: st.ModTime(), stamp: st.ModTime().UnixNano()}
	if c.stamp <= seen {
		return c
	}
	c.unseen = true
	c.Headline = crashHeadline(crashLogPath(dir))
	return c
}

func (c crashInfo) markSeen(dir string) {
	if c.unseen {
		_ = os.WriteFile(crashSeenPath(dir), []byte(strconv.FormatInt(c.stamp, 10)), 0o600)
	}
}

// crashHeadline: the last "panic:" or "fatal error:" line of crash.log.
func crashHeadline(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	if len(b) > 64<<10 {
		b = b[len(b)-64<<10:]
	}
	head := ""
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "panic:") || strings.HasPrefix(ln, "fatal error:") {
			head = ln
		}
	}
	return short(head, 160)
}
