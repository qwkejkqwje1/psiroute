package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
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

// goSafe runs f in a goroutine that survives a panic in f.
func goSafe(where string, f func()) {
	go func() {
		defer recoverLog(where)
		f()
	}()
}

// goLoop runs a long-lived loop and starts it again after a panic, so one
// bad moment does not silently switch off stats, config watching or WARP.
func goLoop(ctx context.Context, where string, f func()) {
	go func() {
		for {
			if !catchPanic(where, f) || ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
}

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
