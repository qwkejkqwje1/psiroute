package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The watchdog (1.0.7) is the process started from the shortcut or from
// autostart. It runs the core ("psiroute --core ...") and does nothing else,
// a few MB. If the core dies from a crash, the watchdog turns the system
// proxy off at once (otherwise every browser looks at a dead port) and starts
// the core again, minimized to the tray. Normal exits, errors at start and a
// process ended from Task Manager are not restarted; after three crashes in
// ten minutes it gives up and says so.

const (
	crashExitCode    = 2 // Go: unrecovered panic or fatal runtime error
	maxCrashRestarts = 3
	crashWindow      = 10 * time.Minute
)

// watchdogPID: in a core started by the watchdog, the watchdog's process
// id (its memory is counted with the rest).
var watchdogPID int

// isCrashExit: a Go crash (2) or a Windows exception code (0xC0000005 and
// the like). -1 means "no exit code" (killed by a signal).
func isCrashExit(code int) bool {
	if code == -1 {
		return false
	}
	return code == crashExitCode || uint32(code) >= 0xC0000000
}

type watchdog struct {
	args    []string
	run     func(args []string) (int, error) // starts the core, waits, returns its exit code
	sleep   func(time.Duration)
	now     func() time.Time
	onCrash func(n int) // n: crashes within crashWindow
	giveUp  func(n int)
}

// loop returns the core's exit code; ran is false if the core could not be
// started at all (then the caller runs the core in its own process).
func (w *watchdog) loop() (code int, ran bool) {
	var crashes []time.Time
	args := w.args
	for restarts := 0; ; restarts++ {
		c, err := w.run(coreArgs(args, restarts))
		if err != nil {
			if restarts == 0 {
				return 0, false
			}
			return crashExitCode, true
		}
		if !isCrashExit(c) {
			return c, true
		}
		now := w.now()
		crashes = append(crashes, now)
		crashes = slices.DeleteFunc(crashes, func(t time.Time) bool { return now.Sub(t) > crashWindow })
		w.onCrash(len(crashes))
		if len(crashes) >= maxCrashRestarts {
			w.giveUp(len(crashes))
			return c, true
		}
		w.sleep(time.Duration(len(crashes)) * 2 * time.Second)
	}
}

// coreArgs: the user's flags plus --core; a restarted core goes straight to
// the tray and knows it was restarted.
func coreArgs(args []string, restarts int) []string {
	out := []string{"--core"}
	minimized := false
	for _, a := range args {
		name := strings.TrimLeft(a, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		switch name {
		case "core", "restarts":
			continue
		case "minimized":
			minimized = true
		}
		out = append(out, a)
	}
	if restarts > 0 {
		out = append(out, "--restarts="+strconv.Itoa(restarts))
		if !minimized {
			out = append(out, "--minimized")
		}
	}
	return out
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// runWatchdog supervises the core. ran=false: run the core in this process.
func runWatchdog(dir string) (int, bool) {
	for _, a := range os.Args[1:] {
		if a == "--test-config" || a == "-test-config" || a == "--version" || a == "-version" {
			return 0, false
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, false
	}
	w := &watchdog{
		args: os.Args[1:],
		run: func(args []string) (int, error) {
			cmd := exec.Command(exe, args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				return 0, err
			}
			allowForeground(cmd.Process.Pid) // its window may come to the front
			return exitCodeOf(cmd.Wait()), nil
		},
		sleep:   time.Sleep,
		now:     time.Now,
		onCrash: func(int) { crashCleanup(dir) },
		giveUp: func(n int) {
			msg := fmt.Sprintf("Psiroute аварийно завершился %d раза за 10 минут и больше не перезапускается.\n\nСистемный прокси выключен, интернет работает напрямую.", n)
			if h := crashHeadline(crashLogPath(dir)); h != "" {
				msg += "\n\nПричина: " + h
			}
			msg += "\n\nПодробности — в crash.log и psiroute.log в папке\n" + dir
			showFatal(msg)
		},
	}
	return w.loop()
}

// crashCleanup runs in the watchdog right after the core crashed.
func crashCleanup(dir string) {
	if listen := readInstanceLine(dir, 2); listen != "" && systemProxyOwnedBy(listen) {
		_ = setSystemProxy(listen, false)
	}
	_ = os.Remove(instanceFile(dir))
}
