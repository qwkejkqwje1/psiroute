//go:build !windows

package main

import (
	"context"
	"os/exec"
	"runtime"
)

func openBrowser(url string) {
	cmd := "xdg-open"
	if runtime.GOOS == "darwin" {
		cmd = "open"
	}
	_ = exec.Command(cmd, url).Start()
}

// runDesktop: there is no tray here; the UI opens in the browser.
func runDesktop(ctx context.Context, a *App, dir string, openNow bool) {
	if openNow {
		openBrowser(a.uiURL())
	}
	<-ctx.Done()
}

func runWindowProcess(dataDir, url string, parentPID int) { openBrowser(url) }

// procTreeMemory: no per-process figures here; memView falls back to the
// Go runtime's own numbers.
func procTreeMemory() memSnap { return memSnap{} }

func showFatal(msg string) {}
