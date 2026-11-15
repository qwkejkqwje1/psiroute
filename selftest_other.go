//go:build !windows

package main

import (
	"context"
	"os/exec"
	"runtime"
)

func platformChecks(a *App) []check                { return nil }
func portOwner(addr string) string                 { return "" }
func revealFile(path string)                       {}
func allowForeground(pid int)                      {}
func platformNetNotify(context.Context, *netWatch) {}

func openWithDefault(path string) {
	cmd := "xdg-open"
	if runtime.GOOS == "darwin" {
		cmd = "open"
	}
	_ = exec.Command(cmd, path).Start()
}
