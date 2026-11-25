//go:build windows

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const wfpSupported = true

var wfpRuleNames = []string{
	"PsiRoute_KS_AllowSelf",
	"PsiRoute_KS_AllowLAN",
	"PsiRoute_KS_AllowTun",
	"PsiRoute_KS_BlockOut",
}

type windowsWFPBackend struct {
	runFn func(args ...string) error
}

func defaultWFPBackend() wfpBackend {
	return &windowsWFPBackend{}
}

func (b *windowsWFPBackend) execNetsh(args ...string) error {
	if b.runFn != nil {
		return b.runFn(args...)
	}
	cmd := exec.Command("netsh", args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("netsh %s: %s", strings.Join(args[:min(3, len(args))], " "), msg)
	}
	return nil
}

func (b *windowsWFPBackend) Apply(exePath string, strict bool) error {
	if !isElevated() && b.runFn == nil {
		return errors.New("для системного WFP Kill Switch нужны права администратора")
	}
	// Clean any stale rules first so duplicate rules never accumulate.
	_ = b.Clear()

	// 1. Allow PsiRoute core binary so bootstrap, WARP, and Psiphon can reconnect.
	if exePath != "" {
		if err := b.execNetsh(
			"advfirewall", "firewall", "add", "rule",
			"name=PsiRoute_KS_AllowSelf",
			"dir=out", "action=allow", "enable=yes", "profile=any",
			"program="+exePath,
		); err != nil {
			return err
		}
	}

	// 2. Allow loopback and RFC1918 LAN subnets + link-local IPv6.
	if err := b.execNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name=PsiRoute_KS_AllowLAN",
		"dir=out", "action=allow", "enable=yes", "profile=any",
		"remoteip=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1,fe80::/10",
	); err != nil {
		_ = b.Clear()
		return err
	}

	// 3. In strict mode, allow traffic originating from the Wintun interface subnet
	// so tunneled flows pass while direct physical-interface leaks are blocked.
	if strict {
		if err := b.execNetsh(
			"advfirewall", "firewall", "add", "rule",
			"name=PsiRoute_KS_AllowTun",
			"dir=out", "action=allow", "enable=yes", "profile=any",
			"localip=172.19.0.0/30,fdfe:dcba:9876::/126",
		); err != nil {
			_ = b.Clear()
			return err
		}
	}

	// 4. Block all other outbound traffic on physical adapters.
	if err := b.execNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name=PsiRoute_KS_BlockOut",
		"dir=out", "action=block", "enable=yes", "profile=any",
		"remoteip=any",
	); err != nil {
		_ = b.Clear()
		return err
	}
	return nil
}

func (b *windowsWFPBackend) Clear() error {
	var firstErr error
	for _, name := range wfpRuleNames {
		if err := b.execNetsh("advfirewall", "firewall", "delete", "rule", "name="+name); err != nil {
			// Deleting a non-existent rule is expected during orphan cleanup.
			if firstErr == nil && !strings.Contains(strings.ToLower(err.Error()), "no rules match") && !strings.Contains(err.Error(), "правил") {
				firstErr = err
			}
		}
	}
	return firstErr
}
