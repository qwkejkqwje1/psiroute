package main

import (
	"errors"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// Tuning presets, DNS routing, and Client Identity validation (Steps 4 & 5).
//
// Preset names ("Advanced connection"):
//   - "fast"     : lower latency multiplier, brisk worker pool, 35 s first round
//   - "balanced" : default safe profile for Russian networks
//   - "patient"  : high latency multiplier (2.5-3.0), wider staggered pool, 150 s+ budget

const (
	PresetFast     = "fast"
	PresetBalanced = "balanced"
	PresetPatient  = "patient"

	// Client identity honest disclosure for UI/docs (Step 5).
	clientIdentityNotice = "По умолчанию используются тестовые идентификаторы Psiphon (FFFF…). С ними серверы Psiphon могут не выдавать региональные тактики для России и параметры Conduit/in-proxy. Для расширенного использования получите официальные значения у Psiphon."
)

// defaultAlternateDNSServers are used only when DoH/DNS poisoning is detected
// and the carrier does not already route through local DoH desync SOCKS.
var defaultAlternateDNSServers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

// normalizePreset maps arbitrary config strings to one of fast / balanced / patient.
func normalizePreset(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case PresetFast:
		return PresetFast
	case PresetPatient:
		return PresetPatient
	default:
		return PresetBalanced
	}
}

// validateHexID16 validates PropagationChannelId / SponsorId (exactly 16 hex chars).
func validateHexID16(s string) error {
	s = strings.TrimSpace(s)
	if len(s) != 16 {
		return errors.New("идентификатор должен содержать ровно 16 шестнадцатеричных символов (0-9, A-F)")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return errors.New("идентификатор может содержать только шестнадцатеричные символы (0-9, A-F)")
		}
	}
	return nil
}

// applyTuning applies preset- and carrier-aware tuning parameters to psiphon.Config.
// Uses only long-stable psiphon.Config fields present in upstream v2.0.28+ and master
// (see docs/PSIPHON_CONFIG_INVENTORY.md).
func applyTuning(cfg *psiphon.Config, preset, carrier string, report *CarrierReport, round int, seedEmptyOrRSL bool) {
	if cfg == nil {
		return
	}
	p := normalizePreset(preset)

	// 1. NetworkLatencyMultiplier: 1.0 default; 2.0-3.0 on high-latency / throttled carriers.
	mult := 1.0
	switch p {
	case PresetFast:
		if carrier == carrierWARP || carrier == carrierWorker || carrier == carrierProxy {
			mult = 1.5
		} else {
			mult = 1.0
		}
	case PresetPatient:
		if carrier == carrierWARP || carrier == carrierWorker || carrier == carrierProxy {
			mult = 3.0
		} else {
			mult = 2.5
		}
	default: // balanced
		if carrier == carrierWARP || carrier == carrierWorker || carrier == carrierProxy {
			mult = 2.0
		} else {
			mult = 1.5
		}
	}
	cfg.NetworkLatencyMultiplier = mult

	// 2. Connection worker pool + stagger + intensive cap.
	switch p {
	case PresetFast:
		cfg.ConnectionWorkerPoolSize = 10
		cfg.StaggerConnectionWorkersMilliseconds = 100
		cfg.LimitIntensiveConnectionWorkers = 4
	case PresetPatient:
		cfg.ConnectionWorkerPoolSize = 16
		cfg.StaggerConnectionWorkersMilliseconds = 250
		cfg.LimitIntensiveConnectionWorkers = 4
	default: // balanced
		cfg.ConnectionWorkerPoolSize = 12
		cfg.StaggerConnectionWorkersMilliseconds = 150
		cfg.LimitIntensiveConnectionWorkers = 4
	}

	// 3. EstablishTunnelTimeoutSeconds: escalate 35 -> 75 -> 150 s, как в 2.3.9-fixed
	// (решение Аллы 2026-11-24: бюджеты 90/150/240 на её сети дают долгое ожидание и
	// быстрый сброс). ВАЖНО: этот внутренний бюджет обязан двигаться вместе с
	// attemptTimeout в psiorder.go — applyTuning берёт max() из двух, и один только
	// внешний таймаут ничего не ускорит. Идущую загрузку списка серверов/тактик
	// прикрывает rslGrace в attemptOnce (продление по факту, а не по расписанию),
	// поэтому пол при пустом сиде равен бюджету раунда 0, а не 60 с.
	budgets := []int{35, 75, 150}
	if p == PresetPatient {
		budgets = []int{150, 210, 300}
	} else if p == PresetFast {
		budgets = []int{35, 60, 120}
	}
	rIdx := min(max(round, 0), len(budgets)-1)
	timeout := budgets[rIdx]
	if cfg.EstablishTunnelTimeoutSeconds != nil && *cfg.EstablishTunnelTimeoutSeconds > 0 {
		if rIdx == 0 || *cfg.EstablishTunnelTimeoutSeconds > timeout {
			timeout = *cfg.EstablishTunnelTimeoutSeconds
		}
	}
	if seedEmptyOrRSL && timeout < minSeedOrRSLTimeout {
		timeout = minSeedOrRSLTimeout
	}
	cfg.EstablishTunnelTimeoutSeconds = ptr(timeout)

	// 4. DNS hardening: if preflight detected DNS poisoning, TUN is active (with DeviceBinder),
	// or always on balanced/patient direct, supply alternate DNS resolvers to tunnel-core when
	// not already routed via upstream SOCKS.
	if cfg.UpstreamProxyURL == "" {
		poisoned := report != nil && report.DNSPoisoned
		if cfg.DeviceBinder != nil || p != PresetFast || poisoned {
			cfg.DNSResolverAlternateServers = append([]string(nil), defaultAlternateDNSServers...)
		}
		if p != PresetFast || poisoned || tunActive.Load() {
			// tunnel-core's Resolver checks DNSResolverPreferredAlternateServers alongside PreferAlternateServerProbability.
			cfg.DNSResolverPreferredAlternateServers = append([]string(nil), defaultAlternateDNSServers...)
			cfg.DNSResolverPreferAlternateServerProbability = ptr(1.0)
		}
	}
}
