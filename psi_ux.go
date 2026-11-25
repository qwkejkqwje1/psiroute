package main

import (
	"fmt"
	"strings"
)

// Connection State UX & One-Click Actions (Step 6).
// Exposes timeline, carrier ranking, current stage, seed health, tactics status,
// and classified failures with concrete Russian one-click actions for GUI & Web UI.

type connQuickAction struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

var (
	actionImportServers  = connQuickAction{ID: "import_servers", Label: "Импортировать серверы"}
	actionUseWARP        = connQuickAction{ID: "use_warp", Label: "Использовать WARP"}
	actionUseWorker      = connQuickAction{ID: "use_worker", Label: "Использовать свой Worker"}
	actionRunDiagnostics = connQuickAction{ID: "run_diagnostics", Label: "Запустить диагностику"}
	actionRetryPatient   = connQuickAction{ID: "retry_patient", Label: "Повторить в терпеливом режиме"}
)

// actionsForDiagCode returns the ordered one-click actions for any classified failure code.
func actionsForDiagCode(code string) []connQuickAction {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case DiagNoSeed, "NO_CANDIDATES":
		return []connQuickAction{actionImportServers, actionUseWARP, actionUseWorker, actionRunDiagnostics}
	case DiagListHostBlocked:
		return []connQuickAction{actionUseWARP, actionUseWorker, actionImportServers, actionRetryPatient}
	case DiagCarrierThrottled16KB:
		return []connQuickAction{actionUseWorker, actionUseWARP, actionRetryPatient, actionRunDiagnostics}
	case DiagHandshakeReset:
		return []connQuickAction{actionUseWARP, actionUseWorker, actionRetryPatient, actionRunDiagnostics}
	case DiagDNSPoisoned:
		return []connQuickAction{actionRunDiagnostics, actionUseWARP, actionRetryPatient}
	case DiagUDPBlocked:
		return []connQuickAction{actionRetryPatient, actionUseWARP, actionRunDiagnostics}
	case DiagAllProtocolsTimeout, "ALL_TIMEOUT":
		return []connQuickAction{actionRetryPatient, actionUseWARP, actionUseWorker, actionRunDiagnostics}
	case DiagTunnelUnstable:
		return []connQuickAction{actionUseWARP, actionUseWorker, actionRetryPatient, actionRunDiagnostics}
	case DiagClockSkew:
		return []connQuickAction{actionRunDiagnostics, actionRetryPatient}
	case DiagNoNetwork:
		return []connQuickAction{actionRunDiagnostics}
	default:
		return []connQuickAction{actionRunDiagnostics, actionRetryPatient, actionUseWARP}
	}
}

// normalizedDiagCode maps legacy lowercase codes to canonical Section 3.5 uppercase codes.
func normalizedDiagCode(code string) string {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "":
		return ""
	case "no_network":
		return DiagNoNetwork
	case "clock_skew":
		return DiagClockSkew
	case "dns_poisoned":
		return DiagDNSPoisoned
	case "list_host_blocked":
		return DiagListHostBlocked
	case "no_seed", "no_candidates":
		return DiagNoSeed
	case "carrier_throttled_16kb":
		return DiagCarrierThrottled16KB
	case "udp_blocked":
		return DiagUDPBlocked
	case "handshake_reset":
		return DiagHandshakeReset
	case "all_timeout", "all_protocols_timeout":
		return DiagAllProtocolsTimeout
	case "tunnel_unstable":
		return DiagTunnelUnstable
	default:
		return strings.ToUpper(strings.TrimSpace(code))
	}
}

// connectionStateView returns the complete Step 6 UX payload for GET /api/psiphon/state.
func (p *Psi) connectionStateView() map[string]any {
	if p == nil {
		return map[string]any{"ok": false}
	}
	preflight := p.lastPreflightReport()
	timeline := p.tl().Events()
	counters := p.tl().Counters()
	seedHealth := p.SeedHealth()

	var preset, mirrorURL, propID, sponsorID, platform string
	if p.app != nil && p.app.cfg != nil {
		p.app.cfg.mu.Lock()
		preset = normalizePreset(p.app.cfg.Psiphon.Preset)
		mirrorURL = p.app.cfg.Psiphon.MirrorURL
		propID = p.app.cfg.Psiphon.PropagationChannelID
		sponsorID = p.app.cfg.Psiphon.SponsorID
		platform = p.app.cfg.Psiphon.ClientPlatform
		p.app.cfg.mu.Unlock()
	}

	p.mu.Lock()
	state := p.state
	diagCode := normalizedDiagCode(p.diagCode)
	diagReason := p.diagReason
	diagAdvice := p.diagAdvice
	stage := p.stage
	stratID := p.strategy.ID
	stratTitle := p.strategy.Title
	carrier := carrierNameForStrategy(p.strategy)
	tacticsOK := p.tacticsApplied
	tacticsTag := p.tacticsTag
	p.mu.Unlock()

	if diagCode == "" && preflight != nil && preflight.ClassifiedCode != "" && state != "connected" {
		diagCode = preflight.ClassifiedCode
	}
	info := diagInfoForCode(diagCode)
	if diagReason == "" {
		diagReason = info.Message
	}
	if diagAdvice == "" {
		diagAdvice = info.ManualAction
	}

	var ranking []string
	if preflight != nil {
		ranking = preflight.Ranking
	}
	if ranking == nil {
		ranking = []string{}
	}

	tacticsHint := ""
	if !tacticsOK {
		tacticsHint = "Тактики от серверов Psiphon не получены — используются локальные параметры обхода"
	}
	isDefaultIdentity := (propID == "" || strings.EqualFold(propID, psiPropagationChannelID)) &&
		(sponsorID == "" || strings.EqualFold(sponsorID, psiSponsorID))
	identityNote := ""
	if isDefaultIdentity {
		identityNote = clientIdentityNotice
	}
	maskedTactics := "none"
	if tacticsOK {
		if tacticsTag != "" {
			maskedTactics = fmt.Sprintf("applied(%s)", maskTimelineSecrets(tacticsTag))
		} else {
			maskedTactics = "applied"
		}
	}

	return map[string]any{
		"ok":                  true,
		"state":               state,
		"stage":               stage,
		"carrier":             carrier,
		"strategy_id":         stratID,
		"strategy_title":      stratTitle,
		"preset":              preset,
		"mirror_configured":   mirrorURL != "",
		"carrier_ranking":     ranking,
		"preflight":           preflight,
		"seed_health":         seedHealth,
		"tactics_applied":     tacticsOK,
		"tactics_status":      maskedTactics,
		"tactics_hint":        tacticsHint,
		"identity_is_default": isDefaultIdentity,
		"identity_platform":   platform,
		"identity_notice":     identityNote,
		"diag_code":           diagCode,
		"diag_message":        diagReason,
		"diag_auto_action":    info.AutoAction,
		"diag_manual_action":  diagAdvice,
		"actions":             actionsForDiagCode(diagCode),
		"timeline":            timeline,
		"counters":            counters,
	}
}
