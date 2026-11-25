package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// Stage 1 Seed pipeline (Step 2).
// Replaces dead hardcoded emergency bootstrap domains/keys with:
//   1. Parallel multi-carrier seed/mirror acquisition (first success wins)
//   2. Persistent seed store + optional user-provided seed-bundle.txt
//   3. Per-protocol seed health reporting and NO_SEED diagnostics
//   4. Optional user-configured HTTPS mirror URL (off by default)
//   5. Honest import UX (paste/file/QR) with counts and trust warning.

const (
	seedMinHealthyThreshold = 3
	seedTrustWarning        = "Отдельные записи серверов Psiphon не подписываются независимо для клиента — импортируйте их только из источников, которым доверяете."
	seedBundleFilename      = "seed-bundle.txt"

	// seedImportMaxEntries caps the records taken in one import (audit A-04).
	seedImportMaxEntries = 500
	// seedSourcesFilename keeps the import sources the user has already been
	// warned about; the trust warning is shown on the FIRST import from a source.
	seedSourcesFilename = "seed-sources.json"
)

// Honest seed statuses (audit A-03). Only seedStatusOK means that entries really
// reached the store.
const (
	seedStatusOK        = "ok"         // entries were added to / found in the store
	seedStatusReachable = "reachable"  // official list host answers through a carrier; nothing downloaded yet
	seedStatusFailed    = "failed"     // checked and failed
	seedStatusUnchecked = "unchecked"  // not checked (interrupted or nothing to check with)
)

var errSeedRedirect = errors.New("редирект зеркала запрещён: разрешён только https на том же хосте")

// sameHostHTTPSRedirect is the CheckRedirect policy for mirror and list probes:
// only https and only the host of the first request.
func sameHostHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 4 {
		return errSeedRedirect
	}
	if req.URL.Scheme != "https" {
		return errSeedRedirect
	}
	if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
		return errSeedRedirect
	}
	return nil
}

// noteSeedSource remembers an import source and reports whether it is new, i.e.
// whether the trust warning must be shown now.
func (p *Psi) noteSeedSource(source string) (isNew bool) {
	key := strings.ToLower(strings.TrimSpace(source))
	if key == "" {
		key = "unknown"
	}
	if p == nil || p.dataDir == "" {
		return true
	}
	p.seedSourcesMu.Lock()
	defer p.seedSourcesMu.Unlock()
	path := filepath.Join(p.dataDir, seedSourcesFilename)
	var known []string
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &known)
	}
	for _, k := range known {
		if k == key {
			return false
		}
	}
	known = append(known, key)
	if b, err := json.Marshal(known); err == nil {
		if werr := writeFileAtomic(path, b, 0o600); werr != nil {
			logf("warn", "Не удалось запомнить источник записей серверов: %v", werr)
		}
	}
	return true
}

// SeedHealth summarizes usable persisted server entries per protocol.
type SeedHealth struct {
	Total           int            `json:"total"`
	ByProtocol      map[string]int `json:"by_protocol"`
	Healthy         bool           `json:"healthy"`
	Threshold       int            `json:"threshold"`
	Warning         string         `json:"warning,omitempty"`
	LastUpdatedUnix int64          `json:"last_updated_unix,omitempty"`
}

// SeedImportResult is returned by manual/semi-manual import APIs (paste, file, QR).
type SeedImportResult struct {
	OK           bool       `json:"ok"`
	Imported     int        `json:"imported"`
	Added        int        `json:"added"`
	Duplicates   int        `json:"duplicates"`
	Invalid      int        `json:"invalid"`
	Source       string     `json:"source"`
	TrustWarning string     `json:"trust_warning,omitempty"`
	NewSource    bool       `json:"new_source"`
	SeedHealth   SeedHealth `json:"seed_health"`
}

// SeedAcquireResult summarizes one multi-carrier parallel seed acquisition run.
type SeedAcquireResult struct {
	Succeeded bool   `json:"succeeded"`
	Status    string `json:"status"` // seedStatusOK / Reachable / Failed / Unchecked
	Carrier   string `json:"carrier,omitempty"`
	Source    string `json:"source,omitempty"`
	Added     int    `json:"added"`
	DiagCode  string `json:"diag_code,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SeedHealth inspects persisted server entries and counts usable entries per protocol.
func (p *Psi) SeedHealth() SeedHealth {
	sh := SeedHealth{
		ByProtocol: map[string]int{},
		Threshold:  seedMinHealthyThreshold,
	}
	if p == nil || p.dataDir == "" {
		sh.Warning = diagInfoForCode(DiagNoSeed).Message
		return sh
	}
	path := p.serverEntriesFile()
	fi, err := os.Stat(path)
	if err == nil {
		sh.LastUpdatedUnix = fi.ModTime().Unix()
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		sh.Warning = diagInfoForCode(DiagNoSeed).Message
		return sh
	}
	seenIP := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields, derr := protocol.DecodeServerEntryFields(line, "", protocol.SERVER_ENTRY_SOURCE_TARGET)
		if derr != nil || fields == nil {
			continue
		}
		ipStr, _ := fields["ipAddress"].(string)
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" || seenIP[ipStr] {
			continue
		}
		seenIP[ipStr] = true
		sh.Total++
		if caps, ok := fields["capabilities"].([]any); ok {
			for _, rawCap := range caps {
				if capStr, ok := rawCap.(string); ok && capStr != "" {
					sh.ByProtocol[capStr]++
				}
			}
		} else if capsStr, ok := fields["capabilities"].([]string); ok {
			for _, capStr := range capsStr {
				if capStr != "" {
					sh.ByProtocol[capStr]++
				}
			}
		}
	}
	sh.Healthy = sh.Total >= seedMinHealthyThreshold
	if sh.Total == 0 {
		sh.Warning = diagInfoForCode(DiagNoSeed).Message
	} else if !sh.Healthy {
		sh.Warning = fmt.Sprintf("В локальном хранилище мало записей серверов (%d из рекомендуемых %d) — обновите список или импортируйте резервные записи", sh.Total, seedMinHealthyThreshold)
	}
	return sh
}

// loadOptionalSeedBundle imports an optional user-provided seed-bundle.txt from dataDir
// on startup so first start does not depend on network download when bundled by the user.
func (p *Psi) loadOptionalSeedBundle() int {
	if p == nil || p.dataDir == "" {
		return 0
	}
	path := filepath.Join(p.dataDir, seedBundleFilename)
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return 0
	}
	added, _, _, err := p.importServerEntriesWithoutRestart(string(b), "bundle")
	if err != nil {
		return 0
	}
	if added > 0 {
		logf("info", "Psiphon: загружено %d записей серверов из локального пакета %s", added, seedBundleFilename)
	}
	return added
}

// validateUserMirrorURL verifies that an optional user-configured mirror URL is a valid HTTPS URL.
func validateUserMirrorURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("URL зеркала списка серверов должен начинаться с https:// и содержать домен")
	}
	return u.String(), nil
}

// fetchMirrorOverCarrier downloads raw server entries from a user-configured HTTPS mirror
// through a specific Carrier.
func fetchMirrorOverCarrier(ctx context.Context, c Carrier, mirrorURL string) (string, error) {
	if c == nil || !c.Configured() {
		return "", errors.New("носитель не настроен")
	}
	tctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cl := &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{DialContext: c.Dial},
		CheckRedirect: sameHostHTTPSRedirect,
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, mirrorURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// AcquireSeedsParallel tries to acquire server entries in parallel across all healthy
// configured carriers (first success wins). It uses the user-configured HTTPS mirror URL
// (off by default) or an injected fetcher for offline tests. No built-in fake endpoints exist.
func (p *Psi) AcquireSeedsParallel(
	ctx context.Context,
	carriers []Carrier,
	mirrorURL string,
	fetchFn func(ctx context.Context, c Carrier, targetURL string) (string, error),
) SeedAcquireResult {
	var healthy []Carrier
	for _, c := range carriers {
		if c != nil && c.Configured() && c.Healthy() {
			healthy = append(healthy, c)
		}
	}
	if len(healthy) == 0 {
		info := diagInfoForCode(DiagNoSeed)
		if p != nil {
			p.set(func() {
				p.diagCode = DiagNoSeed
				p.diagReason = info.Message
				p.diagAdvice = info.ManualAction
			})
			p.tl().Record(connTimelineEvent{
				Stage:    "seed",
				Outcome:  "failed",
				DiagCode: DiagNoSeed,
				Detail:   "Нет здоровых носителей для загрузки списка серверов",
			})
		}
		return SeedAcquireResult{
			Succeeded: false,
			Status:    seedStatusFailed,
			DiagCode:  DiagNoSeed,
			Error:     info.Message,
		}
	}

	targetURL := strings.TrimSpace(mirrorURL)
	if targetURL == "" {
		// No user mirror configured: tunnel-core fetches the official list itself.
		// Report only what was verified (never "success" without a check).
		return p.probeOfficialListOverCarriers(ctx, healthy)
	}
	if _, err := validateUserMirrorURL(targetURL); err != nil {
		return SeedAcquireResult{Succeeded: false, Status: seedStatusFailed, DiagCode: DiagNoSeed, Error: err.Error()}
	}
	if fetchFn == nil {
		fetchFn = fetchMirrorOverCarrier
	}

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type attemptRes struct {
		carrier string
		body    string
		err     error
	}
	resCh := make(chan attemptRes, len(healthy))
	var wg sync.WaitGroup
	for _, c := range healthy {
		carrier := c
		wg.Add(1)
		safeGo("Psi.AcquireSeedsParallel", func() {
			defer wg.Done()
			body, err := fetchFn(rctx, carrier, targetURL)
			resCh <- attemptRes{carrier: carrier.Name(), body: body, err: err}
		})
	}
	safeGo("Psi.AcquireSeedsParallel#2", func() {
		wg.Wait()
		close(resCh)
	})

	var lastErr error
	for r := range resCh {
		if r.err != nil || strings.TrimSpace(r.body) == "" {
			if r.err != nil {
				lastErr = r.err
			}
			continue
		}
		added, dup, _, ierr := p.importServerEntriesWithoutRestart(r.body, "mirror:"+r.carrier)
		if ierr == nil && (added+dup) > 0 {
			cancel()
			p.tl().Record(connTimelineEvent{
				Stage:   "seed",
				Carrier: r.carrier,
				Outcome: "ok",
				Detail:  fmt.Sprintf("mirror added=%d dup=%d", added, dup),
			})
			if p.noteSeedSource("mirror:" + mirrorHost(targetURL)) {
				logf("warn", "Новый источник записей серверов (зеркало %s). %s", mirrorHost(targetURL), seedTrustWarning)
			}
			return SeedAcquireResult{
				Succeeded: true,
				Status:    seedStatusOK,
				Carrier:   r.carrier,
				Source:    "mirror:" + r.carrier,
				Added:     added,
			}
		}
		if ierr != nil {
			lastErr = ierr
		}
	}

	info := diagInfoForCode(DiagNoSeed)
	errMsg := info.Message
	if lastErr != nil {
		errMsg = maskTimelineSecrets(cleanPsiErr(lastErr.Error()))
	}
	if p != nil {
		p.set(func() {
			p.diagCode = DiagNoSeed
			p.diagReason = info.Message
			p.diagAdvice = info.ManualAction
		})
		p.tl().Record(connTimelineEvent{
			Stage:    "seed",
			Outcome:  "failed",
			DiagCode: DiagNoSeed,
			Detail:   errMsg,
		})
	}
	return SeedAcquireResult{
		Succeeded: false,
		Status:    seedStatusFailed,
		DiagCode:  DiagNoSeed,
		Error:     errMsg,
	}
}

// mirrorHost is the host part of a mirror URL, for logs and source tracking.
func mirrorHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	return "?"
}

// probeOfficialListOverCarriers is the honest path when no mirror is configured
// (audit A-03): it really asks the official list host for a range of bytes
// through every healthy carrier. It does NOT download the list, so a good result
// is "reachable", never "ok": tunnel-core itself fetches the list later.
func (p *Psi) probeOfficialListOverCarriers(ctx context.Context, healthy []Carrier) SeedAcquireResult {
	probe := probeRangeOverCarrier
	if p != nil && p.seedProbe != nil {
		probe = p.seedProbe
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		carrier string
		n       int
		err     error
	}
	ch := make(chan res, len(healthy))
	for _, c := range healthy {
		c := c
		safeGo("probeOfficialList", func() {
			n, err := probe(rctx, c, psiRSLBackupURL1, probeChunkMinBytes)
			ch <- res{c.Name(), n, err}
		})
	}
	var lastErr error
	for range healthy {
		r := <-ch
		if r.err == nil && r.n >= probeChunkMinBytes {
			p.tl().Record(connTimelineEvent{
				Stage:   "seed",
				Carrier: r.carrier,
				Outcome: "reachable",
				Detail:  "официальный список доступен (диапазонный запрос); загрузка — за tunnel-core",
			})
			return SeedAcquireResult{Status: seedStatusReachable, Carrier: r.carrier, Source: "rsl-probe:" + r.carrier}
		}
		if r.err != nil {
			lastErr = r.err
		}
	}
	if ctx.Err() != nil {
		return SeedAcquireResult{Status: seedStatusUnchecked, Error: "проверка списка серверов прервана"}
	}
	msg := diagInfoForCode(DiagNoSeed).Message
	if lastErr != nil {
		msg = maskTimelineSecrets(cleanPsiErr(lastErr.Error()))
	}
	p.tl().Record(connTimelineEvent{Stage: "seed", Outcome: "failed", DiagCode: DiagNoSeed, Detail: msg})
	return SeedAcquireResult{Status: seedStatusFailed, DiagCode: DiagNoSeed, Error: msg}
}
