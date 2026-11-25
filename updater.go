package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// UpdateManifest описывает подписанный манифест обновления клиента PsiRoute.
// Загрузка манифеста и бинарного обновления прозрачно маршрутизируется через
// активный туннель (Psiphon / WARP / DPI-обход), если GitHub или сервер обновлений
// недоступен напрямую в РФ, с обязательной проверкой SHA-256 и подписи Ed25519.
type UpdateManifest struct {
	Version    string `json:"version"`
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	Ed25519Sig string `json:"ed25519_sig"`
	Notes      string `json:"notes,omitempty"`
	// Release is a monotonically growing release number; NotAfter is the Unix time
	// after which the manifest is no longer accepted. Both are signed (audit A-07),
	// so an old signed manifest cannot be replayed to roll the client back.
	Release  int64 `json:"release"`
	NotAfter int64 `json:"not_after"`
}

// currentRelease is the release number of this build. It grows with every
// version; a manifest is accepted only if its release is greater.
const currentRelease int64 = 20400 // major*10000 + minor*100 + patch: 2.4.0 -> 20400

// updaterNow is the clock of the manifest check (replaced in tests).
var updaterNow = time.Now

// CanonicalPayload — подписываемая строка формата v2:
// "v2|release|version|sha256|url|not_after". Формат v1 ("version|sha256|url") не принимается.
func (m *UpdateManifest) CanonicalPayload() []byte {
	return []byte("v2|" + strconv.FormatInt(m.Release, 10) + "|" + strings.TrimSpace(m.Version) + "|" +
		strings.ToLower(strings.TrimSpace(m.SHA256)) + "|" + strings.TrimSpace(m.URL) + "|" +
		strconv.FormatInt(m.NotAfter, 10))
}

// checkFreshness rejects a manifest that is not newer than this build or has expired.
func (m *UpdateManifest) checkFreshness(now time.Time) error {
	if m.Release <= 0 || m.NotAfter <= 0 {
		return errors.New("манифест обновления старого формата (v1) отвергнут: нет номера выпуска и срока действия")
	}
	if m.Release <= currentRelease {
		return fmt.Errorf("манифест отвергнут: номер выпуска %d не новее установленного (%d) — защита от отката", m.Release, currentRelease)
	}
	if now.Unix() > m.NotAfter {
		return errors.New("манифест обновления просрочен (not_after в прошлом)")
	}
	return nil
}

// VerifyManifestSignature проверяет криптографическую подпись Ed25519 манифеста обновления.
func (m *UpdateManifest) VerifyManifestSignature(pubKeyHex string) error {
	if m == nil {
		return errors.New("пустой манифест обновления")
	}
	if strings.TrimSpace(m.Version) == "" || strings.TrimSpace(m.URL) == "" || len(strings.TrimSpace(m.SHA256)) != 64 {
		return errors.New("манифест обновления содержит неполные поля")
	}
	if pubKeyHex == "" {
		pubKeyHex = defaultBootstrapEd25519PubHex // пусто = проверка отказывает (безопасно)
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("некорректный публичный ключ Ed25519")
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(m.Ed25519Sig))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("некорректная подпись Ed25519 в манифесте")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), m.CanonicalPayload(), sigBytes) {
		return errors.New("подпись Ed25519 манифеста обновления не прошла проверку")
	}
	// Свежесть проверяется после подписи: release и not_after подписаны.
	return m.checkFreshness(updaterNow())
}

// VerifyUpdateBinary проверяет контрольную сумму SHA-256 и подпись Ed25519 скачанного .exe файла.
func VerifyUpdateBinary(data []byte, expectedSHA256Hex, sigHex, pubKeyHex string) error {
	if len(data) == 0 {
		return errors.New("файл обновления пуст")
	}
	sum := sha256.Sum256(data)
	gotHex := hex.EncodeToString(sum[:])
	wantHex := strings.ToLower(strings.TrimSpace(expectedSHA256Hex))
	if gotHex != wantHex {
		return fmt.Errorf("контрольная сумма SHA-256 не совпадает: получено %s, ожидалось %s", gotHex, wantHex)
	}
	if pubKeyHex == "" {
		pubKeyHex = defaultBootstrapEd25519PubHex
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("некорректный публичный ключ Ed25519")
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("некорректный формат подписи Ed25519 файла")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), sum[:], sigBytes) && !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
		return errors.New("криптографическая подпись Ed25519 файла обновления недействительна")
	}
	return nil
}

// tunnelHTTPClient возвращает HTTP-клиент, прозрачно идущий через поднятый туннель (Psiphon -> WARP -> DPI -> Direct).
func (a *App) tunnelHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	outbounds := []string{obPsiphon, obWarp, obDesync, obDirect}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
				if a == nil || a.router == nil {
					return dialDirect(ctx, network, addr)
				}
				for _, ob := range outbounds {
					if ob == obPsiphon && (a.psi == nil || !a.psi.running()) {
						continue
					}
					if ob == obWarp && (a.warp == nil || !a.warp.connected()) {
						continue
					}
					c, derr := a.router.dialer(ob)(ctx, network, addr)
					if derr == nil {
						return c, nil
					}
					err = derr
				}
				return nil, err
			},
		},
	}
}

// CheckUpdateViaTunnel загружает манифест новой версии через активный туннель и проверяет его Ed25519-подпись.
func (a *App) CheckUpdateViaTunnel(ctx context.Context, manifestURL, pubKeyHex string) (*UpdateManifest, error) {
	manifestURL = strings.TrimSpace(manifestURL)
	if manifestURL == "" {
		return nil, errors.New("не указан URL манифеста обновления")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.tunnelHTTPClient(15 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("сервер обновлений вернул HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var m UpdateManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("ошибка чтения манифеста обновления: %w", err)
	}
	if err := m.VerifyManifestSignature(pubKeyHex); err != nil {
		return nil, err
	}
	return &m, nil
}

const maxUpdateBinaryBytes = 256 << 20

// DownloadUpdateViaTunnel stages an authenticated release without replacing the
// running executable. On failure the destination is preserved and temp removed.
func (a *App) DownloadUpdateViaTunnel(ctx context.Context, manifest *UpdateManifest, pubKeyHex, destination string) error {
	if err := manifest.VerifyManifestSignature(pubKeyHex); err != nil {
		return err
	}
	if strings.TrimSpace(destination) == "" {
		return errors.New("update staging destination is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.URL, nil)
	if err != nil {
		return err
	}
	client := a.tunnelHTTPClient(5 * time.Minute)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update download HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxUpdateBinaryBytes {
		return errors.New("update binary exceeds size limit")
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".psiroute-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, maxUpdateBinaryBytes+1))
	if err != nil {
		return err
	}
	if size == 0 || size > maxUpdateBinaryBytes {
		return errors.New("invalid update binary size")
	}
	if hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(strings.TrimSpace(manifest.SHA256)) {
		return errors.New("update SHA-256 mismatch")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), destination)
}
