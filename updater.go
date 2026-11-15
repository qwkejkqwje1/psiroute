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
}

// CanonicalPayload формирует строку "version|sha256|url", подписываемую ключом Ed25519 разработчика.
func (m *UpdateManifest) CanonicalPayload() []byte {
	return []byte(strings.TrimSpace(m.Version) + "|" + strings.ToLower(strings.TrimSpace(m.SHA256)) + "|" + strings.TrimSpace(m.URL))
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
		pubKeyHex = defaultBootstrapEd25519PubHex
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
	return nil
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
