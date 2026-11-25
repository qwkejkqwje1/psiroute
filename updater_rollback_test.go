package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// A-07: the manifest is v2 (release + not_after are signed); old, equal-release,
// expired and v1 manifests are refused; an empty trust key refuses everything.
func TestManifestRollbackProtection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	now := time.Unix(1_800_000_000, 0)
	old := updaterNow
	updaterNow = func() time.Time { return now }
	defer func() { updaterNow = old }()

	mk := func(release, notAfter int64) *UpdateManifest {
		m := &UpdateManifest{Version: "2.5.0", URL: "https://updates.example.com/p.exe", SHA256: strings.Repeat("ab", 32), Release: release, NotAfter: notAfter}
		m.Ed25519Sig = hex.EncodeToString(ed25519.Sign(priv, m.CanonicalPayload()))
		return m
	}
	future := now.Add(time.Hour).Unix()

	if err := mk(currentRelease+1, future).VerifyManifestSignature(pubHex); err != nil {
		t.Fatalf("fresh manifest must pass: %v", err)
	}
	for name, m := range map[string]*UpdateManifest{
		"older release":  mk(currentRelease-1, future),
		"equal release":  mk(currentRelease, future),
		"expired":        mk(currentRelease+1, now.Add(-time.Second).Unix()),
		"v1 (no fields)": mk(0, 0),
	} {
		if err := m.VerifyManifestSignature(pubHex); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	// Signed fields cannot be bumped after signing.
	m := mk(currentRelease-1, future)
	m.Release = currentRelease + 50
	if err := m.VerifyManifestSignature(pubHex); err == nil {
		t.Error("changing release after signing must break the signature")
	}
	// The payload really is the v2 format.
	if got := string(mk(241, 99).CanonicalPayload()); !strings.HasPrefix(got, "v2|241|2.5.0|") || !strings.HasSuffix(got, "|99") {
		t.Errorf("payload = %q", got)
	}
	// Empty key: defaultBootstrapEd25519PubHex is empty, so verification refuses (safe).
	if defaultBootstrapEd25519PubHex == "" {
		if err := mk(currentRelease+1, future).VerifyManifestSignature(""); err == nil {
			t.Error("empty trust key must refuse")
		}
	}
}
