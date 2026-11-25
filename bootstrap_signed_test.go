package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestSignedBootstrapPayloadVerification(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	validEntryRaw := `203.0.113.55 80 DE web {"ipAddress":"203.0.113.55","webServerPort":"80","webServerSecret":"sec999","webServerCertificate":"cert","sshPort":22,"sshPassword":"pw","sshHostKey":"hk","sshObfuscatedPort":443,"sshObfuscatedKey":"obkey","region":"DE","capabilities":["OSSH","TLS-OSSH"]}`
	hexEntry := hex.EncodeToString([]byte(validEntryRaw))
	sig := hex.EncodeToString(ed25519.Sign(priv, []byte(hexEntry)))

	for _, tc := range []struct {
		name, payload, key string
		wantOK             bool
	}{
		{"plain", hexEntry, key, false},
		{"prefix", "psiroute-se:" + hexEntry, key, false},
		{"invalid-json", `{"sig":"bad","data":"` + hexEntry + `"}`, key, false},
		{"invalid-kv", "sig=bad;data=" + hexEntry, key, false},
		{"tampered", "sig=" + sig + ";data=" + hexEntry + "00", key, false},
		{"missing-key", "sig=" + sig + ";data=" + hexEntry, "", false},
		{"invalid-key", "sig=" + sig + ";data=" + hexEntry, "bad", false},
		{"valid-kv", "sig=" + sig + ";data=" + hexEntry, key, true},
		{"valid-json", `{"sig":"` + sig + `","data":"` + hexEntry + `"}`, key, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := verifySignedBootstrapPayload(tc.payload, tc.key)
			if ok != tc.wantOK {
				t.Fatalf("verifySignedBootstrapPayload ok=%v, want %v", ok, tc.wantOK)
			}
			if tc.wantOK && got != hexEntry {
				t.Fatalf("payload mismatch: got %q, want %q", got, hexEntry)
			}
		})
	}
}
