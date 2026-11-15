package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

func TestEmergencyBootstrapRequiresSignature(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	validEntryRaw := `203.0.113.55 80 DE web {"ipAddress":"203.0.113.55","webServerPort":"80","webServerSecret":"sec999","webServerCertificate":"cert","sshPort":22,"sshPassword":"pw","sshHostKey":"hk","sshObfuscatedPort":443,"sshObfuscatedKey":"obkey","region":"DE","capabilities":["OSSH","TLS-OSSH"]}`
	hexEntry := hex.EncodeToString([]byte(validEntryRaw))
	sig := hex.EncodeToString(ed25519.Sign(priv, []byte(hexEntry)))
	for _, source := range []string{"txt", "mirror"} {
		for _, tc := range []struct {
			name, payload, key string
			want               int
		}{
			{"plain", hexEntry, key, 0}, {"prefix", "psiroute-se:" + hexEntry, key, 0}, {"invalid-json", `{"sig":"bad","data":"` + hexEntry + `"}`, key, 0}, {"invalid-kv", "sig=bad;data=" + hexEntry, key, 0}, {"tampered", "sig=" + sig + ";data=" + hexEntry + "00", key, 0}, {"missing-key", "sig=" + sig + ";data=" + hexEntry, "", 0}, {"invalid-key", "sig=" + sig + ";data=" + hexEntry, "bad", 0}, {"valid", "sig=" + sig + ";data=" + hexEntry, key, 1}, {"valid-json", `{"sig":"` + sig + `","data":"` + hexEntry + `"}`, key, 1},
		} {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				a := testApp(t)
				setDNSTXTLookupHook(func(context.Context, string) ([]string, error) {
					if source == "txt" {
						return []string{tc.payload}, nil
					}
					return nil, errors.New("synthetic unavailable")
				})
				defer setDNSTXTLookupHook(nil)
				a.psi.mirrorFetchFunc = func(context.Context, string) (string, error) {
					if source == "mirror" {
						return tc.payload, nil
					}
					return "", errors.New("synthetic unavailable")
				}
				got := a.psi.bootstrapEmergencyServerEntries(context.Background(), tc.key)
				if got != tc.want || a.psi.importedServerEntriesCount() != tc.want {
					t.Fatalf("added=%d count=%d want=%d", got, a.psi.importedServerEntriesCount(), tc.want)
				}
			})
		}
	}
}
