package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateDownloadPreservesDestinationOnFailure(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("synthetic release")
	sum := sha256.Sum256(body)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.Write(body) }))
	defer server.Close()
	for _, mode := range []string{"valid", "tamper", "signature", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "release.exe")
			if mode != "valid" {
				if err := os.WriteFile(path, []byte("previous"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			m := &UpdateManifest{Version: "2.0.5", URL: server.URL, SHA256: hex.EncodeToString(sum[:]), Release: currentRelease + 1, NotAfter: time.Now().Add(time.Hour).Unix()}
			if mode == "tamper" {
				m.SHA256 = hex.EncodeToString(make([]byte, 32))
			}
			m.Ed25519Sig = hex.EncodeToString(ed25519.Sign(key, m.CanonicalPayload()))
			if mode == "signature" {
				m.Version = "changed"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			before := requests
			err := (*App)(nil).DownloadUpdateViaTunnel(ctx, m, hex.EncodeToString(pub), path)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("error=%v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := "previous"
			if mode == "valid" {
				want = string(body)
			}
			if string(got) != want {
				t.Fatalf("destination=%q", got)
			}
			if mode == "signature" && requests != before {
				t.Fatal("invalid signature caused download")
			}
			leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".psiroute-update-*"))
			if len(leftovers) != 0 {
				t.Fatal("temporary files leaked")
			}
		})
	}
}
