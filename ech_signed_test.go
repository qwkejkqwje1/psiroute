package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestECHCustomTXTRequiresSignature(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	cfg := buildSyntheticECHConfigList("ech.example", 0x55)
	payload := base64.StdEncoding.EncodeToString(cfg)
	sign := func(data string) string {
		return "sig=" + hex.EncodeToString(ed25519.Sign(priv, []byte(data))) + ";data=" + data
	}
	valid := sign(payload)
	mid := len(valid) / 2
	for _, tc := range []struct {
		name string
		txt  []string
		key  string
		want bool
	}{
		{"raw", []string{payload}, key, false},
		{"prefix", []string{"ech=" + payload}, key, false},
		{"bad-signature", []string{"sig=bad;ech=" + payload}, key, false},
		{"unsigned-among-invalid", []string{"sig=bad;data=invalid", payload}, key, false},
		{"tampered", []string{valid + "AA"}, key, false},
		{"missing-key", []string{valid}, "", false},
		{"valid", []string{valid}, key, true},
		{"signed-prefix", []string{sign("ech=" + payload)}, key, true},
		{"chunks", []string{"v=psiroute1;seq=1;data=" + valid[mid:], "v=psiroute1;seq=0;data=" + valid[:mid]}, key, true},
		{"signed-invalid-config", []string{sign(base64.StdEncoding.EncodeToString([]byte("invalid")))}, key, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseECHFromTXT(tc.txt, tc.key)
			if ok != tc.want || (ok && !bytes.Equal(got, cfg)) {
				t.Fatalf("accepted=%v want=%v config=%x", ok, tc.want, got)
			}
		})
	}
}
