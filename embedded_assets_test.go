package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCompressedAssetsMatchSources(t *testing.T) {
	paths := []string{"ui/index.html"}
	for _, name := range builtinSeedNames() {
		paths = append(paths, "seedlists/"+name+".txt")
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readCompressedAsset(path + ".gz")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("stale gzip asset: run python3 tools/compress-assets.py")
			}
		})
	}
	if _, ok := builtinSeed("../ui/index.html"); ok {
		t.Fatal("accepted non-seed path")
	}
}

func TestEmbeddedHTMLResponse(t *testing.T) {
	a := testApp(t)
	source, err := os.ReadFile("ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	// The embedded gzip is storage compression; HTTP serves decoded HTML after
	// token substitution, so it must not advertise gzip or its compressed size.
	if w.Header().Get("Content-Encoding") != "" {
		t.Fatal("incorrect compressed HTTP header")
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatal("incorrect content type")
	}
	want := bytes.ReplaceAll(source, []byte("__PSIROUTE_TOKEN__"), []byte(a.token))
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatal("HTML/token differs from source")
	}
}
