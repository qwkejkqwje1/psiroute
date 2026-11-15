package main

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io"
	"strings"
)

// Compressed source assets are decompressed only by their consumers. Keep the
// editable originals and regenerate gzip files when their contents change.
//
//go:embed ui/index.html.gz seedlists/*.txt.gz
var compressedAssets embed.FS

func readCompressedAsset(path string) ([]byte, error) {
	b, err := compressedAssets.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
func builtinSeed(name string) (string, bool) {
	// Names come from user include directives; forbid traversal into other assets.
	if strings.ContainsAny(name, "/\\.") {
		return "", false
	}
	b, err := readCompressedAsset("seedlists/" + name + ".txt.gz")
	return string(b), err == nil
}
func builtinSeedNames() []string {
	entries, err := compressedAssets.ReadDir("seedlists")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, strings.TrimSuffix(entry.Name(), ".txt.gz"))
	}
	return names
}
