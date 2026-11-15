package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigMigrationBackupFailurePreservesOriginal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	original := []byte(`{"schema_version":1,"routing":{"default":"direct"}}`)
	if err := os.WriteFile(p, original, 0600); err != nil {
		t.Fatal(err)
	}
	// A directory at the destination reliably rejects rename even under root.
	if err := os.Mkdir(p+".bak", 0700); err != nil {
		t.Fatal(err)
	}
	c := loadConfig(p)
	if !strings.Contains(c.corruptError(), "резервная копия не создана") {
		t.Fatalf("missing backup error: %s", c.corruptError())
	}
	if c.corruptBackupPath() != "" {
		t.Fatal("reported nonexistent backup")
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(original) {
		t.Fatalf("original changed: %q, %v", got, err)
	}
	if c.Routing.Default != "direct" {
		t.Fatal("loaded settings lost")
	}
}

func TestConfigMigrationSaveFailureReportsBackup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	original := []byte(`{"schema_version":1}`)
	if err := os.WriteFile(p, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	c := loadConfig(p)
	if !strings.Contains(c.corruptError(), "не сохранена") {
		t.Fatalf("missing save error: %s", c.corruptError())
	}
	backup, err := os.ReadFile(c.corruptBackupPath())
	if err != nil || string(backup) != string(original) {
		t.Fatalf("backup lost: %q, %v", backup, err)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(original) {
		t.Fatalf("original changed: %q, %v", got, err)
	}
}
