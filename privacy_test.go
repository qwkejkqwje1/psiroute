package main

import (
	"strings"
	"testing"
)

func TestPrivacyDisplay(t *testing.T) {
	for _, input := range []string{"IP 203.0.113.9:1080", "[2001:db8::1]:443", "https://visited.example/path", "домен пример.рф → direct", "example.com.", "2001:db8::abcd", "::1", "xn--e1afmkfd.xn--p1ai", "https://host.example:8443/a"} {
		got := privacyDisplay(input, true)
		if got == input {
			t.Errorf("not masked: %q", input)
		}
		if privacyDisplay(input, false) != input {
			t.Errorf("disabled altered %q", input)
		}
	}
	for _, input := range []string{"Psiroute.exe", "config.json", "12.5 MB", "Пауза 5 мин"} {
		if got := privacyDisplay(input, true); got != input {
			t.Errorf("ordinary text changed: %q => %q", input, got)
		}
	}
	if got := privacyDisplay("a.example b.example", true); strings.Contains(got, "example") {
		t.Fatal(got)
	}
}
