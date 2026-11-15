package main

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

// Only rendered text is filtered; editor contents and clipboard values stay intact.
var privacyTokens = regexp.MustCompile(`[\pL\pN_*:%.-]+`)

func privacyDisplay(text string, enabled bool) string {
	if !enabled {
		return text
	}
	return privacyTokens.ReplaceAllStringFunc(text, func(token string) string {
		candidate := strings.Trim(token, ".")
		if _, err := netip.ParseAddr(candidate); err == nil {
			return "[IP скрыт]"
		}
		// Brackets and ports are separate tokens or part of the token respectively.
		host := candidate
		if h, _, ok := strings.Cut(candidate, ":"); ok && strings.Contains(h, ".") {
			host = h
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return "[IP скрыт]"
		}
		host = strings.TrimPrefix(host, "*.")
		parts := strings.Split(host, ".")
		if len(parts) < 2 {
			return token
		}
		tld := parts[len(parts)-1]
		if len(tld) < 2 {
			return token
		}
		for _, r := range tld {
			if !strings.HasPrefix(strings.ToLower(tld), "xn--") && !unicode.IsLetter(r) {
				return token
			}
		}
		// Application/file names are not visited domains.
		switch strings.ToLower(tld) {
		case "exe", "dll", "json", "log", "txt", "bat", "toml":
			return token
		}
		return "[домен скрыт]"
	})
}
