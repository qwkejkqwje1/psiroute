package main

import (
	"fmt"
	"strconv"
	"strings"
)

func ruleEditableTokens(r map[string]any) string {
	var parts []string
	addStrs := func(key, prefix string) {
		switch arr := r[key].(type) {
		case []any:
			for _, it := range arr {
				if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
					if prefix != "" && !strings.HasPrefix(s, prefix) {
						parts = append(parts, prefix+s)
					} else {
						parts = append(parts, s)
					}
				}
			}
		case []string:
			for _, s := range arr {
				if strings.TrimSpace(s) != "" {
					if prefix != "" && !strings.HasPrefix(s, prefix) {
						parts = append(parts, prefix+s)
					} else {
						parts = append(parts, s)
					}
				}
			}
		}
	}
	addStrs("lists", "list:")
	addStrs("domains", "domain:")
	addStrs("ips", "cidr:")
	addStrs("cidr", "cidr:")
	addStrs("keywords", "keyword:")
	addStrs("port_ranges", "port:")
	addStrs("apps", "app:")
	if p, ok := r["ports"].(string); ok && strings.TrimSpace(p) != "" {
		parts = append(parts, "port:"+strings.TrimSpace(p))
	}
	if ports, ok := r["ports"].([]any); ok {
		for _, port := range ports {
			parts = append(parts, "port:"+fmt.Sprint(port))
		}
	}
	if ports, ok := r["ports"].([]int); ok {
		for _, port := range ports {
			parts = append(parts, "port:"+strconv.Itoa(port))
		}
	}
	for i, part := range parts {
		if strings.ContainsAny(part, ",;\n\r#\"") {
			parts[i] = strconv.Quote(part)
		}
	}
	return strings.Join(parts, ", ")
}

// Preserve the typed original when only metadata (such as outbound or always) is edited:
// smart token classification cannot losslessly represent regexes, keywords or list names,
// and exact_domains in rulesAddAPI preserves domain entries verbatim without adding "exact:" prefix.
func ruleEditRequest(original map[string]any, target, name, outbound, proto string, always bool) map[string]any {
	body := map[string]any{"name": name, "outbound": outbound, "proto": proto, "always": always}
	if original != nil {
		body["disabled"] = original["disabled"]
	}
	if original != nil && target == ruleEditableTokens(original) {
		for _, key := range []string{"domains", "cidr", "ips", "keywords", "lists", "apps", "ports", "port_ranges"} {
			if value, ok := original[key]; ok {
				switch key {
				case "domains":
					body["exact_domains"] = value
				case "ips":
					if _, hasCIDR := original["cidr"]; !hasCIDR {
						body["cidr"] = value
					}
				default:
					body[key] = value
				}
			}
		}
	} else {
		body["tokens"] = target
	}
	return body
}

// splitRuleInput preserves explicitly quoted editor tokens (regex repetition,
// keyword punctuation), while keeping legacy delimiters for unquoted input.
func splitRuleInput(raw string) []string {
	var result []string
	for len(strings.TrimSpace(raw)) > 0 {
		raw = strings.TrimLeft(raw, " ,;\n\r\t")
		if raw == "" {
			break
		}
		if raw[0] == '"' {
			end := 1
			for end < len(raw) {
				if raw[end] == '\\' {
					end += 2
					continue
				}
				if raw[end] == '"' {
					break
				}
				end++
			}
			if end < len(raw) {
				if token, err := strconv.Unquote(raw[:end+1]); err == nil {
					result = append(result, token)
					raw = raw[end+1:]
					continue
				}
			}
		}
		end := strings.IndexAny(raw, ",;\n\r")
		if end < 0 {
			end = len(raw)
		}
		if token := sanitizeRuleToken(raw[:end]); token != "" {
			result = append(result, token)
		}
		raw = raw[end:]
	}
	return result
}
