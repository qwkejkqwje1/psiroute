package main

import (
	"net"
	"net/url"
	"strings"
)

// isHTTPURL reports whether raw is an absolute http or https URL. It is checked
// before a URL is handed to the shell (rundll32): file:, javascript:, ms-*: and
// other schemes must never be opened this way.
func isHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	s := strings.ToLower(u.Scheme)
	return s == "http" || s == "https"
}

// pprofLoopbackAddr makes the pprof listener loopback-only: a non-loopback or
// empty host is replaced by 127.0.0.1 and a loud warning is returned. pprof on a
// public address would expose memory and goroutine dumps.
func pprofLoopbackAddr(addr string) (listen, warning string) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "127.0.0.1:6060", "Адрес -pprof «" + addr + "» не разобран; pprof слушает только 127.0.0.1:6060"
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return net.JoinHostPort(host, port), ""
	}
	return net.JoinHostPort("127.0.0.1", port), "ВНИМАНИЕ: -pprof был задан на " + addr + " (не loopback) — pprof открывает дампы памяти и горутин. Слушаю только 127.0.0.1:" + port
}
