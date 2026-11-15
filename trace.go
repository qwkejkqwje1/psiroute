package main

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"time"
)

// traceInfo is the subset of Cloudflare's /cdn-cgi/trace we care about.
type traceInfo struct {
	IP   string
	Loc  string // country code
	Colo string // Cloudflare datacenter
}

// getTrace fetches https://www.cloudflare.com/cdn-cgi/trace through the given
// dialer and reports the exit IP and location. It is the quickest way to prove
// a tunnel actually carries traffic.
func getTrace(ctx context.Context, dial dialFunc) (traceInfo, error) {
	var tr traceInfo
	c := &http.Client{
		Transport: &http.Transport{DialContext: dial, TLSHandshakeTimeout: 10 * time.Second},
	}
	defer c.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return tr, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return tr, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			tr.IP = v
		case "loc":
			tr.Loc = v
		case "colo":
			tr.Colo = v
		}
	}
	return tr, sc.Err()
}
