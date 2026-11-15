package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCaptivePortalResponse(t *testing.T) {
	for _, tc := range []struct {
		name, request, location, mime, body string
		status                              int
		want                                string
	}{
		{name: "absolute", location: "https://login.example/auth", status: 302, want: "https://login.example/auth"},
		{name: "relative", location: "/login?next=wifi", status: 307, want: "http://connectivitycheck.gstatic.com/login?next=wifi"},
		{name: "network-relative", location: "//login.example/auth#section", status: 511, want: "http://login.example/auth"},
		{name: "script", location: "javascript:alert(1)", status: 302},
		{name: "credentials", location: "https://user:secret@login.example/", status: 302},
		{name: "bad-port", location: "https://login.example:99999/", status: 302},
		{name: "missing-host", location: "http:///login", status: 302},
		{name: "missing-location", status: 511},
		{name: "html-interception", status: 200, mime: "text/html; charset=utf-8", body: " <!DOCTYPE html><html>WiFi login</html>", want: captiveConnectivityURL},
		{name: "arbitrary-page", request: "https://example.com/", status: 200, mime: "text/html", body: "<html>News</html>"},
		{name: "other-probe-path", request: "http://connectivitycheck.gstatic.com/index.html", status: 200, mime: "text/html", body: "<html>News</html>"},
		{name: "wrong-mime", status: 200, mime: "text/plain", body: "<html>News</html>"},
		{name: "nonhtml", status: 200, mime: "text/html", body: "arbitrary data"},
		{name: "online", status: 204},
		{name: "server-error", status: 500, mime: "text/html", body: "<html>Error</html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := tc.request
			if request == "" {
				request = captiveConnectivityURL
			}
			u, err := url.Parse(request)
			if err != nil {
				t.Fatal(err)
			}
			response := &http.Response{StatusCode: tc.status, Request: &http.Request{URL: u}, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}
			defer response.Body.Close()
			response.Header.Set("Location", tc.location)
			response.Header.Set("Content-Type", tc.mime)
			active, got := captivePortalResponse(response)
			if active != (tc.want != "") || got != tc.want {
				t.Fatalf("active=%v url=%q want=%q", active, got, tc.want)
			}
		})
	}
}
