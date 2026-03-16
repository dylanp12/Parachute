package broker

import (
	"net/http"
	"testing"
)

func TestStripAndInject(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/test/test", nil)
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("X-Auth-Token", "agent-x-token")
	req.Header.Set("X-Custom", "keep-me")

	StripAndInject(req, &Credential{
		HeaderName:  "Authorization",
		HeaderValue: "Bearer broker-token",
	})

	if got := req.Header.Get("Authorization"); got != "Bearer broker-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer broker-token")
	}
	if got := req.Header.Get("X-Auth-Token"); got != "" {
		t.Errorf("X-Auth-Token should be stripped, got %q", got)
	}
	if got := req.Header.Get("X-Custom"); got != "keep-me" {
		t.Errorf("X-Custom = %q, want keep-me (should be preserved)", got)
	}
}

func TestStripAndInject_NilCredential(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/test/test", nil)
	req.Header.Set("Authorization", "Bearer agent-token")

	StripAndInject(req, nil)

	// Should be a no-op
	if got := req.Header.Get("Authorization"); got != "Bearer agent-token" {
		t.Errorf("nil credential should be a no-op, Authorization = %q", got)
	}
}

func TestStripAuth(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/test/test", nil)
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("X-Auth-Token", "agent-x-token")
	req.Header.Set("Private-Token", "agent-private")
	req.Header.Set("X-Custom", "keep-me")

	StripAuth(req)

	for _, h := range authHeaders {
		if got := req.Header.Get(h); got != "" {
			t.Errorf("%s should be stripped, got %q", h, got)
		}
	}
	if got := req.Header.Get("X-Custom"); got != "keep-me" {
		t.Errorf("X-Custom should be preserved, got %q", got)
	}
}
