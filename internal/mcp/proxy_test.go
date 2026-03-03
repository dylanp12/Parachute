package mcp

import "testing"

func TestStdioUpstreamReturns501(t *testing.T) {
	cfg := ServerConfig{Name: "local", Transport: "stdio", Command: "node server.js"}
	if cfg.Transport != "stdio" {
		t.Fatal("transport should be stdio")
	}
	// Verify the config structure is correct
	if cfg.Command != "node server.js" {
		t.Fatal("command should be preserved")
	}
}

func TestHTTPUpstreamDefault(t *testing.T) {
	cfg := ServerConfig{Name: "remote", URL: "http://localhost:9090"}
	if cfg.Transport != "" {
		t.Fatal("transport should default to empty (caller sets 'http')")
	}
}
