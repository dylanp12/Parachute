package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	content := `
auth:
  username: "testuser"
  password_env: "TEST_PASSWORD"
  allowed_ips:
    - "127.0.0.1"

risk_policy:
  block_commands:
    - "rm -rf /"
  require_approval:
    - "\\bsudo\\b"

egress:
  allow_domains:
    - "api.example.com"
    - "*.github.com"
  pii_patterns:
    - "\\b4[0-9]{12}(?:[0-9]{3})?\\b"

upstream: "http://localhost:3000"
listen: ":9090"
`
	tmpFile, err := os.CreateTemp("", "parachute-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Auth.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", cfg.Auth.Username)
	}

	if cfg.Listen != ":9090" {
		t.Errorf("Expected listen ':9090', got '%s'", cfg.Listen)
	}
}

func TestPasswordFromEnv(t *testing.T) {
	cfg := AuthConfig{PasswordEnv: "TEST_PARACHUTE_PASS"}
	os.Setenv("TEST_PARACHUTE_PASS", "secret123")
	defer os.Unsetenv("TEST_PARACHUTE_PASS")

	if cfg.Password() != "secret123" {
		t.Errorf("Expected password 'secret123', got '%s'", cfg.Password())
	}
}

func TestRiskPolicyBlock(t *testing.T) {
	policy := RiskPolicyConfig{BlockCommands: []string{"rm -rf /", "mkfs\\."}}
	if err := policy.Compile(); err != nil {
		t.Fatalf("Failed to compile policy: %v", err)
	}

	tests := []struct {
		cmd      string
		expected bool
	}{
		{"rm -rf /", true},
		{"rm -rf /home", true},
		{"mkfs.ext4 /dev/sda1", true},
		{"ls -la", false},
	}

	for _, tt := range tests {
		if got := policy.ShouldBlock(tt.cmd); got != tt.expected {
			t.Errorf("ShouldBlock(%q) = %v, want %v", tt.cmd, got, tt.expected)
		}
	}
}

func TestDomainWhitelist(t *testing.T) {
	cfg := EgressConfig{AllowDomains: []string{"api.anthropic.com", "*.github.com"}}

	tests := []struct {
		domain   string
		expected bool
	}{
		{"api.anthropic.com", true},
		{"api.openai.com", false},
		{"raw.github.com", true},
		{"evil.com", false},
	}

	for _, tt := range tests {
		if got := cfg.IsDomainAllowed(tt.domain); got != tt.expected {
			t.Errorf("IsDomainAllowed(%q) = %v, want %v", tt.domain, got, tt.expected)
		}
	}
}

func TestPIIDetection(t *testing.T) {
	cfg := EgressConfig{PIIPatterns: []string{
		"\\b4[0-9]{12}(?:[0-9]{3})?\\b",
		"-----BEGIN RSA PRIVATE KEY-----",
	}}
	if err := cfg.Compile(); err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	tests := []struct {
		content string
		hasPII  bool
	}{
		{"Hello world", false},
		{"My card is 4111111111111111", true},
		{"-----BEGIN RSA PRIVATE KEY-----\nxxx", true},
	}

	for _, tt := range tests {
		hasPII, _ := cfg.ContainsPII(tt.content)
		if hasPII != tt.hasPII {
			t.Errorf("ContainsPII() = %v, want %v", hasPII, tt.hasPII)
		}
	}
}

func TestReverseProxyToolInterceptionDefaultsFalse(t *testing.T) {
	content := `
listen: ":8080"
auth:
  allow_insecure: true
`
	tmpFile, err := os.CreateTemp("", "parachute-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.ReverseProxy.ToolInterception.Enabled {
		t.Error("tool interception should default to false")
	}
}

func TestReverseProxyToolInterceptionExplicitTrue(t *testing.T) {
	content := `
listen: ":8080"
auth:
  allow_insecure: true
reverse_proxy:
  tool_interception:
    enabled: true
`
	tmpFile, err := os.CreateTemp("", "parachute-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if !cfg.ReverseProxy.ToolInterception.Enabled {
		t.Error("tool interception should be true when explicitly set")
	}
}
