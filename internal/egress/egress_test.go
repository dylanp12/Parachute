package egress

import (
	"testing"

	"github.com/dylanp12/parachute/internal/config"
)

func TestCheckURLStructuredRules(t *testing.T) {
	cfg := &config.EgressConfig{
		Rules: []config.EgressRule{
			{Domains: []string{"api.openai.com", "*.anthropic.com"}, Label: "llm-providers", Action: "allow"},
		},
	}
	f := New(cfg)

	tests := []struct {
		name     string
		url      string
		allowed  bool
		rulePath string
	}{
		{"exact match", "https://api.openai.com/v1/chat", true, "egress/domain/allow:llm-providers"},
		{"wildcard match", "https://api.anthropic.com/v1/messages", true, "egress/domain/allow:llm-providers"},
		{"unlisted domain", "https://evil.com/exfil", false, "egress/domain/deny:unlisted"},
		{"invalid url", "://bad", false, "egress/parse_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := f.CheckURL(tt.url)
			if result.Allowed != tt.allowed {
				t.Errorf("Allowed = %v, want %v", result.Allowed, tt.allowed)
			}
			if result.RulePath != tt.rulePath {
				t.Errorf("RulePath = %q, want %q", result.RulePath, tt.rulePath)
			}
		})
	}
}

func TestCheckURLLegacyFallback(t *testing.T) {
	cfg := &config.EgressConfig{
		AllowDomains: []string{"github.com"},
	}
	f := New(cfg)

	result := f.CheckURL("https://github.com/foo/bar")
	if !result.Allowed {
		t.Error("legacy domain should be allowed")
	}
	if result.RulePath != "egress/domain/allow:legacy" {
		t.Errorf("RulePath = %q, want %q", result.RulePath, "egress/domain/allow:legacy")
	}
}

func TestCheckContentPII(t *testing.T) {
	cfg := &config.EgressConfig{
		PIIPatterns: []string{`AKIA[0-9A-Z]{16}`},
	}
	if err := cfg.Compile(); err != nil {
		t.Fatal(err)
	}
	f := New(cfg)

	result := f.CheckContent("here is AKIAIOSFODNN7EXAMPLE key")
	if result.Allowed {
		t.Error("should block content with AWS key")
	}
}

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		host, pattern string
		want          bool
	}{
		{"api.openai.com", "api.openai.com", true},
		{"API.OpenAI.COM", "api.openai.com", true},
		{"sub.anthropic.com", "*.anthropic.com", true},
		{"anthropic.com", "*.anthropic.com", false},
		{"evil.com", "api.openai.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.host+"_"+tt.pattern, func(t *testing.T) {
			if got := matchDomain(tt.host, tt.pattern); got != tt.want {
				t.Errorf("matchDomain(%q, %q) = %v, want %v", tt.host, tt.pattern, got, tt.want)
			}
		})
	}
}
