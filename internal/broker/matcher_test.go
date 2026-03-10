package broker

import "testing"

func newTestMatcher() *IntegrationMatcher {
	return NewMatcher([]IntegrationDef{
		{
			Name:  "github",
			Hosts: []string{"api.github.com", "uploads.github.com"},
		},
	})
}

func TestMatcher_Match(t *testing.T) {
	m := newTestMatcher()

	tests := []struct {
		name       string
		hostname   string
		wantMatch  bool
		wantInteg  string
		wantHost   string
	}{
		{"github api", "api.github.com", true, "github", "api.github.com"},
		{"github uploads", "uploads.github.com", true, "github", "uploads.github.com"},
		{"github api with port", "api.github.com:443", true, "github", "api.github.com"},
		{"case insensitive", "API.GITHUB.COM", true, "github", "api.github.com"},
		{"mixed case", "Api.GitHub.Com", true, "github", "api.github.com"},
		{"not managed", "api.anthropic.com", false, "", ""},
		{"similar but different", "api.github.io", false, "", ""},
		{"empty", "", false, "", ""},
		{"just github.com", "github.com", false, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.Match(tt.hostname)
			if tt.wantMatch {
				if result == nil {
					t.Fatalf("expected match for %q, got nil", tt.hostname)
				}
				if result.Integration != tt.wantInteg {
					t.Errorf("integration = %q, want %q", result.Integration, tt.wantInteg)
				}
				if result.Host != tt.wantHost {
					t.Errorf("host = %q, want %q", result.Host, tt.wantHost)
				}
			} else {
				if result != nil {
					t.Errorf("expected no match for %q, got %+v", tt.hostname, result)
				}
			}
		})
	}
}

func TestMatcher_EmptyDefs(t *testing.T) {
	m := NewMatcher(nil)
	if result := m.Match("api.github.com"); result != nil {
		t.Errorf("empty matcher should not match, got %+v", result)
	}
}

func TestMatcher_Integrations(t *testing.T) {
	m := newTestMatcher()
	names := m.Integrations()
	if len(names) != 1 || names[0] != "github" {
		t.Errorf("Integrations() = %v, want [github]", names)
	}
}

func TestMatcher_HostForIntegration(t *testing.T) {
	m := newTestMatcher()
	host := m.HostForIntegration("github")
	if host != "api.github.com" && host != "uploads.github.com" {
		t.Errorf("HostForIntegration(github) = %q, want api.github.com or uploads.github.com", host)
	}
	if host := m.HostForIntegration("unknown"); host != "" {
		t.Errorf("HostForIntegration(unknown) = %q, want empty", host)
	}
}
