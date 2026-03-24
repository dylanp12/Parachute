package linear

import "testing"

func TestClassify(t *testing.T) {
	c := &Classifier{}

	tests := []struct {
		name     string
		method   string
		path     string
		expected string
	}{
		// GraphQL
		{"post graphql", "POST", "/graphql", RouteGraphQL},
		{"post graphql trailing slash", "POST", "/graphql/", RouteGraphQL},
		{"post graphql with query", "POST", "/graphql?extensions", RouteGraphQL},

		// GraphQL read (introspection)
		{"get graphql", "GET", "/graphql", RouteGraphQLRead},
		{"get graphql trailing slash", "GET", "/graphql/", RouteGraphQLRead},

		// Webhooks
		{"post webhooks", "POST", "/api/webhooks", RouteWebhooks},
		{"post webhooks trailing slash", "POST", "/api/webhooks/", RouteWebhooks},

		// OAuth
		{"oauth authorize", "GET", "/api/oauth/authorize", RouteOAuth},
		{"oauth token", "POST", "/api/oauth/token", RouteOAuth},
		{"oauth revoke", "POST", "/api/oauth/revoke", RouteOAuth},
		{"oauth callback", "GET", "/api/oauth/callback", RouteOAuth},
		{"oauth bare", "GET", "/api/oauth", RouteOAuth},

		// Unknown
		{"get webhooks", "GET", "/api/webhooks", RouteUnknown},
		{"put graphql", "PUT", "/graphql", RouteUnknown},
		{"random path", "GET", "/api/v1/issues", RouteUnknown},
		{"empty path", "GET", "", RouteUnknown},
		{"root path", "GET", "/", RouteUnknown},
		{"delete graphql", "DELETE", "/graphql", RouteUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.Classify(tt.method, tt.path)
			if got != tt.expected {
				t.Errorf("Classify(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.expected)
			}
		})
	}
}

func TestClassifierInterface(t *testing.T) {
	c := &Classifier{}

	if c.Provider() != "linear" {
		t.Errorf("Provider() = %q, want %q", c.Provider(), "linear")
	}

	if c.UnknownClass() != RouteUnknown {
		t.Errorf("UnknownClass() = %q, want %q", c.UnknownClass(), RouteUnknown)
	}

	classes := c.RouteClasses()
	if len(classes) != 4 {
		t.Errorf("RouteClasses() returned %d classes, want 4", len(classes))
	}

	hosts := c.KnownHosts()
	if len(hosts) != 2 {
		t.Errorf("KnownHosts() returned %d hosts, want 2", len(hosts))
	}
	expected := map[string]bool{
		"api.linear.app": true,
		"linear.app":     true,
	}
	for _, h := range hosts {
		if !expected[h] {
			t.Errorf("unexpected host in KnownHosts: %q", h)
		}
	}
}
