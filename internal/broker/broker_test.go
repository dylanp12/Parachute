package broker

import (
	"context"
	"testing"
)

func TestNoopBroker(t *testing.T) {
	b := NewNoopBroker()
	result, err := b.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want %q", result.Decision, DecisionAllow)
	}
	if result.Credential != nil {
		t.Error("noop broker should not return a credential")
	}
}

func TestDevStaticBroker_Success(t *testing.T) {
	t.Setenv("TEST_GITHUB_TOKEN", "ghp_test123")

	b := NewDevStaticBroker(map[string]DevStaticConfig{
		"github": {TokenEnv: "TEST_GITHUB_TOKEN"},
	})

	result, err := b.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionCredentialInjected {
		t.Errorf("decision = %q, want %q", result.Decision, DecisionCredentialInjected)
	}
	if result.Credential == nil {
		t.Fatal("expected credential, got nil")
	}
	if result.Credential.HeaderName != "Authorization" {
		t.Errorf("header name = %q, want Authorization", result.Credential.HeaderName)
	}
	if result.Credential.HeaderValue != "Bearer ghp_test123" {
		t.Errorf("header value = %q, want %q", result.Credential.HeaderValue, "Bearer ghp_test123")
	}
}

func TestDevStaticBroker_EmptyEnvVar(t *testing.T) {
	t.Setenv("TEST_EMPTY_TOKEN", "")

	b := NewDevStaticBroker(map[string]DevStaticConfig{
		"github": {TokenEnv: "TEST_EMPTY_TOKEN"},
	})

	result, err := b.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionUnavailable {
		t.Errorf("decision = %q, want %q", result.Decision, DecisionUnavailable)
	}
}

func TestDevStaticBroker_UnknownIntegration(t *testing.T) {
	b := NewDevStaticBroker(map[string]DevStaticConfig{
		"github": {TokenEnv: "GITHUB_TOKEN"},
	})

	result, err := b.Resolve(context.Background(), &BrokerRequest{
		Integration: "jira",
		RouteClass:  "issues_read",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionUnavailable {
		t.Errorf("decision = %q, want %q", result.Decision, DecisionUnavailable)
	}
}

func TestDevStaticBroker_CustomHeaderAndPrefix(t *testing.T) {
	t.Setenv("TEST_CUSTOM_TOKEN", "my-token")

	b := NewDevStaticBroker(map[string]DevStaticConfig{
		"custom": {
			TokenEnv:   "TEST_CUSTOM_TOKEN",
			HeaderName: "X-API-Key",
			NoPrefix:   true,
		},
	})

	result, err := b.Resolve(context.Background(), &BrokerRequest{
		Integration: "custom",
		RouteClass:  "api",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Credential.HeaderName != "X-API-Key" {
		t.Errorf("header name = %q, want X-API-Key", result.Credential.HeaderName)
	}
	if result.Credential.HeaderValue != "my-token" {
		t.Errorf("header value = %q, want my-token", result.Credential.HeaderValue)
	}
}
