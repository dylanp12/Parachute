package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProBroker_Resolve_AllowWithCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/broker/credential" {
			t.Errorf("expected /v1/broker/credential, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("expected Bearer test-api-key, got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Verify body
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["integration"] != "github" {
			t.Errorf("expected integration=github, got %s", body["integration"])
		}
		if body["agent_id"] != "agent-1" {
			t.Errorf("expected agent_id=agent-1, got %s", body["agent_id"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"decision": "allow",
			"credential": map[string]string{
				"type":  "bearer",
				"value": "Bearer ghs_test123",
			},
			"ttl": 300,
		})
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-api-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	result, err := pb.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
		AgentID:     "agent-1",
		Method:      "GET",
		Path:        "/repos/org/repo/issues",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionCredentialInjected {
		t.Errorf("expected credential_injected, got %s", result.Decision)
	}
	if result.Credential == nil {
		t.Fatal("expected credential, got nil")
	}
	if result.Credential.HeaderName != "Authorization" {
		t.Errorf("expected Authorization header, got %s", result.Credential.HeaderName)
	}
	if result.Credential.HeaderValue != "Bearer ghs_test123" {
		t.Errorf("expected Bearer ghs_test123, got %s", result.Credential.HeaderValue)
	}
}

func TestProBroker_Resolve_Deny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"decision": "deny",
			"reason":   "policy denies admin for agent-1",
		})
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	result, err := pb.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "admin",
		AgentID:     "agent-1",
		Method:      "DELETE",
		Path:        "/repos/org/repo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision)
	}
	if result.Reason != "policy denies admin for agent-1" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestProBroker_Resolve_AllowWithoutCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"decision": "allow",
			"ttl":      60,
		})
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	result, err := pb.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
		AgentID:     "agent-1",
		Method:      "GET",
		Path:        "/repos/org/repo/issues",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", result.Decision)
	}
	if result.Credential != nil {
		t.Errorf("expected no credential, got %+v", result.Credential)
	}
}

func TestProBroker_Resolve_FailClosed(t *testing.T) {
	// Server that immediately closes connection
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server doesn't support hijacking")
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	result, err := pb.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
		AgentID:     "agent-1",
		Method:      "GET",
		Path:        "/repos/org/repo/issues",
	})
	if err != nil {
		t.Fatalf("should not return error on unreachable (fail-closed), got: %v", err)
	}
	if result.Decision != DecisionUnavailable {
		t.Errorf("expected credential_unavailable, got %s", result.Decision)
	}
	if result.Reason == "" {
		t.Error("expected reason explaining why Pro is unreachable")
	}
}

func TestProBroker_Resolve_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	result, err := pb.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
		AgentID:     "agent-1",
		Method:      "GET",
		Path:        "/repos/org/repo/issues",
	})
	if err != nil {
		t.Fatalf("should not return error on non-OK status, got: %v", err)
	}
	if result.Decision != DecisionUnavailable {
		t.Errorf("expected credential_unavailable, got %s", result.Decision)
	}
	if result.Reason != "Pro returned status 500" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestProBroker_Resolve_CachesResults(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"decision": "allow",
			"credential": map[string]string{
				"type":  "bearer",
				"value": "Bearer cached-token",
			},
			"ttl": 300,
		})
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	req := &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
		AgentID:     "agent-1",
		Method:      "GET",
		Path:        "/repos/org/repo/issues",
	}

	// First call hits the server
	result1, err := pb.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result1.Decision != DecisionCredentialInjected {
		t.Errorf("expected credential_injected, got %s", result1.Decision)
	}

	// Second call should be cached
	result2, err := pb.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Decision != DecisionCredentialInjected {
		t.Errorf("expected credential_injected, got %s", result2.Decision)
	}

	if callCount.Load() != 1 {
		t.Errorf("expected 1 server call (cached), got %d", callCount.Load())
	}
}

func TestProBroker_Resolve_CacheExpiry(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"decision": "allow",
			"credential": map[string]string{
				"type":  "bearer",
				"value": "Bearer token",
			},
			"ttl": 1, // 1 second TTL
		})
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	req := &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
		AgentID:     "agent-1",
		Method:      "GET",
		Path:        "/repos/org/repo/issues",
	}

	// First call
	pb.Resolve(context.Background(), req)
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", callCount.Load())
	}

	// Wait for cache to expire
	time.Sleep(1100 * time.Millisecond)

	// Should hit server again
	pb.Resolve(context.Background(), req)
	if callCount.Load() != 2 {
		t.Errorf("expected 2 calls after cache expiry, got %d", callCount.Load())
	}
}

func TestProBroker_Resolve_DefaultTTL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"decision": "allow",
			"ttl":      0, // Zero TTL → default 5 minutes
		})
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	req := &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
		AgentID:     "agent-1",
		Method:      "GET",
		Path:        "/repos/org/repo/issues",
	}

	pb.Resolve(context.Background(), req)

	// Verify cache entry exists with reasonable expiry (should be ~5 min from now)
	pb.mu.RLock()
	entry, ok := pb.cache["github:issues_read"]
	pb.mu.RUnlock()

	if !ok {
		t.Fatal("expected cache entry")
	}
	// Should expire roughly 5 minutes from now (give 10s tolerance)
	expectedExpiry := time.Now().Add(5 * time.Minute)
	if entry.expiresAt.Before(expectedExpiry.Add(-10*time.Second)) || entry.expiresAt.After(expectedExpiry.Add(10*time.Second)) {
		t.Errorf("expected expiry ~5min from now, got %v (expected ~%v)", entry.expiresAt, expectedExpiry)
	}
}

func TestProBroker_Resolve_UnknownDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"decision": "something_unexpected",
		})
	}))
	defer srv.Close()

	pb := &ProBroker{
		proURL: srv.URL,
		apiKey: "test-key",
		client: srv.Client(),
		cache:  make(map[string]*cachedResponse),
	}

	result, err := pb.Resolve(context.Background(), &BrokerRequest{
		Integration: "github",
		RouteClass:  "issues_read",
		AgentID:     "agent-1",
		Method:      "GET",
		Path:        "/repos/org/repo/issues",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Unknown decisions map to unavailable (fail-closed)
	if result.Decision != DecisionUnavailable {
		t.Errorf("expected credential_unavailable for unknown decision, got %s", result.Decision)
	}
}
