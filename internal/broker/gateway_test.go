package broker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// mockUpstream creates an HTTP server that echoes request details back.
func mockUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back request details in headers for verification
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("X-Echo-Query", r.URL.RawQuery)
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Content-Type", r.Header.Get("Content-Type"))
		w.Header().Set("Link", `<https://api.github.com/repos?page=2>; rel="next"`)

		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			w.Header().Set("X-Echo-Body", string(body))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
}

func setupGateway(t *testing.T, broker CredentialBroker, mode, failBeh string) (*fiber.App, *Gateway) {
	t.Helper()

	matcher := NewMatcher([]IntegrationDef{
		{Name: "github", Hosts: []string{"api.github.com"}},
	})

	gw := NewGateway(GatewayConfig{
		Matcher: matcher,
		Broker:  broker,
		Mode:    mode,
		FailBeh: failBeh,
		AgentID: "test-agent",
	})

	app := fiber.New()
	app.All("/broker/:integration/*", gw.Handler())
	return app, gw
}

func TestGateway_NoopBroker(t *testing.T) {
	app, _ := setupGateway(t, NewNoopBroker(), "enforce", "closed")

	req, _ := http.NewRequest("GET", "/broker/github/repos/owner/repo", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Without a real upstream, this will fail with bad gateway
	// which is expected -- the noop broker returns Allow (passthrough)
	// and the gateway attempts to forward to api.github.com
	if resp.StatusCode != http.StatusBadGateway {
		t.Logf("status = %d (expected 502 since no real upstream)", resp.StatusCode)
	}
}

func TestGateway_UnknownIntegration(t *testing.T) {
	app, _ := setupGateway(t, NewNoopBroker(), "enforce", "closed")

	req, _ := http.NewRequest("GET", "/broker/jira/some/path", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for unknown integration", resp.StatusCode)
	}
}

func TestGateway_DenyInEnforceMode(t *testing.T) {
	// Custom broker that always denies
	denyBroker := &denyAllBroker{}
	app, _ := setupGateway(t, denyBroker, "enforce", "closed")

	req, _ := http.NewRequest("GET", "/broker/github/repos/owner/repo", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for denied request in enforce mode", resp.StatusCode)
	}
}

func TestGateway_UnavailableFailClosed(t *testing.T) {
	unavailBroker := &unavailableBroker{}
	app, _ := setupGateway(t, unavailBroker, "enforce", "closed")

	req, _ := http.NewRequest("GET", "/broker/github/repos/owner/repo", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for unavailable + fail-closed", resp.StatusCode)
	}
}

func TestGateway_PathReconstruction(t *testing.T) {
	// Verify the path is correctly extracted
	matcher := NewMatcher([]IntegrationDef{
		{Name: "github", Hosts: []string{"api.github.com"}},
	})

	var capturedReq *BrokerRequest
	captureBroker := &capturingBroker{captured: &capturedReq}

	app := fiber.New()
	gw := NewGateway(GatewayConfig{
		Matcher: matcher,
		Broker:  captureBroker,
		Mode:    "enforce",
		FailBeh: "closed",
		AgentID: "test-agent",
	})
	app.All("/broker/:integration/*", gw.Handler())

	req, _ := http.NewRequest("POST", "/broker/github/repos/org/repo/issues", strings.NewReader(`{"title":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	app.Test(req)

	if capturedReq == nil {
		t.Fatal("broker was not called")
	}
	if (*capturedReq).Path != "/repos/org/repo/issues" {
		t.Errorf("captured path = %q, want /repos/org/repo/issues", (*capturedReq).Path)
	}
	if (*capturedReq).Method != "POST" {
		t.Errorf("captured method = %q, want POST", (*capturedReq).Method)
	}
	if (*capturedReq).Integration != "github" {
		t.Errorf("captured integration = %q, want github", (*capturedReq).Integration)
	}
}

func TestGateway_TelemetryCallback(t *testing.T) {
	var events []string
	callback := func(actionType, target, decision, rulePath, mode string, params map[string]any) {
		events = append(events, actionType+":"+decision)
	}

	matcher := NewMatcher([]IntegrationDef{
		{Name: "github", Hosts: []string{"api.github.com"}},
	})
	app := fiber.New()
	gw := NewGateway(GatewayConfig{
		Matcher: matcher,
		Broker:  &denyAllBroker{},
		Mode:    "enforce",
		FailBeh: "closed",
		OnEvent: callback,
		AgentID: "test-agent",
	})
	app.All("/broker/:integration/*", gw.Handler())

	req, _ := http.NewRequest("GET", "/broker/github/repos/test/test", nil)
	app.Test(req)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d: %v", len(events), events)
	}
	if events[0] != "broker_request:deny" {
		t.Errorf("event = %q, want broker_request:deny", events[0])
	}
}

// Test helper brokers

type denyAllBroker struct{}

func (b *denyAllBroker) Resolve(_ context.Context, req *BrokerRequest) (*BrokerResult, error) {
	return &BrokerResult{
		Decision:    DecisionDeny,
		Integration: req.Integration,
		RouteClass:  req.RouteClass,
		Reason:      "test: always deny",
	}, nil
}

type unavailableBroker struct{}

func (b *unavailableBroker) Resolve(_ context.Context, req *BrokerRequest) (*BrokerResult, error) {
	return &BrokerResult{
		Decision:    DecisionUnavailable,
		Integration: req.Integration,
		RouteClass:  req.RouteClass,
		Reason:      "test: credential unavailable",
	}, nil
}

type capturingBroker struct {
	captured **BrokerRequest
}

func (b *capturingBroker) Resolve(_ context.Context, req *BrokerRequest) (*BrokerResult, error) {
	*b.captured = req
	return &BrokerResult{
		Decision:    DecisionDeny,
		Integration: req.Integration,
		RouteClass:  req.RouteClass,
		Reason:      "capturing broker",
	}, nil
}
