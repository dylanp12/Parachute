package proxy

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dylanp12/parachute/internal/broker"
	"github.com/dylanp12/parachute/internal/config"
)

func testConfig(brokerMode string) *config.Config {
	return &config.Config{
		Egress: config.EgressConfig{
			Mode: "enforce",
		},
		Broker: config.BrokerConfig{
			Enabled:      true,
			Listen:       ":8081",
			Mode:         brokerMode,
			FailBehavior: "closed",
		},
	}
}

func testMatcher() *broker.IntegrationMatcher {
	return broker.NewMatcher([]broker.IntegrationDef{
		{Name: "github", Hosts: []string{"api.github.com", "uploads.github.com"}},
	})
}

func TestCheckManagedHost_EnforceMode(t *testing.T) {
	cfg := testConfig("enforce")
	fp := NewForwardProxy(cfg, testMatcher(), nil)

	integration, blocked := fp.checkManagedHost("api.github.com")
	if !blocked {
		t.Error("expected managed host to be blocked in enforce mode")
	}
	if integration != "github" {
		t.Errorf("integration = %q, want github", integration)
	}
}

func TestCheckManagedHost_RecordMode(t *testing.T) {
	cfg := testConfig("record")
	var events []string
	onEvent := func(actionType, target, decision, rulePath, enforcementMode string) {
		events = append(events, actionType+":"+decision)
	}
	fp := NewForwardProxy(cfg, testMatcher(), onEvent)

	integration, blocked := fp.checkManagedHost("api.github.com")
	if blocked {
		t.Error("expected managed host NOT to be blocked in record mode")
	}
	if integration != "github" {
		t.Errorf("integration = %q, want github", integration)
	}
	if len(events) != 1 || events[0] != "broker_egress_block:deny" {
		t.Errorf("events = %v, want [broker_egress_block:deny]", events)
	}
}

func TestCheckManagedHost_UnmanagedHost(t *testing.T) {
	cfg := testConfig("enforce")
	fp := NewForwardProxy(cfg, testMatcher(), nil)

	_, blocked := fp.checkManagedHost("api.openai.com")
	if blocked {
		t.Error("expected unmanaged host to NOT be blocked")
	}
}

func TestCheckManagedHost_NilMatcher(t *testing.T) {
	cfg := testConfig("enforce")
	fp := NewForwardProxy(cfg, nil, nil)

	_, blocked := fp.checkManagedHost("api.github.com")
	if blocked {
		t.Error("expected no blocking with nil matcher")
	}
}

func TestCheckManagedHost_OffMode(t *testing.T) {
	cfg := testConfig("off")
	fp := NewForwardProxy(cfg, testMatcher(), nil)

	_, blocked := fp.checkManagedHost("api.github.com")
	if blocked {
		t.Error("expected no blocking when broker mode is off")
	}
}

func TestManagedHostGuidance(t *testing.T) {
	cfg := testConfig("enforce")
	fp := NewForwardProxy(cfg, testMatcher(), nil)

	guidance := fp.managedHostGuidance("github")
	if !strings.Contains(guidance, "github") {
		t.Error("guidance should mention the integration name")
	}
	if !strings.Contains(guidance, ":8081") {
		t.Error("guidance should include the broker listen address")
	}
	if !strings.Contains(guidance, "/broker/github/") {
		t.Error("guidance should include the broker path")
	}
}

func TestHandleConnect_ManagedHostBlocked(t *testing.T) {
	cfg := testConfig("enforce")
	// Add github.com to egress allow list so the egress check doesn't interfere
	cfg.Egress.AllowDomains = []string{"api.github.com"}
	cfg.Egress.Compile()

	var events []string
	onEvent := func(actionType, target, decision, rulePath, enforcementMode string) {
		events = append(events, actionType+":"+decision)
	}
	fp := NewForwardProxy(cfg, testMatcher(), onEvent)

	// Use a pipe to simulate a network connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		fp.HandleConnect(serverConn, "api.github.com:443")
		close(done)
	}()

	// Read the response
	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}

	// Verify telemetry event was emitted
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConnect didn't return")
	}

	if len(events) == 0 {
		t.Error("expected broker_egress_block telemetry event")
	} else if events[0] != "broker_egress_block:deny" {
		t.Errorf("event = %q, want broker_egress_block:deny", events[0])
	}
}

func TestHandleConnect_RecordModeAllowsThrough(t *testing.T) {
	cfg := testConfig("record")
	cfg.Egress.AllowDomains = []string{"api.github.com"}
	cfg.Egress.Compile()

	var events []string
	onEvent := func(actionType, target, decision, rulePath, enforcementMode string) {
		events = append(events, actionType+":"+decision)
	}
	fp := NewForwardProxy(cfg, testMatcher(), onEvent)

	// In record mode, managed hosts should NOT be blocked (just logged).
	// Verify by checking that the 403 is NOT returned and we see
	// the broker_egress_block event logged.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		fp.HandleConnect(serverConn, "api.github.com:443")
		close(done)
	}()

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	// Should NOT get 403 in record mode -- gets 502 because no real upstream
	if resp.StatusCode == 403 {
		t.Error("record mode should not block managed host connections")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// HandleConnect might hang trying to dial -- that's OK for record mode,
		// the important check is that we didn't get a 403
	}

	brokerEvents := 0
	for _, e := range events {
		if e == "broker_egress_block:deny" {
			brokerEvents++
		}
	}
	if brokerEvents == 0 {
		t.Errorf("expected broker_egress_block event in record mode, got: %v", events)
	}
}

func TestHandleHTTPRequest_ManagedHostBlocked(t *testing.T) {
	cfg := testConfig("enforce")
	cfg.Egress.AllowDomains = []string{"api.github.com"}
	cfg.Egress.Compile()

	var events []string
	onEvent := func(actionType, target, decision, rulePath, enforcementMode string) {
		events = append(events, actionType+":"+decision)
	}

	ps := NewProxyServer(cfg, testMatcher(), onEvent)

	clientConn, serverConn := net.Pipe()

	// Write a valid HTTP request to the pipe
	go func() {
		clientConn.Write([]byte("GET http://api.github.com/repos/test/test HTTP/1.1\r\nHost: api.github.com\r\n\r\n"))
	}()

	// handleHTTPRequest reads from serverConn
	httpReq, err := http.ReadRequest(bufio.NewReader(serverConn))
	if err != nil {
		t.Fatalf("failed to read request: %v", err)
	}

	done := make(chan struct{})
	go func() {
		ps.handleHTTPRequest(serverConn, httpReq)
		serverConn.Close()
		close(done)
	}()

	// Read raw bytes from clientConn rather than using http.ReadResponse,
	// because http.Response.Write without ContentLength can leave the body
	// length ambiguous until the connection is closed.
	buf := make([]byte, 4096)
	var response string
	for {
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, readErr := clientConn.Read(buf)
		if n > 0 {
			response += string(buf[:n])
		}
		if readErr != nil {
			break
		}
	}
	clientConn.Close()

	if !strings.Contains(response, "403") {
		t.Errorf("response should contain 403, got:\n%s", response)
	}
	if !strings.Contains(response, "managed integration") {
		t.Errorf("response should contain guidance message, got:\n%s", response)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHTTPRequest didn't return")
	}

	brokerEvents := 0
	for _, e := range events {
		if e == "broker_egress_block:deny" {
			brokerEvents++
		}
	}
	if brokerEvents == 0 {
		t.Errorf("expected broker_egress_block event, got: %v", events)
	}
}
