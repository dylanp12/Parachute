package exporters

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/parachute-security/parachute/pkg/sdr"
)

func TestHeartbeatEmitter(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hb sdr.HeartbeatPayload
		json.NewDecoder(r.Body).Decode(&hb)
		if hb.AgentID != "test-agent" {
			t.Errorf("agent_id: %s", hb.AgentID)
		}
		received.Add(1)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	emitter := NewHeartbeatEmitter(HeartbeatConfig{
		ProURL:   server.URL,
		AgentID:  "test-agent",
		TenantID: "test-tenant",
		Interval: 100 * time.Millisecond,
		Version:  "dev",
	})

	ctx, cancel := context.WithCancel(context.Background())
	emitter.Start(ctx)
	time.Sleep(350 * time.Millisecond)
	cancel()
	emitter.Close()

	if received.Load() < 2 {
		t.Errorf("expected at least 2 heartbeats, got %d", received.Load())
	}
}
