package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dylanp12/parachute/pkg/sdr"
)

// mockExporter collects exported SDRs for verification
type mockExporter struct {
	mu      sync.Mutex
	records []sdr.SDR
}

func (m *mockExporter) Export(ctx context.Context, records []sdr.SDR) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, records...)
	return nil
}

func (m *mockExporter) Close() error { return nil }

func (m *mockExporter) Records() []sdr.SDR {
	m.mu.Lock()
	defer m.mu.Unlock()
	dst := make([]sdr.SDR, len(m.records))
	copy(dst, m.records)
	return dst
}

func TestCollectorRecordProducesSDR(t *testing.T) {
	mock := &mockExporter{}
	cs := &ChainState{ChainID: "test-agent", PrevHash: "genesis"}

	c := NewCollector(CollectorConfig{
		AgentID:  "test-agent",
		TenantID: "test-tenant",
	}, cs, []Exporter{mock})

	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)

	c.Record(TelemetryEvent{
		ActionType:      "egress",
		ActionTarget:    "api.example.com",
		Decision:        "allow",
		RulePath:        "egress/domain/allow:example",
		EnforcementMode: "enforce",
	})

	// Give the export loop time to flush
	time.Sleep(200 * time.Millisecond)
	cancel()
	c.Close()

	records := mock.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	r := records[0]
	if r.AgentID != "test-agent" {
		t.Errorf("agent_id: %s", r.AgentID)
	}
	if r.Action.Type != "egress" {
		t.Errorf("action.type: %s", r.Action.Type)
	}
	if r.Policy.Decision != "allow" {
		t.Errorf("policy.decision: %s", r.Policy.Decision)
	}
	if r.Enforcement.Mode != "enforce" {
		t.Errorf("enforcement.mode: %s", r.Enforcement.Mode)
	}
	if r.Chain.PrevHash != "genesis" {
		t.Errorf("chain.prev_hash: %s", r.Chain.PrevHash)
	}
	if r.Chain.RecordHash == "" {
		t.Error("chain.record_hash should be set")
	}
	if r.Telemetry.SessionID == "" {
		t.Error("session_id should be set")
	}
}

func TestCollectorChainAdvances(t *testing.T) {
	mock := &mockExporter{}
	cs := &ChainState{ChainID: "test-agent", PrevHash: "genesis"}

	c := NewCollector(CollectorConfig{
		AgentID:  "test-agent",
		TenantID: "test-tenant",
	}, cs, []Exporter{mock})

	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)

	c.Record(TelemetryEvent{ActionType: "egress", ActionTarget: "a.com", Decision: "allow", RulePath: "r1", EnforcementMode: "enforce"})
	c.Record(TelemetryEvent{ActionType: "egress", ActionTarget: "b.com", Decision: "deny", RulePath: "r2", EnforcementMode: "enforce"})

	time.Sleep(200 * time.Millisecond)
	cancel()
	c.Close()

	records := mock.Records()
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if records[0].Chain.PrevHash != "genesis" {
		t.Errorf("first record prev_hash: %s", records[0].Chain.PrevHash)
	}
	if records[1].Chain.PrevHash != records[0].Chain.RecordHash {
		t.Error("second record should chain from first")
	}
}

func TestCollectorDropsWhenQueueFull(t *testing.T) {
	mock := &mockExporter{}
	cs := &ChainState{ChainID: "test-agent", PrevHash: "genesis"}

	c := NewCollector(CollectorConfig{
		AgentID:   "test-agent",
		TenantID:  "test-tenant",
		QueueSize: 1,
	}, cs, []Exporter{mock})

	// Don't start the export loop — queue will fill up
	for i := 0; i < 10; i++ {
		c.Record(TelemetryEvent{ActionType: "egress", ActionTarget: "x.com", Decision: "allow", RulePath: "r", EnforcementMode: "enforce"})
	}

	metrics := c.Metrics()
	if metrics.EventsDropped == 0 {
		t.Error("expected some events to be dropped")
	}
}
