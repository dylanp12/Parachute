package exporters

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/parachute-security/parachute/pkg/sdr"
)

func testSDR(actionType, target string) sdr.SDR {
	return sdr.SDR{
		SDRVersion: sdr.SDRVersion,
		SDRID:      uuid.New(),
		TenantID:   "test",
		AgentID:    "test-agent",
		OccurredAt: time.Now().UTC(),
		Action:     sdr.ActionInfo{Type: actionType, Target: target},
		Policy:     sdr.PolicyInfo{Decision: "allow", RulePath: "test/rule"},
		Chain:      sdr.ChainInfo{PrevHash: "genesis", RecordHash: "abc", ChainID: "test-agent"},
		Signing:    sdr.SigningInfo{KeyID: "unsigned", Algorithm: "none", SigningTime: time.Now().UTC()},
		Enforcement: sdr.EnforcementInfo{Mode: "enforce"},
	}
}

func TestJSONLExporterWritesLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	exp, err := NewJSONLExporter(path)
	if err != nil {
		t.Fatalf("NewJSONLExporter: %v", err)
	}

	records := []sdr.SDR{
		testSDR("egress", "a.com"),
		testSDR("mcp_tool_call", "Bash"),
	}

	if err := exp.Export(context.Background(), records); err != nil {
		t.Fatalf("Export: %v", err)
	}
	exp.Close()

	// Read back
	f, _ := os.Open(path)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var count int
	for scanner.Scan() {
		var record sdr.SDR
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("line %d: %v", count, err)
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 lines, got %d", count)
	}
}

func TestJSONLExporterAppendsToExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	exp1, _ := NewJSONLExporter(path)
	exp1.Export(context.Background(), []sdr.SDR{testSDR("egress", "a.com")})
	exp1.Close()

	exp2, _ := NewJSONLExporter(path)
	exp2.Export(context.Background(), []sdr.SDR{testSDR("egress", "b.com")})
	exp2.Close()

	f, _ := os.Open(path)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var count int
	for scanner.Scan() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 lines after append, got %d", count)
	}
}
