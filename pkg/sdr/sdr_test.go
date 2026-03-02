package sdr

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func makeTestSDR() SDR {
	return SDR{
		SDRVersion: SDRVersion,
		SDRID:      uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
		TenantID:   "acme",
		AgentID:    "prod/billing/agent-1/default",
		OccurredAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Action: ActionInfo{
			Type:   "tool_call",
			Target: "rm -rf /tmp/cache",
			Params: map[string]any{"cwd": "/app"},
		},
		Policy: PolicyInfo{
			BundleHash:        "abc123def456",
			Version:           "1.2.0",
			RulePath:          "parachute.risk.destructive",
			Decision:          "deny",
			RequiredApprovals: 0,
		},
		Approval: nil,
		Chain: ChainInfo{
			PrevHash:   "genesis",
			RecordHash: "", // will be computed
			ChainID:    "prod/billing/agent-1/default",
		},
		Signing: SigningInfo{
			KeyID:       "acme/sidecar/1705312000",
			Algorithm:   "Ed25519",
			Signature:   "fakesignature",
			SigningTime: time.Date(2025, 1, 15, 10, 30, 0, 500000000, time.UTC),
		},
		Runtime: RuntimeInfo{
			SidecarVersion: "0.5.0",
			Framework:      "claude-code",
		},
		Telemetry: TelemetryContext{
			SessionID:    "sess-001",
			SpanID:       "span-abc",
			ParentSpanID: "span-parent",
		},
		Enforcement: EnforcementInfo{
			Mode: "enforce",
		},
	}
}

func generateTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	return pub, priv
}

// TestSDRRoundTrip creates an SDR with all fields, tests that canonical JSON
// is deterministic, and tests sign+verify.
func TestSDRRoundTrip(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	record := makeTestSDR()

	// Set approval to exercise all fields
	record.Approval = &ApprovalInfo{
		ID:             "appr-001",
		ApproverID:     "alice@acme.com",
		ApproverType:   "human",
		ApprovalSource: "slack",
		Justification:  "Emergency maintenance approved",
		DecisionTime:   time.Date(2025, 1, 15, 10, 32, 0, 0, time.UTC),
	}

	// Sign the record
	if err := Sign(&record, priv, "test-key-1"); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify record hash is populated
	if record.Chain.RecordHash == "" {
		t.Fatal("record_hash should be populated after signing")
	}

	// Verify signing metadata
	if record.Signing.KeyID != "test-key-1" {
		t.Errorf("expected key_id 'test-key-1', got %q", record.Signing.KeyID)
	}
	if record.Signing.Algorithm != "Ed25519" {
		t.Errorf("expected alg 'Ed25519', got %q", record.Signing.Algorithm)
	}
	if record.Signing.Signature == "" {
		t.Error("signature is empty")
	}

	// Verify the signature
	if err := Verify(&record, pub); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Test canonical JSON is deterministic across multiple calls
	canonical1, err := CanonicalJSON(&record)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	canonical2, err := CanonicalJSON(&record)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	if string(canonical1) != string(canonical2) {
		t.Error("canonical JSON is not deterministic")
	}

	// Verify tampering detection
	tampered := record
	tampered.Action.Target = "tampered-command"
	if err := Verify(&tampered, pub); err == nil {
		t.Error("Verify should fail for tampered record")
	}

	// Verify wrong key detection
	wrongPub, _ := generateTestKeypair(t)
	if err := Verify(&record, wrongPub); err == nil {
		t.Error("Verify should fail with wrong public key")
	}

	// Test JSON round-trip: marshal then unmarshal
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var decoded SDR
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if decoded.SDRID != record.SDRID {
		t.Error("SDRID mismatch after JSON round-trip")
	}
	if decoded.Telemetry.SessionID != "sess-001" {
		t.Errorf("Telemetry.SessionID mismatch: got %q", decoded.Telemetry.SessionID)
	}
	if decoded.Enforcement.Mode != "enforce" {
		t.Errorf("Enforcement.Mode mismatch: got %q", decoded.Enforcement.Mode)
	}
	if decoded.Approval == nil {
		t.Fatal("Approval should not be nil after round-trip")
	}
	if decoded.Approval.ApproverID != "alice@acme.com" {
		t.Errorf("ApproverID mismatch: got %q", decoded.Approval.ApproverID)
	}
	if decoded.Approval.ApproverType != "human" {
		t.Errorf("ApproverType mismatch: got %q", decoded.Approval.ApproverType)
	}
	if decoded.Approval.ApprovalSource != "slack" {
		t.Errorf("ApprovalSource mismatch: got %q", decoded.Approval.ApprovalSource)
	}

	// Verify the decoded record still passes verification
	if err := Verify(&decoded, pub); err != nil {
		t.Fatalf("Verify failed after JSON round-trip: %v", err)
	}
}

// TestCanonicalJSONExcludesSigningAndTelemetry verifies that canonical JSON
// excludes the signing, telemetry, and enforcement fields.
func TestCanonicalJSONExcludesSigningAndTelemetry(t *testing.T) {
	record := makeTestSDR()

	canonical, err := CanonicalJSON(&record)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}

	canonicalStr := string(canonical)

	// Must NOT contain excluded fields
	excludedFields := []string{"signing", "telemetry", "enforcement"}
	for _, field := range excludedFields {
		if strings.Contains(canonicalStr, `"`+field+`"`) {
			t.Errorf("canonical JSON should not contain %q field: %s", field, canonicalStr)
		}
	}

	// Must NOT contain record_hash within chain
	if strings.Contains(canonicalStr, `"record_hash"`) {
		t.Errorf("canonical JSON should not contain record_hash: %s", canonicalStr)
	}

	// Must contain all other core fields
	requiredFields := []string{"sdr_version", "sdr_id", "tenant_id", "agent_id",
		"action", "policy", "chain", "runtime", "occurred_at"}
	for _, field := range requiredFields {
		if !strings.Contains(canonicalStr, `"`+field+`"`) {
			t.Errorf("canonical JSON missing required field %q: %s", field, canonicalStr)
		}
	}

	// Verify different signing/telemetry/enforcement values do NOT affect canonical output
	record2 := makeTestSDR()
	record2.Signing.Signature = "completely-different-signature"
	record2.Signing.KeyID = "different-key"
	record2.Telemetry.SessionID = "different-session"
	record2.Telemetry.SpanID = "different-span"
	record2.Enforcement.Mode = "record"

	canonical2, err := CanonicalJSON(&record2)
	if err != nil {
		t.Fatalf("CanonicalJSON failed for record2: %v", err)
	}

	if string(canonical) != string(canonical2) {
		t.Errorf("different signing/telemetry/enforcement should produce identical canonical JSON:\n  1: %s\n  2: %s",
			canonical, canonical2)
	}

	// Verify null approval is explicit
	record3 := makeTestSDR()
	record3.Approval = nil
	canonical3, err := CanonicalJSON(&record3)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	if !strings.Contains(string(canonical3), `"approval":null`) {
		t.Errorf("null approval should be explicit in canonical JSON: %s", canonical3)
	}

	// Verify compact format (no newlines or indentation)
	if strings.Contains(canonicalStr, "\n") {
		t.Error("canonical JSON contains newlines")
	}
	if strings.Contains(canonicalStr, "  ") {
		t.Error("canonical JSON contains indentation")
	}

	// Verify keys are sorted
	keys := extractKeyOrder(canonical)
	for i := 1; i < len(keys); i++ {
		if keys[i-1] >= keys[i] {
			t.Errorf("keys not sorted: %q >= %q (at position %d)", keys[i-1], keys[i], i)
		}
	}
}

// extractKeyOrder returns the top-level keys in the order they appear in JSON.
func extractKeyOrder(data []byte) []string {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	// Read the opening brace
	_, _ = dec.Token()

	var keys []string
	for dec.More() {
		tok, _ := dec.Token()
		if key, ok := tok.(string); ok {
			keys = append(keys, key)
			// Skip the value
			var v json.RawMessage
			_ = dec.Decode(&v)
		}
	}
	return keys
}
