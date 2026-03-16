package sdr

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestVector is the structure stored in testdata/ for golden file testing.
type TestVector struct {
	Description   string `json:"description"`
	SDR           SDR    `json:"sdr"`
	CanonicalJSON string `json:"canonical_json"`
	RecordHash    string `json:"record_hash"`
	PublicKey     string `json:"public_key_hex"`
}

// TestGenerateTestVector generates a golden test vector file.
// Run with: go test -run TestGenerateTestVector -v ./pkg/sdr/
func TestGenerateTestVector(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	record := SDR{
		SDRVersion: SDRVersion,
		SDRID:      uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
		TenantID:   "acme-corp",
		AgentID:    "prod/billing/agent-1/default",
		OccurredAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Action: ActionInfo{
			Type:   "tool_call",
			Target: "rm -rf /tmp/cache",
			Params: map[string]any{"cwd": "/app"},
		},
		Policy: PolicyInfo{
			BundleHash:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Version:           "1.2.0",
			RulePath:          "parachute.risk.destructive",
			Decision:          "deny",
			RequiredApprovals: 0,
		},
		Approval: nil,
		Chain: ChainInfo{
			PrevHash: GenesisHash,
			ChainID:  "prod/billing/agent-1/default",
		},
		Runtime: RuntimeInfo{
			SidecarVersion: "0.5.0",
			Framework:      "claude-code",
		},
	}

	// Sign the record
	if err := Sign(&record, priv, "acme-corp/sidecar/1705312000"); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Compute canonical JSON for the test vector
	canonical, err := CanonicalJSON(&record)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}

	hash := sha256.Sum256(canonical)

	vector := TestVector{
		Description:   "Basic SDR with deny decision, no approval, genesis chain",
		SDR:           record,
		CanonicalJSON: string(canonical),
		RecordHash:    hex.EncodeToString(hash[:]),
		PublicKey:     hex.EncodeToString(pub),
	}

	data, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal test vector: %v", err)
	}

	if err := os.MkdirAll("testdata", 0755); err != nil {
		t.Fatalf("failed to create testdata dir: %v", err)
	}

	path := filepath.Join("testdata", "sdr_v1_basic.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test vector: %v", err)
	}

	t.Logf("Test vector written to %s (%d bytes)", path, len(data))
	t.Logf("Public key: %s", hex.EncodeToString(pub))
	t.Logf("Record hash: %s", hex.EncodeToString(hash[:]))
}

// TestTestVector_Roundtrip loads the golden test vector and verifies
// canonical encoding, hash, and signature all match.
func TestTestVector_Roundtrip(t *testing.T) {
	path := filepath.Join("testdata", "sdr_v1_basic.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("test vector not found at %s (run TestGenerateTestVector first): %v", path, err)
	}

	var vector TestVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("failed to parse test vector: %v", err)
	}

	record := vector.SDR

	// 1. Verify canonical JSON matches expected bytes
	canonical, err := CanonicalJSON(&record)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}

	if string(canonical) != vector.CanonicalJSON {
		t.Errorf("canonical JSON mismatch:\n  expected: %s\n  got:      %s",
			vector.CanonicalJSON, string(canonical))
	}

	// 2. Verify record hash matches
	hash := sha256.Sum256(canonical)
	actualHash := hex.EncodeToString(hash[:])
	if actualHash != vector.RecordHash {
		t.Errorf("record hash mismatch: expected %s, got %s", vector.RecordHash, actualHash)
	}

	if record.Chain.RecordHash != vector.RecordHash {
		t.Errorf("SDR record_hash field mismatch: expected %s, got %s",
			vector.RecordHash, record.Chain.RecordHash)
	}

	// 3. Verify signature with embedded public key
	pubKeyBytes, err := hex.DecodeString(vector.PublicKey)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	if err := Verify(&record, pubKey); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// 4. Verify tampering detection
	tampered := record
	tampered.Action.Target = "tampered-command"
	if err := Verify(&tampered, pubKey); err == nil {
		t.Error("verification should fail for tampered record")
	}

	t.Log("Test vector round-trip verified successfully")
}

// TestTestVector_ChainOfThree verifies a 3-record chain can be built,
// serialized, and validated.
func TestTestVector_ChainOfThree(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	records := make([]SDR, 3)
	for i := range records {
		records[i] = SDR{
			SDRVersion: SDRVersion,
			SDRID:      uuid.New(),
			TenantID:   "acme-corp",
			AgentID:    "prod/billing/agent-1/default",
			OccurredAt: time.Date(2025, 1, 15, 10, 30, i, 0, time.UTC),
			Action: ActionInfo{
				Type:   "tool_call",
				Target: "command-" + string(rune('a'+i)),
			},
			Policy: PolicyInfo{
				BundleHash: "abc123",
				Version:    "1.0.0",
				RulePath:   "parachute.default",
				Decision:   "allow",
			},
			Approval: nil,
			Chain: ChainInfo{
				ChainID: "prod/billing/agent-1/default",
			},
			Runtime: RuntimeInfo{
				SidecarVersion: "0.5.0",
			},
		}

		if i == 0 {
			records[i].Chain.PrevHash = GenesisHash
		} else {
			records[i].Chain.PrevHash = records[i-1].Chain.RecordHash
		}

		if err := Sign(&records[i], priv, "test-key"); err != nil {
			t.Fatalf("Sign record %d failed: %v", i, err)
		}
	}

	// Validate chain
	if err := ValidateChain(records); err != nil {
		t.Fatalf("ValidateChain failed: %v", err)
	}

	// Verify each signature
	for i, r := range records {
		if err := Verify(&r, pub); err != nil {
			t.Errorf("Verify record %d failed: %v", i, err)
		}
	}

	// Verify continuity from stored head
	latestHash := records[1].Chain.RecordHash
	if err := ValidateChainContinuity(records[2:], latestHash); err != nil {
		t.Errorf("ValidateChainContinuity failed: %v", err)
	}

	t.Log("3-record chain verified successfully")
}
