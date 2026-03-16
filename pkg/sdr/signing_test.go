package sdr

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSign_ProducesVerifiableSignature(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	record := makeTestSDR()

	if err := Sign(&record, priv, "test-key-1"); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify the signature
	if err := Verify(&record, pub); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Check signing metadata
	if record.Signing.KeyID != "test-key-1" {
		t.Errorf("expected key_id 'test-key-1', got %q", record.Signing.KeyID)
	}
	if record.Signing.Algorithm != "Ed25519" {
		t.Errorf("expected alg 'Ed25519', got %q", record.Signing.Algorithm)
	}
	if record.Signing.Signature == "" {
		t.Error("signature is empty")
	}
	if record.Chain.RecordHash == "" {
		t.Error("record_hash is empty")
	}
}

func TestVerify_RejectsModifiedPayload(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	record := makeTestSDR()

	if err := Sign(&record, priv, "test-key-1"); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	tests := []struct {
		name   string
		modify func(r *SDR)
	}{
		{
			name:   "modified agent_id",
			modify: func(r *SDR) { r.AgentID = "attacker/evil/agent" },
		},
		{
			name:   "modified action target",
			modify: func(r *SDR) { r.Action.Target = "rm -rf /" },
		},
		{
			name:   "modified decision",
			modify: func(r *SDR) { r.Policy.Decision = "allow" },
		},
		{
			name:   "modified occurred_at",
			modify: func(r *SDR) { r.OccurredAt = time.Now() },
		},
		{
			name:   "modified chain prev_hash",
			modify: func(r *SDR) { r.Chain.PrevHash = "tampered" },
		},
		{
			name:   "modified tenant_id",
			modify: func(r *SDR) { r.TenantID = "other-tenant" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modified := record // copy
			tt.modify(&modified)

			if err := Verify(&modified, pub); err == nil {
				t.Error("Verify should have failed for modified record")
			}
		})
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	_, priv := generateTestKeypair(t)
	wrongPub, _ := generateTestKeypair(t)
	record := makeTestSDR()

	if err := Sign(&record, priv, "test-key-1"); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if err := Verify(&record, wrongPub); err == nil {
		t.Error("Verify should have failed with wrong public key")
	}
}

func TestSign_RecordHashMatchesCanonical(t *testing.T) {
	_, priv := generateTestKeypair(t)
	record := makeTestSDR()

	if err := Sign(&record, priv, "test-key-1"); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Independently compute the hash
	expectedHash, err := ComputeRecordHash(&record)
	if err != nil {
		t.Fatalf("ComputeRecordHash failed: %v", err)
	}

	if record.Chain.RecordHash != expectedHash {
		t.Errorf("record hash mismatch: Sign produced %q, ComputeRecordHash produced %q",
			record.Chain.RecordHash, expectedHash)
	}
}

func TestSign_DifferentRecordsProduceDifferentHashes(t *testing.T) {
	_, priv := generateTestKeypair(t)

	record1 := makeTestSDR()
	record2 := makeTestSDR()
	record2.SDRID = uuid.New()
	record2.Action.Target = "different-command"

	if err := Sign(&record1, priv, "test-key-1"); err != nil {
		t.Fatalf("Sign record1 failed: %v", err)
	}
	if err := Sign(&record2, priv, "test-key-1"); err != nil {
		t.Fatalf("Sign record2 failed: %v", err)
	}

	if record1.Chain.RecordHash == record2.Chain.RecordHash {
		t.Error("different records should produce different hashes")
	}
	if record1.Signing.Signature == record2.Signing.Signature {
		t.Error("different records should produce different signatures")
	}
}

func TestComputeRecordHash_Deterministic(t *testing.T) {
	record := makeTestSDR()

	hash1, err := ComputeRecordHash(&record)
	if err != nil {
		t.Fatalf("ComputeRecordHash failed: %v", err)
	}

	hash2, err := ComputeRecordHash(&record)
	if err != nil {
		t.Fatalf("ComputeRecordHash failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hash not deterministic: %q != %q", hash1, hash2)
	}
}
