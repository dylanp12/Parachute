package sdr

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
)

// buildSignedChain creates a valid chain of N signed SDRs.
func buildSignedChain(t *testing.T, n int) ([]SDR, ed25519.PublicKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	records := make([]SDR, n)
	for i := range records {
		records[i] = makeTestSDR()
		records[i].SDRID = uuid.New()
		records[i].Chain.ChainID = "test-chain"

		if i == 0 {
			records[i].Chain.PrevHash = GenesisHash
		} else {
			records[i].Chain.PrevHash = records[i-1].Chain.RecordHash
		}

		if err := Sign(&records[i], priv, "test-key"); err != nil {
			t.Fatalf("Sign record %d failed: %v", i, err)
		}
	}

	return records, pub
}

func TestValidateChain_ValidChain(t *testing.T) {
	records, _ := buildSignedChain(t, 5)

	if err := ValidateChain(records); err != nil {
		t.Errorf("ValidateChain failed for valid chain: %v", err)
	}
}

func TestValidateChain_EmptyChain(t *testing.T) {
	if err := ValidateChain(nil); err != nil {
		t.Errorf("ValidateChain failed for empty chain: %v", err)
	}
}

func TestValidateChain_SingleRecord(t *testing.T) {
	records, _ := buildSignedChain(t, 1)

	if err := ValidateChain(records); err != nil {
		t.Errorf("ValidateChain failed for single record: %v", err)
	}
}

func TestValidateChain_DetectsMissingGenesis(t *testing.T) {
	records, _ := buildSignedChain(t, 3)

	// Corrupt the first record's prev_hash
	records[0].Chain.PrevHash = "not-genesis"

	err := ValidateChain(records)
	if err == nil {
		t.Fatal("ValidateChain should detect missing genesis")
	}

	gapErr, ok := err.(*ChainGapError)
	if !ok {
		t.Fatalf("expected ChainGapError, got %T: %v", err, err)
	}
	if gapErr.Position != 0 {
		t.Errorf("expected gap at position 0, got %d", gapErr.Position)
	}
	if gapErr.Expected != GenesisHash {
		t.Errorf("expected %q, got %q", GenesisHash, gapErr.Expected)
	}
}

func TestValidateChain_DetectsGap(t *testing.T) {
	records, _ := buildSignedChain(t, 5)

	// Break the chain at position 3
	records[3].Chain.PrevHash = "tampered-hash"

	err := ValidateChain(records)
	if err == nil {
		t.Fatal("ValidateChain should detect gap")
	}

	gapErr, ok := err.(*ChainGapError)
	if !ok {
		t.Fatalf("expected ChainGapError, got %T: %v", err, err)
	}
	if gapErr.Position != 3 {
		t.Errorf("expected gap at position 3, got %d", gapErr.Position)
	}
}

func TestValidateChainContinuity_ValidContinuation(t *testing.T) {
	records, _ := buildSignedChain(t, 5)

	// First 3 are "already stored", last 2 are new batch
	latestHash := records[2].Chain.RecordHash
	newRecords := records[3:]

	if err := ValidateChainContinuity(newRecords, latestHash); err != nil {
		t.Errorf("ValidateChainContinuity failed: %v", err)
	}
}

func TestValidateChainContinuity_DetectsDisconnect(t *testing.T) {
	records, _ := buildSignedChain(t, 5)

	// Use wrong latest hash
	newRecords := records[3:]

	err := ValidateChainContinuity(newRecords, "wrong-hash")
	if err == nil {
		t.Fatal("ValidateChainContinuity should detect disconnect")
	}
}

func TestValidateChainContinuity_EmptyLatestHashExpectsGenesis(t *testing.T) {
	records, _ := buildSignedChain(t, 3)

	// Empty latest hash means new chain, first record should be genesis
	if err := ValidateChainContinuity(records, ""); err != nil {
		t.Errorf("ValidateChainContinuity failed for new chain: %v", err)
	}
}

func TestValidateChainContinuity_EmptyBatch(t *testing.T) {
	if err := ValidateChainContinuity(nil, "some-hash"); err != nil {
		t.Errorf("ValidateChainContinuity failed for empty batch: %v", err)
	}
}

func TestChainGapError_Message(t *testing.T) {
	err := &ChainGapError{
		ChainID:  "test-chain",
		Position: 3,
		SDRID:    "abc-123",
		Expected: "expected-hash",
		Got:      "got-hash",
	}

	msg := err.Error()
	if msg == "" {
		t.Error("error message is empty")
	}

	// Verify it contains key info
	for _, expected := range []string{"test-chain", "position 3", "abc-123", "expected-hash", "got-hash"} {
		if !containsStr(msg, expected) {
			t.Errorf("error message missing %q: %s", expected, msg)
		}
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
