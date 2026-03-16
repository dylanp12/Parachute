package telemetry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChainStateLoadMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.json")
	cs, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("LoadChainState on missing file: %v", err)
	}
	if cs.PrevHash != "genesis" {
		t.Errorf("expected genesis, got %s", cs.PrevHash)
	}
	if cs.Sequence != 0 {
		t.Errorf("expected seq 0, got %d", cs.Sequence)
	}
}

func TestChainStateSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.json")
	cs := &ChainState{
		ChainID:  "agent-1",
		PrevHash: "abc123",
		Sequence: 42,
		LastTS:   time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := cs.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ChainID != cs.ChainID {
		t.Errorf("chain_id mismatch: %s vs %s", loaded.ChainID, cs.ChainID)
	}
	if loaded.PrevHash != cs.PrevHash {
		t.Errorf("prev_hash mismatch: %s vs %s", loaded.PrevHash, cs.PrevHash)
	}
	if loaded.Sequence != cs.Sequence {
		t.Errorf("seq mismatch: %d vs %d", loaded.Sequence, cs.Sequence)
	}
}

func TestChainStateCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.json")
	os.WriteFile(path, []byte("not json{{{"), 0644)

	cs, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("should recover from corrupt file, got: %v", err)
	}
	if cs.PrevHash != "genesis" {
		t.Error("corrupt file should start genesis")
	}
}

func TestChainStateAdvance(t *testing.T) {
	cs := &ChainState{
		ChainID:  "agent-1",
		PrevHash: "genesis",
		Sequence: 0,
	}

	cs.Advance("hash-1")
	if cs.PrevHash != "hash-1" {
		t.Errorf("expected hash-1, got %s", cs.PrevHash)
	}
	if cs.Sequence != 1 {
		t.Errorf("expected seq 1, got %d", cs.Sequence)
	}

	cs.Advance("hash-2")
	if cs.PrevHash != "hash-2" {
		t.Errorf("expected hash-2, got %s", cs.PrevHash)
	}
	if cs.Sequence != 2 {
		t.Errorf("expected seq 2, got %d", cs.Sequence)
	}
}
