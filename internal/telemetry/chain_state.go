package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ChainState tracks the per-agent hash chain for SDR continuity.
type ChainState struct {
	ChainID  string    `json:"chain_id"`
	PrevHash string    `json:"prev_hash"`
	Sequence int64     `json:"seq"`
	LastTS   time.Time `json:"last_ts"`

	mu         sync.Mutex `json:"-"`
	path       string     `json:"-"`
	dirtyCount int        `json:"-"` // SDRs since last fsync
}

const (
	genesisHash   = "genesis"
	fsyncInterval = 10 // fsync every N SDRs
)

// LoadChainState loads chain state from disk.
// Returns a genesis state if the file is missing or corrupt.
func LoadChainState(path string) (*ChainState, error) {
	cs := &ChainState{
		PrevHash: genesisHash,
		path:     path,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// Missing file: start genesis
		return cs, nil
	}

	if err := json.Unmarshal(data, cs); err != nil {
		// Corrupt file: start genesis
		cs.PrevHash = genesisHash
		cs.Sequence = 0
		cs.ChainID = ""
		return cs, nil
	}

	return cs, nil
}

// GetChainInfo returns the current chain linkage info under the lock.
func (cs *ChainState) GetChainInfo() (prevHash, chainID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.PrevHash, cs.ChainID
}

// Advance updates chain state after a new SDR is created.
func (cs *ChainState) Advance(recordHash string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.PrevHash = recordHash
	cs.Sequence++
	cs.LastTS = time.Now().UTC()
	cs.dirtyCount++

	if cs.dirtyCount >= fsyncInterval {
		cs.syncLocked()
	}
}

// Save writes chain state to disk.
func (cs *ChainState) Save(path string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if path != "" {
		cs.path = path
	}
	return cs.syncLocked()
}

// Sync forces a write to disk.
func (cs *ChainState) Sync() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.syncLocked()
}

func (cs *ChainState) syncLocked() error {
	if cs.path == "" {
		return nil
	}

	data, err := json.Marshal(cs)
	if err != nil {
		return err
	}

	// Atomic write: write to temp, rename
	dir := filepath.Dir(cs.path)
	tmp, err := os.CreateTemp(dir, "chain_state_*.tmp")
	if err != nil {
		return err
	}

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()

	if err := os.Rename(tmp.Name(), cs.path); err != nil {
		os.Remove(tmp.Name())
		return err
	}

	cs.dirtyCount = 0
	return nil
}
