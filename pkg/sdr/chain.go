package sdr

import "fmt"

// GenesisHash is the prev_hash value for the first record in a chain.
const GenesisHash = "genesis"

// ValidateChain verifies that a slice of SDRs forms a valid hash chain.
// Records must be sorted by their position in the chain (i.e., each record's
// prev_hash must equal the preceding record's record_hash).
//
// The first record in a chain must have prev_hash == "genesis".
func ValidateChain(records []SDR) error {
	if len(records) == 0 {
		return nil
	}

	if records[0].Chain.PrevHash != GenesisHash {
		return &ChainGapError{
			ChainID:  records[0].Chain.ChainID,
			Position: 0,
			SDRID:    records[0].SDRID.String(),
			Expected: GenesisHash,
			Got:      records[0].Chain.PrevHash,
		}
	}

	for i := 1; i < len(records); i++ {
		if records[i].Chain.PrevHash != records[i-1].Chain.RecordHash {
			return &ChainGapError{
				ChainID:  records[i].Chain.ChainID,
				Position: i,
				SDRID:    records[i].SDRID.String(),
				Expected: records[i-1].Chain.RecordHash,
				Got:      records[i].Chain.PrevHash,
			}
		}
	}

	return nil
}

// ValidateChainContinuity checks that a batch of new records continues
// from a known chain head. If latestHash is empty, the first record
// must be a genesis record.
func ValidateChainContinuity(records []SDR, latestHash string) error {
	if len(records) == 0 {
		return nil
	}

	// Check first record links to known head
	expectedPrev := latestHash
	if expectedPrev == "" {
		expectedPrev = GenesisHash
	}

	if records[0].Chain.PrevHash != expectedPrev {
		return &ChainGapError{
			ChainID:  records[0].Chain.ChainID,
			Position: 0,
			SDRID:    records[0].SDRID.String(),
			Expected: expectedPrev,
			Got:      records[0].Chain.PrevHash,
		}
	}

	// Check internal linkage
	for i := 1; i < len(records); i++ {
		if records[i].Chain.PrevHash != records[i-1].Chain.RecordHash {
			return &ChainGapError{
				ChainID:  records[i].Chain.ChainID,
				Position: i,
				SDRID:    records[i].SDRID.String(),
				Expected: records[i-1].Chain.RecordHash,
				Got:      records[i].Chain.PrevHash,
			}
		}
	}

	return nil
}

// ChainGapError represents a break in the hash chain.
type ChainGapError struct {
	ChainID  string // The chain where the gap was detected
	Position int    // Position in the slice where the gap was found
	SDRID    string // The SDR with the invalid prev_hash
	Expected string // The expected prev_hash value
	Got      string // The actual prev_hash value
}

func (e *ChainGapError) Error() string {
	return fmt.Sprintf("chain gap in %s at position %d (SDR %s): expected prev_hash %q, got %q",
		e.ChainID, e.Position, e.SDRID, e.Expected, e.Got)
}
