package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// HashChainLogger wraps a Logger and adds tamper-evident hash chain integrity.
// Each audit event includes the hash of the previous entry, creating a chain
// that can be verified for integrity after the fact.
type HashChainLogger struct {
	mu       sync.Mutex
	output   io.Writer
	prevHash string
	seq      int64
}

// HashChainEvent extends Event with integrity fields
type HashChainEvent struct {
	Event
	Integrity IntegrityInfo `json:"integrity"`
}

// IntegrityInfo contains the hash chain fields for tamper-evident logging
type IntegrityInfo struct {
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	Seq      int64  `json:"seq"`
}

// NewHashChainLogger creates an audit logger with hash chain integrity
func NewHashChainLogger(output io.Writer) *HashChainLogger {
	return &HashChainLogger{
		output:   output,
		prevHash: "genesis",
	}
}

// Log writes an audit event with hash chain integrity
func (l *HashChainLogger) Log(event *Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.CorrelationID == "" {
		event.CorrelationID = GenerateCorrelationID()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++

	// Compute hash of this entry (including previous hash)
	chainEvent := HashChainEvent{
		Event: *event,
		Integrity: IntegrityInfo{
			PrevHash: l.prevHash,
			Seq:      l.seq,
		},
	}

	// Hash the event content + prev hash + seq
	hash := computeHash(chainEvent)
	chainEvent.Integrity.Hash = hash
	l.prevHash = hash

	// Encode and write
	encoder := json.NewEncoder(l.output)
	if err := encoder.Encode(chainEvent); err != nil {
		fmt.Fprintf(l.output, `{"error":"failed to write audit log: %v"}`+"\n", err)
	}
}

// computeHash creates a SHA-256 hash of the event content for chain integrity
func computeHash(event HashChainEvent) string {
	// Hash the event without the hash field itself
	h := sha256.New()
	h.Write([]byte(event.PrevHash))
	h.Write([]byte(fmt.Sprintf("%d", event.Seq)))
	h.Write([]byte(event.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(string(event.EventType)))
	h.Write([]byte(event.CorrelationID))
	h.Write([]byte(event.Command))
	h.Write([]byte(event.CommandID))
	h.Write([]byte(event.ToolName))
	h.Write([]byte(event.Reason))
	h.Write([]byte(event.Domain))
	h.Write([]byte(event.ClientIP))
	h.Write([]byte(event.Method))
	h.Write([]byte(event.Path))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain verifies the integrity of a sequence of hash chain events.
// Returns nil if the chain is valid, or an error indicating where it breaks.
func VerifyChain(events []HashChainEvent) error {
	if len(events) == 0 {
		return nil
	}

	// First event should reference "genesis"
	if events[0].Integrity.PrevHash != "genesis" {
		return fmt.Errorf("chain broken at seq %d: expected genesis prev_hash, got %q",
			events[0].Integrity.Seq, events[0].Integrity.PrevHash)
	}

	for i, event := range events {
		// Verify the hash
		expected := computeHash(HashChainEvent{
			Event: event.Event,
			Integrity: IntegrityInfo{
				PrevHash: event.Integrity.PrevHash,
				Seq:      event.Integrity.Seq,
			},
		})
		if event.Integrity.Hash != expected {
			return fmt.Errorf("chain broken at seq %d: hash mismatch (expected %s, got %s)",
				event.Integrity.Seq, expected, event.Integrity.Hash)
		}

		// Verify chain linkage (prev_hash of next event = hash of current)
		if i > 0 {
			if event.Integrity.PrevHash != events[i-1].Integrity.Hash {
				return fmt.Errorf("chain broken at seq %d: prev_hash doesn't match previous entry hash",
					event.Integrity.Seq)
			}
		}

		// Verify sequence is monotonic
		if event.Integrity.Seq != int64(i+1) {
			return fmt.Errorf("chain broken at seq %d: expected seq %d",
				event.Integrity.Seq, i+1)
		}
	}

	return nil
}
