package approval

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/dylanp12/parachute/internal/storage"
)

// PendingCommand represents a command awaiting approval
type PendingCommand struct {
	ID        string         `json:"id"`
	Command   string         `json:"command"`
	ToolName  string         `json:"tool_name"`
	Args      map[string]any `json:"args"`
	Reason    string         `json:"reason"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	approved  chan bool
	once      sync.Once
}

// Decision represents the outcome of an approval request
type Decision int

const (
	DecisionPending Decision = iota
	DecisionApproved
	DecisionDenied
	DecisionExpired
)

// Queue manages pending approval requests with optional persistence
type Queue struct {
	mu      sync.RWMutex
	pending map[string]*PendingCommand
	timeout time.Duration
	store   *storage.Store // Optional persistent storage
}

// WebhookConfig defines a notification endpoint
type WebhookConfig struct {
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"`
	Headers map[string]string `yaml:"headers"`
}

// NewQueue creates a new in-memory approval queue (for backward compatibility)
func NewQueue(timeout time.Duration) *Queue {
	q := &Queue{
		pending: make(map[string]*PendingCommand),
		timeout: timeout,
	}
	go q.cleanupExpired()
	return q
}

// NewPersistentQueue creates a new approval queue with SQLite persistence
func NewPersistentQueue(timeout time.Duration, store *storage.Store) *Queue {
	q := &Queue{
		pending: make(map[string]*PendingCommand),
		timeout: timeout,
		store:   store,
	}
	go q.cleanupExpired()
	return q
}

// Add creates a new pending approval and returns its ID
func (q *Queue) Add(command, toolName, reason string, args any) *PendingCommand {
	id := uuid.New().String()[:8]

	// Convert args to map[string]any if needed
	argsMap, ok := args.(map[string]any)
	if !ok {
		argsMap = make(map[string]any)
		if args != nil {
			argsMap["raw"] = args
		}
	}

	pc := &PendingCommand{
		ID:        id,
		Command:   command,
		ToolName:  toolName,
		Args:      argsMap,
		Reason:    reason,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(q.timeout),
		approved:  make(chan bool, 1),
	}

	// Store in memory
	q.mu.Lock()
	q.pending[id] = pc
	q.mu.Unlock()

	// Persist to database if available
	if q.store != nil {
		storePc := &storage.PendingCommand{
			ID:        pc.ID,
			Command:   pc.Command,
			ToolName:  pc.ToolName,
			Args:      pc.Args,
			Reason:    pc.Reason,
			CreatedAt: pc.CreatedAt,
			ExpiresAt: pc.ExpiresAt,
			Status:    "pending",
		}
		q.store.Add(storePc)
	}

	return pc
}

// Wait blocks until approval/denial or timeout
func (q *Queue) Wait(ctx context.Context, id string) Decision {
	q.mu.RLock()
	pc, exists := q.pending[id]
	q.mu.RUnlock()

	if !exists {
		// Check persistent storage for already-decided commands
		if q.store != nil {
			status, err := q.store.GetStatus(id)
			if err == nil {
				switch status {
				case "approved":
					return DecisionApproved
				case "denied":
					return DecisionDenied
				case "expired":
					return DecisionExpired
				}
			}
		}
		return DecisionExpired
	}

	select {
	case approved := <-pc.approved:
		if approved {
			return DecisionApproved
		}
		return DecisionDenied
	case <-ctx.Done():
		return DecisionExpired
	case <-time.After(time.Until(pc.ExpiresAt)):
		q.Remove(id)
		return DecisionExpired
	}
}

// Approve marks a command as approved (idempotent)
func (q *Queue) Approve(id string) bool {
	q.mu.Lock()
	pc, exists := q.pending[id]
	q.mu.Unlock()

	// Update persistent storage first (idempotent)
	if q.store != nil {
		updated, err := q.store.Approve(id)
		if err == nil && updated {
			// Log the approval
			q.store.LogEvent(&storage.AuditEvent{
				Timestamp: time.Now(),
				EventType: "command_approved",
				CommandID: id,
				Command:   pc.Command,
				Action:    "approved",
			})
		}
	}

	if !exists {
		// Already removed from memory, but may have been in storage
		return q.store != nil
	}

	pc.once.Do(func() {
		pc.approved <- true
		close(pc.approved)
	})

	q.Remove(id)
	return true
}

// Deny marks a command as denied (idempotent)
func (q *Queue) Deny(id string) bool {
	q.mu.Lock()
	pc, exists := q.pending[id]
	q.mu.Unlock()

	// Update persistent storage first (idempotent)
	if q.store != nil {
		updated, err := q.store.Deny(id)
		if err == nil && updated {
			// Log the denial
			q.store.LogEvent(&storage.AuditEvent{
				Timestamp: time.Now(),
				EventType: "command_denied",
				CommandID: id,
				Command:   pc.Command,
				Action:    "denied",
			})
		}
	}

	if !exists {
		return q.store != nil
	}

	pc.once.Do(func() {
		pc.approved <- false
		close(pc.approved)
	})

	q.Remove(id)
	return true
}

// Remove deletes a pending command from the queue
func (q *Queue) Remove(id string) {
	q.mu.Lock()
	delete(q.pending, id)
	q.mu.Unlock()
}

// List returns all pending commands (from memory and storage)
func (q *Queue) List() []*PendingCommand {
	q.mu.RLock()
	defer q.mu.RUnlock()

	result := make([]*PendingCommand, 0, len(q.pending))
	for _, pc := range q.pending {
		result = append(result, pc)
	}
	return result
}

// Get retrieves a specific pending command
func (q *Queue) Get(id string) (*PendingCommand, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	pc, exists := q.pending[id]
	if exists {
		return pc, true
	}

	// Check persistent storage
	if q.store != nil {
		storePc, err := q.store.Get(id)
		if err == nil && storePc != nil && storePc.Status == "pending" {
			return &PendingCommand{
				ID:        storePc.ID,
				Command:   storePc.Command,
				ToolName:  storePc.ToolName,
				Args:      storePc.Args,
				Reason:    storePc.Reason,
				CreatedAt: storePc.CreatedAt,
				ExpiresAt: storePc.ExpiresAt,
			}, true
		}
	}

	return nil, false
}

func (q *Queue) cleanupExpired() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		q.mu.Lock()
		for id, pc := range q.pending {
			if now.After(pc.ExpiresAt) {
				pc.once.Do(func() { close(pc.approved) })
				delete(q.pending, id)

				// Log expiration
				if q.store != nil {
					q.store.LogEvent(&storage.AuditEvent{
						Timestamp: now,
						EventType: "command_expired",
						CommandID: id,
						Command:   pc.Command,
						Action:    "expired",
						Reason:    "timeout",
					})
				}
			}
		}
		q.mu.Unlock()
	}
}
