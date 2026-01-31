package approval

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// PendingCommand represents a command awaiting approval
type PendingCommand struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	ToolName  string    `json:"tool_name"`
	Args      any       `json:"args"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
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

// Queue manages pending approval requests
type Queue struct {
	mu      sync.RWMutex
	pending map[string]*PendingCommand
	timeout time.Duration
}

// WebhookConfig defines a notification endpoint
type WebhookConfig struct {
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"`
	Headers map[string]string `yaml:"headers"`
}

// NewQueue creates a new approval queue
func NewQueue(timeout time.Duration) *Queue {
	q := &Queue{
		pending: make(map[string]*PendingCommand),
		timeout: timeout,
	}
	go q.cleanupExpired()
	return q
}

// Add creates a new pending approval and returns its ID
func (q *Queue) Add(command, toolName, reason string, args any) *PendingCommand {
	id := uuid.New().String()[:8]

	pc := &PendingCommand{
		ID:        id,
		Command:   command,
		ToolName:  toolName,
		Args:      args,
		Reason:    reason,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(q.timeout),
		approved:  make(chan bool, 1),
	}

	q.mu.Lock()
	q.pending[id] = pc
	q.mu.Unlock()

	return pc
}

// Wait blocks until approval/denial or timeout
func (q *Queue) Wait(ctx context.Context, id string) Decision {
	q.mu.RLock()
	pc, exists := q.pending[id]
	q.mu.RUnlock()

	if !exists {
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

// Approve marks a command as approved
func (q *Queue) Approve(id string) bool {
	q.mu.Lock()
	pc, exists := q.pending[id]
	q.mu.Unlock()

	if !exists {
		return false
	}

	pc.once.Do(func() {
		pc.approved <- true
		close(pc.approved)
	})

	q.Remove(id)
	return true
}

// Deny marks a command as denied
func (q *Queue) Deny(id string) bool {
	q.mu.Lock()
	pc, exists := q.pending[id]
	q.mu.Unlock()

	if !exists {
		return false
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

// List returns all pending commands
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
	return pc, exists
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
			}
		}
		q.mu.Unlock()
	}
}
