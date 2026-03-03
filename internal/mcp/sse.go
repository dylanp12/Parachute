package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
)

// SSEEvent is an event sent over the SSE stream.
type SSEEvent struct {
	ID   int64  `json:"id"`
	Type string `json:"type"` // "result", "approval_decision", "error"
	Data any    `json:"data"`
}

// SSEBroker manages SSE client connections and event dispatch.
type SSEBroker struct {
	mu      sync.RWMutex
	clients map[string]chan SSEEvent // correlation_id -> channel
	buffer  []SSEEvent              // ring buffer for replay
	bufSize int                     // max buffer size
	nextID  atomic.Int64
}

// NewSSEBroker creates an SSE broker with the given replay buffer size.
func NewSSEBroker(bufferSize int) *SSEBroker {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	return &SSEBroker{
		clients: make(map[string]chan SSEEvent),
		buffer:  make([]SSEEvent, 0, bufferSize),
		bufSize: bufferSize,
	}
}

// Publish sends an event to the matching client and stores in replay buffer.
func (b *SSEBroker) Publish(correlationID string, eventType string, data any) {
	event := SSEEvent{
		ID:   b.nextID.Add(1),
		Type: eventType,
		Data: data,
	}

	b.mu.Lock()
	// Add to buffer (drop oldest if full)
	if len(b.buffer) >= b.bufSize {
		b.buffer = b.buffer[1:]
	}
	b.buffer = append(b.buffer, event)

	// Deliver to client
	if ch, ok := b.clients[correlationID]; ok {
		select {
		case ch <- event:
		default:
			// Client slow, drop
		}
	}
	b.mu.Unlock()
}

// Subscribe creates a channel for receiving events.
func (b *SSEBroker) Subscribe(correlationID string) chan SSEEvent {
	ch := make(chan SSEEvent, 100)
	b.mu.Lock()
	b.clients[correlationID] = ch
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a client subscription.
func (b *SSEBroker) Unsubscribe(correlationID string) {
	b.mu.Lock()
	if ch, ok := b.clients[correlationID]; ok {
		close(ch)
		delete(b.clients, correlationID)
	}
	b.mu.Unlock()
}

// EventsSince returns events with ID greater than lastID (for replay on reconnect).
func (b *SSEBroker) EventsSince(lastID int64) []SSEEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var result []SSEEvent
	for _, e := range b.buffer {
		if e.ID > lastID {
			result = append(result, e)
		}
	}
	return result
}

// HandleSSE is the Fiber handler for the SSE endpoint.
func (b *SSEBroker) HandleSSE(c fiber.Ctx) error {
	correlationID := c.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = c.Query("correlation_id", "default")
	}

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	// Parse Last-Event-ID for reconnect replay
	lastEventID := c.Get("Last-Event-ID")
	var replayEvents []SSEEvent
	if lastEventID != "" {
		if id, err := strconv.ParseInt(lastEventID, 10, 64); err == nil {
			replayEvents = b.EventsSince(id)
		}
	}

	ch := b.Subscribe(correlationID)

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer b.Unsubscribe(correlationID)

		// Replay missed events on reconnect
		for _, event := range replayEvents {
			if err := writeSSEEventTo(w, event); err != nil {
				return
			}
		}

		for {
			select {
			case event, ok := <-ch:
				if !ok {
					return
				}
				if err := writeSSEEventTo(w, event); err != nil {
					return
				}
			case <-time.After(30 * time.Second):
				// Keepalive comment
				if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
					return
				}
				if err := w.Flush(); err != nil {
					return
				}
			}
		}
	})
}

func writeSSEEventTo(w *bufio.Writer, event SSEEvent) error {
	data, _ := json.Marshal(event.Data)
	if _, err := fmt.Fprintf(w, "id: %d\n", event.ID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\n", event.Type); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", string(data)); err != nil {
		return err
	}
	return w.Flush()
}
