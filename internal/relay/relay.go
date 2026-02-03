package relay

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/approval"
	"github.com/parachute-security/parachute/internal/config"
)

// Client manages connection to cloud relay server
type Client struct {
	cfg       *config.RelayConfig
	approvalQ *approval.Queue
	mu        sync.RWMutex
	connected bool
	stopCh    chan struct{}
}

// Message represents a relay protocol message
type Message struct {
	Type    string         `json:"type"`
	ID      string         `json:"id,omitempty"`
	Payload map[string]any `json:"payload,omitempty"`
}

// New creates a new relay client
func New(cfg *config.RelayConfig, approvalQ *approval.Queue) *Client {
	return &Client{
		cfg:       cfg,
		approvalQ: approvalQ,
		stopCh:    make(chan struct{}),
	}
}

// Start begins the relay connection (run in goroutine)
func (c *Client) Start(ctx context.Context) {
	if !c.cfg.Enabled {
		log.Info("[RELAY] Relay disabled, running in local-only mode")
		return
	}

	log.Infof("[RELAY] Connecting to relay server: %s", c.cfg.ServerURL)

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
			if err := c.connect(ctx); err != nil {
				log.Warnf("[RELAY] Connection failed: %v, retrying in 10s", err)
				time.Sleep(10 * time.Second)
			}
		}
	}
}

// Stop closes the relay connection
func (c *Client) Stop() {
	close(c.stopCh)
}

// IsConnected returns true if connected to relay
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *Client) connect(ctx context.Context) error {
	// Note: Install gorilla/websocket for production WebSocket client
	// go get github.com/gorilla/websocket
	//
	// Example:
	// conn, _, err := websocket.DefaultDialer.DialContext(ctx, c.cfg.ServerURL, nil)
	// if err != nil { return err }
	// defer conn.Close()
	// for { _, msg, err := conn.ReadMessage(); c.handleMessage(msg) }

	log.Info("[RELAY] WebSocket client placeholder - install gorilla/websocket for production")

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopCh:
		return nil
	case <-time.After(30 * time.Second):
		return nil
	}
}

func (c *Client) handleMessage(data []byte) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Warnf("[RELAY] Invalid message: %v", err)
		return
	}

	switch msg.Type {
	case "approve":
		if msg.ID != "" {
			c.approvalQ.Approve(msg.ID)
			log.Infof("[RELAY] Approved via relay: %s", msg.ID)
		}
	case "deny":
		if msg.ID != "" {
			c.approvalQ.Deny(msg.ID)
			log.Infof("[RELAY] Denied via relay: %s", msg.ID)
		}
	default:
		log.Warnf("[RELAY] Unknown message type: %s", msg.Type)
	}
}
