package relay

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/config"
)

// Client manages connection to cloud relay server
type Client struct {
	cfg       *config.RelayConfig
	handler   ApprovalHandler
	mu        sync.RWMutex
	connected bool
	stopCh    chan struct{}
}

// New creates a new relay client
func New(cfg *config.RelayConfig, handler ApprovalHandler) *Client {
	return &Client{
		cfg:     cfg,
		handler: handler,
		stopCh:  make(chan struct{}),
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
	// Production implementation requires gorilla/websocket:
	//   go get github.com/gorilla/websocket
	//
	// The connection flow:
	// 1. Dial wss://relay.parachute.dev/ws
	// 2. Send MsgTypeAuthenticate with API key
	// 3. Enter read loop: handle approve/deny/sync messages
	// 4. Send MsgTypeHeartbeat every 30s
	// 5. Forward local pending commands via MsgTypePending

	log.Info("[RELAY] WebSocket client placeholder - requires Parachute Pro license")

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
	var msg RelayMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Warnf("[RELAY] Invalid message: %v", err)
		return
	}

	switch msg.Type {
	case MsgTypeApprove:
		if msg.ID != "" {
			c.handler.Approve(msg.ID)
			log.Infof("[RELAY] Approved via relay: %s", msg.ID)
		}
	case MsgTypeDeny:
		if msg.ID != "" {
			c.handler.Deny(msg.ID)
			log.Infof("[RELAY] Denied via relay: %s", msg.ID)
		}
	case MsgTypeSync:
		log.Info("[RELAY] Sync requested by relay server")
	default:
		log.Warnf("[RELAY] Unknown message type: %s", msg.Type)
	}
}
