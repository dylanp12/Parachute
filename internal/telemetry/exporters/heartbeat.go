package exporters

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/parachute-security/parachute/pkg/sdr"
)

// HeartbeatConfig configures the heartbeat emitter.
type HeartbeatConfig struct {
	ProURL   string
	APIKey   string
	AgentID  string
	TenantID string
	Interval time.Duration
	Version  string
}

// HeartbeatEmitter sends periodic heartbeats to Pro's fleet endpoint.
type HeartbeatEmitter struct {
	cfg    HeartbeatConfig
	client *http.Client
	done   chan struct{}
}

// NewHeartbeatEmitter creates a new heartbeat emitter.
func NewHeartbeatEmitter(cfg HeartbeatConfig) *HeartbeatEmitter {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	return &HeartbeatEmitter{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		done:   make(chan struct{}),
	}
}

// Start begins the heartbeat loop.
func (h *HeartbeatEmitter) Start(ctx context.Context) {
	go h.loop(ctx)
}

// Close waits for the heartbeat loop to finish.
func (h *HeartbeatEmitter) Close() {
	<-h.done
}

func (h *HeartbeatEmitter) loop(ctx context.Context) {
	defer close(h.done)
	ticker := time.NewTicker(h.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.send()
		case <-ctx.Done():
			return
		}
	}
}

func (h *HeartbeatEmitter) send() {
	payload := sdr.HeartbeatPayload{
		AgentID:        h.cfg.AgentID,
		TenantID:       h.cfg.TenantID,
		SidecarVersion: h.cfg.Version,
	}

	data, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", h.cfg.ProURL, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if h.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.cfg.APIKey)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return // silent retry next tick
	}
	resp.Body.Close()
}
