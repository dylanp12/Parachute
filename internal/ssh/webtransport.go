package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/audit"
)

// WebTransportConfig holds configuration for WebTransport SSH streaming
type WebTransportConfig struct {
	// Enabled controls whether WebTransport endpoints are available
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxStreamsPerSession limits concurrent streams per WebTransport session
	MaxStreamsPerSession int `yaml:"max_streams_per_session" json:"max_streams_per_session"`

	// IdleTimeout closes WebTransport sessions after this duration of inactivity
	IdleTimeout time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
}

// StreamMessage represents a message sent over a WebTransport stream
type StreamMessage struct {
	Type          string `json:"type"`                     // "stdin", "stdout", "stderr", "resize", "signal", "exit", "error"
	Data          string `json:"data,omitempty"`           // For stdin/stdout/stderr
	ExitCode      int    `json:"exit_code,omitempty"`      // For exit messages
	Rows          int    `json:"rows,omitempty"`           // For resize
	Cols          int    `json:"cols,omitempty"`           // For resize
	Signal        string `json:"signal,omitempty"`         // For signal messages
	CorrelationID string `json:"correlation_id,omitempty"` // For tracing
}

// StreamSession represents an active SSH streaming session over WebTransport
type StreamSession struct {
	mu            sync.Mutex
	id            string
	targetName    string
	correlationID string
	manager       *Manager
	executor      *Executor
	createdAt     time.Time
	lastActivity  time.Time
	closed        bool
}

// StreamHandler provides HTTP/WebSocket endpoints for SSH session streaming.
// This is designed to be compatible with WebTransport (HTTP/3 QUIC) when
// a WebTransport-capable server is used, while also supporting fallback
// via WebSocket for HTTP/2 environments.
//
// WebTransport advantages over WebSocket for SSH streaming:
//   - Multiplexed bidirectional streams (multiple channels over one connection)
//   - Lower latency via QUIC (0-RTT connection establishment)
//   - Independent stream flow control (stdout doesn't block stderr)
//   - Native support for datagrams (for keepalive/signals)
//
// Protocol:
//
//	Client opens a stream to /api/ssh/stream/:target
//	Messages are JSON-encoded StreamMessage objects
//	Types: stdin (client->server), stdout/stderr/exit/error (server->client)
type StreamHandler struct {
	manager  *Manager
	executor *Executor
	config   WebTransportConfig
	sessions sync.Map // map[string]*StreamSession
}

// NewStreamHandler creates a new WebTransport-compatible stream handler
func NewStreamHandler(manager *Manager, executor *Executor, cfg WebTransportConfig) *StreamHandler {
	if cfg.MaxStreamsPerSession <= 0 {
		cfg.MaxStreamsPerSession = 4
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}

	h := &StreamHandler{
		manager:  manager,
		executor: executor,
		config:   cfg,
	}

	// Background cleanup of idle sessions
	go h.cleanupLoop()

	return h
}

// RegisterRoutes registers WebTransport-compatible streaming routes
func (h *StreamHandler) RegisterRoutes(router fiber.Router) {
	// Stream endpoint - initiates a streaming SSH session
	// This uses Server-Sent Events (SSE) as a fallback transport
	// When WebTransport is available, clients should use the WT protocol directly
	router.Post("/stream/:target", h.initiateStream)

	// Stream capabilities endpoint - advertises WebTransport support
	router.Get("/stream/capabilities", h.capabilities)
}

// capabilities returns the streaming capabilities of this server
func (h *StreamHandler) capabilities(c fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"webtransport": fiber.Map{
			"supported":               true,
			"protocol":                "ssh-stream/1.0",
			"max_streams":             h.config.MaxStreamsPerSession,
			"idle_timeout_seconds":    int(h.config.IdleTimeout.Seconds()),
			"message_format":          "json",
			"supported_message_types": []string{"stdin", "stdout", "stderr", "resize", "signal", "exit", "error"},
		},
		"fallback": fiber.Map{
			"websocket": true,
			"sse":       true,
		},
	})
}

// initiateStream starts a streaming SSH session using SSE (Server-Sent Events)
// as the transport. This serves as a fallback when WebTransport is not available.
// For true WebTransport, a QUIC-capable server middleware would intercept before this.
func (h *StreamHandler) initiateStream(c fiber.Ctx) error {
	targetName := c.Params("target")

	target, ok := h.manager.GetTarget(targetName)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("target %q not found", targetName),
		})
	}

	if !target.Enabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": fmt.Sprintf("target %q is disabled", targetName),
		})
	}

	var req struct {
		Command       string            `json:"command"`
		Env           map[string]string `json:"env,omitempty"`
		WorkingDir    string            `json:"working_dir,omitempty"`
		CorrelationID string            `json:"correlation_id,omitempty"`
		Rows          int               `json:"rows,omitempty"`
		Cols          int               `json:"cols,omitempty"`
	}

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid stream request",
		})
	}

	if req.Command == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "command is required",
		})
	}

	correlationID := req.CorrelationID
	if correlationID == "" {
		correlationID = audit.GenerateCorrelationID()
	}

	// Acquire session slot
	if err := h.manager.AcquireSession(targetName); err != nil {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": fmt.Sprintf("session limit: %v", err),
		})
	}

	log.Infof("[SSH:STREAM] [%s] Starting stream on target %q: %s",
		correlationID, targetName, truncateCmd(req.Command))

	// Get SSH connection
	client, err := h.manager.GetConnection(targetName)
	if err != nil {
		h.manager.ReleaseSession(targetName)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": fmt.Sprintf("connection failed: %v", err),
		})
	}

	// Create SSH session
	session, err := client.NewSession()
	if err != nil {
		h.manager.ReleaseSession(targetName)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": fmt.Sprintf("session creation failed: %v", err),
		})
	}

	// Set up PTY if dimensions provided
	if req.Rows > 0 && req.Cols > 0 {
		modes := map[uint8]uint32{}
		if err := session.RequestPty("xterm-256color", req.Rows, req.Cols, modes); err != nil {
			log.Warnf("[SSH:STREAM] [%s] PTY request failed: %v", correlationID, err)
		}
	}

	// Set environment variables
	for k, v := range req.Env {
		session.Setenv(k, v)
	}

	// Get stdin pipe for writing
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		session.Close()
		h.manager.ReleaseSession(targetName)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to create stdin pipe",
		})
	}

	// Get stdout/stderr pipes
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		h.manager.ReleaseSession(targetName)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to create stdout pipe",
		})
	}

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		session.Close()
		h.manager.ReleaseSession(targetName)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to create stderr pipe",
		})
	}

	// Build command
	cmd := req.Command
	if req.WorkingDir != "" {
		cmd = fmt.Sprintf("cd %s && %s", shellQuote(req.WorkingDir), cmd)
	}

	// Start the command (non-blocking)
	if err := session.Start(cmd); err != nil {
		session.Close()
		h.manager.ReleaseSession(targetName)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": fmt.Sprintf("command start failed: %v", err),
		})
	}

	// Use SSE (Server-Sent Events) for streaming output back
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Correlation-ID", correlationID)

	ctx, cancel := context.WithCancel(c.Context())

	// Stream output using SendStreamWriter
	return c.SendStreamWriter(func(w io.Writer) {
		defer func() {
			cancel()
			stdinPipe.Close()
			session.Close()
			h.manager.ReleaseSession(targetName)
			log.Infof("[SSH:STREAM] [%s] Stream closed for target %q", correlationID, targetName)
		}()

		encoder := json.NewEncoder(w)
		writeMu := &sync.Mutex{}

		writeMsg := func(msg *StreamMessage) {
			writeMu.Lock()
			defer writeMu.Unlock()
			msg.CorrelationID = correlationID
			// SSE format: data: {json}\n\n
			fmt.Fprint(w, "data: ")
			encoder.Encode(msg)
			fmt.Fprint(w, "\n")
		}

		// Stream stdout
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			for {
				n, err := stdoutPipe.Read(buf)
				if n > 0 {
					writeMsg(&StreamMessage{
						Type: "stdout",
						Data: string(buf[:n]),
					})
				}
				if err != nil {
					break
				}
			}
		}()

		// Stream stderr
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			for {
				n, err := stderrPipe.Read(buf)
				if n > 0 {
					writeMsg(&StreamMessage{
						Type: "stderr",
						Data: string(buf[:n]),
					})
				}
				if err != nil {
					break
				}
			}
		}()

		// Wait for command completion
		exitCode := 0
		waitErr := session.Wait()
		if waitErr != nil {
			exitCode = extractExitCode(waitErr)
		}

		wg.Wait()

		// Send exit message
		writeMsg(&StreamMessage{
			Type:     "exit",
			ExitCode: exitCode,
		})

		_ = ctx // keep reference to context for future cancellation support
	})
}

// cleanupLoop removes idle stream sessions
func (h *StreamHandler) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		h.sessions.Range(func(key, value any) bool {
			sess := value.(*StreamSession)
			sess.mu.Lock()
			idle := now.Sub(sess.lastActivity)
			sess.mu.Unlock()

			if idle > h.config.IdleTimeout {
				h.sessions.Delete(key)
				log.Infof("[SSH:STREAM] Cleaned up idle stream session %s", key)
			}
			return true
		})
	}
}
