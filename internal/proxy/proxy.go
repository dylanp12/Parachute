package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	fasthttpwebsocket "github.com/fasthttp/websocket"
	fiberwebsocket "github.com/gofiber/contrib/v3/websocket"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/approval"
	"github.com/parachute-security/parachute/internal/config"
	"github.com/parachute-security/parachute/internal/egress"
	"github.com/parachute-security/parachute/internal/interceptor"
	"github.com/parachute-security/parachute/internal/metrics"
)

// Proxy handles proxying requests to the upstream agent
type Proxy struct {
	upstream    string
	client      *http.Client
	interceptor *interceptor.Interceptor
	approvalQ   *approval.Queue
	notifier    *approval.Notifier
	egress      *egress.Filter
	cfg         *config.Config
}

// New creates a new proxy instance
func New(cfg *config.Config, approvalQ *approval.Queue, notifier *approval.Notifier) *Proxy {
	// Create a transport that supports streaming
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // Preserve streaming
		MaxIdleConnsPerHost: 10,
	}

	return &Proxy{
		upstream: cfg.Upstream,
		client: &http.Client{
			Transport: transport,
			Timeout:   0, // No timeout for streaming
		},
		interceptor: interceptor.New(&cfg.RiskPolicy),
		approvalQ:   approvalQ,
		notifier:    notifier,
		egress:      egress.New(&cfg.Egress),
		cfg:         cfg,
	}
}

// Handler returns the Fiber handler for proxying requests
func (p *Proxy) Handler() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Check for WebSocket upgrade request - delegate to WebSocket handler
		if fiberwebsocket.IsWebSocketUpgrade(c) {
			return p.handleWebSocket(c)
		}

		body := c.Body()

		// Check for PII in request body
		if len(body) > 0 {
			result := p.egress.CheckContent(string(body))
			if !result.Allowed {
				log.Warnf("[BLOCKED] PII detected in request: %s", result.Pattern)
				metrics.Get().PIIDetected.Add(1)
				metrics.Get().RequestsBlocked.Add(1)
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":   "request blocked",
					"reason":  result.Reason,
					"pattern": result.Pattern,
				})
			}
		}

		// Check for OpenClaw tools/invoke endpoint
		path := c.Path()
		if strings.HasSuffix(path, "/tools/invoke") || strings.Contains(path, "/tools/invoke") {
			return p.handleOpenClawToolInvoke(c, body)
		}

		// Try to intercept tool calls
		if len(body) > 0 {
			blocked, err := p.checkToolCalls(c.Context(), body)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
			}
			if blocked {
				metrics.Get().RequestsBlocked.Add(1)
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":  "command blocked by policy",
					"reason": "command matches block list or was denied",
				})
			}
		}

		// Check for streaming request (Accept: text/event-stream or similar)
		if isStreamingRequest(c) {
			return p.handleStreaming(c, body)
		}

		return p.handleStandardRequest(c, body)
	}
}

// handleStandardRequest handles regular HTTP requests
func (p *Proxy) handleStandardRequest(c fiber.Ctx, body []byte) error {
	path := c.OriginalURL()
	if strings.HasPrefix(path, "/proxy") {
		path = strings.TrimPrefix(path, "/proxy")
		if path == "" {
			path = "/"
		}
	}
	upstreamURL := p.upstream + path

	req, err := http.NewRequestWithContext(c.Context(), c.Method(), upstreamURL, bytes.NewReader(body))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create upstream request"})
	}

	// Copy headers
	c.Request().Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		// Skip hop-by-hop headers
		if !isHopByHopHeader(keyStr) {
			req.Header.Set(keyStr, string(value))
		}
	})

	resp, err := p.client.Do(req)
	if err != nil {
		log.Errorf("Upstream request failed: %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "upstream request failed"})
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read upstream response"})
	}

	for key, values := range resp.Header {
		if !isHopByHopHeader(key) {
			for _, value := range values {
				c.Set(key, value)
			}
		}
	}

	return c.Status(resp.StatusCode).Send(respBody)
}

// handleStreaming handles Server-Sent Events (SSE) and streaming responses
func (p *Proxy) handleStreaming(c fiber.Ctx, body []byte) error {
	path := c.OriginalURL()
	if strings.HasPrefix(path, "/proxy") {
		path = strings.TrimPrefix(path, "/proxy")
		if path == "" {
			path = "/"
		}
	}
	upstreamURL := p.upstream + path

	req, err := http.NewRequestWithContext(c.Context(), c.Method(), upstreamURL, bytes.NewReader(body))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create upstream request"})
	}

	// Copy headers
	c.Request().Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if !isHopByHopHeader(keyStr) {
			req.Header.Set(keyStr, string(value))
		}
	})

	resp, err := p.client.Do(req)
	if err != nil {
		log.Errorf("Upstream streaming request failed: %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "upstream request failed"})
	}

	// Set response headers before streaming
	c.Set("Content-Type", resp.Header.Get("Content-Type"))
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Status(resp.StatusCode)

	// Use Fiber v3's SendStreamWriter for streaming responses
	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer resp.Body.Close()

		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err != io.EOF {
					log.Errorf("Streaming read error: %v", err)
				}
				break
			}
			if _, err := w.Write(line); err != nil {
				log.Errorf("Streaming write error: %v", err)
				break
			}
			if err := w.Flush(); err != nil {
				log.Errorf("Streaming flush error: %v", err)
				break
			}
		}
	})
}

// WebSocketHandler returns a Fiber handler for WebSocket upgrade requests
// This should be registered with the websocket.New() middleware
func (p *Proxy) WebSocketHandler() fiber.Handler {
	return fiberwebsocket.New(func(c *fiberwebsocket.Conn) {
		defer c.Close()

		// Get the path from locals (set before upgrade)
		path, _ := c.Locals("proxy_path").(string)
		if path == "" {
			path = "/"
		}

		// Build upstream WebSocket URL
		upstreamURL := p.upstream + path
		upstreamURL = strings.Replace(upstreamURL, "http://", "ws://", 1)
		upstreamURL = strings.Replace(upstreamURL, "https://", "wss://", 1)

		log.Infof("[WEBSOCKET] Connecting to upstream: %s", upstreamURL)

		// Connect to upstream WebSocket using gorilla websocket dialer
		dialer := fasthttpwebsocket.Dialer{
			HandshakeTimeout: 30 * time.Second,
		}

		upstreamConn, _, err := dialer.Dial(upstreamURL, nil)
		if err != nil {
			log.Errorf("[WEBSOCKET] Failed to connect to upstream: %v", err)
			return
		}
		defer upstreamConn.Close()

		log.Infof("[WEBSOCKET] Connected to upstream: %s", upstreamURL)

		// Bidirectional proxy using goroutines
		var wg sync.WaitGroup
		wg.Add(2)

		// Client -> Upstream
		go func() {
			defer wg.Done()
			for {
				messageType, message, err := c.ReadMessage()
				if err != nil {
					if !fasthttpwebsocket.IsCloseError(err, fasthttpwebsocket.CloseGoingAway, fasthttpwebsocket.CloseNormalClosure) {
						log.Errorf("[WEBSOCKET] Client read error: %v", err)
					}
					upstreamConn.Close()
					return
				}
				if err := upstreamConn.WriteMessage(messageType, message); err != nil {
					log.Errorf("[WEBSOCKET] Upstream write error: %v", err)
					return
				}
			}
		}()

		// Upstream -> Client
		go func() {
			defer wg.Done()
			for {
				messageType, message, err := upstreamConn.ReadMessage()
				if err != nil {
					if !fasthttpwebsocket.IsCloseError(err, fasthttpwebsocket.CloseGoingAway, fasthttpwebsocket.CloseNormalClosure) {
						log.Errorf("[WEBSOCKET] Upstream read error: %v", err)
					}
					c.Close()
					return
				}
				if err := c.WriteMessage(messageType, message); err != nil {
					log.Errorf("[WEBSOCKET] Client write error: %v", err)
					return
				}
			}
		}()

		wg.Wait()
		log.Infof("[WEBSOCKET] Connection closed for %s", path)
	})
}

// handleWebSocket handles WebSocket upgrade requests
func (p *Proxy) handleWebSocket(c fiber.Ctx) error {
	// Store the path for the WebSocket handler
	path := c.OriginalURL()
	if strings.HasPrefix(path, "/proxy") {
		path = strings.TrimPrefix(path, "/proxy")
		if path == "" {
			path = "/"
		}
	}
	c.Locals("proxy_path", path)

	log.Infof("[WEBSOCKET] Upgrade request for %s", path)

	// Use the WebSocket handler
	return p.WebSocketHandler()(c)
}

// handleOpenClawToolInvoke handles OpenClaw's POST /tools/invoke endpoint
// This applies Parachute's risk_policy to tool invocations.
//
// SECURITY: This handler implements FAIL-CLOSED behavior. If we cannot parse
// the request into a known tool invocation format, we DENY the request rather
// than forwarding it. This prevents attackers from crafting unparseable payloads
// to bypass security controls.
func (p *Proxy) handleOpenClawToolInvoke(c fiber.Ctx, body []byte) error {
	correlationID := c.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}

	log.Infof("[OPENCLAW] [%s] Processing tools/invoke request (%d bytes)", correlationID, len(body))

	// Use the tolerant normalizer to parse various payload formats
	normalized, err := interceptor.NormalizeToolInvoke(body)
	if err != nil {
		// FAIL-CLOSED: If we can't parse the tool invocation, deny the request
		// This prevents attackers from crafting malformed payloads to bypass security
		log.Warnf("[OPENCLAW:PARSE_ERROR] [%s] Failed to parse tool invocation: %v", correlationID, err)

		// Truncate raw body for logging (avoid logging huge payloads)
		rawPreview := string(body)
		if len(rawPreview) > 200 {
			rawPreview = rawPreview[:200] + "..."
		}
		log.Warnf("[OPENCLAW:PARSE_ERROR] [%s] Raw payload preview: %s", correlationID, rawPreview)

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":          "unable to parse tool invocation request",
			"reason":         "request does not match any known tool invocation format",
			"blocked":        true,
			"correlation_id": correlationID,
			"hint":           "expected formats: {tool,input}, {tool,args}, {action,args}, {name,args}, {tool_name,tool_input}, or {type:'tool_use',name,input}",
		})
	}

	log.Infof("[OPENCLAW] [%s] Parsed tool invocation: %s", correlationID, normalized.String())

	// Log any unknown keys for monitoring (helps detect new payload formats)
	normalized.LogUnknownKeys(correlationID)

	// Check if this is a shell/command execution tool
	if normalized.IsCommandTool() {
		command := normalized.Command
		if command != "" {
			tc := normalized.ToToolCall()
			result := p.interceptor.Check(tc)

			switch result.Action {
			case interceptor.ActionBlock:
				log.Warnf("[OPENCLAW:BLOCKED] [%s] Tool %s command blocked: %s (reason: %s, format: %s)",
					correlationID, normalized.ToolName, truncateCommand(command), result.Reason, normalized.Format)
				metrics.Get().CommandsBlocked.Add(1)
				metrics.Get().RequestsBlocked.Add(1)
				if interceptor.IsForkBomb(command) {
					metrics.Get().ForkBombsBlocked.Add(1)
				}
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":          "tool invocation blocked by policy",
					"tool":           normalized.ToolName,
					"reason":         result.Reason,
					"blocked":        true,
					"correlation_id": correlationID,
				})

			case interceptor.ActionPending:
				log.Infof("[OPENCLAW:PENDING] [%s] Tool %s requires approval: %s (format: %s)",
					correlationID, normalized.ToolName, truncateCommand(command), normalized.Format)
				metrics.Get().CommandsPending.Add(1)

				pc := p.approvalQ.Add(command, normalized.ToolName, result.Reason, normalized.Args)
				if err := p.notifier.NotifyPending(pc); err != nil {
					log.Warnf("[%s] Failed to send notification: %v", correlationID, err)
				}

				decision := p.approvalQ.Wait(c.Context(), pc.ID)

				switch decision {
				case approval.DecisionApproved:
					log.Infof("[OPENCLAW:APPROVED] [%s] Tool %s approved: %s",
						correlationID, normalized.ToolName, truncateCommand(command))
					metrics.Get().RequestsApproved.Add(1)
					metrics.Get().CommandsAllowed.Add(1)
					// Continue to forward the request
				case approval.DecisionDenied:
					log.Warnf("[OPENCLAW:DENIED] [%s] Tool %s denied: %s",
						correlationID, normalized.ToolName, truncateCommand(command))
					metrics.Get().RequestsDenied.Add(1)
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":          "tool invocation denied",
						"tool":           normalized.ToolName,
						"reason":         "request was denied by operator",
						"blocked":        true,
						"correlation_id": correlationID,
					})
				default:
					log.Warnf("[OPENCLAW:EXPIRED] [%s] Tool %s approval timed out: %s",
						correlationID, normalized.ToolName, truncateCommand(command))
					return c.Status(fiber.StatusGatewayTimeout).JSON(fiber.Map{
						"error":          "approval timed out",
						"tool":           normalized.ToolName,
						"reason":         "request was not approved in time",
						"blocked":        true,
						"correlation_id": correlationID,
					})
				}
			default:
				log.Infof("[OPENCLAW:ALLOWED] [%s] Tool %s command allowed: %s (format: %s)",
					correlationID, normalized.ToolName, truncateCommand(command), normalized.Format)
				metrics.Get().CommandsAllowed.Add(1)
			}
		} else {
			// Command tool but no command found - log warning but allow
			// (the tool might use different semantics)
			log.Warnf("[OPENCLAW:WARN] [%s] Command tool %s has no extractable command (format: %s)",
				correlationID, normalized.ToolName, normalized.Format)
		}
	} else {
		// Non-command tool - allow to pass through
		log.Infof("[OPENCLAW:PASSTHROUGH] [%s] Non-command tool %s (format: %s)",
			correlationID, normalized.ToolName, normalized.Format)
	}

	// Forward the request to upstream
	return p.handleStandardRequest(c, body)
}

// truncateCommand truncates a command for safe logging
func truncateCommand(cmd string) string {
	if len(cmd) > 100 {
		return cmd[:100] + "..."
	}
	return cmd
}

func (p *Proxy) checkToolCalls(ctx context.Context, body []byte) (blocked bool, err error) {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return false, nil
	}

	tc := interceptor.ParseToolCallFromJSON(data)
	if tc == nil {
		return false, nil
	}

	result := p.interceptor.Check(tc)

	switch result.Action {
	case interceptor.ActionBlock:
		log.Warnf("[BLOCKED] Command blocked: %s (reason: %s)", tc.Command, result.Reason)
		metrics.Get().CommandsBlocked.Add(1)
		if interceptor.IsForkBomb(tc.Command) {
			metrics.Get().ForkBombsBlocked.Add(1)
		}
		return true, nil

	case interceptor.ActionPending:
		log.Infof("[PENDING] Command requires approval: %s", tc.Command)
		metrics.Get().CommandsPending.Add(1)

		pc := p.approvalQ.Add(tc.Command, tc.Name, result.Reason, tc.Args)
		if err := p.notifier.NotifyPending(pc); err != nil {
			log.Warnf("Failed to send notification: %v", err)
		}

		decision := p.approvalQ.Wait(ctx, pc.ID)

		switch decision {
		case approval.DecisionApproved:
			log.Infof("[APPROVED] Command approved: %s", tc.Command)
			metrics.Get().RequestsApproved.Add(1)
			metrics.Get().CommandsAllowed.Add(1)
			return false, nil
		case approval.DecisionDenied:
			log.Warnf("[DENIED] Command denied: %s", tc.Command)
			metrics.Get().RequestsDenied.Add(1)
			return true, nil
		default:
			log.Warnf("[EXPIRED] Approval timed out: %s", tc.Command)
			return true, fmt.Errorf("approval timed out")
		}

	default:
		metrics.Get().CommandsAllowed.Add(1)
		return false, nil
	}
}

// Helper functions

func isStreamingRequest(c fiber.Ctx) bool {
	accept := c.Get("Accept")
	return strings.Contains(accept, "text/event-stream") ||
		strings.Contains(accept, "application/x-ndjson") ||
		strings.Contains(accept, "application/stream+json")
}

func isHopByHopHeader(header string) bool {
	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}
	return hopByHop[header]
}

// isCommandTool checks if a tool name is a shell/command execution tool
func isCommandTool(toolName string) bool {
	commandTools := []string{
		"bash", "shell", "terminal", "execute", "run",
		"execute_bash", "run_command", "command", "sh",
		"exec", "system", "subprocess", "cmd",
	}
	toolLower := strings.ToLower(toolName)
	for _, ct := range commandTools {
		if toolLower == ct || strings.Contains(toolLower, ct) {
			return true
		}
	}
	return false
}

// extractCommandFromInput extracts the command string from tool input
func extractCommandFromInput(input map[string]any) string {
	// Try common field names
	fields := []string{"command", "cmd", "script", "code", "input", "CommandLine", "shell_command"}
	for _, field := range fields {
		if val, ok := input[field]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

// HealthHandler returns a simple health check endpoint
func HealthHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "parachute",
			"time":    time.Now().Format(time.RFC3339),
		})
	}
}

// VersionHandler returns the current version of Parachute
func VersionHandler(version string) fiber.Handler {
	return func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"version":   version,
			"service":   "parachute",
			"goVersion": "go1.21+",
		})
	}
}
