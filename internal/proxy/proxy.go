package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/parachute-security/parachute/internal/approval"
	"github.com/parachute-security/parachute/internal/config"
	"github.com/parachute-security/parachute/internal/egress"
	"github.com/parachute-security/parachute/internal/interceptor"
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
		// Check for WebSocket upgrade request
		if isWebSocketUpgrade(c) {
			return p.handleWebSocket(c)
		}

		body := c.Body()

		// Check for PII in request body
		if len(body) > 0 {
			result := p.egress.CheckContent(string(body))
			if !result.Allowed {
				log.Printf("[BLOCKED] PII detected in request: %s", result.Pattern)
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
		log.Printf("[ERROR] Upstream request failed: %v", err)
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
		log.Printf("[ERROR] Upstream streaming request failed: %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "upstream request failed"})
	}
	defer resp.Body.Close()

	// Set response headers
	c.Set("Content-Type", resp.Header.Get("Content-Type"))
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Status(resp.StatusCode)

	// Stream the response
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("[ERROR] Streaming read error: %v", err)
				}
				break
			}
			if _, err := w.Write(line); err != nil {
				log.Printf("[ERROR] Streaming write error: %v", err)
				break
			}
			if err := w.Flush(); err != nil {
				log.Printf("[ERROR] Streaming flush error: %v", err)
				break
			}
		}
	})

	return nil
}

// handleWebSocket handles WebSocket upgrade requests
func (p *Proxy) handleWebSocket(c fiber.Ctx) error {
	log.Printf("[WEBSOCKET] Upgrade request for %s", c.Path())

	// Get the underlying connection
	c.Context().Hijack(func(clientConn net.Conn) {
		defer clientConn.Close()

		// Build upstream URL (convert http to ws)
		path := c.OriginalURL()
		if strings.HasPrefix(path, "/proxy") {
			path = strings.TrimPrefix(path, "/proxy")
			if path == "" {
				path = "/"
			}
		}

		upstreamURL := p.upstream + path
		upstreamURL = strings.Replace(upstreamURL, "http://", "ws://", 1)
		upstreamURL = strings.Replace(upstreamURL, "https://", "wss://", 1)

		// Connect to upstream WebSocket
		dialer := net.Dialer{Timeout: 30 * time.Second}
		upstreamConn, err := dialer.Dial("tcp", extractHost(p.upstream))
		if err != nil {
			log.Printf("[WEBSOCKET] Failed to connect to upstream: %v", err)
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer upstreamConn.Close()

		// Forward the original request to upstream
		req := fmt.Sprintf("%s %s HTTP/1.1\r\n", c.Method(), path)
		c.Request().Header.VisitAll(func(key, value []byte) {
			req += fmt.Sprintf("%s: %s\r\n", string(key), string(value))
		})
		req += "\r\n"

		if _, err := upstreamConn.Write([]byte(req)); err != nil {
			log.Printf("[WEBSOCKET] Failed to send upgrade request: %v", err)
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}

		// Bidirectional copy
		done := make(chan struct{}, 2)
		go func() {
			io.Copy(upstreamConn, clientConn)
			done <- struct{}{}
		}()
		go func() {
			io.Copy(clientConn, upstreamConn)
			done <- struct{}{}
		}()

		<-done
		log.Printf("[WEBSOCKET] Connection closed for %s", c.Path())
	})

	return nil
}

// handleOpenClawToolInvoke handles OpenClaw's POST /tools/invoke endpoint
// This applies Parachute's risk_policy to tool invocations
func (p *Proxy) handleOpenClawToolInvoke(c fiber.Ctx, body []byte) error {
	log.Printf("[OPENCLAW] Processing tools/invoke request")

	// Parse the OpenClaw tool invoke request
	var invokeReq struct {
		Tool   string         `json:"tool"`
		Input  map[string]any `json:"input"`
		Config map[string]any `json:"config,omitempty"`
	}

	if err := json.Unmarshal(body, &invokeReq); err != nil {
		// Not a valid OpenClaw request, forward as-is
		return p.handleStandardRequest(c, body)
	}

	// Check if this is a shell/command tool
	if isCommandTool(invokeReq.Tool) {
		command := extractCommandFromInput(invokeReq.Input)
		if command != "" {
			tc := &interceptor.ToolCall{
				Name:    invokeReq.Tool,
				Command: command,
				Args:    invokeReq.Input,
			}

			result := p.interceptor.Check(tc)

			switch result.Action {
			case interceptor.ActionBlock:
				log.Printf("[OPENCLAW:BLOCKED] Tool %s command blocked: %s (reason: %s)",
					invokeReq.Tool, command, result.Reason)
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":   "tool invocation blocked by policy",
					"tool":    invokeReq.Tool,
					"reason":  result.Reason,
					"blocked": true,
				})

			case interceptor.ActionPending:
				log.Printf("[OPENCLAW:PENDING] Tool %s requires approval: %s", invokeReq.Tool, command)

				pc := p.approvalQ.Add(command, invokeReq.Tool, result.Reason, invokeReq.Input)
				if err := p.notifier.NotifyPending(pc); err != nil {
					log.Printf("[WARN] Failed to send notification: %v", err)
				}

				decision := p.approvalQ.Wait(c.Context(), pc.ID)

				switch decision {
				case approval.DecisionApproved:
					log.Printf("[OPENCLAW:APPROVED] Tool %s approved: %s", invokeReq.Tool, command)
					// Continue to forward the request
				case approval.DecisionDenied:
					log.Printf("[OPENCLAW:DENIED] Tool %s denied: %s", invokeReq.Tool, command)
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":   "tool invocation denied",
						"tool":    invokeReq.Tool,
						"reason":  "request was denied by operator",
						"blocked": true,
					})
				default:
					log.Printf("[OPENCLAW:EXPIRED] Tool %s approval timed out: %s", invokeReq.Tool, command)
					return c.Status(fiber.StatusGatewayTimeout).JSON(fiber.Map{
						"error":   "approval timed out",
						"tool":    invokeReq.Tool,
						"reason":  "request was not approved in time",
						"blocked": true,
					})
				}
			}
		}
	}

	// Forward the request to upstream
	return p.handleStandardRequest(c, body)
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
		log.Printf("[BLOCKED] Command blocked: %s (reason: %s)", tc.Command, result.Reason)
		return true, nil

	case interceptor.ActionPending:
		log.Printf("[PENDING] Command requires approval: %s", tc.Command)

		pc := p.approvalQ.Add(tc.Command, tc.Name, result.Reason, tc.Args)
		if err := p.notifier.NotifyPending(pc); err != nil {
			log.Printf("[WARN] Failed to send notification: %v", err)
		}

		decision := p.approvalQ.Wait(ctx, pc.ID)

		switch decision {
		case approval.DecisionApproved:
			log.Printf("[APPROVED] Command approved: %s", tc.Command)
			return false, nil
		case approval.DecisionDenied:
			log.Printf("[DENIED] Command denied: %s", tc.Command)
			return true, nil
		default:
			log.Printf("[EXPIRED] Approval timed out: %s", tc.Command)
			return true, fmt.Errorf("approval timed out")
		}

	default:
		return false, nil
	}
}

// Helper functions

func isWebSocketUpgrade(c fiber.Ctx) bool {
	upgrade := strings.ToLower(c.Get("Upgrade"))
	connection := strings.ToLower(c.Get("Connection"))
	return upgrade == "websocket" && strings.Contains(connection, "upgrade")
}

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

func extractHost(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	// Add default port if not present
	if !strings.Contains(url, ":") {
		url += ":80"
	}
	return url
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
