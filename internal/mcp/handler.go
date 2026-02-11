package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/client"
	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/approval"
	"github.com/parachute-security/parachute/internal/audit"
	"github.com/parachute-security/parachute/internal/metrics"
)

// Handler processes MCP JSON-RPC requests, applying policy and HITL
type Handler struct {
	policy    *PolicyEngine
	approvalQ *approval.Queue
	notifier  *approval.Notifier
}

// NewHandler creates a new MCP request handler
func NewHandler(policy *PolicyEngine, approvalQ *approval.Queue, notifier *approval.Notifier) *Handler {
	return &Handler{
		policy:    policy,
		approvalQ: approvalQ,
		notifier:  notifier,
	}
}

// HandleJSONRPC processes a single JSON-RPC request
func (h *Handler) HandleJSONRPC(c fiber.Ctx) error {
	body := c.Body()
	if len(body) == 0 {
		return c.Status(400).JSON(NewErrorResponse(nil, ErrCodeParseError, "empty request body", nil))
	}

	req, err := ParseMessage(body)
	if err != nil {
		return c.Status(400).JSON(NewErrorResponse(nil, ErrCodeParseError, err.Error(), nil))
	}

	m := metrics.Get()

	// Non-sensitive methods pass through
	if !IsSensitiveMethod(req.Method) {
		return c.Next()
	}

	correlationID := c.Get("X-Correlation-ID")
	serverName := c.Get("X-MCP-Server", "default")

	switch req.Method {
	case MethodToolsCall:
		return h.handleToolsCall(c, req, correlationID, serverName, m)
	case MethodResourcesRead:
		return h.handleResourcesRead(c, req, correlationID, serverName, m)
	default:
		return c.Next()
	}
}

func (h *Handler) handleToolsCall(c fiber.Ctx, req *JSONRPCRequest, correlationID, serverName string, m *metrics.Metrics) error {
	tc, err := ParseToolCall(req)
	if err != nil {
		return c.Status(400).JSON(NewErrorResponse(req.ID, ErrCodeInvalidParams, err.Error(), nil))
	}

	m.MCPToolCallsTotal.Add(1)

	result := h.policy.CheckToolCall(tc, serverName)

	switch result.Action {
	case ActionBlock:
		m.MCPToolCallsBlocked.Add(1)
		audit.DefaultLogger.Log(&audit.Event{
			EventType:     audit.EventMCPToolBlock,
			CorrelationID: correlationID,
			ToolName:      tc.Name,
			Command:       result.Command,
			Reason:        result.Reason,
			Details:       map[string]string{"mcp_server": serverName},
		})
		return c.Status(403).JSON(NewErrorResponse(req.ID, ErrCodeServerError, result.Reason, map[string]string{
			"tool":   tc.Name,
			"action": "blocked",
		}))

	case ActionPending:
		return h.handleApproval(c, req, tc, result, correlationID, serverName, m)

	default:
		m.MCPToolCallsAllowed.Add(1)
		audit.DefaultLogger.Log(&audit.Event{
			EventType:     audit.EventMCPToolCall,
			CorrelationID: correlationID,
			ToolName:      tc.Name,
			Details:       map[string]string{"mcp_server": serverName},
		})
		return c.Next()
	}
}

func (h *Handler) handleApproval(c fiber.Ctx, req *JSONRPCRequest, tc *ToolCallParams, result *PolicyResult, correlationID, serverName string, m *metrics.Metrics) error {
	cmdStr := result.Command
	if cmdStr == "" {
		cmdStr = tc.Name
	}

	pc := h.approvalQ.Add(cmdStr, tc.Name, result.Reason, tc.Arguments)

	audit.DefaultLogger.Log(&audit.Event{
		EventType:     audit.EventMCPToolPending,
		CorrelationID: correlationID,
		CommandID:     pc.ID,
		ToolName:      tc.Name,
		Command:       cmdStr,
		Reason:        result.Reason,
		Details:       map[string]string{"mcp_server": serverName},
	})

	if h.notifier != nil {
		h.notifier.NotifyPending(pc)
	}

	log.Infof("[MCP] Tool call pending approval: %s (tool=%s, id=%s)", cmdStr, tc.Name, pc.ID)

	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Minute)
	defer cancel()

	decision := h.approvalQ.Wait(ctx, pc.ID)

	switch decision {
	case approval.DecisionApproved:
		m.MCPToolCallsApproved.Add(1)
		audit.DefaultLogger.Log(&audit.Event{
			EventType:     audit.EventMCPToolApprove,
			CorrelationID: correlationID,
			CommandID:     pc.ID,
			ToolName:      tc.Name,
			Command:       cmdStr,
			Details:       map[string]string{"mcp_server": serverName},
		})
		return c.Next()

	case approval.DecisionDenied:
		m.MCPToolCallsBlocked.Add(1)
		audit.DefaultLogger.Log(&audit.Event{
			EventType:     audit.EventMCPToolDeny,
			CorrelationID: correlationID,
			CommandID:     pc.ID,
			ToolName:      tc.Name,
			Command:       cmdStr,
			Details:       map[string]string{"mcp_server": serverName},
		})
		return c.Status(403).JSON(NewErrorResponse(req.ID, ErrCodeServerError, "tool call denied by approver", map[string]string{
			"tool":   tc.Name,
			"id":     pc.ID,
			"action": "denied",
		}))

	default: // Expired
		m.MCPToolCallsBlocked.Add(1)
		audit.DefaultLogger.Log(&audit.Event{
			EventType:     audit.EventMCPToolDeny,
			CorrelationID: correlationID,
			CommandID:     pc.ID,
			ToolName:      tc.Name,
			Command:       cmdStr,
			Reason:        "approval timed out",
			Details:       map[string]string{"mcp_server": serverName},
		})
		return c.Status(408).JSON(NewErrorResponse(req.ID, ErrCodeServerError,
			fmt.Sprintf("tool call blocked: approval timed out for %s", tc.Name), map[string]string{
				"tool":   tc.Name,
				"id":     pc.ID,
				"action": "timeout",
			}))
	}
}

func (h *Handler) handleResourcesRead(c fiber.Ctx, req *JSONRPCRequest, correlationID, serverName string, m *metrics.Metrics) error {
	rr, err := ParseResourceRead(req)
	if err != nil {
		return c.Status(400).JSON(NewErrorResponse(req.ID, ErrCodeInvalidParams, err.Error(), nil))
	}

	m.MCPResourceReads.Add(1)

	result := h.policy.CheckResourceRead(rr, serverName)
	if result.Action == ActionBlock {
		audit.DefaultLogger.Log(&audit.Event{
			EventType:     audit.EventMCPResourceBlock,
			CorrelationID: correlationID,
			Reason:        result.Reason,
			Details:       map[string]string{"mcp_server": serverName, "uri": rr.URI},
		})
		return c.Status(403).JSON(NewErrorResponse(req.ID, ErrCodeServerError, result.Reason, map[string]string{
			"uri":    rr.URI,
			"action": "blocked",
		}))
	}

	audit.DefaultLogger.Log(&audit.Event{
		EventType:     audit.EventMCPResourceRead,
		CorrelationID: correlationID,
		Details:       map[string]string{"mcp_server": serverName, "uri": rr.URI},
	})
	return c.Next()
}

// ForwardToServer creates a handler that forwards MCP requests to an upstream server
func ForwardToServer(upstreamURL string) fiber.Handler {
	cc := client.New()
	cc.SetTimeout(30 * time.Second)

	return func(c fiber.Ctx) error {
		resp, err := cc.Post(upstreamURL, client.Config{
			Header: map[string]string{"Content-Type": "application/json"},
			Body:   c.Body(),
		})
		if err != nil {
			return c.Status(502).JSON(NewErrorResponse(nil, ErrCodeInternal, "upstream MCP server error", nil))
		}

		// Parse response to check for PII in results
		body := resp.Body()
		var jsonResp JSONRPCResponse
		if err := json.Unmarshal(body, &jsonResp); err == nil && jsonResp.Result != nil {
			// Could add PII detection on response content here
		}

		c.Set("Content-Type", "application/json")
		return c.Status(resp.StatusCode()).Send(body)
	}
}
