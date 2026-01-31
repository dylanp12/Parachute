package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	return &Proxy{
		upstream:    cfg.Upstream,
		client:      &http.Client{Timeout: 60 * time.Second},
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

		// Build upstream request
		upstreamURL := p.upstream + c.OriginalURL()
		req, err := http.NewRequestWithContext(c.Context(), c.Method(), upstreamURL, bytes.NewReader(body))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create upstream request"})
		}

		c.Request().Header.VisitAll(func(key, value []byte) {
			req.Header.Set(string(key), string(value))
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
			for _, value := range values {
				c.Set(key, value)
			}
		}

		return c.Status(resp.StatusCode).Send(respBody)
	}
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
