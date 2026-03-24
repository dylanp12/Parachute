package broker

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"

	"github.com/dylanp12/parachute/pkg/integrations"
)

// TelemetryCallback is invoked for every broker event.
type TelemetryCallback func(actionType, target, decision, rulePath, enforcementMode string, params map[string]any)

// Gateway is the broker gateway HTTP handler.
// It accepts agent requests, resolves credentials, and forwards authenticated
// requests to upstream APIs. Must be fully HTTP-semantic: preserves method,
// query params, body, content-type, all response headers, and status codes.
type Gateway struct {
	matcher  *IntegrationMatcher
	registry *integrations.Registry
	broker   CredentialBroker
	mode     string // "off", "record", "enforce"
	failBeh  string // "closed" or "open"
	onEvent  TelemetryCallback
	agentID  string

	// Dedicated HTTP client for upstream calls.
	// Uses direct dialing -- does NOT route through the forward proxy.
	client *http.Client
}

// GatewayConfig holds configuration for the broker gateway.
type GatewayConfig struct {
	Matcher  *IntegrationMatcher
	Registry *integrations.Registry
	Broker   CredentialBroker
	Mode     string
	FailBeh  string
	OnEvent  TelemetryCallback
	AgentID  string
}

// NewGateway creates a broker gateway handler.
func NewGateway(cfg GatewayConfig) *Gateway {
	return &Gateway{
		matcher:  cfg.Matcher,
		registry: cfg.Registry,
		broker:   cfg.Broker,
		mode:     cfg.Mode,
		failBeh:  cfg.FailBeh,
		onEvent:  cfg.OnEvent,
		agentID:  cfg.AgentID,
		client: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				// Direct dial -- bypass HTTP_PROXY/HTTPS_PROXY to prevent self-loops
				Proxy: nil,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Handler returns the Fiber handler for the broker gateway.
// Route pattern: /broker/:integration/*
func (g *Gateway) Handler() fiber.Handler {
	return func(c fiber.Ctx) error {
		integration := c.Params("integration")
		if integration == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "missing integration name in path",
			})
		}

		// Reconstruct the upstream path from the wildcard
		upstreamPath := c.Params("*")
		if upstreamPath == "" {
			upstreamPath = "/"
		} else if !strings.HasPrefix(upstreamPath, "/") {
			upstreamPath = "/" + upstreamPath
		}

		// Preserve query string
		queryString := string(c.Request().URI().QueryString())

		// Look up the integration host
		host := g.matcher.HostForIntegration(integration)
		if host == "" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "unknown integration: " + integration,
			})
		}

		// Classify the route using the provider registry
		method := c.Method()
		provider := g.matcher.ProviderForIntegration(integration)
		routeClass := g.registry.ClassifyForProvider(provider, method, upstreamPath)

		// Resolve credential
		brokerReq := &BrokerRequest{
			Integration: integration,
			RouteClass:  routeClass,
			AgentID:     g.agentID,
			Method:      method,
			Path:        upstreamPath,
		}

		result, err := g.broker.Resolve(c.Context(), brokerReq)
		if err != nil {
			log.Errorf("[BROKER:ERROR] Credential resolution failed for %s: %v", integration, err)
			g.emitEvent(upstreamPath, integration, routeClass, string(DecisionUnavailable),
				"broker/"+integration+"/error", "")
			if g.failBeh == "closed" && g.mode == "enforce" {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":  "credential broker error (fail-closed)",
					"detail": err.Error(),
				})
			}
			// fail-open or record mode: attempt without credential
			return g.forwardRequest(c, host, upstreamPath, queryString, nil)
		}

		switch result.Decision {
		case DecisionCredentialInjected:
			g.emitEvent(upstreamPath, integration, routeClass, string(DecisionCredentialInjected),
				"broker/"+integration+"/injected", result.Credential.HeaderName)
			return g.forwardRequest(c, host, upstreamPath, queryString, result.Credential)

		case DecisionDeny:
			g.emitEvent(upstreamPath, integration, routeClass, string(DecisionDeny),
				"broker/"+integration+"/deny", "")
			if g.mode == "enforce" {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":  "broker denied request",
					"reason": result.Reason,
				})
			}
			// record mode: log and forward without credential
			return g.forwardRequest(c, host, upstreamPath, queryString, nil)

		case DecisionUnavailable:
			g.emitEvent(upstreamPath, integration, routeClass, string(DecisionUnavailable),
				"broker/"+integration+"/unavailable", "")
			if g.failBeh == "closed" && g.mode == "enforce" {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":  "no credential available for managed integration",
					"reason": result.Reason,
				})
			}
			// fail-open or record mode: forward without credential
			return g.forwardRequest(c, host, upstreamPath, queryString, nil)

		default: // DecisionAllow (noop/passthrough)
			g.emitEvent(upstreamPath, integration, routeClass, string(DecisionAllow),
				"broker/"+integration+"/passthrough", "")
			return g.forwardRequest(c, host, upstreamPath, queryString, nil)
		}
	}
}

// forwardRequest builds and sends the upstream HTTP request, copying the full
// HTTP semantics: method, headers, body, query params, response headers, status.
func (g *Gateway) forwardRequest(c fiber.Ctx, host, path, queryString string, cred *Credential) error {
	// Build upstream URL.
	// Use http:// for hosts with an explicit non-443 port (e.g., local mock servers),
	// and https:// for everything else (standard API hosts).
	scheme := "https"
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		port := host[idx+1:]
		if port != "443" {
			scheme = "http"
		}
	}
	targetURL := scheme + "://" + host + path
	if queryString != "" {
		targetURL += "?" + queryString
	}

	// Read request body
	body := c.Body()
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = strings.NewReader(string(body))
	}

	upstreamReq, err := http.NewRequestWithContext(
		context.Background(),
		c.Method(),
		targetURL,
		bodyReader,
	)
	if err != nil {
		log.Errorf("[BROKER:ERROR] Failed to create upstream request: %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "failed to create upstream request",
		})
	}

	// Copy headers from agent request (skip hop-by-hop)
	hopByHop := map[string]bool{
		"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
		"Proxy-Authorization": true, "Te": true, "Trailers": true,
		"Transfer-Encoding": true, "Upgrade": true, "Proxy-Connection": true,
	}
	c.Request().Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if !hopByHop[keyStr] && keyStr != "Host" {
			upstreamReq.Header.Set(keyStr, string(value))
		}
	})

	// Strip agent auth and inject broker credential
	if cred != nil {
		StripAndInject(upstreamReq, cred)
	} else {
		// Even without a credential to inject, strip agent-supplied auth
		// for managed integrations to prevent credential leakage
		StripAuth(upstreamReq)
	}

	// Execute upstream request
	resp, err := g.client.Do(upstreamReq)
	if err != nil {
		log.Errorf("[BROKER:ERROR] Upstream request failed: %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "upstream request failed",
		})
	}
	defer resp.Body.Close()

	// Copy response headers (preserve all, including Link pagination, ETags, etc.)
	for key, values := range resp.Header {
		if !hopByHop[key] {
			for _, value := range values {
				c.Set(key, value)
			}
		}
	}

	// Read and return response body with original status code
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "failed to read upstream response",
		})
	}

	return c.Status(resp.StatusCode).Send(respBody)
}

func (g *Gateway) emitEvent(target, integration, routeClass, decision, rulePath, credSource string) {
	if g.onEvent == nil {
		return
	}
	params := map[string]any{
		"integration":       integration,
		"route_class":       routeClass,
		"credential_source": credSource,
	}
	g.onEvent("broker_request", target, decision, rulePath, g.mode, params)
}
