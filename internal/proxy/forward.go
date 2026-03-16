package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/dylanp12/parachute/internal/broker"
	"github.com/dylanp12/parachute/internal/config"
	"github.com/dylanp12/parachute/internal/egress"
)

// ForwardProxy handles outbound requests from the agent container
// acting as an HTTP/HTTPS forward proxy with domain filtering.
//
// SECURITY NOTE: PII Detection Limitations
// - HTTP requests: Full content inspection (PII patterns checked)
// - HTTPS CONNECT: Only domain filtering, NO content inspection
//
//	HTTPS tunnels are end-to-end encrypted; we cannot inspect the payload
//	without TLS interception (MITM), which is not implemented.
//	See docs/pii-detection.md for details.
type ForwardProxy struct {
	egress  *egress.Filter
	cfg     *config.Config
	matcher *broker.IntegrationMatcher // nil when broker is disabled
	dialer  *net.Dialer
	timeout time.Duration
	onEvent func(actionType, target, decision, rulePath, enforcementMode string)
}

// NewForwardProxy creates a new forward proxy instance.
// matcher may be nil when the broker is disabled.
func NewForwardProxy(cfg *config.Config, matcher *broker.IntegrationMatcher, onEvent func(string, string, string, string, string)) *ForwardProxy {
	return &ForwardProxy{
		egress:  egress.New(&cfg.Egress),
		cfg:     cfg,
		matcher: matcher,
		dialer:  &net.Dialer{Timeout: 30 * time.Second},
		timeout: 60 * time.Second,
		onEvent: onEvent,
	}
}

// emitEvent calls the telemetry callback if set.
func (fp *ForwardProxy) emitEvent(actionType, target, decision, rulePath string) {
	if fp.onEvent != nil {
		fp.onEvent(actionType, target, decision, rulePath, fp.cfg.Egress.Mode)
	}
}

// isRecordMode returns true when egress is in record-only mode.
func (fp *ForwardProxy) isRecordMode() bool {
	return fp.cfg.Egress.Mode == "record"
}

// checkManagedHost checks if a hostname belongs to a managed integration.
// Returns the integration name if blocked, empty string if allowed.
// In "enforce" mode, this blocks the request. In "record" mode, it logs but allows.
func (fp *ForwardProxy) checkManagedHost(hostname string) (integration string, blocked bool) {
	if fp.matcher == nil || fp.cfg.Broker.Mode != "enforce" && fp.cfg.Broker.Mode != "record" {
		return "", false
	}

	match := fp.matcher.Match(hostname)
	if match == nil {
		return "", false
	}

	fp.emitEvent("broker_egress_block", hostname, "deny", "broker/"+match.Integration+"/direct_access_blocked")
	log.Warnf("[BROKER:BLOCKED] Direct access to managed integration %q (%s) denied", match.Integration, hostname)

	if fp.cfg.Broker.Mode == "record" {
		return match.Integration, false
	}
	return match.Integration, true
}

// managedHostGuidance returns a human-readable message guiding the agent to use the broker gateway.
func (fp *ForwardProxy) managedHostGuidance(integration string) string {
	listen := fp.cfg.Broker.Listen
	return fmt.Sprintf(
		"Direct access to managed integration %q is blocked.\n"+
			"Configure your agent to use: http://parachute%s/broker/%s/\n"+
			"Example: Set GITHUB_API_URL=http://parachute%s/broker/%s in agent container.\n",
		integration, listen, integration, listen, integration,
	)
}

// Handler returns the Fiber handler for forward proxying
// This handles regular HTTP requests (non-CONNECT)
func (fp *ForwardProxy) Handler() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract target URL from the request
		targetURL := string(c.Request().URI().FullURI())

		// Check if host belongs to a managed integration (broker enforcement)
		fiberHost := string(c.Request().URI().Host())
		if idx := strings.LastIndex(fiberHost, ":"); idx != -1 {
			fiberHost = fiberHost[:idx]
		}
		if integration, blocked := fp.checkManagedHost(fiberHost); blocked {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "direct access to managed integration blocked",
				"message": fp.managedHostGuidance(integration),
			})
		}

		// Check if domain is allowed
		result := fp.egress.CheckURL(targetURL)
		if !result.Allowed {
			log.Warnf("[EGRESS:BLOCKED] Domain not allowed: %s (reason: %s)", targetURL, result.Reason)
			fp.emitEvent("egress", targetURL, "deny", result.RulePath)

			// In record mode, log but don't enforce — let the request through
			if !fp.isRecordMode() {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":  "egress blocked",
					"reason": result.Reason,
					"url":    targetURL,
				})
			}
		} else {
			fp.emitEvent("egress", targetURL, "allow", result.RulePath)
		}

		// Check for PII in request body
		body := c.Body()
		if len(body) > 0 {
			piiResult := fp.egress.CheckContent(string(body))
			if !piiResult.Allowed {
				log.Warnf("[EGRESS:BLOCKED] PII detected in outbound request: %s", piiResult.Pattern)
				fp.emitEvent("egress", targetURL, "deny", "egress/pii")

				if !fp.isRecordMode() {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":   "egress blocked",
						"reason":  piiResult.Reason,
						"pattern": piiResult.Pattern,
					})
				}
			}
		}

		log.Infof("[EGRESS:ALLOWED] %s %s", c.Method(), targetURL)

		// Create upstream request
		req, err := http.NewRequestWithContext(c.Context(), c.Method(), targetURL, strings.NewReader(string(body)))
		if err != nil {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to create request"})
		}

		// Copy headers (skip hop-by-hop headers)
		hopByHop := map[string]bool{
			"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
			"Proxy-Authorization": true, "Te": true, "Trailers": true,
			"Transfer-Encoding": true, "Upgrade": true,
		}
		c.Request().Header.VisitAll(func(key, value []byte) {
			keyStr := string(key)
			if !hopByHop[keyStr] && keyStr != "Host" {
				req.Header.Set(keyStr, string(value))
			}
		})

		// Execute request
		client := &http.Client{Timeout: fp.timeout}
		resp, err := client.Do(req)
		if err != nil {
			log.Errorf("[EGRESS:ERROR] Request failed: %v", err)
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "upstream request failed"})
		}
		defer resp.Body.Close()

		// Copy response headers (skip hop-by-hop)
		for key, values := range resp.Header {
			if !hopByHop[key] {
				for _, value := range values {
					c.Set(key, value)
				}
			}
		}

		// Read and return response body
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to read response"})
		}

		return c.Status(resp.StatusCode).Send(respBody)
	}
}

// HandleConnect handles HTTPS CONNECT tunneling requests.
// This must be called from a raw TCP handler, not Fiber.
//
// IMPORTANT: This creates an opaque tunnel - we can only filter by domain,
// not by content. The TLS handshake and all subsequent traffic between client
// and target is encrypted end-to-end. PII detection is NOT possible here
// without implementing TLS interception (MITM proxy), which would require:
// 1. Generating certificates on-the-fly for each domain
// 2. Installing a CA certificate in the agent container
// 3. Handling certificate pinning failures
func (fp *ForwardProxy) HandleConnect(clientConn net.Conn, host string) {
	defer clientConn.Close()

	// Extract hostname for domain check
	hostname := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		hostname = host[:idx]
	}

	// Check if host belongs to a managed integration (broker enforcement)
	if integration, blocked := fp.checkManagedHost(hostname); blocked {
		guidance := fp.managedHostGuidance(integration)
		clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n" + guidance))
		return
	}

	// Check if domain is allowed
	result := fp.egress.CheckURL("https://" + hostname)
	if !result.Allowed {
		log.Warnf("[EGRESS:BLOCKED] CONNECT to %s denied (reason: %s)", host, result.Reason)
		fp.emitEvent("egress", hostname, "deny", result.RulePath)

		// In record mode, log but don't enforce — let the tunnel through
		if !fp.isRecordMode() {
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nDomain not allowed\n"))
			return
		}
	} else {
		fp.emitEvent("egress", hostname, "allow", result.RulePath)
	}

	log.Infof("[EGRESS:ALLOWED] CONNECT tunnel to %s", host)

	// Connect to target
	targetConn, err := fp.dialer.Dial("tcp", host)
	if err != nil {
		log.Errorf("[EGRESS:ERROR] Failed to connect to %s: %v", host, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\nConnection failed\n"))
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()

	// Wait for either direction to finish
	<-done
}

// ProxyServer runs a standalone HTTP proxy server for agent egress
type ProxyServer struct {
	fp       *ForwardProxy
	listener net.Listener
}

// NewProxyServer creates a new proxy server.
// matcher may be nil when the broker is disabled.
func NewProxyServer(cfg *config.Config, matcher *broker.IntegrationMatcher, onEvent func(string, string, string, string, string)) *ProxyServer {
	return &ProxyServer{
		fp: NewForwardProxy(cfg, matcher, onEvent),
	}
}

// ListenAndServe starts the proxy server on the given address
func (ps *ProxyServer) ListenAndServe(addr string) error {
	var err error
	ps.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Infof("[PROXY] Forward proxy listening on %s", addr)

	for {
		conn, err := ps.listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			log.Errorf("[PROXY:ERROR] Accept failed: %v", err)
			continue
		}
		go ps.handleConnection(conn)
	}
}

// Close stops the proxy server
func (ps *ProxyServer) Close() error {
	if ps.listener != nil {
		return ps.listener.Close()
	}
	return nil
}

func (ps *ProxyServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Errorf("[PROXY:ERROR] Failed to read request: %v", err)
		return
	}

	// Clear deadline for the rest of the connection
	conn.SetReadDeadline(time.Time{})

	if req.Method == "CONNECT" {
		ps.fp.HandleConnect(conn, req.Host)
		return
	}

	// Handle regular HTTP requests
	ps.handleHTTPRequest(conn, req)
}

func (ps *ProxyServer) handleHTTPRequest(conn net.Conn, req *http.Request) {
	targetURL := req.URL.String()
	if !req.URL.IsAbs() {
		targetURL = "http://" + req.Host + req.URL.RequestURI()
	}

	// Check if host belongs to a managed integration (broker enforcement)
	httpHost := req.Host
	if idx := strings.LastIndex(httpHost, ":"); idx != -1 {
		httpHost = httpHost[:idx]
	}
	if integration, blocked := ps.fp.checkManagedHost(httpHost); blocked {
		guidance := ps.fp.managedHostGuidance(integration)
		resp := &http.Response{
			StatusCode: 403,
			Status:     "403 Forbidden",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(guidance)),
		}
		resp.Header.Set("Content-Type", "text/plain")
		resp.Write(conn)
		return
	}

	// Check if domain is allowed
	result := ps.fp.egress.CheckURL(targetURL)
	if !result.Allowed {
		log.Warnf("[EGRESS:BLOCKED] HTTP to %s denied (reason: %s)", targetURL, result.Reason)
		ps.fp.emitEvent("egress", targetURL, "deny", result.RulePath)

		// In record mode, log but don't enforce — let the request through
		if !ps.fp.isRecordMode() {
			resp := &http.Response{
				StatusCode: 403,
				Status:     "403 Forbidden",
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("Domain not allowed\n")),
			}
			resp.Header.Set("Content-Type", "text/plain")
			resp.Write(conn)
			return
		}
	} else {
		ps.fp.emitEvent("egress", targetURL, "allow", result.RulePath)
	}

	// Check for PII in request body
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil && len(bodyBytes) > 0 {
			piiResult := ps.fp.egress.CheckContent(string(bodyBytes))
			if !piiResult.Allowed {
				log.Warnf("[EGRESS:BLOCKED] PII in outbound request: %s", piiResult.Pattern)
				ps.fp.emitEvent("egress", targetURL, "deny", "egress/pii")

				if !ps.fp.isRecordMode() {
					resp := &http.Response{
						StatusCode: 403,
						Status:     "403 Forbidden",
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("PII detected in request\n")),
					}
					resp.Write(conn)
					return
				}
			}
			req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}
	}

	log.Infof("[EGRESS:ALLOWED] %s %s", req.Method, targetURL)

	// Forward request
	client := &http.Client{Timeout: ps.fp.timeout}
	proxyReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		log.Errorf("[EGRESS:ERROR] Failed to create request: %v", err)
		return
	}

	// Copy headers (skip hop-by-hop)
	hopByHop := map[string]bool{
		"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
		"Proxy-Authorization": true, "Te": true, "Trailers": true,
		"Transfer-Encoding": true, "Upgrade": true, "Proxy-Connection": true,
	}
	for key, values := range req.Header {
		if !hopByHop[key] {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Errorf("[EGRESS:ERROR] Request failed: %v", err)
		errResp := &http.Response{
			StatusCode: 502,
			Status:     "502 Bad Gateway",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("Upstream request failed\n")),
		}
		errResp.Write(conn)
		return
	}
	defer resp.Body.Close()

	// Write response back to client
	resp.Write(conn)
}
