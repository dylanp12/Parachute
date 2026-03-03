package mcp

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/approval"
	"github.com/parachute-security/parachute/internal/interceptor"
)

// ServerConfig defines an upstream MCP server
type ServerConfig struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// ProxyConfig holds MCP proxy configuration
type ProxyConfig struct {
	Enabled       bool                    `yaml:"enabled"`
	Listen        string                  `yaml:"listen"`
	DefaultPolicy ServerPolicy            `yaml:"default_policy"`
	Servers       map[string]ServerPolicy `yaml:"servers"`
	Upstreams     []ServerConfig          `yaml:"upstreams"`
}

// Proxy is the MCP-aware proxy that sits between MCP clients and servers
type Proxy struct {
	handler   *Handler
	upstreams map[string]string // server name → upstream URL
	sseBroker *SSEBroker
}

// NewProxy creates a new MCP proxy
func NewProxy(cfg *ProxyConfig, approvalQ *approval.Queue, notifier *approval.Notifier, cmdInterceptor *interceptor.Interceptor) *Proxy {
	policy := NewPolicyEngine(cfg.DefaultPolicy, cfg.Servers, cmdInterceptor)
	handler := NewHandler(policy, approvalQ, notifier, nil)

	upstreams := make(map[string]string)
	for _, u := range cfg.Upstreams {
		upstreams[u.Name] = u.URL
		log.Infof("[MCP] Registered upstream server: %s -> %s", u.Name, u.URL)
	}

	return &Proxy{
		handler:   handler,
		upstreams: upstreams,
		sseBroker: NewSSEBroker(100),
	}
}

// RegisterRoutes adds MCP proxy routes to a Fiber router
func (p *Proxy) RegisterRoutes(router fiber.Router) {
	// SSE stream for server-to-client notifications
	router.Get("/sse", p.sseBroker.HandleSSE)

	// POST /mcp/:server — Route to specific MCP server
	router.Post("/:server", p.proxyToServer)

	// POST /mcp — Route to default server or use X-MCP-Server header
	router.Post("/", p.proxyToDefault)

	log.Info("[MCP] MCP proxy routes registered")
}

func (p *Proxy) proxyToServer(c fiber.Ctx) error {
	serverName := c.Params("server")
	c.Request().Header.Set("X-MCP-Server", serverName)

	// Apply policy check
	if err := p.handler.HandleJSONRPC(c); err != nil {
		return err
	}

	// If HandleJSONRPC returned (via c.Next()), forward to upstream
	upstream, ok := p.upstreams[serverName]
	if !ok {
		return c.Status(404).JSON(NewErrorResponse(nil, ErrCodeServerError,
			"unknown MCP server: "+serverName, nil))
	}

	return ForwardToServer(upstream)(c)
}

func (p *Proxy) proxyToDefault(c fiber.Ctx) error {
	serverName := c.Get("X-MCP-Server", "default")

	// Apply policy check
	if err := p.handler.HandleJSONRPC(c); err != nil {
		return err
	}

	// Forward to the first upstream or the named one
	upstream, ok := p.upstreams[serverName]
	if !ok {
		// Try "default" server
		upstream, ok = p.upstreams["default"]
		if !ok && len(p.upstreams) > 0 {
			// Use first available server
			for _, u := range p.upstreams {
				upstream = u
				break
			}
		}
	}

	if upstream == "" {
		return c.Status(502).JSON(NewErrorResponse(nil, ErrCodeServerError,
			"no upstream MCP server configured", nil))
	}

	return ForwardToServer(upstream)(c)
}
