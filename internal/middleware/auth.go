package middleware

import (
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/parachute-security/parachute/internal/audit"
	"github.com/parachute-security/parachute/internal/config"
)

// CorrelationID creates middleware that adds a correlation ID to each request
func CorrelationID() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Check for existing correlation ID in header
		correlationID := c.Get("X-Correlation-ID")
		if correlationID == "" {
			correlationID = audit.GenerateCorrelationID()
		}
		c.Locals("correlation_id", correlationID)
		c.Set("X-Correlation-ID", correlationID)
		return c.Next()
	}
}

// GetCorrelationID retrieves the correlation ID from the request context
func GetCorrelationID(c fiber.Ctx) string {
	if id, ok := c.Locals("correlation_id").(string); ok {
		return id
	}
	return ""
}

// Auth creates an authentication middleware with constant-time comparisons and audit logging
func Auth(cfg *config.AuthConfig) fiber.Handler {
	return func(c fiber.Ctx) error {
		correlationID := GetCorrelationID(c)
		clientIP := c.IP()

		// Check IP whitelist first (if configured)
		if len(cfg.AllowedIPs) > 0 {
			allowed := false
			for _, ip := range cfg.AllowedIPs {
				if ip == clientIP || ip == "*" {
					allowed = true
					break
				}
			}
			if !allowed {
				audit.LogIngressDeny(correlationID, clientIP, c.Method(), c.Path(), "IP not allowed")
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "IP not allowed",
				})
			}
		}

		authHeader := c.Get("Authorization")

		// Check for Bearer token (constant-time comparison)
		if cfg.Token != "" && authHeader != "" {
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if constantTimeEqual(token, cfg.Token) {
					audit.LogIngressAllow(correlationID, clientIP, c.Method(), c.Path())
					return c.Next()
				}
			}
		}

		// Check for Basic Auth (constant-time comparison)
		if cfg.Username != "" {
			if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
				encoded := strings.TrimPrefix(authHeader, "Basic ")
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err == nil {
					parts := strings.SplitN(string(decoded), ":", 2)
					if len(parts) == 2 {
						usernameMatch := constantTimeEqual(parts[0], cfg.Username)
						passwordMatch := constantTimeEqual(parts[1], cfg.Password())
						if usernameMatch && passwordMatch {
							audit.LogIngressAllow(correlationID, clientIP, c.Method(), c.Path())
							return c.Next()
						}
					}
				}
			}

			audit.LogAuthFailure(correlationID, clientIP, "invalid credentials")
			c.Set("WWW-Authenticate", `Basic realm="Parachute"`)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		// If no auth configured, still allow access (for backwards compatibility)
		return c.Next()
	}
}

// constantTimeEqual performs constant-time string comparison to prevent timing attacks
func constantTimeEqual(a, b string) bool {
	// Ensure same length comparison to prevent length-based timing
	if len(a) != len(b) {
		// Still perform comparison to ensure constant time
		subtle.ConstantTimeCompare([]byte(a), []byte(a))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*rateLimitEntry
	rate    int           // requests per window
	window  time.Duration // time window
	cleanup time.Duration // cleanup interval
}

type rateLimitEntry struct {
	count       int
	windowStart time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*rateLimitEntry),
		rate:    rate,
		window:  window,
		cleanup: 5 * time.Minute,
	}
	go rl.cleanupLoop()
	return rl
}

// Handler returns a Fiber middleware for rate limiting with audit logging
func (rl *RateLimiter) Handler() fiber.Handler {
	return func(c fiber.Ctx) error {
		clientIP := c.IP()
		correlationID := GetCorrelationID(c)

		rl.mu.Lock()
		entry, exists := rl.clients[clientIP]
		now := time.Now()

		if !exists {
			rl.clients[clientIP] = &rateLimitEntry{
				count:       1,
				windowStart: now,
			}
			rl.mu.Unlock()
			return c.Next()
		}

		// Reset window if expired
		if now.Sub(entry.windowStart) > rl.window {
			entry.count = 1
			entry.windowStart = now
			rl.mu.Unlock()
			return c.Next()
		}

		// Check rate limit
		if entry.count >= rl.rate {
			rl.mu.Unlock()
			audit.LogRateLimited(correlationID, clientIP)
			c.Set("Retry-After", "60")
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "rate limit exceeded",
			})
		}

		entry.count++
		rl.mu.Unlock()
		return c.Next()
	}
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, entry := range rl.clients {
			if now.Sub(entry.windowStart) > rl.window*2 {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// RequireAuth creates middleware that enforces authentication
// Unlike Auth(), this returns 401 if no auth method is configured
func RequireAuth(cfg *config.AuthConfig) fiber.Handler {
	return func(c fiber.Ctx) error {
		// If no auth methods configured, reject all requests
		if cfg.Username == "" && cfg.Token == "" {
			correlationID := GetCorrelationID(c)
			audit.LogAuthFailure(correlationID, c.IP(), "no auth configured")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication not configured",
			})
		}

		// Delegate to standard Auth middleware
		return Auth(cfg)(c)
	}
}

// RequestLogger logs all incoming requests
func RequestLogger() fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals("request_log", map[string]string{
			"method": c.Method(),
			"path":   c.Path(),
			"ip":     c.IP(),
		})
		return c.Next()
	}
}
