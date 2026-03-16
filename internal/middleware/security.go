package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/dylanp12/parachute/internal/audit"
)

// CSRFConfig holds configuration for CSRF protection
type CSRFConfig struct {
	// TokenLength is the length of the CSRF token in bytes (default: 32)
	TokenLength int
	// CookieName is the name of the CSRF cookie (default: "_csrf")
	CookieName string
	// HeaderName is the name of the header to check for the token (default: "X-CSRF-Token")
	HeaderName string
	// FormField is the name of the form field to check for the token (default: "csrf_token")
	FormField string
	// Expiration is how long tokens are valid (default: 1 hour)
	Expiration time.Duration
	// Secure sets the Secure flag on the cookie (default: true in production)
	Secure bool
	// SameSite sets the SameSite attribute (default: Strict)
	SameSite string
}

// DefaultCSRFConfig returns the default CSRF configuration
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		TokenLength: 32,
		CookieName:  "_csrf",
		HeaderName:  "X-CSRF-Token",
		FormField:   "csrf_token",
		Expiration:  1 * time.Hour,
		Secure:      true,
		SameSite:    "Strict",
	}
}

// CSRFManager manages CSRF tokens
type CSRFManager struct {
	config CSRFConfig
	tokens sync.Map // map[token]expiresAt
}

// NewCSRFManager creates a new CSRF manager
func NewCSRFManager(config CSRFConfig) *CSRFManager {
	if config.TokenLength == 0 {
		config.TokenLength = 32
	}
	if config.CookieName == "" {
		config.CookieName = "_csrf"
	}
	if config.HeaderName == "" {
		config.HeaderName = "X-CSRF-Token"
	}
	if config.FormField == "" {
		config.FormField = "csrf_token"
	}
	if config.Expiration == 0 {
		config.Expiration = 1 * time.Hour
	}
	if config.SameSite == "" {
		config.SameSite = "Strict"
	}

	mgr := &CSRFManager{config: config}
	go mgr.cleanupLoop()
	return mgr
}

// generateToken creates a new CSRF token
func (m *CSRFManager) generateToken() (string, error) {
	bytes := make([]byte, m.config.TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(bytes)
	m.tokens.Store(token, time.Now().Add(m.config.Expiration))
	return token, nil
}

// validateToken checks if a token is valid
func (m *CSRFManager) validateToken(token string) bool {
	if token == "" {
		return false
	}
	if expiresAt, ok := m.tokens.Load(token); ok {
		if time.Now().Before(expiresAt.(time.Time)) {
			return true
		}
		m.tokens.Delete(token)
	}
	return false
}

// cleanupLoop periodically removes expired tokens
func (m *CSRFManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.tokens.Range(func(key, value interface{}) bool {
			if now.After(value.(time.Time)) {
				m.tokens.Delete(key)
			}
			return true
		})
	}
}

// Handler returns CSRF protection middleware
// It issues tokens for GET requests and validates tokens for state-changing requests
func (m *CSRFManager) Handler() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Skip CSRF for safe methods (GET, HEAD, OPTIONS)
		method := c.Method()
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			// Issue a new token and set it in cookie
			token, err := m.generateToken()
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "failed to generate CSRF token",
				})
			}

			cookie := &fiber.Cookie{
				Name:     m.config.CookieName,
				Value:    token,
				Expires:  time.Now().Add(m.config.Expiration),
				HTTPOnly: false, // JavaScript needs to read this
				Secure:   m.config.Secure,
				SameSite: m.config.SameSite,
				Path:     "/",
			}
			c.Cookie(cookie)
			c.Locals("csrf_token", token)
			return c.Next()
		}

		// For state-changing methods, validate the token
		// Check header first, then form field
		token := c.Get(m.config.HeaderName)
		if token == "" {
			token = c.FormValue(m.config.FormField)
		}

		// Also check cookie to compare
		cookieToken := c.Cookies(m.config.CookieName)

		// Both must be present and match
		if token == "" || cookieToken == "" {
			correlationID := GetCorrelationID(c)
			audit.LogIngressDeny(correlationID, c.IP(), c.Method(), c.Path(), "CSRF token missing")
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "CSRF token required",
			})
		}

		// Constant-time comparison
		if subtle.ConstantTimeCompare([]byte(token), []byte(cookieToken)) != 1 {
			correlationID := GetCorrelationID(c)
			audit.LogIngressDeny(correlationID, c.IP(), c.Method(), c.Path(), "CSRF token mismatch")
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "CSRF token invalid",
			})
		}

		// Validate token exists in our store
		if !m.validateToken(token) {
			correlationID := GetCorrelationID(c)
			audit.LogIngressDeny(correlationID, c.IP(), c.Method(), c.Path(), "CSRF token expired")
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "CSRF token expired",
			})
		}

		return c.Next()
	}
}

// StripForwardedHeaders middleware removes/overwrites X-Forwarded-* headers
// This prevents clients from spoofing their IP or protocol
func StripForwardedHeaders() fiber.Handler {
	// Headers to strip from incoming requests
	headersToStrip := []string{
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Forwarded-Port",
		"X-Forwarded-Server",
		"X-Real-IP",
		"X-Original-URL",
		"X-Rewrite-URL",
		"Forwarded",
	}

	return func(c fiber.Ctx) error {
		// Remove all forwarded headers from the incoming request
		for _, header := range headersToStrip {
			c.Request().Header.Del(header)
		}

		// Set the real client IP based on the connection
		// This ensures we use the actual connection IP, not spoofed headers
		clientIP := c.IP()
		c.Request().Header.Set("X-Real-Client-IP", clientIP)

		return c.Next()
	}
}

// TrustedProxyConfig configures trusted proxy handling
type TrustedProxyConfig struct {
	// TrustedProxies is a list of trusted proxy IPs/CIDRs
	// Only these proxies can set X-Forwarded-* headers
	TrustedProxies []string
	// TrustAllProxies allows all proxies (dangerous, use only in dev)
	TrustAllProxies bool
}

// SecureHeaders middleware adds security headers to responses
func SecureHeaders() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Prevent clickjacking
		c.Set("X-Frame-Options", "DENY")
		// Prevent MIME type sniffing
		c.Set("X-Content-Type-Options", "nosniff")
		// Enable XSS filter
		c.Set("X-XSS-Protection", "1; mode=block")
		// Referrer policy
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Permissions policy (disable dangerous features)
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		return c.Next()
	}
}

// FailClosedAuth creates middleware that requires authentication
// and fails closed if auth is not properly configured
func FailClosedAuth(username, password, token string, allowInsecure bool) fiber.Handler {
	// Check if auth is configured
	hasBasicAuth := username != "" && password != ""
	hasTokenAuth := token != ""
	authConfigured := hasBasicAuth || hasTokenAuth

	return func(c fiber.Ctx) error {
		correlationID := GetCorrelationID(c)
		clientIP := c.IP()

		// If no auth configured and insecure mode not explicitly enabled, fail closed
		if !authConfigured && !allowInsecure {
			audit.LogAuthFailure(correlationID, clientIP, "authentication not configured (fail-closed)")
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"error":   "authentication not configured",
				"message": "Parachute requires authentication. Configure auth.username/password_env or auth.token in config, or set allow_insecure: true to bypass (not recommended).",
			})
		}

		// If insecure mode is enabled and no auth configured, allow access with warning header
		if !authConfigured && allowInsecure {
			c.Set("X-Parachute-Warning", "running in insecure mode without authentication")
			return c.Next()
		}

		// Auth is configured, validate credentials
		authHeader := c.Get("Authorization")

		// Check Bearer token
		if hasTokenAuth && authHeader != "" {
			if strings.HasPrefix(authHeader, "Bearer ") {
				providedToken := strings.TrimPrefix(authHeader, "Bearer ")
				if constantTimeEqual(providedToken, token) {
					return c.Next()
				}
			}
		}

		// Check Basic Auth
		if hasBasicAuth && authHeader != "" {
			if strings.HasPrefix(authHeader, "Basic ") {
				// Delegate to existing auth logic
				// This is a simplified check; the full Auth middleware handles this
			}
		}

		// If we get here with auth configured but no valid credentials provided
		if authHeader == "" {
			c.Set("WWW-Authenticate", `Basic realm="Parachute"`)
			audit.LogAuthFailure(correlationID, clientIP, "no credentials provided")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		// Invalid credentials
		audit.LogAuthFailure(correlationID, clientIP, "invalid credentials")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid credentials",
		})
	}
}

// SecureCookieConfig returns a cookie configuration with secure defaults
func SecureCookieConfig(name, value string, expiration time.Duration, secure bool) *fiber.Cookie {
	sameSite := "Strict"
	return &fiber.Cookie{
		Name:     name,
		Value:    value,
		Expires:  time.Now().Add(expiration),
		HTTPOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		Path:     "/",
	}
}
