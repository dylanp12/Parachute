package middleware

import (
	"encoding/base64"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/parachute-security/parachute/internal/config"
)

// Auth creates an authentication middleware
func Auth(cfg *config.AuthConfig) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Check IP whitelist first (if configured)
		if len(cfg.AllowedIPs) > 0 {
			clientIP := c.IP()
			allowed := false
			for _, ip := range cfg.AllowedIPs {
				if ip == clientIP || ip == "*" {
					allowed = true
					break
				}
			}
			if !allowed {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "IP not allowed",
				})
			}
		}

		// Check for Bearer token
		authHeader := c.Get("Authorization")
		if cfg.Token != "" && authHeader != "" {
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if token == cfg.Token {
					return c.Next()
				}
			}
		}

		// Check for Basic Auth
		if cfg.Username != "" {
			if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
				encoded := strings.TrimPrefix(authHeader, "Basic ")
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err == nil {
					parts := strings.SplitN(string(decoded), ":", 2)
					if len(parts) == 2 {
						if parts[0] == cfg.Username && parts[1] == cfg.Password() {
							return c.Next()
						}
					}
				}
			}

			c.Set("WWW-Authenticate", `Basic realm="Parachute"`)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		return c.Next()
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
