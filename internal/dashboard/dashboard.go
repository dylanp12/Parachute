package dashboard

import (
	"embed"

	"github.com/gofiber/fiber/v3"
	"github.com/dylanp12/parachute/internal/approval"
	"github.com/dylanp12/parachute/internal/middleware"
)

//go:embed static/*
var staticFiles embed.FS

// Handler returns a Fiber handler that serves the dashboard
func Handler() fiber.Handler {
	return func(c fiber.Ctx) error {
		content, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			return c.Status(fiber.StatusNotFound).SendString("Dashboard not found")
		}
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Send(content)
	}
}

// APIRoutes registers dashboard API routes on the given router
// csrfManager can be nil to disable CSRF protection (for API-only access with tokens)
func APIRoutes(router fiber.Router, approvalQ *approval.Queue) {
	// GET endpoints - read-only, no CSRF needed
	router.Get("/pending", func(c fiber.Ctx) error {
		pending := approvalQ.List()
		// Include CSRF token in response for convenience
		response := fiber.Map{
			"pending": pending,
			"count":   len(pending),
		}
		// Add CSRF token if available
		if token, ok := c.Locals("csrf_token").(string); ok {
			response["csrf_token"] = token
		}
		return c.JSON(response)
	})

	router.Get("/pending/:id", func(c fiber.Ctx) error {
		id := c.Params("id")
		pc, exists := approvalQ.Get(id)
		if !exists {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "pending command not found"})
		}
		return c.JSON(pc)
	})

	// POST endpoints - state-changing, require CSRF token
	router.Post("/approve/:id", func(c fiber.Ctx) error {
		id := c.Params("id")
		if approvalQ.Approve(id) {
			return c.JSON(fiber.Map{"success": true, "id": id, "action": "approved"})
		}
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "pending command not found"})
	})

	router.Post("/deny/:id", func(c fiber.Ctx) error {
		id := c.Params("id")
		if approvalQ.Deny(id) {
			return c.JSON(fiber.Map{"success": true, "id": id, "action": "denied"})
		}
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "pending command not found"})
	})
}

// APIRoutesWithCSRF registers dashboard API routes with CSRF protection
func APIRoutesWithCSRF(router fiber.Router, approvalQ *approval.Queue, csrfManager *middleware.CSRFManager) {
	// GET endpoints - read-only, no CSRF needed
	router.Get("/pending", func(c fiber.Ctx) error {
		pending := approvalQ.List()
		response := fiber.Map{
			"pending": pending,
			"count":   len(pending),
		}
		// Add CSRF token if available
		if token, ok := c.Locals("csrf_token").(string); ok {
			response["csrf_token"] = token
		}
		return c.JSON(response)
	})

	router.Get("/pending/:id", func(c fiber.Ctx) error {
		id := c.Params("id")
		pc, exists := approvalQ.Get(id)
		if !exists {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "pending command not found"})
		}
		return c.JSON(pc)
	})

	// POST endpoints - state-changing, protected by CSRF middleware
	stateChangingGroup := router.Group("")
	if csrfManager != nil {
		stateChangingGroup.Use(csrfManager.Handler())
	}

	stateChangingGroup.Post("/approve/:id", func(c fiber.Ctx) error {
		id := c.Params("id")
		if approvalQ.Approve(id) {
			return c.JSON(fiber.Map{"success": true, "id": id, "action": "approved"})
		}
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "pending command not found"})
	})

	stateChangingGroup.Post("/deny/:id", func(c fiber.Ctx) error {
		id := c.Params("id")
		if approvalQ.Deny(id) {
			return c.JSON(fiber.Map{"success": true, "id": id, "action": "denied"})
		}
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "pending command not found"})
	})
}
