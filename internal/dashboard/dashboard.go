package dashboard

import (
	"embed"

	"github.com/gofiber/fiber/v3"
	"github.com/parachute-security/parachute/internal/approval"
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
func APIRoutes(router fiber.Router, approvalQ *approval.Queue) {
	router.Get("/pending", func(c fiber.Ctx) error {
		pending := approvalQ.List()
		return c.JSON(fiber.Map{"pending": pending, "count": len(pending)})
	})

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

	router.Get("/pending/:id", func(c fiber.Ctx) error {
		id := c.Params("id")
		pc, exists := approvalQ.Get(id)
		if !exists {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "pending command not found"})
		}
		return c.JSON(pc)
	})
}
