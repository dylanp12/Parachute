package ssh

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/approval"
	"github.com/parachute-security/parachute/internal/audit"
	"github.com/parachute-security/parachute/internal/interceptor"
)

// Handler provides HTTP API endpoints for SSH execution chaining
type Handler struct {
	manager   *Manager
	executor  *Executor
	approvalQ *approval.Queue
	notifier  *approval.Notifier
}

// NewHandler creates a new SSH API handler
func NewHandler(manager *Manager, executor *Executor, approvalQ *approval.Queue, notifier *approval.Notifier) *Handler {
	return &Handler{
		manager:   manager,
		executor:  executor,
		approvalQ: approvalQ,
		notifier:  notifier,
	}
}

// RegisterRoutes registers all SSH API routes on the given router group
func (h *Handler) RegisterRoutes(router fiber.Router) {
	// Target management
	router.Get("/targets", h.listTargets)
	router.Post("/targets", h.addTarget)
	router.Get("/targets/:name", h.getTarget)
	router.Delete("/targets/:name", h.removeTarget)

	// Connection management
	router.Get("/connections", h.listConnections)
	router.Post("/connect/:name", h.connect)
	router.Post("/disconnect/:name", h.disconnect)
	router.Post("/test/:name", h.testConnection)

	// Command execution
	router.Post("/execute", h.execute)

	// Chain resolution
	router.Get("/chain/:name", h.resolveChain)
}

func (h *Handler) listTargets(c fiber.Ctx) error {
	targets := h.manager.ListTargets()
	return c.JSON(fiber.Map{
		"targets": targets,
		"count":   len(targets),
	})
}

func (h *Handler) addTarget(c fiber.Ctx) error {
	var target Target
	if err := c.Bind().JSON(&target); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid target configuration",
		})
	}

	if err := h.manager.AddTarget(&target); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	log.Infof("[SSH] Target added: %s (%s@%s)", target.Name, target.User, target.Addr())

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"success": true,
		"target":  target.Name,
		"message": fmt.Sprintf("target %q added successfully", target.Name),
	})
}

func (h *Handler) getTarget(c fiber.Ctx) error {
	name := c.Params("name")
	target, ok := h.manager.GetTarget(name)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("target %q not found", name),
		})
	}

	// Get connection info
	info := &ConnectionInfo{Target: target}
	h.manager.mu.RLock()
	if pc, exists := h.manager.connections[name]; exists {
		info.Connected = true
		info.ConnectedAt = pc.connectedAt
		info.LastUsedAt = pc.lastUsedAt
		info.SessionCount = pc.sessionCount
	}
	h.manager.mu.RUnlock()

	return c.JSON(info)
}

func (h *Handler) removeTarget(c fiber.Ctx) error {
	name := c.Params("name")
	if err := h.manager.RemoveTarget(name); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	log.Infof("[SSH] Target removed: %s", name)

	return c.JSON(fiber.Map{
		"success": true,
		"message": fmt.Sprintf("target %q removed", name),
	})
}

func (h *Handler) listConnections(c fiber.Ctx) error {
	connections := h.manager.ListConnections()
	return c.JSON(fiber.Map{
		"connections": connections,
		"count":       len(connections),
	})
}

func (h *Handler) connect(c fiber.Ctx) error {
	name := c.Params("name")

	target, ok := h.manager.GetTarget(name)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("target %q not found", name),
		})
	}

	if !target.Enabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": fmt.Sprintf("target %q is disabled", name),
		})
	}

	// Resolve chain for display
	chain, err := h.manager.ResolveChain(name)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	chainNames := make([]string, len(chain))
	for i, t := range chain {
		chainNames[i] = t.Name
	}

	_, err = h.manager.GetConnection(name)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error":  fmt.Sprintf("failed to connect: %v", err),
			"target": name,
			"chain":  chainNames,
		})
	}

	audit.Log(&audit.Event{
		EventType: EventSSHConnect,
		ToolName:  "ssh_connect",
		Details: map[string]string{
			"target": name,
			"chain":  fmt.Sprintf("%v", chainNames),
		},
	})

	return c.JSON(fiber.Map{
		"success": true,
		"target":  name,
		"chain":   chainNames,
		"message": fmt.Sprintf("connected to %q via %v", name, chainNames),
	})
}

func (h *Handler) disconnect(c fiber.Ctx) error {
	name := c.Params("name")
	if err := h.manager.Disconnect(name); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": fmt.Sprintf("disconnected from %q", name),
	})
}

func (h *Handler) testConnection(c fiber.Ctx) error {
	name := c.Params("name")

	if _, ok := h.manager.GetTarget(name); !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("target %q not found", name),
		})
	}

	if err := h.manager.TestConnection(name); err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"success": false,
			"target":  name,
			"error":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"target":  name,
		"message": "connection test passed",
	})
}

func (h *Handler) execute(c fiber.Ctx) error {
	var req ExecutionRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid execution request",
		})
	}

	if req.TargetName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "target is required",
		})
	}
	if req.Command == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "command is required",
		})
	}

	correlationID := c.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = audit.GenerateCorrelationID()
	}
	req.CorrelationID = correlationID

	// Check command against risk policy and execute
	checkResult, execResult := h.executor.CheckAndExecute(c.Context(), &req)

	switch checkResult.Action {
	case interceptor.ActionBlock:
		log.Warnf("[SSH] [%s] Command blocked on target %q: %s (reason: %s)",
			correlationID, req.TargetName, truncateCmd(req.Command), checkResult.Reason)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":          "command blocked by policy",
			"reason":         checkResult.Reason,
			"command":        checkResult.Command,
			"target":         req.TargetName,
			"correlation_id": correlationID,
		})

	case interceptor.ActionPending:
		log.Infof("[SSH] [%s] Command requires approval on target %q: %s",
			correlationID, req.TargetName, truncateCmd(req.Command))

		// Add to approval queue
		pc := h.approvalQ.Add(req.Command, "ssh_execute", checkResult.Reason, map[string]any{
			"target":      req.TargetName,
			"working_dir": req.WorkingDir,
			"env":         req.Env,
		})

		audit.Log(&audit.Event{
			EventType:     EventSSHPending,
			CorrelationID: correlationID,
			Command:       req.Command,
			CommandID:     pc.ID,
			ToolName:      "ssh_execute",
			Reason:        checkResult.Reason,
			Details: map[string]string{
				"target": req.TargetName,
			},
		})

		if err := h.notifier.NotifyPending(pc); err != nil {
			log.Warnf("[SSH] [%s] Failed to send notification: %v", correlationID, err)
		}

		// Wait for approval
		decision := h.approvalQ.Wait(c.Context(), pc.ID)

		switch decision {
		case approval.DecisionApproved:
			log.Infof("[SSH] [%s] Command approved on target %q: %s",
				correlationID, req.TargetName, truncateCmd(req.Command))

			audit.Log(&audit.Event{
				EventType:     EventSSHApprove,
				CorrelationID: correlationID,
				Command:       req.Command,
				CommandID:     pc.ID,
				ToolName:      "ssh_execute",
				Details: map[string]string{
					"target": req.TargetName,
				},
			})

			// Execute the command now that it's approved
			execResult = h.executor.Execute(c.Context(), &req)

		case approval.DecisionDenied:
			log.Warnf("[SSH] [%s] Command denied on target %q: %s",
				correlationID, req.TargetName, truncateCmd(req.Command))

			audit.Log(&audit.Event{
				EventType:     EventSSHDeny,
				CorrelationID: correlationID,
				Command:       req.Command,
				CommandID:     pc.ID,
				ToolName:      "ssh_execute",
				Details: map[string]string{
					"target": req.TargetName,
				},
			})

			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":          "command denied by operator",
				"target":         req.TargetName,
				"correlation_id": correlationID,
			})

		default:
			log.Warnf("[SSH] [%s] Command approval timed out on target %q: %s",
				correlationID, req.TargetName, truncateCmd(req.Command))
			return c.Status(fiber.StatusGatewayTimeout).JSON(fiber.Map{
				"error":          "approval timed out",
				"target":         req.TargetName,
				"correlation_id": correlationID,
			})
		}
	}

	// Return execution result
	status := fiber.StatusOK
	if execResult.ExitCode != 0 {
		status = fiber.StatusOK // Still 200 - non-zero exit is not an HTTP error
	}
	if execResult.Error != "" && execResult.ExitCode == -1 {
		status = fiber.StatusBadGateway
	}

	return c.Status(status).JSON(execResult)
}

func (h *Handler) resolveChain(c fiber.Ctx) error {
	name := c.Params("name")

	chain, err := h.manager.ResolveChain(name)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	hops := make([]fiber.Map, len(chain))
	for i, t := range chain {
		hops[i] = fiber.Map{
			"name":    t.Name,
			"host":    t.Host,
			"port":    t.Port,
			"user":    t.User,
			"hop":     i + 1,
			"is_jump": i < len(chain)-1,
		}
	}

	return c.JSON(fiber.Map{
		"target":    name,
		"chain":     hops,
		"hop_count": len(chain),
	})
}

// ExecuteOnChain executes a command across multiple targets in sequence
// This is for "fan-out" execution where the same command runs on multiple targets
func (h *Handler) ExecuteOnChain(c fiber.Ctx) error {
	var req struct {
		Targets []string          `json:"targets"`
		Command string            `json:"command"`
		Timeout time.Duration     `json:"timeout,omitempty"`
		Env     map[string]string `json:"env,omitempty"`
	}

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request",
		})
	}

	if len(req.Targets) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "at least one target is required",
		})
	}

	correlationID := c.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = audit.GenerateCorrelationID()
	}

	results := make([]*ExecutionResult, 0, len(req.Targets))

	for _, targetName := range req.Targets {
		execReq := &ExecutionRequest{
			TargetName:    targetName,
			Command:       req.Command,
			Timeout:       req.Timeout,
			Env:           req.Env,
			CorrelationID: correlationID,
		}

		result := h.executor.Execute(c.Context(), execReq)
		results = append(results, result)
	}

	return c.JSON(fiber.Map{
		"results":        results,
		"count":          len(results),
		"correlation_id": correlationID,
	})
}
