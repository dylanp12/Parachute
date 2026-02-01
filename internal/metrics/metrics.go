package metrics

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
)

// Metrics holds application metrics for Prometheus scraping
type Metrics struct {
	// Request counters
	RequestsTotal       atomic.Int64
	RequestsBlocked     atomic.Int64
	RequestsApproved    atomic.Int64
	RequestsDenied      atomic.Int64
	RequestsRateLimited atomic.Int64

	// Command interception
	CommandsAllowed  atomic.Int64
	CommandsBlocked  atomic.Int64
	CommandsPending  atomic.Int64
	ForkBombsBlocked atomic.Int64

	// Egress control
	EgressAllowed atomic.Int64
	EgressBlocked atomic.Int64
	PIIDetected   atomic.Int64

	// Auth
	AuthSuccess atomic.Int64
	AuthFailure atomic.Int64

	// Latency tracking (in microseconds)
	latencyMu    sync.Mutex
	latencySum   int64
	latencyCount int64

	startTime time.Time
}

// Global metrics instance
var global = &Metrics{
	startTime: time.Now(),
}

// Get returns the global metrics instance
func Get() *Metrics {
	return global
}

// RecordLatency records a request latency
func (m *Metrics) RecordLatency(d time.Duration) {
	m.latencyMu.Lock()
	m.latencySum += d.Microseconds()
	m.latencyCount++
	m.latencyMu.Unlock()
}

// Handler returns a Fiber handler for /metrics endpoint
func Handler() fiber.Handler {
	return func(c fiber.Ctx) error {
		m := global

		var sb strings.Builder

		// Write Prometheus-format metrics
		sb.WriteString("# HELP parachute_uptime_seconds Time since service started\n")
		sb.WriteString("# TYPE parachute_uptime_seconds gauge\n")
		sb.WriteString(fmt.Sprintf("parachute_uptime_seconds %.2f\n", time.Since(m.startTime).Seconds()))

		sb.WriteString("\n# HELP parachute_requests_total Total HTTP requests received\n")
		sb.WriteString("# TYPE parachute_requests_total counter\n")
		sb.WriteString(fmt.Sprintf("parachute_requests_total %d\n", m.RequestsTotal.Load()))

		sb.WriteString("\n# HELP parachute_requests_blocked Total requests blocked by policy\n")
		sb.WriteString("# TYPE parachute_requests_blocked counter\n")
		sb.WriteString(fmt.Sprintf("parachute_requests_blocked %d\n", m.RequestsBlocked.Load()))

		sb.WriteString("\n# HELP parachute_requests_approved Total requests approved via HITL\n")
		sb.WriteString("# TYPE parachute_requests_approved counter\n")
		sb.WriteString(fmt.Sprintf("parachute_requests_approved %d\n", m.RequestsApproved.Load()))

		sb.WriteString("\n# HELP parachute_requests_denied Total requests denied via HITL\n")
		sb.WriteString("# TYPE parachute_requests_denied counter\n")
		sb.WriteString(fmt.Sprintf("parachute_requests_denied %d\n", m.RequestsDenied.Load()))

		sb.WriteString("\n# HELP parachute_requests_rate_limited Total requests rate limited\n")
		sb.WriteString("# TYPE parachute_requests_rate_limited counter\n")
		sb.WriteString(fmt.Sprintf("parachute_requests_rate_limited %d\n", m.RequestsRateLimited.Load()))

		sb.WriteString("\n# HELP parachute_commands_allowed Total commands allowed\n")
		sb.WriteString("# TYPE parachute_commands_allowed counter\n")
		sb.WriteString(fmt.Sprintf("parachute_commands_allowed %d\n", m.CommandsAllowed.Load()))

		sb.WriteString("\n# HELP parachute_commands_blocked Total commands blocked\n")
		sb.WriteString("# TYPE parachute_commands_blocked counter\n")
		sb.WriteString(fmt.Sprintf("parachute_commands_blocked %d\n", m.CommandsBlocked.Load()))

		sb.WriteString("\n# HELP parachute_commands_pending Total commands pending approval\n")
		sb.WriteString("# TYPE parachute_commands_pending counter\n")
		sb.WriteString(fmt.Sprintf("parachute_commands_pending %d\n", m.CommandsPending.Load()))

		sb.WriteString("\n# HELP parachute_fork_bombs_blocked Total fork bombs blocked\n")
		sb.WriteString("# TYPE parachute_fork_bombs_blocked counter\n")
		sb.WriteString(fmt.Sprintf("parachute_fork_bombs_blocked %d\n", m.ForkBombsBlocked.Load()))

		sb.WriteString("\n# HELP parachute_egress_allowed Total egress requests allowed\n")
		sb.WriteString("# TYPE parachute_egress_allowed counter\n")
		sb.WriteString(fmt.Sprintf("parachute_egress_allowed %d\n", m.EgressAllowed.Load()))

		sb.WriteString("\n# HELP parachute_egress_blocked Total egress requests blocked\n")
		sb.WriteString("# TYPE parachute_egress_blocked counter\n")
		sb.WriteString(fmt.Sprintf("parachute_egress_blocked %d\n", m.EgressBlocked.Load()))

		sb.WriteString("\n# HELP parachute_pii_detected Total PII patterns detected\n")
		sb.WriteString("# TYPE parachute_pii_detected counter\n")
		sb.WriteString(fmt.Sprintf("parachute_pii_detected %d\n", m.PIIDetected.Load()))

		sb.WriteString("\n# HELP parachute_auth_success Total successful authentications\n")
		sb.WriteString("# TYPE parachute_auth_success counter\n")
		sb.WriteString(fmt.Sprintf("parachute_auth_success %d\n", m.AuthSuccess.Load()))

		sb.WriteString("\n# HELP parachute_auth_failure Total failed authentications\n")
		sb.WriteString("# TYPE parachute_auth_failure counter\n")
		sb.WriteString(fmt.Sprintf("parachute_auth_failure %d\n", m.AuthFailure.Load()))

		// Latency metrics
		m.latencyMu.Lock()
		avgLatency := float64(0)
		if m.latencyCount > 0 {
			avgLatency = float64(m.latencySum) / float64(m.latencyCount) / 1000.0 // convert to ms
		}
		m.latencyMu.Unlock()

		sb.WriteString("\n# HELP parachute_request_latency_ms Average request latency in milliseconds\n")
		sb.WriteString("# TYPE parachute_request_latency_ms gauge\n")
		sb.WriteString(fmt.Sprintf("parachute_request_latency_ms %.3f\n", avgLatency))

		c.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		return c.SendString(sb.String())
	}
}
