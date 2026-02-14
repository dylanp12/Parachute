package ssh

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/audit"
	"github.com/parachute-security/parachute/internal/egress"
	"github.com/parachute-security/parachute/internal/interceptor"
	"github.com/parachute-security/parachute/internal/metrics"
)

// limitedWriter wraps a bytes.Buffer and caps writes at a maximum size.
// Writes beyond the limit are silently discarded.
type limitedWriter struct {
	buf    bytes.Buffer
	max    int
	capped bool
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	remaining := lw.max - lw.buf.Len()
	if remaining <= 0 {
		lw.capped = true
		return len(p), nil // discard but report success
	}
	if len(p) > remaining {
		lw.capped = true
		p = p[:remaining]
	}
	return lw.buf.Write(p)
}

func (lw *limitedWriter) String() string {
	return lw.buf.String()
}

// Executor handles secure command execution across SSH chains
type Executor struct {
	manager     *Manager
	interceptor *interceptor.Interceptor
	egress      *egress.Filter
}

// NewExecutor creates a new SSH command executor
func NewExecutor(manager *Manager, intcpt *interceptor.Interceptor, egressFilter *egress.Filter) *Executor {
	return &Executor{
		manager:     manager,
		interceptor: intcpt,
		egress:      egressFilter,
	}
}

// Execute runs a command on a remote target through the SSH chain
// The command is first checked against the interceptor's risk policy
func (e *Executor) Execute(ctx context.Context, req *ExecutionRequest) *ExecutionResult {
	startTime := time.Now()
	correlationID := req.CorrelationID
	if correlationID == "" {
		correlationID = audit.GenerateCorrelationID()
	}

	result := &ExecutionResult{
		TargetName:    req.TargetName,
		Command:       req.Command,
		CorrelationID: correlationID,
	}

	metrics.Get().SSHExecutionsTotal.Add(1)

	// Resolve the chain to record the hop path
	chain, err := e.manager.ResolveChain(req.TargetName)
	if err != nil {
		result.Error = fmt.Sprintf("failed to resolve chain: %v", err)
		result.ExitCode = -1
		metrics.Get().SSHExecutionsFailed.Add(1)
		return result
	}

	chainNames := make([]string, len(chain))
	for i, t := range chain {
		chainNames[i] = t.Name
	}
	result.Chain = chainNames

	log.Infof("[SSH] [%s] Executing on target %q via chain %v: %s",
		correlationID, req.TargetName, chainNames, truncateCmd(req.Command))

	// Log the SSH execution event
	audit.Log(&audit.Event{
		EventType:     EventSSHExecute,
		CorrelationID: correlationID,
		Command:       req.Command,
		ToolName:      "ssh_execute",
		Details: map[string]string{
			"target": req.TargetName,
			"chain":  strings.Join(chainNames, " -> "),
		},
	})

	// Acquire a session slot (enforces MaxSessions)
	if err := e.manager.AcquireSession(req.TargetName); err != nil {
		result.Error = fmt.Sprintf("session limit: %v", err)
		result.ExitCode = -1
		metrics.Get().SSHExecutionsFailed.Add(1)
		return result
	}
	defer e.manager.ReleaseSession(req.TargetName)

	// Get or establish the SSH connection (handles chaining internally)
	client, err := e.manager.GetConnection(req.TargetName)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		result.ExitCode = -1
		result.Duration = time.Since(startTime)
		metrics.Get().SSHExecutionsFailed.Add(1)

		audit.Log(&audit.Event{
			EventType:     EventSSHError,
			CorrelationID: correlationID,
			Command:       req.Command,
			Reason:        result.Error,
			Details: map[string]string{
				"target": req.TargetName,
			},
		})
		return result
	}

	// Create a new session
	session, err := client.NewSession()
	if err != nil {
		// Connection might be stale, try reconnecting once
		e.manager.Disconnect(req.TargetName)
		client, err = e.manager.GetConnection(req.TargetName)
		if err != nil {
			result.Error = fmt.Sprintf("reconnection failed: %v", err)
			result.ExitCode = -1
			result.Duration = time.Since(startTime)
			metrics.Get().SSHExecutionsFailed.Add(1)
			return result
		}
		session, err = client.NewSession()
		if err != nil {
			result.Error = fmt.Sprintf("session creation failed: %v", err)
			result.ExitCode = -1
			result.Duration = time.Since(startTime)
			metrics.Get().SSHExecutionsFailed.Add(1)
			return result
		}
	}
	defer session.Close()

	// Set up environment variables
	for k, v := range req.Env {
		if err := session.Setenv(k, v); err != nil {
			// Many SSH servers restrict env variables; log but don't fail
			log.Warnf("[SSH] [%s] Failed to set env %s on %q (server may restrict this)",
				correlationID, k, req.TargetName)
		}
	}

	// Build the final command with optional working directory
	cmd := req.Command
	if req.WorkingDir != "" {
		cmd = fmt.Sprintf("cd %s && %s", shellQuote(req.WorkingDir), cmd)
	}

	// Set up output capture with size limits
	maxOutput := e.manager.defaults.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = 1048576 // 1MB default
	}
	stdout := &limitedWriter{max: maxOutput}
	stderr := &limitedWriter{max: maxOutput}
	session.Stdout = stdout
	session.Stderr = stderr

	// Execute with timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = e.manager.defaults.DefaultTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Run the command in a goroutine to support context cancellation
	errCh := make(chan error, 1)
	go func() {
		errCh <- session.Run(cmd)
	}()

	select {
	case err := <-errCh:
		result.Stdout = stdout.String()
		result.Stderr = stderr.String()
		result.Duration = time.Since(startTime)
		result.OutputTruncated = stdout.capped || stderr.capped

		if err != nil {
			// Try to extract exit code from SSH error
			result.ExitCode = extractExitCode(err)
			if result.ExitCode == -1 {
				result.Error = err.Error()
			}
		}

	case <-execCtx.Done():
		// Command timed out - signal the session to close
		session.Signal(SignalKill)
		result.Stdout = stdout.String()
		result.Stderr = stderr.String()
		result.Duration = time.Since(startTime)
		result.ExitCode = -1
		result.Error = fmt.Sprintf("command timed out after %v", timeout)
		result.OutputTruncated = stdout.capped || stderr.capped

		audit.Log(&audit.Event{
			EventType:     EventSSHTimeout,
			CorrelationID: correlationID,
			Command:       req.Command,
			Reason:        result.Error,
			Details: map[string]string{
				"target": req.TargetName,
			},
		})
	}

	// PII scanning on output
	if e.egress != nil {
		if result.Stdout != "" {
			contentResult := e.egress.CheckContent(result.Stdout)
			if !contentResult.Allowed {
				result.PIIDetected = true
				result.Stdout = "[REDACTED: PII detected - " + contentResult.Pattern + "]"
				metrics.Get().SSHPIIDetected.Add(1)
				audit.Log(&audit.Event{
					EventType:     EventSSHPIIDetected,
					CorrelationID: correlationID,
					ToolName:      "ssh_execute",
					Reason:        "PII detected in stdout",
					Details: map[string]string{
						"target":  req.TargetName,
						"pattern": contentResult.Pattern,
					},
				})
			}
		}
		if result.Stderr != "" {
			contentResult := e.egress.CheckContent(result.Stderr)
			if !contentResult.Allowed {
				result.PIIDetected = true
				result.Stderr = "[REDACTED: PII detected - " + contentResult.Pattern + "]"
				if !result.PIIDetected {
					metrics.Get().SSHPIIDetected.Add(1)
				}
			}
		}
	}

	// Log completion
	eventType := EventSSHComplete
	if result.ExitCode != 0 {
		eventType = EventSSHError
		metrics.Get().SSHExecutionsFailed.Add(1)
	}

	audit.Log(&audit.Event{
		EventType:     eventType,
		CorrelationID: correlationID,
		Command:       req.Command,
		Details: map[string]string{
			"target":    req.TargetName,
			"exit_code": fmt.Sprintf("%d", result.ExitCode),
			"duration":  result.Duration.String(),
		},
	})

	log.Infof("[SSH] [%s] Command completed on %q: exit_code=%d duration=%v",
		correlationID, req.TargetName, result.ExitCode, result.Duration)

	return result
}

// CheckAndExecute runs a command through the interceptor before executing
// Returns the interceptor result and execution result
func (e *Executor) CheckAndExecute(ctx context.Context, req *ExecutionRequest) (*interceptor.Result, *ExecutionResult) {
	correlationID := req.CorrelationID
	if correlationID == "" {
		correlationID = audit.GenerateCorrelationID()
		req.CorrelationID = correlationID
	}

	// Check the command against risk policy
	tc := &interceptor.ToolCall{
		Name: "ssh_execute",
		Args: map[string]any{
			"command": req.Command,
			"target":  req.TargetName,
		},
		Command: req.Command,
	}

	checkResult := e.interceptor.Check(tc)

	// If blocked, return immediately
	if checkResult.Action == interceptor.ActionBlock {
		metrics.Get().SSHExecutionsBlocked.Add(1)
		audit.Log(&audit.Event{
			EventType:     EventSSHBlock,
			CorrelationID: correlationID,
			Command:       req.Command,
			ToolName:      "ssh_execute",
			Reason:        checkResult.Reason,
			Details: map[string]string{
				"target": req.TargetName,
			},
		})

		return checkResult, &ExecutionResult{
			TargetName:    req.TargetName,
			Command:       req.Command,
			ExitCode:      -1,
			Error:         fmt.Sprintf("command blocked: %s", checkResult.Reason),
			CorrelationID: correlationID,
		}
	}

	// If pending (requires approval), return the check result for the caller to handle
	if checkResult.Action == interceptor.ActionPending {
		metrics.Get().SSHExecutionsPending.Add(1)
		return checkResult, nil
	}

	// Command is allowed - execute
	metrics.Get().SSHExecutionsAllowed.Add(1)
	return checkResult, e.Execute(ctx, req)
}

// shellQuote adds single quotes around a string for shell safety
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func truncateCmd(cmd string) string {
	if len(cmd) > 100 {
		return cmd[:100] + "..."
	}
	return cmd
}
