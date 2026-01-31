package interceptor

import (
	"github.com/parachute-security/parachute/internal/config"
)

// ToolCall represents a parsed tool call from the LLM
type ToolCall struct {
	Name    string         `json:"name"`
	Args    map[string]any `json:"args"`
	Command string         `json:"-"`
}

// Result represents the decision for a tool call
type Result struct {
	Action Action
	Reason string
	ID     string
}

// Action defines what to do with a tool call
type Action int

const (
	ActionAllow Action = iota
	ActionBlock
	ActionPending
)

// Interceptor checks tool calls against risk policy
type Interceptor struct {
	policy *config.RiskPolicyConfig
}

// New creates a new interceptor with the given policy
func New(policy *config.RiskPolicyConfig) *Interceptor {
	return &Interceptor{policy: policy}
}

// Check evaluates a tool call and returns the decision
func (i *Interceptor) Check(tc *ToolCall) *Result {
	cmd := i.extractCommand(tc)
	if cmd == "" {
		return &Result{Action: ActionAllow}
	}

	tc.Command = cmd

	if i.policy.ShouldBlock(cmd) {
		return &Result{Action: ActionBlock, Reason: "command matches block policy"}
	}

	if i.policy.RequiresApproval(cmd) {
		return &Result{Action: ActionPending, Reason: "command requires approval"}
	}

	return &Result{Action: ActionAllow}
}

// extractCommand extracts the command string from various tool call formats
func (i *Interceptor) extractCommand(tc *ToolCall) string {
	execToolNames := map[string]bool{
		"execute_bash": true, "run_command": true, "bash": true,
		"shell": true, "terminal": true, "execute": true, "run": true, "command": true,
	}

	if !execToolNames[tc.Name] {
		return ""
	}

	cmdArgNames := []string{"command", "cmd", "script", "code", "input", "CommandLine"}
	for _, name := range cmdArgNames {
		if val, ok := tc.Args[name]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}

	return ""
}

// ParseToolCallFromJSON extracts tool call info from various JSON formats
func ParseToolCallFromJSON(data map[string]any) *ToolCall {
	tc := &ToolCall{Args: make(map[string]any)}

	if name, ok := data["name"].(string); ok {
		tc.Name = name
		if args, ok := data["args"].(map[string]any); ok {
			tc.Args = args
		}
		return tc
	}

	if name, ok := data["tool_name"].(string); ok {
		tc.Name = name
		if input, ok := data["tool_input"].(map[string]any); ok {
			tc.Args = input
		}
		return tc
	}

	if data["type"] == "tool_use" {
		if name, ok := data["name"].(string); ok {
			tc.Name = name
			if input, ok := data["input"].(map[string]any); ok {
				tc.Args = input
			}
		}
		return tc
	}

	return nil
}
