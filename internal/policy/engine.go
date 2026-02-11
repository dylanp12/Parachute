package policy

import "context"

// Action defines what to do with a command/request
type Action int

const (
	ActionAllow Action = iota
	ActionBlock
	ActionPending
)

// PolicyInput is the data provided to the policy engine for evaluation
type PolicyInput struct {
	Command   string         `json:"command"`
	ToolName  string         `json:"tool_name"`
	Args      map[string]any `json:"args,omitempty"`
	ClientIP  string         `json:"client_ip,omitempty"`
	Method    string         `json:"method,omitempty"`      // For MCP: the JSON-RPC method
	MCPServer string         `json:"mcp_server,omitempty"`  // For MCP: server name
}

// PolicyResult is the decision from the policy engine
type PolicyResult struct {
	Action  Action
	Reason  string
	Command string // The specific command that triggered the decision
}

// Engine evaluates commands and requests against security policies.
// Implementations include:
//   - RegexEngine: backward-compatible wrapper around RiskPolicyConfig
//   - OPAEngine: Open Policy Agent / Rego policy evaluation
//   - CompositeEngine: combines OPA (primary) with regex (fallback)
type Engine interface {
	// Check evaluates a policy input and returns a decision
	Check(ctx context.Context, input *PolicyInput) (*PolicyResult, error)
}
