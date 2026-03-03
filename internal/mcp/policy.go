package mcp

import (
	"strings"

	"github.com/parachute-security/parachute/internal/interceptor"
)

// Action mirrors interceptor.Action for MCP policy decisions
type Action = interceptor.Action

const (
	ActionAllow   = interceptor.ActionAllow
	ActionBlock   = interceptor.ActionBlock
	ActionPending = interceptor.ActionPending
)

// PolicyResult represents the outcome of a policy evaluation
type PolicyResult struct {
	Action   Action
	Reason   string
	Command  string // Extracted command for command-execution tools
	RulePath string // stable identifier for this rule
}

// ServerPolicy defines per-server or default MCP policy rules
type ServerPolicy struct {
	BlockTools      []string `yaml:"block_tools"`
	RequireApproval []string `yaml:"require_approval"`
	AllowTools      []string `yaml:"allow_tools"`
	BlockResources  []string `yaml:"block_resources"`
}

// PolicyEngine evaluates MCP requests against configured policies
type PolicyEngine struct {
	defaultPolicy ServerPolicy
	serverPolicies map[string]ServerPolicy
	cmdInterceptor *interceptor.Interceptor
}

// NewPolicyEngine creates a new MCP policy engine
func NewPolicyEngine(defaultPolicy ServerPolicy, serverPolicies map[string]ServerPolicy, cmdInterceptor *interceptor.Interceptor) *PolicyEngine {
	if serverPolicies == nil {
		serverPolicies = make(map[string]ServerPolicy)
	}
	return &PolicyEngine{
		defaultPolicy:  defaultPolicy,
		serverPolicies: serverPolicies,
		cmdInterceptor: cmdInterceptor,
	}
}

// CheckToolCall evaluates a tools/call request against policy
func (pe *PolicyEngine) CheckToolCall(tc *ToolCallParams, serverName string) *PolicyResult {
	policy := pe.getPolicyForServer(serverName)

	// Check block list first
	if matchesTool(tc.Name, policy.BlockTools) {
		return &PolicyResult{
			Action:   ActionBlock,
			Reason:   "tool blocked by MCP policy: " + tc.Name,
			RulePath: "mcp/tool/block:" + tc.Name,
		}
	}

	// If allow list is non-empty, only listed tools are permitted
	if len(policy.AllowTools) > 0 && !matchesTool(tc.Name, policy.AllowTools) {
		return &PolicyResult{
			Action:   ActionBlock,
			Reason:   "tool not in MCP allow list: " + tc.Name,
			RulePath: "mcp/allow_list/reject:" + tc.Name,
		}
	}

	// Check if this is a command-execution tool — delegate to existing interceptor
	if pe.cmdInterceptor != nil && isCommandTool(tc.Name) {
		cmdStr := extractCommandFromArgs(tc.Arguments)
		if cmdStr != "" {
			toolCall := &interceptor.ToolCall{
				Name: tc.Name,
				Args: tc.Arguments,
			}
			result := pe.cmdInterceptor.Check(toolCall)
			if result.Action != ActionAllow {
				actionStr := "block"
				if result.Action == ActionPending {
					actionStr = "pending"
				}
				return &PolicyResult{
					Action:   result.Action,
					Reason:   result.Reason,
					Command:  result.Command,
					RulePath: "mcp/command/" + actionStr + ":" + cmdStr,
				}
			}
		}
	}

	// Check require-approval list
	if matchesTool(tc.Name, policy.RequireApproval) {
		return &PolicyResult{
			Action:   ActionPending,
			Reason:   "tool requires approval by MCP policy: " + tc.Name,
			RulePath: "mcp/tool/require_approval:" + tc.Name,
		}
	}

	return &PolicyResult{Action: ActionAllow, RulePath: "mcp/tool/allow:" + tc.Name}
}

// CheckResourceRead evaluates a resources/read request against policy
func (pe *PolicyEngine) CheckResourceRead(rr *ResourceReadParams, serverName string) *PolicyResult {
	policy := pe.getPolicyForServer(serverName)

	for _, blocked := range policy.BlockResources {
		if matchesResource(rr.URI, blocked) {
			return &PolicyResult{
				Action:   ActionBlock,
				Reason:   "resource blocked by MCP policy: " + rr.URI,
				RulePath: "mcp/resource/block:" + rr.URI,
			}
		}
	}

	return &PolicyResult{Action: ActionAllow, RulePath: "mcp/resource/allow:" + rr.URI}
}

func (pe *PolicyEngine) getPolicyForServer(serverName string) ServerPolicy {
	if sp, ok := pe.serverPolicies[serverName]; ok {
		return mergePolicy(pe.defaultPolicy, sp)
	}
	return pe.defaultPolicy
}

// mergePolicy combines default and server-specific policies
func mergePolicy(base, override ServerPolicy) ServerPolicy {
	merged := ServerPolicy{
		BlockTools:      append(base.BlockTools, override.BlockTools...),
		RequireApproval: append(base.RequireApproval, override.RequireApproval...),
		AllowTools:      override.AllowTools, // Allow list from server overrides default
		BlockResources:  append(base.BlockResources, override.BlockResources...),
	}
	if len(override.AllowTools) == 0 {
		merged.AllowTools = base.AllowTools
	}
	return merged
}

func matchesTool(name string, patterns []string) bool {
	nameLower := strings.ToLower(name)
	for _, p := range patterns {
		if strings.ToLower(p) == nameLower {
			return true
		}
		// Support wildcard prefix matching: "filesystem_*"
		if strings.HasSuffix(p, "*") && strings.HasPrefix(nameLower, strings.ToLower(strings.TrimSuffix(p, "*"))) {
			return true
		}
	}
	return false
}

func matchesResource(uri, pattern string) bool {
	uriLower := strings.ToLower(uri)
	patternLower := strings.ToLower(pattern)

	if uriLower == patternLower {
		return true
	}
	// Support prefix matching for resource URIs
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(uriLower, strings.TrimSuffix(patternLower, "*"))
	}
	return false
}

// isCommandTool checks if an MCP tool name is a known command-execution tool
func isCommandTool(name string) bool {
	cmdTools := map[string]bool{
		"execute_bash": true, "run_command": true, "bash": true,
		"shell": true, "terminal": true, "execute": true, "run": true, "command": true,
	}
	return cmdTools[strings.ToLower(name)]
}

// extractCommandFromArgs tries to find a command string in tool arguments
func extractCommandFromArgs(args map[string]any) string {
	cmdArgNames := []string{"command", "cmd", "script", "code", "input"}
	for _, name := range cmdArgNames {
		if val, ok := args[name]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}
