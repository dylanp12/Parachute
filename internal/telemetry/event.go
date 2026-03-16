package telemetry

import "time"

// TelemetryEvent is the input to the collector from egress/MCP code paths.
// The collector converts this to an sdr.SDR with chain, signing, and runtime info.
type TelemetryEvent struct {
	// When the event occurred (defaults to time.Now if zero)
	Timestamp time.Time

	// Action fields
	ActionType   string         // "egress", "mcp_tool_call", "mcp_resource_read", "command", etc.
	ActionTarget string         // domain, tool name, or command string
	ActionParams map[string]any // redacted parameters (optional)

	// Policy evaluation
	Decision string // "allow", "deny", "pending"
	RulePath string // stable identifier: "egress/domain/allow:llm-providers"

	// Enforcement
	EnforcementMode string // "enforce" or "record"

	// Causality (optional)
	SpanID       string // unique per event; auto-generated if empty
	ParentSpanID string // links to parent event (e.g., approval -> trigger)

	// Approval info (optional, populated when approval was involved)
	Approval *ApprovalDetail
}

// ApprovalDetail captures who approved/denied and through which channel.
type ApprovalDetail struct {
	ID             string
	ApproverID     string // who approved
	ApproverType   string // "human", "automation"
	ApprovalSource string // "local_ui", "pro_relay", "slack"
	Justification  string
	DecisionTime   time.Time
}
