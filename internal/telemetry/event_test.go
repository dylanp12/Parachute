package telemetry

import (
	"testing"
	"time"
)

func TestTelemetryEventDefaults(t *testing.T) {
	e := TelemetryEvent{
		ActionType:      "egress",
		ActionTarget:    "api.example.com",
		Decision:        "allow",
		RulePath:        "egress/domain/allow:example",
		EnforcementMode: "enforce",
	}

	if e.ActionType != "egress" {
		t.Errorf("unexpected ActionType: %s", e.ActionType)
	}
	if e.Timestamp.IsZero() {
		// This is expected — the collector fills it in
	}
	if e.Approval != nil {
		t.Error("approval should be nil when not set")
	}
}

func TestApprovalDetail(t *testing.T) {
	e := TelemetryEvent{
		ActionType:   "mcp_tool_call",
		ActionTarget: "Bash",
		Decision:     "allow",
		RulePath:     "mcp/tool/require_approval:Bash",
		Approval: &ApprovalDetail{
			ID:             "apr-123",
			ApproverID:     "admin@example.com",
			ApproverType:   "human",
			ApprovalSource: "local_ui",
			DecisionTime:   time.Now(),
		},
	}

	if e.Approval.ApproverType != "human" {
		t.Errorf("unexpected approver type: %s", e.Approval.ApproverType)
	}
	if e.Approval.ApprovalSource != "local_ui" {
		t.Errorf("unexpected approval source: %s", e.Approval.ApprovalSource)
	}
}
