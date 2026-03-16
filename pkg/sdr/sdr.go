// Package sdr defines the Signed Decision Record (SDR) types used by both
// the Parachute OSS sidecar (producer) and the Pro control plane (consumer).
//
// The SDR is the core evidence-grade data type: a cryptographically signed
// record of a policy decision made at the moment an agent attempted an action.
package sdr

import (
	"time"

	"github.com/google/uuid"
)

// SDRVersion is the current schema version for SDR records.
const SDRVersion = "1.0.0"

// SDR is the Signed Decision Record — the canonical evidence-grade record
// produced by the sidecar and consumed by the control plane.
//
// The canonical JSON encoding (used for signing and hashing) includes all
// fields except the Signing, Telemetry, and Enforcement blocks, with keys
// sorted lexicographically at every nesting level.
type SDR struct {
	SDRVersion string    `json:"sdr_version"`
	SDRID      uuid.UUID `json:"sdr_id"`
	TenantID   string    `json:"tenant_id"`
	AgentID    string    `json:"agent_id"`
	OccurredAt time.Time `json:"occurred_at"`
	ReceivedAt time.Time `json:"received_at,omitempty"`

	Action       ActionInfo       `json:"action"`
	InputsDigest string           `json:"inputs_digest,omitempty"`
	Policy       PolicyInfo       `json:"policy"`
	Approval     *ApprovalInfo    `json:"approval"`
	Chain        ChainInfo        `json:"chain"`
	Signing      SigningInfo       `json:"signing"`
	Runtime      RuntimeInfo      `json:"runtime"`
	Telemetry    TelemetryContext  `json:"telemetry"`
	Enforcement  EnforcementInfo   `json:"enforcement"`
}

// ActionInfo describes the agent action that was evaluated.
type ActionInfo struct {
	Type   string         `json:"type"`             // "tool_call", "egress", "mcp_tool_call"
	Target string         `json:"target"`           // command, URL, or tool name
	Params map[string]any `json:"params,omitempty"` // redacted parameters
}

// PolicyInfo describes the policy evaluation that produced the decision.
type PolicyInfo struct {
	BundleHash        string `json:"bundle_hash"`
	Version           string `json:"version"`
	RulePath          string `json:"rule_path"`
	Decision          string `json:"decision"`           // "allow", "deny", "pending"
	RequiredApprovals int    `json:"required_approvals"`
}

// ApprovalInfo captures who approved/denied the action and why.
// Nil when the action did not require approval.
type ApprovalInfo struct {
	ID             string    `json:"id"`
	ApproverID     string    `json:"approver_id"`
	ApproverType   string    `json:"approver_type"`     // "human", "automation"
	ApprovalSource string    `json:"approval_source"`   // "local_ui", "pro_relay", "slack"
	Justification  string    `json:"justification"`
	DecisionTime   time.Time `json:"decision_time"`
}

// ChainInfo links this SDR into the per-agent hash chain.
type ChainInfo struct {
	PrevHash   string `json:"prev_hash"`   // "genesis" for the first record
	RecordHash string `json:"record_hash"` // SHA-256 of canonical JSON
	ChainID    string `json:"chain_id"`    // typically == agent_id
}

// SigningInfo contains the cryptographic signature over the canonical payload.
// This block is excluded from the canonical JSON used for signing.
type SigningInfo struct {
	KeyID       string    `json:"key_id"`
	Algorithm   string    `json:"alg"`        // "Ed25519"
	Signature   string    `json:"signature"`  // base64url-encoded Ed25519 signature
	SigningTime time.Time `json:"signing_time"`
}

// RuntimeInfo describes the sidecar and host environment.
type RuntimeInfo struct {
	SidecarVersion  string `json:"sidecar_version"`
	HostFingerprint string `json:"host_fingerprint,omitempty"`
	Framework       string `json:"framework,omitempty"`
}

// TelemetryContext provides causality and session tracking.
type TelemetryContext struct {
	SessionID    string `json:"session_id"`
	SpanID       string `json:"span_id,omitempty"`
	ParentSpanID string `json:"parent_span_id,omitempty"`
}

// EnforcementInfo describes whether the decision was enforced or record-only.
type EnforcementInfo struct {
	Mode string `json:"mode"` // "enforce" or "record"
}

// Batch represents a collection of SDRs submitted together.
type Batch struct {
	BatchID string `json:"batch_id"`
	Records []SDR  `json:"records"`
}

// IngestResult is the response from the ingest API for a batch submission.
type IngestResult struct {
	Accepted int               `json:"accepted"`
	Rejected []RejectionReason `json:"rejected,omitempty"`
}

// RejectionReason explains why a specific SDR was rejected during ingest.
type RejectionReason struct {
	SDRID  uuid.UUID `json:"sdr_id"`
	Reason string    `json:"reason"`
}

// HeartbeatPayload is the heartbeat message sent by sidecars to the control plane.
type HeartbeatPayload struct {
	AgentID         string         `json:"agent_id"`
	TenantID        string         `json:"tenant_id"`
	Env             string         `json:"env,omitempty"`
	Service         string         `json:"service,omitempty"`
	Region          string         `json:"region,omitempty"`
	SidecarVersion  string         `json:"sidecar_version"`
	PolicyBundleHash string        `json:"policy_bundle_hash"`
	ConfigHash      string         `json:"config_hash"`
	PendingCount    int            `json:"pending_count"`
	CommandsBlocked int64          `json:"commands_blocked"`
	CommandsAllowed int64          `json:"commands_allowed"`
	UptimeSeconds   float64        `json:"uptime_seconds"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}
