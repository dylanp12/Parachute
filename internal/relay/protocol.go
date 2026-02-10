package relay

import "time"

// Wire protocol contract between the open-source Parachute sidecar (client)
// and the closed-source Parachute Pro relay server.
//
// Transport: WebSocket (wss://)
// Encoding: JSON
// Auth: First message must be MsgTypeAuthenticate with API key
// Heartbeat: Client sends MsgTypeHeartbeat every 30s; server responds with same
// Reconnection: Client retries with exponential backoff (10s base, 5m max)

// Message type constants — the contract between OSS client and Pro server
const (
	MsgTypeAuthenticate = "authenticate" // Client → Server: initial auth handshake
	MsgTypeApprove      = "approve"      // Server → Client: approve a pending command
	MsgTypeDeny         = "deny"         // Server → Client: deny a pending command
	MsgTypePending      = "pending"      // Client → Server: new pending command notification
	MsgTypeDecision     = "decision"     // Client → Server: local decision notification
	MsgTypeHeartbeat    = "heartbeat"    // Bidirectional: keepalive
	MsgTypeStatus       = "status"       // Client → Server: sidecar status update
	MsgTypeSync         = "sync"         // Server → Client: request full state sync
	MsgTypeError        = "error"        // Bidirectional: error notification
)

// ProtocolVersion is the current wire protocol version
const ProtocolVersion = "1.0"

// RelayMessage is the wire format for relay protocol messages
type RelayMessage struct {
	Type      string         `json:"type"`
	ID        string         `json:"id,omitempty"`
	Version   string         `json:"version,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
	Timestamp time.Time      `json:"timestamp,omitempty"`
}

// AuthPayload is the payload for MsgTypeAuthenticate
type AuthPayload struct {
	APIKey       string `json:"api_key"`
	InstanceID   string `json:"instance_id"`
	Version      string `json:"version"`
	ProtocolVer  string `json:"protocol_version"`
}

// PendingPayload is the payload for MsgTypePending
type PendingPayload struct {
	CommandID string         `json:"command_id"`
	Command   string         `json:"command"`
	ToolName  string         `json:"tool_name"`
	Reason    string         `json:"reason"`
	ExpiresAt time.Time      `json:"expires_at"`
	Args      map[string]any `json:"args,omitempty"`
}

// DecisionPayload is the payload for MsgTypeApprove/MsgTypeDeny/MsgTypeDecision
type DecisionPayload struct {
	CommandID string `json:"command_id"`
	Decision  string `json:"decision"` // "approved" or "denied"
	ApprovedBy string `json:"approved_by,omitempty"`
}

// StatusPayload is the payload for MsgTypeStatus
type StatusPayload struct {
	Uptime          float64 `json:"uptime_seconds"`
	PendingCount    int     `json:"pending_count"`
	CommandsBlocked int64   `json:"commands_blocked"`
	CommandsAllowed int64   `json:"commands_allowed"`
	Connected       bool    `json:"connected"`
}

// ApprovalHandler defines the contract for handling remote approvals.
// The closed-source relay server communicates with the sidecar through this interface.
type ApprovalHandler interface {
	Approve(id string) bool
	Deny(id string) bool
}
