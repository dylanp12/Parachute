// Package broker implements the credential brokerage seam for managed integrations.
// The broker gateway accepts agent requests, resolves credentials, and forwards
// authenticated requests to upstream APIs.
package broker

import "context"

// MatchResult describes a matched managed integration.
type MatchResult struct {
	Integration string // e.g., "github"
	Host        string // the matched hostname, e.g., "api.github.com"
	Provider    string // provider name for route classification (e.g., "github")
}

// BrokerDecision represents the outcome of a credential brokerage attempt.
type BrokerDecision string

const (
	DecisionCredentialInjected BrokerDecision = "credential_injected"
	DecisionDeny               BrokerDecision = "deny"
	DecisionUnavailable        BrokerDecision = "credential_unavailable"
	DecisionAllow              BrokerDecision = "allow" // passthrough (noop)
)

// Credential holds the resolved credential to inject into upstream requests.
type Credential struct {
	HeaderName  string // typically "Authorization"
	HeaderValue string // e.g., "Bearer ghs_xxx" or "token xxx"
}

// BrokerRequest is the input to a CredentialBroker.
type BrokerRequest struct {
	Integration string // e.g., "github"
	RouteClass  string // e.g., "issues_read"
	AgentID     string // from telemetry config
	Method      string // HTTP method
	Path        string // request path (e.g., "/repos/org/repo/issues")
}

// BrokerResult is the outcome of a credential brokerage call.
type BrokerResult struct {
	Decision    BrokerDecision
	Credential  *Credential // nil when denied or unavailable
	Reason      string
	Integration string
	RouteClass  string
}

// CredentialBroker resolves credentials for managed integrations.
//
// Implementations:
//   - NoopBroker:      passthrough, no credential injection (default when disabled)
//   - DevStaticBroker: reads token from env var (dev/local only)
//   - ProBroker:       calls Pro API POST /v1/broker/credential (production mode)
type CredentialBroker interface {
	Resolve(ctx context.Context, req *BrokerRequest) (*BrokerResult, error)
}
