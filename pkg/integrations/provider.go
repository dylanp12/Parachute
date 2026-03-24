// Package integrations defines the provider abstraction layer for route classification.
// Each integration provider (GitHub, Slack, Linear, etc.) implements the RouteClassifier
// interface to classify API requests into route classes used by the credential broker
// for policy evaluation.
package integrations

// RouteClassifier classifies API requests for a specific integration provider.
// Implementations map (method, path) pairs to route class strings used by the
// broker's policy engine to make allow/deny decisions.
type RouteClassifier interface {
	// Classify returns the route class for an API request.
	// Returns UnknownClass() if no rule matches (fail-closed).
	Classify(method, path string) string

	// Provider returns the provider name (e.g., "github", "slack", "linear").
	Provider() string

	// KnownHosts returns the hostnames associated with this provider's API.
	KnownHosts() []string

	// RouteClasses returns all known route class strings for this provider.
	RouteClasses() []string

	// UnknownClass returns the sentinel string for unrecognized routes.
	// By convention, all providers use "unknown".
	UnknownClass() string
}
