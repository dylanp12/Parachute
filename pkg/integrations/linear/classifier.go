package linear

import (
	"strings"

	"github.com/dylanp12/parachute/pkg/integrations"
)

// Compile-time check that Classifier implements integrations.RouteClassifier.
var _ integrations.RouteClassifier = (*Classifier)(nil)

// Classifier implements integrations.RouteClassifier for Linear.
type Classifier struct{}

// Classify returns the route class for a Linear API request.
// Linear is primarily a GraphQL API, so classification is coarse:
//   - POST /graphql  -> RouteGraphQL (mutations and queries)
//   - GET  /graphql  -> RouteGraphQLRead (introspection)
//   - POST /api/webhooks -> RouteWebhooks
//   - */api/oauth/*  -> RouteOAuth
//   - everything else -> RouteUnknown
func (c *Classifier) Classify(method, path string) string {
	// Normalize: strip query string and trailing slash for matching.
	cleanPath := path
	if idx := strings.IndexByte(cleanPath, '?'); idx != -1 {
		cleanPath = cleanPath[:idx]
	}
	cleanPath = strings.TrimRight(cleanPath, "/")

	switch {
	case cleanPath == "/graphql" && method == "POST":
		return RouteGraphQL
	case cleanPath == "/graphql" && method == "GET":
		return RouteGraphQLRead
	case cleanPath == "/api/webhooks" && method == "POST":
		return RouteWebhooks
	case strings.HasPrefix(cleanPath, "/api/oauth"):
		return RouteOAuth
	default:
		return RouteUnknown
	}
}

// Provider returns "linear".
func (c *Classifier) Provider() string {
	return "linear"
}

// KnownHosts returns the Linear API hostnames.
func (c *Classifier) KnownHosts() []string {
	return KnownHosts
}

// RouteClasses returns all defined route classes for Linear.
func (c *Classifier) RouteClasses() []string {
	return []string{
		RouteGraphQL,
		RouteGraphQLRead,
		RouteWebhooks,
		RouteOAuth,
	}
}

// UnknownClass returns the sentinel value for unrecognized routes.
func (c *Classifier) UnknownClass() string {
	return RouteUnknown
}
