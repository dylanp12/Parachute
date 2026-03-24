// Package linear provides route classification for the Linear API.
// Linear uses a GraphQL API, so fine-grained operation classification
// (issue vs project vs comment) requires request body parsing -- a future
// enhancement. For now, classification is at the HTTP level.
package linear

// Route class constants for Linear API operations.
const (
	RouteGraphQL     = "graphql"
	RouteGraphQLRead = "graphql_read"
	RouteWebhooks    = "webhooks"
	RouteOAuth       = "oauth"
	RouteUnknown     = "unknown"
)

// KnownHosts are the hostnames associated with the Linear API.
var KnownHosts = []string{
	"api.linear.app",
	"linear.app",
}
