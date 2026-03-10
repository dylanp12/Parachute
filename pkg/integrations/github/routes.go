// Package github provides route classification for the GitHub REST API.
// This package is shared between the OSS sidecar and Pro control plane
// to ensure consistent classification -- one classifier, one test corpus.
package github

// Route class constants for GitHub API operations.
// Pro is authoritative on classification semantics.
const (
	RouteRepoMetadataRead = "repo_metadata_read"
	RouteIssuesRead       = "issues_read"
	RouteIssuesWrite      = "issues_write"
	RoutePullsRead        = "pulls_read"
	RoutePullsWrite       = "pulls_write"
	RouteAdmin            = "admin"
	RouteUnknown          = "unknown"
)

// KnownHosts are the hostnames associated with the GitHub API.
var KnownHosts = []string{
	"api.github.com",
	"uploads.github.com",
}
