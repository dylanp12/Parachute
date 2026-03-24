// Package github provides route classification for the GitHub REST API.
// This package is shared between the OSS sidecar and Pro control plane
// to ensure consistent classification -- one classifier, one test corpus.
package github

import "github.com/dylanp12/parachute/pkg/integrations"

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

// Classifier implements integrations.RouteClassifier for the GitHub API.
// It wraps the package-level Classify function to satisfy the interface.
type Classifier struct{}

// Compile-time interface check.
var _ integrations.RouteClassifier = (*Classifier)(nil)

// NewClassifier returns a new GitHub RouteClassifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

func (c *Classifier) Classify(method, path string) string {
	return Classify(method, path)
}

func (c *Classifier) Provider() string {
	return "github"
}

func (c *Classifier) KnownHosts() []string {
	return KnownHosts
}

func (c *Classifier) RouteClasses() []string {
	return []string{
		RouteRepoMetadataRead,
		RouteIssuesRead,
		RouteIssuesWrite,
		RoutePullsRead,
		RoutePullsWrite,
		RouteAdmin,
		RouteUnknown,
	}
}

func (c *Classifier) UnknownClass() string {
	return RouteUnknown
}
