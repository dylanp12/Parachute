package github

import "regexp"

// routeRule maps an HTTP method and path pattern to a route class.
type routeRule struct {
	method     string         // HTTP method ("GET", "POST", etc.) or "*" for any
	pattern    *regexp.Regexp // compiled regex for the path
	routeClass string
}

// rules is evaluated in order; first match wins.
// The list is intentionally narrow for M2 -- expand as needed.
var rules = []routeRule{
	// Admin operations (denied by default)
	{method: "DELETE", pattern: regexp.MustCompile(`^/repos/[^/]+/[^/]+$`), routeClass: RouteAdmin},

	// Repository metadata
	{method: "GET", pattern: regexp.MustCompile(`^/repos/[^/]+/[^/]+$`), routeClass: RouteRepoMetadataRead},

	// Issues
	{method: "GET", pattern: regexp.MustCompile(`^/repos/[^/]+/[^/]+/issues(/|$)`), routeClass: RouteIssuesRead},
	{method: "POST", pattern: regexp.MustCompile(`^/repos/[^/]+/[^/]+/issues$`), routeClass: RouteIssuesWrite},
	{method: "PATCH", pattern: regexp.MustCompile(`^/repos/[^/]+/[^/]+/issues/\d+$`), routeClass: RouteIssuesWrite},

	// Pull Requests
	{method: "GET", pattern: regexp.MustCompile(`^/repos/[^/]+/[^/]+/pulls(/|$)`), routeClass: RoutePullsRead},
	{method: "POST", pattern: regexp.MustCompile(`^/repos/[^/]+/[^/]+/pulls$`), routeClass: RoutePullsWrite},
	{method: "PATCH", pattern: regexp.MustCompile(`^/repos/[^/]+/[^/]+/pulls/\d+$`), routeClass: RoutePullsWrite},
}

// Classify returns the route class for a GitHub API request.
// Returns RouteUnknown if no rule matches (fail-closed: unknown is denied by default).
func Classify(method, path string) string {
	for _, rule := range rules {
		if (rule.method == "*" || rule.method == method) && rule.pattern.MatchString(path) {
			return rule.routeClass
		}
	}
	return RouteUnknown
}
