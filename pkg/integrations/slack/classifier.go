package slack

import (
	"strings"

	"github.com/dylanp12/parachute/pkg/integrations"
)

// Compile-time check that Classifier implements integrations.RouteClassifier.
var _ integrations.RouteClassifier = (*Classifier)(nil)

// readSuffixes are Slack API method suffixes that indicate read operations.
var readSuffixes = []string{
	".list",
	".info",
	".get",
	".history",
	".members",
	".replies",
	".getPresence",
}

// namespaceMap maps a Slack method namespace prefix to its read/write route classes.
type routePair struct {
	read  string
	write string
}

var namespaceMap = map[string]routePair{
	"chat.":          {read: RouteChatRead, write: RouteChatWrite},
	"conversations.": {read: RouteChatRead, write: RouteChatWrite},
	"reactions.":     {read: RouteReactionsRead, write: RouteReactionsWrite},
	"files.":         {read: RouteFilesRead, write: RouteFilesWrite},
	"users.":         {read: RouteUsersRead, write: RouteUsersRead},
	"channels.":      {read: RouteChannelsRead, write: RouteChannelsWrite},
	"admin.":         {read: RouteAdminRead, write: RouteAdminWrite},
	"team.":          {read: RouteAdminRead, write: RouteAdminWrite},
}

// Classifier implements integrations.RouteClassifier for Slack.
type Classifier struct{}

// Classify returns the route class for a Slack API request.
// It extracts the Slack method name from the URL path (e.g., /api/chat.postMessage)
// and maps it to a route class based on namespace and read/write semantics.
func (c *Classifier) Classify(method, path string) string {
	slackMethod := extractMethod(path)
	if slackMethod == "" {
		return RouteUnknown
	}

	for prefix, pair := range namespaceMap {
		if strings.HasPrefix(slackMethod, prefix) {
			if isReadMethod(slackMethod) {
				return pair.read
			}
			return pair.write
		}
	}

	return RouteUnknown
}

// Provider returns "slack".
func (c *Classifier) Provider() string {
	return "slack"
}

// KnownHosts returns the Slack API hostnames.
func (c *Classifier) KnownHosts() []string {
	return KnownHosts
}

// RouteClasses returns all defined route classes for Slack.
func (c *Classifier) RouteClasses() []string {
	return []string{
		RouteChatRead,
		RouteChatWrite,
		RouteReactionsRead,
		RouteReactionsWrite,
		RouteFilesRead,
		RouteFilesWrite,
		RouteUsersRead,
		RouteChannelsRead,
		RouteChannelsWrite,
		RouteAdminRead,
		RouteAdminWrite,
	}
}

// UnknownClass returns the sentinel value for unrecognized routes.
func (c *Classifier) UnknownClass() string {
	return RouteUnknown
}

// extractMethod strips the /api/ prefix from a Slack API path to get the method name.
// For example, "/api/chat.postMessage" returns "chat.postMessage".
func extractMethod(path string) string {
	const prefix = "/api/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	m := strings.TrimPrefix(path, prefix)
	// Strip any query string
	if idx := strings.IndexByte(m, '?'); idx != -1 {
		m = m[:idx]
	}
	// Strip trailing slash
	m = strings.TrimRight(m, "/")
	if m == "" {
		return ""
	}
	return m
}

// isReadMethod returns true if the Slack method name ends with a known read suffix.
func isReadMethod(slackMethod string) bool {
	for _, suffix := range readSuffixes {
		if strings.HasSuffix(slackMethod, suffix) {
			return true
		}
	}
	return false
}
