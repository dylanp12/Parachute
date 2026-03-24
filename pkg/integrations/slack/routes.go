// Package slack provides route classification for the Slack Web API.
// Slack's API uses a method-in-path convention: all requests go to
// POST /api/{method} (e.g., /api/chat.postMessage).
package slack

// Route class constants for Slack API operations.
const (
	RouteChatRead      = "chat_read"
	RouteChatWrite     = "chat_write"
	RouteReactionsRead = "reactions_read"
	RouteReactionsWrite = "reactions_write"
	RouteFilesRead     = "files_read"
	RouteFilesWrite    = "files_write"
	RouteUsersRead     = "users_read"
	RouteChannelsRead  = "channels_read"
	RouteChannelsWrite = "channels_write"
	RouteAdminRead     = "admin_read"
	RouteAdminWrite    = "admin_write"
	RouteUnknown       = "unknown"
)

// KnownHosts are the hostnames associated with the Slack API.
var KnownHosts = []string{
	"slack.com",
	"api.slack.com",
}
