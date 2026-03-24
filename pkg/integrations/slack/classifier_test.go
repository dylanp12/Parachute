package slack

import "testing"

func TestClassify(t *testing.T) {
	c := &Classifier{}

	tests := []struct {
		name     string
		method   string
		path     string
		expected string
	}{
		// Chat write
		{"post message", "POST", "/api/chat.postMessage", RouteChatWrite},
		{"update message", "POST", "/api/chat.update", RouteChatWrite},
		{"delete message", "POST", "/api/chat.delete", RouteChatWrite},
		{"post ephemeral", "POST", "/api/chat.postEphemeral", RouteChatWrite},

		// Chat read (conversations namespace maps to chat)
		{"conversations history", "POST", "/api/conversations.history", RouteChatRead},
		{"conversations list", "POST", "/api/conversations.list", RouteChatRead},
		{"conversations info", "POST", "/api/conversations.info", RouteChatRead},
		{"conversations members", "POST", "/api/conversations.members", RouteChatRead},
		{"conversations replies", "POST", "/api/conversations.replies", RouteChatRead},

		// Reactions
		{"reactions add", "POST", "/api/reactions.add", RouteReactionsWrite},
		{"reactions remove", "POST", "/api/reactions.remove", RouteReactionsWrite},
		{"reactions list", "POST", "/api/reactions.list", RouteReactionsRead},
		{"reactions get", "POST", "/api/reactions.get", RouteReactionsRead},

		// Files
		{"files upload", "POST", "/api/files.upload", RouteFilesWrite},
		{"files delete", "POST", "/api/files.delete", RouteFilesWrite},
		{"files completeUploadExternal", "POST", "/api/files.completeUploadExternal", RouteFilesWrite},
		{"files list", "POST", "/api/files.list", RouteFilesRead},
		{"files info", "POST", "/api/files.info", RouteFilesRead},

		// Users
		{"users list", "POST", "/api/users.list", RouteUsersRead},
		{"users info", "POST", "/api/users.info", RouteUsersRead},
		{"users profile get", "POST", "/api/users.profile.get", RouteUsersRead},
		{"users getPresence", "POST", "/api/users.getPresence", RouteUsersRead},

		// Channels
		{"channels list", "GET", "/api/channels.list", RouteChannelsRead},
		{"channels info", "GET", "/api/channels.info", RouteChannelsRead},
		{"channels create", "POST", "/api/channels.create", RouteChannelsWrite},
		{"channels rename", "POST", "/api/channels.rename", RouteChannelsWrite},
		{"channels archive", "POST", "/api/channels.archive", RouteChannelsWrite},

		// Admin
		{"admin users list", "POST", "/api/admin.users.list", RouteAdminRead},
		{"admin teams list", "POST", "/api/admin.teams.list", RouteAdminRead},
		{"admin users assign", "POST", "/api/admin.users.assign", RouteAdminWrite},
		{"team info", "POST", "/api/team.info", RouteAdminRead},
		{"team accessLogs", "GET", "/api/team.accessLogs", RouteAdminWrite},

		// Unknown
		{"unknown method", "GET", "/api/unknown.method", RouteUnknown},
		{"no api prefix", "POST", "/chat.postMessage", RouteUnknown},
		{"empty path", "POST", "", RouteUnknown},
		{"root path", "POST", "/", RouteUnknown},
		{"api root", "POST", "/api/", RouteUnknown},
		{"bare api", "POST", "/api", RouteUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.Classify(tt.method, tt.path)
			if got != tt.expected {
				t.Errorf("Classify(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.expected)
			}
		})
	}
}

func TestClassifierInterface(t *testing.T) {
	c := &Classifier{}

	if c.Provider() != "slack" {
		t.Errorf("Provider() = %q, want %q", c.Provider(), "slack")
	}

	if c.UnknownClass() != RouteUnknown {
		t.Errorf("UnknownClass() = %q, want %q", c.UnknownClass(), RouteUnknown)
	}

	classes := c.RouteClasses()
	if len(classes) != 11 {
		t.Errorf("RouteClasses() returned %d classes, want 11", len(classes))
	}

	hosts := c.KnownHosts()
	if len(hosts) != 2 {
		t.Errorf("KnownHosts() returned %d hosts, want 2", len(hosts))
	}
	expected := map[string]bool{
		"slack.com":     true,
		"api.slack.com": true,
	}
	for _, h := range hosts {
		if !expected[h] {
			t.Errorf("unexpected host in KnownHosts: %q", h)
		}
	}
}
