package github

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		expected string
	}{
		// Repository metadata
		{"get repo", "GET", "/repos/owner/repo", RouteRepoMetadataRead},
		{"get repo trailing nothing", "GET", "/repos/org/my-repo", RouteRepoMetadataRead},

		// Issues - read
		{"list issues", "GET", "/repos/owner/repo/issues", RouteIssuesRead},
		{"list issues trailing slash", "GET", "/repos/owner/repo/issues/", RouteIssuesRead},
		{"get single issue", "GET", "/repos/owner/repo/issues/123", RouteIssuesRead},
		{"list issue comments", "GET", "/repos/owner/repo/issues/123/comments", RouteIssuesRead},
		{"list issue labels", "GET", "/repos/owner/repo/issues/42/labels", RouteIssuesRead},
		{"list issue events", "GET", "/repos/owner/repo/issues/events", RouteIssuesRead},

		// Issues - write
		{"create issue", "POST", "/repos/owner/repo/issues", RouteIssuesWrite},
		{"update issue", "PATCH", "/repos/owner/repo/issues/123", RouteIssuesWrite},

		// Pull requests - read
		{"list pulls", "GET", "/repos/owner/repo/pulls", RoutePullsRead},
		{"list pulls trailing slash", "GET", "/repos/owner/repo/pulls/", RoutePullsRead},
		{"get single pull", "GET", "/repos/owner/repo/pulls/42", RoutePullsRead},
		{"list pull commits", "GET", "/repos/owner/repo/pulls/42/commits", RoutePullsRead},
		{"list pull files", "GET", "/repos/owner/repo/pulls/42/files", RoutePullsRead},
		{"list pull reviews", "GET", "/repos/owner/repo/pulls/42/reviews", RoutePullsRead},

		// Pull requests - write
		{"create pull", "POST", "/repos/owner/repo/pulls", RoutePullsWrite},
		{"update pull", "PATCH", "/repos/owner/repo/pulls/42", RoutePullsWrite},

		// Admin operations
		{"delete repo", "DELETE", "/repos/owner/repo", RouteAdmin},

		// Unknown routes (fail-closed)
		{"get contents", "GET", "/repos/owner/repo/contents/README.md", RouteUnknown},
		{"put contents", "PUT", "/repos/owner/repo/contents/file.txt", RouteUnknown},
		{"get actions", "GET", "/repos/owner/repo/actions/runs", RouteUnknown},
		{"post actions dispatch", "POST", "/repos/owner/repo/actions/workflows/ci.yml/dispatches", RouteUnknown},
		{"list releases", "GET", "/repos/owner/repo/releases", RouteUnknown},
		{"search code", "GET", "/search/code?q=test", RouteUnknown},
		{"get user", "GET", "/users/octocat", RouteUnknown},
		{"get org", "GET", "/orgs/github", RouteUnknown},
		{"get rate limit", "GET", "/rate_limit", RouteUnknown},
		{"root endpoint", "GET", "/", RouteUnknown},
		{"empty path", "GET", "", RouteUnknown},

		// Edge cases
		{"POST to repo (not issues/pulls)", "POST", "/repos/owner/repo", RouteUnknown},
		{"PUT to repo", "PUT", "/repos/owner/repo", RouteUnknown},
		{"PATCH to repo", "PATCH", "/repos/owner/repo", RouteUnknown},
		{"GET repos list (not single repo)", "GET", "/repos/owner", RouteUnknown},
		{"issue with query params path only", "GET", "/repos/owner/repo/issues", RouteIssuesRead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			if got != tt.expected {
				t.Errorf("Classify(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.expected)
			}
		})
	}
}

func TestKnownHosts(t *testing.T) {
	if len(KnownHosts) == 0 {
		t.Fatal("KnownHosts should not be empty")
	}
	expected := map[string]bool{
		"api.github.com":     true,
		"uploads.github.com": true,
	}
	for _, h := range KnownHosts {
		if !expected[h] {
			t.Errorf("unexpected host in KnownHosts: %q", h)
		}
	}
}
