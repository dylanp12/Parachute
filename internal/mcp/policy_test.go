package mcp

import (
	"testing"

	"github.com/parachute-security/parachute/internal/config"
	"github.com/parachute-security/parachute/internal/interceptor"
)

func newTestInterceptor() *interceptor.Interceptor {
	policy := &config.RiskPolicyConfig{
		BlockCommands:   []string{"rm -rf /", ":(){ :|:& };:"},
		RequireApproval: []string{"\\brm\\b", "\\bsudo\\b"},
	}
	policy.Compile()
	return interceptor.New(policy)
}

func TestCheckToolCall_BlockedTool(t *testing.T) {
	pe := NewPolicyEngine(
		ServerPolicy{BlockTools: []string{"dangerous_tool", "drop_database"}},
		nil,
		nil,
	)

	result := pe.CheckToolCall(&ToolCallParams{Name: "dangerous_tool"}, "")
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock, got %d", result.Action)
	}

	result = pe.CheckToolCall(&ToolCallParams{Name: "safe_tool"}, "")
	if result.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %d", result.Action)
	}
}

func TestCheckToolCall_AllowList(t *testing.T) {
	pe := NewPolicyEngine(
		ServerPolicy{AllowTools: []string{"read_file", "list_files"}},
		nil,
		nil,
	)

	result := pe.CheckToolCall(&ToolCallParams{Name: "read_file"}, "")
	if result.Action != ActionAllow {
		t.Errorf("expected ActionAllow for listed tool, got %d", result.Action)
	}

	result = pe.CheckToolCall(&ToolCallParams{Name: "write_file"}, "")
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock for unlisted tool, got %d", result.Action)
	}
}

func TestCheckToolCall_RequireApproval(t *testing.T) {
	pe := NewPolicyEngine(
		ServerPolicy{RequireApproval: []string{"query_db", "send_email"}},
		nil,
		nil,
	)

	result := pe.CheckToolCall(&ToolCallParams{Name: "query_db"}, "")
	if result.Action != ActionPending {
		t.Errorf("expected ActionPending, got %d", result.Action)
	}
}

func TestCheckToolCall_CommandInterception(t *testing.T) {
	pe := NewPolicyEngine(
		ServerPolicy{},
		nil,
		newTestInterceptor(),
	)

	// Fork bomb via MCP tool call
	result := pe.CheckToolCall(&ToolCallParams{
		Name:      "execute_bash",
		Arguments: map[string]any{"command": ":(){ :|:& };:"},
	}, "")
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock for fork bomb, got %d", result.Action)
	}

	// Safe command via MCP
	result = pe.CheckToolCall(&ToolCallParams{
		Name:      "bash",
		Arguments: map[string]any{"command": "ls -la"},
	}, "")
	if result.Action != ActionAllow {
		t.Errorf("expected ActionAllow for safe command, got %d", result.Action)
	}

	// Approval-required via MCP
	result = pe.CheckToolCall(&ToolCallParams{
		Name:      "bash",
		Arguments: map[string]any{"command": "sudo apt install curl"},
	}, "")
	if result.Action != ActionPending {
		t.Errorf("expected ActionPending for sudo, got %d", result.Action)
	}
}

func TestCheckToolCall_PerServerPolicy(t *testing.T) {
	pe := NewPolicyEngine(
		ServerPolicy{},
		map[string]ServerPolicy{
			"filesystem": {
				BlockTools:     []string{"write_file", "delete_file"},
				BlockResources: []string{"file:///etc/*"},
			},
		},
		nil,
	)

	// Blocked by server-specific policy
	result := pe.CheckToolCall(&ToolCallParams{Name: "write_file"}, "filesystem")
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock for filesystem write_file, got %d", result.Action)
	}

	// Allowed because different server
	result = pe.CheckToolCall(&ToolCallParams{Name: "write_file"}, "other-server")
	if result.Action != ActionAllow {
		t.Errorf("expected ActionAllow for other server, got %d", result.Action)
	}
}

func TestCheckResourceRead(t *testing.T) {
	pe := NewPolicyEngine(
		ServerPolicy{BlockResources: []string{"file:///etc/passwd", "file:///etc/shadow"}},
		nil,
		nil,
	)

	result := pe.CheckResourceRead(&ResourceReadParams{URI: "file:///etc/passwd"}, "")
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock for /etc/passwd, got %d", result.Action)
	}

	result = pe.CheckResourceRead(&ResourceReadParams{URI: "file:///home/user/readme.txt"}, "")
	if result.Action != ActionAllow {
		t.Errorf("expected ActionAllow for user file, got %d", result.Action)
	}
}

func TestCheckResourceRead_Wildcard(t *testing.T) {
	pe := NewPolicyEngine(
		ServerPolicy{BlockResources: []string{"file:///etc/*"}},
		nil,
		nil,
	)

	result := pe.CheckResourceRead(&ResourceReadParams{URI: "file:///etc/passwd"}, "")
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock for /etc/* wildcard, got %d", result.Action)
	}
}

func TestWildcardToolMatching(t *testing.T) {
	pe := NewPolicyEngine(
		ServerPolicy{BlockTools: []string{"filesystem_*"}},
		nil,
		nil,
	)

	result := pe.CheckToolCall(&ToolCallParams{Name: "filesystem_write"}, "")
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock for filesystem_* wildcard, got %d", result.Action)
	}

	result = pe.CheckToolCall(&ToolCallParams{Name: "database_query"}, "")
	if result.Action != ActionAllow {
		t.Errorf("expected ActionAllow for non-matching tool, got %d", result.Action)
	}
}
