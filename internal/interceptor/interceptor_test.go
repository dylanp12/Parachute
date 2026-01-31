package interceptor

import (
	"testing"

	"github.com/parachute-security/parachute/internal/config"
)

func TestInterceptorBlock(t *testing.T) {
	policy := &config.RiskPolicyConfig{BlockCommands: []string{"rm -rf /", ":(){ :|:& };:"}}
	policy.Compile()

	interceptor := New(policy)

	tests := []struct {
		name     string
		toolCall *ToolCall
		expected Action
	}{
		{"blocked command", &ToolCall{Name: "execute_bash", Args: map[string]any{"command": "rm -rf /"}}, ActionBlock},
		{"fork bomb blocked", &ToolCall{Name: "bash", Args: map[string]any{"cmd": ":(){ :|:& };:"}}, ActionBlock},
		{"safe command allowed", &ToolCall{Name: "execute_bash", Args: map[string]any{"command": "ls -la"}}, ActionAllow},
		{"non-exec tool allowed", &ToolCall{Name: "read_file", Args: map[string]any{"path": "/etc/passwd"}}, ActionAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := interceptor.Check(tt.toolCall)
			if result.Action != tt.expected {
				t.Errorf("Check() action = %v, want %v", result.Action, tt.expected)
			}
		})
	}
}

func TestInterceptorApproval(t *testing.T) {
	policy := &config.RiskPolicyConfig{RequireApproval: []string{"\\bsudo\\b", "\\bcurl\\b"}}
	policy.Compile()

	interceptor := New(policy)

	tests := []struct {
		name     string
		toolCall *ToolCall
		expected Action
	}{
		{"sudo requires approval", &ToolCall{Name: "run_command", Args: map[string]any{"CommandLine": "sudo apt update"}}, ActionPending},
		{"curl requires approval", &ToolCall{Name: "shell", Args: map[string]any{"script": "curl https://evil.com"}}, ActionPending},
		{"safe command allowed", &ToolCall{Name: "execute_bash", Args: map[string]any{"command": "echo hello"}}, ActionAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := interceptor.Check(tt.toolCall)
			if result.Action != tt.expected {
				t.Errorf("Check() action = %v, want %v", result.Action, tt.expected)
			}
		})
	}
}

func TestParseToolCallFromJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected string
	}{
		{"format 1", map[string]any{"name": "execute_bash", "args": map[string]any{"command": "ls"}}, "execute_bash"},
		{"format 2", map[string]any{"tool_name": "run_command", "tool_input": map[string]any{"cmd": "pwd"}}, "run_command"},
		{"format 3", map[string]any{"type": "tool_use", "name": "bash", "input": map[string]any{"code": "whoami"}}, "bash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := ParseToolCallFromJSON(tt.input)
			if tc == nil {
				t.Fatal("ParseToolCallFromJSON returned nil")
			}
			if tc.Name != tt.expected {
				t.Errorf("Name = %q, want %q", tc.Name, tt.expected)
			}
		})
	}
}
