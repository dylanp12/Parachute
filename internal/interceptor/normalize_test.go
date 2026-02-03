package interceptor

import (
	"encoding/json"
	"testing"
)

// Fixture payloads representing real-world tool invocation formats
var testFixtures = []struct {
	name           string
	payload        string
	expectedTool   string
	expectedCmd    string
	expectedFormat string
	shouldFail     bool
}{
	// Format 1: {tool, input} - Parachute native / OpenClaw v1
	{
		name:           "format_tool_input",
		payload:        `{"tool": "bash", "input": {"command": "ls -la"}}`,
		expectedTool:   "bash",
		expectedCmd:    "ls -la",
		expectedFormat: "tool_input",
	},
	{
		name:           "format_tool_input_with_config",
		payload:        `{"tool": "execute_bash", "input": {"command": "whoami", "cwd": "/tmp"}, "config": {"timeout": 30}}`,
		expectedTool:   "execute_bash",
		expectedCmd:    "whoami",
		expectedFormat: "tool_input",
	},

	// Format 2: {tool, args} - Simplified tool format
	{
		name:           "format_tool_args",
		payload:        `{"tool": "shell", "args": {"cmd": "pwd"}}`,
		expectedTool:   "shell",
		expectedCmd:    "pwd",
		expectedFormat: "tool_args",
	},

	// Format 3: {action, args, sessionKey} - OpenClaw v2 style
	{
		name:           "format_action_args",
		payload:        `{"action": "run_command", "args": {"command": "cat /etc/passwd"}, "sessionKey": "abc123"}`,
		expectedTool:   "run_command",
		expectedCmd:    "cat /etc/passwd",
		expectedFormat: "action_args",
	},
	{
		name:           "format_action_args_with_env",
		payload:        `{"action": "bash", "args": {"script": "echo $HOME", "env": {"DEBUG": "1"}}}`,
		expectedTool:   "bash",
		expectedCmd:    "echo $HOME",
		expectedFormat: "action_args",
	},

	// Format 4: {name, args} - LLM tool call style
	{
		name:           "format_name_args",
		payload:        `{"name": "execute_bash", "args": {"command": "npm install"}}`,
		expectedTool:   "execute_bash",
		expectedCmd:    "npm install",
		expectedFormat: "name_args",
	},

	// Format 5: {tool_name, tool_input} - Alternative naming
	{
		name:           "format_tool_name_input",
		payload:        `{"tool_name": "run_command", "tool_input": {"cmd": "git status"}}`,
		expectedTool:   "run_command",
		expectedCmd:    "git status",
		expectedFormat: "tool_name_input",
	},

	// Format 6: {type: "tool_use", name, input} - Claude/Anthropic format
	{
		name:           "format_claude_tool_use",
		payload:        `{"type": "tool_use", "id": "toolu_123", "name": "bash", "input": {"command": "find . -name '*.go'"}}`,
		expectedTool:   "bash",
		expectedCmd:    "find . -name '*.go'",
		expectedFormat: "claude_tool_use",
	},

	// Non-command tools should parse but have empty command
	{
		name:           "non_command_tool_read_file",
		payload:        `{"tool": "read_file", "input": {"path": "/etc/passwd"}}`,
		expectedTool:   "read_file",
		expectedCmd:    "",
		expectedFormat: "tool_input",
	},
	{
		name:           "non_command_tool_search",
		payload:        `{"action": "search_code", "args": {"query": "password", "directory": "/app"}}`,
		expectedTool:   "search_code",
		expectedCmd:    "",
		expectedFormat: "action_args",
	},

	// Edge cases - various command field names
	{
		name:           "command_in_script_field",
		payload:        `{"tool": "bash", "input": {"script": "#!/bin/bash\necho hello"}}`,
		expectedTool:   "bash",
		expectedCmd:    "#!/bin/bash\necho hello",
		expectedFormat: "tool_input",
	},
	{
		name:           "command_in_code_field",
		payload:        `{"tool": "execute", "input": {"code": "ls -la /tmp"}}`,
		expectedTool:   "execute",
		expectedCmd:    "ls -la /tmp",
		expectedFormat: "tool_input",
	},
	{
		name:           "command_in_CommandLine_field",
		payload:        `{"tool": "cmd", "input": {"CommandLine": "dir /s"}}`,
		expectedTool:   "cmd",
		expectedCmd:    "dir /s",
		expectedFormat: "tool_input",
	},

	// Edge cases - with additional/unknown fields (should still parse)
	{
		name:           "extra_unknown_fields",
		payload:        `{"tool": "bash", "input": {"command": "echo test"}, "unknown_field": "value", "another": 123}`,
		expectedTool:   "bash",
		expectedCmd:    "echo test",
		expectedFormat: "tool_input",
	},

	// Failure cases
	{
		name:       "empty_object",
		payload:    `{}`,
		shouldFail: true,
	},
	{
		name:       "no_tool_identifier",
		payload:    `{"input": {"command": "ls"}}`,
		shouldFail: true,
	},
	{
		name:       "invalid_json",
		payload:    `{not valid json}`,
		shouldFail: true,
	},
	{
		name:       "empty_body",
		payload:    ``,
		shouldFail: true,
	},
	{
		name:       "null_payload",
		payload:    `null`,
		shouldFail: true,
	},
	{
		name:       "array_instead_of_object",
		payload:    `[{"tool": "bash"}]`,
		shouldFail: true,
	},
}

func TestNormalizeToolInvoke(t *testing.T) {
	for _, tt := range testFixtures {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeToolInvoke([]byte(tt.payload))

			if tt.shouldFail {
				if err == nil {
					t.Errorf("NormalizeToolInvoke() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("NormalizeToolInvoke() unexpected error: %v", err)
			}

			if result.ToolName != tt.expectedTool {
				t.Errorf("ToolName = %q, want %q", result.ToolName, tt.expectedTool)
			}

			if result.Command != tt.expectedCmd {
				t.Errorf("Command = %q, want %q", result.Command, tt.expectedCmd)
			}

			if result.Format != tt.expectedFormat {
				t.Errorf("Format = %q, want %q", result.Format, tt.expectedFormat)
			}
		})
	}
}

func TestNormalizeToolInvoke_IsCommandTool(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected bool
	}{
		{"bash_tool", `{"tool": "bash", "input": {"command": "ls"}}`, true},
		{"execute_bash", `{"tool": "execute_bash", "input": {"command": "ls"}}`, true},
		{"run_command", `{"action": "run_command", "args": {"cmd": "ls"}}`, true},
		{"shell", `{"tool": "shell", "input": {"script": "ls"}}`, true},
		{"terminal", `{"tool": "terminal", "input": {"command": "ls"}}`, true},
		{"exec", `{"tool": "exec", "input": {"command": "ls"}}`, true},
		{"my_bash_tool", `{"tool": "my_bash_tool", "input": {"command": "ls"}}`, true},
		{"read_file", `{"tool": "read_file", "input": {"path": "/etc/passwd"}}`, false},
		{"search", `{"tool": "search", "input": {"query": "test"}}`, false},
		{"write_file", `{"tool": "write_file", "input": {"path": "/tmp/test"}}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeToolInvoke([]byte(tt.payload))
			if err != nil {
				t.Fatalf("NormalizeToolInvoke() error: %v", err)
			}
			if result.IsCommandTool() != tt.expected {
				t.Errorf("IsCommandTool() = %v, want %v", result.IsCommandTool(), tt.expected)
			}
		})
	}
}

func TestNormalizeToolInvoke_ExtractsEnvAndCwd(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		expectedCwd string
		expectedEnv map[string]string
	}{
		{
			name:        "with_cwd",
			payload:     `{"tool": "bash", "input": {"command": "ls", "cwd": "/home/user"}}`,
			expectedCwd: "/home/user",
			expectedEnv: map[string]string{},
		},
		{
			name:        "with_workdir",
			payload:     `{"tool": "bash", "input": {"command": "ls", "workdir": "/tmp"}}`,
			expectedCwd: "/tmp",
			expectedEnv: map[string]string{},
		},
		{
			name:        "with_env",
			payload:     `{"tool": "bash", "input": {"command": "echo $FOO", "env": {"FOO": "bar", "DEBUG": "1"}}}`,
			expectedCwd: "",
			expectedEnv: map[string]string{"FOO": "bar", "DEBUG": "1"},
		},
		{
			name:        "with_cwd_and_env",
			payload:     `{"tool": "bash", "input": {"command": "ls", "cwd": "/app", "env": {"PATH": "/usr/bin"}}}`,
			expectedCwd: "/app",
			expectedEnv: map[string]string{"PATH": "/usr/bin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeToolInvoke([]byte(tt.payload))
			if err != nil {
				t.Fatalf("NormalizeToolInvoke() error: %v", err)
			}

			if result.Cwd != tt.expectedCwd {
				t.Errorf("Cwd = %q, want %q", result.Cwd, tt.expectedCwd)
			}

			if len(result.Env) != len(tt.expectedEnv) {
				t.Errorf("Env length = %d, want %d", len(result.Env), len(tt.expectedEnv))
			}

			for k, v := range tt.expectedEnv {
				if result.Env[k] != v {
					t.Errorf("Env[%q] = %q, want %q", k, result.Env[k], v)
				}
			}
		})
	}
}

func TestNormalizeToolInvoke_ToToolCall(t *testing.T) {
	payload := `{"tool": "bash", "input": {"command": "ls -la", "cwd": "/tmp"}}`
	result, err := NormalizeToolInvoke([]byte(payload))
	if err != nil {
		t.Fatalf("NormalizeToolInvoke() error: %v", err)
	}

	tc := result.ToToolCall()
	if tc.Name != "bash" {
		t.Errorf("ToolCall.Name = %q, want %q", tc.Name, "bash")
	}
	if tc.Command != "ls -la" {
		t.Errorf("ToolCall.Command = %q, want %q", tc.Command, "ls -la")
	}
	if tc.Args["command"] != "ls -la" {
		t.Errorf("ToolCall.Args[command] = %v, want %q", tc.Args["command"], "ls -la")
	}
}

func TestNormalizeToolInvoke_UnknownKeys(t *testing.T) {
	payload := `{"tool": "bash", "input": {"command": "ls"}, "custom_field": "value", "metrics": {"foo": "bar"}}`
	result, err := NormalizeToolInvoke([]byte(payload))
	if err != nil {
		t.Fatalf("NormalizeToolInvoke() error: %v", err)
	}

	// Should track unknown keys
	if len(result.UnknownKeys) != 2 {
		t.Errorf("UnknownKeys length = %d, want 2", len(result.UnknownKeys))
	}

	hasCustomField := false
	hasMetrics := false
	for _, k := range result.UnknownKeys {
		if k == "custom_field" {
			hasCustomField = true
		}
		if k == "metrics" {
			hasMetrics = true
		}
	}
	if !hasCustomField {
		t.Error("UnknownKeys should contain 'custom_field'")
	}
	if !hasMetrics {
		t.Error("UnknownKeys should contain 'metrics'")
	}
}

func TestNormalizeToolInvoke_RawPreserved(t *testing.T) {
	payload := `{"tool": "bash", "input": {"command": "ls"}}`
	result, err := NormalizeToolInvoke([]byte(payload))
	if err != nil {
		t.Fatalf("NormalizeToolInvoke() error: %v", err)
	}

	// Raw should be preserved
	if len(result.Raw) == 0 {
		t.Error("Raw should be preserved")
	}

	// Should be valid JSON
	var check map[string]any
	if err := json.Unmarshal(result.Raw, &check); err != nil {
		t.Errorf("Raw is not valid JSON: %v", err)
	}
}

// TestParseError verifies error responses contain useful information
func TestParseError(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		errContains string
	}{
		{
			name:        "invalid_json",
			payload:     `{not valid}`,
			errContains: "invalid JSON",
		},
		{
			name:        "empty_body",
			payload:     ``,
			errContains: "empty request body",
		},
		{
			name:        "no_tool",
			payload:     `{"foo": "bar"}`,
			errContains: "no recognized format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeToolInvoke([]byte(tt.payload))
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			parseErr, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("expected *ParseError, got %T", err)
			}

			if parseErr.Message == "" {
				t.Error("ParseError.Message should not be empty")
			}
		})
	}
}

// Benchmark the normalizer performance
func BenchmarkNormalizeToolInvoke(b *testing.B) {
	payloads := [][]byte{
		[]byte(`{"tool": "bash", "input": {"command": "ls -la"}}`),
		[]byte(`{"action": "run_command", "args": {"cmd": "pwd"}, "sessionKey": "abc"}`),
		[]byte(`{"type": "tool_use", "id": "toolu_123", "name": "bash", "input": {"command": "echo hello"}}`),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payload := payloads[i%len(payloads)]
		_, _ = NormalizeToolInvoke(payload)
	}
}
