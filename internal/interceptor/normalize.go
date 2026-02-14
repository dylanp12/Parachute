package interceptor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3/log"
)

// NormalizedToolInvoke represents a tool invocation request normalized from various formats.
// This struct provides a consistent interface regardless of the incoming payload format.
type NormalizedToolInvoke struct {
	// ToolName is the normalized name of the tool being invoked
	ToolName string `json:"tool_name"`

	// Command is the extracted command string (if this is a shell/command tool)
	Command string `json:"command,omitempty"`

	// Cwd is the working directory if specified
	Cwd string `json:"cwd,omitempty"`

	// Env contains environment variables if specified
	Env map[string]string `json:"env,omitempty"`

	// Args contains all the arguments/input for the tool
	Args map[string]any `json:"args"`

	// Raw is the original unparsed request for audit logging
	Raw json.RawMessage `json:"raw"`

	// Format indicates which payload format was detected
	Format string `json:"format"`

	// UnknownKeys tracks any unrecognized top-level keys (for logging)
	UnknownKeys []string `json:"unknown_keys,omitempty"`
}

// ParseError represents an error during payload parsing
type ParseError struct {
	Message string
	Raw     json.RawMessage
}

func (e *ParseError) Error() string {
	return e.Message
}

// knownTopLevelKeys are keys we expect to see in tool invocation payloads
var knownTopLevelKeys = map[string]bool{
	// Format: {tool, input}
	"tool": true, "input": true, "config": true,
	// Format: {action, args}
	"action": true, "args": true,
	// Format: {name, args} / {tool_name, tool_input}
	"name": true, "tool_name": true, "tool_input": true,
	// Format: {type: "tool_use", name, input}
	"type": true,
	// Common additional fields
	"id": true, "session_key": true, "sessionKey": true,
	"request_id": true, "requestId": true, "correlation_id": true,
	"timeout": true, "metadata": true, "context": true,
}

// NormalizeToolInvoke attempts to parse a tool invocation request from various known formats.
// It returns a normalized struct or an error if parsing fails.
//
// Supported formats:
//  1. {tool, input, config} - Parachute native / OpenClaw v1
//  2. {tool, args} - Simplified tool format
//  3. {action, args, sessionKey} - OpenClaw v2 / agent framework style
//  4. {name, args} - LLM tool call style
//  5. {tool_name, tool_input} - Alternative naming
//  6. {type: "tool_use", name, input} - Claude/Anthropic format
func NormalizeToolInvoke(body []byte) (*NormalizedToolInvoke, error) {
	if len(body) == 0 {
		return nil, &ParseError{Message: "empty request body", Raw: body}
	}

	// First, parse as generic map to inspect structure
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, &ParseError{
			Message: fmt.Sprintf("invalid JSON: %v", err),
			Raw:     body,
		}
	}

	if len(data) == 0 {
		return nil, &ParseError{Message: "empty JSON object", Raw: body}
	}

	result := &NormalizedToolInvoke{
		Args: make(map[string]any),
		Raw:  json.RawMessage(body),
		Env:  make(map[string]string),
	}

	// Track unknown keys for logging
	for key := range data {
		if !knownTopLevelKeys[key] {
			result.UnknownKeys = append(result.UnknownKeys, key)
		}
	}

	// Try each format in order of specificity

	// Format 6: {type: "tool_use", name, input} - Claude/Anthropic format
	if typeVal, ok := data["type"].(string); ok && typeVal == "tool_use" {
		result.Format = "claude_tool_use"
		if name, ok := data["name"].(string); ok {
			result.ToolName = name
		}
		if input, ok := data["input"].(map[string]any); ok {
			result.Args = input
		}
		if result.ToolName != "" {
			extractCommandAndEnv(result)
			return result, nil
		}
	}

	// Format 1: {tool, input} - Parachute native / OpenClaw v1
	if tool, ok := data["tool"].(string); ok {
		result.Format = "tool_input"
		result.ToolName = tool
		if input, ok := data["input"].(map[string]any); ok {
			result.Args = input
		} else if args, ok := data["args"].(map[string]any); ok {
			// Format 2: {tool, args}
			result.Format = "tool_args"
			result.Args = args
		}
		if result.ToolName != "" {
			extractCommandAndEnv(result)
			return result, nil
		}
	}

	// Format 3: {action, args, sessionKey} - OpenClaw v2 style
	if action, ok := data["action"].(string); ok {
		result.Format = "action_args"
		result.ToolName = action
		if args, ok := data["args"].(map[string]any); ok {
			result.Args = args
		}
		if result.ToolName != "" {
			extractCommandAndEnv(result)
			return result, nil
		}
	}

	// Format 5: {tool_name, tool_input} - Alternative naming
	if toolName, ok := data["tool_name"].(string); ok {
		result.Format = "tool_name_input"
		result.ToolName = toolName
		if toolInput, ok := data["tool_input"].(map[string]any); ok {
			result.Args = toolInput
		}
		if result.ToolName != "" {
			extractCommandAndEnv(result)
			return result, nil
		}
	}

	// Format 4: {name, args} - LLM tool call style
	if name, ok := data["name"].(string); ok {
		result.Format = "name_args"
		result.ToolName = name
		if args, ok := data["args"].(map[string]any); ok {
			result.Args = args
		} else if input, ok := data["input"].(map[string]any); ok {
			result.Args = input
		}
		if result.ToolName != "" {
			extractCommandAndEnv(result)
			return result, nil
		}
	}

	// If we got here, we couldn't identify a valid tool invocation format
	return nil, &ParseError{
		Message: "unable to parse tool invocation: no recognized format (expected tool/action/name field)",
		Raw:     body,
	}
}

// extractCommandAndEnv extracts command, cwd, and env from the normalized args
func extractCommandAndEnv(n *NormalizedToolInvoke) {
	// Extract command from various possible field names
	commandFields := []string{
		"command", "cmd", "script", "code", "input",
		"CommandLine", "shell_command", "bash_command",
		"execute", "run", "shell",
	}

	for _, field := range commandFields {
		if val, ok := n.Args[field]; ok {
			if str, ok := val.(string); ok && str != "" {
				n.Command = str
				break
			}
		}
	}

	// Extract working directory
	cwdFields := []string{"cwd", "workdir", "working_directory", "dir", "directory"}
	for _, field := range cwdFields {
		if val, ok := n.Args[field]; ok {
			if str, ok := val.(string); ok && str != "" {
				n.Cwd = str
				break
			}
		}
	}

	// Extract environment variables
	envFields := []string{"env", "environment", "env_vars", "envVars"}
	for _, field := range envFields {
		if val, ok := n.Args[field]; ok {
			switch e := val.(type) {
			case map[string]any:
				for k, v := range e {
					if str, ok := v.(string); ok {
						n.Env[k] = str
					}
				}
			case map[string]string:
				for k, v := range e {
					n.Env[k] = v
				}
			}
			break
		}
	}
}

// IsCommandTool checks if the normalized tool is a shell/command execution tool
func (n *NormalizedToolInvoke) IsCommandTool() bool {
	commandTools := []string{
		"bash", "shell", "terminal", "execute", "run",
		"execute_bash", "run_command", "command", "sh",
		"exec", "system", "subprocess", "cmd", "zsh",
		"powershell", "pwsh", "execute_command",
		"ssh_execute", "ssh", "remote_execute", "ssh_run", "ssh_command",
	}

	toolLower := strings.ToLower(n.ToolName)
	for _, ct := range commandTools {
		if toolLower == ct || strings.Contains(toolLower, ct) {
			return true
		}
	}
	return false
}

// ToToolCall converts the normalized invocation to a ToolCall for the interceptor
func (n *NormalizedToolInvoke) ToToolCall() *ToolCall {
	return &ToolCall{
		Name:    n.ToolName,
		Args:    n.Args,
		Command: n.Command,
	}
}

// LogUnknownKeys logs any unrecognized keys found in the payload (for monitoring)
func (n *NormalizedToolInvoke) LogUnknownKeys(correlationID string) {
	if len(n.UnknownKeys) > 0 {
		log.Warnf("[%s] Unknown keys in tool invoke payload (format=%s): %v",
			correlationID, n.Format, n.UnknownKeys)
	}
}

// String returns a string representation for logging
func (n *NormalizedToolInvoke) String() string {
	if n.Command != "" {
		// Truncate command for logging
		cmd := n.Command
		if len(cmd) > 100 {
			cmd = cmd[:100] + "..."
		}
		return fmt.Sprintf("NormalizedToolInvoke{tool=%q, format=%q, command=%q}",
			n.ToolName, n.Format, cmd)
	}
	return fmt.Sprintf("NormalizedToolInvoke{tool=%q, format=%q}",
		n.ToolName, n.Format)
}
