package interceptor

import (
	"regexp"
	"strings"

	"github.com/dylanp12/parachute/internal/config"
)

// ToolCall represents a parsed tool call from the LLM
type ToolCall struct {
	Name    string         `json:"name"`
	Args    map[string]any `json:"args"`
	Command string         `json:"-"`
}

// Result represents the decision for a tool call
type Result struct {
	Action  Action
	Reason  string
	ID      string
	Command string // The actual command that triggered the action
}

// Action defines what to do with a tool call
type Action int

const (
	ActionAllow Action = iota
	ActionBlock
	ActionPending
)

// Interceptor checks tool calls against risk policy
type Interceptor struct {
	policy *config.RiskPolicyConfig
}

// New creates a new interceptor with the given policy
func New(policy *config.RiskPolicyConfig) *Interceptor {
	return &Interceptor{policy: policy}
}

// Check evaluates a tool call and returns the decision
// It extracts all commands (including from shell wrappers) and checks each one
func (i *Interceptor) Check(tc *ToolCall) *Result {
	rawCmd := i.extractCommand(tc)
	if rawCmd == "" {
		return &Result{Action: ActionAllow}
	}

	tc.Command = rawCmd

	// Check for base64 encoded command evasion
	if IsBase64Encoded(rawCmd) {
		return &Result{
			Action:  ActionPending,
			Reason:  "potential base64 encoded command evasion",
			Command: rawCmd,
		}
	}

	// Check for known fork bomb patterns (before splitting, since they contain `;`)
	if IsForkBomb(rawCmd) {
		return &Result{
			Action:  ActionBlock,
			Reason:  "fork bomb detected",
			Command: rawCmd,
		}
	}

	// IMPORTANT: Check raw command against block patterns BEFORE splitting
	// This catches patterns that contain command separators (like fork bombs)
	if i.policy.ShouldBlock(rawCmd) {
		return &Result{
			Action:  ActionBlock,
			Reason:  "command matches block policy",
			Command: rawCmd,
		}
	}

	// Extract all commands including from shell wrappers and compound commands
	commands := ExtractAllCommands(rawCmd)

	// Check each extracted command against policy
	// Block takes precedence over approval, which takes precedence over allow
	var pendingCmd string
	for _, cmd := range commands {
		if i.policy.ShouldBlock(cmd) {
			return &Result{
				Action:  ActionBlock,
				Reason:  "command matches block policy",
				Command: cmd,
			}
		}
		if i.policy.RequiresApproval(cmd) && pendingCmd == "" {
			pendingCmd = cmd
		}
	}

	if pendingCmd != "" {
		return &Result{
			Action:  ActionPending,
			Reason:  "command requires approval",
			Command: pendingCmd,
		}
	}

	return &Result{Action: ActionAllow}
}

// extractCommand extracts the command string from various tool call formats
func (i *Interceptor) extractCommand(tc *ToolCall) string {
	execToolNames := map[string]bool{
		"execute_bash": true, "run_command": true, "bash": true,
		"shell": true, "terminal": true, "execute": true, "run": true, "command": true,
	}

	// Check both exact match and lowercase
	if !execToolNames[tc.Name] && !execToolNames[strings.ToLower(tc.Name)] {
		return ""
	}

	cmdArgNames := []string{"command", "cmd", "script", "code", "input", "CommandLine"}
	for _, name := range cmdArgNames {
		if val, ok := tc.Args[name]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}

	return ""
}

// ExtractAllCommands extracts all individual commands from a complex command string
// This handles shell wrappers, command separators, and nested commands
func ExtractAllCommands(cmd string) []string {
	var result []string

	// First, unwrap any shell wrappers
	unwrapped := unwrapShellCommand(cmd)

	// Split on command separators
	parts := splitCommandSeparators(unwrapped)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for command substitution
		subcommands := extractCommandSubstitution(part)
		result = append(result, subcommands...)

		// Add the main command too
		result = append(result, part)
	}

	// Also add the original command for pattern matching
	if cmd != unwrapped {
		result = append(result, cmd)
	}

	return dedupe(result)
}

// unwrapShellCommand recursively extracts commands from shell wrappers like:
// - bash -c "command"
// - sh -c 'command'
// - bash -lc "command"
// - zsh -c "command"
// - /bin/bash -c "command"
func unwrapShellCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)

	// Regex to match shell wrapper patterns
	shellWrapperPatterns := []*regexp.Regexp{
		// bash -c 'cmd' or bash -c "cmd" with various flags
		regexp.MustCompile(`^(?:/bin/|/usr/bin/)?(?:ba)?sh\s+-[a-z]*c\s+["'](.+?)["']\s*$`),
		// bash -c cmd (no quotes)
		regexp.MustCompile(`^(?:/bin/|/usr/bin/)?(?:ba)?sh\s+-[a-z]*c\s+(.+)$`),
		// zsh -c 'cmd'
		regexp.MustCompile(`^(?:/bin/|/usr/bin/)?zsh\s+-[a-z]*c\s+["'](.+?)["']\s*$`),
		// zsh -c cmd
		regexp.MustCompile(`^(?:/bin/|/usr/bin/)?zsh\s+-[a-z]*c\s+(.+)$`),
		// env bash -c cmd
		regexp.MustCompile(`^env\s+(?:/bin/|/usr/bin/)?(?:ba)?sh\s+-[a-z]*c\s+["'](.+?)["']\s*$`),
	}

	for _, pattern := range shellWrapperPatterns {
		if matches := pattern.FindStringSubmatch(cmd); len(matches) > 1 {
			// Recursively unwrap in case of nested wrappers
			return unwrapShellCommand(matches[1])
		}
	}

	return cmd
}

// splitCommandSeparators splits a command on separators like ; && || and newlines
func splitCommandSeparators(cmd string) []string {
	var result []string
	var current strings.Builder
	inQuote := rune(0)
	escapeNext := false
	depth := 0 // Track parentheses/braces depth

	for _, r := range cmd {
		if escapeNext {
			current.WriteRune(r)
			escapeNext = false
			continue
		}

		if r == '\\' {
			escapeNext = true
			current.WriteRune(r)
			continue
		}

		// Track quotes
		if r == '"' || r == '\'' || r == '`' {
			if inQuote == 0 {
				inQuote = r
			} else if inQuote == r {
				inQuote = 0
			}
			current.WriteRune(r)
			continue
		}

		// Track nesting
		if r == '(' || r == '{' || r == '[' {
			depth++
			current.WriteRune(r)
			continue
		}
		if r == ')' || r == '}' || r == ']' {
			depth--
			current.WriteRune(r)
			continue
		}

		// Only split on separators when not in quotes or nested
		if inQuote == 0 && depth == 0 {
			if r == ';' || r == '\n' {
				if s := strings.TrimSpace(current.String()); s != "" {
					result = append(result, s)
				}
				current.Reset()
				continue
			}
		}

		current.WriteRune(r)
	}

	if s := strings.TrimSpace(current.String()); s != "" {
		result = append(result, s)
	}

	// Also split on && and ||
	var finalResult []string
	for _, part := range result {
		subParts := splitOnOperators(part)
		finalResult = append(finalResult, subParts...)
	}

	return finalResult
}

// splitOnOperators splits on && and || while respecting quotes
func splitOnOperators(cmd string) []string {
	var result []string
	var current strings.Builder
	inQuote := rune(0)
	chars := []rune(cmd)

	for i := 0; i < len(chars); i++ {
		r := chars[i]

		// Track quotes
		if r == '"' || r == '\'' || r == '`' {
			if inQuote == 0 {
				inQuote = r
			} else if inQuote == r {
				inQuote = 0
			}
			current.WriteRune(r)
			continue
		}

		// Check for && or || when not in quotes
		if inQuote == 0 && i < len(chars)-1 {
			next := chars[i+1]
			if (r == '&' && next == '&') || (r == '|' && next == '|') {
				if s := strings.TrimSpace(current.String()); s != "" {
					result = append(result, s)
				}
				current.Reset()
				i++ // Skip next character
				continue
			}
		}

		current.WriteRune(r)
	}

	if s := strings.TrimSpace(current.String()); s != "" {
		result = append(result, s)
	}

	return result
}

// extractCommandSubstitution finds and extracts commands from $() and “ substitutions
func extractCommandSubstitution(cmd string) []string {
	var result []string

	// Find $(...) patterns
	dollarParenRegex := regexp.MustCompile(`\$\(([^)]+)\)`)
	matches := dollarParenRegex.FindAllStringSubmatch(cmd, -1)
	for _, match := range matches {
		if len(match) > 1 {
			// Recursively extract from nested commands
			result = append(result, match[1])
			result = append(result, ExtractAllCommands(match[1])...)
		}
	}

	// Find `...` patterns (backticks)
	backtickRegex := regexp.MustCompile("`([^`]+)`")
	matches = backtickRegex.FindAllStringSubmatch(cmd, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result = append(result, match[1])
			result = append(result, ExtractAllCommands(match[1])...)
		}
	}

	return result
}

// dedupe removes duplicate strings from a slice
func dedupe(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// ParseToolCallFromJSON extracts tool call info from various JSON formats
func ParseToolCallFromJSON(data map[string]any) *ToolCall {
	tc := &ToolCall{Args: make(map[string]any)}

	if name, ok := data["name"].(string); ok {
		tc.Name = name
		if args, ok := data["args"].(map[string]any); ok {
			tc.Args = args
		}
		return tc
	}

	if name, ok := data["tool_name"].(string); ok {
		tc.Name = name
		if input, ok := data["tool_input"].(map[string]any); ok {
			tc.Args = input
		}
		return tc
	}

	if data["type"] == "tool_use" {
		if name, ok := data["name"].(string); ok {
			tc.Name = name
			if input, ok := data["input"].(map[string]any); ok {
				tc.Args = input
			}
		}
		return tc
	}

	return nil
}

// IsBase64Encoded checks if a command appears to be base64 encoded
// This is useful for detecting evasion attempts like: echo "cm0gLXJmIC8=" | base64 -d | sh
func IsBase64Encoded(cmd string) bool {
	// Look for patterns like: base64 -d | sh, base64 --decode | bash
	base64PipePattern := regexp.MustCompile(`base64\s+(-d|--decode).*\|\s*(sh|bash|zsh)`)
	return base64PipePattern.MatchString(cmd)
}

// IsForkBomb detects various shell fork bomb patterns
// Fork bombs are dangerous because they consume all system resources
func IsForkBomb(cmd string) bool {
	// Known fork bomb patterns (checked via literal string match)
	forkBombPatterns := []string{
		":(){ :|:& };:",             // Classic Bash fork bomb
		":(){ :|:& };: &",           // Variant
		".(){.|.&};.",               // Variant
		"bomb(){ bomb|bomb& };bomb", // Named variant
		":(){:|:&};:",               // No spaces variant
	}

	// Normalize whitespace for comparison
	normalized := strings.TrimSpace(cmd)

	for _, pattern := range forkBombPatterns {
		if normalized == pattern || strings.Contains(normalized, pattern) {
			return true
		}
	}

	// Regex for fork bomb structure: name(){ name|name& };name
	// This catches variations like: x(){ x|x& };x
	forkBombRegex := regexp.MustCompile(`^[a-zA-Z_.:]+\(\)\s*\{\s*[a-zA-Z_.:]+\s*\|\s*[a-zA-Z_.:]+\s*&\s*\}\s*;\s*[a-zA-Z_.:]+\s*&?\s*$`)
	if forkBombRegex.MatchString(normalized) {
		return true
	}

	return false
}
