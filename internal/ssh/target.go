package ssh

import (
	"fmt"
	"time"
)

// Target represents a remote SSH execution environment
type Target struct {
	// Name is the unique identifier for this target
	Name string `json:"name" yaml:"name"`

	// Host is the SSH server hostname or IP
	Host string `json:"host" yaml:"host"`

	// Port is the SSH server port (default: 22)
	Port int `json:"port" yaml:"port"`

	// User is the SSH username
	User string `json:"user" yaml:"user"`

	// AuthMethod specifies how to authenticate: "key", "key_file", "password_env"
	AuthMethod string `json:"auth_method" yaml:"auth_method"`

	// KeyFile is the path to the SSH private key file (when auth_method is "key_file")
	KeyFile string `json:"key_file,omitempty" yaml:"key_file"`

	// KeyEnv is the environment variable containing the SSH private key (when auth_method is "key")
	KeyEnv string `json:"key_env,omitempty" yaml:"key_env"`

	// PasswordEnv is the environment variable containing the SSH password (when auth_method is "password_env")
	PasswordEnv string `json:"password_env,omitempty" yaml:"password_env"`

	// ProxyJump specifies an intermediate target name for multi-hop SSH
	// This enables chaining: local -> jump_host -> final_target
	ProxyJump string `json:"proxy_jump,omitempty" yaml:"proxy_jump"`

	// Labels are key-value pairs for organizing and filtering targets
	Labels map[string]string `json:"labels,omitempty" yaml:"labels"`

	// Enabled controls whether this target accepts connections
	Enabled bool `json:"enabled" yaml:"enabled"`

	// MaxSessions limits concurrent SSH sessions to this target (0 = unlimited)
	MaxSessions int `json:"max_sessions,omitempty" yaml:"max_sessions"`
}

// ConnectionInfo holds runtime state for an active SSH target
type ConnectionInfo struct {
	Target       *Target   `json:"target"`
	Connected    bool      `json:"connected"`
	ConnectedAt  time.Time `json:"connected_at,omitempty"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
	SessionCount int       `json:"session_count"`
	Error        string    `json:"error,omitempty"`
}

// Addr returns the host:port string for this target
func (t *Target) Addr() string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("%s:%d", t.Host, port)
}

// Validate checks that the target configuration is valid
func (t *Target) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("target name is required")
	}
	if t.Host == "" {
		return fmt.Errorf("target %q: host is required", t.Name)
	}
	if t.User == "" {
		return fmt.Errorf("target %q: user is required", t.Name)
	}
	if t.Port < 0 || t.Port > 65535 {
		return fmt.Errorf("target %q: invalid port %d", t.Name, t.Port)
	}

	switch t.AuthMethod {
	case "key_file":
		if t.KeyFile == "" {
			return fmt.Errorf("target %q: key_file is required when auth_method is key_file", t.Name)
		}
	case "key":
		if t.KeyEnv == "" {
			return fmt.Errorf("target %q: key_env is required when auth_method is key", t.Name)
		}
	case "password_env":
		if t.PasswordEnv == "" {
			return fmt.Errorf("target %q: password_env is required when auth_method is password_env", t.Name)
		}
	case "agent":
		// SSH agent auth - no additional config needed
	case "":
		return fmt.Errorf("target %q: auth_method is required (key, key_file, password_env, agent)", t.Name)
	default:
		return fmt.Errorf("target %q: unknown auth_method %q", t.Name, t.AuthMethod)
	}

	return nil
}

// ExecutionRequest represents a request to execute a command on a target (or chain of targets)
type ExecutionRequest struct {
	// TargetName is the name of the target (or the final target in a chain)
	TargetName string `json:"target"`

	// Command is the command to execute
	Command string `json:"command"`

	// Timeout is the maximum execution time (0 = use default)
	Timeout time.Duration `json:"timeout,omitempty"`

	// Env contains environment variables to set before execution
	Env map[string]string `json:"env,omitempty"`

	// WorkingDir is the working directory for command execution
	WorkingDir string `json:"working_dir,omitempty"`

	// CorrelationID links this execution to an existing request chain
	CorrelationID string `json:"correlation_id,omitempty"`
}

// ExecutionResult holds the result of a remote command execution
type ExecutionResult struct {
	// TargetName is the target where the command was executed
	TargetName string `json:"target"`

	// Command is the command that was executed
	Command string `json:"command"`

	// ExitCode is the process exit code (0 = success)
	ExitCode int `json:"exit_code"`

	// Stdout contains the standard output
	Stdout string `json:"stdout"`

	// Stderr contains the standard error output
	Stderr string `json:"stderr"`

	// Duration is how long the command took to execute
	Duration time.Duration `json:"duration_ns"`

	// Chain describes the SSH hop path taken (e.g., ["jump1", "jump2", "target"])
	Chain []string `json:"chain"`

	// Error is set if the execution failed at the infrastructure level
	Error string `json:"error,omitempty"`

	// CorrelationID links this result to the originating request
	CorrelationID string `json:"correlation_id,omitempty"`
}
