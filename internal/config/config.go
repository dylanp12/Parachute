package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ReverseProxyConfig controls the reverse proxy behavior
type ReverseProxyConfig struct {
	ToolInterception ToolInterceptionConfig `yaml:"tool_interception"`
}

// ToolInterceptionConfig controls tool-call interception in the reverse proxy
type ToolInterceptionConfig struct {
	Enabled bool `yaml:"enabled"` // default false
}

// TelemetryConfig controls SDR event emission
type TelemetryConfig struct {
	Enabled        bool   `yaml:"enabled"`
	AgentID        string `yaml:"agent_id"`
	TenantID       string `yaml:"tenant_id"`
	ChainStatePath string `yaml:"chain_state_path"`
	JSONL          struct {
		Path string `yaml:"path"`
	} `yaml:"jsonl"`
	HTTP struct {
		URL           string `yaml:"url"`
		APIKeyEnv     string `yaml:"api_key_env"`
		BatchSize     int    `yaml:"batch_size"`
		FlushInterval string `yaml:"flush_interval"`
		OffsetPath    string `yaml:"offset_path"`
	} `yaml:"http"`
	Heartbeat struct {
		Interval string `yaml:"interval"`
	} `yaml:"heartbeat"`
}

// Config is the root configuration structure
type Config struct {
	Auth         AuthConfig         `yaml:"auth"`
	RiskPolicy   RiskPolicyConfig   `yaml:"risk_policy"`
	Egress       EgressConfig       `yaml:"egress"`
	Relay        RelayConfig        `yaml:"relay"`
	Storage      StorageConfig      `yaml:"storage"`
	MCP          MCPConfig          `yaml:"mcp"`
	ReverseProxy ReverseProxyConfig `yaml:"reverse_proxy"`
	Telemetry    TelemetryConfig    `yaml:"telemetry"`
	Webhooks     []WebhookConfig    `yaml:"webhooks"`
	License      LicenseConfig      `yaml:"license"`
	Upstream     string             `yaml:"upstream"`
	Listen       string             `yaml:"listen"`
	ProxyListen  string             `yaml:"proxy_listen"` // Forward proxy listen address for agent egress
}

// MCPConfig defines Model Context Protocol proxy settings
type MCPConfig struct {
	Enabled       bool                       `yaml:"enabled"`
	Listen        string                     `yaml:"listen"`         // MCP proxy listen address (e.g. ":9090")
	DefaultPolicy MCPServerPolicy            `yaml:"default_policy"`
	Servers       map[string]MCPServerPolicy `yaml:"servers"`
	Upstreams     []MCPUpstreamConfig        `yaml:"upstreams"`
}

// MCPServerPolicy defines per-server MCP policy rules
type MCPServerPolicy struct {
	BlockTools      []string `yaml:"block_tools"`
	RequireApproval []string `yaml:"require_approval"`
	AllowTools      []string `yaml:"allow_tools"`
	BlockResources  []string `yaml:"block_resources"`
}

// MCPUpstreamConfig defines an upstream MCP server
type MCPUpstreamConfig struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// WebhookConfig defines a notification endpoint
type WebhookConfig struct {
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"`
	Headers map[string]string `yaml:"headers"`
}

// LicenseConfig defines license key settings for Parachute Pro features
type LicenseConfig struct {
	Key    string `yaml:"key"`
	KeyEnv string `yaml:"key_env"` // Environment variable for license key
}

// LicenseKey retrieves the license key from config or environment variable
func (l *LicenseConfig) LicenseKey() string {
	if l.KeyEnv != "" {
		if key := os.Getenv(l.KeyEnv); key != "" {
			return key
		}
	}
	return l.Key
}

// StorageConfig defines persistent storage settings
type StorageConfig struct {
	Type string `yaml:"type"` // "memory" or "sqlite"
	Path string `yaml:"path"` // Path to SQLite database file
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Username      string   `yaml:"username"`
	PasswordEnv   string   `yaml:"password_env"`   // Environment variable name for password
	Token         string   `yaml:"token"`          // Bearer token (optional)
	AllowedIPs    []string `yaml:"allowed_ips"`    // IP whitelist
	AllowInsecure bool     `yaml:"allow_insecure"` // Allow running without auth (DANGEROUS - dev only)
}

// Password retrieves the password from environment variable
func (a *AuthConfig) Password() string {
	if a.PasswordEnv != "" {
		return os.Getenv(a.PasswordEnv)
	}
	return ""
}

// RiskPolicyConfig defines command risk levels
type RiskPolicyConfig struct {
	BlockCommands   []string `yaml:"block_commands"`   // Always block these
	RequireApproval []string `yaml:"require_approval"` // Require HITL for these
	blockRegexes    []*regexp.Regexp
	approvalRegexes []*regexp.Regexp
}

// Compile pre-compiles regex patterns for performance
func (r *RiskPolicyConfig) Compile() error {
	r.blockRegexes = make([]*regexp.Regexp, 0, len(r.BlockCommands))
	for _, pattern := range r.BlockCommands {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid block pattern %q: %w", pattern, err)
		}
		r.blockRegexes = append(r.blockRegexes, re)
	}

	r.approvalRegexes = make([]*regexp.Regexp, 0, len(r.RequireApproval))
	for _, pattern := range r.RequireApproval {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid approval pattern %q: %w", pattern, err)
		}
		r.approvalRegexes = append(r.approvalRegexes, re)
	}
	return nil
}

// ShouldBlock checks if a command should be blocked entirely
func (r *RiskPolicyConfig) ShouldBlock(cmd string) bool {
	for _, re := range r.blockRegexes {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// RequiresApproval checks if a command requires HITL approval
func (r *RiskPolicyConfig) RequiresApproval(cmd string) bool {
	for _, re := range r.approvalRegexes {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// EgressRule defines a structured egress rule with label and action.
type EgressRule struct {
	Domains []string `yaml:"domains"`
	Label   string   `yaml:"label"`
	Action  string   `yaml:"action"` // "allow"
}

// EgressConfig defines outbound traffic controls
type EgressConfig struct {
	Mode         string       `yaml:"mode"`          // "enforce" (default) or "record"
	AllowDomains []string     `yaml:"allow_domains"` // legacy flat list (backward compat)
	Rules        []EgressRule `yaml:"rules"`         // structured rules
	PIIPatterns  []string     `yaml:"pii_patterns"`  // Regex patterns for PII detection
	piiRegexes   []*regexp.Regexp
}

// Compile pre-compiles PII regex patterns
func (e *EgressConfig) Compile() error {
	e.piiRegexes = make([]*regexp.Regexp, 0, len(e.PIIPatterns))
	for _, pattern := range e.PIIPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid PII pattern %q: %w", pattern, err)
		}
		e.piiRegexes = append(e.piiRegexes, re)
	}
	return nil
}

// IsDomainAllowed checks if a domain is in the whitelist
func (e *EgressConfig) IsDomainAllowed(domain string) bool {
	domain = strings.ToLower(domain)
	for _, allowed := range e.AllowDomains {
		if strings.ToLower(allowed) == domain {
			return true
		}
		// Support wildcard subdomains
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.TrimPrefix(allowed, "*")
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		}
	}
	return false
}

// ContainsPII checks if content contains PII patterns
func (e *EgressConfig) ContainsPII(content string) (bool, string) {
	for i, re := range e.piiRegexes {
		if re.MatchString(content) {
			return true, e.PIIPatterns[i]
		}
	}
	return false, ""
}

// RelayConfig defines cloud relay settings (Phase 3)
type RelayConfig struct {
	Enabled   bool   `yaml:"enabled"`
	ServerURL string `yaml:"server_url"` // wss://relay.parachute.io
	APIKey    string `yaml:"api_key"`
}

// Load reads and parses configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Set defaults
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.Upstream == "" {
		cfg.Upstream = "http://openclaw:3000"
	}
	if cfg.ProxyListen == "" {
		cfg.ProxyListen = ":8888"
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "memory" // Default to in-memory for backward compatibility
	}
	if cfg.Storage.Path == "" {
		cfg.Storage.Path = "/var/lib/parachute/parachute.db"
	}
	if cfg.Telemetry.ChainStatePath == "" {
		cfg.Telemetry.ChainStatePath = "/var/lib/parachute/chain_state.json"
	}
	if cfg.Telemetry.JSONL.Path == "" {
		cfg.Telemetry.JSONL.Path = "/var/lib/parachute/events.jsonl"
	}

	// Egress mode defaults
	if cfg.Egress.Mode == "" {
		cfg.Egress.Mode = "enforce"
	}
	// Convert legacy allow_domains to structured rule
	if len(cfg.Egress.AllowDomains) > 0 && len(cfg.Egress.Rules) == 0 {
		cfg.Egress.Rules = []EgressRule{{
			Domains: cfg.Egress.AllowDomains,
			Label:   "legacy",
			Action:  "allow",
		}}
	}

	// Compile regex patterns
	if err := cfg.RiskPolicy.Compile(); err != nil {
		return nil, err
	}
	if err := cfg.Egress.Compile(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
