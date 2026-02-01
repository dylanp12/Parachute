package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure
type Config struct {
	Auth        AuthConfig       `yaml:"auth"`
	RiskPolicy  RiskPolicyConfig `yaml:"risk_policy"`
	Egress      EgressConfig     `yaml:"egress"`
	Relay       RelayConfig      `yaml:"relay"`
	Storage     StorageConfig    `yaml:"storage"`
	Upstream    string           `yaml:"upstream"`
	Listen      string           `yaml:"listen"`
	ProxyListen string           `yaml:"proxy_listen"` // Forward proxy listen address for agent egress
}

// StorageConfig defines persistent storage settings
type StorageConfig struct {
	Type string `yaml:"type"` // "memory" or "sqlite"
	Path string `yaml:"path"` // Path to SQLite database file
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Username    string   `yaml:"username"`
	PasswordEnv string   `yaml:"password_env"` // Environment variable name for password
	Token       string   `yaml:"token"`        // Bearer token (optional)
	AllowedIPs  []string `yaml:"allowed_ips"`  // IP whitelist
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

// EgressConfig defines outbound traffic controls
type EgressConfig struct {
	AllowDomains []string `yaml:"allow_domains"` // Whitelisted domains
	PIIPatterns  []string `yaml:"pii_patterns"`  // Regex patterns for PII detection
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

	// Compile regex patterns
	if err := cfg.RiskPolicy.Compile(); err != nil {
		return nil, err
	}
	if err := cfg.Egress.Compile(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
