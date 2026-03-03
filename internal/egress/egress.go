package egress

import (
	"net/url"
	"strings"

	"github.com/parachute-security/parachute/internal/config"
)

// Filter controls outbound requests
type Filter struct {
	cfg *config.EgressConfig
}

// New creates a new egress filter
func New(cfg *config.EgressConfig) *Filter {
	return &Filter{cfg: cfg}
}

// CheckResult represents the outcome of an egress check
type CheckResult struct {
	Allowed  bool
	Reason   string
	Pattern  string
	RulePath string // e.g., "egress/domain/allow:llm-providers"
}

// CheckURL validates if an outbound URL is allowed
func (f *Filter) CheckURL(rawURL string) *CheckResult {
	u, err := url.Parse(rawURL)
	if err != nil {
		return &CheckResult{Allowed: false, Reason: "invalid URL", RulePath: "egress/parse_error"}
	}

	host := u.Hostname()
	if host == "" {
		return &CheckResult{Allowed: false, Reason: "no hostname in URL", RulePath: "egress/no_host"}
	}

	// Check structured rules
	for _, rule := range f.cfg.Rules {
		for _, domain := range rule.Domains {
			if matchDomain(host, domain) {
				return &CheckResult{
					Allowed:  rule.Action == "allow",
					RulePath: "egress/domain/" + rule.Action + ":" + rule.Label,
				}
			}
		}
	}

	// Fall back to legacy allow_domains
	if f.cfg.IsDomainAllowed(host) {
		return &CheckResult{Allowed: true, RulePath: "egress/domain/allow:legacy"}
	}

	return &CheckResult{Allowed: false, Reason: "domain not in allowlist", RulePath: "egress/domain/deny:unlisted"}
}

// matchDomain checks if a host matches a domain pattern (exact or wildcard).
func matchDomain(host, pattern string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)
	if host == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. ".github.com"
		return strings.HasSuffix(host, suffix)
	}
	return false
}

// CheckContent scans content for PII patterns
func (f *Filter) CheckContent(content string) *CheckResult {
	hasPII, pattern := f.cfg.ContainsPII(content)
	if hasPII {
		return &CheckResult{Allowed: false, Reason: "content contains PII", Pattern: pattern}
	}
	return &CheckResult{Allowed: true}
}

// ExtractURLsFromCommand finds URLs in a command string
func ExtractURLsFromCommand(cmd string) []string {
	var urls []string
	words := strings.Fields(cmd)
	for _, word := range words {
		word = strings.Trim(word, "\"'`;|&>")
		if strings.HasPrefix(word, "http://") || strings.HasPrefix(word, "https://") {
			urls = append(urls, word)
		}
	}
	return urls
}

// DefaultPIIPatterns returns common PII regex patterns
func DefaultPIIPatterns() []string {
	return []string{
		`\b4[0-9]{12}(?:[0-9]{3})?\b`,
		`\b5[1-5][0-9]{14}\b`,
		`\b3[47][0-9]{13}\b`,
		`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`,
		`-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		`AKIA[0-9A-Z]{16}`,
		`\b\d{3}-\d{2}-\d{4}\b`,
		`ghp_[a-zA-Z0-9]{36}`,
		`gho_[a-zA-Z0-9]{36}`,
	}
}
