package broker

import "strings"

// IntegrationMatcher determines if an outbound request targets a managed integration.
type IntegrationMatcher struct {
	// hostMap maps lowercase hostname → integration name for O(1) lookup.
	hostMap map[string]string
}

// IntegrationDef defines a single managed integration for the matcher.
type IntegrationDef struct {
	Name  string
	Hosts []string // exact hostnames (e.g., "api.github.com")
}

// NewMatcher creates an IntegrationMatcher from integration definitions.
func NewMatcher(defs []IntegrationDef) *IntegrationMatcher {
	hostMap := make(map[string]string)
	for _, def := range defs {
		for _, h := range def.Hosts {
			hostMap[strings.ToLower(h)] = def.Name
		}
	}
	return &IntegrationMatcher{hostMap: hostMap}
}

// Match checks if a hostname targets a managed integration.
// Returns nil if the hostname is not managed.
func (m *IntegrationMatcher) Match(hostname string) *MatchResult {
	hostname = strings.ToLower(hostname)
	// Strip port if present
	if idx := strings.LastIndex(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	name, ok := m.hostMap[hostname]
	if !ok {
		return nil
	}
	return &MatchResult{
		Integration: name,
		Host:        hostname,
	}
}

// Integrations returns the list of managed integration names.
func (m *IntegrationMatcher) Integrations() []string {
	seen := make(map[string]bool)
	var names []string
	for _, name := range m.hostMap {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// HostForIntegration returns the first known host for a given integration name.
// Returns empty string if not found.
func (m *IntegrationMatcher) HostForIntegration(integration string) string {
	for host, name := range m.hostMap {
		if name == integration {
			return host
		}
	}
	return ""
}
