package mcp

// PolicyTemplates maps template names to pre-built policy configurations.
var PolicyTemplates = map[string]ServerPolicy{
	"claude-code": {
		RequireApproval: []string{"Bash", "Write"},
		BlockResources:  []string{"file:///etc/passwd", "file:///etc/shadow"},
	},
	"restrictive": {
		RequireApproval: []string{"*"},
	},
	"permissive": {
		// No blocks, no approvals — record-only telemetry
	},
}

// ApplyTemplate returns the policy from a template name, merged with any overrides.
func ApplyTemplate(templateName string, override ServerPolicy) ServerPolicy {
	base, ok := PolicyTemplates[templateName]
	if !ok {
		return override
	}
	return mergePolicy(base, override)
}
