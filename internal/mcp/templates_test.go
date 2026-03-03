package mcp

import "testing"

func TestApplyTemplateClaude(t *testing.T) {
	policy := ApplyTemplate("claude-code", ServerPolicy{})
	if len(policy.RequireApproval) != 2 {
		t.Errorf("expected 2 require_approval tools, got %d", len(policy.RequireApproval))
	}
	found := false
	for _, tool := range policy.RequireApproval {
		if tool == "Bash" {
			found = true
		}
	}
	if !found {
		t.Error("Bash should require approval in claude-code template")
	}
}

func TestApplyTemplateWithOverride(t *testing.T) {
	policy := ApplyTemplate("claude-code", ServerPolicy{
		BlockTools: []string{"dangerous_tool"},
	})
	if len(policy.BlockTools) != 1 {
		t.Errorf("expected 1 block tool, got %d", len(policy.BlockTools))
	}
	if len(policy.RequireApproval) != 2 {
		t.Error("base template require_approval should be preserved")
	}
}

func TestApplyTemplateUnknown(t *testing.T) {
	override := ServerPolicy{BlockTools: []string{"x"}}
	policy := ApplyTemplate("nonexistent", override)
	if len(policy.BlockTools) != 1 {
		t.Error("unknown template should return override as-is")
	}
}
