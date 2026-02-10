package policy

import (
	"context"

	"github.com/parachute-security/parachute/internal/config"
)

// RegexEngine wraps the existing RiskPolicyConfig behind the Engine interface.
// This provides backward compatibility — when no OPA policies are configured,
// the regex engine preserves existing behavior exactly.
type RegexEngine struct {
	policy *config.RiskPolicyConfig
}

// NewRegexEngine creates a policy engine that uses regex-based risk policies
func NewRegexEngine(policy *config.RiskPolicyConfig) *RegexEngine {
	return &RegexEngine{policy: policy}
}

// Check evaluates a command against regex-based block and approval patterns
func (e *RegexEngine) Check(ctx context.Context, input *PolicyInput) (*PolicyResult, error) {
	if input.Command == "" {
		return &PolicyResult{Action: ActionAllow}, nil
	}

	if e.policy.ShouldBlock(input.Command) {
		return &PolicyResult{
			Action:  ActionBlock,
			Reason:  "command matches block policy",
			Command: input.Command,
		}, nil
	}

	if e.policy.RequiresApproval(input.Command) {
		return &PolicyResult{
			Action:  ActionPending,
			Reason:  "command requires approval",
			Command: input.Command,
		}, nil
	}

	return &PolicyResult{Action: ActionAllow}, nil
}
