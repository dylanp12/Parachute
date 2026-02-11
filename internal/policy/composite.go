package policy

import "context"

// CompositeEngine combines multiple policy engines.
// The OPA engine is checked first; if it returns Allow (pass-through when no policies loaded),
// the regex engine is used as fallback. Block/Pending from either engine takes effect.
type CompositeEngine struct {
	primary  Engine // OPA engine (takes precedence)
	fallback Engine // Regex engine (backward compat)
}

// NewCompositeEngine creates a composite engine with OPA primary and regex fallback
func NewCompositeEngine(primary, fallback Engine) *CompositeEngine {
	return &CompositeEngine{
		primary:  primary,
		fallback: fallback,
	}
}

// Check evaluates the input against both engines.
// Primary (OPA) is checked first. If it blocks or requires approval, that decision stands.
// If primary allows, fallback (regex) is checked for backward compatibility.
func (e *CompositeEngine) Check(ctx context.Context, input *PolicyInput) (*PolicyResult, error) {
	if e.primary != nil {
		result, err := e.primary.Check(ctx, input)
		if err != nil {
			return nil, err
		}
		if result.Action != ActionAllow {
			return result, nil
		}
	}

	if e.fallback != nil {
		return e.fallback.Check(ctx, input)
	}

	return &PolicyResult{Action: ActionAllow}, nil
}
