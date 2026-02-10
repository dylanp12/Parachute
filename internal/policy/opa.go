package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OPAEngine evaluates commands against Open Policy Agent / Rego policies.
// This engine supports complex conditional policies that the regex engine cannot express:
//   - "allow rm only in /tmp, block everywhere else"
//   - "require approval for any command during off-hours"
//   - Composable policy libraries that can be shared and versioned
//
// Requires: github.com/open-policy-agent/opa (added in M5 implementation)
//
// This is a structural placeholder that defines the interface and loads policy files.
// The actual OPA evaluation will be wired in when the OPA dependency is added.
type OPAEngine struct {
	policyDir string
	policies  map[string]string // filename -> policy content
}

// NewOPAEngine creates a new OPA policy engine that loads .rego files from the given directory
func NewOPAEngine(policyDir string) (*OPAEngine, error) {
	engine := &OPAEngine{
		policyDir: policyDir,
		policies:  make(map[string]string),
	}

	if err := engine.loadPolicies(); err != nil {
		return nil, fmt.Errorf("loading OPA policies: %w", err)
	}

	return engine, nil
}

func (e *OPAEngine) loadPolicies() error {
	if e.policyDir == "" {
		return nil
	}

	entries, err := os.ReadDir(e.policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(e.policyDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("reading policy %s: %w", entry.Name(), err)
		}

		e.policies[entry.Name()] = string(data)
	}

	return nil
}

// Check evaluates a policy input against loaded Rego policies.
// When the OPA dependency is added, this will use rego.New() to compile and evaluate.
// For now, this returns ActionAllow as a pass-through (use CompositeEngine with regex fallback).
func (e *OPAEngine) Check(ctx context.Context, input *PolicyInput) (*PolicyResult, error) {
	if len(e.policies) == 0 {
		return &PolicyResult{Action: ActionAllow}, nil
	}

	// Serialize input for OPA evaluation
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshaling policy input: %w", err)
	}

	// TODO: Wire in OPA evaluation when dependency is added:
	//   import "github.com/open-policy-agent/opa/rego"
	//
	//   query := rego.New(
	//       rego.Query("data.parachute.decision"),
	//       rego.Module("policy.rego", policyContent),
	//       rego.Input(input),
	//   )
	//   rs, err := query.Eval(ctx)
	//   // Parse result into PolicyResult

	_ = inputJSON // Will be used when OPA is wired in

	return &PolicyResult{Action: ActionAllow}, nil
}
