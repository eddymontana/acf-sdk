package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	// LOCAL IMPORT: Explicitly using the local module name 'sidecar'
	"sidecar/pkg/riskcontext"
)

// Evaluate runs the Rego policy against our RiskContext signals.
// This is the core "Brain" of the ACF PDP (Policy Decision Point).
func Evaluate(ctx context.Context, risk *riskcontext.RiskContext) (*riskcontext.PolicyResult, error) {
	// 1. Initialize the OPA query.
	// We point it to the 'authz' package and the 'allow' rule.
	// The path "../policies/v1" tells OPA where to find your .rego policy files.
	query, err := rego.New(
		rego.Query("data.acf.v1.authz.allow"),
		rego.Load([]string{"../policies/v1"}, nil), 
	).PrepareForEval(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA engine: %v", err)
	}

	// 2. Map the RiskContext signals into the OPA Input format.
	// This structure is what your Rego rules will look at (e.g., input.risk_score).
	input := map[string]interface{}{
		"signals":    risk.Signals,
		"risk_score": risk.RiskScore,
		"hook_type":  risk.HookType,
	}

	// 3. Run the evaluation.
	results, err := query.Eval(ctx, rego.WithInput(input))
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation failed: %v", err)
	}

	// 4. Determine the verdict based on the OPA result.
	// Default to DENY (Secure-by-default/Fail-closed).
	decision := "DENY"
	reason := "Policy evaluation resulted in rejection"

	// OPA returns an array of results; we extract the boolean from the first expression.
	if len(results) > 0 {
		if allowed, ok := results[0].Expressions[0].Value.(bool); ok && allowed {
			decision = "ALLOW"
			reason = "Policy criteria met"
		}
	}

	return &riskcontext.PolicyResult{
		Decision: decision,
		Reason:   reason,
	}, nil
}