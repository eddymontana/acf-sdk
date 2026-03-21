package pipeline

import (
	"context"
	"fmt"
	"os"

	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
	"github.com/eddymontana/acf-sdk/pkg/kernel"
	"github.com/open-policy-agent/opa/rego"
)

func ExecuteLexicalScan(ctx *riskcontext.RiskContext) {
	result := kernel.LexicalScan(ctx.RawPayload)
	ctx.RiskScore = float64(result.RiskScore)
	if result.MatchedPattern != "" {
		ctx.Signals["kernel_match"] = result.MatchedPattern
	}
}

func EvaluatePolicy(ctx *riskcontext.RiskContext) (bool, string, error) {
	regoInput := map[string]interface{}{
		"risk_score": ctx.RiskScore,
		"signals":    ctx.Signals,
	}

	// Determine the correct path to the rego file
	policyPath := os.Getenv("ACF_POLICY_PATH")
	if policyPath == "" {
		// Fallback logic for local development
		policyPath = "../sidecar/policies/main.rego"
		if _, err := os.Stat(policyPath); os.IsNotExist(err) {
			policyPath = "sidecar/policies/main.rego"
		}
	}

	r := rego.New(
		rego.Query("data.acf.authz.allow"),
		rego.Load([]string{policyPath}, nil),
	)

	query, err := r.PrepareForEval(context.Background())
	if err != nil {
		return false, fmt.Sprintf("policy_load_error: %v", err), err
	}

	results, err := query.Eval(context.Background(), rego.EvalInput(regoInput))
	if err != nil {
		return false, "evaluation_error", err
	}

	if len(results) == 0 {
		return false, "no_policy_match", fmt.Errorf("no results from OPA")
	}

	isAllowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, "type_mismatch", fmt.Errorf("OPA result was not a boolean")
	}

	reason := "content_safe"
	if !isAllowed {
		reason = "malicious_content_detected"
	}

	return isAllowed, reason, nil
}