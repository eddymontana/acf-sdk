package pipeline

import (
	"context"
	"fmt"

	// LOCAL IMPORTS: Ensuring we use the 'sidecar' module prefix
	"sidecar/internal/policy"
	"sidecar/pkg/riskcontext"
)

// Pipeline handles the sequential processing of a request.
// As an AI/ML Engineer, you can think of this as a preprocessing and 
// inference pipeline for security signals.
type Pipeline struct {
	// Future-proofing: You can add shared resources like 
	// regex caches, model loaders, or database connections here.
}

// Process evaluates a raw payload and returns a final PolicyResult.
// It coordinates the flow from raw bytes to a finalized OPA decision.
func (p *Pipeline) Process(ctx context.Context, raw []byte, hookType string) (*riskcontext.PolicyResult, error) {
	// 1. Initialize the shared RiskContext.
	// This state object travels through the pipeline stages.
	riskCtx := &riskcontext.RiskContext{
		RawPayload: string(raw),
		HookType:   hookType,
		Signals:    make(map[string]interface{}),
	}

	// 2. VALIDATE: Check schema and basic integrity.
	// If the payload is malformed (e.g., bad JSON), we fail-closed (DENY).
	if err := Validate(riskCtx); err != nil {
		return &riskcontext.PolicyResult{
			Decision: "DENY",
			Reason:   "validation failed: " + err.Error(),
		}, nil
	}

	// 3. NORMALISE: Clean the input to prevent evasion.
	// Strips zero-width characters and normalizes Unicode (NFC/NFKC).
	Normalise(riskCtx)

	// 4. SCAN: Identify Jailbreaks, PII, and Forbidden Phrases.
	// Each scan adds data to the riskCtx.Signals map.
	Scan(riskCtx)

	// 5. AGGREGATE: Calculate final risk scores.
	// Weights the signals to provide a summary risk score for OPA.
	Aggregate(riskCtx)

	// 6. POLICY: Call the OPA Engine (Rego) for the final verdict.
	// Separates detection logic (Scans) from business logic (Policy).
	decision, err := policy.Evaluate(ctx, riskCtx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation error: %w", err)
	}

	return decision, nil
}