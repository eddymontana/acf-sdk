package pipeline

import (
	// LOCAL IMPORT: Using the 'sidecar' module prefix
	"sidecar/pkg/riskcontext"
)

// Aggregate synthesizes all signals collected by previous stages.
// As an AI/ML Engineer, think of this as the "Final Layer" that weights 
// different signals before passing them to the Rego Policy Engine.
func Aggregate(ctx *riskcontext.RiskContext) {
	// 1. Environmental Context (Future-proofing)
	// You could check if the user is an 'admin' or if the environment 
	// is 'production' vs 'staging' and adjust the risk score here.
	
	// 2. Risk Score Clamping
	// We ensure the RiskScore stays within a standard 0-100 range.
	// This makes it predictable for the OPA (Rego) policy writers.
	if ctx.RiskScore > 100 {
		ctx.RiskScore = 100
	}

	if ctx.RiskScore < 0 {
		ctx.RiskScore = 0
	}

	// 3. Final Signal Map Update
	// We export the finalized score so the OPA engine can use it 
	// (e.g., 'allow if input.risk_score < 75')
	ctx.Signals["final_risk_score"] = ctx.RiskScore
}