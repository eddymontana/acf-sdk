package pipeline

import "github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"

func Aggregate(ctx *riskcontext.RiskContext) {
	// Convert integer hits into a 0.0 - 1.0 float
	score := float64(ctx.RiskScore) / 100.0
	
	if score > 1.0 { score = 1.0 }
	if score < 0.0 { score = 0.0 }

	// Store for OPA
	ctx.Signals["final_risk_score"] = score
}