// aggregate.go — Stage 4 of the pipeline.
package pipeline

import (
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

// Aggregate combines signals into a normalized risk score (0.0–1.0).
func Aggregate(ctx *riskcontext.RiskContext) {
	var totalRisk float64

	// 1. Provenance Trust Weight (Seam 2)
	// User prompts are higher risk than internal system messages.
	provenanceWeight := 1.0
	if source, ok := ctx.Metadata["source"].(string); ok {
		if source == "system" || source == "trusted_rag" {
			provenanceWeight = 0.5 // Reduce risk for trusted sources
		}
	}

	// 2. Lexical Scanner Signal (from Stage 3)
	if hit, ok := ctx.Signals["kernel_match"].(bool); ok && hit {
		// A basic lexical hit adds significant risk
		totalRisk += 0.7
	}

	// 3. Normalisation Anomalies (from Stage 2)
	// If we found hidden characters or heavy leetspeak, it's a high-risk signal.
	if hidden, ok := ctx.Signals["hidden_chars_detected"].(bool); ok && hidden {
		totalRisk += 0.5
	}

	// 4. Integrity/HMAC Failures (from Stage 1)
	if _, exists := ctx.Signals["integrity_failure"]; exists {
		totalRisk += 1.0 // Immediate high risk for tampering
	}

	// 5. Final Normalization
	// Apply the provenance multiplier and clamp between 0.0 and 1.0
	finalScore := totalRisk * provenanceWeight

	if finalScore > 1.0 {
		finalScore = 1.0
	}
	if finalScore < 0.0 {
		finalScore = 0.0
	}

	// 6. Output for OPA Policy Engine (Stage 5)
	ctx.RiskScore = finalScore
	ctx.Signals["final_risk_score"] = finalScore
	
	// If V2 state existed, we would blend it here:
	// finalScore = (finalScore * 0.7) + (ctx.State.PriorScore * 0.3)
}