// pipeline.go — The Engine Room. 
// Orchestrates the 4 stages of the PDP pipeline.
package pipeline

import (
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

// PipelineInterface defines the contract for the security kernel.
type PipelineInterface interface {
	Process(ctx *riskcontext.RiskContext)
}

// Pipeline is the concrete implementation of the 4-stage engine.
type Pipeline struct{}

// Process executes the sequential stages of the Cognitive Firewall.
func (p *Pipeline) Process(ctx *riskcontext.RiskContext) {
	// Stage 1: Validate (Structural & Integrity check)
	if err := Validate(ctx); err != nil {
		ctx.RiskScore = 1.0 // Maximum risk on validation failure
		ctx.Signals["error"] = err.Error()
		return
	}

	// Stage 2: Normalise (De-obfuscation & Unicode cleaning)
	Normalise(ctx)

	// Stage 3: Scan (Aho-Corasick Lexical Analysis)
	Scan(ctx)

	// Stage 4: Aggregate (Weighted Trust Scoring)
	Aggregate(ctx)
}