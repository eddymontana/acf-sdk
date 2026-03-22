// validate.go — Stage 1 of the pipeline.
package pipeline

import (
	"errors"
	"strings"

	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

const MaxPayloadSize = 1024 * 1024 // 1MB

// Validate ensures the incoming request is structurally sound and verified.
func Validate(ctx *riskcontext.RiskContext) error {
	// 1. Structural Sanity Check
	// Prevents empty or whitespace-only payloads from consuming resources.
	if strings.TrimSpace(ctx.RawPayload) == "" {
		return errors.New("err: empty_payload")
	}

	// 2. Resource Protection (DoS Mitigation)
	// Hard 1MB limit as specified in the Phase 2 goals.
	if len(ctx.RawPayload) > MaxPayloadSize {
		return errors.New("err: payload_too_large")
	}

	// 3. Defence-in-Depth Verification
	// We ensure that the transport layer successfully verified the HMAC.
	// This signal is crucial for the OPA engine (Stage 5) to trust the source.
	if verified, ok := ctx.Signals["transport_verified"].(bool); !ok || !verified {
		// If the transport layer didn't set this, we treat it as an unverified/rogue request.
		// Note: We check this here to keep the pipeline 'self-aware' of security status.
		ctx.RiskScore = 100 
		return errors.New("err: unverified_transport_integrity")
	}

	// 4. Hook Context Validation (Seam 1)
	// Ensuring the hook type is recognized so OPA pulls the correct policy files.
	supportedHooks := map[string]bool{
		"on_prompt":      true,
		"on_response":    true,
		"on_tool_call":   true,
		"on_memory_read": true,
	}

	if !supportedHooks[ctx.HookType] {
		// If unknown, we don't fail, but we flag it for policy-based rejection.
		ctx.Signals["unknown_hook_type"] = true
	}

	// 5. Initialize Registry for downstream stages
	if ctx.Signals == nil {
		ctx.Signals = make(map[string]interface{})
	}

	return nil
}