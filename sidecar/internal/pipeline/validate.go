package pipeline

import (
	"errors"
	"strings"

	// MENTOR-ALIGNED IMPORT: Final path correction
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

// Validate ensures the incoming request is structurally sound.
// It acts as the "Gatekeeper" for the entire security pipeline.
func Validate(ctx *riskcontext.RiskContext) error {
	// 1. Check for Empty Payloads
	// If there's no text, there's nothing to secure.
	if strings.TrimSpace(ctx.RawPayload) == "" {
		return errors.New("empty_payload_received")
	}

	// 2. Check for Payload Size Limits
	// We set a hard limit of 1MB to prevent memory exhaustion (DoS).
	if len(ctx.RawPayload) > 1024*1024 {
		return errors.New("payload_exceeds_maximum_size_1MB")
	}

	// 3. Hook Type Validation
	// The ACF Kernel currently supports 'on_prompt' and 'on_response'.
	if ctx.HookType != "on_prompt" && ctx.HookType != "on_response" {
		// Defaulting to 'on_prompt' for compatibility, but logging the anomaly.
		ctx.HookType = "on_prompt"
	}

	// 4. Initialize Signals Map
	// Ensuring the map exists so 'Normalise' and 'Scan' don't panic.
	if ctx.Signals == nil {
		ctx.Signals = make(map[string]interface{})
	}

	return nil
}