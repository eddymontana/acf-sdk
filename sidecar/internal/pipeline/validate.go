package pipeline

import (
	"encoding/json"
	"errors"

	// LOCAL IMPORT: Updated to use the local 'sidecar' module prefix
	"sidecar/pkg/riskcontext"
)

// Validate ensures the incoming payload meets the expected structural requirements.
// As an AI/ML Engineer, you're implementing the first line of defense here
// to prevent malformed or malicious data from reaching the LLM.
func Validate(ctx *riskcontext.RiskContext) error {
	// 1. Basic JSON validation
	// Ensure the payload is at least valid JSON.
	var js map[string]interface{}
	if err := json.Unmarshal([]byte(ctx.RawPayload), &js); err != nil {
		return errors.New("payload is not valid JSON")
	}

	// 2. Schema Integrity (Example)
	// You can expand this to check for specific fields like "prompt" or "model_id"
	if len(ctx.RawPayload) > 10000 {
		return errors.New("payload size exceeds maximum limit of 10KB")
	}

	// 3. Hook Type validation
	if ctx.HookType == "" {
		return errors.New("hook type is missing")
	}

	return nil
}