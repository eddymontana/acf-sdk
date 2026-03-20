package riskcontext

// RiskContext holds the state of a request as it moves through the pipeline
type RiskContext struct {
	RawPayload string                 // Original input from SDK
	HookType   string                 // e.g., "on_prompt", "on_response"
	RiskScore  float64                // Calculated risk (0-100)
	Signals    map[string]interface{} // Key-Value pairs for OPA (e.g., "jailbreak_detected": true)
}

// PolicyResult is the final output sent back to the Python SDK
type PolicyResult struct {
	Decision string `json:"decision"` // "ALLOW" or "DENY"
	Reason   string `json:"reason"`   // Brief explanation for the decision
}