package riskcontext

// RiskContext matches the "Seam 2" definition in the README.
type RiskContext struct {
	RawPayload string                 `json:"raw_payload"`
	HookType   string                 `json:"hook_type"`
	RiskScore  float64                `json:"risk_score"` // Updated to float64 for 0.0-1.0 range
	Signals    map[string]interface{} `json:"signals"`
}

type PolicyResult struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}