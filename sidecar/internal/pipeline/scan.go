package pipeline

import (
	"regexp"
	"strings"

	// LOCAL IMPORT: Using the 'sidecar' module prefix
	"sidecar/pkg/riskcontext"
)

var (
	// common jailbreak patterns (simplified for v0.2)
	// These patterns detect prompt injection and system override attempts.
	jailbreakPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore previous instructions`),
		regexp.MustCompile(`(?i)you are now a(?:n)? [a-z]+ without filters`),
		regexp.MustCompile(`(?i)system override`),
		regexp.MustCompile(`(?i)dan mode`),
	}

	// sensitive data patterns (PII)
	// Basic regex for credit cards and email addresses.
	piiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),             // Credit Card
		regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`), // Email
	}
)

// Scan identifies Jailbreaks and PII within the payload.
func Scan(ctx *riskcontext.RiskContext) {
	// We use the normalized payload from the previous stage if available
	payload, ok := ctx.Signals["normalized_payload"].(string)
	if !ok {
		payload = strings.ToLower(ctx.RawPayload)
	}

	jailbreakHits := 0
	piiHits := 0

	// 1. Scan for Jailbreaks
	for _, re := range jailbreakPatterns {
		if re.MatchString(payload) {
			jailbreakHits++
		}
	}

	// 2. Scan for PII
	for _, re := range piiPatterns {
		if re.MatchString(payload) {
			piiHits++
		}
	}

	// 3. Update Signals for OPA (Open Policy Agent)
	// These boolean and integer signals are what the Rego policy evaluates.
	ctx.Signals["jailbreak_detected"] = jailbreakHits > 0
	ctx.Signals["jailbreak_count"] = jailbreakHits
	ctx.Signals["pii_detected"] = piiHits > 0
	ctx.Signals["pii_count"] = piiHits
	
	// 4. Calculate a raw RiskScore
	// We weight jailbreaks more heavily (50 pts) than PII (20 pts).
	ctx.RiskScore = float64(jailbreakHits*50 + piiHits*20)
}