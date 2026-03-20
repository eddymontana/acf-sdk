// Package riskcontext defines the RiskContext struct — the single payload
// that flows through the entire PDP pipeline. All pipeline stages read from
// and write to this struct. The schema is fixed across v1 and v2; the State
// field is null in v1 and populated by the TTL state store in v2.
package riskcontext
