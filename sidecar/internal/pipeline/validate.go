// validate.go — Stage 1 of the pipeline.
// Responsibilities:
//   - HMAC verification of the inbound frame (already done in transport, re-checked here for defence-in-depth)
//   - Nonce replay check against the nonce store
//   - JSON schema validation of the RiskContext payload
// Invalid frames are rejected before any payload parsing.
package pipeline
