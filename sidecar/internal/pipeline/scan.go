// scan.go — Stage 3 of the pipeline.
// Runs on the canonical text produced by the normalise stage:
//   - Aho-Corasick multi-pattern lexical scan against jailbreak_patterns.json
//   - Allowlist permission lookups (tool names, memory keys)
//   - Integrity checks (HMAC verification for memory read operations)
// Emits named signals into RiskContext.Signals.
// Semantic scan (LLM classifier) runs only for mid-band inputs that lexical cannot resolve.
package pipeline
