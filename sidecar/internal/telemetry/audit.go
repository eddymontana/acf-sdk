// audit.go — structured audit log formatting.
// Writes one JSON line per enforcement decision to the configured audit sink.
// Fields: hook_type, decision, score, signals, provenance, session_id, policy_version, trace_id.
package telemetry
