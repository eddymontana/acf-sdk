// ttl_store.go — v2 StateStore implementation.
// In-memory map keyed by session_id with TTL decay.
// Hydrates the State field of RiskContext before the pipeline runs,
// then updates after the decision is returned.
// A background goroutine handles TTL eviction.
package state
