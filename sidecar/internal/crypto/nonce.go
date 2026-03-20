// nonce.go — per-request nonce store.
// Maintains a sync.Map of seen nonces with TTL eviction to prevent replay attacks.
// A background goroutine sweeps expired entries on a fixed interval.
package crypto
