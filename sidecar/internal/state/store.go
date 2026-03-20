// Package state defines the StateStore interface and its implementations.
// v1 uses noop.go (stateless). v2 swaps in ttl_store.go at startup injection.
// The pipeline is unchanged between versions — it calls the interface only.
package state
