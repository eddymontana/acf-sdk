// main.go — sidecar entrypoint.
// Responsibilities:
//   - Parse flags and load config (sidecar.yaml)
//   - Load HMAC key from environment
//   - Initialise the StateStore (noop in v1, TTL in v2)
//   - Start the policy engine with hot-reload watcher
//   - Start the UDS listener
//   - Block until shutdown signal, then drain and exit cleanly
package main
