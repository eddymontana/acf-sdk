// harness_test.go — end-to-end integration test suite.
// Spins up a real sidecar process, connects via UDS, fires each payload from
// adversarial_payloads.json, and asserts the decision matches expectations.
//
// Coverage: all 33 adversarial payloads across all four hook types.
// Run with: go test ./tests/integration/... (requires sidecar binary in PATH or built locally)
package integration
