// Package policy wraps the OPA Go SDK for policy evaluation, sanitisation
// execution, and result assembly.
//
// engine.go — OPA engine.
// Loads the Rego bundle from the policies directory at startup.
// Watches for file changes and hot-reloads without restarting.
// Queries the policy matching the RiskContext.HookType field.
// Returns a structured decision object (ALLOW / SANITISE / BLOCK) with sanitise_targets.
package policy
