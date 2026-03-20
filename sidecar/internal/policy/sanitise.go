// sanitise.go — string transformation functions called by the executor.
// Supported actions (declared by OPA in sanitise_targets):
//   - strip_matched_segments: remove pattern-matched substrings
//   - redact: replace matched segments with a redaction marker
//   - inject_prefix: prepend a warning string to the sanitised payload
package policy
