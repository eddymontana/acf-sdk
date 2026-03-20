// aggregate.go — Stage 4 of the pipeline.
// Combines scanner signals into a final risk score (0.0–1.0):
//   - Applies per-signal weights from policy_config.yaml
//   - Applies provenance trust weight (e.g. user input vs. retrieved doc)
//   - If State is non-nil (v2), blends in prior_score with decay_factor
// Writes the final score and populated RiskContext for the policy engine.
package pipeline
