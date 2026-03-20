// Package pipeline orchestrates the four enforcement stages in order:
// validate → normalise → scan → aggregate.
// Short-circuits and returns BLOCK immediately if any stage emits a hard block signal.
// The pipeline receives a RiskContext from the transport layer and returns a
// populated RiskContext to the policy engine.
package pipeline
