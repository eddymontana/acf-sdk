package acf.v1.context_test

# Test cases for policies/v1/context.rego.
#
# Coverage targets:
#   - embedded_instruction signal in low-trust RAG chunk → BLOCK
#   - structural_anomaly signal alone → SANITISE
#   - high source_trust + clean content → ALLOW
#   - multiple signals accumulate to breach sanitise threshold → SANITISE
