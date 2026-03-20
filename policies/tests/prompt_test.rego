package acf.v1.prompt_test

# Test cases for policies/v1/prompt.rego.
#
# Coverage targets:
#   - score >= block_score threshold → BLOCK
#   - score >= sanitise_score threshold → SANITISE with targets
#   - score < sanitise_score → ALLOW
#   - jailbreak_pattern signal → BLOCK regardless of score
#   - instruction_override signal → BLOCK
#   - role_escalation signal → SANITISE + inject_prefix
#   - clean input with score 0.0 → ALLOW
#   - v2 state: elevated prior_score pushes borderline input to BLOCK
