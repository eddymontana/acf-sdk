package acf.v1.prompt

# prompt.rego — policy for on_prompt hook.
# Threat model: direct prompt injection — instruction override, role escalation, jailbreak.
#
# Inputs (from RiskContext):
#   input.score         float — aggregated risk score from pipeline
#   input.signals       array — named signals from scan stage
#   input.provenance    string — origin of the payload
#   input.session_id    string
#   input.state         null (v1) | object (v2)
#
# Output (structured decision object):
#   decision: "ALLOW" | "SANITISE" | "BLOCK"
#   sanitise_targets: { matched_patterns, action, inject_prefix }  — on SANITISE only
