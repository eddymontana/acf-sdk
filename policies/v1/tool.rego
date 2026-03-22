package acf.v1.tool

# tool.rego — policy for on_tool_call hook.
# Threat model: tool abuse — unsafe tool invocation or malicious parameters.
#
# Checks:
#   - Tool name against allowlist (data.policy_config.tool_allowlist)
#   - Shell metacharacter detection in string parameters
#   - Path traversal patterns (../../) in path parameters
#   - Unexpected network destinations in URL parameters
