package acf.v1.tool_test

# Test cases for policies/v1/tool.rego.
#
# Coverage targets:
#   - tool name not in allowlist → BLOCK
#   - tool name in allowlist, clean params → ALLOW
#   - shell metachar in string param → BLOCK
#   - path traversal (../../) in path param → BLOCK
#   - unexpected network destination in URL param → BLOCK
#   - empty allowlist (allow all) + clean tool → ALLOW
