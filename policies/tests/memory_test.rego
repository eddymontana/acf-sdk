package acf.v1.memory_test

# Test cases for policies/v1/memory.rego.
#
# Coverage targets:
#   - write with clean value → ALLOW (+ HMAC stamp)
#   - write with injection pattern in value → BLOCK
#   - write from untrusted provenance (tool output) → elevated risk score
#   - read with valid HMAC → ALLOW
#   - read with invalid HMAC (hmac_invalid signal) → BLOCK
#   - read with missing HMAC stamp → BLOCK
