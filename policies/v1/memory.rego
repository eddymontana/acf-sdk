package acf.v1.memory

# memory.rego — policy for on_memory hook.
# Threat model: memory poisoning — malicious values written to persistent agent state.
#
# Checks:
#   - On write: scan value content for injection patterns
#   - On write: stamp value with HMAC for future integrity verification
#   - On read:  verify HMAC stamp (detect tampered memory)
#   - Provenance: flag writes from untrusted sources (e.g. tool output, RAG chunk)
