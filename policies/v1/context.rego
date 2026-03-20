package acf.v1.context

# context.rego — policy for on_context hook.
# Threat model: indirect injection — malicious instructions embedded in retrieved documents.
#
# Additional signals relevant to this hook:
#   source_trust      — provenance weight of the RAG source
#   embedded_instruction — instruction-like structure detected in chunk
#   structural_anomaly   — chunk shape inconsistent with normal document content
