"""
Firewall — the main developer-facing class.
Provides the four v1 hook call sites:
  on_prompt(text: str) -> Decision
  on_context(chunks: list[str]) -> list[ChunkResult]
  on_tool_call(name: str, params: dict) -> Decision
  on_memory(key: str, value: str, op: str) -> Decision

Each method builds the RiskContext payload, delegates to transport.py,
and returns the decoded Decision (or raises FirewallError on hard failure).
"""
