"""
Tests for acf.models — Decision enum and result dataclasses.

Coverage targets:
  - Decision enum has ALLOW, SANITISE, BLOCK members
  - Decision.from_byte: 0x00 → ALLOW, 0x01 → SANITISE, 0x02 → BLOCK
  - Decision.from_byte: unknown byte raises ValueError
  - SanitiseResult stores sanitised payload and targets
  - ChunkResult stores original, sanitised text, and Decision
"""
