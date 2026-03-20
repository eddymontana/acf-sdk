"""
Tests for acf.frame — binary frame encode/decode round-trips.

Coverage targets:
  - encode_request / decode_request round-trip with known payload
  - magic byte is 0xAC at offset 0
  - version byte is 1 at offset 1
  - payload length field matches actual payload length
  - nonce is 16 bytes and unique across calls
  - decode_response: ALLOW (0x00), BLOCK (0x02), SANITISE (0x01) with payload
  - malformed frame (wrong magic) raises FrameError
  - truncated frame raises FrameError
"""
