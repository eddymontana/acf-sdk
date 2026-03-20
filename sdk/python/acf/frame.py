"""
Binary frame encoder/decoder for the ACF IPC protocol.
Mirrors sidecar/internal/transport/frame.go exactly.

Request frame layout (54-byte header + payload):
  [0]      magic     — 0xAC
  [1]      version   — 1
  [2:6]    length    — uint32 big-endian
  [6:22]   nonce     — 16 random bytes
  [22:54]  hmac      — 32 bytes HMAC-SHA256
  [54:]    payload   — JSON bytes

Response frame layout:
  [0]      decision  — 0x00 ALLOW · 0x01 SANITISE · 0x02 BLOCK
  [1:5]    san_len   — uint32 big-endian (0 if not SANITISE)
  [5:]     sanitised — JSON bytes (SANITISE only)
"""
