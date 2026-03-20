// Package transport handles the UDS accept loop and binary frame encoding/decoding.
//
// Frame format (54-byte header + variable payload):
//   [0]      magic byte  — 0xAC, fast-reject misaddressed connections
//   [1]      version     — current: 1
//   [2:6]    length      — uint32 big-endian, length of JSON payload
//   [6:22]   nonce       — 16 random bytes, per-request replay protection
//   [22:54]  HMAC        — 32 bytes, HMAC-SHA256 over (version+length+nonce+payload)
//   [54:]    payload     — JSON-serialised RiskContext
//
// Response frame:
//   [0]      decision    — 0x00 ALLOW · 0x01 SANITISE · 0x02 BLOCK
//   [1:5]    san_length  — uint32 big-endian, 0 if not SANITISE
//   [5:]     sanitised   — present only on SANITISE
package transport
