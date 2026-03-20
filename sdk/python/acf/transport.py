"""
UDS client transport for the ACF SDK.
Responsibilities:
  - Maintain a connection to /tmp/acf.sock (or configured path)
  - Sign each payload with HMAC-SHA256 and generate a per-request nonce
  - Encode the request frame (via frame.py) and write to the socket
  - Read and decode the response frame
  - Retry logic for transient connection failures (exponential backoff, max 3 attempts)

Zero external dependencies — stdlib only (socket, hmac, hashlib, os, struct).
"""
