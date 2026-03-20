"""
Tests for acf.transport — UDS client with a mock socket.

Coverage targets:
  - send_and_receive: happy path returns decoded Decision
  - HMAC key is applied correctly (frame passes verification with correct key)
  - retry logic: transient ConnectionRefusedError retries up to max_attempts
  - retry logic: exceeding max_attempts raises FirewallConnectionError
  - SANITISE response: returns SanitiseResult with sanitised payload
  - BLOCK response: returns Decision.BLOCK
"""
