// Package crypto provides HMAC-SHA256 signing and verification for IPC frames,
// and nonce generation and replay protection for the sidecar.
// The HMAC key is loaded from the ACF_HMAC_KEY environment variable at startup.
package crypto
