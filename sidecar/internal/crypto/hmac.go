package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// VerifyHMAC checks if the payload matches the signature using a shared secret
func VerifyHMAC(payload, messageHMAC, key []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(payload)
	expectedHMAC := h.Sum(nil)
	return hmac.Equal(messageHMAC, expectedHMAC)
}