package kernel

import (
	"encoding/base64"
	"strings"
	"github.com/eddymontana/acf-sdk/internal/protocol"
)

// HygieneCheck runs the L1 stage: it cleans the input and sets the bitmask flags.
func HygieneCheck(rawInput string) (string, protocol.StatusFlags) {
	var flags protocol.StatusFlags
	
	// 1. Basic cleaning (Whitespace stripping)
	cleanOutput := strings.TrimSpace(rawInput)

	// 2. Base64 Evasion Check
	// We attempt to decode. If successful, we unwrap the attack layer.
	decoded, err := base64.StdEncoding.DecodeString(cleanOutput)
	if err == nil && len(decoded) > 0 {
		cleanOutput = string(decoded)
		// BITWISE OR: Sets the Base64 flag bit to 1
		flags |= protocol.FlagBase64Detected 
	}

	// 3. Mark the L1 check as complete (Standard normalization flag)
	flags |= protocol.FlagUnicodeClean

	return cleanOutput, flags
}