package pipeline

import (
	"regexp"
	"strings"

	// LOCAL IMPORT: Using the 'sidecar' module prefix
	"sidecar/pkg/riskcontext"
	"golang.org/x/text/unicode/norm"
)

var (
	// Regex to identify hidden characters:
	// - Control characters (\x00-\x1F, \x7F-\x9F)
	// - Soft hyphens (\xAD)
	// - Zero-width spaces and Joiners (\x{200B}-\x{200D})
	// - Byte Order Marks (\x{FEFF})
	nonPrintableRegex = regexp.MustCompile(`[\x00-\x1F\x7F-\x9F\xAD\x{200B}-\x{200D}\x{FEFF}]`)
)

// Normalise cleanses the input to prevent "Obfuscation" attacks.
// It uses Unicode NFKC (Compatibility Decomposition, followed by Canonical Composition).
func Normalise(ctx *riskcontext.RiskContext) {
	input := ctx.RawPayload

	// 1. Unicode Normalization (NFKC)
	// This collapses visually identical characters (e.g., 'ⓐ' becomes 'a')
	// to prevent attackers from hiding "jailbreak" words in fancy fonts.
	normalized := norm.NFKC.String(input)

	// 2. Strip Zero-Width and Non-Printable characters
	// These are often used to split up "banned" words so filters don't see them.
	normalized = nonPrintableRegex.ReplaceAllString(normalized, "")

	// 3. Lowercase for consistent downstream regex matching
	normalized = strings.ToLower(normalized)

	// 4. Update the Signals map
	// The 'Scan' stage will look for this key first.
	ctx.Signals["normalized_payload"] = normalized
}