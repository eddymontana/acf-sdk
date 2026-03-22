// normalise.go — Stage 2 of the pipeline.
package pipeline

import (
	"encoding/base64"
	"net/url"
	"strings"
	"unicode"

	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
	"golang.org/x/text/unicode/norm"
)

// Normalise produces canonical text for scanning.
func Normalise(ctx *riskcontext.RiskContext) {
	text := ctx.RawPayload

	// 1. Recursive Decoding (URL, Base64)
	// Peel back layers of obfuscation (up to 3 levels to avoid recursion bombs)
	for i := 0; i < 3; i++ {
		decoded := tryDecode(text)
		if decoded == text {
			break
		}
		text = decoded
	}

	// 2. Unicode NFKC Normalisation
	// Combines characters like 'e' + '´' into 'é' to defeat visual spoofing
	text = norm.NFKC.String(text)

	// 3. Zero-Width Character Stripping
	// Removes invisible markers used to break pattern matching
	text = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Variation_Selector, r) || 
		   r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
			return -1
		}
		return r
	}, text)

	// 4. Leetspeak Cleaning & Lowercasing
	// Standardize 4 -> a, 3 -> e, etc. for the Lexical Scanner
	replacer := strings.NewReplacer(
		"0", "o", 
		"1", "i", 
		"!", "i",
		"3", "e", 
		"4", "a", 
		"@", "a",
		"5", "s", 
		"$", "s",
		"7", "t",
	)
	text = replacer.Replace(strings.ToLower(text))

	// 5. Store canonical text for Stage 3 (Scan)
	ctx.Signals["normalized_text"] = text
}

// tryDecode attempts to strip one layer of URL or Base64 encoding.
func tryDecode(input string) string {
	// Try URL Decoding
	if strings.Contains(input, "%") {
		if u, err := url.QueryUnescape(input); err == nil && u != input {
			return u
		}
	}

	// Try Base64 Decoding (Only if it looks like Base64 to save CPU)
	if len(input) > 4 && len(input)%4 == 0 {
		if b, err := base64.StdEncoding.DecodeString(input); err == nil {
			return string(b)
		}
	}

	return input
}