package pipeline

import (
	"strings"
	"unicode"
	"golang.org/x/text/unicode/norm"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

func Normalise(ctx *riskcontext.RiskContext) {
	text := ctx.RawPayload

	// 1. NFKC Normalization (Combines characters like 'e' + '´' into 'é')
	text = norm.NFKC.String(text)

	// 2. Remove Zero-Width characters (used to hide malicious text from scanners)
	text = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Variation_Selector, r) || r == '\u200B' || r == '\u200C' {
			return -1
		}
		return r
	}, text)

	// 3. Basic Leetspeak mapping (Simplified for Phase 2)
	replacer := strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t")
	text = replacer.Replace(strings.ToLower(text))

	ctx.Signals["normalized_text"] = text
}