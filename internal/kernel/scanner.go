package kernel

import (
	"regexp"
	"github.com/eddymontana/acf-sdk/internal/protocol"
)

// High-speed Deterministic Patterns
var (
	sqlInjection  = regexp.MustCompile(`(?i)(SELECT|INSERT|DELETE|DROP|UPDATE|OR\s+1=1|--|/\*)`)
	promptEvasion = regexp.MustCompile(`(?i)(ignore\s+previous|system\s+prompt|dan\s+mode|as\s+an\s+ai|you\s+are\s+now|disregard)`)
)

func LexicalScan(input string) protocol.StatusFlags {
	var flags protocol.StatusFlags

	if sqlInjection.MatchString(input) {
		flags |= protocol.FlagSqlInjectionDetected
	}

	if promptEvasion.MatchString(input) {
		flags |= protocol.FlagPromptInjectionDetected
	}

	return flags
}