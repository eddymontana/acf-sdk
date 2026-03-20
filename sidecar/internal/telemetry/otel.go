// Package telemetry handles async OpenTelemetry span emission and structured
// audit logging. Spans are emitted after each enforcement decision and never
// block the enforcement path. If the OTel sink is unavailable, enforcement
// continues unaffected.
package telemetry
