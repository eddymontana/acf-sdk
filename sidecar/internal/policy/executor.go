// executor.go — reads the OPA decision output, calls sanitise if needed,
// and assembles the final Result returned to the transport layer.
// OPA declares *what* to sanitise; this file performs the actual transformation.
package policy
