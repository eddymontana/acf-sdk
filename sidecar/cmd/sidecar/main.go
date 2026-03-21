package main

import (
	"log"
	"os"

	// MODULE-ALIGNED IMPORTS
	"github.com/c2siorg/acf-sdk/sidecar/internal/transport"
)

func main() {
	log.Println("=== 🛡️ ACF Sidecar (PDP) Phase 2 ===")

	// 1. Validate Environment (Phase 1 Requirement)
	hmacKey := os.Getenv("ACF_HMAC_KEY")
	if hmacKey == "" {
		log.Println("[WARNING] ACF_HMAC_KEY not set. Using default development key.")
		// In production, you would os.Exit(1) here.
	}

	// 2. Define the socket path
	// On Windows, this creates a local .sock file that Go handles via the 'unix' network.
	socketPath := "acf.sock"

	// 3. Start the Listener
	// This calls the StartUDSListener function in internal/transport/listener.go
	log.Printf("[STATUS] Initializing Pipe: %s", socketPath)
	transport.StartUDSListener(socketPath)
}