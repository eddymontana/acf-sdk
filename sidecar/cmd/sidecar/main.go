// main.go — sidecar entrypoint.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/c2siorg/acf-sdk/sidecar/internal/crypto"
	"github.com/c2siorg/acf-sdk/sidecar/internal/transport"
)

func main() {
	log.Println("==========================================")
	log.Println("   🛡️ ACF Security Sidecar (Go-PDP)       ")
	log.Println("   Status: Phase 2 - Pipeline Active     ")
	log.Println("==========================================")

	// 1. Load HMAC key from environment (Tharindu's Way)
	signer, err := crypto.NewSignerFromEnv()
	if err != nil {
		log.Fatalf("sidecar: failed to load HMAC key: %v", err)
	}

	// 2. Start nonce store with 5-minute TTL
	nonceStore := crypto.NewNonceStore(5 * time.Minute)
	defer nonceStore.Stop()

	// 3. Resolve IPC address
	// This uses your Named Pipe logic for Windows by default
	connector := transport.DefaultConnector()
	address := connector.DefaultAddress()
	if p := os.Getenv("ACF_SOCKET_PATH"); p != "" {
		address = p
	}

	// 4. Create and start listener
	ln, err := transport.NewListener(transport.Config{
		Address:    address,
		Connector:  connector,
		Signer:     signer,
		NonceStore: nonceStore,
	})
	if err != nil {
		log.Fatalf("sidecar: failed to create listener on %s: %v", address, err)
	}

	log.Printf("sidecar: listening on %s", address)

	// 5. Serve in background; block on shutdown signal
	serveErr := make(chan error, 1)
	go func() { serveErr <- ln.Serve() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		log.Printf("sidecar: received %s, shutting down", sig)
		ln.Stop()
	case err := <-serveErr:
		if err != nil {
			log.Fatalf("sidecar: listener error: %v", err)
		}
	}
}