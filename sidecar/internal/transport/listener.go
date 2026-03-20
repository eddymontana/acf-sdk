package transport

import (
	"context" // Added context for compatibility with Process()
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	// LOCAL IMPORTS: Using the 'sidecar' module prefix
	"sidecar/internal/crypto"
	"sidecar/internal/pipeline"
)

// In production, this would be loaded from a secure environment variable or KMS
var sharedSecret = []byte("gsoc-acf-super-secret-key-2026")

// StartUDSListener sets up the Unix Domain Socket (or Named Pipe) server.
// Since we are on Windows for this build, we use the pipe logic from main.go,
// but this listener handles the higher-level connection logic.
func StartUDSListener(socketPath string) {
	if _, err := os.Stat(socketPath); err == nil {
		os.Remove(socketPath)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to start UDS listener: %v", err)
	}
	defer listener.Close()

	log.Printf("🛡️ ACF Kernel Active: Listening on %s", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Connection Error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	
	// Initialize the Pipeline Orchestrator (Orchestrates scans and policy)
	p := &pipeline.Pipeline{}

	for {
		// 1. Read the Binary Frame (The Envelope)
		// Note: ReadFrame must be defined in your transport package
		frame, err := ReadFrame(conn)
		if err != nil {
			if err == io.EOF {
				log.Println("🔌 SDK Disconnected.")
				return
			}
			log.Printf("⚠️ Security Warning: Malformed frame: %v", err)
			return
		}

		// 2. CRYPTO: Verify HMAC Integrity
		// This prevents "Man-in-the-Middle" or unauthorized prompt injections
		// from bypassing the kernel.
		if !crypto.VerifyHMAC(frame.Payload, frame.HMAC[:], sharedSecret) {
			log.Printf("🚫 SECURITY ALERT: HMAC Mismatch from %s! Dropping connection.", conn.RemoteAddr())
			return
		}

		// 3. PIPELINE: Process the verified payload
		// We pass a background context to the pipeline stages.
		result, err := p.Process(context.Background(), frame.Payload, "on_prompt")
		if err != nil {
			log.Printf("❌ Pipeline Error: %v", err)
			sendErrorResponse(conn, err.Error())
			continue
		}

		// 4. RESPONSE: Serialize the Result back to the SDK
		responseJSON, _ := json.Marshal(result)
		conn.Write(responseJSON)
		
		log.Printf("✅ Decision: %s | ID: %x...", result.Decision, frame.Nonce[:4])
	}
}

func sendErrorResponse(conn net.Conn, message string) {
	resp := fmt.Sprintf(`{"decision": "ERROR", "reason": "%s"}`, message)
	conn.Write([]byte(resp))
}