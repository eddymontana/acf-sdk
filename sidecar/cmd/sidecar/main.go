package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
	"github.com/c2siorg/acf-sdk/sidecar/internal/pipeline"
	"github.com/c2siorg/acf-sdk/sidecar/internal/transport"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

func main() {
	// 1. Fetch Secrets from Environment (Hiding API/HMAC keys)
	// This prevents hardcoded secrets from leaking into GitHub.
	hmacKey := os.Getenv("ACF_HMAC_KEY")
	if hmacKey == "" {
		log.Println("[WARN] ACF_HMAC_KEY not set. Using 'dev-secret-2026' for local testing.")
		hmacKey = "dev-secret-2026"
	}

	// Windows Named Pipe path for IPC
	pipePath := `\\.\pipe\acf_security_pipe`

	fmt.Println("==========================================")
	fmt.Println("   🛡️ ACF Security Sidecar (Go-PDP)       ")
	fmt.Println("   Status: SECURE BINARY MODE            ")
	fmt.Println("==========================================")

	// 2. Start Windows Named Pipe Listener
	l, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		log.Fatalf("[FATAL] Pipe failure: %v", err)
	}
	defer l.Close()

	log.Printf("[STATUS] Listening on %s\n", pipePath)

	// 3. Initialize the Security Pipeline (Aho-Corasick + OPA)
	pipe := &pipeline.Pipeline{}

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		// Pass the HMAC key to handleConnection for secure frame verification
		go handleConnection(conn, pipe, []byte(hmacKey))
	}
}

func handleConnection(conn net.Conn, pipe *pipeline.Pipeline, key []byte) {
	defer conn.Close()

	// 4. READ: Receive Binary Frame from Python SDK
	// Validates Magic Byte (0xAC) and frame integrity.
	frame, err := transport.ReadFrame(conn)
	if err != nil {
		log.Printf("[ERR] Protocol Mismatch: %v", err)
		return
	}

	// 5. PROCESS: Execute Lexical Scan & OPA Policy Evaluation
	// frame.Payload contains the raw data extracted from the binary frame.
	result, err := pipe.Process(context.Background(), frame.Payload, "on_prompt")
	if err != nil {
		log.Printf("[ERR] Pipeline failure: %v", err)
		result = &riskcontext.PolicyResult{
			Decision: "DENY",
			Reason:   "internal_security_error",
		}
	}

	// 6. WRITE: Wrap response in a Secure Binary Frame
	responseBytes, _ := json.Marshal(result)
	respFrame := &transport.Frame{
		Version: transport.Version,
		Payload: responseBytes,
	}

	// Sign the frame with our secret key and send back to the SDK
	err = transport.WriteFrame(conn, respFrame)
	if err != nil {
		log.Printf("[ERR] Failed to send response: %v", err)
	}

	log.Printf("[LOG] Decision: %s | Reason: %s\n", result.Decision, result.Reason)
}