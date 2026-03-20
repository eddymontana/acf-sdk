package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
	// LOCAL IMPORT: Must match the name in your 'go mod init sidecar'
	"sidecar/internal/pipeline"
)

func main() {
	// 1. Setup the Windows Named Pipe path for IPC (Inter-Process Communication)
	// The Python SDK will look for this specific address.
	pipePath := `\\.\pipe\acf_security_pipe`

	// 2. Security Check: Key management for the Kernel's internal crypto functions.
	if os.Getenv("ACF_SECRET_KEY") == "" {
		log.Println("[WARN] ACF_SECRET_KEY not set. Using 'dev-key' for local testing.")
		os.Setenv("ACF_SECRET_KEY", "dev-key")
	}

	fmt.Println("=== ACF Security Kernel (Go-PDP) v0.2 Running ===")

	// 3. Start the Listener for Windows using Named Pipes.
	l, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		log.Fatalf("[FATAL] Failed to start pipe listener: %v", err)
	}
	defer l.Close()

	log.Printf("[STATUS] Listening for Python SDK on %s\n", pipePath)

	// 4. Initialize the Pipeline Orchestrator.
	// This maintains the state of our scanning stages.
	pipe := &pipeline.Pipeline{}

	// 5. The Service Loop: Keeps the sidecar alive to handle multiple requests.
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("[ERR] Connection failed: %v", err)
			continue
		}

		// Handle each request concurrently in a Goroutine to prevent blocking.
		go handleConnection(conn, pipe)
	}
}

func handleConnection(conn net.Conn, pipe *pipeline.Pipeline) {
	defer conn.Close()

	// Read raw payload from the Python SDK.
	// 4KB is standard, though LLM prompts can be larger (adjustable).
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	// 6. Execute the Security Pipeline.
	// Validate -> Normalise -> Scan -> Aggregate -> Policy (OPA)
	result, err := pipe.Process(context.Background(), buf[:n], "on_prompt")
	if err != nil {
		log.Printf("[ERR] Pipeline failure: %v", err)
		// Fail-safe: Always DENY if the security logic itself fails.
		conn.Write([]byte(`{"decision":"DENY","reason":"internal_pipeline_error"}`))
		return
	}

	// 7. Marshal the PolicyResult to JSON.
	// This allows the Python SDK to see the decision and the reason.
	responseBytes, err := json.Marshal(result)
	if err != nil {
		log.Printf("[ERR] JSON Marshalling failed: %v", err)
		return
	}
	
	conn.Write(responseBytes)

	log.Printf("[LOG] Handled Request. Decision: %s | Reason: %s\n",
		result.Decision, result.Reason)
}