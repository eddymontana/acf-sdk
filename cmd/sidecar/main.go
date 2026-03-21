package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	// EXTERNAL DEPENDENCIES
	"github.com/Microsoft/go-winio"

	// MENTOR-ALIGNED INTERNAL IMPORTS
	// These match your 'go mod init github.com/c2siorg/acf-sdk/sidecar'
	"github.com/c2siorg/acf-sdk/sidecar/internal/pipeline"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

func main() {
	// 1. Setup the Windows Named Pipe path for IPC (Inter-Process Communication).
	// This is the standard address the Python SDK will use to talk to the Go Kernel.
	pipePath := `\\.\pipe\acf_security_pipe`

	// 2. Security Check: Key management for the Kernel's internal functions.
	if os.Getenv("ACF_SECRET_KEY") == "" {
		log.Println("[WARN] ACF_SECRET_KEY not set. Using 'dev-key' for local testing.")
		os.Setenv("ACF_SECRET_KEY", "dev-key")
	}

	fmt.Println("==========================================")
	fmt.Println("   ACF Security Kernel (Go-PDP) v0.2      ")
	fmt.Println("   Status: ALIGNED WITH UPSTREAM          ")
	fmt.Println("==========================================")

	// 3. Start the Listener for Windows using Named Pipes.
	l, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		log.Fatalf("[FATAL] Failed to start pipe listener: %v", err)
	}
	defer l.Close()

	log.Printf("[STATUS] Listening for Python SDK on %s\n", pipePath)

	// 4. Initialize the Pipeline Orchestrator.
	// This handles the flow: Validate -> Normalise -> Scan -> Aggregate -> Policy.
	pipe := &pipeline.Pipeline{}

	// 5. The Service Loop: Keeps the sidecar alive to handle multiple SDK requests.
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("[ERR] Connection failed: %v", err)
			continue
		}

		// Handle each request concurrently in a Goroutine.
		go handleConnection(conn, pipe)
	}
}

// handleConnection manages the lifecycle of a single SDK request.
func handleConnection(conn net.Conn, pipe *pipeline.Pipeline) {
	defer conn.Close()

	// Read raw payload from the Python SDK.
	// 4KB buffer for the initial prompt (adjustable for larger LLM contexts).
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	// 6. Execute the Security Pipeline.
	// We pass a Background Context and the 'on_prompt' hook type.
	result, err := pipe.Process(context.Background(), buf[:n], "on_prompt")
	if err != nil {
		log.Printf("[ERR] Pipeline failure: %v", err)
		
		// Fail-Closed: Return a DENY response if the pipeline errors out.
		errorResp := &riskcontext.PolicyResult{
			Decision: "DENY",
			Reason:   "internal_pipeline_error: " + err.Error(),
		}
		respBytes, _ := json.Marshal(errorResp)
		conn.Write(respBytes)
		return
	}

	// 7. Marshal the PolicyResult to JSON for the Python SDK.
	responseBytes, err := json.Marshal(result)
	if err != nil {
		log.Printf("[ERR] JSON Marshalling failed: %v", err)
		return
	}
	
	conn.Write(responseBytes)

	log.Printf("[LOG] Decision: %s | Reason: %s\n", result.Decision, result.Reason)
}