package transport

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	// NATIVE WINDOWS IPC
	"github.com/Microsoft/go-winio"

	// MODULE-ALIGNED IMPORTS
	"github.com/c2siorg/acf-sdk/sidecar/internal/crypto"
	"github.com/c2siorg/acf-sdk/sidecar/internal/pipeline"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

// getSharedSecret pulls the HMAC key from the environment.
func getSharedSecret() []byte {
	key := os.Getenv("ACF_HMAC_KEY")
	if key == "" {
		return []byte("gsoc-acf-super-secret-key-2026")
	}
	return []byte(key)
}

func StartUDSListener(unusedPath string) {
	pipePath := `\\.\pipe\acf_security_pipe`

	config := &winio.PipeConfig{
		MessageMode:      true,
		InputBufferSize:  65536,
		OutputBufferSize: 65536,
	}

	listener, err := winio.ListenPipe(pipePath, config)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to start Windows Named Pipe: %v", err)
	}
	defer listener.Close()

	log.Printf("🛡️ ACF Kernel Active: Listening on Named Pipe -> %s", pipePath)

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
	secret := getSharedSecret()

	for {
		// 1. Read the Binary Frame (Using the existing ReadFrame in frame.go)
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
		if !crypto.VerifyHMAC(frame.Payload, frame.HMAC[:], secret) {
			log.Printf("🚫 SECURITY ALERT: HMAC Mismatch!")
			sendErrorResponse(conn, "unauthorized: hmac mismatch")
			return
		}

		// 3. PIPELINE: Initialize RiskContext
		ctx := &riskcontext.RiskContext{
			RawPayload: string(frame.Payload),
			Signals:    make(map[string]interface{}),
		}

		// 4. SCAN: Run the Aho-Corasick Kernel
		pipeline.ExecuteLexicalScan(ctx)

		// 5. POLICY: Ask OPA for the final Decision
		isAllowed, reason, err := pipeline.EvaluatePolicy(ctx)
		if err != nil {
			log.Printf("❌ Policy Evaluation Error: %v", err)
			sendErrorResponse(conn, "policy_engine_failure")
			continue
		}

		decision := "ALLOW"
		if !isAllowed {
			decision = "DENY"
		}

		// 6. RESPONSE: Build and Send JSON
		response := fmt.Sprintf(`{"decision":"%s","reason":"%s","score":%v}`, 
			decision, reason, ctx.RiskScore)

		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("🔌 Pipe Write Error: %v", err)
			return
		}

		log.Printf("✅ OPA Decision: %s | Score: %v", decision, ctx.RiskScore)
	}
}

func sendErrorResponse(conn net.Conn, message string) {
	resp := fmt.Sprintf(`{"decision": "ERROR", "reason": "%s"}`, message)
	conn.Write([]byte(resp))
}
