// listener.go — IPC accept loop.
package transport

import (
	"log"
	"net"

	"github.com/c2siorg/acf-sdk/sidecar/internal/crypto"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

// Config holds listener configuration.
type Config struct {
	Address    string
	Connector  Connector
	Signer     *crypto.Signer
	NonceStore *crypto.NonceStore
	// Pipeline is added here to bridge to Phase 2
	Pipeline   PipelineInterface 
}

type PipelineInterface interface {
	Process(ctx *riskcontext.RiskContext)
}

// Listener wraps a platform net.Listener.
type Listener struct {
	cfg    Config
	ln     net.Listener
	stopCh chan struct{}
}

func NewListener(cfg Config) (*Listener, error) {
	if cfg.Address == "" {
		cfg.Address = cfg.Connector.DefaultAddress()
	}
	if err := cfg.Connector.Cleanup(cfg.Address); err != nil {
		return nil, err
	}
	ln, err := cfg.Connector.Listen(cfg.Address)
	if err != nil {
		return nil, err
	}
	return &Listener{cfg: cfg, ln: ln, stopCh: make(chan struct{})}, nil
}

func (l *Listener) Serve() error {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.stopCh:
				return nil
			default:
				return err
			}
		}
		go l.handleConn(conn)
	}
}

func (l *Listener) Stop() {
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
	l.ln.Close()
}

func (l *Listener) handleConn(conn net.Conn) {
	defer conn.Close()

	// 1. Decode using your Binary Frame logic
	rf, err := DecodeRequest(conn)
	if err != nil {
		log.Printf("transport: decode error: %v", err)
		return
	}

	// 2. Verify HMAC using Tharindu's Signer
	length := uint32(len(rf.Payload))
	signedMsg := SignedMessage(rf.Version, length, rf.Nonce, rf.Payload)
	if !l.cfg.Signer.Verify(signedMsg, rf.HMAC[:]) {
		log.Printf("transport: security alert: HMAC mismatch")
		return
	}

	// 3. Check nonce replay using Tharindu's Store
	if l.cfg.NonceStore.Seen(rf.Nonce[:]) {
		log.Printf("transport: security alert: Replay detected")
		return
	}

	// 4. Phase 2: Execute your Pipeline
	ctx := &riskcontext.RiskContext{
		RawPayload: string(rf.Payload),
		Signals:    make(map[string]interface{}),
	}

	// This is where your Scan/Normalise/OPA logic is called
	if l.cfg.Pipeline != nil {
		l.cfg.Pipeline.Process(ctx)
	}

	// 5. Encode and Write Response
	respFrame := &ResponseFrame{
		Decision: mapDecision(ctx.RiskScore),
		Reason:   "policy_evaluation_complete",
	}
	
	resp := EncodeResponse(respFrame)
	if _, err := conn.Write(resp); err != nil {
		log.Printf("transport: write error: %v", err)
	}
}

func mapDecision(score float64) string {
	if score >= 100 {
		return "BLOCK"
	}
	return "ALLOW"
}