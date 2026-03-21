package transport

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	MagicByte      = 0xAC 
	Version        = 0x01
	MaxPayloadSize = 10 * 1024 * 1024 // 🛡️ 10MB Cap to prevent OOM attacks
)

// Frame represents the wire-format envelope
type Frame struct {
	Version uint8
	Length  uint32
	Nonce   [16]byte
	HMAC    [32]byte
	Payload []byte
}

// ReadFrame parses the binary data from the connection with safety checks
func ReadFrame(r io.Reader) (*Frame, error) {
	// 1. Check Magic Byte
	var magic uint8
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, err
	}
	if magic != MagicByte {
		return nil, fmt.Errorf("protocol mismatch: expected 0x%X, got 0x%X", MagicByte, magic)
	}

	frame := &Frame{}
	
	// 2. Read Version
	if err := binary.Read(r, binary.BigEndian, &frame.Version); err != nil {
		return nil, err
	}

	// 3. Read Length and Validate
	if err := binary.Read(r, binary.BigEndian, &frame.Length); err != nil {
		return nil, err
	}
	if frame.Length > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d bytes (max %d)", frame.Length, MaxPayloadSize)
	}

	// 4. Read Nonce (Replay Protection)
	if _, err := io.ReadFull(r, frame.Nonce[:]); err != nil {
		return nil, err
	}

	// 5. Read HMAC (Integrity)
	if _, err := io.ReadFull(r, frame.HMAC[:]); err != nil {
		return nil, err
	}

	// 6. Read Actual Payload safely
	if frame.Length > 0 {
		frame.Payload = make([]byte, frame.Length)
		if _, err := io.ReadFull(r, frame.Payload); err != nil {
			return nil, err
		}
	}

	return frame, nil
}

// WriteFrame is the reverse: it packs a Frame into bytes for the connection
func WriteFrame(w io.Writer, f *Frame) error {
	// Write Magic, Version, and Length
	if err := binary.Write(w, binary.BigEndian, uint8(MagicByte)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, f.Version); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(f.Payload))); err != nil {
		return err
	}
	
	// Write Nonce, HMAC, and Payload
	if _, err := w.Write(f.Nonce[:]); err != nil {
		return err
	}
	if _, err := w.Write(f.HMAC[:]); err != nil {
		return err
	}
	_, err := w.Write(f.Payload)
	return err
}