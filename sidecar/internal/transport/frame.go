package transport

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	MagicByte = 0xAC // "AC" for ACF-SDK
	Version   = 0x01
)

// Frame represents the wire-format envelope
type Frame struct {
	Version uint8
	Length  uint32
	Nonce   [16]byte
	HMAC    [32]byte
	Payload []byte
}

// ReadFrame parses the binary data from the UDS connection
func ReadFrame(r io.Reader) (*Frame, error) {
	// 1. Check Magic Byte
	var magic uint8
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, err
	}
	if magic != MagicByte {
		return nil, errors.New("invalid magic byte: protocol mismatch")
	}

	frame := &Frame{}
	// 2. Read Version
	binary.Read(r, binary.BigEndian, &frame.Version)

	// 3. Read Length of Payload
	binary.Read(r, binary.BigEndian, &frame.Length)

	// 4. Read Nonce (to prevent replay attacks)
	io.ReadFull(r, frame.Nonce[:])

	// 5. Read HMAC (for integrity)
	io.ReadFull(r, frame.HMAC[:])

	// 6. Read Actual Payload
	frame.Payload = make([]byte, frame.Length)
	_, err := io.ReadFull(r, frame.Payload)

	return frame, err
}