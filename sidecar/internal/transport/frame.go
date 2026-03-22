// Package transport handles binary frame encoding/decoding for IPC.
//
// Request frame layout (54-byte header + variable payload):
//  [0]      magic     — 0xAC
//  [1]      version   — 1
//  [2:6]    length    — uint32 (Payload size)
//  [6:22]   nonce     — 16B (Replay protection)
//  [22:54]  hmac      — 32B (Integrity)
//  [54:]    payload   — JSON RiskContext
package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/c2siorg/acf-sdk/sidecar/internal/crypto"
)

const (
	MagicByte      = byte(0xAC)
	VersionByte    = byte(0x01)
	HeaderSize     = 54 // 1 + 1 + 4 + 16 + 32
	MaxPayloadSize = 10 * 1024 * 1024 // 🛡️ 10MB Safety Cap

	DecisionAllow    = byte(0x00)
	DecisionSanitise = byte(0x01)
	DecisionBlock    = byte(0x02)
)

var (
	ErrBadMagic    = errors.New("transport: bad magic byte")
	ErrBadVersion  = errors.New("transport: unsupported version")
	ErrPayloadSize = errors.New("transport: payload exceeds safety limit")
)

type RequestFrame struct {
	Version byte
	Nonce   [16]byte
	HMAC    [32]byte
	Payload []byte
}

type ResponseFrame struct {
	Decision         byte
	SanitisedPayload []byte
}

// SignedMessage prepares the byte slice for HMAC signing/verification.
func SignedMessage(version byte, length uint32, nonce [16]byte, payload []byte) []byte {
	buf := make([]byte, 1+4+16+len(payload))
	buf[0] = version
	binary.BigEndian.PutUint32(buf[1:5], length)
	copy(buf[5:21], nonce[:])
	copy(buf[21:], payload)
	return buf
}

// DecodeRequest reads a request frame from the connection safely.
func DecodeRequest(r io.Reader) (*RequestFrame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	// 1. Validate Protocol
	if header[0] != MagicByte {
		return nil, ErrBadMagic
	}
	if header[1] != VersionByte {
		return nil, ErrBadVersion
	}

	// 2. Validate Length
	length := binary.BigEndian.Uint32(header[2:6])
	if length > MaxPayloadSize {
		return nil, ErrPayloadSize
	}

	// 3. Read Payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	rf := &RequestFrame{
		Version: header[1],
		Payload: payload,
	}
	copy(rf.Nonce[:], header[6:22])
	copy(rf.HMAC[:], header[22:54])
	return rf, nil
}

// EncodeResponse packs a policy decision for the SDK.
func EncodeResponse(resp *ResponseFrame) []byte {
	sanLen := uint32(len(resp.SanitisedPayload))
	buf := make([]byte, 5+len(resp.SanitisedPayload))
	buf[0] = resp.Decision
	binary.BigEndian.PutUint32(buf[1:5], sanLen)
	if sanLen > 0 {
		copy(buf[5:], resp.SanitisedPayload)
	}
	return buf
}

// EncodeRequest is used by tests/SDK to simulate a client.
func EncodeRequest(payload []byte, s *crypto.Signer) ([]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	length := uint32(len(payload))
	msg := SignedMessage(VersionByte, length, nonce, payload)
	mac := s.Sign(msg)

	frame := make([]byte, HeaderSize+len(payload))
	frame[0] = MagicByte
	frame[1] = VersionByte
	binary.BigEndian.PutUint32(frame[2:6], length)
	copy(frame[6:22], nonce[:])
	copy(frame[22:54], mac)
	copy(frame[54:], payload)
	return frame, nil
}