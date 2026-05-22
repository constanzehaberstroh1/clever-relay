package dataengine

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ──────────────────────────────────────────────────────────────────────────────
// Protocol – the high-level API that combines:
//   1. Binary serialization   (TunnelPacket → raw bytes)
//   2. Zstd compression       (raw bytes → compressed bytes)
//   3. ChaCha20-Poly1305      (compressed bytes → encrypted ciphertext)
//
// On the wire, every HTTP POST body contains exactly one sealed envelope
// produced by Seal(). The receiver calls Open() to reverse the pipeline.
// ──────────────────────────────────────────────────────────────────────────────

// Protocol orchestrates the full serialize → compress → encrypt pipeline
// (and the reverse). It is safe for concurrent use because the underlying
// CryptoLayer and Zstd functions are safe.
type Protocol struct {
	crypto *CryptoLayer
}

// NewProtocol creates a Protocol instance from a 32-byte pre-shared key.
func NewProtocol(psk []byte) (*Protocol, error) {
	c, err := NewCryptoLayer(psk)
	if err != nil {
		return nil, err
	}
	return &Protocol{crypto: c}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Serialization helpers
// ──────────────────────────────────────────────────────────────────────────────

// serialize converts a TunnelPacket into its compact binary representation.
//
// Wire format:
//
//	[1]  Version
//	[1]  Command
//	[16] SessionID
//	[4]  SeqNum   (big-endian)
//	[2]  TargetLen (big-endian)
//	[N]  Target   (UTF-8 bytes, length = TargetLen)
//	[M]  Payload  (raw bytes, length = total - header - N)
func serialize(pkt *TunnelPacket) ([]byte, error) {
	targetLen := len(pkt.Target)
	if targetLen > MaxTargetLen {
		return nil, fmt.Errorf("target address too long: %d > %d", targetLen, MaxTargetLen)
	}

	totalLen := HeaderSize + targetLen + len(pkt.Payload)
	buf := make([]byte, totalLen)

	// Fixed header
	buf[0] = pkt.Version
	buf[1] = pkt.Command
	copy(buf[2:18], pkt.SessionID[:])
	binary.BigEndian.PutUint32(buf[18:22], pkt.SeqNum)
	binary.BigEndian.PutUint16(buf[22:24], uint16(targetLen))

	// Variable-length fields
	if targetLen > 0 {
		copy(buf[HeaderSize:HeaderSize+targetLen], pkt.Target)
	}
	if len(pkt.Payload) > 0 {
		copy(buf[HeaderSize+targetLen:], pkt.Payload)
	}

	return buf, nil
}

// deserialize reconstructs a TunnelPacket from raw bytes.
func deserialize(raw []byte) (*TunnelPacket, error) {
	if len(raw) < HeaderSize {
		return nil, errors.New("packet too short: need at least 24 bytes")
	}

	pkt := &TunnelPacket{
		Version: raw[0],
		Command: raw[1],
	}
	copy(pkt.SessionID[:], raw[2:18])
	pkt.SeqNum = binary.BigEndian.Uint32(raw[18:22])

	targetLen := int(binary.BigEndian.Uint16(raw[22:24]))
	if targetLen > MaxTargetLen {
		return nil, fmt.Errorf("target length %d exceeds max %d", targetLen, MaxTargetLen)
	}

	remaining := len(raw) - HeaderSize
	if remaining < targetLen {
		return nil, fmt.Errorf("packet truncated: need %d bytes for target, have %d", targetLen, remaining)
	}

	if targetLen > 0 {
		pkt.Target = string(raw[HeaderSize : HeaderSize+targetLen])
	}

	payloadLen := remaining - targetLen
	if payloadLen > 0 {
		// Make a safe copy so the caller can release the original buffer.
		pkt.Payload = make([]byte, payloadLen)
		copy(pkt.Payload, raw[HeaderSize+targetLen:])
	}

	return pkt, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

// Seal takes a TunnelPacket, serializes it to a compact binary form,
// compresses it with Zstd, encrypts it with ChaCha20-Poly1305, and wraps
// the result with random-length padding for DPI traffic obfuscation.
//
// The returned byte slice is ready to be placed into an HTTP POST body.
func (p *Protocol) Seal(pkt *TunnelPacket) ([]byte, error) {
	// 1. Serialize
	raw, err := serialize(pkt)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	// 2. Compress
	compressed, err := Compress(raw, nil)
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}

	// 3. Encrypt (nonce is prepended automatically)
	sealed, err := p.crypto.Encrypt(compressed, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// 4. Add random padding for traffic obfuscation (Phase 5)
	padded, err := AddPadding(sealed)
	if err != nil {
		return nil, fmt.Errorf("padding: %w", err)
	}

	return padded, nil
}

// Open reverses Seal: strips padding, decrypts, decompresses, and deserializes
// the ciphertext back into a TunnelPacket.
//
// If the Poly1305 authentication tag is invalid (DPI probe, corrupted data),
// Open returns ErrAuthFailed. Callers should silently drop the connection
// without sending any response (Silent Drop strategy).
func (p *Protocol) Open(ciphertext []byte) (*TunnelPacket, error) {
	// 0. Strip random padding (Phase 5)
	envelope, err := RemovePadding(ciphertext)
	if err != nil {
		// Might be a legacy unpadded envelope — try direct decryption
		envelope = ciphertext
	}

	// 1. Decrypt
	compressed, err := p.crypto.Decrypt(envelope, nil)
	if err != nil {
		// If padding removal produced garbage, try the original ciphertext
		if envelope != nil {
			compressed, err = p.crypto.Decrypt(ciphertext, nil)
			if err != nil {
				return nil, err // ErrAuthFailed — silent drop
			}
		} else {
			return nil, err
		}
	}

	// 2. Decompress
	raw, err := Decompress(compressed, nil)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	// 3. Deserialize
	pkt, err := deserialize(raw)
	if err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}

	return pkt, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Batch helpers – used by the Micro-Batching system (Phase 4)
// ──────────────────────────────────────────────────────────────────────────────

// SealBatch seals multiple packets into individually encrypted envelopes.
// Each envelope is length-prefixed (4 bytes big-endian) for framing.
//
// Wire format: [4B len1][envelope1][4B len2][envelope2]...
func (p *Protocol) SealBatch(pkts []*TunnelPacket) ([]byte, error) {
	var result []byte
	for i, pkt := range pkts {
		envelope, err := p.Seal(pkt)
		if err != nil {
			return nil, fmt.Errorf("sealing packet %d: %w", i, err)
		}
		// Length prefix (4 bytes, big-endian)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(envelope)))
		result = append(result, lenBuf[:]...)
		result = append(result, envelope...)
	}
	return result, nil
}

// OpenBatch reverses SealBatch: reads length-prefixed envelopes and decrypts
// each one. On the first authentication failure it returns an error (the
// caller should silent-drop the entire batch).
func (p *Protocol) OpenBatch(data []byte) ([]*TunnelPacket, error) {
	var pkts []*TunnelPacket
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			return nil, errors.New("batch: truncated length prefix")
		}
		envLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4

		if offset+envLen > len(data) {
			return nil, fmt.Errorf("batch: envelope %d truncated (need %d, have %d)",
				len(pkts), envLen, len(data)-offset)
		}
		envelope := data[offset : offset+envLen]
		offset += envLen

		pkt, err := p.Open(envelope)
		if err != nil {
			return nil, fmt.Errorf("batch: opening envelope %d: %w", len(pkts), err)
		}
		pkts = append(pkts, pkt)
	}

	return pkts, nil
}
