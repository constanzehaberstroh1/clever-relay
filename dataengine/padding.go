package dataengine

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	mrand "math/rand"
)

// ──────────────────────────────────────────────────────────────────────────────
// Random Padding – Traffic Obfuscation Layer
//
// Iran's DPI systems use AI-based traffic analysis that looks for fixed-size
// HTTP request patterns. By appending cryptographically random padding bytes
// to every sealed envelope, we make every packet a unique, unpredictable
// length. The padding is stripped transparently by the receiver.
//
// Wire format (wrapping the existing sealed envelope):
//
//   [2B]  PaddingLen  (big-endian uint16 — length of the trailing padding)
//   [NB]  Envelope    (the original Seal() output)
//   [PB]  Padding     (PaddingLen bytes of crypto/rand noise)
//
// The maximum padding is 512 bytes, and the minimum is 16 bytes.
// The distribution is weighted toward smaller pads (exponential) to avoid
// wasting bandwidth while still defeating fixed-pattern detection.
// ──────────────────────────────────────────────────────────────────────────────

const (
	// PaddingHeaderSize is the 2-byte prefix that encodes the padding length.
	PaddingHeaderSize = 2

	// MinPadding is the minimum number of random bytes appended.
	MinPadding = 16

	// MaxPadding is the maximum number of random bytes appended.
	MaxPadding = 512
)

// ErrPaddingTruncated is returned when the padded envelope is too short.
var ErrPaddingTruncated = errors.New("padded envelope truncated")

// AddPadding wraps an encrypted envelope with random-length padding.
func AddPadding(envelope []byte) ([]byte, error) {
	// Exponential distribution biased toward smaller values
	padLen := MinPadding + mrand.Intn(MaxPadding-MinPadding+1)

	// Further bias: take the minimum of two random draws (smaller values more likely)
	padLen2 := MinPadding + mrand.Intn(MaxPadding-MinPadding+1)
	if padLen2 < padLen {
		padLen = padLen2
	}

	// Build output: [2B padLen] [envelope] [padding]
	out := make([]byte, PaddingHeaderSize+len(envelope)+padLen)
	binary.BigEndian.PutUint16(out[:PaddingHeaderSize], uint16(padLen))
	copy(out[PaddingHeaderSize:], envelope)

	// Fill padding with cryptographically random bytes
	if _, err := rand.Read(out[PaddingHeaderSize+len(envelope):]); err != nil {
		return nil, err
	}

	return out, nil
}

// RemovePadding strips the random padding and returns the original envelope.
func RemovePadding(data []byte) ([]byte, error) {
	if len(data) < PaddingHeaderSize {
		return nil, ErrPaddingTruncated
	}

	padLen := int(binary.BigEndian.Uint16(data[:PaddingHeaderSize]))

	envelopeEnd := len(data) - padLen
	if envelopeEnd <= PaddingHeaderSize {
		return nil, ErrPaddingTruncated
	}

	return data[PaddingHeaderSize:envelopeEnd], nil
}
