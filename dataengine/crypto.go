package dataengine

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ──────────────────────────────────────────────────────────────────────────────
// ChaCha20-Poly1305 AEAD encryption layer with Silent Drop
//
// Why ChaCha20 over AES-GCM?
// • 3× faster on ARM / devices without AES-NI hardware acceleration.
// • Constant-time by design — no timing side channels.
// • Combined with the Poly1305 authenticator tag, any tampered byte causes
//   Open() to fail, enabling the Silent Drop anti-probing strategy.
//
// Silent Drop strategy: when authentication fails (DPI probe, corrupted
// packet, replay attempt), we return a generic error with no distinguishing
// information. The caller should silently discard the packet and close the
// connection without sending any response, making the server appear as a
// black hole to active probing scanners.
// ──────────────────────────────────────────────────────────────────────────────

// PSKSize is the required pre-shared key length in bytes (256-bit).
const PSKSize = 32

// ErrInvalidPSK is returned when the provided key is not exactly 32 bytes.
var ErrInvalidPSK = errors.New("PSK must be exactly 32 bytes")

// ErrAuthFailed is the opaque error returned on any authentication failure.
// Intentionally generic to avoid leaking information to DPI probes.
var ErrAuthFailed = errors.New("packet authentication failed")

// ErrPayloadTooShort is returned when the encrypted payload is shorter than
// the minimum possible length (nonce + tag).
var ErrPayloadTooShort = errors.New("encrypted payload too short")

// CryptoLayer wraps a ChaCha20-Poly1305 AEAD cipher for symmetric
// encrypt-then-authenticate and decrypt-then-verify operations.
type CryptoLayer struct {
	aead cipher.AEAD
}

// NewCryptoLayer creates a CryptoLayer from a 32-byte pre-shared key.
func NewCryptoLayer(psk []byte) (*CryptoLayer, error) {
	if len(psk) != PSKSize {
		return nil, ErrInvalidPSK
	}
	aead, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, fmt.Errorf("creating ChaCha20-Poly1305 AEAD: %w", err)
	}
	return &CryptoLayer{aead: aead}, nil
}

// Encrypt encrypts plaintext and prepends a random nonce.
// The returned ciphertext is: nonce || AEAD.Seal(plaintext).
// The optional additionalData is authenticated but not encrypted (can be nil).
func (c *CryptoLayer) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Seal appends the ciphertext+tag after the nonce slice.
	// Result layout: [nonce | ciphertext | poly1305-tag]
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt decrypts a ciphertext that was produced by Encrypt.
// It extracts the nonce prefix, verifies the Poly1305 tag, and returns
// the original plaintext.
//
// On any failure (wrong key, tampered data, truncated payload), it returns
// ErrAuthFailed to support the Silent Drop strategy.
func (c *CryptoLayer) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize+c.aead.Overhead() {
		return nil, ErrPayloadTooShort
	}

	nonce := ciphertext[:nonceSize]
	sealed := ciphertext[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, sealed, additionalData)
	if err != nil {
		// Silent Drop: return opaque error regardless of failure reason.
		return nil, ErrAuthFailed
	}

	return plaintext, nil
}

// NonceSize returns the nonce length used by the underlying AEAD.
func (c *CryptoLayer) NonceSize() int {
	return c.aead.NonceSize()
}

// Overhead returns the maximum difference between plaintext and ciphertext
// lengths (i.e., the Poly1305 tag size).
func (c *CryptoLayer) Overhead() int {
	return c.aead.Overhead()
}
