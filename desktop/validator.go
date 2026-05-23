package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/salman/clever-relay/dataengine"
)

var gasURLRegex = regexp.MustCompile(`^https://script\.google\.com/macros/s/[A-Za-z0-9_-]+/exec$`)

// ValidationResult represents the output of validating a GAS script.
type ValidationResult struct {
	IsValid bool          `json:"is_valid"`
	Error   string        `json:"error"`
	Latency time.Duration `json:"latency"`
}

// ValidateGASNode checks if the URL format is correct, performs a lightweight SOCKS-level handshake,
// and returns the latency and correctness.
func ValidateGASNode(gasURL string, psk []byte) ValidationResult {
	// 1. Regex validation
	if !gasURLRegex.MatchString(gasURL) {
		return ValidationResult{
			IsValid: false,
			Error:   "Invalid GAS URL format. Must match https://script.google.com/macros/s/.../exec",
		}
	}

	// 2. HTTP Round-trip validation with encryption check
	proto, err := dataengine.NewProtocol(psk)
	if err != nil {
		return ValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("Failed to initialize cryptographic protocol: %v", err),
		}
	}

	// Build a dummy connect command payload (or UDP payload) to check end-to-end traversal
	// We'll send a connection request to an invalid port or a dummy target just to see if the
	// exit node decrypts it and returns a valid binary envelope.
	dummySid, _ := dataengine.NewSessionID()
	connectPkt := &dataengine.TunnelPacket{
		Version:   dataengine.ProtocolVersion,
		Command:   dataengine.CmdTCPConnect,
		SessionID: dummySid,
		SeqNum:    0,
		Target:    "127.0.0.1:9999", // A target that won't succeed, but should return a response
	}

	sealed, err := proto.Seal(connectPkt)
	if err != nil {
		return ValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("Failed to encrypt test packet: %v", err),
		}
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	u, _ := url.Parse(gasURL)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(sealed))
	if err != nil {
		return ValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("Failed to create HTTP request: %v", err),
		}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// Set GetBody for redirect preservation
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(sealed)), nil
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return ValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("Relay connection timed out or failed: %v", err),
			Latency: latency,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return ValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("Relay script returned HTTP status %d", resp.StatusCode),
			Latency: latency,
		}
	}

	// Read response body - if the exit node returned a valid encrypted envelope (e.g. CmdTCPClose or dial fail response)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ValidationResult{
			IsValid: false,
			Error:   "Failed to read validation response",
			Latency: latency,
		}
	}

	// Try opening the response packet using the PSK
	if len(body) > 0 {
		_, err := proto.Open(body)
		if err != nil {
			return ValidationResult{
				IsValid: false,
				Error:   "Decryption error: Validation signature verification failed (invalid PSK or exit node mismatch)",
				Latency: latency,
			}
		}
	}

	return ValidationResult{
		IsValid: true,
		Latency: latency,
	}
}
