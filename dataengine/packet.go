// Package dataengine provides the core binary protocol, cryptographic, and
// compression primitives for the Clever Relay tunnel. Every component in the
// system (local client, exit node, and Google Apps Script relay) speaks this
// protocol.
package dataengine

import (
	"crypto/rand"
	"fmt"
	"sync"
)

// ProtocolVersion is the current wire format version.
const ProtocolVersion uint8 = 0x01

// Command types used in the tunnel protocol header.
const (
	CmdTCPConnect uint8 = 0x01 // Initiate a new TCP connection to a target
	CmdTCPData    uint8 = 0x02 // Send raw TCP payload for an existing session
	CmdTCPClose   uint8 = 0x03 // Gracefully close a TCP session
	CmdUDPData    uint8 = 0x04 // Encapsulated UDP datagram (DNS, WebRTC, etc.)
	CmdPull       uint8 = 0x05 // Pull pending downstream data from exit node
)

// HeaderSize is the fixed-length binary header size in bytes.
//
// Layout:
//
//	[1B] Version
//	[1B] Command
//	[16B] SessionID (UUID)
//	[4B] SeqNum (big-endian uint32)
//	[2B] TargetLen (big-endian uint16)
//	Total = 24 bytes
const HeaderSize = 24

// MaxTargetLen caps the destination address length to prevent abuse.
const MaxTargetLen = 253 // max DNS name = 253 chars

// MaxPayloadSize caps a single packet payload (before compression).
// 256 KB aligns with the Micro-Chunker flush threshold.
const MaxPayloadSize = 256 * 1024

// TunnelPacket is the application-layer data unit exchanged between the
// local client and the exit node (via GAS). It is serialized into a
// compact binary format, compressed with Zstd, and encrypted with
// ChaCha20-Poly1305 before being placed in an HTTP POST body.
type TunnelPacket struct {
	Version   uint8    // Protocol version (always ProtocolVersion)
	Command   uint8    // One of Cmd* constants
	SessionID [16]byte // UUID identifying the logical connection
	SeqNum    uint32   // Monotonic sequence number for reassembly
	Target    string   // Destination address (host:port), set only on CmdTCPConnect / CmdUDPData
	Payload   []byte   // Raw TCP/UDP payload bytes
}

// NewSessionID generates a cryptographically random 16-byte session identifier.
func NewSessionID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("generating session ID: %w", err)
	}
	return id, nil
}

// CommandName returns a human-readable label for a command byte.
func CommandName(cmd uint8) string {
	switch cmd {
	case CmdTCPConnect:
		return "TCP_CONNECT"
	case CmdTCPData:
		return "TCP_DATA"
	case CmdTCPClose:
		return "TCP_CLOSE"
	case CmdUDPData:
		return "UDP_DATA"
	case CmdPull:
		return "PULL"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", cmd)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Buffer pool – reusable byte slices to reduce GC pressure during high-
// throughput streaming (video, large file downloads).
// ──────────────────────────────────────────────────────────────────────────────

// BufPool provides reusable byte buffers. Callers must return slices by
// calling PutBuf when they are done.
var BufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 32*1024) // 32 KB default capacity
		return &b
	},
}

// GetBuf retrieves a buffer from the pool and resets its length to zero.
func GetBuf() *[]byte {
	bp := BufPool.Get().(*[]byte)
	*bp = (*bp)[:0]
	return bp
}

// PutBuf returns a buffer to the pool. The caller must not use the buffer
// after calling PutBuf.
func PutBuf(bp *[]byte) {
	if bp == nil {
		return
	}
	// Cap the pooled buffer size to avoid holding huge allocations.
	if cap(*bp) > 1<<20 { // > 1 MB
		return // let the GC collect oversized buffers
	}
	*bp = (*bp)[:0]
	BufPool.Put(bp)
}
