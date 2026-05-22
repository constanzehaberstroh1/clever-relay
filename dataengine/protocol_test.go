package dataengine

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// Test PSK – DO NOT use in production. Generate with: openssl rand -hex 32
// ──────────────────────────────────────────────────────────────────────────────
var testPSK = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// ──────────────────────────────────────────────────────────────────────────────
// Packet / Constants Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestNewSessionID(t *testing.T) {
	id1, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	id2, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	if id1 == id2 {
		t.Error("two session IDs should not be equal")
	}
}

func TestCommandName(t *testing.T) {
	tests := []struct {
		cmd  uint8
		want string
	}{
		{CmdTCPConnect, "TCP_CONNECT"},
		{CmdTCPData, "TCP_DATA"},
		{CmdTCPClose, "TCP_CLOSE"},
		{CmdUDPData, "UDP_DATA"},
		{CmdPull, "PULL"},
		{0xFF, "UNKNOWN(0xff)"},
	}
	for _, tt := range tests {
		if got := CommandName(tt.cmd); got != tt.want {
			t.Errorf("CommandName(0x%02x) = %q, want %q", tt.cmd, got, tt.want)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Compression Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestCompressDecompress(t *testing.T) {
	original := []byte("Hello, this is a test of the Zstd compression layer in the dataengine package!")
	compressed, err := Compress(original, nil)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}

	decompressed, err := Decompress(compressed, nil)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}

	if !bytes.Equal(original, decompressed) {
		t.Errorf("round-trip failed:\n  got:  %q\n  want: %q", decompressed, original)
	}
}

func TestCompressLargePayload(t *testing.T) {
	// 256 KB of random data (worst case for compression)
	original := make([]byte, 256*1024)
	if _, err := rand.Read(original); err != nil {
		t.Fatal(err)
	}

	compressed, err := Compress(original, nil)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}

	decompressed, err := Decompress(compressed, nil)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}

	if !bytes.Equal(original, decompressed) {
		t.Error("large payload round-trip failed")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Crypto Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestCryptoLayerRoundTrip(t *testing.T) {
	cl, err := NewCryptoLayer(testPSK)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secret tunnel data 12345")
	ciphertext, err := cl.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Ciphertext must be longer than plaintext (nonce + tag)
	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext")
	}

	decrypted, err := cl.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("round-trip failed:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
}

func TestCryptoSilentDropOnTamper(t *testing.T) {
	cl, err := NewCryptoLayer(testPSK)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := cl.Encrypt([]byte("untampered data"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = cl.Decrypt(tampered, nil)
	if err != ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed on tampered data, got: %v", err)
	}
}

func TestCryptoInvalidPSK(t *testing.T) {
	_, err := NewCryptoLayer([]byte("too-short"))
	if err != ErrInvalidPSK {
		t.Errorf("expected ErrInvalidPSK, got: %v", err)
	}
}

func TestCryptoPayloadTooShort(t *testing.T) {
	cl, err := NewCryptoLayer(testPSK)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cl.Decrypt([]byte{0x01, 0x02}, nil)
	if err != ErrPayloadTooShort {
		t.Errorf("expected ErrPayloadTooShort, got: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Serialization Tests (internal)
// ──────────────────────────────────────────────────────────────────────────────

func TestSerializeDeserialize(t *testing.T) {
	sid, _ := NewSessionID()
	original := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdTCPConnect,
		SessionID: sid,
		SeqNum:    42,
		Target:    "youtube.com:443",
		Payload:   []byte("GET / HTTP/1.1\r\n"),
	}

	raw, err := serialize(original)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	restored, err := deserialize(raw)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	if restored.Version != original.Version {
		t.Errorf("Version: got %d, want %d", restored.Version, original.Version)
	}
	if restored.Command != original.Command {
		t.Errorf("Command: got %d, want %d", restored.Command, original.Command)
	}
	if restored.SessionID != original.SessionID {
		t.Error("SessionID mismatch")
	}
	if restored.SeqNum != original.SeqNum {
		t.Errorf("SeqNum: got %d, want %d", restored.SeqNum, original.SeqNum)
	}
	if restored.Target != original.Target {
		t.Errorf("Target: got %q, want %q", restored.Target, original.Target)
	}
	if !bytes.Equal(restored.Payload, original.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestSerializeNoTarget(t *testing.T) {
	sid, _ := NewSessionID()
	pkt := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdTCPData,
		SessionID: sid,
		SeqNum:    100,
		Payload:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	raw, err := serialize(pkt)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := deserialize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Target != "" {
		t.Errorf("expected empty target, got %q", restored.Target)
	}
	if !bytes.Equal(restored.Payload, pkt.Payload) {
		t.Error("payload mismatch")
	}
}

func TestSerializeTargetTooLong(t *testing.T) {
	pkt := &TunnelPacket{
		Version: ProtocolVersion,
		Command: CmdTCPConnect,
		Target:  strings.Repeat("a", MaxTargetLen+1),
	}
	_, err := serialize(pkt)
	if err == nil {
		t.Error("expected error for oversized target")
	}
}

func TestDeserializeTooShort(t *testing.T) {
	_, err := deserialize([]byte{0x01, 0x02, 0x03}) // < 24 bytes
	if err == nil {
		t.Error("expected error for short packet")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Full Protocol Tests (Seal / Open)
// ──────────────────────────────────────────────────────────────────────────────

func TestProtocolSealOpen(t *testing.T) {
	proto, err := NewProtocol(testPSK)
	if err != nil {
		t.Fatal(err)
	}

	sid, _ := NewSessionID()
	original := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdTCPConnect,
		SessionID: sid,
		SeqNum:    1,
		Target:    "chatgpt.com:443",
		Payload:   []byte("TLS Client Hello simulation..."),
	}

	sealed, err := proto.Seal(original)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	t.Logf("Original payload: %d bytes → Sealed envelope: %d bytes", len(original.Payload), len(sealed))

	opened, err := proto.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if opened.Version != original.Version {
		t.Errorf("Version: got %d, want %d", opened.Version, original.Version)
	}
	if opened.Command != original.Command {
		t.Errorf("Command: got %d, want %d", opened.Command, original.Command)
	}
	if opened.SessionID != original.SessionID {
		t.Error("SessionID mismatch")
	}
	if opened.SeqNum != original.SeqNum {
		t.Errorf("SeqNum: got %d, want %d", opened.SeqNum, original.SeqNum)
	}
	if opened.Target != original.Target {
		t.Errorf("Target: got %q, want %q", opened.Target, original.Target)
	}
	if !bytes.Equal(opened.Payload, original.Payload) {
		t.Error("Payload mismatch")
	}
}

func TestProtocolSealOpenDataOnly(t *testing.T) {
	proto, err := NewProtocol(testPSK)
	if err != nil {
		t.Fatal(err)
	}

	// Large payload (simulate video streaming chunk)
	payload := make([]byte, 128*1024) // 128 KB
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	sid, _ := NewSessionID()
	original := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdTCPData,
		SessionID: sid,
		SeqNum:    999,
		Payload:   payload,
	}

	sealed, err := proto.Seal(original)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	opened, err := proto.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(opened.Payload, original.Payload) {
		t.Error("large payload round-trip failed")
	}
}

func TestProtocolSilentDropWrongKey(t *testing.T) {
	proto1, _ := NewProtocol(testPSK)

	// Different key
	wrongPSK := make([]byte, 32)
	copy(wrongPSK, testPSK)
	wrongPSK[0] ^= 0xFF
	proto2, _ := NewProtocol(wrongPSK)

	sid, _ := NewSessionID()
	pkt := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdTCPData,
		SessionID: sid,
		SeqNum:    1,
		Payload:   []byte("this should fail with wrong key"),
	}

	sealed, err := proto1.Seal(pkt)
	if err != nil {
		t.Fatal(err)
	}

	_, err = proto2.Open(sealed)
	if err != ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed with wrong key, got: %v", err)
	}
}

func TestProtocolUDPPacket(t *testing.T) {
	proto, err := NewProtocol(testPSK)
	if err != nil {
		t.Fatal(err)
	}

	sid, _ := NewSessionID()
	// Simulate a DNS query
	dnsQuery := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}

	original := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdUDPData,
		SessionID: sid,
		SeqNum:    0,
		Target:    "1.1.1.1:53",
		Payload:   dnsQuery,
	}

	sealed, err := proto.Seal(original)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := proto.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}

	if opened.Command != CmdUDPData {
		t.Errorf("Command: got 0x%02x, want 0x%02x", opened.Command, CmdUDPData)
	}
	if opened.Target != "1.1.1.1:53" {
		t.Errorf("Target: got %q, want %q", opened.Target, "1.1.1.1:53")
	}
	if !bytes.Equal(opened.Payload, dnsQuery) {
		t.Error("DNS query payload mismatch")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Batch Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestBatchSealOpen(t *testing.T) {
	proto, err := NewProtocol(testPSK)
	if err != nil {
		t.Fatal(err)
	}

	sid, _ := NewSessionID()
	pkts := []*TunnelPacket{
		{Version: ProtocolVersion, Command: CmdTCPConnect, SessionID: sid, SeqNum: 0, Target: "example.com:443"},
		{Version: ProtocolVersion, Command: CmdTCPData, SessionID: sid, SeqNum: 1, Payload: []byte("hello")},
		{Version: ProtocolVersion, Command: CmdTCPData, SessionID: sid, SeqNum: 2, Payload: []byte("world")},
		{Version: ProtocolVersion, Command: CmdTCPClose, SessionID: sid, SeqNum: 3},
	}

	batch, err := proto.SealBatch(pkts)
	if err != nil {
		t.Fatalf("SealBatch: %v", err)
	}

	opened, err := proto.OpenBatch(batch)
	if err != nil {
		t.Fatalf("OpenBatch: %v", err)
	}

	if len(opened) != len(pkts) {
		t.Fatalf("opened %d packets, want %d", len(opened), len(pkts))
	}

	for i := range pkts {
		if opened[i].Command != pkts[i].Command {
			t.Errorf("pkt[%d] Command: got 0x%02x, want 0x%02x", i, opened[i].Command, pkts[i].Command)
		}
		if opened[i].SeqNum != pkts[i].SeqNum {
			t.Errorf("pkt[%d] SeqNum: got %d, want %d", i, opened[i].SeqNum, pkts[i].SeqNum)
		}
		if opened[i].Target != pkts[i].Target {
			t.Errorf("pkt[%d] Target: got %q, want %q", i, opened[i].Target, pkts[i].Target)
		}
		if !bytes.Equal(opened[i].Payload, pkts[i].Payload) {
			t.Errorf("pkt[%d] Payload mismatch", i)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ──────────────────────────────────────────────────────────────────────────────

func BenchmarkSeal(b *testing.B) {
	proto, _ := NewProtocol(testPSK)
	sid, _ := NewSessionID()
	payload := make([]byte, 16*1024) // 16 KB typical chunk
	rand.Read(payload)

	pkt := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdTCPData,
		SessionID: sid,
		SeqNum:    1,
		Payload:   payload,
	}

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := proto.Seal(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	proto, _ := NewProtocol(testPSK)
	sid, _ := NewSessionID()
	payload := make([]byte, 16*1024)
	rand.Read(payload)

	pkt := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdTCPData,
		SessionID: sid,
		SeqNum:    1,
		Payload:   payload,
	}

	sealed, _ := proto.Seal(pkt)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := proto.Open(sealed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSealOpen256KB(b *testing.B) {
	proto, _ := NewProtocol(testPSK)
	sid, _ := NewSessionID()
	payload := make([]byte, 256*1024)
	rand.Read(payload)

	pkt := &TunnelPacket{
		Version:   ProtocolVersion,
		Command:   CmdTCPData,
		SessionID: sid,
		SeqNum:    1,
		Payload:   payload,
	}

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sealed, _ := proto.Seal(pkt)
		_, err := proto.Open(sealed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Buffer Pool Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestBufferPool(t *testing.T) {
	buf := GetBuf()
	if buf == nil {
		t.Fatal("GetBuf returned nil")
	}
	if len(*buf) != 0 {
		t.Errorf("buffer should have zero length, got %d", len(*buf))
	}
	if cap(*buf) < 32*1024 {
		t.Errorf("buffer capacity should be at least 32KB, got %d", cap(*buf))
	}

	// Write some data and return
	*buf = append(*buf, []byte("test data")...)
	PutBuf(buf)

	// Get again — should be reset
	buf2 := GetBuf()
	if len(*buf2) != 0 {
		t.Errorf("recycled buffer should be reset, got len=%d", len(*buf2))
	}
	PutBuf(buf2)

	// PutBuf(nil) should not panic
	PutBuf(nil)
}
