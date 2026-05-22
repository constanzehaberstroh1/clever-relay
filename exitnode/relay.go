package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/salman/clever-relay/dataengine"
)

// ──────────────────────────────────────────────────────────────────────────────
// RelayHandler processes encrypted tunnel packets arriving from Google Apps
// Script. It implements the core demultiplexer that routes packets to the
// correct session based on SessionID and Command.
// ──────────────────────────────────────────────────────────────────────────────

const (
	// DialTimeout is the maximum time to establish a TCP connection to a
	// destination server.
	DialTimeout = 10 * time.Second

	// PreemptionTimeout is the maximum time a PULL request will hold open
	// before returning with HAS_MORE_DATA. Set to 45 seconds to stay well
	// within Google Apps Script's 60-second execution limit.
	PreemptionTimeout = 45 * time.Second

	// ReadBufferSize is the size of the buffer used when reading from
	// destination connections.
	ReadBufferSize = 32 * 1024 // 32 KB

	// MaxRequestBody is the maximum request body size (10 MB, aligned with
	// GAS limits).
	MaxRequestBody = 10 * 1024 * 1024
)

// RelayHandler holds the protocol instance and session store.
type RelayHandler struct {
	proto    *dataengine.Protocol
	sessions *SessionStore
	logger   *TunnelLogger // Phase 6: ring-buffered async logger
}

// NewRelayHandler creates a relay handler with the given PSK and session store.
func NewRelayHandler(psk []byte, ss *SessionStore) (*RelayHandler, error) {
	proto, err := dataengine.NewProtocol(psk)
	if err != nil {
		return nil, fmt.Errorf("creating protocol: %w", err)
	}
	return &RelayHandler{proto: proto, sessions: ss}, nil
}

// HandleRelay is the HTTP handler for POST /relay. It reads the encrypted
// body, decrypts it, and dispatches commands to the appropriate session.
func (h *RelayHandler) HandleRelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// Silent Drop: don't reveal that this endpoint exists
		http.NotFound(w, r)
		return
	}

	// Read the request body using a pooled buffer for GC pressure reduction
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBody))
	r.Body.Close()
	if err != nil {
		// Silent Drop
		http.NotFound(w, r)
		return
	}

	if len(body) == 0 {
		http.NotFound(w, r)
		return
	}

	// Check if this is a batch or single packet
	// Try batch first (length-prefixed envelopes)
	isBatch := r.Header.Get("X-Batch") == "1"

	if isBatch {
		h.handleBatch(w, body)
	} else {
		h.handleSingle(w, body)
	}
}

// handleSingle processes a single encrypted envelope.
func (h *RelayHandler) handleSingle(w http.ResponseWriter, body []byte) {
	pkt, err := h.proto.Open(body)
	if err != nil {
		// Silent Drop: DPI probe or wrong key – return 404 to look like
		// a normal web server with no such page.
		w.WriteHeader(http.StatusNotFound)
		return
	}

	h.dispatch(w, pkt)
}

// handleBatch processes a batch of length-prefixed encrypted envelopes.
func (h *RelayHandler) handleBatch(w http.ResponseWriter, body []byte) {
	pkts, err := h.proto.OpenBatch(body)
	if err != nil {
		// Silent Drop
		http.NotFound(w, nil)
		return
	}

	// Process each packet. Collect responses for the batch.
	var responses [][]byte
	for _, pkt := range pkts {
		resp := h.dispatchCollect(pkt)
		responses = append(responses, resp)
	}

	// Seal and return the responses as a batch
	var respPkts []*dataengine.TunnelPacket
	for i, resp := range responses {
		if len(resp) > 0 {
			respPkts = append(respPkts, &dataengine.TunnelPacket{
				Version:   dataengine.ProtocolVersion,
				Command:   dataengine.CmdTCPData,
				SessionID: pkts[i].SessionID,
				SeqNum:    pkts[i].SeqNum,
				Payload:   resp,
			})
		}
	}

	if len(respPkts) > 0 {
		sealed, err := h.proto.SealBatch(respPkts)
		if err != nil {
			log.Printf("[relay] failed to seal batch response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Batch", "1")
		w.Write(sealed)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

// dispatch processes a single packet and writes the response to w.
func (h *RelayHandler) dispatch(w http.ResponseWriter, pkt *dataengine.TunnelPacket) {
	switch pkt.Command {
	case dataengine.CmdTCPConnect:
		h.handleTCPConnect(w, pkt)
	case dataengine.CmdTCPData:
		h.handleTCPData(w, pkt)
	case dataengine.CmdTCPClose:
		h.handleTCPClose(w, pkt)
	case dataengine.CmdUDPData:
		h.handleUDPData(w, pkt)
	case dataengine.CmdPull:
		h.handlePull(w, pkt)
	default:
		log.Printf("[relay] unknown command 0x%02x from session %x",
			pkt.Command, pkt.SessionID[:4])
		w.WriteHeader(http.StatusNoContent)
	}
}

// dispatchCollect processes a single packet and returns response data (for batches).
func (h *RelayHandler) dispatchCollect(pkt *dataengine.TunnelPacket) []byte {
	switch pkt.Command {
	case dataengine.CmdTCPConnect:
		return h.execTCPConnect(pkt)
	case dataengine.CmdTCPData:
		return h.execTCPData(pkt)
	case dataengine.CmdTCPClose:
		h.sessions.Remove(pkt.SessionID)
		return nil
	case dataengine.CmdUDPData:
		return h.execUDPData(pkt)
	default:
		return nil
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Command handlers
// ──────────────────────────────────────────────────────────────────────────────

// handleTCPConnect establishes a new TCP connection to the target and starts
// a background reader goroutine.
func (h *RelayHandler) handleTCPConnect(w http.ResponseWriter, pkt *dataengine.TunnelPacket) {
	session := h.sessions.Create(pkt.SessionID, pkt.Target)

	conn, err := net.DialTimeout("tcp", pkt.Target, DialTimeout)
	if err != nil {
		log.Printf("[relay] TCP_CONNECT failed to %s: %v", pkt.Target, err)
		h.sessions.Remove(pkt.SessionID)

		// Send error response
		errPkt := &dataengine.TunnelPacket{
			Version:   dataengine.ProtocolVersion,
			Command:   dataengine.CmdTCPClose,
			SessionID: pkt.SessionID,
			SeqNum:    0,
			Payload:   []byte(fmt.Sprintf("dial failed: %v", err)),
		}
		h.sendResponse(w, errPkt)
		return
	}

	session.TCPConn = conn
	log.Printf("[relay] TCP_CONNECT session %x → %s", pkt.SessionID[:4], pkt.Target)

	// Start background reader: continuously reads from destination and
	// buffers data for PULL requests.
	go h.backgroundReader(session)

	// If there's payload in the CONNECT packet (e.g., TLS ClientHello),
	// write it immediately.
	if len(pkt.Payload) > 0 {
		if _, err := session.WriteToTarget(pkt.Payload); err != nil {
			log.Printf("[relay] write on connect failed: %v", err)
		}
	}

	// Return 204 to acknowledge the connection
	w.WriteHeader(http.StatusNoContent)
}

// execTCPConnect is the batch version of handleTCPConnect.
func (h *RelayHandler) execTCPConnect(pkt *dataengine.TunnelPacket) []byte {
	session := h.sessions.Create(pkt.SessionID, pkt.Target)

	conn, err := net.DialTimeout("tcp", pkt.Target, DialTimeout)
	if err != nil {
		log.Printf("[relay] TCP_CONNECT failed to %s: %v", pkt.Target, err)
		h.sessions.Remove(pkt.SessionID)
		return []byte(fmt.Sprintf("dial failed: %v", err))
	}

	session.TCPConn = conn
	log.Printf("[relay] TCP_CONNECT session %x → %s", pkt.SessionID[:4], pkt.Target)

	go h.backgroundReader(session)

	if len(pkt.Payload) > 0 {
		if _, err := session.WriteToTarget(pkt.Payload); err != nil {
			log.Printf("[relay] write on connect failed: %v", err)
		}
	}

	return nil
}

// handleTCPData writes payload data to an existing TCP session.
func (h *RelayHandler) handleTCPData(w http.ResponseWriter, pkt *dataengine.TunnelPacket) {
	session, ok := h.sessions.Get(pkt.SessionID)
	if !ok {
		log.Printf("[relay] TCP_DATA for unknown session %x", pkt.SessionID[:4])
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if len(pkt.Payload) > 0 {
		if _, err := session.WriteToTarget(pkt.Payload); err != nil {
			log.Printf("[relay] TCP_DATA write error for session %x: %v",
				pkt.SessionID[:4], err)
			h.sessions.Remove(pkt.SessionID)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// execTCPData is the batch version of handleTCPData.
func (h *RelayHandler) execTCPData(pkt *dataengine.TunnelPacket) []byte {
	session, ok := h.sessions.Get(pkt.SessionID)
	if !ok {
		return nil
	}

	if len(pkt.Payload) > 0 {
		if _, err := session.WriteToTarget(pkt.Payload); err != nil {
			log.Printf("[relay] TCP_DATA write error: %v", err)
			h.sessions.Remove(pkt.SessionID)
		}
	}
	return nil
}

// handleTCPClose closes a TCP session.
func (h *RelayHandler) handleTCPClose(w http.ResponseWriter, pkt *dataengine.TunnelPacket) {
	log.Printf("[relay] TCP_CLOSE session %x", pkt.SessionID[:4])
	h.sessions.Remove(pkt.SessionID)
	w.WriteHeader(http.StatusNoContent)
}

// handleUDPData sends a UDP datagram and returns the response.
// This solves the Sōzu load balancer limitation (no raw UDP ports).
func (h *RelayHandler) handleUDPData(w http.ResponseWriter, pkt *dataengine.TunnelPacket) {
	resp := h.execUDPData(pkt)
	if resp == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Seal the response
	respPkt := &dataengine.TunnelPacket{
		Version:   dataengine.ProtocolVersion,
		Command:   dataengine.CmdUDPData,
		SessionID: pkt.SessionID,
		SeqNum:    pkt.SeqNum,
		Target:    pkt.Target,
		Payload:   resp,
	}
	h.sendResponse(w, respPkt)
}

// execUDPData sends a UDP datagram and returns the response bytes.
func (h *RelayHandler) execUDPData(pkt *dataengine.TunnelPacket) []byte {
	addr, err := net.ResolveUDPAddr("udp", pkt.Target)
	if err != nil {
		log.Printf("[relay] UDP resolve error for %s: %v", pkt.Target, err)
		return nil
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("[relay] UDP dial error for %s: %v", pkt.Target, err)
		return nil
	}
	defer conn.Close()

	// Set a short timeout for UDP (DNS queries should be fast)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(pkt.Payload); err != nil {
		log.Printf("[relay] UDP write error: %v", err)
		return nil
	}

	buf := make([]byte, 4096) // DNS responses are typically < 512 bytes
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[relay] UDP read error: %v", err)
		return nil
	}

	return buf[:n]
}

// handlePull implements the Time-Aware Preemption pattern.
// It holds the request open for up to PreemptionTimeout (45s), streaming
// buffered data back to the client. When the timeout fires, it signals
// HAS_MORE_DATA so the client sends a new PULL through another GAS node.
func (h *RelayHandler) handlePull(w http.ResponseWriter, pkt *dataengine.TunnelPacket) {
	session, ok := h.sessions.Get(pkt.SessionID)
	if !ok {
		w.Header().Set("X-Session-Status", "CLOSED")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if session.IsClosed() {
		// Drain remaining buffer
		data, _ := session.ReadFromBuffer()
		if len(data) > 0 {
			h.sendDataResponse(w, pkt.SessionID, pkt.SeqNum, data, "CLOSED")
		} else {
			w.Header().Set("X-Session-Status", "CLOSED")
			w.WriteHeader(http.StatusNoContent)
		}
		h.sessions.Remove(pkt.SessionID)
		return
	}

	// Time-Aware Preemption: hold the connection for up to 45 seconds,
	// collecting data from the background reader.
	ctx, cancel := context.WithTimeout(context.Background(), PreemptionTimeout)
	defer cancel()

	var collected []byte
	ticker := time.NewTicker(50 * time.Millisecond) // poll interval
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Timeout – send what we have with HAS_MORE_DATA
			data, _ := session.ReadFromBuffer()
			collected = append(collected, data...)

			if len(collected) > 0 {
				session.SetHasMore(true)
				h.sendDataResponse(w, pkt.SessionID, pkt.SeqNum, collected, "HAS_MORE_DATA")
			} else {
				w.Header().Set("X-Session-Status", "HAS_MORE_DATA")
				w.WriteHeader(http.StatusNoContent)
			}
			return

		case <-ticker.C:
			data, _ := session.ReadFromBuffer()
			if len(data) > 0 {
				collected = append(collected, data...)
			}

			// If we've accumulated enough data, send it immediately
			// rather than waiting for the full timeout.
			if len(collected) >= 256*1024 { // 256 KB threshold
				status := "HAS_MORE_DATA"
				if session.IsClosed() {
					// Check if there's more data after this chunk
					remaining, _ := session.ReadFromBuffer()
					collected = append(collected, remaining...)
					if len(remaining) == 0 {
						status = "CLOSED"
					}
				}
				h.sendDataResponse(w, pkt.SessionID, pkt.SeqNum, collected, status)
				return
			}

			// If the session was closed while we were waiting
			if session.IsClosed() {
				data, _ := session.ReadFromBuffer()
				collected = append(collected, data...)
				status := "CLOSED"
				if len(collected) > 0 {
					h.sendDataResponse(w, pkt.SessionID, pkt.SeqNum, collected, status)
				} else {
					w.Header().Set("X-Session-Status", status)
					w.WriteHeader(http.StatusNoContent)
				}
				h.sessions.Remove(pkt.SessionID)
				return
			}
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Background reader – continuously reads from the destination and buffers
// ──────────────────────────────────────────────────────────────────────────────

// backgroundReader runs as a goroutine for each TCP session. It continuously
// reads from the destination connection and stores data in the session's
// downstream buffer.
//
// Phase 5: Uses sync.Pool recycled buffers to eliminate GC pressure during
// high-throughput streaming (4K video, large file downloads).
func (h *RelayHandler) backgroundReader(session *Session) {
	// Get a reusable read buffer from the pool
	bufPtr := dataengine.GetBuf()
	defer dataengine.PutBuf(bufPtr)

	// Ensure the buffer is at least ReadBufferSize
	if cap(*bufPtr) < ReadBufferSize {
		*bufPtr = make([]byte, ReadBufferSize)
	} else {
		*bufPtr = (*bufPtr)[:ReadBufferSize]
	}
	buf := *bufPtr

	for {
		if session.IsClosed() {
			return
		}

		// Set a read deadline to prevent blocking forever
		if session.TCPConn != nil {
			session.TCPConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		}

		n, err := session.TCPConn.Read(buf)
		if n > 0 {
			// Copy the data to avoid buffer overwrite on next Read
			data := make([]byte, n)
			copy(data, buf[:n])
			session.AppendToBuffer(data)
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Read timeout, try again
			}
			// Connection closed or error
			log.Printf("[reader] session %x: connection ended (%v)", session.ID[:4], err)
			session.Close()
			return
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Response helpers
// ──────────────────────────────────────────────────────────────────────────────

// sendResponse encrypts a TunnelPacket and writes it to the HTTP response.
func (h *RelayHandler) sendResponse(w http.ResponseWriter, pkt *dataengine.TunnelPacket) {
	sealed, err := h.proto.Seal(pkt)
	if err != nil {
		log.Printf("[relay] failed to seal response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(sealed)
}

// sendDataResponse sends downstream data with a session status header.
// The data is Base64-encoded and wrapped in an encrypted envelope for
// compatibility with GAS response handling.
func (h *RelayHandler) sendDataResponse(w http.ResponseWriter, sessionID [16]byte, seqNum uint32, data []byte, status string) {
	pkt := &dataengine.TunnelPacket{
		Version:   dataengine.ProtocolVersion,
		Command:   dataengine.CmdTCPData,
		SessionID: sessionID,
		SeqNum:    seqNum,
		Payload:   data,
	}

	sealed, err := h.proto.Seal(pkt)
	if err != nil {
		log.Printf("[relay] failed to seal data response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Session-Status", status)

	// Also provide a Base64 version for GAS compatibility
	w.Header().Set("X-Data-Encoding", "binary")
	_ = base64.StdEncoding // available if needed by GAS relay

	w.Write(sealed)
}
