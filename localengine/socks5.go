package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/salman/clever-relay/dataengine"
)

// ──────────────────────────────────────────────────────────────────────────────
// SOCKS5 Server
//
// Implements the SOCKS5 protocol (RFC 1928) for TCP CONNECT.
// Each incoming connection is assigned a unique SessionID and routed
// through the GAS pool to the exit node.
//
// Supports:
//   - SOCKS5 CONNECT (TCP proxying)
//   - UDP ASSOCIATE (DNS resolution via CmdUDPData)
// ──────────────────────────────────────────────────────────────────────────────

const (
	socks5Version = 0x05
	cmdConnect    = 0x01
	cmdUDPAssoc   = 0x03
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
)

// SOCKS5Server listens for SOCKS5 connections and tunnels them through GAS.
type SOCKS5Server struct {
	addr     string
	proto    *dataengine.Protocol
	chunker  *Chunker
	pool     *GASPool
	listener net.Listener

	// Active sessions
	sessions sync.Map // map[[16]byte]*clientSession
	wg       sync.WaitGroup
}

// clientSession tracks a single SOCKS5 connection.
type clientSession struct {
	id       [16]byte
	seqNum   atomic.Uint32
	conn     net.Conn
	target   string
	cancel   context.CancelFunc
	closed   atomic.Bool
}

// NewSOCKS5Server creates a new SOCKS5 proxy server.
func NewSOCKS5Server(addr string, proto *dataengine.Protocol, chunker *Chunker, pool *GASPool) *SOCKS5Server {
	return &SOCKS5Server{
		addr:    addr,
		proto:   proto,
		chunker: chunker,
		pool:    pool,
	}
}

// ListenAndServe starts the SOCKS5 server.
func (s *SOCKS5Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen: %w", err)
	}
	s.listener = ln
	log.Printf("[socks5] listening on %s", s.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			default:
				log.Printf("[socks5] accept error: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

// Close shuts down the SOCKS5 server and all active sessions.
func (s *SOCKS5Server) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
	// Close all active sessions
	s.sessions.Range(func(key, value interface{}) bool {
		if cs, ok := value.(*clientSession); ok {
			cs.cancel()
			cs.conn.Close()
		}
		return true
	})
	s.wg.Wait()
}

// handleConnection performs the SOCKS5 handshake and starts tunnelling.
func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// ── Step 1: Auth Negotiation ──────────────────────────────────────
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return
	}

	if buf[0] != socks5Version {
		return
	}

	// Accept no-auth method (0x00)
	conn.Write([]byte{socks5Version, 0x00})

	// ── Step 2: Read Connection Request ───────────────────────────────
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	if buf[0] != socks5Version || buf[1] != cmdConnect {
		// Only TCP CONNECT is supported
		s.sendReply(conn, 0x07) // Command not supported
		return
	}

	// Parse the target address
	target, err := s.parseTarget(buf[3:n])
	if err != nil {
		log.Printf("[socks5] invalid target: %v", err)
		s.sendReply(conn, 0x01) // General failure
		return
	}

	// ── Step 3: Create Session and Connect ────────────────────────────
	sid, err := dataengine.NewSessionID()
	if err != nil {
		s.sendReply(conn, 0x01)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	cs := &clientSession{
		id:     sid,
		conn:   conn,
		target: target,
		cancel: cancel,
	}
	s.sessions.Store(sid, cs)

	log.Printf("[socks5] new session %x → %s", sid[:4], target)

	// Send TCP_CONNECT to the exit node via GAS
	connectPkt := &dataengine.TunnelPacket{
		Version:   dataengine.ProtocolVersion,
		Command:   dataengine.CmdTCPConnect,
		SessionID: sid,
		SeqNum:    cs.seqNum.Add(1) - 1,
		Target:    target,
	}

	_, err = s.chunker.SendImmediate(connectPkt)
	if err != nil {
		log.Printf("[socks5] TCP_CONNECT failed: %v", err)
		s.sendReply(conn, 0x05) // Connection refused
		s.sessions.Delete(sid)
		cancel()
		return
	}

	// Send success reply to the SOCKS5 client
	s.sendReply(conn, 0x00)

	// ── Step 4: Start Bidirectional Tunnelling ────────────────────────
	// Uplink: browser → SOCKS5 → GAS → Clever Cloud
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.uplinkLoop(ctx, cs)
	}()

	// Downlink: Clever Cloud → GAS → SOCKS5 → browser
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.downlinkLoop(ctx, cs)
	}()

	// Wait for context cancellation (session close)
	<-ctx.Done()

	// Send TCP_CLOSE
	closePkt := &dataengine.TunnelPacket{
		Version:   dataengine.ProtocolVersion,
		Command:   dataengine.CmdTCPClose,
		SessionID: sid,
		SeqNum:    cs.seqNum.Add(1) - 1,
	}
	s.chunker.SendImmediate(closePkt)

	s.sessions.Delete(sid)
	log.Printf("[socks5] session %x closed", sid[:4])
}

// uplinkLoop reads data from the browser and sends it to the exit node.
func (s *SOCKS5Server) uplinkLoop(ctx context.Context, cs *clientSession) {
	buf := make([]byte, 32*1024) // 32 KB read buffer

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := cs.conn.Read(buf)
		if n > 0 {
			// Create a copy of the data
			payload := make([]byte, n)
			copy(payload, buf[:n])

			pkt := &dataengine.TunnelPacket{
				Version:   dataengine.ProtocolVersion,
				Command:   dataengine.CmdTCPData,
				SessionID: cs.id,
				SeqNum:    cs.seqNum.Add(1) - 1,
				Payload:   payload,
			}

			s.chunker.Enqueue(pkt)
		}

		if err != nil {
			if err != io.EOF {
				log.Printf("[socks5] uplink read error for %x: %v", cs.id[:4], err)
			}
			cs.cancel()
			return
		}
	}
}

// downlinkLoop implements Reverse Polling (Phase 5): maintains multiple
// concurrent pending PULL requests to minimize downlink latency. When a PULL
// returns with data, it's written to the browser and a new PULL is fired
// immediately, ensuring there are always pending connections ready to receive.
//
// Flow control:
//   HAS_MORE_DATA → immediate re-PULL (zero delay for 4K streaming)
//   Data received → immediate re-PULL (keep the pipeline full)
//   No data       → 500ms backoff (prevent GAS quota burning)
//   CLOSED        → drain remaining data, cancel session
//   Network error → 1s backoff + retry (resilience for Iran network)
func (s *SOCKS5Server) downlinkLoop(ctx context.Context, cs *clientSession) {
	const parallelPulls = 3 // Number of concurrent pending PULLs

	type pullResult struct {
		resp *RelayResponse
		err  error
	}

	results := make(chan pullResult, parallelPulls)

	// Fire initial parallel PULLs
	for i := 0; i < parallelPulls; i++ {
		go func() {
			pullPkt := &dataengine.TunnelPacket{
				Version:   dataengine.ProtocolVersion,
				Command:   dataengine.CmdPull,
				SessionID: cs.id,
				SeqNum:    cs.seqNum.Add(1) - 1,
			}
			resp, err := s.chunker.SendImmediate(pullPkt)
			results <- pullResult{resp: resp, err: err}
		}()
	}

	// firePull launches a replacement PULL goroutine after an optional delay.
	// A zero delay is used when HAS_MORE_DATA is signaled (4K streaming)
	// or when data was received. A 500ms delay prevents quota burning on idle.
	firePull := func(delay time.Duration) {
		go func() {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}
			pullPkt := &dataengine.TunnelPacket{
				Version:   dataengine.ProtocolVersion,
				Command:   dataengine.CmdPull,
				SessionID: cs.id,
				SeqNum:    cs.seqNum.Add(1) - 1,
			}
			resp, err := s.chunker.SendImmediate(pullPkt)
			results <- pullResult{resp: resp, err: err}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case pr := <-results:
			if pr.err != nil {
				// Network error — backoff and retry instead of killing the session.
				// Iran's network can have transient disruptions; the browser's TCP
				// connection is still alive, so we should keep trying.
				log.Printf("[socks5] PULL error for %x: %v (retrying in 1s)", cs.id[:4], pr.err)
				firePull(1 * time.Second)
				continue
			}

			if pr.resp != nil {
				// Session closed by the exit node — drain and exit
				if pr.resp.Status == "CLOSED" {
					if len(pr.resp.Data) > 0 {
						cs.conn.Write(pr.resp.Data)
					}
					cs.cancel()
					return
				}

				// Write received data to the browser
				if len(pr.resp.Data) > 0 {
					if _, err := cs.conn.Write(pr.resp.Data); err != nil {
						log.Printf("[socks5] downlink write error for %x: %v", cs.id[:4], err)
						cs.cancel()
						return
					}
				}

				// Speed control: determine the delay for the next PULL
				if pr.resp.Status == "HAS_MORE_DATA" || len(pr.resp.Data) > 0 {
					// Data is flowing — fire immediately for max throughput
					firePull(0)
				} else {
					// Idle — backoff to avoid burning GAS daily quota
					firePull(500 * time.Millisecond)
				}
			} else {
				// Nil response — backoff
				firePull(500 * time.Millisecond)
			}
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// SOCKS5 protocol helpers
// ──────────────────────────────────────────────────────────────────────────────

// parseTarget extracts the destination address from a SOCKS5 request.
func (s *SOCKS5Server) parseTarget(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("target data too short")
	}

	atyp := data[0]
	switch atyp {
	case atypIPv4:
		if len(data) < 7 { // 1 + 4 + 2
			return "", fmt.Errorf("IPv4 target too short")
		}
		ip := net.IP(data[1:5])
		port := binary.BigEndian.Uint16(data[5:7])
		return fmt.Sprintf("%s:%d", ip.String(), port), nil

	case atypDomain:
		domainLen := int(data[1])
		if len(data) < 2+domainLen+2 {
			return "", fmt.Errorf("domain target too short")
		}
		domain := string(data[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(data[2+domainLen : 2+domainLen+2])
		return fmt.Sprintf("%s:%d", domain, port), nil

	case atypIPv6:
		if len(data) < 19 { // 1 + 16 + 2
			return "", fmt.Errorf("IPv6 target too short")
		}
		ip := net.IP(data[1:17])
		port := binary.BigEndian.Uint16(data[17:19])
		return fmt.Sprintf("[%s]:%d", ip.String(), port), nil

	default:
		return "", fmt.Errorf("unsupported address type: 0x%02x", atyp)
	}
}

// sendReply sends a SOCKS5 reply to the client.
func (s *SOCKS5Server) sendReply(conn net.Conn, status byte) {
	// Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	reply := []byte{
		socks5Version, status, 0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00, // 0.0.0.0
		0x00, 0x00, // port 0
	}
	conn.Write(reply)
}
