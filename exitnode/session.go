package main

import (
	"container/heap"
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/salman/clever-relay/dataengine"
)

// ──────────────────────────────────────────────────────────────────────────────
// Min-Heap for uplink packet reordering (sorted by SeqNum ascending)
// ──────────────────────────────────────────────────────────────────────────────

type packetHeap []*dataengine.TunnelPacket

func (h packetHeap) Len() int            { return len(h) }
func (h packetHeap) Less(i, j int) bool  { return h[i].SeqNum < h[j].SeqNum }
func (h packetHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *packetHeap) Push(x interface{}) { *h = append(*h, x.(*dataengine.TunnelPacket)) }
func (h *packetHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	*h = old[:n-1]
	return item
}

// ──────────────────────────────────────────────────────────────────────────────
// Session represents a single logical tunnel connection (TCP or UDP).
// Each browser connection gets its own Session identified by a 16-byte UUID.
// ──────────────────────────────────────────────────────────────────────────────

// Session holds the state for one tunnelled connection.
type Session struct {
	ID        [16]byte
	Target    string
	CreatedAt time.Time
	LastUsed  time.Time

	// TCP connection to the destination server
	TCPConn net.Conn

	// UDP connection for DNS/WebRTC
	UDPConn *net.UDPConn

	// Downstream buffer – data read from the destination, waiting to be
	// pulled by the client. Protected by mu.
	mu         sync.Mutex
	downBuf    []byte
	hasMore    bool // true if more data is available after a PULL timeout
	closed     bool

	// Sequence tracking for ordered delivery
	nextSeqNum uint32

	// Uplink Reassembler – reorders out-of-order packets arriving from
	// ScatterDispatch before writing to the destination TCP socket.
	// Without this, parallel GAS requests cause packets to arrive at
	// the exit node in random order, corrupting the upstream TCP stream.
	upMu       sync.Mutex
	upExpected uint32       // next expected SeqNum for uplink
	upBuffer   packetHeap   // min-heap of buffered out-of-order packets
}

// WriteToTarget sends data to the destination TCP connection (unordered).
// Used for initial payload in TCP_CONNECT where ordering is guaranteed.
func (s *Session) WriteToTarget(data []byte) (int, error) {
	s.mu.Lock()
	s.LastUsed = time.Now()
	s.mu.Unlock()

	if s.TCPConn == nil {
		return 0, fmt.Errorf("session %x: no TCP connection", s.ID[:4])
	}
	return s.TCPConn.Write(data)
}

// WriteOrderedToTarget inserts a packet into the uplink reassembler and
// writes all contiguous in-order packets to the destination socket.
//
// This is CRITICAL for ScatterDispatch: packets arrive at the exit node
// via different GAS scripts with varying latencies. Without reordering,
// packet 3 could be written before packet 2, corrupting the TCP stream
// and causing Connection Reset on the destination server.
func (s *Session) WriteOrderedToTarget(pkt *dataengine.TunnelPacket) error {
	s.upMu.Lock()
	defer s.upMu.Unlock()

	// Drop duplicates (already written)
	if pkt.SeqNum < s.upExpected {
		return nil
	}

	// Buffer this packet in the min-heap
	heap.Push(&s.upBuffer, pkt)

	// Drain all contiguous packets starting from upExpected
	for s.upBuffer.Len() > 0 && s.upBuffer[0].SeqNum == s.upExpected {
		nextPkt := heap.Pop(&s.upBuffer).(*dataengine.TunnelPacket)

		s.mu.Lock()
		s.LastUsed = time.Now()
		s.mu.Unlock()

		if s.TCPConn != nil && len(nextPkt.Payload) > 0 {
			if _, err := s.TCPConn.Write(nextPkt.Payload); err != nil {
				return err
			}
		}
		s.upExpected++
	}
	return nil
}

// ReadFromBuffer drains the downstream buffer (data received from the
// destination server). Returns the buffered data and whether more data
// may be available (HAS_MORE_DATA flag).
func (s *Session) ReadFromBuffer() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := s.downBuf
	hasMore := s.hasMore
	s.downBuf = nil
	s.hasMore = false
	return data, hasMore
}

// AppendToBuffer adds data received from the destination to the downstream
// buffer for later retrieval via PULL.
func (s *Session) AppendToBuffer(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downBuf = append(s.downBuf, data...)
	s.LastUsed = time.Now()
}

// SetHasMore marks that more data is available after a PULL timeout.
func (s *Session) SetHasMore(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hasMore = v
}

// IsClosed returns whether the session has been closed.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close terminates both TCP and UDP connections and marks the session as closed.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true

	if s.TCPConn != nil {
		s.TCPConn.Close()
	}
	if s.UDPConn != nil {
		s.UDPConn.Close()
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// SessionStore is a thread-safe registry of active sessions.
// It uses sync.Map for lock-free reads on the hot path.
// ──────────────────────────────────────────────────────────────────────────────

// SessionStore manages all active tunnel sessions.
type SessionStore struct {
	sessions sync.Map // map[[16]byte]*Session
	count    int64
	mu       sync.Mutex // protects count
}

// NewSessionStore creates an empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{}
}

// Get retrieves a session by ID.
func (ss *SessionStore) Get(id [16]byte) (*Session, bool) {
	val, ok := ss.sessions.Load(id)
	if !ok {
		return nil, false
	}
	return val.(*Session), true
}

// Create creates and stores a new session. If a session with the same ID
// already exists, the old one is closed first.
func (ss *SessionStore) Create(id [16]byte, target string) *Session {
	// Close any existing session with this ID
	if old, ok := ss.Get(id); ok {
		old.Close()
		ss.delete(id)
	}

	s := &Session{
		ID:        id,
		Target:    target,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}
	ss.sessions.Store(id, s)
	ss.mu.Lock()
	ss.count++
	ss.mu.Unlock()
	return s
}

// Remove closes and removes a session.
func (ss *SessionStore) Remove(id [16]byte) {
	if s, ok := ss.Get(id); ok {
		s.Close()
		ss.delete(id)
	}
}

func (ss *SessionStore) delete(id [16]byte) {
	ss.sessions.Delete(id)
	ss.mu.Lock()
	if ss.count > 0 {
		ss.count--
	}
	ss.mu.Unlock()
}

// Count returns the number of active sessions.
func (ss *SessionStore) Count() int64 {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.count
}

// CloseAll terminates all sessions (used during graceful shutdown).
func (ss *SessionStore) CloseAll() {
	ss.sessions.Range(func(key, value interface{}) bool {
		if s, ok := value.(*Session); ok {
			s.Close()
		}
		ss.sessions.Delete(key)
		return true
	})
	ss.mu.Lock()
	ss.count = 0
	ss.mu.Unlock()
}

// StartReaper periodically removes idle sessions to prevent memory leaks.
// Sessions idle for more than `maxIdle` are closed and removed.
func (ss *SessionStore) StartReaper(ctx context.Context, maxIdle time.Duration) {
	ticker := time.NewTicker(maxIdle / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			ss.sessions.Range(func(key, value interface{}) bool {
				s := value.(*Session)
				s.mu.Lock()
				idle := now.Sub(s.LastUsed)
				s.mu.Unlock()

				if idle > maxIdle {
					log.Printf("[reaper] closing idle session %x (idle %s, target: %s)",
						s.ID[:4], idle.Round(time.Second), s.Target)
					s.Close()
					ss.delete(key.([16]byte))
				}
				return true
			})
		}
	}
}

// ActiveSessions returns a snapshot of all active session metadata (for the
// admin dashboard).
type SessionInfo struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
	BufferLen int       `json:"buffer_len"`
	Closed    bool      `json:"closed"`
}

// ListSessions returns metadata about all active sessions.
func (ss *SessionStore) ListSessions() []SessionInfo {
	var result []SessionInfo
	ss.sessions.Range(func(key, value interface{}) bool {
		s := value.(*Session)
		s.mu.Lock()
		info := SessionInfo{
			ID:        fmt.Sprintf("%x", s.ID),
			Target:    s.Target,
			CreatedAt: s.CreatedAt,
			LastUsed:  s.LastUsed,
			BufferLen: len(s.downBuf),
			Closed:    s.closed,
		}
		s.mu.Unlock()
		result = append(result, info)
		return true
	})
	return result
}
