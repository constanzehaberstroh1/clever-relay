package main

import (
	"crypto/tls"
	"log"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// ConnPool – TLS Connection Pool with Health Checks (Phase 5)
//
// Maintains a pool of live TLS connections to Google's App Engine infrastructure.
// Instead of performing a full TCP+TLS handshake for every GAS request
// (3-4 round trips, ~300-600ms in Iran), this pool recycles connections.
//
// Features:
//   - Concurrency-safe via sync.Mutex
//   - Keep-alive peek: validates connections before reuse
//   - Configurable max pool size and idle timeout
//   - Automatic cleanup of expired connections
// ──────────────────────────────────────────────────────────────────────────────

// poolEntry wraps a connection with its creation time for idle tracking.
type poolEntry struct {
	conn      *tls.Conn
	createdAt time.Time
	lastUsed  time.Time
}

// ConnPool manages a pool of reusable TLS connections.
type ConnPool struct {
	mu         sync.Mutex
	pool       []poolEntry
	maxSize    int
	maxIdle    time.Duration
	done       chan struct{}
}

// NewConnPool creates a connection pool with the given limits.
// maxSize: maximum number of connections to keep in the pool.
// maxIdle: connections idle longer than this are evicted.
func NewConnPool(maxSize int, maxIdle time.Duration) *ConnPool {
	p := &ConnPool{
		maxSize: maxSize,
		maxIdle: maxIdle,
		done:    make(chan struct{}),
	}

	// Start background cleanup worker
	go p.cleanupLoop()

	return p
}

// Get retrieves a healthy connection from the pool.
// Returns nil if no healthy connections are available.
func (p *ConnPool) Get() *tls.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	for len(p.pool) > 0 {
		// Pop from the end (LIFO — most recently used connection)
		entry := p.pool[len(p.pool)-1]
		p.pool = p.pool[:len(p.pool)-1]

		// Check idle timeout
		if time.Since(entry.lastUsed) > p.maxIdle {
			entry.conn.Close()
			continue
		}

		// Step 5.2: Health check — peek 1 byte with short deadline
		// If the server closed the connection, we'll get EOF immediately.
		if !p.isHealthy(entry.conn) {
			entry.conn.Close()
			log.Printf("[conn-pool] evicted stale connection")
			continue
		}

		return entry.conn
	}

	return nil
}

// Put returns a connection to the pool for reuse.
// If the pool is full, the connection is closed.
func (p *ConnPool) Put(conn *tls.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Don't pool if we're shutting down
	select {
	case <-p.done:
		conn.Close()
		return
	default:
	}

	// If pool is full, close the connection
	if len(p.pool) >= p.maxSize {
		conn.Close()
		return
	}

	p.pool = append(p.pool, poolEntry{
		conn:     conn,
		lastUsed: time.Now(),
	})
}

// isHealthy checks if a TLS connection is still alive.
// Sets a very short read deadline and tries to read 1 byte.
// If the server has closed the connection, we get EOF immediately.
// If the connection is alive, we get a timeout error (expected).
func (p *ConnPool) isHealthy(conn *tls.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	if err != nil {
		// Timeout means the connection is alive (no data waiting)
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			return true
		}
		// Any other error (EOF, connection reset) means dead
		return false
	}

	// If we actually read a byte, the server sent unsolicited data — unusual
	// but the connection is technically alive
	return true
}

// Size returns the current number of pooled connections.
func (p *ConnPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pool)
}

// cleanupLoop periodically removes expired connections from the pool.
func (p *ConnPool) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.cleanup()
		}
	}
}

// cleanup evicts connections that have exceeded the idle timeout.
func (p *ConnPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	var alive []poolEntry
	now := time.Now()

	for _, entry := range p.pool {
		if now.Sub(entry.lastUsed) > p.maxIdle {
			entry.conn.Close()
		} else {
			alive = append(alive, entry)
		}
	}

	evicted := len(p.pool) - len(alive)
	p.pool = alive

	if evicted > 0 {
		log.Printf("[conn-pool] evicted %d idle connections, %d remaining", evicted, len(alive))
	}
}

// Close shuts down the pool and closes all connections.
func (p *ConnPool) Close() {
	close(p.done)

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, entry := range p.pool {
		entry.conn.Close()
	}
	p.pool = nil
	log.Printf("[conn-pool] closed all pooled connections")
}
