package dataengine

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Global Asynchronous Event-Driven Logger
//
// This logger lives at the lowest dependency level (dataengine) so that every
// module — exitnode, localengine, desktop — can use the same logging system.
//
// Architecture:
//   LogEntry → Buffered Channel (10K) → Consumer Goroutine → Pluggable Sinks
//
// Key properties:
//   • Zero-blocking: select+default drops logs when queue is full
//   • Pluggable Sinks: Console, File (rotation), WebSocket, Wails Events
//   • Graceful shutdown: drains remaining logs before closing sinks
//   • Ring buffer: stores last N entries for dashboard queries
//   • TraceID: optional field for packet path tracking
// ──────────────────────────────────────────────────────────────────────────────

// ── Log Levels ───────────────────────────────────────────────────────────────

const (
	LevelDebug = "DEBUG"
	LevelInfo  = "INFO"
	LevelWarn  = "WARN"
	LevelError = "ERROR"
)

// ── Log Entry ────────────────────────────────────────────────────────────────

// LogEntry is the universal log record used across all modules.
type LogEntry struct {
	Timestamp string `json:"timestamp"`          // RFC3339Nano (millisecond precision)
	Level     string `json:"level"`              // DEBUG, INFO, WARN, ERROR
	Component string `json:"component"`          // e.g., "socks5", "pool", "chunker", "relay"
	Message   string `json:"message"`            // Main log message
	Details   string `json:"details,omitempty"`  // Optional extra context
	SessionID string `json:"session_id,omitempty"` // Optional: track packet path
	TraceID   string `json:"trace_id,omitempty"`   // Optional: distributed tracing
}

// ── LogSink Interface ────────────────────────────────────────────────────────

// LogSink defines the interface for log output destinations.
// Each environment (server, client, desktop) plugs in its own sinks.
type LogSink interface {
	// Write processes a single log entry. Implementations MUST NOT block.
	Write(entry LogEntry)

	// Close flushes any buffered data and releases resources.
	Close() error
}

// ── Logger Configuration ─────────────────────────────────────────────────────

const (
	// DefaultQueueSize is the capacity of the async log channel.
	// At 10,000 entries, this provides ~10 seconds of buffer at 1000 logs/sec.
	DefaultQueueSize = 10000

	// DefaultRingSize is the capacity of the in-memory ring buffer
	// for recent log queries (dashboard API).
	DefaultRingSize = 5000
)

// ── Logger Core ──────────────────────────────────────────────────────────────

// Logger is the global asynchronous event-driven logger.
// It fans out log entries to all registered sinks via a dedicated consumer
// goroutine, ensuring zero blocking on the hot path (network I/O).
type Logger struct {
	queue    chan LogEntry  // buffered async channel
	sinks    []LogSink     // pluggable output destinations
	sinksMu  sync.RWMutex  // protects sinks slice

	// Ring buffer for recent log queries
	ring     *RingBuffer

	// Shutdown coordination
	closed   atomic.Bool   // blocks new log acceptance
	done     chan struct{}  // signals consumer goroutine exit
	wg       sync.WaitGroup

	// Metrics
	dropped  atomic.Uint64 // number of dropped logs (queue full)
	total    atomic.Uint64 // total logs processed
}

// NewLogger creates a new global logger with the given queue size.
// Call AddSink() to register output destinations, then Start() to begin
// consuming logs.
func NewLogger(queueSize, ringSize int) *Logger {
	if queueSize <= 0 {
		queueSize = DefaultQueueSize
	}
	if ringSize <= 0 {
		ringSize = DefaultRingSize
	}
	l := &Logger{
		queue: make(chan LogEntry, queueSize),
		ring:  NewRingBuffer(ringSize),
		done:  make(chan struct{}),
	}
	// Start the consumer goroutine immediately
	l.wg.Add(1)
	go l.consumer()
	return l
}

// AddSink registers a new log output destination.
// Can be called at any time (thread-safe).
func (l *Logger) AddSink(sink LogSink) {
	l.sinksMu.Lock()
	l.sinks = append(l.sinks, sink)
	l.sinksMu.Unlock()
}

// ── Producer Methods (Zero-Blocking) ─────────────────────────────────────────

// emit is the core producer: creates a LogEntry and pushes it into the
// channel. Uses select+default to guarantee zero blocking.
func (l *Logger) emit(level, component, message string) {
	if l.closed.Load() {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().Format("2006-01-02T15:04:05.000Z07:00"),
		Level:     level,
		Component: component,
		Message:   message,
	}

	select {
	case l.queue <- entry:
		// Enqueued successfully (< 1 nanosecond)
	default:
		// Queue full — drop to protect network throughput
		l.dropped.Add(1)
	}
}

// emitDetailed creates a log entry with extra fields.
func (l *Logger) emitDetailed(level, component, message, details, sessionID, traceID string) {
	if l.closed.Load() {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().Format("2006-01-02T15:04:05.000Z07:00"),
		Level:     level,
		Component: component,
		Message:   message,
		Details:   details,
		SessionID: sessionID,
		TraceID:   traceID,
	}

	select {
	case l.queue <- entry:
	default:
		l.dropped.Add(1)
	}
}

// ── Convenience Methods ──────────────────────────────────────────────────────

// Debug logs at DEBUG level.
func (l *Logger) Debug(component, message string) {
	l.emit(LevelDebug, component, message)
}

// Debugf logs a formatted DEBUG message.
func (l *Logger) Debugf(component, format string, args ...interface{}) {
	l.emit(LevelDebug, component, fmt.Sprintf(format, args...))
}

// Info logs at INFO level.
func (l *Logger) Info(component, message string) {
	l.emit(LevelInfo, component, message)
}

// Infof logs a formatted INFO message.
func (l *Logger) Infof(component, format string, args ...interface{}) {
	l.emit(LevelInfo, component, fmt.Sprintf(format, args...))
}

// Warn logs at WARN level.
func (l *Logger) Warn(component, message string) {
	l.emit(LevelWarn, component, message)
}

// Warnf logs a formatted WARN message.
func (l *Logger) Warnf(component, format string, args ...interface{}) {
	l.emit(LevelWarn, component, fmt.Sprintf(format, args...))
}

// Error logs at ERROR level.
func (l *Logger) Error(component, message string) {
	l.emit(LevelError, component, message)
}

// Errorf logs a formatted ERROR message.
func (l *Logger) Errorf(component, format string, args ...interface{}) {
	l.emit(LevelError, component, fmt.Sprintf(format, args...))
}

// Log logs with explicit level string.
func (l *Logger) Log(level, component, message string) {
	l.emit(level, component, message)
}

// LogWithDetails logs with all optional fields.
func (l *Logger) LogWithDetails(level, component, message, details string) {
	l.emitDetailed(level, component, message, details, "", "")
}

// LogWithTrace logs with session and trace ID for distributed tracing.
func (l *Logger) LogWithTrace(level, component, message, sessionID, traceID string) {
	l.emitDetailed(level, component, message, "", sessionID, traceID)
}

// ── Consumer Goroutine ───────────────────────────────────────────────────────

// consumer is the dedicated goroutine that reads from the queue and
// fans out each entry to all registered sinks + the ring buffer.
func (l *Logger) consumer() {
	defer l.wg.Done()

	for entry := range l.queue {
		l.total.Add(1)

		// Write to ring buffer (for dashboard API queries)
		l.ring.Push(entry)

		// Fan out to all sinks
		l.sinksMu.RLock()
		for _, sink := range l.sinks {
			sink.Write(entry)
		}
		l.sinksMu.RUnlock()
	}

	close(l.done)
}

// ── Query Methods (for Dashboard API) ────────────────────────────────────────

// Recent returns the most recent n log entries in chronological order.
func (l *Logger) Recent(n int) []LogEntry {
	return l.ring.Recent(n)
}

// Stream returns a channel that receives log entries in real-time.
// Each call creates a new independent subscriber.
func (l *Logger) Stream() <-chan LogEntry {
	return l.ring.Subscribe()
}

// Count returns the number of entries in the ring buffer.
func (l *Logger) Count() int {
	return l.ring.Count()
}

// Dropped returns the number of logs dropped due to queue overflow.
func (l *Logger) Dropped() uint64 {
	return l.dropped.Load()
}

// Total returns the total number of logs processed.
func (l *Logger) Total() uint64 {
	return l.total.Load()
}

// ── Graceful Shutdown ────────────────────────────────────────────────────────

// Close performs a graceful shutdown:
//  1. Blocks acceptance of new logs
//  2. Closes the channel
//  3. Waits for the consumer to drain all remaining entries
//  4. Closes all sinks (flushing buffered data to disk)
func (l *Logger) Close() {
	if l.closed.Swap(true) {
		return // already closed
	}

	// Close the channel — consumer will drain remaining items
	close(l.queue)

	// Wait for consumer to finish processing all queued entries
	l.wg.Wait()

	// Close all sinks (flush files, close connections)
	l.sinksMu.RLock()
	for _, sink := range l.sinks {
		sink.Close()
	}
	l.sinksMu.RUnlock()

	// Close all ring buffer subscribers
	l.ring.CloseSubscribers()
}

// ── Ring Buffer (for Dashboard Queries) ──────────────────────────────────────

// RingBuffer stores the most recent N log entries and supports real-time
// streaming via subscriber channels.
type RingBuffer struct {
	mu          sync.RWMutex
	entries     []LogEntry
	head        int
	count       int
	capacity    int
	subscribers []chan LogEntry
	subMu       sync.Mutex
}

// NewRingBuffer creates a ring buffer with the given capacity.
func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		entries:  make([]LogEntry, capacity),
		capacity: capacity,
	}
}

// Push adds an entry and notifies all subscribers (non-blocking).
func (rb *RingBuffer) Push(entry LogEntry) {
	rb.mu.Lock()
	rb.entries[rb.head] = entry
	rb.head = (rb.head + 1) % rb.capacity
	if rb.count < rb.capacity {
		rb.count++
	}
	rb.mu.Unlock()

	// Notify subscribers (non-blocking)
	rb.subMu.Lock()
	for _, ch := range rb.subscribers {
		select {
		case ch <- entry:
		default:
			// subscriber not keeping up — drop
		}
	}
	rb.subMu.Unlock()
}

// Recent returns the most recent n entries in chronological order.
func (rb *RingBuffer) Recent(n int) []LogEntry {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if n > rb.count {
		n = rb.count
	}
	if n <= 0 {
		return nil
	}

	result := make([]LogEntry, n)
	start := (rb.head - n + rb.capacity) % rb.capacity
	for i := 0; i < n; i++ {
		result[i] = rb.entries[(start+i)%rb.capacity]
	}
	return result
}

// Count returns the number of entries in the buffer.
func (rb *RingBuffer) Count() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}

// Subscribe creates a new real-time log stream channel.
func (rb *RingBuffer) Subscribe() <-chan LogEntry {
	ch := make(chan LogEntry, 256)
	rb.subMu.Lock()
	rb.subscribers = append(rb.subscribers, ch)
	rb.subMu.Unlock()
	return ch
}

// CloseSubscribers closes all subscriber channels.
func (rb *RingBuffer) CloseSubscribers() {
	rb.subMu.Lock()
	for _, ch := range rb.subscribers {
		close(ch)
	}
	rb.subscribers = nil
	rb.subMu.Unlock()
}
