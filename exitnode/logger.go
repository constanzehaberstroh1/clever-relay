package main

import (
	"encoding/json"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Ring-Buffered Log System
//
// High-traffic tunnel processing generates thousands of log events per second.
// A naive approach (appending to a slice) would cause unbounded memory growth.
//
// This ring buffer holds the most recent N entries and silently drops older
// ones. Logs are also streamed to WebSocket clients in real time.
// ──────────────────────────────────────────────────────────────────────────────

const (
	// MaxLogEntries is the capacity of the ring buffer.
	MaxLogEntries = 5000
)

// LogLevel constants for structured logging.
const (
	LogInfo  = "INFO"
	LogWarn  = "WARN"
	LogError = "ERROR"
	LogDebug = "DEBUG"
)

// LogEntry represents a single structured log event.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Component string `json:"component"`
	Message   string `json:"message"`
	Details   string `json:"details,omitempty"`
}

// LogBuffer is a thread-safe ring buffer for log entries.
type LogBuffer struct {
	mu       sync.RWMutex
	entries  []LogEntry
	head     int
	count    int
	capacity int

	// Non-blocking channel for real-time streaming to WebSocket clients.
	// Writers drop messages if the channel is full (backpressure).
	stream chan LogEntry
}

// NewLogBuffer creates a ring buffer with the given capacity.
func NewLogBuffer(capacity int) *LogBuffer {
	return &LogBuffer{
		entries:  make([]LogEntry, capacity),
		capacity: capacity,
		stream:   make(chan LogEntry, 256), // buffered channel
	}
}

// Push adds a log entry to the ring buffer. If full, the oldest entry is
// overwritten. Also tries to push to the stream channel (non-blocking).
func (lb *LogBuffer) Push(entry LogEntry) {
	lb.mu.Lock()
	lb.entries[lb.head] = entry
	lb.head = (lb.head + 1) % lb.capacity
	if lb.count < lb.capacity {
		lb.count++
	}
	lb.mu.Unlock()

	// Non-blocking send to stream
	select {
	case lb.stream <- entry:
	default:
		// Drop if no consumer is keeping up
	}
}

// Recent returns the most recent n log entries in chronological order.
func (lb *LogBuffer) Recent(n int) []LogEntry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if n > lb.count {
		n = lb.count
	}
	if n <= 0 {
		return nil
	}

	result := make([]LogEntry, n)
	start := (lb.head - n + lb.capacity) % lb.capacity
	for i := 0; i < n; i++ {
		result[i] = lb.entries[(start+i)%lb.capacity]
	}
	return result
}

// Stream returns the channel for real-time log streaming.
func (lb *LogBuffer) Stream() <-chan LogEntry {
	return lb.stream
}

// Count returns the number of entries currently in the buffer.
func (lb *LogBuffer) Count() int {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	return lb.count
}

// ──────────────────────────────────────────────────────────────────────────────
// TunnelLogger wraps the ring buffer and provides convenient methods.
// ──────────────────────────────────────────────────────────────────────────────

// TunnelLogger provides structured, high-performance async logging.
type TunnelLogger struct {
	buffer *LogBuffer
}

// NewTunnelLogger creates a logger backed by a ring buffer.
func NewTunnelLogger() *TunnelLogger {
	return &TunnelLogger{
		buffer: NewLogBuffer(MaxLogEntries),
	}
}

// Log records a structured log entry.
func (tl *TunnelLogger) Log(level, component, message string) {
	tl.buffer.Push(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Level:     level,
		Component: component,
		Message:   message,
	})
}

// LogWithDetails records a log entry with additional detail text.
func (tl *TunnelLogger) LogWithDetails(level, component, message, details string) {
	tl.buffer.Push(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Level:     level,
		Component: component,
		Message:   message,
		Details:   details,
	})
}

// Info logs at INFO level.
func (tl *TunnelLogger) Info(component, message string) {
	tl.Log(LogInfo, component, message)
}

// Warn logs at WARN level.
func (tl *TunnelLogger) Warn(component, message string) {
	tl.Log(LogWarn, component, message)
}

// Error logs at ERROR level.
func (tl *TunnelLogger) Error(component, message string) {
	tl.Log(LogError, component, message)
}

// Recent returns the most recent n log entries.
func (tl *TunnelLogger) Recent(n int) []LogEntry {
	return tl.buffer.Recent(n)
}

// Stream returns the channel for real-time log events.
func (tl *TunnelLogger) Stream() <-chan LogEntry {
	return tl.buffer.Stream()
}

// RecentJSON returns recent logs as a JSON byte slice.
func (tl *TunnelLogger) RecentJSON(n int) ([]byte, error) {
	entries := tl.Recent(n)
	return json.Marshal(entries)
}
