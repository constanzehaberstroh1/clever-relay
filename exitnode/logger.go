package main

import (
	"encoding/json"

	"github.com/salman/clever-relay/dataengine"
)

// ──────────────────────────────────────────────────────────────────────────────
// TunnelLogger – Exit Node Adapter for Global Logger
//
// This is a thin adapter that wraps dataengine.Logger to maintain backward
// compatibility with the existing admin.go and relay.go code. All actual
// logging, buffering, and sink management is delegated to the global logger.
// ──────────────────────────────────────────────────────────────────────────────

// Re-export constants for backward compatibility
const (
	MaxLogEntries = dataengine.DefaultRingSize
	LogInfo       = dataengine.LevelInfo
	LogWarn       = dataengine.LevelWarn
	LogError      = dataengine.LevelError
	LogDebug      = dataengine.LevelDebug
)

// LogEntry is an alias for the global log entry type.
type LogEntry = dataengine.LogEntry

// TunnelLogger wraps the global dataengine.Logger for the exit node.
type TunnelLogger struct {
	engine *dataengine.Logger
}

// NewTunnelLogger creates a tunnel logger backed by the global engine.
// It adds a ConsoleSink for terminal output automatically.
func NewTunnelLogger() *TunnelLogger {
	engine := dataengine.NewLogger(
		dataengine.DefaultQueueSize,
		dataengine.DefaultRingSize,
	)
	// Always add colored console output for the exit node
	engine.AddSink(dataengine.NewConsoleSink(true))
	return &TunnelLogger{engine: engine}
}

// NewTunnelLoggerWithEngine creates a tunnel logger from an existing engine.
// Used when you want to share a single logger instance across modules.
func NewTunnelLoggerWithEngine(engine *dataengine.Logger) *TunnelLogger {
	return &TunnelLogger{engine: engine}
}

// Engine returns the underlying global logger for direct access.
func (tl *TunnelLogger) Engine() *dataengine.Logger {
	return tl.engine
}

// Log records a structured log entry.
func (tl *TunnelLogger) Log(level, component, message string) {
	tl.engine.Log(level, component, message)
}

// LogWithDetails records a log entry with additional detail text.
func (tl *TunnelLogger) LogWithDetails(level, component, message, details string) {
	tl.engine.LogWithDetails(level, component, message, details)
}

// Info logs at INFO level.
func (tl *TunnelLogger) Info(component, message string) {
	tl.engine.Info(component, message)
}

// Warn logs at WARN level.
func (tl *TunnelLogger) Warn(component, message string) {
	tl.engine.Warn(component, message)
}

// Error logs at ERROR level.
func (tl *TunnelLogger) Error(component, message string) {
	tl.engine.Error(component, message)
}

// Recent returns the most recent n log entries.
func (tl *TunnelLogger) Recent(n int) []LogEntry {
	return tl.engine.Recent(n)
}

// Stream returns a channel for real-time log events.
func (tl *TunnelLogger) Stream() <-chan LogEntry {
	return tl.engine.Stream()
}

// Count returns the number of entries in the ring buffer.
func (tl *TunnelLogger) Count() int {
	return tl.engine.Count()
}

// RecentJSON returns recent logs as a JSON byte slice.
func (tl *TunnelLogger) RecentJSON(n int) ([]byte, error) {
	entries := tl.Recent(n)
	return json.Marshal(entries)
}

// Close performs a graceful shutdown of the logging engine.
func (tl *TunnelLogger) Close() {
	tl.engine.Close()
}

// AddFileSink adds daily-rotating file logging.
func (tl *TunnelLogger) AddFileSink(dir, prefix string) error {
	sink, err := dataengine.NewFileSink(dir, prefix)
	if err != nil {
		return err
	}
	tl.engine.AddSink(sink)
	return nil
}

// AddCallbackSink adds a custom callback sink (e.g., WebSocket broadcast).
func (tl *TunnelLogger) AddCallbackSink(fn func(LogEntry)) {
	tl.engine.AddSink(dataengine.NewCallbackSink(fn))
}
