package dataengine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Pluggable Log Sinks
//
// Each sink implements the LogSink interface. The Logger fans out every
// log entry to all registered sinks. Sinks MUST NOT block.
//
// Available sinks:
//   • ConsoleSink   — Colored terminal output (development)
//   • FileSink      — Daily-rotating file output (production)
//   • CallbackSink  — Generic callback for custom integrations
//                     (WebSocket, Wails Events, etc.)
// ──────────────────────────────────────────────────────────────────────────────

// ── Console Sink ─────────────────────────────────────────────────────────────

// ConsoleSink writes colored, formatted log entries to stdout/stderr.
type ConsoleSink struct {
	mu      sync.Mutex
	colored bool // whether to use ANSI colors
}

// NewConsoleSink creates a console sink.
// If colored is true, uses ANSI escape codes for level coloring.
func NewConsoleSink(colored bool) *ConsoleSink {
	return &ConsoleSink{colored: colored}
}

// Write formats and prints a log entry to the console.
func (s *ConsoleSink) Write(entry LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse timestamp for compact display
	ts := entry.Timestamp
	if t, err := time.Parse("2006-01-02T15:04:05.000Z07:00", ts); err == nil {
		ts = t.Format("15:04:05.000")
	}

	if s.colored {
		var color string
		switch entry.Level {
		case LevelDebug:
			color = "\033[2m" // dim
		case LevelInfo:
			color = "\033[0;36m" // cyan
		case LevelWarn:
			color = "\033[1;33m" // yellow bold
		case LevelError:
			color = "\033[1;31m" // red bold
		default:
			color = "\033[0m"
		}
		reset := "\033[0m"

		msg := fmt.Sprintf("%s%s %-5s %s[%s]%s %s",
			"\033[2m", ts, entry.Level, color, entry.Component, reset, entry.Message)
		if entry.Details != "" {
			msg += fmt.Sprintf(" %s(%s)%s", "\033[2m", entry.Details, reset)
		}
		if entry.SessionID != "" {
			msg += fmt.Sprintf(" %ssid=%s%s", "\033[2m", entry.SessionID[:8], reset)
		}
		fmt.Fprintln(os.Stderr, msg)
	} else {
		msg := fmt.Sprintf("%s %-5s [%s] %s", ts, entry.Level, entry.Component, entry.Message)
		if entry.Details != "" {
			msg += fmt.Sprintf(" (%s)", entry.Details)
		}
		if entry.SessionID != "" {
			msg += fmt.Sprintf(" sid=%s", entry.SessionID[:8])
		}
		fmt.Fprintln(os.Stderr, msg)
	}
}

// Close is a no-op for ConsoleSink.
func (s *ConsoleSink) Close() error { return nil }

// ── File Sink (with Daily Rotation + Automatic Retention) ────────────────────

// Default retention period: files older than this are automatically deleted.
const DefaultRetentionDays = 7

// FileSink writes log entries to daily-rotated files with automatic cleanup.
// File format: {prefix}_2006-01-02.log
//
// Features:
//   - Daily rotation: new file at midnight crossing
//   - Automatic retention: background worker deletes files older than N days
//   - Thread-safe: all writes protected by mutex
type FileSink struct {
	mu       sync.Mutex
	dir      string   // directory to write logs
	prefix   string   // file name prefix (e.g., "exitnode", "client")
	file     *os.File // current open file
	fileDate string   // current file's date (YYYY-MM-DD)

	// Retention policy
	retentionDays int           // max age of log files (0 = no cleanup)
	done          chan struct{} // signals the reaper goroutine to stop
}

// NewFileSink creates a file sink that writes to the given directory.
// Files are named {prefix}_YYYY-MM-DD.log and rotated daily.
// A background goroutine automatically deletes files older than 7 days.
func NewFileSink(dir, prefix string) (*FileSink, error) {
	return NewFileSinkWithRetention(dir, prefix, DefaultRetentionDays)
}

// NewFileSinkWithRetention creates a file sink with a custom retention period.
// Set retentionDays to 0 to disable automatic cleanup.
func NewFileSinkWithRetention(dir, prefix string, retentionDays int) (*FileSink, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	s := &FileSink{
		dir:           dir,
		prefix:        prefix,
		retentionDays: retentionDays,
		done:          make(chan struct{}),
	}
	if err := s.rotate(); err != nil {
		return nil, err
	}

	// Start background retention worker
	if retentionDays > 0 {
		go s.retentionWorker()
	}

	return s, nil
}

// rotate opens a new log file for today's date if needed.
func (s *FileSink) rotate() error {
	today := time.Now().Format("2006-01-02")
	if s.fileDate == today && s.file != nil {
		return nil // already using today's file
	}

	// Close previous file
	if s.file != nil {
		s.file.Close()
	}

	filename := filepath.Join(s.dir, fmt.Sprintf("%s_%s.log", s.prefix, today))
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", filename, err)
	}

	s.file = f
	s.fileDate = today
	return nil
}

// Write formats and writes a log entry to the current file.
func (s *FileSink) Write(entry LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if we need to rotate (midnight crossed)
	if err := s.rotate(); err != nil {
		fmt.Fprintf(os.Stderr, "[file-sink] rotation error: %v\n", err)
		return
	}

	line := fmt.Sprintf("%s %-5s [%s] %s", entry.Timestamp, entry.Level, entry.Component, entry.Message)
	if entry.Details != "" {
		line += fmt.Sprintf(" | %s", entry.Details)
	}
	if entry.SessionID != "" {
		line += fmt.Sprintf(" | sid=%s", entry.SessionID)
	}
	if entry.TraceID != "" {
		line += fmt.Sprintf(" | tid=%s", entry.TraceID)
	}
	line += "\n"

	if s.file != nil {
		s.file.WriteString(line)
	}
}

// Close stops the retention worker, flushes and closes the current log file.
func (s *FileSink) Close() error {
	// Signal the retention worker to stop
	select {
	case <-s.done:
		// already closed
	default:
		close(s.done)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		return err
	}
	return nil
}

// ── Retention Worker ─────────────────────────────────────────────────────────

// retentionWorker runs every 24 hours and deletes log files older than
// the configured retention period. This prevents months of log files
// from accumulating and filling the disk.
func (s *FileSink) retentionWorker() {
	// Run immediately on startup, then every 24 hours
	s.purgeOldFiles()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.purgeOldFiles()
		}
	}
}

// purgeOldFiles scans the log directory and deletes files matching the
// pattern {prefix}_YYYY-MM-DD.log that are older than retentionDays.
func (s *FileSink) purgeOldFiles() {
	cutoff := time.Now().AddDate(0, 0, -s.retentionDays)
	pattern := s.prefix + "_"

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[file-sink] retention scan error: %v\n", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()

		// Match pattern: {prefix}_YYYY-MM-DD.log
		if !strings.HasPrefix(name, pattern) || !strings.HasSuffix(name, ".log") {
			continue
		}

		// Extract the date portion
		dateStr := strings.TrimPrefix(name, pattern)
		dateStr = strings.TrimSuffix(dateStr, ".log")

		fileDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue // not a valid date format, skip
		}

		if fileDate.Before(cutoff) {
			path := filepath.Join(s.dir, name)
			if err := os.Remove(path); err != nil {
				fmt.Fprintf(os.Stderr, "[file-sink] retention delete error %s: %v\n", name, err)
			}
		}
	}
}

// ── Callback Sink ────────────────────────────────────────────────────────────

// CallbackSink wraps a function as a LogSink. This is the bridge for
// environment-specific integrations:
//   - exitnode: wraps WebSocket broadcast
//   - desktop: wraps Wails runtime.EventsEmit()
type CallbackSink struct {
	fn func(LogEntry)
}

// NewCallbackSink creates a sink that calls fn for every log entry.
func NewCallbackSink(fn func(LogEntry)) *CallbackSink {
	return &CallbackSink{fn: fn}
}

// Write calls the callback function.
func (s *CallbackSink) Write(entry LogEntry) {
	if s.fn != nil {
		s.fn(entry)
	}
}

// Close is a no-op for CallbackSink.
func (s *CallbackSink) Close() error { return nil }
