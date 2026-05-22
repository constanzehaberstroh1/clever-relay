package dataengine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── TestLoggerBasic ──────────────────────────────────────────────────────────

func TestLoggerBasic(t *testing.T) {
	logger := NewLogger(100, 50)
	defer logger.Close()

	// Collect logs via a test sink
	var collected []LogEntry
	var mu sync.Mutex
	logger.AddSink(NewCallbackSink(func(e LogEntry) {
		mu.Lock()
		collected = append(collected, e)
		mu.Unlock()
	}))

	logger.Info("test", "hello")
	logger.Warn("test", "warning")
	logger.Error("test", "error")
	logger.Debugf("test", "count=%d", 42)

	// Give consumer goroutine time to process
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(collected))
	}
	if collected[0].Level != LevelInfo || collected[0].Message != "hello" {
		t.Errorf("unexpected first entry: %+v", collected[0])
	}
	if collected[3].Level != LevelDebug || collected[3].Message != "count=42" {
		t.Errorf("unexpected Debugf entry: %+v", collected[3])
	}
}

// ── TestLoggerRingBuffer ─────────────────────────────────────────────────────

func TestLoggerRingBuffer(t *testing.T) {
	logger := NewLogger(100, 10) // small ring
	defer logger.Close()

	for i := 0; i < 25; i++ {
		logger.Infof("test", "msg-%d", i)
	}

	time.Sleep(50 * time.Millisecond)

	recent := logger.Recent(100) // ask for more than ring size
	if len(recent) != 10 {
		t.Fatalf("expected 10 entries (ring capacity), got %d", len(recent))
	}
	// Most recent should be msg-24
	if recent[9].Message != "msg-24" {
		t.Errorf("last entry should be msg-24, got %s", recent[9].Message)
	}
}

// ── TestLoggerZeroBlocking ───────────────────────────────────────────────────

func TestLoggerZeroBlocking(t *testing.T) {
	// Create a tiny queue to force drops
	logger := NewLogger(5, 10)

	// Add a slow sink that blocks
	var count atomic.Int64
	logger.AddSink(NewCallbackSink(func(e LogEntry) {
		count.Add(1)
		time.Sleep(10 * time.Millisecond) // simulate slow sink
	}))

	// Fire 100 logs rapidly — should NOT block
	start := time.Now()
	for i := 0; i < 100; i++ {
		logger.Info("test", "rapid fire")
	}
	elapsed := time.Since(start)

	// Should complete in < 10ms (if blocking, would take 100*10ms = 1s)
	if elapsed > 50*time.Millisecond {
		t.Errorf("logging blocked for %v (should be < 50ms)", elapsed)
	}

	// Some logs should have been dropped
	dropped := logger.Dropped()
	if dropped == 0 {
		t.Log("no drops detected (consumer was fast enough)")
	} else {
		t.Logf("dropped %d logs as expected (zero-blocking guarantee)", dropped)
	}

	logger.Close()
}

// ── TestLoggerGracefulShutdown ───────────────────────────────────────────────

func TestLoggerGracefulShutdown(t *testing.T) {
	logger := NewLogger(1000, 100)

	var count atomic.Int64
	logger.AddSink(NewCallbackSink(func(e LogEntry) {
		count.Add(1)
	}))

	// Enqueue logs
	for i := 0; i < 50; i++ {
		logger.Infof("test", "shutdown-test-%d", i)
	}

	// Close should drain all remaining
	logger.Close()

	// All 50 should have been processed
	final := count.Load()
	if final != 50 {
		t.Errorf("expected 50 logs after Close(), got %d", final)
	}
}

// ── TestLoggerStream ─────────────────────────────────────────────────────────

func TestLoggerStream(t *testing.T) {
	logger := NewLogger(100, 50)
	defer logger.Close()

	stream := logger.Stream()

	logger.Info("test", "streamed")

	select {
	case entry := <-stream:
		if entry.Message != "streamed" {
			t.Errorf("unexpected stream entry: %+v", entry)
		}
	case <-time.After(1 * time.Second):
		t.Error("stream timeout — no entry received")
	}
}

// ── TestLoggerWithTrace ──────────────────────────────────────────────────────

func TestLoggerWithTrace(t *testing.T) {
	logger := NewLogger(100, 50)
	defer logger.Close()

	var received LogEntry
	var mu sync.Mutex
	logger.AddSink(NewCallbackSink(func(e LogEntry) {
		mu.Lock()
		received = e
		mu.Unlock()
	}))

	logger.LogWithTrace(LevelInfo, "relay", "packet forwarded", "abcd1234", "trace-001")
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if received.SessionID != "abcd1234" {
		t.Errorf("expected SessionID=abcd1234, got %s", received.SessionID)
	}
	if received.TraceID != "trace-001" {
		t.Errorf("expected TraceID=trace-001, got %s", received.TraceID)
	}
}
