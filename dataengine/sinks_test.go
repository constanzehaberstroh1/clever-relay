package dataengine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── TestFileSinkRotation ─────────────────────────────────────────────────────

func TestFileSinkDailyRotation(t *testing.T) {
	dir := t.TempDir()

	sink, err := NewFileSinkWithRetention(dir, "test", 0) // no retention
	if err != nil {
		t.Fatalf("NewFileSink error: %v", err)
	}
	defer sink.Close()

	// Write a log entry
	sink.Write(LogEntry{
		Timestamp: "2026-05-22T10:00:00.000Z",
		Level:     LevelInfo,
		Component: "test",
		Message:   "hello from test",
	})

	// Verify file exists with today's date
	today := time.Now().Format("2006-01-02")
	expectedFile := filepath.Join(dir, fmt.Sprintf("test_%s.log", today))
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Fatalf("expected log file %s to exist", expectedFile)
	}

	// Read contents
	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("could not read log file: %v", err)
	}
	content := string(data)
	if len(content) == 0 {
		t.Error("log file is empty")
	}
	t.Logf("Log file contents: %s", content)
}

// ── TestFileSinkRetentionPolicy ──────────────────────────────────────────────

func TestFileSinkRetentionPolicy(t *testing.T) {
	dir := t.TempDir()

	// Create fake old log files
	oldFiles := []string{
		"app_2026-05-01.log", // 21 days old
		"app_2026-05-10.log", // 12 days old
		"app_2026-05-15.log", // 7 days old (on boundary)
		"app_2026-05-20.log", // 2 days old — should survive
		"app_2026-05-21.log", // 1 day old — should survive
		"other_2026-05-01.log", // different prefix — should survive
		"random.txt",            // not a log file — should survive
	}
	for _, name := range oldFiles {
		os.WriteFile(filepath.Join(dir, name), []byte("log data"), 0644)
	}

	// Create FileSink with 3-day retention (will purge anything > 3 days old)
	sink := &FileSink{
		dir:           dir,
		prefix:        "app",
		retentionDays: 3,
		done:          make(chan struct{}),
	}

	// Run purge manually
	sink.purgeOldFiles()

	// Check which files survived
	entries, _ := os.ReadDir(dir)
	survivors := make(map[string]bool)
	for _, e := range entries {
		survivors[e.Name()] = true
	}

	// Should be deleted (> 3 days old with "app" prefix)
	for _, shouldDelete := range []string{
		"app_2026-05-01.log",
		"app_2026-05-10.log",
		"app_2026-05-15.log",
	} {
		if survivors[shouldDelete] {
			t.Errorf("file %s should have been deleted (retention policy)", shouldDelete)
		}
	}

	// Should survive (recent, different prefix, or not a log)
	for _, shouldSurvive := range []string{
		"app_2026-05-20.log",
		"app_2026-05-21.log",
		"other_2026-05-01.log",
		"random.txt",
	} {
		if !survivors[shouldSurvive] {
			t.Errorf("file %s should have survived retention policy", shouldSurvive)
		}
	}

	t.Logf("Retention test: %d files survived out of %d", len(survivors), len(oldFiles))
}
