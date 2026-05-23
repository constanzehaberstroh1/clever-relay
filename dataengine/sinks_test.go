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

	now := time.Now()

	// Create fake log files dynamically
	// retentionDays is 3
	// Files that should be deleted (> 3 days old):
	del1 := fmt.Sprintf("app_%s.log", now.AddDate(0, 0, -10).Format("2006-01-02")) // 10 days old
	del2 := fmt.Sprintf("app_%s.log", now.AddDate(0, 0, -4).Format("2006-01-02"))  // 4 days old

	// Files that should survive (<= 3 days old, or different prefix, or not a log):
	keep1 := fmt.Sprintf("app_%s.log", now.AddDate(0, 0, -2).Format("2006-01-02")) // 2 days old
	keep2 := fmt.Sprintf("app_%s.log", now.AddDate(0, 0, -1).Format("2006-01-02")) // 1 day old
	keep3 := fmt.Sprintf("other_%s.log", now.AddDate(0, 0, -10).Format("2006-01-02")) // different prefix
	keep4 := "random.txt"

	allFiles := []string{del1, del2, keep1, keep2, keep3, keep4}
	for _, name := range allFiles {
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
	for _, shouldDelete := range []string{del1, del2} {
		if survivors[shouldDelete] {
			t.Errorf("file %s should have been deleted (retention policy)", shouldDelete)
		}
	}

	// Should survive (recent, different prefix, or not a log)
	for _, shouldSurvive := range []string{keep1, keep2, keep3, keep4} {
		if !survivors[shouldSurvive] {
			t.Errorf("file %s should have survived retention policy", shouldSurvive)
		}
	}

	t.Logf("Retention test: %d files survived out of %d", len(survivors), len(allFiles))
}
