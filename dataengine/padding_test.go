package dataengine

import (
	"testing"
)

func TestPaddingRoundTrip(t *testing.T) {
	original := []byte("hello world this is a test envelope with some data inside it")

	padded, err := AddPadding(original)
	if err != nil {
		t.Fatalf("AddPadding: %v", err)
	}

	// Padded version must be larger
	if len(padded) <= len(original) {
		t.Fatalf("padded size %d should be > original %d", len(padded), len(original))
	}

	// Strip padding
	recovered, err := RemovePadding(padded)
	if err != nil {
		t.Fatalf("RemovePadding: %v", err)
	}

	if string(recovered) != string(original) {
		t.Fatalf("round-trip mismatch: got %q, want %q", recovered, original)
	}
}

func TestPaddingLengthVariation(t *testing.T) {
	data := []byte("fixed input")
	sizes := make(map[int]bool)

	for i := 0; i < 100; i++ {
		padded, err := AddPadding(data)
		if err != nil {
			t.Fatalf("AddPadding iter %d: %v", i, err)
		}
		sizes[len(padded)] = true
	}

	// With 100 iterations, we should see at least 5 distinct sizes
	if len(sizes) < 5 {
		t.Fatalf("expected high entropy in padding sizes, only got %d distinct sizes", len(sizes))
	}
}

func TestPaddingTruncatedData(t *testing.T) {
	// Too short
	_, err := RemovePadding([]byte{0x00})
	if err != ErrPaddingTruncated {
		t.Fatalf("expected ErrPaddingTruncated, got %v", err)
	}

	// Empty
	_, err = RemovePadding(nil)
	if err != ErrPaddingTruncated {
		t.Fatalf("expected ErrPaddingTruncated for nil, got %v", err)
	}
}

func BenchmarkAddPadding(b *testing.B) {
	data := make([]byte, 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AddPadding(data)
	}
}

func BenchmarkRemovePadding(b *testing.B) {
	data := make([]byte, 4096)
	padded, _ := AddPadding(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RemovePadding(padded)
	}
}
