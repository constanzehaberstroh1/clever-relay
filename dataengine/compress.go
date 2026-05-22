package dataengine

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// ──────────────────────────────────────────────────────────────────────────────
// Zstd compression layer
//
// We use SpeedFastest to minimise CPU overhead on the hot path. Even at this
// level Zstd typically achieves 2–3x compression on structured binary data,
// which raises ciphertext entropy and shrinks payloads for the HTTP transport.
// ──────────────────────────────────────────────────────────────────────────────

var (
	zstdEncoderOnce sync.Once
	zstdDecoderOnce sync.Once
	zstdEncoder     *zstd.Encoder
	zstdDecoder     *zstd.Decoder
	zstdInitErr     error
)

// initEncoder lazily creates the global encoder.
func initEncoder() {
	zstdEncoderOnce.Do(func() {
		zstdEncoder, zstdInitErr = zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedFastest),
			zstd.WithEncoderConcurrency(1), // we call EncodeAll, not streaming
		)
	})
}

// initDecoder lazily creates the global decoder.
func initDecoder() {
	zstdDecoderOnce.Do(func() {
		zstdDecoder, zstdInitErr = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(0),            // auto
			zstd.WithDecoderMaxMemory(8*1024*1024*1024), // 8 GB guard
		)
	})
}

// Compress applies Zstd compression to src and appends the result to dst.
// Pass nil for dst to allocate a new slice.
func Compress(src, dst []byte) ([]byte, error) {
	initEncoder()
	if zstdInitErr != nil {
		return nil, fmt.Errorf("zstd encoder init: %w", zstdInitErr)
	}
	return zstdEncoder.EncodeAll(src, dst), nil
}

// Decompress applies Zstd decompression to src and appends the result to dst.
// Pass nil for dst to allocate a new slice.
func Decompress(src, dst []byte) ([]byte, error) {
	initDecoder()
	if zstdInitErr != nil {
		return nil, fmt.Errorf("zstd decoder init: %w", zstdInitErr)
	}
	out, err := zstdDecoder.DecodeAll(src, dst)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress: %w", err)
	}
	return out, nil
}
