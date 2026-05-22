package localengine

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/salman/clever-relay/dataengine"
)

const (
	FlushInterval  = 10 * time.Millisecond
	FlushThreshold = 256 * 1024
)

type RelayResponse struct {
	Data   []byte
	Status string
}

type Chunker struct {
	proto   *dataengine.Protocol
	pool    *GASPool
	mu      sync.Mutex
	queue   []*dataengine.TunnelPacket
	queueSz int
	done    chan struct{}
	wg      sync.WaitGroup
}

func NewChunker(proto *dataengine.Protocol, pool *GASPool) *Chunker {
	c := &Chunker{
		proto: proto,
		pool:  pool,
		done:  make(chan struct{}),
	}
	c.wg.Add(1)
	go c.flushLoop()
	return c
}

func (c *Chunker) Enqueue(pkt *dataengine.TunnelPacket) {
	c.mu.Lock()
	c.queue = append(c.queue, pkt)
	c.queueSz += len(pkt.Payload) + dataengine.HeaderSize
	shouldFlush := c.queueSz >= FlushThreshold
	c.mu.Unlock()
	if shouldFlush {
		c.flush()
	}
}

func (c *Chunker) SendImmediate(pkt *dataengine.TunnelPacket) (*RelayResponse, error) {
	sealed, err := c.proto.Seal(pkt)
	if err != nil {
		return nil, err
	}

	// Base64-encode so GAS's postData.contents doesn't corrupt the binary.
	// The exit node will Base64-decode before decryption.
	b64Data := base64.StdEncoding.EncodeToString(sealed)

	body, err := c.pool.Dispatch([]byte(b64Data), false)
	if err != nil {
		return nil, err
	}
	return c.parseResponse(body)
}

func (c *Chunker) Close() {
	close(c.done)
	c.flush()
	c.wg.Wait()
}

func (c *Chunker) flushLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.flush()
		}
	}
}

func (c *Chunker) flush() {
	c.mu.Lock()
	if len(c.queue) == 0 {
		c.mu.Unlock()
		return
	}
	pkts := c.queue
	c.queue = nil
	c.queueSz = 0
	c.mu.Unlock()

	// Seal each packet individually and Base64-encode for GAS safety.
	// Since fetchAll fires separate requests, each packet goes through
	// its own GAS → exit node round-trip via ScatterDispatch.
	var envelopes [][]byte
	for _, pkt := range pkts {
		sealed, err := c.proto.Seal(pkt)
		if err != nil {
			log.Printf("[chunker] seal error: %v", err)
			continue
		}
		b64Data := base64.StdEncoding.EncodeToString(sealed)
		envelopes = append(envelopes, []byte(b64Data))
	}

	if len(envelopes) > 0 {
		errs := c.ScatterDispatch(envelopes)
		for i, err := range errs {
			if err != nil {
				log.Printf("[chunker] scatter dispatch[%d] error: %v", i, err)
			}
		}
	}
}

func (c *Chunker) parseResponse(body []byte) (*RelayResponse, error) {
	if len(body) == 0 {
		return &RelayResponse{Status: "OK"}, nil
	}
	content := string(body)
	resp := &RelayResponse{Status: "OK"}

	// GAS prefixes the response with "STATUS=...\n" when the exit node
	// sets the X-Session-Status header. Parse and strip it.
	if strings.HasPrefix(content, "STATUS=") {
		parts := strings.SplitN(content, "\n", 2)
		resp.Status = strings.TrimPrefix(parts[0], "STATUS=")
		if len(parts) > 1 && len(parts[1]) > 0 {
			content = parts[1]
		} else {
			return resp, nil
		}
	}

	// The exit node Base64-encodes all sealed envelopes.
	// Decode from Base64, then decrypt.
	raw, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		// Not valid Base64 — treat as raw data (direct-to-server testing)
		raw = []byte(content)
	}

	pkt, err := c.proto.Open(raw)
	if err != nil {
		// Decryption failed — return raw data for debugging
		resp.Data = raw
		return resp, nil
	}
	resp.Data = pkt.Payload
	return resp, nil
}

// ScatterDispatch fires envelopes in parallel through different GAS nodes.
// Each goroutine has a 15-second timeout to prevent one slow GAS script
// from blocking the entire flush pipeline (which would cause the queue
// to explode and leak memory). If a packet times out, the browser's own
// TCP retransmission mechanism will re-request the data.
func (c *Chunker) ScatterDispatch(envelopes [][]byte) []error {
	const scatterTimeout = 15 * time.Second

	errs := make([]error, len(envelopes))
	var wg sync.WaitGroup
	for i, env := range envelopes {
		wg.Add(1)
		go func(idx int, data []byte) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), scatterTimeout)
			defer cancel()

			done := make(chan struct{})
			go func() {
				_, errs[idx] = c.pool.Dispatch(data, false)
				close(done)
			}()

			select {
			case <-done:
				// Dispatch completed normally
			case <-ctx.Done():
				errs[idx] = fmt.Errorf("scatter timeout (%v) for packet %d", scatterTimeout, idx)
			}
		}(i, env)
	}
	wg.Wait()
	return errs
}
