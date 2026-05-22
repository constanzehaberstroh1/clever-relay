package localengine

import (
	"bytes"
	"io"
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
	body, err := c.pool.Dispatch(sealed, false)
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

	batch, err := c.proto.SealBatch(pkts)
	if err != nil {
		log.Printf("[chunker] seal batch error: %v", err)
		return
	}
	_, err = c.pool.Dispatch(batch, true)
	if err != nil {
		log.Printf("[chunker] dispatch error: %v", err)
	}
}

func (c *Chunker) parseResponse(body []byte) (*RelayResponse, error) {
	if len(body) == 0 {
		return &RelayResponse{Status: "OK"}, nil
	}
	content := string(body)
	resp := &RelayResponse{Status: "OK"}

	if strings.HasPrefix(content, "STATUS=") {
		parts := strings.SplitN(content, "\n", 2)
		resp.Status = strings.TrimPrefix(parts[0], "STATUS=")
		if len(parts) > 1 && len(parts[1]) > 0 {
			pkt, err := c.proto.Open([]byte(parts[1]))
			if err != nil {
				resp.Data = []byte(parts[1])
			} else {
				resp.Data = pkt.Payload
			}
		}
		return resp, nil
	}

	pkt, err := c.proto.Open(body)
	if err != nil {
		resp.Data = body
		return resp, nil
	}
	resp.Data = pkt.Payload
	return resp, nil
}

func (c *Chunker) ScatterDispatch(envelopes [][]byte) []error {
	errs := make([]error, len(envelopes))
	var wg sync.WaitGroup
	for i, env := range envelopes {
		wg.Add(1)
		go func(idx int, data []byte) {
			defer wg.Done()
			_, errs[idx] = c.pool.Dispatch(data, false)
		}(i, env)
	}
	wg.Wait()
	return errs
}

func sealedReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}
