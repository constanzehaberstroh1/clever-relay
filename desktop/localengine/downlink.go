package localengine

import (
	"container/heap"
	"sync"

	"github.com/salman/clever-relay/dataengine"
)

// ──────────────────────────────────────────────────────────────────────────────
// Downlink Engine – SeqNum Reassembly with Min-Heap
//
// Data returning from different GAS scripts may arrive out-of-order due
// to varying latencies. The reassembler buffers packets by SeqNum and
// delivers them in-order to the SOCKS5 connection (browser).
// ──────────────────────────────────────────────────────────────────────────────

// Reassembler reorders out-of-order packets for a single session.
type Reassembler struct {
	mu          sync.Mutex
	expected    uint32        // next expected SeqNum
	buffer      packetHeap    // min-heap sorted by SeqNum
	readyCh     chan struct{} // signaled when in-order data is available
}

// NewReassembler creates a reassembler starting at sequence number 0.
func NewReassembler() *Reassembler {
	r := &Reassembler{
		readyCh: make(chan struct{}, 1),
	}
	heap.Init(&r.buffer)
	return r
}

// Insert adds a packet. If it completes the sequence, signals readyCh.
func (r *Reassembler) Insert(pkt *dataengine.TunnelPacket) {
	r.mu.Lock()
	defer r.mu.Unlock()

	heap.Push(&r.buffer, pkt)

	// Check if the next expected packet is now available
	if r.buffer.Len() > 0 && r.buffer[0].SeqNum == r.expected {
		select {
		case r.readyCh <- struct{}{}:
		default:
		}
	}
}

// Drain returns all contiguous in-order packets starting from `expected`.
func (r *Reassembler) Drain() []*dataengine.TunnelPacket {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []*dataengine.TunnelPacket

	for r.buffer.Len() > 0 && r.buffer[0].SeqNum == r.expected {
		pkt := heap.Pop(&r.buffer).(*dataengine.TunnelPacket)
		result = append(result, pkt)
		r.expected++
	}

	return result
}

// Ready returns a channel that is signaled when in-order data may be available.
func (r *Reassembler) Ready() <-chan struct{} {
	return r.readyCh
}

// ──────────────────────────────────────────────────────────────────────────────
// Min-Heap implementation for TunnelPackets (sorted by SeqNum)
// ──────────────────────────────────────────────────────────────────────────────

type packetHeap []*dataengine.TunnelPacket

func (h packetHeap) Len() int            { return len(h) }
func (h packetHeap) Less(i, j int) bool  { return h[i].SeqNum < h[j].SeqNum }
func (h packetHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }

func (h *packetHeap) Push(x interface{}) {
	*h = append(*h, x.(*dataengine.TunnelPacket))
}

func (h *packetHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	*h = old[:n-1]
	return item
}
