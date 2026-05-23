package localengine

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Smart GAS Pool – Intelligent Layer 7 Load Balancer
//
// Strategies:
//   1. Weighted Least-Latency: routes traffic to the fastest GAS node
//   2. Circuit Breaker: quarantines nodes on 429 (24h) or 500 (5 min)
//   3. Parallel Scatter: fires chunks through multiple nodes simultaneously
// ──────────────────────────────────────────────────────────────────────────────

type NodeState int

const (
	NodeHealthy    NodeState = iota
	NodeCooldown5M           // 500/502 error → 5 min cooldown
	NodeCooldown24H          // 429 rate limit → 24 hour cooldown
)

type GASNode struct {
	URL        string
	State      NodeState
	CooldownAt time.Time     // when cooldown expires
	AvgLatency time.Duration // exponential moving average
	Failures   int32
	Successes  int64
	mu         sync.RWMutex
}

type GASPool struct {
	nodes      []*GASNode
	currentIdx uint64
	client     *http.Client
	transport  *H2Transport
	mu         sync.RWMutex
}

func NewGASPool(urls []string, transport *H2Transport) *GASPool {
	nodes := make([]*GASNode, len(urls))
	for i, url := range urls {
		nodes[i] = &GASNode{
			URL:        url,
			State:      NodeHealthy,
			AvgLatency: 500 * time.Millisecond, // initial estimate
		}
	}

	pool := &GASPool{
		nodes:     nodes,
		transport: transport,
		client: &http.Client{
			Transport: transport.Transport(),
			Timeout:   55 * time.Second, // just under GAS 60s limit
		},
	}
	return pool
}

// GetOptimalNode selects the best available node using weighted latency.
func (p *GASPool) GetOptimalNode() *GASNode {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var best *GASNode
	bestLatency := time.Duration(math.MaxInt64)
	now := time.Now()

	for _, node := range p.nodes {
		node.mu.RLock()
		state := node.State
		cooldownAt := node.CooldownAt
		latency := node.AvgLatency
		node.mu.RUnlock()

		// Skip nodes in cooldown
		if state != NodeHealthy {
			if now.After(cooldownAt) {
				// Cooldown expired, resurrect
				node.mu.Lock()
				node.State = NodeHealthy
				atomic.StoreInt32(&node.Failures, 0)
				node.mu.Unlock()
			} else {
				continue
			}
		}

		if latency < bestLatency {
			bestLatency = latency
			best = node
		}
	}

	if best == nil {
		// All nodes are in cooldown – use round-robin fallback
		idx := atomic.AddUint64(&p.currentIdx, 1) % uint64(len(p.nodes))
		return p.nodes[idx]
	}

	return best
}

// Dispatch sends encrypted data through the optimal GAS node.
func (p *GASPool) Dispatch(data []byte, isBatch bool) ([]byte, error) {
	node := p.GetOptimalNode()
	return p.dispatchToNode(node, data, isBatch)
}

func (p *GASPool) dispatchToNode(node *GASNode, data []byte, isBatch bool) ([]byte, error) {
	url := node.URL
	if isBatch {
		url += "?mode=batch"
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// IMPORTANT: Use text/plain, not application/octet-stream!
	// The payload is Base64-encoded text. GAS's doPost only processes
	// POST requests with text-compatible Content-Types. Sending
	// octet-stream causes a 405 on some ISPs/proxy redirect chains.
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// Set GetBody for redirect preservation
	bodyBytes := data
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}

	start := time.Now()
	resp, err := p.client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		p.markFailure(node, 0)
		return nil, fmt.Errorf("dispatch to %s: %w", node.URL, err)
	}
	defer resp.Body.Close()

	// Update latency (exponential moving average)
	node.mu.Lock()
	node.AvgLatency = (node.AvgLatency*7 + elapsed*3) / 10 // 70/30 EMA
	node.mu.Unlock()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		p.markFailure(node, resp.StatusCode)
		// Log response details for debugging GAS/redirect issues
		bodySnippet := string(body)
		if len(bodySnippet) > 200 {
			bodySnippet = bodySnippet[:200] + "..."
		}
		log.Printf("[pool] HTTP %d from %s (final_url=%s, body=%q)",
			resp.StatusCode, node.URL, resp.Request.URL.String(), bodySnippet)
		return body, fmt.Errorf("HTTP %d from GAS node %s", resp.StatusCode, node.URL)
	}

	// Success – reset failure count
	atomic.StoreInt32(&node.Failures, 0)
	atomic.AddInt64(&node.Successes, 1)

	return body, nil
}

// markFailure applies the circuit breaker logic.
func (p *GASPool) markFailure(node *GASNode, statusCode int) {
	fails := atomic.AddInt32(&node.Failures, 1)

	node.mu.Lock()
	defer node.mu.Unlock()

	switch {
	case statusCode == 429:
		// Rate limited – 24 hour cooldown
		node.State = NodeCooldown24H
		node.CooldownAt = time.Now().Add(24 * time.Hour)
		log.Printf("[pool] node %s → 24H cooldown (429 rate limit)", node.URL)

	case statusCode >= 500 || fails > 3:
		// Server error or repeated failures – 5 min cooldown
		node.State = NodeCooldown5M
		node.CooldownAt = time.Now().Add(5 * time.Minute)
		log.Printf("[pool] node %s → 5M cooldown (status=%d, fails=%d)",
			node.URL, statusCode, fails)
	}
}

// HealthyCount returns the number of healthy nodes.
func (p *GASPool) HealthyCount() int {
	count := 0
	now := time.Now()
	for _, node := range p.nodes {
		node.mu.RLock()
		if node.State == NodeHealthy || now.After(node.CooldownAt) {
			count++
		}
		node.mu.RUnlock()
	}
	return count
}

// Close shuts down the pool.
func (p *GASPool) Close() {
	p.client.CloseIdleConnections()
}

// SetNodes safely updates the pool with a new set of URLs at runtime.
// It preserves existing nodes' latency metrics and circuit breaker state.
func (p *GASPool) SetNodes(urls []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	newNodes := make([]*GASNode, len(urls))
	for i, url := range urls {
		var existing *GASNode
		for _, oldNode := range p.nodes {
			if oldNode.URL == url {
				existing = oldNode
				break
			}
		}

		if existing != nil {
			newNodes[i] = existing
		} else {
			newNodes[i] = &GASNode{
				URL:        url,
				State:      NodeHealthy,
				AvgLatency: 500 * time.Millisecond,
			}
		}
	}
	p.nodes = newNodes
}

