package main

import (
	"bytes"
	"errors"
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
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("too many redirects")
				}
				// Preserve POST method on Google 302 redirects
				if len(via) > 0 && via[0].Method == http.MethodPost {
					req.Method = http.MethodPost
					if via[0].GetBody != nil {
						body, _ := via[0].GetBody()
						req.Body = body
					}
				}
				return nil
			},
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
		url += "?batch=1"
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
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

// SetNodes safely updates the pool with a new set of URLs at runtime.
// Existing nodes are preserved if their URL matches; new URLs get fresh nodes.
// This enables hot-reloading without interrupting active SOCKS5 connections.
func (p *GASPool) SetNodes(urls []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Build a lookup of existing nodes by URL
	existing := make(map[string]*GASNode, len(p.nodes))
	for _, node := range p.nodes {
		existing[node.URL] = node
	}

	// Build the new node list, preserving stats for known URLs
	newNodes := make([]*GASNode, len(urls))
	for i, url := range urls {
		if node, ok := existing[url]; ok {
			newNodes[i] = node
		} else {
			newNodes[i] = &GASNode{
				URL:        url,
				State:      NodeHealthy,
				AvgLatency: 500 * time.Millisecond,
			}
		}
	}

	p.nodes = newNodes
	log.Printf("[pool] hot-reloaded: %d GAS nodes active", len(newNodes))
}

// TotalNodes returns the total number of nodes (healthy + cooldown).
func (p *GASPool) TotalNodes() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.nodes)
}

// Close shuts down the pool.
func (p *GASPool) Close() {
	p.client.CloseIdleConnections()
}
