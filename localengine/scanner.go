package main

import (
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Google Clean IP Scanner
//
// Background module that periodically probes known Google IP ranges to
// find the fastest, most reliable IPs for routing H2 connections.
// This prevents local ISP routing issues from degrading tunnel performance.
// ──────────────────────────────────────────────────────────────────────────────

// Known Google IP ranges commonly used for Apps Script / googleapis
var googleIPCandidates = []string{
	"142.250.185.0",
	"142.250.186.0",
	"142.250.187.0",
	"142.250.188.0",
	"142.250.189.0",
	"172.217.16.0",
	"172.217.17.0",
	"172.217.18.0",
	"172.217.19.0",
	"172.217.20.0",
	"216.58.208.0",
	"216.58.209.0",
	"216.58.210.0",
	"216.58.211.0",
	"216.58.212.0",
}

// ScanResult holds the result of probing a single IP.
type ScanResult struct {
	IP      string
	Latency time.Duration
	Alive   bool
}

// IPScanner periodically scans Google IPs and ranks them.
type IPScanner struct {
	mu      sync.RWMutex
	results []ScanResult
	bestIPs []string
	done    chan struct{}
}

// NewIPScanner creates and starts a background IP scanner.
func NewIPScanner() *IPScanner {
	s := &IPScanner{
		done: make(chan struct{}),
	}
	go s.scanLoop()
	return s
}

// BestIPs returns the top N fastest Google IPs.
func (s *IPScanner) BestIPs(n int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n > len(s.bestIPs) {
		n = len(s.bestIPs)
	}
	result := make([]string, n)
	copy(result, s.bestIPs[:n])
	return result
}

// Close stops the scanner.
func (s *IPScanner) Close() {
	close(s.done)
}

func (s *IPScanner) scanLoop() {
	// Initial scan
	s.scan()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.scan()
		}
	}
}

func (s *IPScanner) scan() {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range googleIPCandidates {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			target := ip + ":443"
			start := time.Now()
			conn, err := net.DialTimeout("tcp", target, 3*time.Second)
			elapsed := time.Since(start)

			result := ScanResult{
				IP:      ip,
				Latency: elapsed,
				Alive:   err == nil,
			}
			if conn != nil {
				conn.Close()
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(ip)
	}

	wg.Wait()

	// Sort by latency (alive IPs first)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Alive != results[j].Alive {
			return results[i].Alive
		}
		return results[i].Latency < results[j].Latency
	})

	var bestIPs []string
	for _, r := range results {
		if r.Alive {
			bestIPs = append(bestIPs, r.IP)
		}
	}

	s.mu.Lock()
	s.results = results
	s.bestIPs = bestIPs
	s.mu.Unlock()

	if len(bestIPs) > 0 {
		log.Printf("[scanner] top 3 Google IPs: %v (best: %v)",
			bestIPs[:min(3, len(bestIPs))],
			results[0].Latency.Round(time.Millisecond))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
