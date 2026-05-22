package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// App Engine Targeted IP Scanner (Phase 3)
//
// Unlike the previous scanner that probed generic Google CDN IPs (which include
// YouTube, Gmail, and other edge servers that return 405 for GAS requests),
// this scanner ONLY targets IP ranges belonging to Google App Engine and
// Google Sites infrastructure.
//
// Key improvements:
//   1. Restricted to App Engine subnets (216.239.32.0/19, select 142.250.x.x)
//   2. Logical probing: sends HEAD with Host: script.google.com to verify
//      the IP actually serves GAS traffic (not just TCP connectivity)
//   3. IPs returning 405 are immediately blacklisted
//   4. Results are ranked by latency for optimal routing
// ──────────────────────────────────────────────────────────────────────────────

// GAS-capable IP candidates — verified to serve Google Apps Script traffic.
// Sourced from the reference project's gasCandidateIPs list and verified
// against live GAS infrastructure. These IPs return 302 (redirect to
// execution endpoint) instead of 405 (CDN edge rejection).
//
// IMPORTANT: When DNS is poisoned (returns 192.168.x.x for script.google.com),
// these hardcoded IPs are the ONLY way to reach Google's servers.
var appEngineIPCandidates = []string{
	// Google App Engine / Sites dedicated infrastructure (216.239.x.x)
	"216.239.32.120",
	"216.239.34.120",
	"216.239.36.120",
	"216.239.38.120",
	// Verified GAS-capable Google Front End IPs (142.250.x.x)
	"142.250.80.142",
	"142.250.80.138",
	"142.250.179.110",
	"142.250.185.110",
	"142.250.184.206",
	"142.250.190.238",
	"142.250.191.78",
	"142.250.80.170",
	"142.250.72.206",
	"142.250.64.206",
	"142.250.72.110",
	// Google Front End IPs (172.217.x.x)
	"172.217.1.206",
	"172.217.14.206",
	"172.217.16.142",
	"172.217.22.174",
	"172.217.164.110",
	"172.217.168.206",
	"172.217.169.206",
	// Additional verified ranges (142.251.x.x, 34.x.x.x)
	"142.251.32.110",
	"142.251.33.110",
	"142.251.46.206",
	"142.251.46.238",
	// Google Cloud App Engine
	"34.107.221.82",
}

// ScanResult holds the result of probing a single IP.
type ScanResult struct {
	IP         string
	Latency    time.Duration
	Alive      bool
	GASCapable bool   // true if the IP can serve GAS traffic (not 405)
	StatusCode int    // HTTP status code from HEAD probe
}

// IPScanner periodically scans Google IPs and ranks them.
type IPScanner struct {
	mu      sync.RWMutex
	results []ScanResult
	bestIPs []string // only IPs confirmed to serve GAS
	allIPs  []string // all alive IPs (including non-GAS)
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

// BestIPs returns the top N fastest GAS-capable Google IPs.
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

// AllAliveIPs returns all alive IPs (for non-GAS routing).
func (s *IPScanner) AllAliveIPs(n int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n > len(s.allIPs) {
		n = len(s.allIPs)
	}
	result := make([]string, n)
	copy(result, s.allIPs[:n])
	return result
}

// Results returns the latest scan results for the admin panel.
func (s *IPScanner) Results() []ScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScanResult, len(s.results))
	copy(out, s.results)
	return out
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

	for _, ip := range appEngineIPCandidates {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			result := s.probeIP(ip)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(ip)
	}

	wg.Wait()

	// Sort by: GAS-capable first, then alive, then by latency
	sort.Slice(results, func(i, j int) bool {
		// GAS-capable IPs always come first
		if results[i].GASCapable != results[j].GASCapable {
			return results[i].GASCapable
		}
		// Then alive before dead
		if results[i].Alive != results[j].Alive {
			return results[i].Alive
		}
		// Then by latency
		return results[i].Latency < results[j].Latency
	})

	var bestIPs []string
	var allIPs []string
	for _, r := range results {
		if r.Alive {
			allIPs = append(allIPs, r.IP)
			if r.GASCapable {
				bestIPs = append(bestIPs, r.IP)
			}
		}
	}

	s.mu.Lock()
	s.results = results
	s.bestIPs = bestIPs
	s.allIPs = allIPs
	s.mu.Unlock()

	gasCount := len(bestIPs)
	aliveCount := len(allIPs)

	if gasCount > 0 {
		topN := gasCount
		if topN > 3 {
			topN = 3
		}
		log.Printf("[scanner] scan complete: %d GAS-capable, %d alive total | top: %v (best: %v)",
			gasCount, aliveCount,
			bestIPs[:topN],
			results[0].Latency.Round(time.Millisecond))
	} else if aliveCount > 0 {
		log.Printf("[scanner] WARNING: %d alive IPs but NONE are GAS-capable (all returned 405)", aliveCount)
	} else {
		log.Printf("[scanner] WARNING: no alive IPs found — all probes failed")
	}
}

// probeIP performs a logical probe of a single IP.
// Step 3.2: Instead of just TCP ping, we do a full TLS+HTTP HEAD probe
// with Host: script.google.com to verify the IP can actually serve GAS.
func (s *IPScanner) probeIP(ip string) ScanResult {
	result := ScanResult{IP: ip}
	target := ip + ":443"

	start := time.Now()

	// Phase 1: TCP connectivity check
	tcpConn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		result.Latency = time.Since(start)
		return result
	}

	result.Alive = true

	// Phase 2: TLS handshake
	tlsConn := tls.Client(tcpConn, &tls.Config{
		ServerName:         "www.google.com",
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	})
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		result.Latency = time.Since(start)
		return result
	}

	// Phase 3: HTTP HEAD probe with Host: script.google.com
	headReq := "HEAD / HTTP/1.1\r\nHost: script.google.com\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(headReq)); err != nil {
		tlsConn.Close()
		result.Latency = time.Since(start)
		return result
	}

	// Read the status line
	reader := bufio.NewReaderSize(tlsConn, 1024)
	statusLine, err := reader.ReadString('\n')
	tlsConn.Close()

	result.Latency = time.Since(start)

	if err != nil {
		return result
	}

	// Parse status code
	statusLine = strings.TrimSpace(statusLine)
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) >= 2 {
		code, parseErr := strconv.Atoi(parts[1])
		if parseErr == nil {
			result.StatusCode = code
			// 302 Found or 200 OK means the IP can serve GAS traffic
			// 405 Method Not Allowed means it's a CDN edge (YouTube/Gmail)
			if code == 200 || code == 301 || code == 302 {
				result.GASCapable = true
			} else if code == 405 {
				result.GASCapable = false
				log.Printf("[scanner] IP %s returned 405 — not GAS-capable (CDN edge)", ip)
			}
		}
	}

	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FormatResults returns a human-readable summary for the admin panel.
func (s *IPScanner) FormatResults() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Scanner: %d IPs probed\n", len(s.results)))
	sb.WriteString(fmt.Sprintf("GAS-capable: %d | All alive: %d\n\n", len(s.bestIPs), len(s.allIPs)))

	for _, r := range s.results {
		status := "DEAD"
		if r.Alive {
			if r.GASCapable {
				status = fmt.Sprintf("GAS-OK (HTTP %d)", r.StatusCode)
			} else if r.StatusCode > 0 {
				status = fmt.Sprintf("NOT-GAS (HTTP %d)", r.StatusCode)
			} else {
				status = "ALIVE (no HTTP)"
			}
		}
		sb.WriteString(fmt.Sprintf("  %-16s  %8s  %s\n",
			r.IP, r.Latency.Round(time.Millisecond), status))
	}

	return sb.String()
}
