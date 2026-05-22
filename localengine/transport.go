package main

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// ──────────────────────────────────────────────────────────────────────────────
// H2Transport – HTTP/2 Multiplexing + SNI Rotation + Clean IP Routing
//
// Creates persistent HTTP/2 connections to Google IPs with:
//   - SNI rotation across whitelisted Google domains
//   - Clean IP routing via IPScanner (fastest IPs from background probing)
//   - Keep-Alive for connection reuse (eliminates repeated TLS handshakes)
//   - Configurable TLS for Domain Fronting compatibility
//
// Phase 5: The scanner integration ensures that even when a local ISP
// degrades routing to certain Google IP ranges, we always use the fastest
// reachable path.
// ──────────────────────────────────────────────────────────────────────────────

// Whitelisted Google domains for SNI rotation.
// Iran's DPI sees these domains and allows the traffic.
var googleSNIs = []string{
	"mail.google.com",
	"drive.google.com",
	"maps.google.com",
	"docs.google.com",
	"sheets.google.com",
	"calendar.google.com",
	"translate.google.com",
	"photos.google.com",
	"meet.google.com",
	"chat.google.com",
}

// H2Transport manages HTTP/2 connections with SNI rotation and clean IP routing.
type H2Transport struct {
	transport *http.Transport
	scanner   *IPScanner
}

// NewH2Transport creates a transport optimized for tunneling through Google.
// It starts a background IPScanner that periodically probes Google IP ranges
// and routes connections through the fastest reachable IPs.
func NewH2Transport() *H2Transport {
	scanner := NewIPScanner()

	h2t := &H2Transport{
		scanner: scanner,
	}

	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
		// HTTP/2 settings for multiplexing
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     20,
		IdleConnTimeout:     120 * time.Second,
		// Keep connections alive
		DisableKeepAlives: false,
		// Disable compression (we handle it ourselves with Zstd)
		DisableCompression: true,
		// Clean IP Routing: resolve script.google.com to scanned IPs
		DialContext: h2t.dialWithCleanIP,
		// TLS handshake timeout
		TLSHandshakeTimeout: 10 * time.Second,
		// Response header timeout
		ResponseHeaderTimeout: 55 * time.Second,
	}

	// Force HTTP/2
	http2.ConfigureTransport(t)

	h2t.transport = t
	return h2t
}

// dialWithCleanIP overrides DNS resolution for Google domains, routing
// connections through the fastest IP discovered by the background scanner.
func (h *H2Transport) dialWithCleanIP(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	// Only override for Google domains (script.google.com and its redirects)
	if strings.HasSuffix(host, ".google.com") || strings.HasSuffix(host, ".googleapis.com") {
		bestIPs := h.scanner.BestIPs(3)
		if len(bestIPs) > 0 {
			// Pick a random IP from the top 3 to distribute load
			chosenIP := bestIPs[rand.Intn(len(bestIPs))]
			addr = net.JoinHostPort(chosenIP, port)
		}
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

// Transport returns the underlying http.Transport for use with http.Client.
func (h *H2Transport) Transport() *http.Transport {
	return h.transport
}

// Scanner returns the IP scanner for status queries.
func (h *H2Transport) Scanner() *IPScanner {
	return h.scanner
}

// Close shuts down the scanner and transport.
func (h *H2Transport) Close() {
	h.scanner.Close()
	h.transport.CloseIdleConnections()
}

// RandomSNI returns a random Google domain for SNI rotation.
func RandomSNI() string {
	return googleSNIs[rand.Intn(len(googleSNIs))]
}

