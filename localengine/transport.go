package main

import (
	"context"
	"crypto/tls"
	"log"
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
// CRITICAL FIX: GAS domains (script.google.com, *.googleusercontent.com)
// MUST use hardcoded/scanned IPs and NEVER system DNS. In censored networks,
// DNS is poisoned and returns local IPs (192.168.x.x) for Google domains.
// The scanner verifies which IPs actually serve GAS traffic (not 405).
// ──────────────────────────────────────────────────────────────────────────────

// SNI pool for domain fronting — DPI sees these whitelisted domains.
// Inspired by gasFrontSNIPoolDefault from reference project.
var googleSNIs = []string{
	"www.google.com",
	"mail.google.com",
	"accounts.google.com",
	"drive.google.com",
	"maps.google.com",
	"docs.google.com",
	"sheets.google.com",
	"calendar.google.com",
	"translate.google.com",
	"photos.google.com",
}

// googleOwnedSuffixes defines domains that belong to Google infrastructure.
// Traffic to these domains is routed through scanned clean IPs.
var googleOwnedSuffixes = []string{
	".google.com",
	".google.co",
	".googleapis.com",
	".gstatic.com",
	".googleusercontent.com",
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
		// Clean IP Routing: resolve Google domains to scanned IPs
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

// dialWithCleanIP overrides DNS resolution for Google-owned domains, routing
// connections through the fastest IP discovered by the background scanner.
//
// WHY THIS IS CRITICAL:
// In censored networks (Iran, China, etc.), system DNS is poisoned:
//   nslookup script.google.com → 192.168.52.89 (local router!)
//
// This means ANY code using system DNS to resolve Google domains will fail.
// We MUST bypass DNS entirely and use hardcoded/scanned IPs for ALL Google
// traffic — especially GAS domains which are our relay endpoints.
//
// For GAS domains specifically, we use BestIPs() which only returns IPs
// verified to serve GAS traffic (they return 302, not 405).
// For other Google domains, we use AllAliveIPs() which returns any reachable IP.
func (h *H2Transport) dialWithCleanIP(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	if isGASDomain(host) {
		// GAS domains → use ONLY verified GAS-capable IPs from scanner.
		// These IPs have been probed with HEAD Host:script.google.com and
		// confirmed to return 302 (not 405 like YouTube/Gmail CDN edges).
		bestIPs := h.scanner.BestIPs(3)
		if len(bestIPs) > 0 {
			chosenIP := bestIPs[rand.Intn(len(bestIPs))]
			log.Printf("[transport] GAS domain %s → scanned IP %s (DNS bypass)", host, chosenIP)
			addr = net.JoinHostPort(chosenIP, port)
		} else {
			// Fallback: use hardcoded App Engine IP when scanner hasn't run yet
			fallbackIP := gasFallbackIP()
			log.Printf("[transport] GAS domain %s → fallback IP %s (scanner empty)", host, fallbackIP)
			addr = net.JoinHostPort(fallbackIP, port)
		}
	} else if isGoogleOwned(host) {
		// Other Google domains → use any alive scanned IPs for domain fronting.
		allIPs := h.scanner.AllAliveIPs(3)
		if len(allIPs) > 0 {
			chosenIP := allIPs[rand.Intn(len(allIPs))]
			addr = net.JoinHostPort(chosenIP, port)
		}
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

// isGASDomain returns true if the host is a Google Apps Script domain.
// These domains are the relay endpoints and MUST use scanned IPs.
func isGASDomain(host string) bool {
	return host == "script.google.com" ||
		strings.HasSuffix(host, ".googleusercontent.com")
}

// isGoogleOwned returns true if the host belongs to Google infrastructure.
func isGoogleOwned(host string) bool {
	for _, suffix := range googleOwnedSuffixes {
		if strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}
	return false
}

// gasFallbackIP returns a hardcoded App Engine IP for when the scanner
// hasn't completed its first scan yet. These IPs are from the 216.239.x.x
// range which is dedicated Google infrastructure (not CDN).
func gasFallbackIP() string {
	fallbacks := []string{
		"216.239.32.120",
		"216.239.34.120",
		"216.239.36.120",
		"216.239.38.120",
	}
	return fallbacks[rand.Intn(len(fallbacks))]
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
