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
//   - True Domain Fronting via DialTLSContext (not just IP substitution)
//   - SNI rotation across whitelisted Google domains
//   - Clean IP routing via IPScanner (fastest IPs from background probing)
//   - Keep-Alive for connection reuse (eliminates repeated TLS handshakes)
//
// CRITICAL: DialTLSContext gives us full control over the TLS handshake.
// Without it, Go's http.Transport uses the URL hostname as SNI, meaning
// DPI sees "script.google.com" in the ClientHello even if we changed the IP.
// With DialTLSContext, we inject a fake SNI (e.g., www.google.com) so DPI
// sees a benign domain while the HTTP Host header carries the real target.
// ──────────────────────────────────────────────────────────────────────────────

// SNI pool for domain fronting — DPI sees these whitelisted domains.
// These are common Google services that are rarely blocked.
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
//
// The key innovation is DialTLSContext: instead of letting Go set the SNI
// from the URL hostname, we manually perform the TLS handshake with a
// rotated fake SNI. This makes Domain Fronting actually work.
func NewH2Transport() *H2Transport {
	scanner := NewIPScanner()

	h2t := &H2Transport{
		scanner: scanner,
	}

	t := &http.Transport{
		// HTTP/2 multiplexing settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     20,
		IdleConnTimeout:     120 * time.Second,
		// Keep connections alive for reuse
		DisableKeepAlives: false,
		// Disable compression (we handle it ourselves with Zstd)
		DisableCompression: true,
		// Timeouts
		TLSHandshakeTimeout:  10 * time.Second,
		ResponseHeaderTimeout: 55 * time.Second,

		// For non-TLS traffic (rare, but needed for completeness)
		DialContext: h2t.dialWithCleanIP,

		// ═══════════════════════════════════════════════════════════════
		// THE MASTER KEY: Full control over TLS handshake (Domain Fronting)
		//
		// Without this, Go's http.Transport uses the URL hostname as SNI:
		//   URL: https://script.google.com/...
		//   → TLS ClientHello SNI: script.google.com  (DPI sees this!)
		//
		// With DialTLSContext, we intercept the TLS handshake and inject
		// a fake SNI from our rotation pool:
		//   → TCP connect to 216.239.38.120:443      (clean Google IP)
		//   → TLS ClientHello SNI: www.google.com     (DPI sees this!)
		//   → HTTP Host header: script.google.com     (only Google sees)
		// ═══════════════════════════════════════════════════════════════
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Step 1: Open a raw TCP socket to a clean Google IP
			// (uses scanner's BestIPs for GAS domains, AllAliveIPs for others)
			rawConn, err := h2t.dialWithCleanIP(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			host, _, _ := net.SplitHostPort(addr)
			sni := host // Default: use the real hostname as SNI
			fakeSNI := false

			// Step 2: Apply SNI Rotation — for script.google.com and script.googleusercontent.com
			//
			// CRITICAL: Google GHS IPs (216.239.x.x) do not natively serve or
			// perform TLS handshakes for script.googleusercontent.com. If we connect
			// with the real SNI (script.googleusercontent.com), GHS returns a cert
			// mismatch or falls back to serving a generic Google Docs landing page
			// (which results in a 405 error).
			//
			// To bypass this, we MUST use a fake SNI (e.g. www.google.com) for BOTH
			// script.google.com and script.googleusercontent.com redirect targets.
			// This forces GHS to accept the connection and route based entirely
			// on the HTTP Host header.
			if isGASDomain(host) {
				sni = RandomSNI()
				fakeSNI = true
				log.Printf("[tls] Domain Fronting (GAS): target=%s → fake SNI=%s", host, sni)
			} else if isGoogleOwned(host) && !strings.HasSuffix(host, ".googleusercontent.com") {
				sni = RandomSNI()
				fakeSNI = true
				log.Printf("[tls] Domain Fronting (Google): target=%s → fake SNI=%s", host, sni)
			}

			// Step 3: TLS configuration with ALPN for HTTP/2
			tlsConfig := &tls.Config{
				ServerName: sni,
				// Only skip cert verification when using a fake SNI.
				// When SNI matches the real host, normal verification works
				// (Google returns valid certs for *.google.com and *.googleusercontent.com).
				InsecureSkipVerify: fakeSNI,
				MinVersion:         tls.VersionTLS12,
				NextProtos:         []string{"h2", "http/1.1"},
			}

			// Step 4: Wrap the raw TCP socket with TLS
			tlsConn := tls.Client(rawConn, tlsConfig)

			// Step 5: Manual handshake with context deadline
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}

			return tlsConn, nil
		},
	}

	// Configure HTTP/2 on top of our custom TLS dialer.
	// This hooks into DialTLSContext and uses the ALPN-negotiated "h2" protocol.
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
