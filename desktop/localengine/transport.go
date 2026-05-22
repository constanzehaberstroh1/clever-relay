package localengine

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
// CRITICAL: DialTLSContext gives us full control over the TLS handshake.
// Without it, Go's http.Transport uses the URL hostname as SNI, meaning
// DPI sees "script.google.com" in the ClientHello even if we changed the IP.
// With DialTLSContext, we inject a fake SNI (e.g., www.google.com) so DPI
// sees a benign domain while the HTTP Host header carries the real target.
// ──────────────────────────────────────────────────────────────────────────────

// SNI pool for domain fronting — DPI sees these whitelisted domains.
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
func NewH2Transport() *H2Transport {
	scanner := NewIPScanner()

	h2t := &H2Transport{
		scanner: scanner,
	}

	t := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       20,
		IdleConnTimeout:       120 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    true,
		TLSHandshakeTimeout:  10 * time.Second,
		ResponseHeaderTimeout: 55 * time.Second,

		// For non-TLS traffic
		DialContext: h2t.dialWithCleanIP,

		// ═══════════════════════════════════════════════════════════════
		// THE MASTER KEY: Full control over TLS handshake (Domain Fronting)
		//
		// Without this, Go's http.Transport uses the URL hostname as SNI:
		//   URL: https://script.google.com/...
		//   → TLS ClientHello SNI: script.google.com  (DPI sees this!)
		//
		// With DialTLSContext, we inject a fake SNI from our rotation pool:
		//   → TCP connect to 216.239.38.120:443      (clean Google IP)
		//   → TLS ClientHello SNI: www.google.com     (DPI sees this!)
		//   → HTTP Host header: script.google.com     (only Google sees)
		// ═══════════════════════════════════════════════════════════════
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Step 1: Open a raw TCP socket to a clean Google IP
			rawConn, err := h2t.dialWithCleanIP(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			host, _, _ := net.SplitHostPort(addr)
			sni := host // Default: use the original domain for non-Google traffic

			// Step 2: Apply SNI Rotation for GAS and Google-owned domains
			if isGASDomain(host) || isGoogleOwned(host) {
				sni = RandomSNI()
				log.Printf("[tls] Domain Fronting: target=%s → fake SNI=%s", host, sni)
			}

			// Step 3: TLS configuration with fake SNI + HTTP/2 ALPN
			tlsConfig := &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true, // Required for domain fronting (cert is for SNI domain, not target)
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

	http2.ConfigureTransport(t)

	h2t.transport = t
	return h2t
}

// dialWithCleanIP overrides DNS resolution for Google-owned domains.
func (h *H2Transport) dialWithCleanIP(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	if isGASDomain(host) {
		bestIPs := h.scanner.BestIPs(3)
		if len(bestIPs) > 0 {
			chosenIP := bestIPs[rand.Intn(len(bestIPs))]
			log.Printf("[transport] GAS domain %s → scanned IP %s (DNS bypass)", host, chosenIP)
			addr = net.JoinHostPort(chosenIP, port)
		} else {
			fallbackIP := gasFallbackIP()
			log.Printf("[transport] GAS domain %s → fallback IP %s (scanner empty)", host, fallbackIP)
			addr = net.JoinHostPort(fallbackIP, port)
		}
	} else if isGoogleOwned(host) {
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

// gasFallbackIP returns a hardcoded App Engine IP for pre-scanner startup.
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
