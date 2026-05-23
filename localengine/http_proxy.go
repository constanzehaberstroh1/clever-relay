package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/salman/clever-relay/dataengine"
	"golang.org/x/net/proxy"
)

// ──────────────────────────────────────────────────────────────────────────────
// HTTP Proxy Server – Phase 9
//
// Provides a standard HTTP/HTTPS proxy that forwards ALL traffic through the
// local SOCKS5 engine. This allows applications that don't support SOCKS5
// natively (curl, wget, most system-level settings, Docker, apt, etc.) to
// use the tunnel via standard HTTP proxy environment variables:
//
//   export http_proxy=http://127.0.0.1:8080
//   export https_proxy=http://127.0.0.1:8080
//
// Architecture:
//
//   Browser/App → HTTP Proxy (:8080) → SOCKS5 (:1080) → GAS → Exit Node → Internet
//
// The HTTP proxy is a thin adapter layer. All encryption, chunking, and
// relay logic stays in the SOCKS5 engine. The proxy just speaks HTTP
// on the frontend and SOCKS5 on the backend.
//
// Supported methods:
//   - CONNECT:        HTTPS tunneling (TLS passthrough, zero-knowledge)
//   - GET/POST/etc:   Plain HTTP request forwarding
//
// Thread-safe, zero external dependencies (uses golang.org/x/net/proxy).
// ──────────────────────────────────────────────────────────────────────────────

// HTTPProxyServer provides an HTTP/HTTPS proxy that dials through SOCKS5.
type HTTPProxyServer struct {
	addr      string
	socksAddr string
	logger    *dataengine.Logger
	server    *http.Server
	dialer    proxy.Dialer

	// Metrics
	activeConns atomic.Int64
	totalConns  atomic.Int64

	// Shared transport for plain HTTP forwarding (connection pooling)
	transport *http.Transport
}

// NewHTTPProxyServer creates an HTTP proxy that forwards through the SOCKS5 server.
func NewHTTPProxyServer(addr, socksAddr string, logger *dataengine.Logger) *HTTPProxyServer {
	return &HTTPProxyServer{
		addr:      addr,
		socksAddr: socksAddr,
		logger:    logger,
	}
}

// ListenAndServe starts the HTTP proxy server.
// It binds to the port, creates a SOCKS5 dialer, and begins accepting connections.
func (h *HTTPProxyServer) ListenAndServe() error {
	// Bind to the port directly to prevent port occupation race conditions
	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		h.logger.Errorf("http-proxy", "Port %s is occupied: %v", h.addr, err)
		return fmt.Errorf("HTTP proxy port %s unavailable: %w", h.addr, err)
	}

	// Create SOCKS5 dialer that routes through our tunnel engine
	socks5Dialer, err := proxy.SOCKS5("tcp", h.socksAddr, nil, proxy.Direct)
	if err != nil {
		ln.Close()
		return fmt.Errorf("creating SOCKS5 dialer for %s: %w", h.socksAddr, err)
	}
	h.dialer = socks5Dialer

	// Shared transport for plain HTTP forwarding with connection pooling
	h.transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return h.dialer.Dial(network, addr)
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 55 * time.Second,
		DisableCompression:    false,
	}

	h.server = &http.Server{
		Addr:        h.addr,
		Handler:     h,
		ReadTimeout: 60 * time.Second,
		IdleTimeout: 120 * time.Second,
		// No WriteTimeout — CONNECT tunnels are long-lived
	}

	h.logger.Infof("http-proxy", "HTTP proxy listening on %s (via SOCKS5 %s)", h.addr, h.socksAddr)
	log.Printf("[http-proxy] listening on %s (via SOCKS5 %s)", h.addr, h.socksAddr)

	return h.server.Serve(ln)
}

// ServeHTTP dispatches incoming requests to the appropriate handler.
func (h *HTTPProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.activeConns.Add(1)
	h.totalConns.Add(1)
	defer h.activeConns.Add(-1)

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

// ── CONNECT Handler (HTTPS Tunneling) ────────────────────────────────────────

// handleConnect implements the HTTP CONNECT method for HTTPS tunneling.
//
// Flow:
//  1. Client sends "CONNECT example.com:443 HTTP/1.1"
//  2. We dial example.com:443 through SOCKS5 (which goes through GAS → exit node)
//  3. We send "200 Connection Established" back to the client
//  4. We relay bytes bidirectionally — the TLS handshake happens directly
//     between the client and the destination. We never see plaintext.
//
// This is the most common case since ~95% of web traffic is HTTPS.
func (h *HTTPProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	// Dial through SOCKS5 → GAS → exit node → destination
	destConn, err := h.dialer.Dial("tcp", target)
	if err != nil {
		h.logger.Errorf("http-proxy", "CONNECT dial failed: %s → %v", target, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Hijack the client connection to get raw TCP access
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.logger.Error("http-proxy", "ResponseWriter does not support hijacking")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		destConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		h.logger.Errorf("http-proxy", "Hijack failed: %v", err)
		destConn.Close()
		return
	}

	// Tell the client the tunnel is established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		destConn.Close()
		return
	}

	// Bidirectional relay — just copy bytes in both directions.
	// When either side closes, the other side closes too.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(destConn, clientConn)
		// Client stopped sending — signal to destination
		if tc, ok := destConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, destConn)
		// Destination stopped sending — signal to client
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	clientConn.Close()
	destConn.Close()
}

// ── Plain HTTP Handler ───────────────────────────────────────────────────────

// handleHTTP forwards plain HTTP requests (non-CONNECT) through SOCKS5.
// This handles the minority of traffic that still uses unencrypted HTTP.
func (h *HTTPProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Proxy requests must have an absolute URL
	if !r.URL.IsAbs() {
		http.Error(w, "Proxy requires absolute URL", http.StatusBadRequest)
		return
	}

	// Clone the request for forwarding
	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // Required for http.Transport

	// Remove hop-by-hop headers (RFC 2616 §13.5.1)
	removeHopByHopHeaders(outReq.Header)

	// Forward through SOCKS5 via the shared transport
	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		h.logger.Errorf("http-proxy", "HTTP forward failed: %s → %v", r.URL.Host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Remove hop-by-hop headers from the response too
	removeHopByHopHeaders(resp.Header)

	// Copy response headers to the client
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ── Metrics ──────────────────────────────────────────────────────────────────

// ActiveConns returns the number of currently active connections.
func (h *HTTPProxyServer) ActiveConns() int64 {
	return h.activeConns.Load()
}

// TotalConns returns the total number of connections served.
func (h *HTTPProxyServer) TotalConns() int64 {
	return h.totalConns.Load()
}

// Addr returns the listen address.
func (h *HTTPProxyServer) Addr() string {
	return h.addr
}

// ── Shutdown ─────────────────────────────────────────────────────────────────

// Close gracefully shuts down the HTTP proxy server.
func (h *HTTPProxyServer) Close() error {
	if h.transport != nil {
		h.transport.CloseIdleConnections()
	}
	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return h.server.Shutdown(ctx)
	}
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// removeHopByHopHeaders strips HTTP headers that are meaningful only for a
// single transport-level connection and must not be forwarded by proxies.
func removeHopByHopHeaders(h http.Header) {
	hopByHop := []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, header := range hopByHop {
		h.Del(header)
	}
}
