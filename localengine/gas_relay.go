package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// GAS Relay – Raw TCP/TLS/HTTP Domain Fronter (Phase 1 & 2)
//
// This module bypasses Go's http.Client entirely for GAS traffic. Instead of
// relying on the standard library (which ties together destination IP, SNI,
// and Host header), we manually:
//
//   1. Open a raw TCP socket to a known-good Google App Engine IP
//   2. Perform a TLS handshake with SNI = whitelisted domain (e.g., www.google.com)
//   3. Craft HTTP/1.1 requests as raw bytes with Host: script.google.com
//   4. Handle 302 redirects on the SAME socket (never DNS-lookup the redirect URL)
//
// This approach is immune to:
//   - Go's POST→GET demotion on 302 redirects
//   - DNS poisoning of script.googleusercontent.com
//   - CDN routing to the wrong server (YouTube edge → 405)
//
// The connection can be reused via the ConnPool for subsequent requests.
// ──────────────────────────────────────────────────────────────────────────────

// GASRelay manages raw TCP/TLS connections to Google for GAS traffic.
type GASRelay struct {
	pool      *ConnPool
	scanner   *IPScanner
	mu        sync.Mutex
}

// NewGASRelay creates a GAS relay with a connection pool.
func NewGASRelay(scanner *IPScanner) *GASRelay {
	return &GASRelay{
		pool:    NewConnPool(10, 120*time.Second),
		scanner: scanner,
	}
}

// RawHTTPResponse holds a manually parsed HTTP response.
type RawHTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// Send sends an encrypted payload to the GAS endpoint using raw TCP/TLS/HTTP.
// It handles 302 redirects by re-crafting requests on the same socket.
//
// gasURL: the full GAS deployment URL (https://script.google.com/macros/s/.../exec)
// data:   Base64-encoded encrypted payload
func (r *GASRelay) Send(gasURL string, data []byte, isBatch bool) ([]byte, error) {
	parsed, err := url.Parse(gasURL)
	if err != nil {
		return nil, fmt.Errorf("invalid GAS URL: %w", err)
	}

	path := parsed.Path
	if isBatch {
		path += "?mode=batch"
	}

	// Acquire a TLS connection (from pool or fresh)
	conn, err := r.acquireConn()
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}

	// Send the initial request to script.google.com
	resp, err := r.relayHTTP1(conn, "script.google.com", path, data, 0)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Return the connection to the pool for reuse
	r.pool.Put(conn)

	return resp.Body, nil
}

// acquireConn gets a TLS connection from the pool or creates a new one.
func (r *GASRelay) acquireConn() (*tls.Conn, error) {
	// Try to get from pool first
	if conn := r.pool.Get(); conn != nil {
		return conn, nil
	}

	// Create a fresh connection
	return r.dialFresh()
}

// dialFresh creates a new raw TCP → TLS connection to a Google App Engine IP.
func (r *GASRelay) dialFresh() (*tls.Conn, error) {
	// Step 1.1: Get a known-good IP from the scanner
	targetIP := r.selectIP()

	// Step 1.1: Raw TCP connection with keep-alive
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tcpConn, err := dialer.Dial("tcp", net.JoinHostPort(targetIP, "443"))
	if err != nil {
		return nil, fmt.Errorf("TCP dial to %s: %w", targetIP, err)
	}

	// Set TCP_NODELAY for reduced latency
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	// Step 1.2: TLS handshake with SNI set to an allowed domain
	tlsConn := tls.Client(tcpConn, &tls.Config{
		ServerName: "www.google.com", // SNI: whitelisted domain visible to DPI
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}, // Use HTTP/1.1 for raw control
	})

	// Set a deadline for the handshake
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", targetIP, err)
	}
	// Clear the deadline after handshake
	tlsConn.SetDeadline(time.Time{})

	log.Printf("[gas-relay] new TLS connection to %s (SNI: www.google.com)", targetIP)
	return tlsConn, nil
}

// selectIP picks the best available IP from the scanner.
// Falls back to a hardcoded App Engine IP if the scanner has no results.
func (r *GASRelay) selectIP() string {
	bestIPs := r.scanner.BestIPs(3)
	if len(bestIPs) > 0 {
		// Use the best available IP
		return bestIPs[0]
	}
	// Fallback: use the same hardcoded GAS-capable IPs as transport.go
	return gasFallbackIP()
}

// relayHTTP1 sends a raw HTTP/1.1 POST request and reads the response.
// If the response is a 3xx redirect, it recursively follows it on the SAME socket.
//
// This is the KEY innovation: by never closing the socket and never doing DNS
// for the redirect target, we guarantee the request reaches the same App Engine
// server that authorized the initial connection.
func (r *GASRelay) relayHTTP1(conn *tls.Conn, host, path string, body []byte, depth int) (*RawHTTPResponse, error) {
	if depth > 10 {
		return nil, fmt.Errorf("too many redirects (depth=%d)", depth)
	}

	// Step 1.3: Manually craft the HTTP/1.1 request as raw bytes
	header := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		path, host, len(body),
	)

	// Set write deadline
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	// Write the header
	if _, err := conn.Write([]byte(header)); err != nil {
		return nil, fmt.Errorf("writing HTTP header: %w", err)
	}

	// Write the body
	if len(body) > 0 {
		if _, err := conn.Write(body); err != nil {
			return nil, fmt.Errorf("writing HTTP body: %w", err)
		}
	}

	// Step 2.1: Read the response manually
	conn.SetReadDeadline(time.Now().Add(55 * time.Second))
	resp, err := r.readHTTPResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Step 2.2: Intercept 3xx redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Headers["location"]
		if location == "" {
			return nil, fmt.Errorf("redirect %d but no Location header", resp.StatusCode)
		}

		// Step 2.3: Extract the new path and host, resend on SAME socket
		newURL, err := url.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("parsing redirect Location: %w", err)
		}

		newHost := newURL.Host
		if newHost == "" {
			newHost = host // relative redirect
		}

		newPath := newURL.RequestURI()
		log.Printf("[gas-relay] following redirect %d → %s%s (depth=%d)",
			resp.StatusCode, newHost, newPath, depth+1)

		// Recursive call on the SAME TLS connection — this is the key!
		// The socket stays connected to the same Google server.
		return r.relayHTTP1(conn, newHost, newPath, body, depth+1)
	}

	// Clear deadline
	conn.SetDeadline(time.Time{})

	return resp, nil
}

// readHTTPResponse manually parses an HTTP response from a buffered reader.
// This gives us full control over response parsing without http.Client's
// automatic behaviors (redirect following, body interpretation, etc.).
func (r *GASRelay) readHTTPResponse(conn net.Conn) (*RawHTTPResponse, error) {
	reader := bufio.NewReaderSize(conn, 4096)
	resp := &RawHTTPResponse{
		Headers: make(map[string]string),
	}

	// Read the status line (e.g., "HTTP/1.1 200 OK\r\n")
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading status line: %w", err)
	}
	statusLine = strings.TrimSpace(statusLine)

	// Parse status code from "HTTP/1.1 200 OK"
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed status line: %q", statusLine)
	}
	resp.StatusCode, err = strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code in %q: %w", statusLine, err)
	}

	// Read headers until empty line (\r\n\r\n)
	contentLength := -1
	isChunked := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading header: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break // End of headers
		}

		colonIdx := strings.IndexByte(line, ':')
		if colonIdx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])
		resp.Headers[key] = value

		if key == "content-length" {
			contentLength, _ = strconv.Atoi(value)
		}
		if key == "transfer-encoding" && strings.Contains(strings.ToLower(value), "chunked") {
			isChunked = true
		}
	}

	// Read the body based on Content-Length or chunked encoding
	if isChunked {
		resp.Body, err = readChunkedBody(reader)
		if err != nil {
			return nil, fmt.Errorf("reading chunked body: %w", err)
		}
	} else if contentLength > 0 {
		resp.Body = make([]byte, contentLength)
		if _, err := io.ReadFull(reader, resp.Body); err != nil {
			return nil, fmt.Errorf("reading body (len=%d): %w", contentLength, err)
		}
	} else if contentLength == 0 {
		resp.Body = nil
	} else {
		// No content-length and not chunked — read until connection close or timeout
		// For keep-alive connections, we set a short timeout to detect EOF
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		resp.Body, _ = io.ReadAll(reader)
		conn.SetReadDeadline(time.Time{})
	}

	return resp, nil
}

// readChunkedBody reads an HTTP chunked transfer-encoded body.
func readChunkedBody(reader *bufio.Reader) ([]byte, error) {
	var result []byte
	for {
		// Read chunk size line
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			return result, err
		}
		sizeLine = strings.TrimSpace(sizeLine)
		if sizeLine == "" {
			continue
		}

		size, err := strconv.ParseInt(sizeLine, 16, 64)
		if err != nil {
			return result, fmt.Errorf("invalid chunk size %q: %w", sizeLine, err)
		}

		if size == 0 {
			// Read trailing CRLF after last chunk
			reader.ReadString('\n')
			break
		}

		chunk := make([]byte, size)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return result, fmt.Errorf("reading chunk data: %w", err)
		}
		result = append(result, chunk...)

		// Read trailing CRLF after chunk data
		reader.ReadString('\n')
	}
	return result, nil
}

// Close shuts down the relay and its connection pool.
func (r *GASRelay) Close() {
	r.pool.Close()
}
