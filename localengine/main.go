// Package main implements the Clever Relay local client — a SOCKS5 proxy
// that captures system/browser traffic, encrypts it with the dataengine
// protocol, and sends it through a pool of Google Apps Script relays to
// the exit node on Clever Cloud.
//
// Architecture sub-modules (all in this package):
//
//   - SOCKS5 server   (socks5.go)      – Listens on :1080, assigns SessionIDs
//   - HTTP Proxy      (http_proxy.go)   – HTTP/HTTPS proxy via SOCKS5 (:8080)
//   - Micro-Chunker   (chunker.go)      – 10ms / 256KB flush, batches packets
//   - Smart GAS Pool  (pool.go)         – Weighted latency + Circuit Breaker
//   - H2 Transport    (transport.go)    – HTTP/2 multiplexing + SNI Rotation
//   - Downlink Engine (downlink.go)     – PULL scheduler + SeqNum reassembly
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/salman/clever-relay/dataengine"
)

// Build-time variables injected via ldflags (see Makefile).
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	// ── CLI Flags ────────────────────────────────────────────────────────
	socksAddr := flag.String("listen", ":1080", "SOCKS5 listen address")
	httpAddr := flag.String("http-proxy", ":8080", "HTTP/HTTPS proxy listen address (set to empty to disable)")
	panelAddr := flag.String("panel", "127.0.0.1:9090", "Admin panel listen address")
	pskHex := flag.String("psk", "", "Pre-shared key (64 hex chars = 32 bytes)")
	gasURLs := flag.String("gas-urls", "", "Comma-separated Google Apps Script URLs")
	flag.Parse()

	// Override with env vars if flags are empty
	if *pskHex == "" {
		*pskHex = os.Getenv("RELAY_PSK")
	}
	if *gasURLs == "" {
		*gasURLs = os.Getenv("GAS_URLS")
	}
	if pa := os.Getenv("PANEL_ADDR"); pa != "" {
		*panelAddr = pa
	}
	if ha := os.Getenv("HTTP_PROXY_ADDR"); ha != "" {
		*httpAddr = ha
	}

	if *pskHex == "" {
		log.Fatal("PSK is required: use -psk flag or RELAY_PSK env var (64 hex chars)")
	}
	if *gasURLs == "" {
		log.Fatal("GAS URLs required: use -gas-urls flag or GAS_URLS env var")
	}

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatal("PSK must be exactly 64 hex characters (32 bytes)")
	}

	urls := parseURLs(*gasURLs)
	if len(urls) == 0 {
		log.Fatal("At least one GAS URL is required")
	}

	// ── Initialize Components ────────────────────────────────────────────
	proto, err := dataengine.NewProtocol(psk)
	if err != nil {
		log.Fatalf("Protocol init error: %v", err)
	}

	// Global async logger (shared across all modules)
	logger := dataengine.NewLogger(dataengine.DefaultQueueSize, dataengine.DefaultRingSize)
	logger.AddSink(dataengine.NewConsoleSink(true))

	// File output with daily rotation + automatic 7-day retention
	// Files: ./logs/client_2026-05-22.log
	if fileSink, err := dataengine.NewFileSink("./logs", "client"); err == nil {
		logger.AddSink(fileSink)
	} else {
		log.Printf("[WARN] Could not create log directory/file: %v", err)
	}

	// Phase 5: H2Transport now starts a background IP scanner automatically
	transport := NewH2Transport()
	pool := NewGASPool(urls, transport)
	chunker := NewChunker(proto, pool)

	// Start the SOCKS5 server
	socks := NewSOCKS5Server(*socksAddr, proto, chunker, pool)

	// Phase 9: HTTP/HTTPS proxy (forwards through SOCKS5)
	var httpProxy *HTTPProxyServer
	if *httpAddr != "" {
		httpProxy = NewHTTPProxyServer(*httpAddr, *socksAddr, logger)
	}

	// Phase 8: Start the client admin panel (after httpProxy so it can report status)
	panel := NewPanelServer(*panelAddr, pool, socks, logger)
	panel.httpProxy = httpProxy

	logger.Info("startup", "Clever Relay – Local Client starting...")
	logger.Infof("startup", "SOCKS5 listening on %s", *socksAddr)
	if httpProxy != nil {
		logger.Infof("startup", "HTTP proxy listening on %s", *httpAddr)
	}
	logger.Infof("startup", "Admin panel on http://%s", *panelAddr)
	logger.Infof("startup", "GAS Pool: %d scripts", len(urls))
	logger.Info("startup", "Scanner: Active (5 min interval)")
	logger.Info("startup", "Polling: Reverse (3 parallel)")

	log.Printf("╔══════════════════════════════════════════════════╗")
	log.Printf("║     Clever Relay – Local Client (Phase 9)       ║")
	log.Printf("╠══════════════════════════════════════════════════╣")
	log.Printf("║ SOCKS5   : %-37s ║", *socksAddr)
	if httpProxy != nil {
		log.Printf("║ HTTP     : %-37s ║", *httpAddr)
	}
	log.Printf("║ Panel    : %-37s ║", fmt.Sprintf("http://%s", *panelAddr))
	log.Printf("║ GAS Pool : %-37s ║", fmt.Sprintf("%d scripts", len(urls)))
	log.Printf("║ Scanner  : %-37s ║", "Active (5 min interval)")
	log.Printf("║ Padding  : %-37s ║", "16–512 bytes random")
	log.Printf("║ Polling  : %-37s ║", "Reverse (3 parallel)")
	log.Printf("╚══════════════════════════════════════════════════╝")

	go func() {
		if err := socks.ListenAndServe(); err != nil {
			log.Fatalf("SOCKS5 server error: %v", err)
		}
	}()

	go func() {
		if err := panel.ListenAndServe(); err != nil {
			log.Printf("[panel] Admin panel error: %v", err)
		}
	}()

	// Phase 9: Start HTTP proxy
	if httpProxy != nil {
		go func() {
			if err := httpProxy.ListenAndServe(); err != nil {
				logger.Errorf("http-proxy", "HTTP proxy failed: %v", err)
				log.Printf("[http-proxy] HTTP proxy error: %v", err)
			}
		}()
	}

	// ── Graceful Shutdown ────────────────────────────────────────────────
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	<-done

	logger.Info("shutdown", "Shutting down local engine...")
	log.Println("Shutting down local engine...")
	if httpProxy != nil {
		httpProxy.Close()
	}
	socks.Close()
	chunker.Close()
	pool.Close()
	transport.Close() // Phase 5: stops the IP scanner
	logger.Close()    // Drain remaining logs to sinks
	log.Println("Goodbye.")
}

// parseURLs splits a comma-separated string into trimmed, non-empty URLs.
func parseURLs(s string) []string {
	var result []string
	for _, u := range strings.Split(s, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			result = append(result, u)
		}
	}
	return result
}
