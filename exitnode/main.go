// Package main implements the Clever Relay exit node – a lightweight HTTP
// server that runs inside a Docker container on Clever Cloud (port 8080).
//
// It receives encrypted tunnel packets from Google Apps Script, manages
// persistent TCP/UDP sessions to destination servers, and implements the
// Time-Aware Preemption pattern for reliable large downloads.
//
// Routes:
//
//	POST /relay              – Tunnel data endpoint (encrypted packets from GAS)
//	GET  /admin/             – Monitoring dashboard SPA
//	GET  /admin/api/login    – JWT authentication
//	GET  /admin/api/metrics  – System metrics JSON
//	GET  /admin/api/sessions – Active sessions JSON
//	GET  /admin/api/logs     – Recent logs JSON
//	GET  /admin/ws           – WebSocket for real-time metrics + logs
//	GET  /health             – Health check for Clever Cloud
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // Phase 5: import pprof handlers
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// Build-time variables injected via ldflags (see Makefile).
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	// ── Configuration ────────────────────────────────────────────────────
	port := getEnv("PORT", "8080")
	pskHex := getEnv("RELAY_PSK", "")
	relayPath := getEnv("RELAY_PATH", "/relay")
	adminPassword := getEnv("ADMIN_PASSWORD", "")

	if pskHex == "" {
		log.Fatal("RELAY_PSK environment variable is required (64 hex chars = 32 bytes)")
	}

	psk, err := hex.DecodeString(pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatal("RELAY_PSK must be exactly 64 hex characters (32 bytes)")
	}

	// ── Initialize components ────────────────────────────────────────────
	tunnelLogger := NewTunnelLogger()
	sessionStore := NewSessionStore()
	relayHandler, err := NewRelayHandler(psk, sessionStore)
	if err != nil {
		log.Fatalf("Failed to create relay handler: %v", err)
	}

	// Inject logger into relay handler
	relayHandler.logger = tunnelLogger

	// Start the session reaper (garbage collects idle sessions)
	go sessionStore.StartReaper(context.Background(), 30*time.Second)

	tunnelLogger.Info("server", "Clever Relay exit node starting...")

	// ── HTTP Routing ─────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Main tunnel endpoint
	mux.HandleFunc(relayPath, relayHandler.HandleRelay)

	// Health check (Clever Cloud requires this)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		fmt.Fprintf(w, `{"status":"ok","sessions":%d,"uptime":"%s","goroutines":%d}`,
			sessionStore.Count(),
			time.Since(startTime).Round(time.Second),
			0)
	})

	// Admin dashboard (Phase 6) + pprof (Phase 5)
	if adminPassword != "" {
		adminHandler := NewAdminHandler(sessionStore, adminPassword, tunnelLogger)
		adminHandler.RegisterRoutes(mux)
		tunnelLogger.Info("server", "Admin dashboard enabled at /admin/")

		// Phase 5: pprof profiling (protected by admin auth)
		mux.HandleFunc("/debug/pprof/", http.DefaultServeMux.ServeHTTP)
		tunnelLogger.Info("server", "pprof profiling enabled at /debug/pprof/")
	} else {
		log.Printf("WARNING: ADMIN_PASSWORD not set – admin dashboard and pprof disabled")
	}

	// ── Server Setup ─────────────────────────────────────────────────────
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// ── Graceful Shutdown ────────────────────────────────────────────────
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		// Phase 5: Tune GC for high-throughput streaming
		runtime.GOMAXPROCS(runtime.NumCPU())

		log.Printf("╔══════════════════════════════════════════════════╗")
		log.Printf("║     Clever Relay – Exit Node (Phase 5+6)        ║")
		log.Printf("╠══════════════════════════════════════════════════╣")
		log.Printf("║ Port     : %-37s ║", port)
		log.Printf("║ Relay    : %-37s ║", relayPath)
		log.Printf("║ Admin    : %-37s ║", "/admin/")
		log.Printf("║ pprof    : %-37s ║", "/debug/pprof/")
		log.Printf("║ CPUs     : %-37d ║", runtime.NumCPU())
		log.Printf("╚══════════════════════════════════════════════════╝")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-done
	tunnelLogger.Info("server", "Shutdown signal received")
	log.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close all active sessions
	sessionStore.CloseAll()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Exit node stopped")
}

var startTime = time.Now()

// getEnv reads an environment variable with a fallback default.
func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
