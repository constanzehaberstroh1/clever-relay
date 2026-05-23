package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/salman/clever-relay/dataengine"
	"golang.org/x/net/websocket"
)

// ──────────────────────────────────────────────────────────────────────────────
// Client Admin Panel – Phase 8
//
// An embedded web-based admin panel served on :9090 that allows monitoring
// and managing the local client from any browser on the network.
//
// Architecture: REST API + WebSocket Multiplexing
//
// Routes:
//   GET  /                     → Embedded SPA (Vite React build)
//   GET  /api/status           → Engine status (SOCKS5, connections, uptime)
//   GET  /api/nodes            → GAS node list with health status
//   POST /api/nodes/add        → Add a GAS node URL
//   POST /api/nodes/remove     → Remove a GAS node by URL
//   POST /api/nodes/toggle     → Enable/disable a GAS node
//   GET  /api/config           → Current engine configuration
//   POST /api/config           → Update engine configuration
//   GET  /api/stats            → Logger statistics (dropped/total)
//   GET  /ws/logs              → WebSocket: real-time log streaming
// ──────────────────────────────────────────────────────────────────────────────

//go:embed panel/dist
var clientPanelFS embed.FS

// PanelServer serves the admin panel and API.
type PanelServer struct {
	addr      string
	pool      *GASPool
	socks     *SOCKS5Server
	httpProxy *HTTPProxyServer
	logger    *dataengine.Logger
	startTime time.Time

	// WebSocket clients for live log streaming
	wsMu    sync.Mutex
	wsConns map[*websocket.Conn]bool

	// Tunnel config (mutable at runtime)
	configMu sync.RWMutex
	config   PanelConfig

	// Session counter
	activeConns atomic.Int64
}

// PanelConfig holds runtime-configurable engine parameters.
type PanelConfig struct {
	ChunkSize    int           `json:"chunk_size"`
	FlushMs      int           `json:"flush_ms"`
	MaxRetries   int           `json:"max_retries"`
	Timeout      int           `json:"timeout_seconds"`
	ParallelPull int           `json:"parallel_pulls"`
	SocksAddr    string        `json:"socks_addr"`
}

// NodeInfo represents a GAS node's status for the API.
type NodeInfo struct {
	URL        string  `json:"url"`
	State      string  `json:"state"`
	AvgLatency float64 `json:"avg_latency_ms"`
	Successes  int64   `json:"successes"`
	Failures   int32   `json:"failures"`
	CooldownAt string  `json:"cooldown_at,omitempty"`
	Enabled    bool    `json:"enabled"`
}

// NewPanelServer creates the admin panel server.
func NewPanelServer(addr string, pool *GASPool, socks *SOCKS5Server, logger *dataengine.Logger) *PanelServer {
	return &PanelServer{
		addr:      addr,
		pool:      pool,
		socks:     socks,
		logger:    logger,
		startTime: time.Now(),
		wsConns:   make(map[*websocket.Conn]bool),
		config: PanelConfig{
			ChunkSize:    FlushThreshold,
			FlushMs:      int(FlushInterval / time.Millisecond),
			MaxRetries:   3,
			Timeout:      55,
			ParallelPull: 3,
			SocksAddr:    ":4046",
		},
	}
}

// ListenAndServe starts the panel HTTP server.
func (p *PanelServer) ListenAndServe() error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/status", p.cors(p.handleStatus))
	mux.HandleFunc("/api/nodes", p.cors(p.handleNodes))
	mux.HandleFunc("/api/nodes/add", p.cors(p.handleAddNode))
	mux.HandleFunc("/api/nodes/remove", p.cors(p.handleRemoveNode))
	mux.HandleFunc("/api/nodes/toggle", p.cors(p.handleToggleNode))
	mux.HandleFunc("/api/config", p.cors(p.handleConfig))
	mux.HandleFunc("/api/stats", p.cors(p.handleStats))
	mux.HandleFunc("/api/logs/recent", p.cors(p.handleRecentLogs))

	// WebSocket for live logs
	mux.Handle("/ws/logs", websocket.Handler(p.handleWSLogs))

	// Serve embedded SPA
	p.registerSPA(mux)

	p.logger.Infof("panel", "Admin panel listening on %s", p.addr)
	log.Printf("[panel] Admin panel listening on %s", p.addr)

	// Start WebSocket broadcast goroutine
	go p.broadcastLogs()

	return http.ListenAndServe(p.addr, mux)
}

// ── CORS Middleware ──────────────────────────────────────────────────────────

func (p *PanelServer) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// ── API Handlers ─────────────────────────────────────────────────────────────

func (p *PanelServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	uptime := time.Since(p.startTime)

	// Count active SOCKS5 sessions
	var sessionCount int
	p.socks.sessions.Range(func(_, _ interface{}) bool {
		sessionCount++
		return true
	})

	status := map[string]interface{}{
		"status":          "running",
		"version":         Version,
		"build_time":      BuildTime,
		"uptime_seconds":  int(uptime.Seconds()),
		"uptime_human":    formatDuration(uptime),
		"socks5_addr":     p.config.SocksAddr,
		"socks5_active":   true,
		"active_sessions": sessionCount,
		"gas_nodes":       len(p.pool.nodes),
		"goroutines":      runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"alloc_mb":      float64(m.Alloc) / 1024 / 1024,
			"sys_mb":        float64(m.Sys) / 1024 / 1024,
			"gc_cycles":     m.NumGC,
			"heap_objects":  m.HeapObjects,
		},
		"logger": map[string]interface{}{
			"total":   p.logger.Total(),
			"dropped": p.logger.Dropped(),
			"buffered": p.logger.Count(),
		},
	}

	// Add HTTP proxy info if available
	if p.httpProxy != nil {
		status["http_proxy"] = map[string]interface{}{
			"active":       true,
			"addr":         p.httpProxy.Addr(),
			"active_conns": p.httpProxy.ActiveConns(),
			"total_conns":  p.httpProxy.TotalConns(),
		}
	} else {
		status["http_proxy"] = map[string]interface{}{
			"active": false,
		}
	}

	writeJSON(w, status)
}

func (p *PanelServer) handleNodes(w http.ResponseWriter, r *http.Request) {
	p.pool.mu.RLock()
	defer p.pool.mu.RUnlock()

	nodes := make([]NodeInfo, len(p.pool.nodes))
	for i, n := range p.pool.nodes {
		n.mu.RLock()
		info := NodeInfo{
			URL:        n.URL,
			AvgLatency: float64(n.AvgLatency) / float64(time.Millisecond),
			Successes:  n.Successes,
			Failures:   n.Failures,
			Enabled:    true,
		}
		switch n.State {
		case NodeHealthy:
			info.State = "healthy"
		case NodeCooldown5M:
			info.State = "cooldown_5m"
			info.CooldownAt = n.CooldownAt.Format(time.RFC3339)
		case NodeCooldown24H:
			info.State = "cooldown_24h"
			info.CooldownAt = n.CooldownAt.Format(time.RFC3339)
			info.Enabled = false
		}
		n.mu.RUnlock()
		nodes[i] = info
	}

	writeJSON(w, map[string]interface{}{
		"nodes": nodes,
		"total": len(nodes),
	})
}

func (p *PanelServer) handleAddNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, `{"error":"invalid request, need url field"}`, http.StatusBadRequest)
		return
	}

	// Validate URL format
	if !strings.HasPrefix(req.URL, "https://script.google.com/") {
		http.Error(w, `{"error":"invalid GAS URL format"}`, http.StatusBadRequest)
		return
	}

	// Check duplicates
	p.pool.mu.Lock()
	for _, n := range p.pool.nodes {
		if n.URL == req.URL {
			p.pool.mu.Unlock()
			http.Error(w, `{"error":"node already exists"}`, http.StatusConflict)
			return
		}
	}
	p.pool.nodes = append(p.pool.nodes, &GASNode{
		URL:        req.URL,
		State:      NodeHealthy,
		AvgLatency: 500 * time.Millisecond,
	})
	p.pool.mu.Unlock()

	p.logger.Infof("panel", "Added GAS node: %s", req.URL)
	writeJSON(w, map[string]string{"status": "added"})
}

func (p *PanelServer) handleRemoveNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	p.pool.mu.Lock()
	found := false
	for i, n := range p.pool.nodes {
		if n.URL == req.URL {
			p.pool.nodes = append(p.pool.nodes[:i], p.pool.nodes[i+1:]...)
			found = true
			break
		}
	}
	p.pool.mu.Unlock()

	if !found {
		http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
		return
	}

	p.logger.Infof("panel", "Removed GAS node: %s", req.URL)
	writeJSON(w, map[string]string{"status": "removed"})
}

func (p *PanelServer) handleToggleNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL   string `json:"url"`
		State string `json:"state"` // "enable" or "disable"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	p.pool.mu.RLock()
	var target *GASNode
	for _, n := range p.pool.nodes {
		if n.URL == req.URL {
			target = n
			break
		}
	}
	p.pool.mu.RUnlock()

	if target == nil {
		http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
		return
	}

	target.mu.Lock()
	if req.State == "disable" {
		target.State = NodeCooldown24H
		target.CooldownAt = time.Now().Add(100 * 365 * 24 * time.Hour) // effectively forever
	} else {
		target.State = NodeHealthy
		target.CooldownAt = time.Time{}
		target.Failures = 0
	}
	target.mu.Unlock()

	p.logger.Infof("panel", "Toggled GAS node %s → %s", req.URL, req.State)
	writeJSON(w, map[string]string{"status": "toggled"})
}

func (p *PanelServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		p.configMu.RLock()
		defer p.configMu.RUnlock()
		writeJSON(w, p.config)
		return
	}

	if r.Method == http.MethodPost {
		var newConfig PanelConfig
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, `{"error":"invalid config"}`, http.StatusBadRequest)
			return
		}

		p.configMu.Lock()
		if newConfig.ChunkSize > 0 {
			p.config.ChunkSize = newConfig.ChunkSize
		}
		if newConfig.FlushMs > 0 {
			p.config.FlushMs = newConfig.FlushMs
		}
		if newConfig.MaxRetries > 0 {
			p.config.MaxRetries = newConfig.MaxRetries
		}
		if newConfig.Timeout > 0 {
			p.config.Timeout = newConfig.Timeout
		}
		if newConfig.ParallelPull > 0 {
			p.config.ParallelPull = newConfig.ParallelPull
		}
		p.configMu.Unlock()

		p.logger.Info("panel", "Configuration updated via admin panel")
		writeJSON(w, map[string]string{"status": "updated"})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

func (p *PanelServer) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"total_logs":   p.logger.Total(),
		"dropped_logs": p.logger.Dropped(),
		"ring_count":   p.logger.Count(),
	})
}

func (p *PanelServer) handleRecentLogs(w http.ResponseWriter, r *http.Request) {
	count := 200
	entries := p.logger.Recent(count)
	writeJSON(w, entries)
}

// ── WebSocket Live Logs ──────────────────────────────────────────────────────

func (p *PanelServer) handleWSLogs(ws *websocket.Conn) {
	p.wsMu.Lock()
	p.wsConns[ws] = true
	p.wsMu.Unlock()

	p.logger.Info("panel", fmt.Sprintf("WebSocket client connected: %s", ws.Request().RemoteAddr))

	defer func() {
		p.wsMu.Lock()
		delete(p.wsConns, ws)
		p.wsMu.Unlock()
		ws.Close()
	}()

	// Keep connection alive by reading (handles ping/pong)
	buf := make([]byte, 512)
	for {
		_, err := ws.Read(buf)
		if err != nil {
			return
		}
	}
}

// broadcastLogs subscribes to the logger stream and pushes entries to all
// connected WebSocket clients.
//
// Critical optimization: we snapshot the client list under a short lock,
// then write to each client OUTSIDE the lock with a write deadline.
// This prevents a slow/sleeping browser tab from blocking log delivery
// to all other clients (head-of-line blocking).
func (p *PanelServer) broadcastLogs() {
	stream := p.logger.Stream()
	for entry := range stream {
		data, err := json.Marshal(map[string]interface{}{
			"type": "log",
			"data": entry,
		})
		if err != nil {
			continue
		}

		// 1. Snapshot the client list under a brief lock
		p.wsMu.Lock()
		conns := make([]*websocket.Conn, 0, len(p.wsConns))
		for ws := range p.wsConns {
			conns = append(conns, ws)
		}
		p.wsMu.Unlock()

		// 2. Write to each client outside the lock, with a short deadline
		//    so a sleeping browser tab cannot stall the entire broadcast.
		for _, ws := range conns {
			ws.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := ws.Write(data); err != nil {
				// Evict the failed client with a brief lock
				p.wsMu.Lock()
				ws.Close()
				delete(p.wsConns, ws)
				p.wsMu.Unlock()
			}
		}
	}
}

// ── Embedded SPA ─────────────────────────────────────────────────────────────

func (p *PanelServer) registerSPA(mux *http.ServeMux) {
	subFS, err := fs.Sub(clientPanelFS, "panel/dist")
	if err != nil {
		log.Printf("[panel] No embedded client panel found: %v", err)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html>
<html><head><title>Clever Relay Client Panel</title></head>
<body style="font-family:monospace;background:#0a0a0f;color:#c9d1d9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center">
<h1 style="color:#58a6ff">🛡️ Clever Relay Client Panel</h1>
<p>Panel not built yet. Run:</p>
<code style="background:#161b22;padding:8px 16px;border-radius:6px;display:block;margin:16px 0">cd client-panel && npm install && npm run build</code>
<p style="color:#8b949e">Then rebuild the client binary.</p>
<p style="margin-top:24px"><a href="/api/status" style="color:#58a6ff">View Status API →</a></p>
</div></body></html>`))
		})
		return
	}

	indexHTML, _ := fs.ReadFile(subFS, "index.html")
	fileServer := http.FileServer(http.FS(subFS))

	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(indexHTML)
	}

	// Root SPA handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Skip API and WS routes
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			http.NotFound(w, r)
			return
		}

		path := r.URL.Path
		if path == "/" {
			serveIndex(w, r)
			return
		}

		// Try static file
		cleanPath := strings.TrimPrefix(path, "/")
		if _, statErr := fs.Stat(subFS, cleanPath); statErr == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA fallback
		serveIndex(w, r)
	})
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(v)
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
