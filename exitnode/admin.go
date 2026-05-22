package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// ──────────────────────────────────────────────────────────────────────────────
// Embedded SPA – The built React frontend is compiled into the Go binary.
//
// When building for production, run:
//   cd frontend && bun run build
//   # The dist/ folder is then embedded below.
//
// During development, the frontend runs on its own Vite dev server and
// proxies API calls to the Go backend.
// ──────────────────────────────────────────────────────────────────────────────

//go:embed dashboard/dist
var dashboardFS embed.FS

// ──────────────────────────────────────────────────────────────────────────────
// AdminHandler – Full Phase 6 implementation
//
// Routes:
//   GET  /admin/           → Serve embedded SPA (index.html)
//   GET  /admin/assets/*   → Serve static assets (JS, CSS, images)
//   POST /admin/api/login  → Authenticate with PSK, return JWT token
//   GET  /admin/api/metrics → System + session metrics (JSON)
//   GET  /admin/api/sessions → Active sessions list
//   GET  /admin/api/logs   → Recent log entries
//   GET  /admin/ws         → WebSocket for real-time streaming
// ──────────────────────────────────────────────────────────────────────────────

// AdminHandler provides the admin dashboard and real-time WebSocket metrics.
type AdminHandler struct {
	sessions  *SessionStore
	password  string
	jwtSecret []byte
	logger    *TunnelLogger

	// WebSocket clients
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
}

// NewAdminHandler creates an admin handler with JWT-based auth.
func NewAdminHandler(ss *SessionStore, password string, logger *TunnelLogger) *AdminHandler {
	// Derive a JWT secret from the password using HMAC-SHA256
	h := hmac.New(sha256.New, []byte("clever-relay-jwt-salt"))
	h.Write([]byte(password))
	jwtSecret := h.Sum(nil)

	return &AdminHandler{
		sessions:  ss,
		password:  password,
		jwtSecret: jwtSecret,
		logger:    logger,
		clients:   make(map[*websocket.Conn]bool),
	}
}

// RegisterRoutes registers all admin routes on the given mux.
func (a *AdminHandler) RegisterRoutes(mux *http.ServeMux) {
	// API endpoints
	mux.HandleFunc("/admin/api/login", a.handleLogin)
	mux.HandleFunc("/admin/api/metrics", a.requireAuth(a.handleMetrics))
	mux.HandleFunc("/admin/api/sessions", a.requireAuth(a.handleSessions))
	mux.HandleFunc("/admin/api/logs", a.requireAuth(a.handleLogs))
	mux.HandleFunc("/admin/ws", a.handleWebSocket)

	// Serve embedded SPA for /admin and /admin/*
	a.registerSPA(mux)
}

// ──────────────────────────────────────────────────────────────────────────────
// JWT Authentication
// ──────────────────────────────────────────────────────────────────────────────

// Simple JWT: header.payload.signature (HMAC-SHA256)
// We don't use a library to keep the binary small.

type jwtPayload struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func (a *AdminHandler) generateJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payload := jwtPayload{
		Sub: "admin",
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(24 * time.Hour).Unix(),
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	sigData := header + "." + payloadB64
	mac := hmac.New(sha256.New, a.jwtSecret)
	mac.Write([]byte(sigData))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return sigData + "." + signature
}

func (a *AdminHandler) validateJWT(token string) bool {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return false
	}

	// Verify signature
	sigData := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, a.jwtSecret)
	mac.Write([]byte(sigData))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return false
	}

	// Check expiration
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}

	return time.Now().Unix() < payload.Exp
}

// extractToken gets the JWT from Authorization header or query param.
func extractToken(r *http.Request) string {
	// Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	// Query param fallback (for WebSocket)
	return r.URL.Query().Get("token")
}

// requireAuth wraps a handler with JWT authentication.
func (a *AdminHandler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS headers for frontend dev server
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		token := extractToken(r)
		if !a.validateJWT(token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// API Handlers
// ──────────────────────────────────────────────────────────────────────────────

// handleLogin authenticates with the PSK password and returns a JWT.
func (a *AdminHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Password != a.password {
		a.logger.Warn("auth", fmt.Sprintf("Failed login attempt from %s", r.RemoteAddr))
		http.Error(w, `{"error":"invalid password"}`, http.StatusUnauthorized)
		return
	}

	token := a.generateJWT()
	a.logger.Info("auth", fmt.Sprintf("Admin login from %s", r.RemoteAddr))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}

// handleMetrics returns full system and session metrics.
func (a *AdminHandler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := struct {
		System   SystemMetrics `json:"system"`
		Sessions int64         `json:"active_sessions"`
		LogCount int           `json:"log_count"`
	}{
		System:   CollectSystemMetrics(),
		Sessions: a.sessions.Count(),
		LogCount: a.logger.buffer.Count(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(metrics)
}

// handleSessions returns detailed info about all active sessions.
func (a *AdminHandler) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions := a.sessions.ListSessions()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// handleLogs returns recent log entries.
func (a *AdminHandler) handleLogs(w http.ResponseWriter, r *http.Request) {
	count := 100 // default
	if q := r.URL.Query().Get("count"); q != "" {
		if n, err := fmt.Sscanf(q, "%d", &count); n == 1 && err == nil {
			if count > MaxLogEntries {
				count = MaxLogEntries
			}
		}
	}

	entries := a.logger.Recent(count)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// ──────────────────────────────────────────────────────────────────────────────
// WebSocket – Real-Time Streaming
// ──────────────────────────────────────────────────────────────────────────────

// handleWebSocket streams real-time metrics and logs via WebSocket.
func (a *AdminHandler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if !a.validateJWT(token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	wsHandler := websocket.Handler(func(ws *websocket.Conn) {
		a.mu.Lock()
		a.clients[ws] = true
		a.mu.Unlock()

		defer func() {
			a.mu.Lock()
			delete(a.clients, ws)
			a.mu.Unlock()
			ws.Close()
		}()

		a.logger.Info("websocket", fmt.Sprintf("Client connected from %s", ws.Request().RemoteAddr))

		// Two goroutines: one for metrics, one for logs
		done := make(chan struct{})

		// Metrics ticker – send system metrics every 2 seconds
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					msg := map[string]interface{}{
						"type":    "metrics",
						"data":    CollectSystemMetrics(),
						"sessions": a.sessions.Count(),
						"session_list": a.sessions.ListSessions(),
					}
					data, _ := json.Marshal(msg)
					if _, err := ws.Write(data); err != nil {
						close(done)
						return
					}
				}
			}
		}()

		// Log streamer – forward log entries in real time
		go func() {
			stream := a.logger.Stream()
			for {
				select {
				case <-done:
					return
				case entry := <-stream:
					msg := map[string]interface{}{
						"type": "log",
						"data": entry,
					}
					data, _ := json.Marshal(msg)
					if _, err := ws.Write(data); err != nil {
						return
					}
				}
			}
		}()

		// Keep the connection open – read from client (ping/pong)
		buf := make([]byte, 1024)
		for {
			_, err := ws.Read(buf)
			if err != nil {
				close(done)
				return
			}
		}
	})

	wsHandler.ServeHTTP(w, r)
}

// BroadcastLog sends a log message to all connected WebSocket clients.
func (a *AdminHandler) BroadcastLog(level, component, message string) {
	a.logger.Log(level, component, message)
}

// ──────────────────────────────────────────────────────────────────────────────
// Embedded SPA Serving
// ──────────────────────────────────────────────────────────────────────────────

// registerSPA serves the embedded React dashboard from /admin/.
//
// There are two subtle issues that must be handled:
//
//  1. http.FileServer auto-redirects "/index.html" → "/" which creates
//     an infinite loop with SPA fallback. We handle index.html explicitly
//     by serving its content via http.ServeContent instead of FileServer.
//
//  2. Vite's build output uses absolute paths for assets (e.g. /assets/...).
//     Since the dashboard is mounted at /admin/, we also register /assets/*
//     at the root so the SPA can find its JS/CSS bundles.
func (a *AdminHandler) registerSPA(mux *http.ServeMux) {
	subFS, err := fs.Sub(dashboardFS, "dashboard/dist")
	if err != nil {
		log.Printf("[admin] No embedded dashboard found (build with 'bun run build' first): %v", err)
		mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html>
<html><head><title>Clever Relay Admin</title></head>
<body style="font-family:monospace;background:#0a0a0f;color:#c9d1d9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center">
<h1 style="color:#58a6ff">🛡️ Clever Relay Admin</h1>
<p>Dashboard not built yet. Run:</p>
<code style="background:#161b22;padding:8px 16px;border-radius:6px;display:block;margin:16px 0">cd frontend && bun run build</code>
<p style="color:#8b949e">Then rebuild the server binary.</p>
<p style="margin-top:24px"><a href="/admin/api/metrics" style="color:#58a6ff">View Raw Metrics API →</a></p>
</div></body></html>`))
		})
		return
	}

	// Read index.html once at startup for fast serving and to avoid
	// http.FileServer's automatic /index.html → / redirect.
	indexHTML, indexErr := fs.ReadFile(subFS, "index.html")
	if indexErr != nil {
		log.Printf("[admin] WARNING: index.html not found in embedded dashboard: %v", indexErr)
	}

	// serveIndex writes the cached index.html with correct headers.
	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		if indexErr != nil {
			http.Error(w, "Dashboard index.html not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(indexHTML)
	}

	fileServer := http.FileServer(http.FS(subFS))

	// Serve /admin/* — the main SPA route
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		// Strip /admin prefix
		path := strings.TrimPrefix(r.URL.Path, "/admin")
		if path == "" || path == "/" {
			serveIndex(w, r)
			return
		}

		// Try to serve the static file from the embedded FS
		cleanPath := strings.TrimPrefix(path, "/")
		if _, statErr := fs.Stat(subFS, cleanPath); statErr == nil {
			// File exists — serve it (adjust path for FileServer)
			r.URL.Path = path
			fileServer.ServeHTTP(w, r)
			return
		}

		// File not found → SPA fallback (serve index.html)
		serveIndex(w, r)
	})

	// Also serve /assets/* at the root level because Vite's build output
	// uses absolute paths like "/assets/index-xxx.js" in index.html.
	// Without this, the browser would 404 on all JS/CSS bundles.
	mux.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if _, statErr := fs.Stat(subFS, path); statErr == nil {
			r.URL.Path = "/" + path
			fileServer.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})

	// Serve /favicon.svg and /icons.svg at root too (referenced by index.html)
	for _, name := range []string{"favicon.svg", "icons.svg"} {
		staticName := name
		mux.HandleFunc("/"+staticName, func(w http.ResponseWriter, r *http.Request) {
			data, err := fs.ReadFile(subFS, staticName)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.Write(data)
		})
	}
}

// ServeDashboard is kept for backward compatibility.
func (a *AdminHandler) ServeDashboard(w http.ResponseWriter, r *http.Request) {
	a.handleMetrics(w, r)
}

// ServeWebSocket is kept for backward compatibility.
func (a *AdminHandler) ServeWebSocket(w http.ResponseWriter, r *http.Request) {
	a.handleWebSocket(w, r)
}
