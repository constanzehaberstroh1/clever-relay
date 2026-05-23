package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/salman/clever-relay/dataengine"
	"desktop/localengine"
	"gorm.io/gorm"
)

// App defines the Wails desktop backend service.
type App struct {
	ctx context.Context
	db  *gorm.DB

	// Proxy state
	mu           sync.Mutex
	proxyRunning bool
	socksAddr    string
	socksServer  *localengine.SOCKS5Server
	gasPool      *localengine.GASPool
	chunker      *localengine.Chunker
	transport    *localengine.H2Transport
	logger       *dataengine.Logger
}

// NewApp creates a new App struct.
func NewApp(db *gorm.DB) *App {
	return &App{
		db: db,
	}
}

// startup is called when the Wails app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	log.Println("[app] Wails application initialized.")
}

// ──────────────────────────────────────────────────────────────────────────────
// Settings Management
// ──────────────────────────────────────────────────────────────────────────────

// GetSettings retrieves the current settings.
func (a *App) GetSettings() SettingsModel {
	var settings SettingsModel
	a.db.First(&settings, 1)
	return settings
}

// SaveSettings updates the settings table.
func (a *App) SaveSettings(socksAddr, psk, clientID, clientSecret, refreshToken string) error {
	// Validate PSK
	psk = strings.TrimSpace(psk)
	if psk != "" {
		pskBytes, err := hex.DecodeString(psk)
		if err != nil || len(pskBytes) != 32 {
			return fmt.Errorf("PSK must be exactly 64 hex characters (32 bytes)")
		}
	}

	var settings SettingsModel
	a.db.First(&settings, 1)
	settings.SocksAddr = socksAddr
	settings.PSK = psk
	settings.GoogleClientID = clientID
	settings.GoogleClientSecret = clientSecret
	settings.GoogleRefreshToken = refreshToken
	settings.UpdatedAt = time.Now()

	return a.db.Save(&settings).Error
}

// ──────────────────────────────────────────────────────────────────────────────
// GAS Node CRUD
// ──────────────────────────────────────────────────────────────────────────────

// GetNodes returns all saved GAS nodes from the local SQLite database.
func (a *App) GetNodes() []GASNodeModel {
	var nodes []GASNodeModel
	a.db.Order("created_at desc").Find(&nodes)
	return nodes
}

// AddNode adds a new Google Apps Script relay URL to the database.
func (a *App) AddNode(gasURL string) (GASNodeModel, error) {
	gasURL = strings.TrimSpace(gasURL)

	// Validate URL using regex first
	if !gasURLRegex.MatchString(gasURL) {
		return GASNodeModel{}, fmt.Errorf("invalid GAS URL format")
	}

	node := GASNodeModel{
		URL:           gasURL,
		Status:        "Active",
		LastCheckedAt: time.Now(),
	}

	err := a.db.Create(&node).Error
	if err != nil {
		return GASNodeModel{}, fmt.Errorf("node already exists or database error: %w", err)
	}

	// Hot-reload if the proxy is running
	a.syncPoolNodes()

	return node, nil
}

// DeleteNode removes a node by ID.
func (a *App) DeleteNode(id string) error {
	err := a.db.Delete(&GASNodeModel{}, "id = ?", id).Error
	if err != nil {
		return err
	}

	// Hot-reload if the proxy is running
	a.syncPoolNodes()
	return nil
}

// ToggleNodeStatus pauses or activates a node.
func (a *App) ToggleNodeStatus(id string, status string) error {
	var node GASNodeModel
	if err := a.db.First(&node, "id = ?", id).Error; err != nil {
		return err
	}

	node.Status = status
	node.UpdatedAt = time.Now()
	err := a.db.Save(&node).Error
	if err != nil {
		return err
	}

	// Hot-reload if the proxy is running
	a.syncPoolNodes()
	return nil
}

// TestNode validates a single GAS node and updates its DB record.
func (a *App) TestNode(id string) ValidationResult {
	var node GASNodeModel
	if err := a.db.First(&node, "id = ?", id).Error; err != nil {
		return ValidationResult{IsValid: false, Error: "Node not found"}
	}

	settings := a.GetSettings()
	psk, _ := hex.DecodeString(settings.PSK)

	res := ValidateGASNode(node.URL, psk)

	// Update DB stats
	node.LastCheckedAt = time.Now()
	if res.IsValid {
		node.Status = "Active"
		node.AverageLatencyMs = res.Latency.Milliseconds()
	} else {
		node.Status = "Paused"
		node.FailedRequests++
	}
	a.db.Save(&node)

	// Hot-reload if running
	a.syncPoolNodes()

	return res
}

// ──────────────────────────────────────────────────────────────────────────────
// Proxy Controller (SOCKS5 Start/Stop/Status)
// ──────────────────────────────────────────────────────────────────────────────

// StartProxy starts the local SOCKS5 proxy engine.
func (a *App) StartProxy() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.proxyRunning {
		return fmt.Errorf("proxy is already running")
	}

	settings := a.GetSettings()
	if settings.PSK == "" {
		return fmt.Errorf("PSK is not configured. Please save a valid PSK first.")
	}

	psk, err := hex.DecodeString(settings.PSK)
	if err != nil || len(psk) != 32 {
		return fmt.Errorf("invalid PSK configuration")
	}

	// Load active GAS nodes
	var activeNodes []GASNodeModel
	a.db.Where("status = ?", "Active").Find(&activeNodes)
	if len(activeNodes) == 0 {
		return fmt.Errorf("no active GAS nodes available in the pool. Add and enable at least one GAS URL.")
	}

	urls := make([]string, len(activeNodes))
	for i, node := range activeNodes {
		urls[i] = node.URL
	}

	// Initialize protocol
	proto, err := dataengine.NewProtocol(psk)
	if err != nil {
		return fmt.Errorf("failed to init encryption protocol: %w", err)
	}

	// Initialize logger for desktop proxy engine
	a.logger = dataengine.NewLogger(dataengine.DefaultQueueSize, dataengine.DefaultRingSize)
	a.logger.AddSink(dataengine.NewConsoleSink(true))

	// File output with daily rotation + automatic 7-day retention in ./logs
	if fileSink, err := dataengine.NewFileSink("./logs", "desktop_client"); err == nil {
		a.logger.AddSink(fileSink)
	} else {
		log.Printf("[WARN] Could not create log directory/file: %v", err)
	}

	dataengine.RedirectStandardLog(a.logger)

	// Start local engine components
	a.transport = localengine.NewH2Transport()
	a.gasPool = localengine.NewGASPool(urls, a.transport)
	a.chunker = localengine.NewChunker(proto, a.gasPool)
	a.socksServer = localengine.NewSOCKS5Server(settings.SocksAddr, proto, a.chunker, a.gasPool)
	a.socksAddr = settings.SocksAddr

	go func() {
		if err := a.socksServer.ListenAndServe(); err != nil {
			log.Printf("[proxy] SOCKS5 server stopped: %v", err)
		}
	}()

	a.proxyRunning = true
	log.Printf("[proxy] SOCKS5 proxy started successfully on %s", settings.SocksAddr)
	return nil
}

// StopProxy halts the local proxy engine cleanly.
func (a *App) StopProxy() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.proxyRunning {
		return nil
	}

	if a.socksServer != nil {
		a.socksServer.Close()
	}
	if a.chunker != nil {
		a.chunker.Close()
	}
	if a.gasPool != nil {
		a.gasPool.Close()
	}

	a.socksServer = nil
	a.chunker = nil
	a.gasPool = nil
	a.transport = nil
	a.proxyRunning = false

	if a.logger != nil {
		a.logger.Close()
		a.logger = nil
	}
	// Restore standard library logger to default stderr
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags)

	log.Println("[proxy] SOCKS5 proxy stopped successfully.")
	return nil
}

// GetProxyStatus returns current runtime statistics.
func (a *App) GetProxyStatus() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()

	status := "Stopped"
	if a.proxyRunning {
		status = "Running"
	}

	var activeNodes []GASNodeModel
	a.db.Where("status = ?", "Active").Find(&activeNodes)

	settings := a.GetSettings()

	// Compute database-inferred Google Cloud metrics
	var allNodes []GASNodeModel
	a.db.Find(&allNodes)
	inferredGCloud := InferMetricsFromDB(allNodes)

	return map[string]interface{}{
		"status":          status,
		"socks_addr":      settings.SocksAddr,
		"psk_configured":  settings.PSK != "",
		"active_node_count": len(activeNodes),
		"gcloud_metrics": inferredGCloud,
	}
}

// syncPoolNodes hot-reloads URLs inside the GAS pool if the proxy is running.
func (a *App) syncPoolNodes() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.proxyRunning || a.gasPool == nil {
		return
	}

	var activeNodes []GASNodeModel
	a.db.Where("status = ?", "Active").Find(&activeNodes)

	urls := make([]string, len(activeNodes))
	for i, node := range activeNodes {
		urls[i] = node.URL
	}

	a.gasPool.SetNodes(urls)
	log.Printf("[proxy] GAS Pool hot-reloaded with %d URLs", len(urls))
}
