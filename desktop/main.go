package main

import (
	"context"
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Initialize database
	db, err := SetupDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Create an instance of the app structure with database
	app := NewApp(db)

	// Create application with options
	err = wails.Run(&options.App{
		Title:  "🛡️ Clever Relay Client",
		Width:  1050,
		Height: 780,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 6, G: 7, B: 11, A: 1}, // Aligned with index.css dark bg
		OnStartup:        app.startup,
		OnShutdown: func(ctx context.Context) {
			app.StopProxy()
		},
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}

