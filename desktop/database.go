package main

import (
	"log"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GASNodeModel represents a Google Apps Script relay node in the local SQLite database.
type GASNodeModel struct {
	ID                string         `gorm:"primaryKey;type:varchar(36)" json:"id"`
	URL               string         `gorm:"uniqueIndex;not null" json:"url"`
	Status            string         `gorm:"default:'Active'" json:"status"` // Active, Paused, Banned, Quota_Exceeded
	TotalRequestsSent int64          `gorm:"default:0" json:"total_requests_sent"`
	FailedRequests    int64          `gorm:"default:0" json:"failed_requests"`
	AverageLatencyMs  int64          `gorm:"default:500" json:"average_latency_ms"`
	LastCheckedAt     time.Time      `json:"last_checked_at"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate hooks into GORM's lifecycle to automatically generate UUIDs.
func (m *GASNodeModel) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = uuid.New().String()
	}
	return nil
}

// SettingsModel stores application preferences in SQLite.
type SettingsModel struct {
	ID                 uint   `gorm:"primaryKey" json:"id"`
	SocksAddr          string `gorm:"default:':4046'" json:"socks_addr"`
	PSK                string `gorm:"default:''" json:"psk"`
	GoogleClientID     string `gorm:"default:''" json:"google_client_id"`
	GoogleClientSecret string `gorm:"default:''" json:"google_client_secret"`
	GoogleRefreshToken string `gorm:"default:''" json:"google_refresh_token"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// SetupDatabase initializes the SQLite database and performs migrations.
func SetupDatabase() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("clever_relay.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Migrate the schema
	err = db.AutoMigrate(&GASNodeModel{}, &SettingsModel{})
	if err != nil {
		return nil, err
	}

	// Seed default settings if empty
	var count int64
	db.Model(&SettingsModel{}).Count(&count)
	if count == 0 {
		defaultSettings := SettingsModel{
			ID:        1,
			SocksAddr: ":4046",
			PSK:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // Default dummy PSK
		}
		db.Create(&defaultSettings)
	}

	log.Println("[database] SQLite database clever_relay.db loaded and migrated successfully.")
	return db, nil
}

