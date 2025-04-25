package storage

import (
	"fmt"

	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Database holds the database connection
type Database struct {
	DB *gorm.DB
}

// NewDatabase creates a new database instance
func NewDatabase(cfg *config.Config) (*Database, error) {
	var db *gorm.DB
	var err error

	switch cfg.Database.Type {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(cfg.Database.Path), &gorm.Config{})
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Database.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	logrus.Info("Connected to database")

	// Auto-migrate the schema
	if err := migrateSchema(db); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	return &Database{DB: db}, nil
}

// migrateSchema creates the tables in the database
func migrateSchema(db *gorm.DB) error {
	logrus.Info("Migrating database schema")

	// Create tables for all models
	err := db.AutoMigrate(
		&models.Resource{},
		&models.AttestationPolicy{},
		&models.ResourcePolicy{},
		&models.AttestationRecord{},
		&models.ResourceRequest{},
	)

	if err != nil {
		return fmt.Errorf("failed to migrate database schema: %w", err)
	}

	return nil
}
