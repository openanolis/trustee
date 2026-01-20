package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/mattn/go-sqlite3"
)

// Database holds the database connection and backup management
type Database struct {
	DB     *gorm.DB
	config *config.DatabaseConfig

	// Backup management
	backupCtx    context.Context
	backupCancel context.CancelFunc
	backupDone   chan struct{}
	backupMux    sync.Mutex
}

// NewDatabase creates a new database instance with optional memory mode and backup
func NewDatabase(cfg *config.Config) (*Database, error) {
	db := &Database{
		config:     &cfg.Database,
		backupDone: make(chan struct{}),
	}

	if err := db.initialize(); err != nil {
		return nil, err
	}

	// Start backup scheduler only for SQLite memory mode
	if cfg.Database.Type == "sqlite" && cfg.Database.UseMemory {
		db.startBackupScheduler()
	}

	return db, nil
}

// initialize sets up the database connection and schema
func (d *Database) initialize() error {
	var err error

	switch d.config.Type {
	case "sqlite":
		if err := d.initializeSQLite(); err != nil {
			return err
		}
	case "mysql":
		if err := d.initializeMySQL(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported database type: %s", d.config.Type)
	}

	logrus.Info("Connected to database")

	// Auto-migrate the schema
	if err = d.migrateSchema(); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}

	return nil
}

// initializeSQLite sets up the SQLite database connection
func (d *Database) initializeSQLite() error {
	var err error

	if d.config.UseMemory {
		// Use a shared-cache in-memory database. This is crucial for preventing "no such table" errors
		// as GORM uses a connection pool, and each connection needs to access the same database.
		d.DB, err = gorm.Open(sqlite.Open("file:trustee_gateway?mode=memory&cache=shared"), &gorm.Config{})
		if err != nil {
			return fmt.Errorf("failed to create in-memory database: %w", err)
		}
		logrus.Info("Created in-memory SQLite database with shared cache")

		// Restore from backup if it exists
		if err := d.restoreFromBackup(); err != nil {
			logrus.Warnf("Failed to restore from backup (starting fresh): %v", err)
		}
	} else {
		dir := filepath.Dir(d.config.Path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}

		d.DB, err = gorm.Open(sqlite.Open(d.config.Path), &gorm.Config{})
		if err != nil {
			return fmt.Errorf("failed to open database file: %w", err)
		}
		logrus.Infof("Using file-based SQLite database: %s", d.config.Path)
	}

	return nil
}

// initializeMySQL sets up the MySQL database connection
func (d *Database) initializeMySQL() error {
	if d.config.DSN == "" {
		return fmt.Errorf("MySQL DSN is required, please set database.dsn in config")
	}

	var err error
	d.DB, err = gorm.Open(mysql.Open(d.config.DSN), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to MySQL database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := d.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	if d.config.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(d.config.MaxOpenConns)
	}
	if d.config.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(d.config.MaxIdleConns)
	}

	if d.config.ConnMaxLifetime != "" {
		lifetime, err := time.ParseDuration(d.config.ConnMaxLifetime)
		if err != nil {
			logrus.Warnf("Invalid conn_max_lifetime '%s', using default 1h", d.config.ConnMaxLifetime)
			lifetime = time.Hour
		}
		sqlDB.SetConnMaxLifetime(lifetime)
	}

	logrus.Info("Connected to MySQL database")
	return nil
}

// migrateSchema creates the tables in the database
func (d *Database) migrateSchema() error {
	logrus.Info("Migrating database schema")

	// Create tables for all models
	err := d.DB.AutoMigrate(
		&models.AttestationRecord{},
		&models.ResourceRequest{},
		&models.AAInstanceHeartbeat{},
	)

	if err != nil {
		return fmt.Errorf("failed to migrate database schema: %w", err)
	}

	// Add unique index on instance_id for AAInstanceHeartbeat table
	// This prevents duplicate heartbeat records for the same instance
	if d.config.Type == "mysql" {
		if err := d.migrateAAInstanceHeartbeatIndexMySQL(); err != nil {
			logrus.Warnf("Failed to migrate AAInstanceHeartbeat index: %v", err)
		}
	} else {
		// SQLite - file-based SQLite has built-in file locking
		// In-memory SQLite is per-process, so no cross-process conflict
		d.migrateAAInstanceHeartbeatIndexSQLite()
	}

	return nil
}

// migrateAAInstanceHeartbeatIndexMySQL handles unique index creation for MySQL with distributed locking
func (d *Database) migrateAAInstanceHeartbeatIndexMySQL() error {
	const lockName = "trustee_gateway_migrate_lock"
	const lockTimeout = 30 // seconds

	// Try to acquire MySQL advisory lock to prevent concurrent migrations
	var lockResult int
	if err := d.DB.Raw("SELECT GET_LOCK(?, ?)", lockName, lockTimeout).Scan(&lockResult).Error; err != nil {
		return fmt.Errorf("failed to acquire migration lock: %w", err)
	}

	if lockResult != 1 {
		logrus.Info("Another instance is running migration, skipping")
		return nil
	}

	// Ensure lock is released when done
	defer func() {
		if err := d.DB.Exec("SELECT RELEASE_LOCK(?)", lockName).Error; err != nil {
			logrus.Warnf("Failed to release migration lock: %v", err)
		}
	}()

	logrus.Info("Acquired migration lock, proceeding with index migration")

	// Check if index already exists (re-check after acquiring lock)
	var exists int
	d.DB.Raw("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'aa_instance_heartbeats' AND index_name = 'idx_aa_heartbeat_instance_id'").Scan(&exists)
	if exists > 0 {
		logrus.Info("Unique index on instance_id already exists, skipping")
		return nil
	}

	// Alter column to VARCHAR(255) for index compatibility
	if err := d.DB.Exec("ALTER TABLE aa_instance_heartbeats MODIFY instance_id VARCHAR(255)").Error; err != nil {
		logrus.Warnf("Failed to alter instance_id column: %v", err)
	}

	// Clean up duplicate instance_id records before creating unique index
	// Keep only the latest record (by id) for each instance_id
	cleanupSQL := `
		DELETE t1 FROM aa_instance_heartbeats t1
		INNER JOIN aa_instance_heartbeats t2
		WHERE t1.instance_id = t2.instance_id AND t1.id < t2.id
	`
	if err := d.DB.Exec(cleanupSQL).Error; err != nil {
		logrus.Warnf("Failed to clean up duplicate instance_id records: %v", err)
	} else {
		logrus.Info("Cleaned up duplicate instance_id records in aa_instance_heartbeats")
	}

	if err := d.DB.Exec("CREATE UNIQUE INDEX idx_aa_heartbeat_instance_id ON aa_instance_heartbeats(instance_id)").Error; err != nil {
		return fmt.Errorf("failed to create unique index on instance_id: %w", err)
	}

	logrus.Info("Created unique index on aa_instance_heartbeats.instance_id")
	return nil
}

// migrateAAInstanceHeartbeatIndexSQLite handles unique index creation for SQLite
func (d *Database) migrateAAInstanceHeartbeatIndexSQLite() {
	migrator := d.DB.Migrator()
	if migrator.HasIndex(&models.AAInstanceHeartbeat{}, "idx_aa_heartbeat_instance_id") {
		return
	}

	// Clean up duplicate instance_id records before creating unique index
	// Keep only the latest record (by id) for each instance_id
	cleanupSQL := `
		DELETE FROM aa_instance_heartbeats
		WHERE id NOT IN (
			SELECT MAX(id) FROM aa_instance_heartbeats GROUP BY instance_id
		)
	`
	if err := d.DB.Exec(cleanupSQL).Error; err != nil {
		logrus.Warnf("Failed to clean up duplicate instance_id records: %v", err)
	} else {
		logrus.Info("Cleaned up duplicate instance_id records in aa_instance_heartbeats")
	}

	if err := d.DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_aa_heartbeat_instance_id ON aa_instance_heartbeats(instance_id)").Error; err != nil {
		logrus.Warnf("Failed to create unique index on instance_id: %v", err)
	}
}

// restoreFromBackup restores data from backup file to in-memory database using native backup API
func (d *Database) restoreFromBackup() error {
	if _, err := os.Stat(d.config.Path); os.IsNotExist(err) {
		logrus.Info("No backup file found, starting with empty database")
		return nil
	}

	logrus.Infof("Restoring database from backup: %s", d.config.Path)

	// Get the underlying sql.DB from GORM
	sqlDB, err := d.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Open the backup file
	backupDB, err := sql.Open("sqlite3", d.config.Path)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer backupDB.Close()

	// Use sqlite3 backup API to copy from backup file to in-memory database
	if err := d.performBackupCopy(context.Background(), backupDB, sqlDB); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	logrus.Info("Successfully restored database from backup")
	return nil
}

// performBackupCopy performs the actual backup copy using sqlite3 native API
func (d *Database) performBackupCopy(ctx context.Context, src, dst *sql.DB) error {
	// Get the underlying SQLite connections
	srcConn, err := src.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to get source connection: %w", err)
	}
	defer srcConn.Close()

	dstConn, err := dst.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to get destination connection: %w", err)
	}
	defer dstConn.Close()

	// Perform the backup using raw SQLite connections
	return srcConn.Raw(func(srcDriverConn interface{}) error {
		return dstConn.Raw(func(dstDriverConn interface{}) error {
			srcSQLiteConn, ok := srcDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("source connection is not sqlite3.SQLiteConn")
			}

			dstSQLiteConn, ok := dstDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("destination connection is not sqlite3.SQLiteConn")
			}

			// Create backup handle
			backup, err := dstSQLiteConn.Backup("main", srcSQLiteConn, "main")
			if err != nil {
				return fmt.Errorf("failed to create backup: %w", err)
			}
			defer backup.Close()

			// Perform the backup
			isDone, err := backup.Step(-1) // -1 means copy all pages at once
			if err != nil {
				return fmt.Errorf("backup step failed: %w", err)
			}

			if !isDone {
				return fmt.Errorf("backup not completed")
			}

			return backup.Finish()
		})
	})
}

// startBackupScheduler starts the periodic backup process using context
func (d *Database) startBackupScheduler() {
	interval, err := time.ParseDuration(d.config.BackupInterval)
	if err != nil {
		logrus.Errorf("Invalid backup interval: %v", err)
		return
	}

	d.backupCtx, d.backupCancel = context.WithCancel(context.Background())

	go func() {
		defer close(d.backupDone)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		logrus.Infof("Started backup scheduler with interval: %s", d.config.BackupInterval)

		for {
			select {
			case <-ticker.C:
				if err := d.performBackup(d.backupCtx); err != nil {
					logrus.Errorf("Scheduled backup failed: %v", err)
				} else {
					logrus.Debug("Scheduled backup completed successfully")
				}
			case <-d.backupCtx.Done():
				logrus.Info("Backup scheduler stopped")
				return
			}
		}
	}()
}

// performBackup creates a backup using sqlite3 native backup API
func (d *Database) performBackup(ctx context.Context) error {
	d.backupMux.Lock()
	defer d.backupMux.Unlock()

	// Backup is only for SQLite memory mode
	if d.config.Type != "sqlite" || !d.config.UseMemory {
		return nil
	}

	// Create temporary backup file
	tempFile := d.config.Path + ".tmp"
	// Clean up any stale temporary file from a previous failed backup
	_ = os.Remove(tempFile) // Ignore error, it's fine if it doesn't exist

	// Ensure backup directory exists
	dir := filepath.Dir(d.config.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Get the underlying sql.DB from GORM
	sqlDB, err := d.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Create the backup file
	backupDB, err := sql.Open("sqlite3", tempFile)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer backupDB.Close()

	// Use sqlite3 backup API to copy from in-memory to file
	if err := d.performBackupCopy(ctx, sqlDB, backupDB); err != nil {
		os.Remove(tempFile) // Clean up temp file on failure
		return fmt.Errorf("failed to backup database: %w", err)
	}

	// Atomically replace the old backup file
	if err := os.Rename(tempFile, d.config.Path); err != nil {
		os.Remove(tempFile) // Clean up temp file on failure
		return fmt.Errorf("failed to replace backup file: %w", err)
	}

	logrus.Debugf("Database backed up to: %s", d.config.Path)
	return nil
}

// Close gracefully shuts down the database and backup scheduler
func (d *Database) Close() error {
	logrus.Info("Shutting down database...")

	// Stop backup scheduler
	if d.backupCancel != nil {
		// Perform final backup if enabled (SQLite memory mode only)
		if d.config.Type == "sqlite" && d.config.UseMemory && d.config.EnableBackupOnShutdown {
			if err := d.performBackup(context.Background()); err != nil {
				logrus.Errorf("Final backup failed: %v", err)
			} else {
				logrus.Info("Final backup completed successfully")
			}
		}

		// Cancel the backup context and wait for scheduler to finish
		d.backupCancel()
		<-d.backupDone
	}

	// Close database connection
	if d.DB != nil {
		sqlDB, err := d.DB.DB()
		if err == nil {
			sqlDB.Close()
		}
	}

	logrus.Info("Database shutdown completed")
	return nil
}
