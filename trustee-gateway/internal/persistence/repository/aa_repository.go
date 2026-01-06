package repository

import (
	"time"

	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AAInstanceRepository handles database operations for attestation agent instance heartbeats
type AAInstanceRepository struct {
	db *gorm.DB
}

// NewAAInstanceRepository creates a new AA instance repository
func NewAAInstanceRepository(database *storage.Database) *AAInstanceRepository {
	return &AAInstanceRepository{
		db: database.DB,
	}
}

// UpsertHeartbeat creates or updates a heartbeat record using database-native upsert
// Uses ON CONFLICT (SQLite) / ON DUPLICATE KEY UPDATE (MySQL) for atomic upsert
// Requires unique index on instance_id column
func (r *AAInstanceRepository) UpsertHeartbeat(heartbeat *models.AAInstanceHeartbeat) error {
	heartbeat.LastHeartbeat = time.Now()

	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "instance_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"image_id",
			"instance_name",
			"owner_account_id",
			"client_ip",
			"last_heartbeat",
			"updated_at",
		}),
	}).Create(heartbeat).Error
}

// GetActiveHeartbeats retrieves all heartbeats that are newer than the cutoff time
func (r *AAInstanceRepository) GetActiveHeartbeats(cutoffTime time.Time) ([]models.AAInstanceHeartbeat, error) {
	var heartbeats []models.AAInstanceHeartbeat
	err := r.db.Where("last_heartbeat >= ?", cutoffTime).Order("last_heartbeat desc").Find(&heartbeats).Error
	return heartbeats, err
}

// CleanupExpiredHeartbeats removes heartbeat records older than the cutoff time
func (r *AAInstanceRepository) CleanupExpiredHeartbeats(cutoffTime time.Time) error {
	return r.db.Unscoped().Where("last_heartbeat < ?", cutoffTime).Delete(&models.AAInstanceHeartbeat{}).Error
}
