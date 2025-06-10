package repository

import (
	"time"

	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"gorm.io/gorm"
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

// UpsertHeartbeat creates or updates a heartbeat record
func (r *AAInstanceRepository) UpsertHeartbeat(heartbeat *models.AAInstanceHeartbeat) error {
	// First try to find existing record by instance_id
	var existing models.AAInstanceHeartbeat
	err := r.db.Where("instance_id = ?", heartbeat.InstanceInfo.InstanceID).First(&existing).Error

	if err == gorm.ErrRecordNotFound {
		// Create new record
		return r.db.Create(heartbeat).Error
	} else if err != nil {
		// Some other error occurred
		return err
	} else {
		// Update existing record
		existing.InstanceInfo = heartbeat.InstanceInfo
		existing.ClientIP = heartbeat.ClientIP
		existing.LastHeartbeat = heartbeat.LastHeartbeat
		return r.db.Save(&existing).Error
	}
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
