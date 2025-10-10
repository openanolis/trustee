package repository

import (
	"time"

	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"gorm.io/gorm"
)

// AuditRepository handles database operations for audit records
type AuditRepository struct {
	db *gorm.DB
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(database *storage.Database) *AuditRepository {
	return &AuditRepository{
		db: database.DB,
	}
}

// SaveAttestationRecord saves an attestation record to the database
func (r *AuditRepository) SaveAttestationRecord(record *models.AttestationRecord) error {
	return r.db.Save(record).Error
}

// ListAttestationRecords retrieves attestation records with optional filtering
func (r *AuditRepository) ListAttestationRecords(
	sessionID string,
	sourceService string,
	instanceID string,
	successful *bool,
	startTime, endTime *time.Time,
	limit, offset int,
) ([]models.AttestationRecord, error) {
	var records []models.AttestationRecord

	query := r.db

	if sessionID != "" {
		query = query.Where("session_id = ?", sessionID)
	}

	if sourceService != "" {
		query = query.Where("source_service = ?", sourceService)
	}

	if instanceID != "" {
		query = query.Where("instance_id = ?", instanceID)
	}

	if successful != nil {
		query = query.Where("successful = ?", *successful)
	}

	if startTime != nil {
		query = query.Where("timestamp >= ?", startTime)
	}

	if endTime != nil {
		query = query.Where("timestamp <= ?", endTime)
	}

	if err := query.Limit(limit).Offset(offset).Order("timestamp desc").Find(&records).Error; err != nil {
		return nil, err
	}

	return records, nil
}

// SaveResourceRequest saves a resource request record to the database
func (r *AuditRepository) SaveResourceRequest(record *models.ResourceRequest) error {
	return r.db.Save(record).Error
}

// ListResourceRequests retrieves resource request records with optional filtering
func (r *AuditRepository) ListResourceRequests(
	sessionID string,
	repository string,
	resourceType string,
	tag string,
	method string,
	instanceID string,
	successful *bool,
	startTime, endTime *time.Time,
	limit, offset int,
) ([]models.ResourceRequest, error) {
	var records []models.ResourceRequest

	query := r.db

	if sessionID != "" {
		query = query.Where("session_id = ?", sessionID)
	}

	if repository != "" {
		query = query.Where("repository = ?", repository)
	}

	if resourceType != "" {
		query = query.Where("type = ?", resourceType)
	}

	if tag != "" {
		query = query.Where("tag = ?", tag)
	}

	if method != "" {
		query = query.Where("method = ?", method)
	}

	if instanceID != "" {
		query = query.Where("instance_id = ?", instanceID)
	}

	if successful != nil {
		query = query.Where("successful = ?", *successful)
	}

	if startTime != nil {
		query = query.Where("timestamp >= ?", startTime)
	}

	if endTime != nil {
		query = query.Where("timestamp <= ?", endTime)
	}

	if err := query.Limit(limit).Offset(offset).Order("timestamp desc").Find(&records).Error; err != nil {
		return nil, err
	}

	return records, nil
}

// CountAttestationRecords counts attestation records with optional filtering (without pagination)
func (r *AuditRepository) CountAttestationRecords(
    sessionID string,
    sourceService string,
    instanceID string,
    successful *bool,
    startTime, endTime *time.Time,
) (int64, error) {
    var count int64

    query := r.db.Model(&models.AttestationRecord{})

    if sessionID != "" {
        query = query.Where("session_id = ?", sessionID)
    }

    if sourceService != "" {
        query = query.Where("source_service = ?", sourceService)
    }

    if instanceID != "" {
        query = query.Where("instance_id = ?", instanceID)
    }

    if successful != nil {
        query = query.Where("successful = ?", *successful)
    }

    if startTime != nil {
        query = query.Where("timestamp >= ?", startTime)
    }

    if endTime != nil {
        query = query.Where("timestamp <= ?", endTime)
    }

    if err := query.Count(&count).Error; err != nil {
        return 0, err
    }

    return count, nil
}

// CountResourceRequests counts resource request records with optional filtering (without pagination)
func (r *AuditRepository) CountResourceRequests(
    sessionID string,
    repository string,
    resourceType string,
    tag string,
    method string,
    instanceID string,
    successful *bool,
    startTime, endTime *time.Time,
) (int64, error) {
    var count int64

    query := r.db.Model(&models.ResourceRequest{})

    if sessionID != "" {
        query = query.Where("session_id = ?", sessionID)
    }

    if repository != "" {
        query = query.Where("repository = ?", repository)
    }

    if resourceType != "" {
        query = query.Where("type = ?", resourceType)
    }

    if tag != "" {
        query = query.Where("tag = ?", tag)
    }

    if method != "" {
        query = query.Where("method = ?", method)
    }

    if instanceID != "" {
        query = query.Where("instance_id = ?", instanceID)
    }

    if successful != nil {
        query = query.Where("successful = ?", *successful)
    }

    if startTime != nil {
        query = query.Where("timestamp >= ?", startTime)
    }

    if endTime != nil {
        query = query.Where("timestamp <= ?", endTime)
    }

    if err := query.Count(&count).Error; err != nil {
        return 0, err
    }

    return count, nil
}

// CleanupOldRecords removes old audit records based on retention policy
func (r *AuditRepository) CleanupOldRecords(maxRecords int, retentionDays int) error {
	// Only apply time-based cleanup if retention days > 0
	if retentionDays > 0 {
		cutoffTime := time.Now().AddDate(0, 0, -retentionDays)

		// Delete old attestation records (hard delete using Unscoped)
		if err := r.db.Unscoped().Where("timestamp < ?", cutoffTime).Delete(&models.AttestationRecord{}).Error; err != nil {
			return err
		}

		// Delete old resource request records (hard delete using Unscoped)
		if err := r.db.Unscoped().Where("timestamp < ?", cutoffTime).Delete(&models.ResourceRequest{}).Error; err != nil {
			return err
		}
	}

	// Only apply count-based cleanup if maxRecords > 0
	if maxRecords > 0 {
		// Keep only the latest maxRecords for attestation records
		var attestationCount int64
		if err := r.db.Model(&models.AttestationRecord{}).Count(&attestationCount).Error; err != nil {
			return err
		}

		if attestationCount > int64(maxRecords) {
			// Get IDs of records to keep (latest maxRecords)
			var keepIDs []uint
			if err := r.db.Model(&models.AttestationRecord{}).
				Select("id").
				Order("timestamp desc").
				Limit(maxRecords).
				Pluck("id", &keepIDs).Error; err != nil {
				return err
			}

			// Delete records not in the keep list (hard delete using Unscoped)
			if len(keepIDs) > 0 {
				if err := r.db.Unscoped().Where("id NOT IN ?", keepIDs).Delete(&models.AttestationRecord{}).Error; err != nil {
					return err
				}
			} else {
				// If no records to keep, delete all attestation records
				if err := r.db.Unscoped().Where("1=1").Delete(&models.AttestationRecord{}).Error; err != nil {
					return err
				}
			}
		}

		// Keep only the latest maxRecords for resource request records
		var resourceCount int64
		if err := r.db.Model(&models.ResourceRequest{}).Count(&resourceCount).Error; err != nil {
			return err
		}

		if resourceCount > int64(maxRecords) {
			// Get IDs of records to keep (latest maxRecords)
			var keepIDs []uint
			if err := r.db.Model(&models.ResourceRequest{}).
				Select("id").
				Order("timestamp desc").
				Limit(maxRecords).
				Pluck("id", &keepIDs).Error; err != nil {
				return err
			}

			// Delete records not in the keep list (hard delete using Unscoped)
			if len(keepIDs) > 0 {
				if err := r.db.Unscoped().Where("id NOT IN ?", keepIDs).Delete(&models.ResourceRequest{}).Error; err != nil {
					return err
				}
			} else {
				// If no records to keep, delete all resource request records
				if err := r.db.Unscoped().Where("1=1").Delete(&models.ResourceRequest{}).Error; err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// GetAuditStats returns statistics about audit records
func (r *AuditRepository) GetAuditStats() (map[string]int64, error) {
	stats := make(map[string]int64)

	var attestationCount int64
	if err := r.db.Model(&models.AttestationRecord{}).Count(&attestationCount).Error; err != nil {
		return nil, err
	}
	stats["attestation_records"] = attestationCount

	var resourceCount int64
	if err := r.db.Model(&models.ResourceRequest{}).Count(&resourceCount).Error; err != nil {
		return nil, err
	}
	stats["resource_requests"] = resourceCount

	return stats, nil
}
