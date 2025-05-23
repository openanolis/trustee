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
