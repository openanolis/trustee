package services

import (
	"context"
	"time"

	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/sirupsen/logrus"
)

// AuditCleanupService handles periodic cleanup of audit records
type AuditCleanupService struct {
	auditRepo *repository.AuditRepository
	config    *config.AuditConfig
	ticker    *time.Ticker
	done      chan bool
}

// NewAuditCleanupService creates a new audit cleanup service
func NewAuditCleanupService(auditRepo *repository.AuditRepository, auditConfig *config.AuditConfig) *AuditCleanupService {
	return &AuditCleanupService{
		auditRepo: auditRepo,
		config:    auditConfig,
		done:      make(chan bool),
	}
}

// Start begins the periodic cleanup process
func (s *AuditCleanupService) Start(ctx context.Context) {
	interval := time.Duration(s.config.CleanupIntervalHours) * time.Hour
	s.ticker = time.NewTicker(interval)

	logrus.Infof("Starting audit cleanup service with interval: %v, max_records: %d, retention_days: %d",
		interval, s.config.MaxRecords, s.config.RetentionDays)

	// Run cleanup immediately on start
	s.performCleanup()

	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.performCleanup()
			case <-s.done:
				logrus.Info("Audit cleanup service stopped")
				return
			case <-ctx.Done():
				logrus.Info("Audit cleanup service stopped due to context cancellation")
				return
			}
		}
	}()
}

// Stop stops the cleanup service
func (s *AuditCleanupService) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	close(s.done)
}

// performCleanup executes the actual cleanup logic
func (s *AuditCleanupService) performCleanup() {
	logrus.Info("Starting audit records hard cleanup (permanent deletion)")

	// Get stats before cleanup
	statsBefore, err := s.auditRepo.GetAuditStats()
	if err != nil {
		logrus.Errorf("Failed to get audit stats before cleanup: %v", err)
		return
	}

	// Perform cleanup
	err = s.auditRepo.CleanupOldRecords(s.config.MaxRecords, s.config.RetentionDays)
	if err != nil {
		logrus.Errorf("Failed to cleanup audit records: %v", err)
		return
	}

	// Get stats after cleanup
	statsAfter, err := s.auditRepo.GetAuditStats()
	if err != nil {
		logrus.Errorf("Failed to get audit stats after cleanup: %v", err)
		return
	}

	// Log cleanup results
	attestationDeleted := statsBefore["attestation_records"] - statsAfter["attestation_records"]
	resourceDeleted := statsBefore["resource_requests"] - statsAfter["resource_requests"]

	if attestationDeleted > 0 || resourceDeleted > 0 {
		logrus.Infof("Audit hard cleanup completed: permanently deleted %d attestation records, %d resource request records",
			attestationDeleted, resourceDeleted)
		logrus.Infof("Remaining records: %d attestation records, %d resource request records",
			statsAfter["attestation_records"], statsAfter["resource_requests"])
	} else {
		logrus.Debug("Audit hard cleanup completed: no records deleted")
	}
}

// ForceCleanup performs an immediate cleanup (useful for testing or manual triggers)
func (s *AuditCleanupService) ForceCleanup() error {
	s.performCleanup()
	return nil
}
