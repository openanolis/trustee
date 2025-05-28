package services

import (
	"context"
	"testing"
	"time"

	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto migrate the schema
	err = db.AutoMigrate(&models.AttestationRecord{}, &models.ResourceRequest{})
	require.NoError(t, err)

	return db
}

func createTestRecords(t *testing.T, db *gorm.DB, count int, daysOld int) {
	timestamp := time.Now().AddDate(0, 0, -daysOld)

	// Create attestation records
	for i := 0; i < count; i++ {
		record := &models.AttestationRecord{
			ClientIP:      "127.0.0.1",
			SessionID:     "test-session",
			RequestBody:   "test-request",
			Claims:        "test-claims",
			Status:        200,
			Successful:    true,
			Timestamp:     timestamp.Add(time.Duration(i) * time.Minute),
			SourceService: "kbs",
		}
		err := db.Create(record).Error
		require.NoError(t, err)
	}

	// Create resource request records
	for i := 0; i < count; i++ {
		record := &models.ResourceRequest{
			ClientIP:   "127.0.0.1",
			SessionID:  "test-session",
			Repository: "test-repo",
			Type:       "secret",
			Tag:        "test-tag",
			Method:     "GET",
			Status:     200,
			Successful: true,
			Timestamp:  timestamp.Add(time.Duration(i) * time.Minute),
		}
		err := db.Create(record).Error
		require.NoError(t, err)
	}
}

func TestAuditCleanupService_CleanupByRetentionDays(t *testing.T) {
	db := setupTestDB(t)
	storage := &storage.Database{DB: db}
	auditRepo := repository.NewAuditRepository(storage)

	// Create test data: 5 records that are 5 days old, 5 records that are 1 day old
	createTestRecords(t, db, 5, 5) // Old records
	createTestRecords(t, db, 5, 1) // Recent records

	// Configure cleanup service with 3-day retention
	config := &config.AuditConfig{
		MaxRecords:           1000,
		RetentionDays:        3,
		CleanupIntervalHours: 24,
	}

	service := NewAuditCleanupService(auditRepo, config)

	// Get initial stats
	statsBefore, err := auditRepo.GetAuditStats()
	require.NoError(t, err)
	assert.Equal(t, int64(10), statsBefore["attestation_records"])
	assert.Equal(t, int64(10), statsBefore["resource_requests"])

	// Perform cleanup
	err = service.ForceCleanup()
	require.NoError(t, err)

	// Check stats after cleanup
	statsAfter, err := auditRepo.GetAuditStats()
	require.NoError(t, err)

	// Should only have 5 records left (the recent ones)
	assert.Equal(t, int64(5), statsAfter["attestation_records"])
	assert.Equal(t, int64(5), statsAfter["resource_requests"])
}

func TestAuditCleanupService_CleanupByMaxRecords(t *testing.T) {
	db := setupTestDB(t)
	storage := &storage.Database{DB: db}
	auditRepo := repository.NewAuditRepository(storage)

	// Create 20 recent records (all within retention period)
	createTestRecords(t, db, 20, 1)

	// Configure cleanup service with max 10 records
	config := &config.AuditConfig{
		MaxRecords:           10,
		RetentionDays:        30, // Long retention, so only max_records limit applies
		CleanupIntervalHours: 24,
	}

	service := NewAuditCleanupService(auditRepo, config)

	// Get initial stats
	statsBefore, err := auditRepo.GetAuditStats()
	require.NoError(t, err)
	assert.Equal(t, int64(20), statsBefore["attestation_records"])
	assert.Equal(t, int64(20), statsBefore["resource_requests"])

	// Perform cleanup
	err = service.ForceCleanup()
	require.NoError(t, err)

	// Check stats after cleanup
	statsAfter, err := auditRepo.GetAuditStats()
	require.NoError(t, err)

	// Should only have 10 records left (the most recent ones)
	assert.Equal(t, int64(10), statsAfter["attestation_records"])
	assert.Equal(t, int64(10), statsAfter["resource_requests"])
}

func TestAuditCleanupService_NoCleanupNeeded(t *testing.T) {
	db := setupTestDB(t)
	storage := &storage.Database{DB: db}
	auditRepo := repository.NewAuditRepository(storage)

	// Create 5 recent records
	createTestRecords(t, db, 5, 1)

	// Configure cleanup service with generous limits
	config := &config.AuditConfig{
		MaxRecords:           1000,
		RetentionDays:        30,
		CleanupIntervalHours: 24,
	}

	service := NewAuditCleanupService(auditRepo, config)

	// Get initial stats
	statsBefore, err := auditRepo.GetAuditStats()
	require.NoError(t, err)
	assert.Equal(t, int64(5), statsBefore["attestation_records"])
	assert.Equal(t, int64(5), statsBefore["resource_requests"])

	// Perform cleanup
	err = service.ForceCleanup()
	require.NoError(t, err)

	// Check stats after cleanup - should be unchanged
	statsAfter, err := auditRepo.GetAuditStats()
	require.NoError(t, err)
	assert.Equal(t, int64(5), statsAfter["attestation_records"])
	assert.Equal(t, int64(5), statsAfter["resource_requests"])
}

func TestAuditCleanupService_StartStop(t *testing.T) {
	db := setupTestDB(t)
	storage := &storage.Database{DB: db}
	auditRepo := repository.NewAuditRepository(storage)

	// Configure cleanup service with short interval for testing
	config := &config.AuditConfig{
		MaxRecords:           10,
		RetentionDays:        3,
		CleanupIntervalHours: 1, // 1 hour interval
	}

	service := NewAuditCleanupService(auditRepo, config)

	// Test start and stop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start service
	service.Start(ctx)

	// Verify service is running
	assert.NotNil(t, service.ticker)

	// Stop service
	service.Stop()

	// Verify service is stopped
	// The done channel should be closed after Stop() is called
	select {
	case <-service.done:
		// Expected - channel is closed
	default:
		t.Error("done channel should be closed after Stop()")
	}
}

func TestAuditCleanupService_ContextCancellation(t *testing.T) {
	db := setupTestDB(t)
	storage := &storage.Database{DB: db}
	auditRepo := repository.NewAuditRepository(storage)

	config := &config.AuditConfig{
		MaxRecords:           10,
		RetentionDays:        3,
		CleanupIntervalHours: 1,
	}

	service := NewAuditCleanupService(auditRepo, config)

	// Create context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start service
	service.Start(ctx)

	// Cancel context
	cancel()

	// Give some time for the service to stop
	time.Sleep(100 * time.Millisecond)

	// Service should handle context cancellation gracefully
	assert.NotNil(t, service.ticker)
}

func TestAuditCleanupService_MixedScenario(t *testing.T) {
	db := setupTestDB(t)
	storage := &storage.Database{DB: db}
	auditRepo := repository.NewAuditRepository(storage)

	// Create mixed data:
	// - 10 records that are 10 days old (should be deleted by retention)
	// - 15 records that are 1 day old (5 should be deleted by max_records limit)
	createTestRecords(t, db, 10, 10) // Old records
	createTestRecords(t, db, 15, 1)  // Recent records

	// Configure cleanup: 3-day retention, max 10 records
	config := &config.AuditConfig{
		MaxRecords:           10,
		RetentionDays:        3,
		CleanupIntervalHours: 24,
	}

	service := NewAuditCleanupService(auditRepo, config)

	// Get initial stats
	statsBefore, err := auditRepo.GetAuditStats()
	require.NoError(t, err)
	assert.Equal(t, int64(25), statsBefore["attestation_records"])
	assert.Equal(t, int64(25), statsBefore["resource_requests"])

	// Perform cleanup
	err = service.ForceCleanup()
	require.NoError(t, err)

	// Check stats after cleanup
	statsAfter, err := auditRepo.GetAuditStats()
	require.NoError(t, err)

	// Should have 10 records left (the 10 most recent ones from the 15 recent records)
	assert.Equal(t, int64(10), statsAfter["attestation_records"])
	assert.Equal(t, int64(10), statsAfter["resource_requests"])
}
