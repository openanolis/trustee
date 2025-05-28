package repository

import (
	"testing"
	"time"

	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAuditTestDB(t *testing.T) *storage.Database {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)

	err = db.AutoMigrate(&models.AttestationRecord{}, &models.ResourceRequest{})
	assert.NoError(t, err)

	return &storage.Database{DB: db}
}

func TestSaveAttestationRecord(t *testing.T) {
	testDB := setupAuditTestDB(t)
	repo := NewAuditRepository(testDB)

	now := time.Now()
	record := &models.AttestationRecord{
		ClientIP:    "192.168.1.1",
		SessionID:   "test-session-id",
		RequestBody: "test-request-body",
		Status:      200,
		Successful:  true,
		Timestamp:   now,
	}

	err := repo.SaveAttestationRecord(record)

	assert.NoError(t, err)
	assert.NotZero(t, record.ID, "record ID should be set")
}

func TestListAttestationRecords(t *testing.T) {
	testDB := setupAuditTestDB(t)
	repo := NewAuditRepository(testDB)

	baseTime := time.Now()
	records := []*models.AttestationRecord{
		{
			ClientIP:    "192.168.1.1",
			SessionID:   "session1",
			RequestBody: "request1",
			Status:      200,
			Successful:  true,
			Timestamp:   baseTime,
		},
		{
			ClientIP:    "192.168.1.2",
			SessionID:   "session2",
			RequestBody: "request2",
			Status:      400,
			Successful:  false,
			Timestamp:   baseTime.Add(time.Hour),
		},
		{
			ClientIP:    "192.168.1.3",
			SessionID:   "session3",
			RequestBody: "request3",
			Status:      200,
			Successful:  true,
			Timestamp:   baseTime.Add(2 * time.Hour),
		},
	}

	for _, rec := range records {
		err := repo.SaveAttestationRecord(rec)
		assert.NoError(t, err)
	}

	results, err := repo.ListAttestationRecords("", "", nil, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	sessionResults, err := repo.ListAttestationRecords("session1", "", nil, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, sessionResults, 1)
	assert.Equal(t, "session1", sessionResults[0].SessionID)

	typeResults, err := repo.ListAttestationRecords("", "auth", nil, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, typeResults, 2)

	successTrue := true
	successResults, err := repo.ListAttestationRecords("", "", &successTrue, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, successResults, 2)

	startTime := baseTime.Add(30 * time.Minute)
	endTime := baseTime.Add(90 * time.Minute)
	timeResults, err := repo.ListAttestationRecords("", "", nil, &startTime, &endTime, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, timeResults, 1)
	assert.Equal(t, "session2", timeResults[0].SessionID)

	pageResults, err := repo.ListAttestationRecords("", "", nil, nil, nil, 1, 1)
	assert.NoError(t, err)
	assert.Len(t, pageResults, 1)
}

func TestSaveResourceRequest(t *testing.T) {
	testDB := setupAuditTestDB(t)
	repo := NewAuditRepository(testDB)

	now := time.Now()
	record := &models.ResourceRequest{
		ClientIP:   "192.168.1.1",
		SessionID:  "test-session-id",
		Repository: "test-repo",
		Type:       "test-type",
		Tag:        "test-tag",
		Method:     "GET",
		Status:     200,
		Successful: true,
		Timestamp:  now,
	}

	err := repo.SaveResourceRequest(record)

	assert.NoError(t, err)
	assert.NotZero(t, record.ID, "record ID should be set")
}

func TestListResourceRequests(t *testing.T) {
	testDB := setupAuditTestDB(t)
	repo := NewAuditRepository(testDB)

	baseTime := time.Now()
	records := []*models.ResourceRequest{
		{
			ClientIP:   "192.168.1.1",
			SessionID:  "session1",
			Repository: "repo1",
			Type:       "type1",
			Tag:        "tag1",
			Method:     "GET",
			Status:     200,
			Successful: true,
			Timestamp:  baseTime,
		},
		{
			ClientIP:   "192.168.1.2",
			SessionID:  "session2",
			Repository: "repo1",
			Type:       "type2",
			Tag:        "tag2",
			Method:     "POST",
			Status:     400,
			Successful: false,
			Timestamp:  baseTime.Add(time.Hour),
		},
		{
			ClientIP:   "192.168.1.3",
			SessionID:  "session3",
			Repository: "repo2",
			Type:       "type1",
			Tag:        "tag3",
			Method:     "GET",
			Status:     200,
			Successful: true,
			Timestamp:  baseTime.Add(2 * time.Hour),
		},
	}

	for _, rec := range records {
		err := repo.SaveResourceRequest(rec)
		assert.NoError(t, err)
	}

	results, err := repo.ListResourceRequests("", "", "", "", "", nil, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	sessionResults, err := repo.ListResourceRequests("session1", "", "", "", "", nil, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, sessionResults, 1)
	assert.Equal(t, "session1", sessionResults[0].SessionID)

	repoResults, err := repo.ListResourceRequests("", "repo1", "", "", "", nil, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, repoResults, 2)

	typeResults, err := repo.ListResourceRequests("", "", "type1", "", "", nil, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, typeResults, 2)

	methodResults, err := repo.ListResourceRequests("", "", "", "", "GET", nil, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, methodResults, 2)

	successTrue := true
	successResults, err := repo.ListResourceRequests("", "", "", "", "", &successTrue, nil, nil, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, successResults, 2)

	startTime := baseTime.Add(30 * time.Minute)
	endTime := baseTime.Add(90 * time.Minute)
	timeResults, err := repo.ListResourceRequests("", "", "", "", "", nil, &startTime, &endTime, 10, 0)
	assert.NoError(t, err)
	assert.Len(t, timeResults, 1)
	assert.Equal(t, "session2", timeResults[0].SessionID)

	pageResults, err := repo.ListResourceRequests("", "", "", "", "", nil, nil, nil, 1, 1)
	assert.NoError(t, err)
	assert.Len(t, pageResults, 1)
}

func TestCleanupOldRecords_HardDelete(t *testing.T) {
	testDB := setupAuditTestDB(t)
	repo := NewAuditRepository(testDB)

	baseTime := time.Now()

	// Create test attestation records
	attestationRecords := []*models.AttestationRecord{
		{
			ClientIP:    "192.168.1.1",
			SessionID:   "old-session-1",
			RequestBody: "old-request-1",
			Status:      200,
			Successful:  true,
			Timestamp:   baseTime.AddDate(0, 0, -5), // 5 days old
		},
		{
			ClientIP:    "192.168.1.2",
			SessionID:   "old-session-2",
			RequestBody: "old-request-2",
			Status:      200,
			Successful:  true,
			Timestamp:   baseTime.AddDate(0, 0, -2), // 2 days old
		},
		{
			ClientIP:    "192.168.1.3",
			SessionID:   "new-session-1",
			RequestBody: "new-request-1",
			Status:      200,
			Successful:  true,
			Timestamp:   baseTime, // current time
		},
	}

	// Create test resource request records
	resourceRecords := []*models.ResourceRequest{
		{
			ClientIP:   "192.168.1.1",
			SessionID:  "old-resource-1",
			Repository: "old-repo-1",
			Type:       "old-type-1",
			Tag:        "old-tag-1",
			Method:     "GET",
			Status:     200,
			Successful: true,
			Timestamp:  baseTime.AddDate(0, 0, -5), // 5 days old
		},
		{
			ClientIP:   "192.168.1.2",
			SessionID:  "old-resource-2",
			Repository: "old-repo-2",
			Type:       "old-type-2",
			Tag:        "old-tag-2",
			Method:     "GET",
			Status:     200,
			Successful: true,
			Timestamp:  baseTime.AddDate(0, 0, -2), // 2 days old
		},
		{
			ClientIP:   "192.168.1.3",
			SessionID:  "new-resource-1",
			Repository: "new-repo-1",
			Type:       "new-type-1",
			Tag:        "new-tag-1",
			Method:     "GET",
			Status:     200,
			Successful: true,
			Timestamp:  baseTime, // current time
		},
	}

	// Save all records
	for _, rec := range attestationRecords {
		err := repo.SaveAttestationRecord(rec)
		assert.NoError(t, err)
	}

	for _, rec := range resourceRecords {
		err := repo.SaveResourceRequest(rec)
		assert.NoError(t, err)
	}

	// Verify initial counts
	stats, err := repo.GetAuditStats()
	assert.NoError(t, err)
	assert.Equal(t, int64(3), stats["attestation_records"])
	assert.Equal(t, int64(3), stats["resource_requests"])

	// Perform cleanup with 3 days retention (should delete records older than 3 days)
	err = repo.CleanupOldRecords(1000, 3)
	assert.NoError(t, err)

	// Verify that old records (5 days old) are permanently deleted
	stats, err = repo.GetAuditStats()
	assert.NoError(t, err)
	assert.Equal(t, int64(2), stats["attestation_records"]) // Should have 2 records left
	assert.Equal(t, int64(2), stats["resource_requests"])   // Should have 2 records left

	// Verify that we cannot find the deleted records even with Unscoped query
	var deletedAttestationCount int64
	err = testDB.DB.Unscoped().Model(&models.AttestationRecord{}).Where("session_id = ?", "old-session-1").Count(&deletedAttestationCount).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(0), deletedAttestationCount, "Old attestation record should be permanently deleted")

	var deletedResourceCount int64
	err = testDB.DB.Unscoped().Model(&models.ResourceRequest{}).Where("session_id = ?", "old-resource-1").Count(&deletedResourceCount).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(0), deletedResourceCount, "Old resource request should be permanently deleted")

	// Test max records limit
	// Add more records to test the max records limit
	for i := 0; i < 5; i++ {
		attestationRecord := &models.AttestationRecord{
			ClientIP:    "192.168.1.100",
			SessionID:   "extra-session-" + string(rune(i)),
			RequestBody: "extra-request",
			Status:      200,
			Successful:  true,
			Timestamp:   baseTime.Add(time.Duration(i) * time.Minute),
		}
		err := repo.SaveAttestationRecord(attestationRecord)
		assert.NoError(t, err)
	}

	// Now we should have 7 attestation records total
	stats, err = repo.GetAuditStats()
	assert.NoError(t, err)
	assert.Equal(t, int64(7), stats["attestation_records"])

	// Cleanup with max 3 records
	err = repo.CleanupOldRecords(3, 0) // 0 retention days, only limit by max records
	assert.NoError(t, err)

	// Should have only 3 attestation records left (the latest ones)
	stats, err = repo.GetAuditStats()
	assert.NoError(t, err)
	assert.Equal(t, int64(3), stats["attestation_records"])
}
