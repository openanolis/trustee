package repository

import (
	"testing"
	"time"

	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAAInstanceTestDB(t *testing.T, withUniqueIndex bool) *storage.Database {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.AAInstanceHeartbeat{})
	require.NoError(t, err)

	if withUniqueIndex {
		err = db.Exec("CREATE UNIQUE INDEX idx_aa_heartbeat_instance_id ON aa_instance_heartbeats(instance_id)").Error
		require.NoError(t, err)
	}

	return &storage.Database{DB: db}
}

func TestAAInstanceRepositoryUpsertHeartbeatUpdatesExistingRecord(t *testing.T) {
	repo := NewAAInstanceRepository(setupAAInstanceTestDB(t, true))

	err := repo.UpsertHeartbeat(&models.AAInstanceHeartbeat{
		InstanceInfo: models.InstanceInfo{
			InstanceID:     "i-test",
			ImageID:        "old-image",
			InstanceName:   "old-name",
			OwnerAccountID: "old-owner",
			IP:             "10.0.0.1",
		},
		ClientIP: "10.0.0.1",
	})
	require.NoError(t, err)

	err = repo.UpsertHeartbeat(&models.AAInstanceHeartbeat{
		InstanceInfo: models.InstanceInfo{
			InstanceID:     "i-test",
			ImageID:        "new-image",
			InstanceName:   "new-name",
			OwnerAccountID: "new-owner",
			EasModelID:     "model-1",
			EasInstanceID:  "eas-1",
			EasPodName:     "pod-1",
			IP:             "10.0.0.2",
		},
		ClientIP: "10.0.0.2",
	})
	require.NoError(t, err)

	var heartbeats []models.AAInstanceHeartbeat
	err = repo.db.Find(&heartbeats).Error
	require.NoError(t, err)
	require.Len(t, heartbeats, 1)

	heartbeat := heartbeats[0]
	assert.Equal(t, "i-test", heartbeat.InstanceID)
	assert.Equal(t, "new-image", heartbeat.ImageID)
	assert.Equal(t, "new-name", heartbeat.InstanceName)
	assert.Equal(t, "new-owner", heartbeat.OwnerAccountID)
	assert.Equal(t, "model-1", heartbeat.EasModelID)
	assert.Equal(t, "eas-1", heartbeat.EasInstanceID)
	assert.Equal(t, "pod-1", heartbeat.EasPodName)
	assert.Equal(t, "10.0.0.2", heartbeat.IP)
	assert.Equal(t, "10.0.0.2", heartbeat.ClientIP)
}

func TestAAInstanceRepositoryGetActiveHeartbeatsDeduplicatesInstanceID(t *testing.T) {
	repo := NewAAInstanceRepository(setupAAInstanceTestDB(t, false))
	now := time.Now()

	records := []models.AAInstanceHeartbeat{
		{
			InstanceInfo:  models.InstanceInfo{InstanceID: "i-test", IP: "10.0.0.1"},
			ClientIP:      "10.0.0.1",
			LastHeartbeat: now.Add(-time.Minute),
		},
		{
			InstanceInfo:  models.InstanceInfo{InstanceID: "i-test", IP: "10.0.0.2"},
			ClientIP:      "10.0.0.2",
			LastHeartbeat: now,
		},
		{
			InstanceInfo:  models.InstanceInfo{InstanceID: "i-other", IP: "10.0.0.3"},
			ClientIP:      "10.0.0.3",
			LastHeartbeat: now.Add(-30 * time.Second),
		},
	}
	require.NoError(t, repo.db.Create(&records).Error)

	heartbeats, err := repo.GetActiveHeartbeats(now.Add(-10 * time.Minute))
	require.NoError(t, err)
	require.Len(t, heartbeats, 2)

	assert.Equal(t, "i-test", heartbeats[0].InstanceID)
	assert.Equal(t, "10.0.0.2", heartbeats[0].ClientIP)
	assert.Equal(t, "i-other", heartbeats[1].InstanceID)
}
