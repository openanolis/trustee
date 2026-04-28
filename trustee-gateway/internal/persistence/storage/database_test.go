package storage

import (
	"testing"
	"time"

	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestMigrateAAInstanceHeartbeatIndexSQLiteCleansDuplicates(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(&models.AAInstanceHeartbeat{}))

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
			InstanceInfo:  models.InstanceInfo{InstanceID: ""},
			ClientIP:      "10.0.0.3",
			LastHeartbeat: now,
		},
	}
	require.NoError(t, db.Create(&records).Error)

	database := &Database{
		DB:     db,
		config: &config.DatabaseConfig{Type: "sqlite"},
	}
	require.NoError(t, database.migrateAAInstanceHeartbeatIndexSQLite())

	var heartbeats []models.AAInstanceHeartbeat
	require.NoError(t, db.Order("last_heartbeat desc").Find(&heartbeats).Error)
	require.Len(t, heartbeats, 1)
	assert.Equal(t, "i-test", heartbeats[0].InstanceID)
	assert.Equal(t, "10.0.0.2", heartbeats[0].ClientIP)

	require.NoError(t, db.Create(&models.AAInstanceHeartbeat{
		InstanceInfo:  models.InstanceInfo{InstanceID: "i-other", IP: "10.0.0.4"},
		ClientIP:      "10.0.0.4",
		LastHeartbeat: now,
	}).Error)

	err = db.Create(&models.AAInstanceHeartbeat{
		InstanceInfo:  models.InstanceInfo{InstanceID: "i-test", IP: "10.0.0.5"},
		ClientIP:      "10.0.0.5",
		LastHeartbeat: now,
	}).Error
	assert.Error(t, err)
}
