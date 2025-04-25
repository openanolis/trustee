package repository

import (
	"testing"

	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *storage.Database {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)

	err = db.AutoMigrate(&models.Resource{})
	assert.NoError(t, err)

	return &storage.Database{DB: db}
}

func TestSaveResource(t *testing.T) {
	testDB := setupTestDB(t)
	repo := NewResourceRepository(testDB)

	resource := &models.Resource{
		Repository: "test-repo",
		Type:       "test-type",
		Tag:        "test-tag",
		Metadata:   "test-metadata",
	}

	err := repo.SaveResource(resource)

	assert.NoError(t, err)
	assert.NotZero(t, resource.ID, "resource ID should be set")
}

func TestGetResource(t *testing.T) {
	testDB := setupTestDB(t)
	repo := NewResourceRepository(testDB)

	resource := &models.Resource{
		Repository: "test-repo",
		Type:       "test-type",
		Tag:        "test-tag",
		Metadata:   "test-metadata",
	}
	err := repo.SaveResource(resource)
	assert.NoError(t, err)

	result, err := repo.GetResource("test-repo", "test-type", "test-tag")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-repo", result.Repository)
	assert.Equal(t, "test-type", result.Type)
	assert.Equal(t, "test-tag", result.Tag)
	assert.Equal(t, "test-metadata", result.Metadata)
}

func TestListResources(t *testing.T) {
	testDB := setupTestDB(t)
	repo := NewResourceRepository(testDB)

	resources := []*models.Resource{
		{
			Repository: "repo1",
			Type:       "type1",
			Tag:        "tag1",
			Metadata:   "metadata1",
		},
		{
			Repository: "repo1",
			Type:       "type2",
			Tag:        "tag2",
			Metadata:   "metadata2",
		},
		{
			Repository: "repo2",
			Type:       "type1",
			Tag:        "tag3",
			Metadata:   "metadata3",
		},
	}

	for _, res := range resources {
		err := repo.SaveResource(res)
		assert.NoError(t, err)
	}

	allResources, err := repo.ListResources("", "")
	assert.NoError(t, err)
	assert.Len(t, allResources, 3)

	repo1Resources, err := repo.ListResources("repo1", "")
	assert.NoError(t, err)
	assert.Len(t, repo1Resources, 2)

	type1Resources, err := repo.ListResources("", "type1")
	assert.NoError(t, err)
	assert.Len(t, type1Resources, 2)

	filteredResources, err := repo.ListResources("repo1", "type1")
	assert.NoError(t, err)
	assert.Len(t, filteredResources, 1)
}

func TestDeleteResource(t *testing.T) {
	testDB := setupTestDB(t)
	repo := NewResourceRepository(testDB)

	resource := &models.Resource{
		Repository: "test-repo",
		Type:       "test-type",
		Tag:        "test-tag",
		Metadata:   "test-metadata",
	}
	err := repo.SaveResource(resource)
	assert.NoError(t, err)

	result, err := repo.GetResource("test-repo", "test-type", "test-tag")
	assert.NoError(t, err)
	assert.NotNil(t, result)

	err = repo.DeleteResource("test-repo", "test-type", "test-tag")
	assert.NoError(t, err)

	result, err = repo.GetResource("test-repo", "test-type", "test-tag")
	assert.Error(t, err)
	assert.Nil(t, result)
}
