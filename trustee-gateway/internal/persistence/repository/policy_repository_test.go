package repository

import (
	"testing"

	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupPolicyTestDB(t *testing.T) *storage.Database {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)

	err = db.AutoMigrate(&models.AttestationPolicy{}, &models.ResourcePolicy{})
	assert.NoError(t, err)

	return &storage.Database{DB: db}
}

func TestSaveAttestationPolicy(t *testing.T) {
	testDB := setupPolicyTestDB(t)
	repo := NewPolicyRepository(testDB)

	policy := &models.AttestationPolicy{
		PolicyID: "test-policy-id",
		Type:     "test-type",
		Policy:   []byte("test-policy-content"),
		Metadata: "test-metadata",
	}

	err := repo.SaveAttestationPolicy(policy)

	assert.NoError(t, err)
	assert.NotZero(t, policy.ID, "policy ID should be set")
}

func TestGetAttestationPolicy(t *testing.T) {
	testDB := setupPolicyTestDB(t)
	repo := NewPolicyRepository(testDB)

	policy := &models.AttestationPolicy{
		PolicyID: "test-policy-id",
		Type:     "test-type",
		Policy:   []byte("test-policy-content"),
		Metadata: "test-metadata",
	}
	err := repo.SaveAttestationPolicy(policy)
	assert.NoError(t, err)

	result, err := repo.GetAttestationPolicy("test-policy-id")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-policy-id", result.PolicyID)
	assert.Equal(t, "test-type", result.Type)
	assert.Equal(t, []byte("test-policy-content"), result.Policy)
	assert.Equal(t, "test-metadata", result.Metadata)
}

func TestListAttestationPolicies(t *testing.T) {
	testDB := setupPolicyTestDB(t)
	repo := NewPolicyRepository(testDB)

	policies := []*models.AttestationPolicy{
		{
			PolicyID: "policy-id-1",
			Type:     "type1",
			Policy:   []byte("policy-content-1"),
			Metadata: "metadata1",
		},
		{
			PolicyID: "policy-id-2",
			Type:     "type2",
			Policy:   []byte("policy-content-2"),
			Metadata: "metadata2",
		},
		{
			PolicyID: "policy-id-3",
			Type:     "type3",
			Policy:   []byte("policy-content-3"),
			Metadata: "metadata3",
		},
	}

	for _, p := range policies {
		err := repo.SaveAttestationPolicy(p)
		assert.NoError(t, err)
	}

	results, err := repo.ListAttestationPolicies()

	assert.NoError(t, err)
	assert.Len(t, results, 3)
}
