package repository

import (
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"gorm.io/gorm"
)

// PolicyRepository handles database operations for policies
type PolicyRepository struct {
	db *gorm.DB
}

// NewPolicyRepository creates a new policy repository
func NewPolicyRepository(database *storage.Database) *PolicyRepository {
	return &PolicyRepository{
		db: database.DB,
	}
}

// SaveAttestationPolicy saves an attestation policy to the database
func (r *PolicyRepository) SaveAttestationPolicy(policy *models.AttestationPolicy) error {
	var existingAttestationPolicy models.AttestationPolicy
	result := r.db.Where("policy_id = ?", policy.PolicyID).First(&existingAttestationPolicy)

	if result.Error == nil {
		policy.ID = existingAttestationPolicy.ID
	}

	return r.db.Save(policy).Error
}

// GetAttestationPolicy retrieves an attestation policy by ID
func (r *PolicyRepository) GetAttestationPolicy(policyID string) (*models.AttestationPolicy, error) {
	var policy models.AttestationPolicy

	result := r.db.Where("policy_id = ?", policyID).First(&policy)
	if result.Error != nil {
		return nil, result.Error
	}

	return &policy, nil
}

// ListAttestationPolicies retrieves all attestation policies
func (r *PolicyRepository) ListAttestationPolicies() ([]models.AttestationPolicy, error) {
	var policies []models.AttestationPolicy

	if err := r.db.Find(&policies).Error; err != nil {
		return nil, err
	}

	return policies, nil
}
