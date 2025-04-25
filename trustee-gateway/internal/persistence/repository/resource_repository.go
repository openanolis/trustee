package repository

import (
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"gorm.io/gorm"
)

// ResourceRepository handles database operations for resources
type ResourceRepository struct {
	db *gorm.DB
}

// NewResourceRepository creates a new resource repository
func NewResourceRepository(database *storage.Database) *ResourceRepository {
	return &ResourceRepository{
		db: database.DB,
	}
}

// SaveResource saves a resource to the database
func (r *ResourceRepository) SaveResource(resource *models.Resource) error {
	var existingResource models.Resource
	result := r.db.Where("repository = ? AND type = ? AND tag = ?", resource.Repository, resource.Type, resource.Tag).First(&existingResource)

	if result.Error == nil {
		resource.ID = existingResource.ID
	}

	return r.db.Save(resource).Error
}

// GetResource retrieves a resource by repository, type, and tag
func (r *ResourceRepository) GetResource(repository, resourceType, tag string) (*models.Resource, error) {
	var resource models.Resource

	result := r.db.Where("repository = ? AND type = ? AND tag = ?", repository, resourceType, tag).First(&resource)
	if result.Error != nil {
		return nil, result.Error
	}

	return &resource, nil
}

// ListResources retrieves all resources, optionally filtered by repository and/or type
func (r *ResourceRepository) ListResources(repository, resourceType string) ([]models.Resource, error) {
	var resources []models.Resource
	query := r.db

	if repository != "" {
		query = query.Where("repository = ?", repository)
	}

	if resourceType != "" {
		query = query.Where("type = ?", resourceType)
	}

	if err := query.Find(&resources).Error; err != nil {
		return nil, err
	}

	return resources, nil
}

// DeleteResource deletes a resource by repository, type, and tag
func (r *ResourceRepository) DeleteResource(repository, resourceType, tag string) error {
	return r.db.Where("repository = ? AND type = ? AND tag = ?", repository, resourceType, tag).Delete(&models.Resource{}).Error
}
