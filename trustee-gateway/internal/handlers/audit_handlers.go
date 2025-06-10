package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/sirupsen/logrus"
)

// AuditHandler handles audit-related requests
type AuditHandler struct {
	auditRepo *repository.AuditRepository
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(auditRepo *repository.AuditRepository) *AuditHandler {
	return &AuditHandler{
		auditRepo: auditRepo,
	}
}

// ListAttestationRecords handles retrieving attestation records
func (h *AuditHandler) ListAttestationRecords(c *gin.Context) {
	sessionID := c.Query("session_id")
	sourceService := c.Query("source_service")
	instanceID := c.Query("instance_id")

	var successful *bool
	if successfulStr := c.Query("successful"); successfulStr != "" {
		successfulBool, err := strconv.ParseBool(successfulStr)
		if err == nil {
			successful = &successfulBool
		}
	}

	var startTime, endTime *time.Time
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		parsed, err := time.Parse(time.RFC3339, startTimeStr)
		if err == nil {
			startTime = &parsed
		}
	}

	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		parsed, err := time.Parse(time.RFC3339, endTimeStr)
		if err == nil {
			endTime = &parsed
		}
	}

	limitStr := c.DefaultQuery("limit", "100")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 100
	}

	offsetStr := c.DefaultQuery("offset", "0")
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	records, err := h.auditRepo.ListAttestationRecords(
		sessionID,
		sourceService,
		instanceID,
		successful,
		startTime,
		endTime,
		limit,
		offset,
	)

	if err != nil {
		logrus.Errorf("Failed to list attestation records: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list attestation records"})
		return
	}

	c.JSON(http.StatusOK, records)
}

// ListResourceRequests handles retrieving resource request records
func (h *AuditHandler) ListResourceRequests(c *gin.Context) {
	sessionID := c.Query("session_id")
	repository := c.Query("repository")
	resourceType := c.Query("type")
	tag := c.Query("tag")
	method := c.Query("method")
	instanceID := c.Query("instance_id")

	var successful *bool
	if successfulStr := c.Query("successful"); successfulStr != "" {
		successfulBool, err := strconv.ParseBool(successfulStr)
		if err == nil {
			successful = &successfulBool
		}
	}

	var startTime, endTime *time.Time
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		parsed, err := time.Parse(time.RFC3339, startTimeStr)
		if err == nil {
			startTime = &parsed
		}
	}

	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		parsed, err := time.Parse(time.RFC3339, endTimeStr)
		if err == nil {
			endTime = &parsed
		}
	}

	limitStr := c.DefaultQuery("limit", "100")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 100
	}

	offsetStr := c.DefaultQuery("offset", "0")
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	records, err := h.auditRepo.ListResourceRequests(
		sessionID,
		repository,
		resourceType,
		tag,
		method,
		instanceID,
		successful,
		startTime,
		endTime,
		limit,
		offset,
	)

	if err != nil {
		logrus.Errorf("Failed to list resource requests: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list resource requests"})
		return
	}

	c.JSON(http.StatusOK, records)
}
