package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/sirupsen/logrus"
)

type AAInstanceHandler struct {
	aaInstanceRepo *repository.AAInstanceRepository
	config         *config.AttestationAgentInstanceInfoConfig
}

func NewAAInstanceHandler(aaInstanceRepo *repository.AAInstanceRepository, config *config.AttestationAgentInstanceInfoConfig) *AAInstanceHandler {
	return &AAInstanceHandler{
		aaInstanceRepo: aaInstanceRepo,
		config:         config,
	}
}

// HandleHeartbeat handles attestation agent instance heartbeat requests
func (h *AAInstanceHandler) HandleHeartbeat(c *gin.Context) {
	// Get AAInstanceInfo from request header
	aaInstanceInfoHeader := c.GetHeader("AAInstanceInfo")
	if aaInstanceInfoHeader == "" {
		logrus.Errorf("Missing AAInstanceInfo header in heartbeat request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing AAInstanceInfo header"})
		return
	}

	// Parse the JSON from header
	var aaInstanceInfo models.InstanceInfo
	if err := json.Unmarshal([]byte(aaInstanceInfoHeader), &aaInstanceInfo); err != nil {
		logrus.Errorf("Failed to parse AAInstanceInfo header: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid AAInstanceInfo format"})
		return
	}

	// Validate required fields
	if aaInstanceInfo.InstanceID == "" {
		logrus.Errorf("Missing instance_id in AAInstanceInfo")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing instance_id in AAInstanceInfo"})
		return
	}

	clientIP := c.ClientIP()
	now := time.Now()

	// Create or update heartbeat record
	heartbeat := &models.AAInstanceHeartbeat{
		InstanceInfo:  aaInstanceInfo,
		ClientIP:      clientIP,
		LastHeartbeat: now,
	}

	err := h.aaInstanceRepo.UpsertHeartbeat(heartbeat)
	if err != nil {
		logrus.Errorf("Failed to save heartbeat: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save heartbeat"})
		return
	}

	logrus.Infof("Heartbeat received from AA instance: %s (IP: %s)", aaInstanceInfo.InstanceID, clientIP)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": now.Format(time.RFC3339)})
}

// HandleGetActiveAAInstances handles requests to get all active attestation agent instances
func (h *AAInstanceHandler) HandleGetActiveAAInstances(c *gin.Context) {
	// Calculate cutoff time for active AA instances
	cutoffTime := time.Now().Add(-time.Duration(h.config.HeartbeatTimeoutMinutes) * time.Minute)

	activeAAInstances, err := h.aaInstanceRepo.GetActiveHeartbeats(cutoffTime)
	if err != nil {
		logrus.Errorf("Failed to get active AA instances: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve active AA instances"})
		return
	}

	// Clean up expired heartbeats
	err = h.aaInstanceRepo.CleanupExpiredHeartbeats(cutoffTime)
	if err != nil {
		logrus.Warnf("Failed to cleanup expired heartbeats: %v", err)
	}

	logrus.Infof("Retrieved %d active AA instances", len(activeAAInstances))
	c.JSON(http.StatusOK, gin.H{
		"active_aa_instances": activeAAInstances,
		"count":               len(activeAAInstances),
		"timestamp":           time.Now().Format(time.RFC3339),
	})
}
