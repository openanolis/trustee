package handlers

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
)

type CredentialHandler struct {
	config *config.CredentialConfig
}

func NewCredentialHandler(config *config.CredentialConfig) *CredentialHandler {
	return &CredentialHandler{
		config: config,
	}
}

func (h *CredentialHandler) HandleGetCredential(c *gin.Context) {
	if h.config == nil || h.config.Path == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not configured"})
		return
	}

	data, err := os.ReadFile(h.config.Path)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Credential configured but file not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read credential file"})
		return
	}

	c.Data(http.StatusOK, "application/octet-stream", data)
}

