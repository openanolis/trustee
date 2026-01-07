package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/openanolis/trustee/gateway/internal/rvps"
	"github.com/sirupsen/logrus"
)

// RVPSHandler handles requests to the RVPS service
type RVPSHandler struct {
	proxy  *proxy.Proxy
	client *rvps.GrpcClient
}

// NewRVPSHandler creates a new RVPS handler
func NewRVPSHandler(proxy *proxy.Proxy, client *rvps.GrpcClient) *RVPSHandler {
	return &RVPSHandler{
		proxy:  proxy,
		client: client,
	}
}

// HandleRVPSRequest is a generic handler for RVPS requests
func (h *RVPSHandler) HandleRVPSRequest(c *gin.Context) {
	rawPath := c.Request.URL.RawPath
	if rawPath == "" {
		rawPath = c.Request.URL.Path
	}
	// Remove the `/api/rvps` prefix that Gin routes with.
	path := strings.TrimPrefix(rawPath, "/api/rvps")
	path = strings.TrimPrefix(path, "/")

	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		logrus.Errorf("Failed to decode RVPS path: %v", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid path encoding"})
		return
	}

	// Try gRPC first if client is available
	if h.client != nil {
		switch {
		case c.Request.Method == "GET" && decodedPath == "query":
			h.handleQueryReferenceValue(c)
			return
		case c.Request.Method == "POST" && decodedPath == "register":
			h.handleRegisterReferenceValue(c)
			return
		case c.Request.Method == "DELETE" && strings.HasPrefix(decodedPath, "delete/"):
			nameRaw := strings.TrimPrefix(path, "delete/")
			name, err := url.PathUnescape(nameRaw)
			if err != nil || name == "" {
				logrus.Errorf("Invalid reference value name encoding: %v", err)
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid reference value name"})
				return
			}
			h.handleDeleteReferenceValue(c, name)
			return
		}
	}

	// Fallback to HTTP proxy for all other requests or when gRPC client is not available
	h.handleHTTPProxy(c)
}

func (h *RVPSHandler) handleQueryReferenceValue(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	result, err := h.client.QueryReferenceValue(ctx)
	if err != nil {
		logrus.Errorf("Failed to query reference values: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, result)
}

func (h *RVPSHandler) handleRegisterReferenceValue(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read request body: %v", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}
	logrus.Infof("Register reference value: %s", string(body))

	var message struct {
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &message); err != nil {
		logrus.Errorf("Failed to parse request body: %v", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	logrus.Infof("Register reference value: %s", message.Message)
	err = h.client.RegisterReferenceValue(ctx, message.Message)
	if err != nil {
		logrus.Errorf("Failed to register reference value: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusOK)
}

func (h *RVPSHandler) handleDeleteReferenceValue(c *gin.Context, name string) {
	if name == "" {
		logrus.Errorf("Reference value name is empty")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Reference value name is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	logrus.Infof("Delete reference value: %s", name)
	err := h.client.DeleteReferenceValue(ctx, name)
	if err != nil {
		logrus.Errorf("Failed to delete reference value: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusOK)
}

// handleHTTPProxy forwards requests to RVPS via HTTP proxy
func (h *RVPSHandler) handleHTTPProxy(c *gin.Context) {
	// For now, return 404 since HTTP proxy to RVPS is not implemented
	// This should be implemented when RVPS HTTP API is available
	logrus.Warnf("RVPS HTTP proxy not implemented, gRPC client unavailable for path: %s", c.Request.URL.Path)
	c.AbortWithStatusJSON(http.StatusNotImplemented, gin.H{
		"error": "RVPS HTTP proxy not implemented, gRPC client required",
	})
}
