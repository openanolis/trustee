package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/sirupsen/logrus"
)

// AttestationServiceHandler handles requests to the Attestation Service
type AttestationServiceHandler struct {
	proxy     *proxy.Proxy
	auditRepo *repository.AuditRepository
}

// NewAttestationServiceHandler creates a new AttestationServiceHandler
func NewAttestationServiceHandler(
	p *proxy.Proxy,
	auditRepo *repository.AuditRepository,
) *AttestationServiceHandler {
	return &AttestationServiceHandler{
		proxy:     p,
		auditRepo: auditRepo,
	}
}

// parseAAInstanceInfo parses the AAInstanceInfo header and returns the structured data
func parseAAInstanceInfoAS(c *gin.Context) (*models.InstanceInfo, error) {
	aaInstanceInfoHeader := c.GetHeader("AAInstanceInfo")
	if aaInstanceInfoHeader == "" {
		// If no AAInstanceInfo header, return empty struct (not an error for backwards compatibility)
		return &models.InstanceInfo{}, nil
	}

	var aaInstanceInfo models.InstanceInfo
	if err := json.Unmarshal([]byte(aaInstanceInfoHeader), &aaInstanceInfo); err != nil {
		return nil, fmt.Errorf("failed to parse AAInstanceInfo header: %v", err)
	}

	return &aaInstanceInfo, nil
}

// HandleAttest handles the attestation endpoint for the Attestation Service
func (h *AttestationServiceHandler) HandleAttestation(c *gin.Context) {
	// Read the request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read attest request body for Attestation Service: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Forward the request to Attestation Service
	resp, err := h.proxy.ForwardToAttestationService(c)
	if err != nil {
		logrus.Errorf("Failed to forward attest request to Attestation Service: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to Attestation Service"})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read Attestation Service attest response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read Attestation Service response"})
		return
	}

	// Note: Session ID extraction might be different or not applicable for Attestation Service.
	// For now, we'll leave it empty. If session management is needed, it should be implemented here.
	sessionID := "" // Placeholder for session ID if applicable

	// Parse AAInstanceInfo from request header
	aaInstanceInfo, err := parseAAInstanceInfoAS(c)
	if err != nil {
		logrus.Errorf("Failed to parse AAInstanceInfo: %v", err)
		// Don't fail the request, just log the error
		aaInstanceInfo = &models.InstanceInfo{}
	}

	claims, err := extractClaimsFromAttestationResponse(string(responseBody))
	if err != nil {
		// Log the error but don't fail the request, claims might not always be present or parsable in the same way
		logrus.Warnf("Failed to extract claims from Attestation Service response: %v", err)
	}
	logrus.Debugf("Attestation Service claims: %+v", claims)

	// Create attestation record
	record := &models.AttestationRecord{
		ClientIP:      c.ClientIP(),
		SessionID:     sessionID, // Use extracted session ID if applicable
		RequestBody:   string(requestBody),
		Claims:        claims,
		Status:        resp.StatusCode,
		Successful:    resp.StatusCode == http.StatusOK,
		Timestamp:     time.Now(),
		SourceService: string(proxy.AttestationServiceType), // Set the source service
		InstanceInfo:  *aaInstanceInfo,
	}

	// Save the record asynchronously
	go func() {
		if err := h.auditRepo.SaveAttestationRecord(record); err != nil {
			logrus.Errorf("Failed to save attestation record for Attestation Service: %v", err)
		}
	}()

	// Copy headers and cookies to the response
	proxy.CopyHeaders(c, resp)
	proxy.CopyCookies(c, resp) // Assuming cookies might also need to be proxied

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// extractClaimsFromAttestationResponse extracts claims from the attestation service response.
// This function might need to be adjusted based on the actual response format of the attestation-service.
// For now, it uses the same logic as for KBS.
func extractClaimsFromAttestationResponse(tokenString string) (string, error) {
	// Check if the response is a JWT-like structure
	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		payloadBase64 := parts[1]
		payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadBase64)
		if err != nil {
			return "", fmt.Errorf("failed to decode JWT payload from attestation service response: %v", err)
		}
		return string(payloadBytes), nil
	}
	// If not JWT, or if claims are in a different format, this part needs adjustment.
	// For now, we return the raw body if it's not a JWT, assuming it might be JSON claims directly.
	// Or, return an error/empty string if claims are strictly expected in JWT format.
	logrus.Debugf("Attestation service response is not a standard JWT, returning raw body for claims (or implement specific parsing): %s", tokenString)
	return tokenString, nil
}

func (h *AttestationServiceHandler) HandleGeneralRequest(c *gin.Context) {
	// Read the request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read general request body: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Forward the request to Attestation Service
	resp, err := h.proxy.ForwardToAttestationService(c)
	if err != nil {
		logrus.Errorf("Failed to forward general request to Attestation Service: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to Attestation Service"})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read Attestation Service general response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read Attestation Service response"})
		return
	}

	// Copy headers to the response
	proxy.CopyHeaders(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// HandleSetAttestationPolicy handles setting an attestation policy in AttestationService
func (h *AttestationServiceHandler) HandleSetAttestationPolicy(c *gin.Context) {
	// Read the request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read attestation policy request body: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Forward the request to Attestation Service
	resp, err := h.proxy.ForwardToAttestationService(c)
	if err != nil {
		logrus.Errorf("Failed to forward attestation policy request to Attestation Service: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to Attestation Service"})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read Attestation Service attestation policy response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read Attestation Service response"})
		return
	}

	// Copy headers to the response
	proxy.CopyHeaders(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// GetAttestationPolicy handles retrieving an attestation policy from AttestationService
func (h *AttestationServiceHandler) GetAttestationPolicy(c *gin.Context) {
	// Forward the request to Attestation Service
	resp, err := h.proxy.ForwardToAttestationService(c)
	if err != nil {
		logrus.Errorf("Failed to get attestation policy from Attestation Service: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get attestation policy"})
		return
	}
	defer resp.Body.Close()
	
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read Attestation Service attestation policy response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read Attestation Service response"})
		return
	}

	proxy.CopyHeaders(c, resp)
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// ListAttestationPolicies handles listing all attestation policies from AttestationService
func (h *AttestationServiceHandler) ListAttestationPolicies(c *gin.Context) {
	// Forward the request to Attestation Service
	resp, err := h.proxy.ForwardToAttestationService(c)
	if err != nil {
		logrus.Errorf("Failed to list attestation policies from Attestation Service: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list attestation policies"})
		return
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read Attestation Service attestation policies response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read Attestation Service response"})
		return
	}

	proxy.CopyHeaders(c, resp)
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// DeleteAttestationPolicy handles deleting an attestation policy from AttestationService
func (h *AttestationServiceHandler) DeleteAttestationPolicy(c *gin.Context) {
	// Forward the request to Attestation Service
	resp, err := h.proxy.ForwardToAttestationService(c)
	if err != nil {
		logrus.Errorf("Failed to delete attestation policy from Attestation Service: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete attestation policy"})
		return
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read Attestation Service delete policy response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read Attestation Service response"})
		return
	}

	proxy.CopyHeaders(c, resp)
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}
