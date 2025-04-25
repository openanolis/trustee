package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/sirupsen/logrus"
)

// KBSHandler handles requests to the KBS service
type KBSHandler struct {
	proxy        *proxy.Proxy
	resourceRepo *repository.ResourceRepository
	policyRepo   *repository.PolicyRepository
	auditRepo    *repository.AuditRepository
}

// NewKBSHandler creates a new KBS handler
func NewKBSHandler(
	proxy *proxy.Proxy,
	resourceRepo *repository.ResourceRepository,
	policyRepo *repository.PolicyRepository,
	auditRepo *repository.AuditRepository,
) *KBSHandler {
	return &KBSHandler{
		proxy:        proxy,
		resourceRepo: resourceRepo,
		policyRepo:   policyRepo,
		auditRepo:    auditRepo,
	}
}

// HandleAuth handles the KBS authentication endpoint
func (h *KBSHandler) HandleAuth(c *gin.Context) {
	// Read the request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read auth request body: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Forward the request to KBS
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to forward auth request to KBS: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to KBS"})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS auth response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	// Copy headers and cookies to the response
	proxy.CopyHeaders(c, resp)
	proxy.CopyCookies(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// HandleAttest handles the KBS attestation endpoint
func (h *KBSHandler) HandleAttest(c *gin.Context) {
	// Read the request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read attest request body: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Forward the request to KBS
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to forward attest request to KBS: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to KBS"})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS attest response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	// Get session ID from cookies
	sessionID := ""
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == "kbs-session-id" {
			sessionID = cookie.Value
			break
		}
	}

	// Create attestation record
	record := &models.AttestationRecord{
		ClientIP:    c.ClientIP(),
		SessionID:   sessionID,
		RequestBody: string(requestBody),
		Status:      resp.StatusCode,
		Successful:  resp.StatusCode == http.StatusOK,
		Timestamp:   time.Now(),
	}

	// Save the record asynchronously
	go func() {
		if err := h.auditRepo.SaveAttestationRecord(record); err != nil {
			logrus.Errorf("Failed to save attestation record: %v", err)
		}
	}()

	// Copy headers and cookies to the response
	proxy.CopyHeaders(c, resp)
	proxy.CopyCookies(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// HandleSetAttestationPolicy handles setting an attestation policy
func (h *KBSHandler) HandleSetAttestationPolicy(c *gin.Context) {
	// Read the request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read attestation policy request body: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Forward the request to KBS
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to forward attestation policy request to KBS: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to KBS"})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS attestation policy response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	// Copy headers to the response
	proxy.CopyHeaders(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// HandleSetResourcePolicy handles setting a resource policy
func (h *KBSHandler) HandleSetResourcePolicy(c *gin.Context) {
	// Read the request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read resource policy request body: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Forward the request to KBS
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to forward resource policy request to KBS: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to KBS"})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS resource policy response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	// Copy headers to the response
	proxy.CopyHeaders(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// HandleGetResource handles retrieving a resource
func (h *KBSHandler) HandleGetResource(c *gin.Context) {
	repository := c.Param("repository")
	resourceType := c.Param("type")
	tag := c.Param("tag")

	// Record the request
	sessionID := ""
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == "kbs-session-id" {
			sessionID = cookie.Value
			break
		}
	}

	// Create a record for this request
	requestRecord := &models.ResourceRequest{
		ClientIP:   c.ClientIP(),
		SessionID:  sessionID,
		Repository: repository,
		Type:       resourceType,
		Tag:        tag,
		Method:     c.Request.Method,
		Timestamp:  time.Now(),
	}

	// Forward the request to KBS
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to forward resource request to KBS: %v", err)
		requestRecord.Status = http.StatusInternalServerError
		requestRecord.Successful = false

		// Save the record asynchronously
		go func() {
			if err := h.auditRepo.SaveResourceRequest(requestRecord); err != nil {
				logrus.Errorf("Failed to save resource request record: %v", err)
			}
		}()

		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to KBS"})
		return
	}
	defer resp.Body.Close()

	// Update the record status
	requestRecord.Status = resp.StatusCode
	requestRecord.Successful = resp.StatusCode == http.StatusOK

	// Save the record asynchronously
	go func() {
		if err := h.auditRepo.SaveResourceRequest(requestRecord); err != nil {
			logrus.Errorf("Failed to save resource request record: %v", err)
		}
	}()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS resource response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	// Copy headers and cookies to the response
	proxy.CopyHeaders(c, resp)
	proxy.CopyCookies(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// HandleSetResource handles setting a resource
func (h *KBSHandler) HandleSetResource(c *gin.Context) {
	repository := c.Param("repository")
	resourceType := c.Param("type")
	tag := c.Param("tag")

	// Read the request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read resource request body: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Record the request
	sessionID := ""
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == "kbs-session-id" {
			sessionID = cookie.Value
			break
		}
	}

	// Create a record for this request
	requestRecord := &models.ResourceRequest{
		ClientIP:   c.ClientIP(),
		SessionID:  sessionID,
		Repository: repository,
		Type:       resourceType,
		Tag:        tag,
		Method:     c.Request.Method,
		Timestamp:  time.Now(),
	}

	// Forward the request to KBS
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to forward resource request to KBS: %v", err)
		requestRecord.Status = http.StatusInternalServerError
		requestRecord.Successful = false

		// Save the record asynchronously
		go func() {
			if err := h.auditRepo.SaveResourceRequest(requestRecord); err != nil {
				logrus.Errorf("Failed to save resource request record: %v", err)
			}
		}()

		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to KBS"})
		return
	}
	defer resp.Body.Close()

	// Update the record status
	requestRecord.Status = resp.StatusCode
	requestRecord.Successful = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent

	// Save the record asynchronously
	go func() {
		if err := h.auditRepo.SaveResourceRequest(requestRecord); err != nil {
			logrus.Errorf("Failed to save resource request record: %v", err)
		}
	}()

	// If the request was successful, save the resource
	if requestRecord.Successful {
		resource := &models.Resource{
			Repository: repository,
			Type:       resourceType,
			Tag:        tag,
			Metadata:   fmt.Sprintf("Set by %s at %s", c.ClientIP(), time.Now().Format(time.RFC3339)),
		}

		if err := h.resourceRepo.SaveResource(resource); err != nil {
			logrus.Errorf("Failed to save resource: %v", err)
		} else {
			logrus.Infof("Saved resource %s/%s/%s", repository, resourceType, tag)
		}
	}

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS resource response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	// Copy headers to the response
	proxy.CopyHeaders(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// GetAttestationPolicy handles retrieving an attestation policy
func (h *KBSHandler) GetAttestationPolicy(c *gin.Context) {
	policyID := c.Param("id")

	c.Request.URL.Path = fmt.Sprintf("/kbs/v0/attestation-policy/%s", policyID)
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to get attestation policy from KBS: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get attestation policy"})
		return
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS attestation policy response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	proxy.CopyHeaders(c, resp)
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// ListAttestationPolicies handles listing all attestation policies
func (h *KBSHandler) ListAttestationPolicies(c *gin.Context) {
	c.Request.URL.Path = "/kbs/v0/attestation-policies"
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to list attestation policies from KBS: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list attestation policies"})
		return
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS attestation policies response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	proxy.CopyHeaders(c, resp)
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// GetResourcePolicy handles retrieving the resource policy
func (h *KBSHandler) GetResourcePolicy(c *gin.Context) {
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("Failed to read resource policy request body: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the request body for forwarding
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))

	// Forward the request to KBS
	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to forward resource policy request to KBS: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to KBS"})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS resource policy response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	// Copy headers to the response
	proxy.CopyHeaders(c, resp)

	// Set status code and write response body
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}

// ListResources handles listing resources
func (h *KBSHandler) ListResources(c *gin.Context) {
	repository := c.Query("repository")
	resourceType := c.Query("type")

	resources, err := h.resourceRepo.ListResources(repository, resourceType)
	if err != nil {
		logrus.Errorf("Failed to list resources: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list resources"})
		return
	}

	c.JSON(http.StatusOK, resources)
}
