package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/openanolis/trustee/gateway/internal/rvps"
	"github.com/sirupsen/logrus"
)

type HealthCheckHandler struct {
	proxy      *proxy.Proxy
	rvpsClient *rvps.GrpcClient
}

func NewHealthCheckHandler(proxy *proxy.Proxy, rvpsClient *rvps.GrpcClient) *HealthCheckHandler {
	return &HealthCheckHandler{
		proxy:      proxy,
		rvpsClient: rvpsClient,
	}
}

type ServiceStatus struct {
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	Timestamp string `json:"timestamp"`
}

type HealthStatus struct {
	Gateway ServiceStatus `json:"gateway"`
	KBS     ServiceStatus `json:"kbs"`
	AS      ServiceStatus `json:"as"`
	RVPS    ServiceStatus `json:"rvps"`
}

func (h *HealthCheckHandler) HandleHealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *HealthCheckHandler) HandleServicesHealthCheck(c *gin.Context) {
	now := time.Now().Format(time.RFC3339)

	healthStatus := HealthStatus{
		Gateway: ServiceStatus{
			Status:    "ok",
			Timestamp: now,
		},
	}

	kbsStatus := h.checkKBSHealth(c)
	healthStatus.KBS = kbsStatus

	asStatus := h.checkASHealth(c)
	healthStatus.AS = asStatus

	rvpsStatus := h.checkRVPSHealth(c)
	healthStatus.RVPS = rvpsStatus

	statusCode := http.StatusOK

	c.JSON(statusCode, healthStatus)
}

func (h *HealthCheckHandler) checkKBSHealth(c *gin.Context) ServiceStatus {
	now := time.Now().Format(time.RFC3339)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	authBody := []byte(`{
		"version": "0.4.0",
		"tee": "sample",
		"extra-params": "foo"
	}`)

	req, err := http.NewRequestWithContext(ctx, "POST", "/api/kbs/v0/auth", bytes.NewBuffer(authBody))
	if err != nil {
		logrus.Errorf("create kbs auth request failed: %v", err)
		return ServiceStatus{
			Status:    "error",
			Message:   "create kbs auth request failed",
			Timestamp: now,
		}
	}

	c.Request = req
	c.Request.Header.Set("Content-Type", "application/json")

	resp, err := h.proxy.ForwardToKBS(c)

	if err != nil {
		logrus.Errorf("forward kbs auth request failed: %v", err)
		return ServiceStatus{
			Status:    "error",
			Message:   "forward kbs auth request failed",
			Timestamp: now,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ServiceStatus{
			Status:    "error",
			Message:   "kbs auth request failed",
			Timestamp: now,
		}
	}

	return ServiceStatus{
		Status:    "ok",
		Timestamp: now,
	}
}

func (h *HealthCheckHandler) checkRVPSHealth(c *gin.Context) ServiceStatus {
	now := time.Now().Format(time.RFC3339)

	if h.rvpsClient == nil {
		return ServiceStatus{
			Status:    "error",
			Message:   "rvps grpc client not available",
			Timestamp: now,
		}
	}

	// Create a fresh context instead of using c.Request.Context() which might be modified
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := h.rvpsClient.QueryReferenceValue(ctx)
	if err != nil {
		logrus.Errorf("rvps health check failed: %v", err)
		return ServiceStatus{
			Status:    "error",
			Message:   fmt.Sprintf("rvps grpc query failed: %v", err),
			Timestamp: now,
		}
	}

	return ServiceStatus{
		Status:    "ok",
		Timestamp: now,
	}
}

// checkASHealth checks the health of the Attestation Service using the challenge endpoint
func (h *HealthCheckHandler) checkASHealth(c *gin.Context) ServiceStatus {
	now := time.Now().Format(time.RFC3339)

	// Create a fresh context for AS health check
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "/api/attestation-service/certificate", nil)
	if err != nil {
		logrus.Errorf("create as certificate request failed: %v", err)
		return ServiceStatus{
			Status:    "error",
			Message:   "create as certificate request failed",
			Timestamp: now,
		}
	}

	c.Request = req
	resp, err := h.proxy.ForwardToAttestationService(c)

	if err != nil {
		logrus.Errorf("forward as certificate request failed: %v", err)
		return ServiceStatus{
			Status:    "error",
			Message:   "forward as certificate request failed",
			Timestamp: now,
		}
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("read as certificate response body failed: %v", err)
		return ServiceStatus{
			Status:    "error",
			Message:   "read as certificate response body failed",
			Timestamp: now,
		}
	}

	// AS is considered healthy if:
	// 1. Returns 200 OK (with certificate content)
	// 2. Returns 404 with specific "No certificate configured" message (service is running but no cert configured)
	if resp.StatusCode == http.StatusOK {
		return ServiceStatus{
			Status:    "ok",
			Timestamp: now,
		}
	} else if resp.StatusCode == http.StatusNotFound {
		// Check if the response body contains the expected "No certificate configured" message
		var errorResponse map[string]interface{}
		if err := json.Unmarshal(body, &errorResponse); err == nil {
			if errorMsg, exists := errorResponse["error"]; exists && errorMsg == "No certificate configured" {
				return ServiceStatus{
					Status:    "ok",
					Timestamp: now,
				}
			}
		}
		// If it's 404 but not the expected message, treat as error
		return ServiceStatus{
			Status:    "error",
			Message:   fmt.Sprintf("as certificate request returned 404 with unexpected content: %s", string(body)),
			Timestamp: now,
		}
	} else {
		return ServiceStatus{
			Status:    "error",
			Message:   fmt.Sprintf("as certificate request failed with status: %d, body: %s", resp.StatusCode, string(body)),
			Timestamp: now,
		}
	}
}
