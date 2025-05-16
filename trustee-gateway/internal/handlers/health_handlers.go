package handlers

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/sirupsen/logrus"
)

type HealthCheckHandler struct {
	proxy *proxy.Proxy
}

func NewHealthCheckHandler(proxy *proxy.Proxy) *HealthCheckHandler {
	return &HealthCheckHandler{
		proxy: proxy,
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
		"version": "0.1.0",
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

	return ServiceStatus{
		Status:    "not supported",
		Timestamp: now,
	}
}
