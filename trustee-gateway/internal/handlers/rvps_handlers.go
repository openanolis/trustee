package handlers

import (
	"io"
	"net/http"
	"strings"

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

	targetPath := "/api/kbs/v0/rvps"
	if path != "" {
		targetPath = "/api/kbs/v0/rvps/" + path
	}

	c.Request.URL.Path = targetPath
	c.Request.URL.RawPath = targetPath

	resp, err := h.proxy.ForwardToKBS(c)
	if err != nil {
		logrus.Errorf("Failed to forward RVPS request to KBS: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request to KBS"})
		return
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read KBS RVPS response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read KBS response"})
		return
	}

	proxy.CopyHeaders(c, resp)
	proxy.CopyCookies(c, resp)

	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}
