package handlers

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/sirupsen/logrus"
)

// IAMHandler proxies IAM API requests to the upstream Trustee IAM service.
type IAMHandler struct {
	proxy *proxy.Proxy
}

// NewIAMHandler creates a new IAM handler.
func NewIAMHandler(proxy *proxy.Proxy) *IAMHandler {
	return &IAMHandler{proxy: proxy}
}

// HandleIAMProxy forwards any IAM request to the upstream service.
func (h *IAMHandler) HandleIAMProxy(c *gin.Context) {
	resp, err := h.proxy.ForwardToIAM(c)
	if err != nil {
		logrus.Errorf("Failed to forward IAM request: %v", err)
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "failed to forward IAM request"})
		return
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read IAM response: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to read IAM response"})
		return
	}

	proxy.CopyHeaders(c, resp)
	proxy.CopyCookies(c, resp)

	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}
